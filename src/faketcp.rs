//! A datagram-preserving TCP-shaped carrier for QUICP packets.
//!
//! The carrier owns only packet appearance and per-path TCP bookkeeping.  It does not expose a
//! byte-stream API and never waits for a missing sequence number before returning a payload. The
//! QUICP engine owns packet recovery, stream ordering, congestion control, and multipath
//! scheduling. Security is deliberately outside this carrier.

use alloc::{sync::Arc, vec, vec::Vec};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use core::ops::{BitOr, BitOrAssign};
use core::sync::atomic::{AtomicU32, Ordering};

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const TCP_PROTOCOL: u8 = 6;
const IPV4_HEADER_BYTES: usize = 20;
const IPV6_HEADER_BYTES: usize = 40;
const TCP_HEADER_BYTES: usize = 20;
const MAX_TCP_OPTIONS_BYTES: usize = 40;
const MAX_PACKET_BYTES: usize = u16::MAX as usize;
const MAX_DATAGRAM_BYTES: usize = MAX_PACKET_BYTES - IPV6_HEADER_BYTES - TCP_HEADER_BYTES;
const TFO_OPTION_KIND: u8 = 34;
pub const DEFAULT_SYN_MSS: u16 = 1460;
const SYN_WINDOW_SCALE: u8 = 7;

/// The two underlay endpoints that identify one `FakeTCP` path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FourTuple {
    /// Source socket address in packet direction.
    pub source: SocketAddr,
    /// Destination socket address in packet direction.
    pub destination: SocketAddr,
}

impl FourTuple {
    /// Creates a path tuple.  [`FakeTcpCarrier::new`] validates it before use.
    #[must_use]
    pub const fn new(source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            source,
            destination,
        }
    }

    #[must_use]
    /// Reverses the packet direction.
    pub const fn reverse(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
        }
    }
}

/// Direction separates the two per-path sequence spaces.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CarrierDirection {
    /// Packets sent from the QUICP client to the server.
    ClientToServer,
    /// Packets sent from the QUICP server to the client.
    ServerToClient,
}

impl CarrierDirection {
    const fn bit(self) -> u8 {
        match self {
            Self::ClientToServer => 0,
            Self::ServerToClient => 1,
        }
    }
}

/// Controls whether a SYN may carry the first QUICP datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SynDataMode {
    /// Disallows a QUICP datagram in the carrier SYN.
    Disabled,
    /// The value is the TFO-style cookie expected on the SYN option.
    Cookie([u8; 16]),
}

/// TCP flags used by the carrier packet encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const FIN: Self = Self(0x01);
    pub const SYN: Self = Self(0x02);
    pub const RST: Self = Self(0x04);
    pub const PSH: Self = Self(0x08);
    pub const ACK: Self = Self(0x10);

    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn is_syn(self) -> bool {
        self.contains(Self::SYN)
    }

    #[must_use]
    pub const fn is_ack(self) -> bool {
        self.contains(Self::ACK)
    }

    #[must_use]
    pub const fn is_rst(self) -> bool {
        self.contains(Self::RST)
    }
}

impl BitOr for TcpFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for TcpFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// TCP options that are visible to middleboxes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcpOptions {
    mss: Option<u16>,
    sack_permitted: bool,
    timestamps: Option<(u32, u32)>,
    window_scale: Option<u8>,
    fast_open_cookie: Option<([u8; 16], usize)>,
}

impl TcpOptions {
    #[must_use]
    pub fn for_syn(cookie: Option<&[u8]>) -> Self {
        Self::for_syn_with_mss(DEFAULT_SYN_MSS, cookie)
    }

    #[must_use]
    pub fn for_syn_with_mss(mss: u16, cookie: Option<&[u8]>) -> Self {
        let fast_open_cookie = cookie.map(|cookie| {
            let mut bytes = [0; 16];
            let copy_length = cookie.len().min(bytes.len());
            bytes[..copy_length].copy_from_slice(&cookie[..copy_length]);
            (bytes, cookie.len())
        });
        Self {
            mss: Some(mss),
            sack_permitted: true,
            timestamps: None,
            window_scale: Some(SYN_WINDOW_SCALE),
            fast_open_cookie,
        }
    }

    #[must_use]
    pub const fn mss(&self) -> Option<u16> {
        self.mss
    }

    #[must_use]
    pub const fn sack_permitted(&self) -> bool {
        self.sack_permitted
    }

    #[must_use]
    pub const fn timestamps(&self) -> Option<(u32, u32)> {
        self.timestamps
    }

    #[must_use]
    pub const fn window_scale(&self) -> Option<u8> {
        self.window_scale
    }

    #[must_use]
    pub fn fast_open_cookie(&self) -> Option<&[u8]> {
        self.fast_open_cookie
            .as_ref()
            .and_then(|(cookie, length)| (*length <= cookie.len()).then(|| &cookie[..*length]))
    }

    #[inline]
    const fn is_empty(&self) -> bool {
        self.mss.is_none()
            && !self.sack_permitted
            && self.timestamps.is_none()
            && self.window_scale.is_none()
            && self.fast_open_cookie.is_none()
    }

    fn encode_into(&self, bytes: &mut [u8]) -> Result<usize, CarrierError> {
        let mut length = 0;
        if let Some(mss) = self.mss {
            append_option(bytes, &mut length, &[2, 4])?;
            append_option(bytes, &mut length, &mss.to_be_bytes())?;
        }
        if self.sack_permitted {
            append_option(bytes, &mut length, &[4, 2])?;
        }
        if let Some((value, echo)) = self.timestamps {
            append_option(bytes, &mut length, &[1, 1, 8, 10])?;
            append_option(bytes, &mut length, &value.to_be_bytes())?;
            append_option(bytes, &mut length, &echo.to_be_bytes())?;
        }
        if let Some(scale) = self.window_scale {
            append_option(bytes, &mut length, &[3, 3, scale])?;
        }
        if let Some((cookie, cookie_length)) = &self.fast_open_cookie {
            if *cookie_length > cookie.len() {
                return Err(CarrierError::InvalidTcpOption);
            }
            let option_length = 2usize.saturating_add(*cookie_length);
            let option_length =
                u8::try_from(option_length).map_err(|_| CarrierError::InvalidTcpOption)?;
            append_option(bytes, &mut length, &[TFO_OPTION_KIND, option_length])?;
            append_option(bytes, &mut length, &cookie[..*cookie_length])?;
        }
        while length % 4 != 0 {
            append_option(bytes, &mut length, &[1])?;
        }
        Ok(length)
    }

    fn decode(mut input: &[u8]) -> Result<Self, CarrierError> {
        let mut options = Self::default();
        while let Some(&kind) = input.first() {
            match kind {
                0 => break,
                1 => input = &input[1..],
                _ => {
                    let Some(&length) = input.get(1) else {
                        return Err(CarrierError::InvalidTcpOption);
                    };
                    let length = usize::from(length);
                    if length < 2 || length > input.len() {
                        return Err(CarrierError::InvalidTcpOption);
                    }
                    let value = &input[2..length];
                    match kind {
                        2 if length == 4 => {
                            options.mss = Some(u16::from_be_bytes([value[0], value[1]]));
                        }
                        3 if length == 3 => options.window_scale = Some(value[0]),
                        4 if length == 2 => options.sack_permitted = true,
                        8 if length == 10 => {
                            options.timestamps = Some((
                                u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
                                u32::from_be_bytes([value[4], value[5], value[6], value[7]]),
                            ));
                        }
                        TFO_OPTION_KIND if (2..=18).contains(&length) => {
                            let mut cookie = [0; 16];
                            let cookie_length = value.len();
                            cookie[..cookie_length].copy_from_slice(value);
                            options.fast_open_cookie = Some((cookie, cookie_length));
                        }
                        _ => {}
                    }
                    input = &input[length..];
                }
            }
        }
        Ok(options)
    }
}

fn append_option(output: &mut [u8], offset: &mut usize, bytes: &[u8]) -> Result<(), CarrierError> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(CarrierError::TcpOptionsTooLong)?;
    if end > MAX_TCP_OPTIONS_BYTES || end > output.len() {
        return Err(CarrierError::TcpOptionsTooLong);
    }
    output[*offset..end].copy_from_slice(bytes);
    *offset = end;
    Ok(())
}

/// One complete raw IP/TCP packet. The payload is an opaque QUICP datagram, not a UDP datagram.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeTcpPacket {
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgment: u32,
    flags: TcpFlags,
    window: u16,
    options: TcpOptions,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct PacketView<'a> {
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgment: u32,
    flags: TcpFlags,
    window: u16,
    options: &'a [u8],
    fast_open_cookie: Option<&'a [u8]>,
    payload: &'a [u8],
}

impl FakeTcpPacket {
    /// Parses and verifies one complete IPv4 or IPv6 TCP packet.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed headers, unsupported fragmentation, or a bad checksum.
    pub fn decode(input: &[u8]) -> Result<Self, CarrierError> {
        let view = decode_packet_view(input, None)?;
        Ok(Self {
            source: view.source,
            destination: view.destination,
            sequence: view.sequence,
            acknowledgment: view.acknowledgment,
            flags: view.flags,
            window: view.window,
            options: TcpOptions::decode(view.options)?,
            payload: view.payload.to_vec(),
        })
    }

    /// Serializes the packet with IPv4/IPv6 and TCP checksums.
    ///
    /// # Errors
    ///
    /// Returns an error when the tuple, options, or packet length cannot be represented.
    pub fn encode(&self) -> Result<Vec<u8>, CarrierError> {
        if self.source.is_ipv4() != self.destination.is_ipv4()
            || self.source.port() == 0
            || self.destination.port() == 0
        {
            return Err(CarrierError::InvalidTuple);
        }
        let pseudo_header_prefix = tcp_pseudo_header_prefix(self.source, self.destination)
            .ok_or(CarrierError::InvalidTuple)?;
        let mut option_bytes = [0; MAX_TCP_OPTIONS_BYTES];
        let option_length = if self.options.is_empty() {
            0
        } else {
            self.options.encode_into(&mut option_bytes)?
        };
        let tcp_length = TCP_HEADER_BYTES
            .checked_add(option_length)
            .and_then(|length| length.checked_add(self.payload.len()))
            .ok_or(CarrierError::PacketTooLarge)?;
        if tcp_length > MAX_PACKET_BYTES {
            return Err(CarrierError::PacketTooLarge);
        }
        let ip_header_length = if self.source.is_ipv4() {
            IPV4_HEADER_BYTES
        } else {
            IPV6_HEADER_BYTES
        };
        let packet_length = ip_header_length
            .checked_add(tcp_length)
            .ok_or(CarrierError::PacketTooLarge)?;
        if packet_length > MAX_PACKET_BYTES {
            return Err(CarrierError::PacketTooLarge);
        }
        let mut packet = vec![0; packet_length];
        let length = encode_packet_into(
            self.source,
            self.destination,
            self.sequence,
            self.acknowledgment,
            self.flags,
            self.window,
            &self.options,
            &self.payload,
            &mut packet,
            pseudo_header_prefix,
        )?;
        debug_assert_eq!(length, packet_length);
        packet.truncate(length);
        Ok(packet)
    }

    /// Serializes the packet into caller-owned storage without allocating the packet buffer.
    ///
    /// # Errors
    ///
    /// Returns an error when the tuple, options, packet length, or output capacity is invalid.
    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, CarrierError> {
        let pseudo_header_prefix = tcp_pseudo_header_prefix(self.source, self.destination)
            .ok_or(CarrierError::InvalidTuple)?;
        encode_packet_into(
            self.source,
            self.destination,
            self.sequence,
            self.acknowledgment,
            self.flags,
            self.window,
            &self.options,
            &self.payload,
            output,
            pseudo_header_prefix,
        )
    }

    #[must_use]
    pub const fn source(&self) -> SocketAddr {
        self.source
    }

    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.destination
    }

    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    #[must_use]
    pub const fn acknowledgment(&self) -> u32 {
        self.acknowledgment
    }

    #[must_use]
    pub const fn flags(&self) -> TcpFlags {
        self.flags
    }

    #[must_use]
    pub const fn window(&self) -> u16 {
        self.window
    }

    #[must_use]
    pub const fn options(&self) -> &TcpOptions {
        &self.options
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

fn decode_packet_view(
    input: &[u8],
    pseudo_header_prefix: Option<u32>,
) -> Result<PacketView<'_>, CarrierError> {
    if input.len() < IPV4_HEADER_BYTES {
        return Err(CarrierError::PacketTooShort);
    }
    if input.len() > MAX_PACKET_BYTES {
        return Err(CarrierError::PacketTooLarge);
    }
    match input[0] >> 4 {
        4 => {
            let ihl = usize::from(input[0] & 0x0f) * 4;
            if ihl < IPV4_HEADER_BYTES || input.len() < ihl {
                return Err(CarrierError::InvalidIpHeader);
            }
            let total_length = usize::from(u16::from_be_bytes([input[2], input[3]]));
            if total_length != input.len() || total_length < ihl + TCP_HEADER_BYTES {
                return Err(CarrierError::InvalidIpHeader);
            }
            let fragment = u16::from_be_bytes([input[6], input[7]]);
            if fragment & 0x3fff != 0
                || input[9] != TCP_PROTOCOL
                || internet_checksum(&input[..ihl]) != 0
            {
                return Err(CarrierError::InvalidIpHeader);
            }
            let source = Ipv4Addr::new(input[12], input[13], input[14], input[15]);
            let destination = Ipv4Addr::new(input[16], input[17], input[18], input[19]);
            decode_tcp_view(
                SocketAddr::V4(SocketAddrV4::new(source, 0)),
                SocketAddr::V4(SocketAddrV4::new(destination, 0)),
                &input[ihl..],
                pseudo_header_prefix,
            )
        }
        6 => {
            if input.len() < IPV6_HEADER_BYTES {
                return Err(CarrierError::InvalidIpHeader);
            }
            let payload_length = usize::from(u16::from_be_bytes([input[4], input[5]]));
            if payload_length + IPV6_HEADER_BYTES != input.len() || input[6] != TCP_PROTOCOL {
                return Err(CarrierError::InvalidIpHeader);
            }
            let source = Ipv6Addr::from(
                <[u8; 16]>::try_from(&input[8..24]).map_err(|_| CarrierError::InvalidIpHeader)?,
            );
            let destination = Ipv6Addr::from(
                <[u8; 16]>::try_from(&input[24..40]).map_err(|_| CarrierError::InvalidIpHeader)?,
            );
            decode_tcp_view(
                SocketAddr::V6(SocketAddrV6::new(source, 0, 0, 0)),
                SocketAddr::V6(SocketAddrV6::new(destination, 0, 0, 0)),
                &input[IPV6_HEADER_BYTES..],
                pseudo_header_prefix,
            )
        }
        _ => Err(CarrierError::UnsupportedIpVersion),
    }
}

#[inline]
fn ipv4_header_checksum(source: Ipv4Addr, destination: Ipv4Addr, total_length: u16) -> u16 {
    let source = source.octets();
    let destination = destination.octets();
    let sum = u32::from(total_length)
        + 0x4500
        + 0x4000
        + 0x4006
        + u32::from(u16::from_be_bytes([source[0], source[1]]))
        + u32::from(u16::from_be_bytes([source[2], source[3]]))
        + u32::from(u16::from_be_bytes([destination[0], destination[1]]))
        + u32::from(u16::from_be_bytes([destination[2], destination[3]]));
    !u16::try_from(fold_checksum(sum)).unwrap_or(u16::MAX)
}

fn decode_tcp_view(
    source: SocketAddr,
    destination: SocketAddr,
    input: &[u8],
    pseudo_header_prefix: Option<u32>,
) -> Result<PacketView<'_>, CarrierError> {
    let checksum = pseudo_header_prefix.map_or_else(
        || tcp_checksum(source, destination, input),
        |prefix| tcp_checksum_with_prefix(source, prefix, input),
    );
    if input.len() < TCP_HEADER_BYTES || checksum != 0 {
        return Err(CarrierError::InvalidTcpHeader);
    }
    let header_length = usize::from(input[12] >> 4) * 4;
    if header_length < TCP_HEADER_BYTES || header_length > input.len() {
        return Err(CarrierError::InvalidTcpHeader);
    }
    let options = &input[TCP_HEADER_BYTES..header_length];
    let fast_open_cookie = fast_open_cookie(options)?;
    Ok(PacketView {
        source: SocketAddr::new(source.ip(), u16::from_be_bytes([input[0], input[1]])),
        destination: SocketAddr::new(destination.ip(), u16::from_be_bytes([input[2], input[3]])),
        sequence: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
        acknowledgment: u32::from_be_bytes([input[8], input[9], input[10], input[11]]),
        flags: TcpFlags(input[13]),
        window: u16::from_be_bytes([input[14], input[15]]),
        options,
        fast_open_cookie,
        payload: &input[header_length..],
    })
}

fn fast_open_cookie(mut input: &[u8]) -> Result<Option<&[u8]>, CarrierError> {
    let mut cookie = None;
    while let Some(&kind) = input.first() {
        match kind {
            0 => break,
            1 => input = &input[1..],
            _ => {
                let Some(&length) = input.get(1) else {
                    return Err(CarrierError::InvalidTcpOption);
                };
                let length = usize::from(length);
                if length < 2 || length > input.len() {
                    return Err(CarrierError::InvalidTcpOption);
                }
                if kind == TFO_OPTION_KIND && (2..=18).contains(&length) {
                    cookie = Some(&input[2..length]);
                }
                input = &input[length..];
            }
        }
    }
    Ok(cookie)
}

#[allow(clippy::too_many_arguments)]
fn encode_packet_into(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgment: u32,
    flags: TcpFlags,
    window: u16,
    options: &TcpOptions,
    payload: &[u8],
    output: &mut [u8],
    pseudo_header_prefix: u32,
) -> Result<usize, CarrierError> {
    if source.is_ipv4() != destination.is_ipv4() || source.port() == 0 || destination.port() == 0 {
        return Err(CarrierError::InvalidTuple);
    }
    let ip_header_length = if source.is_ipv4() {
        IPV4_HEADER_BYTES
    } else {
        IPV6_HEADER_BYTES
    };
    let mut option_bytes = [0; MAX_TCP_OPTIONS_BYTES];
    let option_length = if options.is_empty() {
        0
    } else {
        options.encode_into(&mut option_bytes)?
    };
    let header_length = TCP_HEADER_BYTES
        .checked_add(option_length)
        .ok_or(CarrierError::TcpOptionsTooLong)?;
    let tcp_length = header_length
        .checked_add(payload.len())
        .ok_or(CarrierError::PacketTooLarge)?;
    if tcp_length > MAX_PACKET_BYTES {
        return Err(CarrierError::PacketTooLarge);
    }
    let packet_length = ip_header_length
        .checked_add(tcp_length)
        .ok_or(CarrierError::PacketTooLarge)?;
    if packet_length > MAX_PACKET_BYTES {
        return Err(CarrierError::PacketTooLarge);
    }
    if output.len() < packet_length {
        return Err(CarrierError::OutputTooSmall {
            required: packet_length,
            available: output.len(),
        });
    }
    {
        let tcp = &mut output[ip_header_length..packet_length];
        tcp[16..TCP_HEADER_BYTES].fill(0);
        let data_offset =
            u8::try_from(header_length / 4).map_err(|_| CarrierError::TcpOptionsTooLong)?;
        tcp[..2].copy_from_slice(&source.port().to_be_bytes());
        tcp[2..4].copy_from_slice(&destination.port().to_be_bytes());
        tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&acknowledgment.to_be_bytes());
        tcp[12] = data_offset << 4;
        tcp[13] = flags.bits();
        tcp[14..16].copy_from_slice(&window.to_be_bytes());
        if option_length != 0 {
            tcp[TCP_HEADER_BYTES..header_length].copy_from_slice(&option_bytes[..option_length]);
        }
        tcp[header_length..].copy_from_slice(payload);
        let checksum = tcp_checksum_with_prefix(source, pseudo_header_prefix, tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    }

    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let total_length =
                u16::try_from(packet_length).map_err(|_| CarrierError::PacketTooLarge)?;
            let header = &mut output[..IPV4_HEADER_BYTES];
            header[0] = 0x45;
            header[1] = 0;
            header[2..4].copy_from_slice(&total_length.to_be_bytes());
            header[4..6].fill(0);
            header[6] = 0x40;
            header[7] = 0;
            header[8] = 64;
            header[9] = TCP_PROTOCOL;
            header[10..12].fill(0);
            header[12..16].copy_from_slice(&source.octets());
            header[16..20].copy_from_slice(&destination.octets());
            let checksum = ipv4_header_checksum(source, destination, total_length);
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let payload_length =
                u16::try_from(tcp_length).map_err(|_| CarrierError::PacketTooLarge)?;
            let header = &mut output[..IPV6_HEADER_BYTES];
            header[0] = 0x60;
            header[1..4].fill(0);
            header[4..6].copy_from_slice(&payload_length.to_be_bytes());
            header[6] = TCP_PROTOCOL;
            header[7] = 64;
            header[8..24].copy_from_slice(&source.octets());
            header[24..40].copy_from_slice(&destination.octets());
        }
        _ => return Err(CarrierError::InvalidTuple),
    }
    Ok(packet_length)
}

/// The QUICP datagram returned by a carrier packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedDatagram {
    sequence: u32,
    was_syn: bool,
    payload: Vec<u8>,
}

impl DecodedDatagram {
    #[must_use]
    /// Returns the carrier sequence number used for diagnostics and ACK generation.
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    #[must_use]
    /// Returns whether the datagram arrived in a carrier SYN.
    pub const fn was_syn(&self) -> bool {
        self.was_syn
    }

    #[must_use]
    /// Returns the owned QUICP datagram payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A borrowed QUICP datagram returned while the input packet remains owned by the caller.
#[derive(Debug, Eq, PartialEq)]
pub struct BorrowedDecodedDatagram<'a> {
    sequence: u32,
    was_syn: bool,
    payload: &'a [u8],
}

impl BorrowedDecodedDatagram<'_> {
    #[must_use]
    /// Returns the carrier sequence number used for diagnostics and ACK generation.
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    #[must_use]
    /// Returns whether the datagram arrived in a carrier SYN.
    pub const fn was_syn(&self) -> bool {
        self.was_syn
    }

    #[must_use]
    /// Returns the caller-owned QUICP datagram payload.
    pub const fn payload(&self) -> &[u8] {
        self.payload
    }
}

/// One path's `FakeTCP` sequence state.
#[derive(Debug)]
pub struct FakeTcpCarrier {
    tuple: FourTuple,
    pseudo_header_prefix: u32,
    syn_data: SynDataMode,
    send_sequence: u32,
    acknowledgment: Arc<AtomicU32>,
    sent_syn: bool,
    syn_mss: u16,
    outer_mtu: u16,
}

impl FakeTcpCarrier {
    /// Creates one independent carrier state.  A changed four-tuple must create a new state.
    ///
    /// # Errors
    ///
    /// Returns an error for an unusable or mixed-family tuple, or an MSS/MTU that cannot carry a
    /// TCP payload.
    pub fn new(
        tuple: FourTuple,
        direction: CarrierDirection,
        syn_data: SynDataMode,
    ) -> Result<Self, CarrierError> {
        Self::new_with_mtu(tuple, direction, syn_data, DEFAULT_SYN_MSS, u16::MAX)
    }

    /// Creates one carrier with an explicit SYN MSS and complete outer packet MTU.
    ///
    /// # Errors
    ///
    /// Returns an error for an unusable or mixed-family tuple, or an MSS/MTU that cannot carry a
    /// TCP payload.
    pub fn new_with_mtu(
        tuple: FourTuple,
        direction: CarrierDirection,
        syn_data: SynDataMode,
        syn_mss: u16,
        outer_mtu: u16,
    ) -> Result<Self, CarrierError> {
        let pseudo_header_prefix = validated_pseudo_header_prefix(tuple)?;
        let ip_header_bytes = if tuple.source.is_ipv4() {
            IPV4_HEADER_BYTES
        } else {
            IPV6_HEADER_BYTES
        };
        let header_bytes = u16::try_from(ip_header_bytes + TCP_HEADER_BYTES)
            .map_err(|_| CarrierError::InvalidOuterMtu(outer_mtu))?;
        let maximum_mss = outer_mtu
            .checked_sub(header_bytes)
            .ok_or(CarrierError::InvalidOuterMtu(outer_mtu))?;
        if syn_mss == 0 || syn_mss > maximum_mss {
            return Err(CarrierError::InvalidMss {
                mss: syn_mss,
                maximum: maximum_mss,
            });
        }
        let send_sequence = initial_sequence(tuple, direction)?;
        Ok(Self::from_parts(
            tuple,
            pseudo_header_prefix,
            syn_data,
            send_sequence,
            syn_mss,
            outer_mtu,
        ))
    }

    /// Creates one carrier with caller-provided initial sequence entropy.
    ///
    /// Callers that own sequence-number policy can use this constructor without changing the
    /// packet codec.
    ///
    /// # Errors
    ///
    /// Returns an error for an unusable or mixed-family tuple.
    pub fn new_with_initial_sequence(
        tuple: FourTuple,
        syn_data: SynDataMode,
        initial_sequence: u32,
    ) -> Result<Self, CarrierError> {
        let pseudo_header_prefix = validated_pseudo_header_prefix(tuple)?;
        Ok(Self::from_parts(
            tuple,
            pseudo_header_prefix,
            syn_data,
            initial_sequence,
            DEFAULT_SYN_MSS,
            u16::MAX,
        ))
    }

    fn from_parts(
        tuple: FourTuple,
        pseudo_header_prefix: u32,
        syn_data: SynDataMode,
        send_sequence: u32,
        syn_mss: u16,
        outer_mtu: u16,
    ) -> Self {
        Self {
            tuple,
            pseudo_header_prefix,
            syn_data,
            send_sequence,
            acknowledgment: Arc::new(AtomicU32::new(0)),
            sent_syn: false,
            syn_mss,
            outer_mtu,
        }
    }

    #[cfg(test)]
    fn pair(
        tuple: FourTuple,
        direction: CarrierDirection,
        syn_data: SynDataMode,
    ) -> Result<(Self, Self), CarrierError> {
        Self::pair_with_mtu(tuple, direction, syn_data, DEFAULT_SYN_MSS, u16::MAX)
    }

    #[cfg(any(test, all(unix, feature = "runtime-tokio")))]
    fn pair_with_mtu(
        tuple: FourTuple,
        direction: CarrierDirection,
        syn_data: SynDataMode,
        syn_mss: u16,
        outer_mtu: u16,
    ) -> Result<(Self, Self), CarrierError> {
        let inbound = Self::new_with_mtu(tuple, direction, syn_data, syn_mss, outer_mtu)?;
        let mut outbound = Self::new_with_mtu(tuple, direction, syn_data, syn_mss, outer_mtu)?;
        outbound.acknowledgment = Arc::clone(&inbound.acknowledgment);
        Ok((inbound, outbound))
    }

    /// Encodes one ordinary QUICP datagram in one TCP-shaped packet.
    ///
    /// # Errors
    ///
    /// Returns an error when the datagram or packet is too large.
    pub fn encode_datagram(&mut self, datagram: &[u8]) -> Result<Vec<u8>, CarrierError> {
        self.encode(datagram, TcpFlags::ACK | TcpFlags::PSH, None)
    }

    /// Encodes one ordinary QUICP datagram into caller-owned storage.
    ///
    /// # Errors
    ///
    /// Returns an error when the datagram, packet, or output buffer is too small.
    pub fn encode_datagram_into(
        &mut self,
        datagram: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CarrierError> {
        self.encode_into(datagram, TcpFlags::ACK | TcpFlags::PSH, None, output)
    }

    /// Encodes the first QUICP datagram in a TFO-style SYN packet.
    ///
    /// # Errors
    ///
    /// Returns an error when SYN data is disabled or this carrier already emitted its SYN.
    pub fn encode_syn(&mut self, datagram: &[u8]) -> Result<Vec<u8>, CarrierError> {
        if self.sent_syn {
            return Err(CarrierError::InvalidState);
        }
        let SynDataMode::Cookie(cookie) = self.syn_data else {
            return Err(CarrierError::SynDataDisabled);
        };
        let packet = self.encode(datagram, TcpFlags::SYN, Some(cookie.as_slice()))?;
        self.sent_syn = true;
        Ok(packet)
    }

    /// Encodes the first client QUICP datagram into caller-owned storage.
    ///
    /// # Errors
    ///
    /// Returns an error when SYN data is disabled, this carrier already emitted its SYN, or the
    /// packet does not fit the output buffer.
    pub fn encode_syn_into(
        &mut self,
        datagram: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CarrierError> {
        if self.sent_syn {
            return Err(CarrierError::InvalidState);
        }
        let SynDataMode::Cookie(cookie) = self.syn_data else {
            return Err(CarrierError::SynDataDisabled);
        };
        let length = self.encode_into(datagram, TcpFlags::SYN, Some(cookie.as_slice()), output)?;
        self.sent_syn = true;
        Ok(length)
    }

    /// Encodes a server-side first response with SYN, ACK, and one QUICP datagram.
    ///
    /// # Errors
    ///
    /// Returns an error when SYN data is disabled or this carrier already emitted its SYN.
    pub fn encode_syn_ack(&mut self, datagram: &[u8]) -> Result<Vec<u8>, CarrierError> {
        if self.sent_syn {
            return Err(CarrierError::InvalidState);
        }
        let SynDataMode::Cookie(cookie) = self.syn_data else {
            return Err(CarrierError::SynDataDisabled);
        };
        let packet = self.encode(
            datagram,
            TcpFlags::SYN | TcpFlags::ACK,
            Some(cookie.as_slice()),
        )?;
        self.sent_syn = true;
        Ok(packet)
    }

    /// Encodes the first server QUICP datagram into caller-owned storage.
    ///
    /// # Errors
    ///
    /// Returns an error when SYN data is disabled, this carrier already emitted its SYN, or the
    /// packet does not fit the output buffer.
    pub fn encode_syn_ack_into(
        &mut self,
        datagram: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CarrierError> {
        if self.sent_syn {
            return Err(CarrierError::InvalidState);
        }
        let SynDataMode::Cookie(cookie) = self.syn_data else {
            return Err(CarrierError::SynDataDisabled);
        };
        let length = self.encode_into(
            datagram,
            TcpFlags::SYN | TcpFlags::ACK,
            Some(cookie.as_slice()),
            output,
        )?;
        self.sent_syn = true;
        Ok(length)
    }

    /// Returns one packet's payload immediately, even if its sequence has a gap.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed or wrong-path packet.
    pub fn decode_datagram(&mut self, packet: &[u8]) -> Result<DecodedDatagram, CarrierError> {
        let packet = self.decode_datagram_borrowed(packet)?;
        Ok(DecodedDatagram {
            sequence: packet.sequence,
            was_syn: packet.was_syn,
            payload: packet.payload.to_vec(),
        })
    }

    /// Returns one packet's payload as a borrow of the caller's input buffer.
    ///
    /// The input is not retained after the method returns. QUICP owns duplicate detection because
    /// the unauthenticated carrier sequence cannot safely drive replay state.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed or wrong-path packet.
    pub fn decode_datagram_borrowed<'a>(
        &mut self,
        packet: &'a [u8],
    ) -> Result<BorrowedDecodedDatagram<'a>, CarrierError> {
        if packet.len() > usize::from(self.outer_mtu) {
            return Err(CarrierError::PacketTooLarge);
        }
        let packet = decode_packet_view(packet, Some(self.pseudo_header_prefix))?;
        let expected = self.tuple.reverse();
        if packet.source != expected.source || packet.destination != expected.destination {
            return Err(CarrierError::WrongTuple);
        }
        if packet.payload.is_empty() {
            return Err(CarrierError::EmptyPayload);
        }
        if packet.flags.is_syn() {
            let SynDataMode::Cookie(expected_cookie) = self.syn_data else {
                return Err(CarrierError::SynDataDisabled);
            };
            if packet.fast_open_cookie != Some(expected_cookie.as_slice()) {
                return Err(CarrierError::SynCookieRejected);
            }
        }
        let consumed = u32::try_from(packet.payload.len())
            .unwrap_or(u32::MAX)
            .saturating_add(u32::from(packet.flags.is_syn()));
        let acknowledgment = packet.sequence.wrapping_add(consumed);
        let previous = self.acknowledgment.load(Ordering::Relaxed);
        if previous == 0 || acknowledgment.wrapping_sub(previous) < 0x8000_0000 {
            self.acknowledgment.store(acknowledgment, Ordering::Relaxed);
        }
        Ok(BorrowedDecodedDatagram {
            sequence: packet.sequence,
            was_syn: packet.flags.is_syn(),
            payload: packet.payload,
        })
    }

    fn encode(
        &mut self,
        datagram: &[u8],
        flags: TcpFlags,
        cookie: Option<&[u8]>,
    ) -> Result<Vec<u8>, CarrierError> {
        let options = if flags.is_syn() {
            TcpOptions::for_syn_with_mss(self.syn_mss, cookie)
        } else {
            TcpOptions::default()
        };
        let mut option_bytes = [0; MAX_TCP_OPTIONS_BYTES];
        let option_length = if options.is_empty() {
            0
        } else {
            options.encode_into(&mut option_bytes)?
        };
        let ip_header_length = if self.tuple.source.is_ipv4() {
            IPV4_HEADER_BYTES
        } else {
            IPV6_HEADER_BYTES
        };
        let capacity = ip_header_length
            .checked_add(TCP_HEADER_BYTES)
            .and_then(|length| length.checked_add(option_length))
            .and_then(|length| length.checked_add(datagram.len()))
            .ok_or(CarrierError::PacketTooLarge)?;
        if capacity > MAX_PACKET_BYTES {
            return Err(CarrierError::PacketTooLarge);
        }
        let mut packet = vec![0; capacity];
        let length = self.encode_into(datagram, flags, cookie, &mut packet)?;
        packet.truncate(length);
        Ok(packet)
    }

    fn encode_into(
        &mut self,
        datagram: &[u8],
        flags: TcpFlags,
        cookie: Option<&[u8]>,
        output: &mut [u8],
    ) -> Result<usize, CarrierError> {
        if datagram.len() > MAX_DATAGRAM_BYTES {
            return Err(CarrierError::DatagramTooLarge);
        }
        let consumed = u32::try_from(datagram.len())
            .unwrap_or(u32::MAX)
            .saturating_add(u32::from(flags.is_syn()));
        let options = if flags.is_syn() {
            TcpOptions::for_syn_with_mss(self.syn_mss, cookie)
        } else {
            TcpOptions::default()
        };
        let packet_length = encode_packet_into(
            self.tuple.source,
            self.tuple.destination,
            self.send_sequence,
            self.acknowledgment.load(Ordering::Relaxed),
            flags,
            u16::MAX,
            &options,
            datagram,
            output,
            self.pseudo_header_prefix,
        )?;
        if packet_length > usize::from(self.outer_mtu) {
            return Err(CarrierError::PacketTooLarge);
        }
        self.send_sequence = self.send_sequence.wrapping_add(consumed);
        Ok(packet_length)
    }
}

// The codec above is runtime-neutral; only the Tokio raw-socket adapter needs both gates.
#[cfg(all(unix, feature = "runtime-tokio"))]
mod unix;
#[cfg(all(unix, feature = "runtime-tokio"))]
pub use unix::FakeTcpSocket;

impl FourTuple {
    fn validate(self) -> Result<(), CarrierError> {
        if self.source.is_ipv4() != self.destination.is_ipv4()
            || self.source.ip().is_unspecified()
            || self.destination.ip().is_unspecified()
            || self.source.port() == 0
            || self.destination.port() == 0
        {
            return Err(CarrierError::InvalidTuple);
        }
        Ok(())
    }
}

fn validated_pseudo_header_prefix(tuple: FourTuple) -> Result<u32, CarrierError> {
    tuple.validate()?;
    tcp_pseudo_header_prefix(tuple.source, tuple.destination).ok_or(CarrierError::InvalidTuple)
}

fn append_address(output: &mut [u8], offset: &mut usize, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(value) => {
            output[*offset] = 4;
            *offset += 1;
            let octets = value.octets();
            output[*offset..*offset + octets.len()].copy_from_slice(&octets);
            *offset += octets.len();
        }
        IpAddr::V6(value) => {
            output[*offset] = 6;
            *offset += 1;
            let octets = value.octets();
            output[*offset..*offset + octets.len()].copy_from_slice(&octets);
            *offset += octets.len();
        }
    }
    let port = address.port().to_be_bytes();
    output[*offset..*offset + port.len()].copy_from_slice(&port);
    *offset += port.len();
}

fn initial_sequence(tuple: FourTuple, direction: CarrierDirection) -> Result<u32, CarrierError> {
    let mut input = [0; 40];
    let mut input_length = 0;
    append_address(&mut input, &mut input_length, tuple.source);
    append_address(&mut input, &mut input_length, tuple.destination);
    input[input_length] = direction.bit();
    input_length += 1;
    let checksum = crc32c_checksum(&input[..input_length]);
    let mut random = [0; 4];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| CarrierError::Randomness)?;
    Ok(u32::from_be_bytes(random) ^ checksum)
}

#[inline]
fn crc32c_checksum(input: &[u8]) -> u32 {
    crc32c::crc32c(input)
}

#[inline]
fn internet_checksum(input: &[u8]) -> u16 {
    !u16::try_from(fold_checksum(checksum_sum(input))).unwrap_or(u16::MAX)
}

#[inline]
fn checksum_sum(input: &[u8]) -> u32 {
    // The maximum IP packet keeps this accumulator below u32::MAX; folding once enables
    // LLVM to vectorize the hot payload loop.
    let mut sum = 0u32;
    let (chunks, remainder) = input.as_chunks::<2>();
    for &[high, low] in chunks {
        sum += u32::from(u16::from_be_bytes([high, low]));
    }
    if let Some(&byte) = remainder.first() {
        sum += u32::from(byte) << 8;
    }
    sum
}

#[inline]
fn fold_checksum(mut sum: u32) -> u32 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

fn tcp_pseudo_header_prefix(source: SocketAddr, destination: SocketAddr) -> Option<u32> {
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => Some(
            checksum_sum(&source.octets())
                + checksum_sum(&destination.octets())
                + u32::from(TCP_PROTOCOL),
        ),
        (IpAddr::V6(source), IpAddr::V6(destination)) => Some(
            checksum_sum(&source.octets())
                + checksum_sum(&destination.octets())
                + u32::from(TCP_PROTOCOL),
        ),
        _ => None,
    }
}

fn tcp_checksum(source: SocketAddr, destination: SocketAddr, tcp: &[u8]) -> u16 {
    let Some(prefix) = tcp_pseudo_header_prefix(source, destination) else {
        return u16::MAX;
    };
    tcp_checksum_with_prefix(source, prefix, tcp)
}

fn tcp_checksum_with_prefix(source: SocketAddr, prefix: u32, tcp: &[u8]) -> u16 {
    let length_sum = if source.is_ipv4() {
        u32::from(u16::try_from(tcp.len()).unwrap_or(u16::MAX))
    } else {
        let length = u32::try_from(tcp.len()).unwrap_or(u32::MAX);
        (length >> 16) + (length & u32::from(u16::MAX))
    };
    !u16::try_from(fold_checksum(prefix + length_sum + checksum_sum(tcp))).unwrap_or(u16::MAX)
}

/// Orders a four-tuple so both path ends derive the same SYN cookie.
fn cookie_tuple(tuple: FourTuple) -> FourTuple {
    let source = (tuple.source.ip(), tuple.source.port());
    let destination = (tuple.destination.ip(), tuple.destination.port());
    if source <= destination {
        tuple
    } else {
        tuple.reverse()
    }
}

/// Issues a stateless 16-byte SYN cookie bound to a path tuple and epoch.
///
/// The HMAC input is direction-independent: a client `A -> B` tuple and the
/// server's `B -> A` view produce the same cookie.
#[must_use]
pub fn issue_syn_cookie(secret: &[u8], tuple: FourTuple, epoch: u64) -> [u8; 16] {
    let tuple = cookie_tuple(tuple);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut message = [0; 48];
    let mut message_length = 0;
    append_address(&mut message, &mut message_length, tuple.source);
    append_address(&mut message, &mut message_length, tuple.destination);
    let epoch = epoch.to_be_bytes();
    message[message_length..message_length + epoch.len()].copy_from_slice(&epoch);
    message_length += epoch.len();
    let tag = hmac::sign(&key, &message[..message_length]);
    let mut cookie = [0; 16];
    cookie.copy_from_slice(&tag.as_ref()[..16]);
    cookie
}

/// Verifies a SYN cookie without maintaining per-client handshake state.
#[must_use]
pub fn verify_syn_cookie(secret: &[u8], tuple: FourTuple, epoch: u64, cookie: &[u8]) -> bool {
    cookie.ct_eq(&issue_syn_cookie(secret, tuple, epoch)).into()
}

/// Packet validation, bounded encoding, and carrier-state errors.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum CarrierError {
    /// Source and destination do not form a usable same-family path.
    #[error("invalid FakeTCP four-tuple")]
    InvalidTuple,
    /// The packet has an unsupported IP version.
    #[error("unsupported IP version")]
    UnsupportedIpVersion,
    /// The input ends before the declared headers or payload.
    #[error("packet is too short")]
    PacketTooShort,
    /// The packet exceeds the IP length limit.
    #[error("packet is too large")]
    PacketTooLarge,
    /// The complete outer MTU is too small for the IP and TCP headers.
    #[error("outer MTU {0} is too small for the IP and TCP headers")]
    InvalidOuterMtu(u16),
    /// The advertised MSS cannot fit the configured outer packet MTU.
    #[error("MSS {mss} exceeds the carrier maximum {maximum}")]
    InvalidMss {
        /// Rejected MSS.
        mss: u16,
        /// Maximum MSS for the outer packet MTU.
        maximum: u16,
    },
    /// The caller-owned output buffer cannot hold the encoded packet.
    #[error("output buffer capacity {available} is smaller than packet size {required}")]
    OutputTooSmall {
        /// Required packet bytes.
        required: usize,
        /// Supplied output capacity.
        available: usize,
    },
    /// The IP header or checksum is invalid.
    #[error("invalid IPv4/IPv6 header")]
    InvalidIpHeader,
    /// The TCP-shaped header or checksum is invalid.
    #[error("invalid TCP header")]
    InvalidTcpHeader,
    /// A TCP option is malformed.
    #[error("invalid TCP option")]
    InvalidTcpOption,
    /// Encoded TCP options exceed the protocol maximum.
    #[error("TCP options exceed 40 bytes")]
    TcpOptionsTooLong,
    /// A QUICP datagram cannot fit in one carrier packet.
    #[error("datagram exceeds the carrier limit")]
    DatagramTooLarge,
    /// SYN data was requested while disabled.
    #[error("SYN data is disabled")]
    SynDataDisabled,
    /// The SYN did not carry the expected tuple-bound cookie.
    #[error("SYN data cookie was rejected")]
    SynCookieRejected,
    /// The requested SYN/data transition is not valid for current state.
    #[error("carrier state transition is invalid")]
    InvalidState,
    /// The decoded packet belongs to a different carrier tuple.
    #[error("packet tuple does not match the carrier path")]
    WrongTuple,
    /// The carrier packet contains no QUICP datagram.
    #[error("packet has no carrier payload")]
    EmptyPayload,
    /// The operating system did not provide secure randomness.
    #[error("system randomness is unavailable")]
    Randomness,
}

#[cfg(test)]
mod sequence_tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn sequence_numbers_wrap_like_tcp() {
        let tuple = FourTuple::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_001)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 44_443)),
        );
        let mut carrier = FakeTcpCarrier::new(
            tuple,
            CarrierDirection::ClientToServer,
            SynDataMode::Disabled,
        )
        .expect("carrier");
        carrier.send_sequence = u32::MAX - 1;

        let first = carrier.encode_datagram(b"1234").expect("first packet");
        let second = carrier.encode_datagram(b"5678").expect("wrapped packet");
        let first = decode_packet_view(&first, None).expect("first view");
        let second = decode_packet_view(&second, None).expect("second view");
        assert_eq!(first.sequence, u32::MAX - 1);
        assert_eq!(second.sequence, 2);
    }

    #[test]
    fn paired_sender_acknowledges_packets_decoded_by_receiver() {
        let tuple = FourTuple::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_001)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 44_443)),
        );
        let cookie = SynDataMode::Cookie([7; 16]);
        let mut client =
            FakeTcpCarrier::new(tuple.reverse(), CarrierDirection::ServerToClient, cookie)
                .expect("client carrier");
        let (mut inbound, mut outbound) =
            FakeTcpCarrier::pair(tuple, CarrierDirection::ClientToServer, cookie)
                .expect("server carriers");

        let syn = client.encode_syn(b"initial").expect("client SYN");
        inbound
            .decode_datagram_borrowed(&syn)
            .expect("server receives SYN");
        let syn = decode_packet_view(&syn, None).expect("client SYN view");
        let syn_ack = outbound
            .encode_syn_ack(b"response")
            .expect("server SYN-ACK");
        let syn_ack = decode_packet_view(&syn_ack, None).expect("server SYN-ACK view");

        assert_eq!(
            syn_ack.acknowledgment,
            syn.sequence
                .wrapping_add(u32::try_from(syn.payload.len()).expect("payload length"))
                .wrapping_add(1)
        );
    }
}

#[cfg(all(test, unix, feature = "runtime-tokio"))]
mod unix_socket_tests {
    use super::unix::{MAX_DECODE_REJECTS_PER_POLL, reject_budget_exhausted};
    #[cfg(not(target_os = "linux"))]
    use super::{CarrierDirection, FourTuple, SynDataMode};
    #[cfg(not(target_os = "linux"))]
    use core::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn malformed_packet_budget_forces_a_scheduler_yield() {
        let mut budget = MAX_DECODE_REJECTS_PER_POLL;
        for _ in 1..MAX_DECODE_REJECTS_PER_POLL {
            assert!(!reject_budget_exhausted(&mut budget));
        }
        assert!(reject_budget_exhausted(&mut budget));
        assert!(reject_budget_exhausted(&mut budget));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn packet_socket_mode_is_linux_only() {
        let tuple = FourTuple::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 44_000)),
        );
        let error = super::unix::FakeTcpSocket::bind(
            tuple,
            CarrierDirection::ClientToServer,
            SynDataMode::Disabled,
            1460,
            1500,
            true,
        )
        .expect_err("non-Linux packet sockets must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }
}
