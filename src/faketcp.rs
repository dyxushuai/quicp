//! A datagram-preserving TCP-shaped carrier for QUICP packets.
//!
//! The carrier owns only packet appearance and per-path TCP bookkeeping.  It does not expose a
//! byte-stream API and never waits for a missing sequence number before returning a payload. The
//! QUICP engine owns packet recovery, stream ordering, congestion control, and multipath
//! scheduling. Security is deliberately outside this carrier.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::{BitOr, BitOrAssign};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use std::sync::OnceLock;
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use std::sync::atomic::{Ordering, fence};
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use std::sync::{Arc, Mutex};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use fearless_simd::{Avx2, Level, prelude::*};
#[cfg(target_arch = "x86")]
use std::arch::x86::{
    __m256i, _mm_add_epi32, _mm_cvtsi128_si32, _mm_hadd_epi32, _mm256_add_epi32,
    _mm256_castsi256_si128, _mm256_extracti128_si256, _mm256_madd_epi16, _mm256_set1_epi16,
    _mm256_set1_epi32, _mm256_setr_epi8, _mm256_setzero_si256, _mm256_shuffle_epi8,
    _mm256_sub_epi16,
};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{
    __m256i, _mm_add_epi32, _mm_cvtsi128_si32, _mm_hadd_epi32, _mm256_add_epi32,
    _mm256_castsi256_si128, _mm256_extracti128_si256, _mm256_madd_epi16, _mm256_set1_epi16,
    _mm256_set1_epi32, _mm256_setr_epi8, _mm256_setzero_si256, _mm256_shuffle_epi8,
    _mm256_sub_epi16,
};

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use thiserror::Error;

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use noq::udp::{RecvMeta, Transmit};
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use noq::{AsyncUdpSocket, UdpSender};
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use socket2::{Domain, Protocol, SockAddr, SockFilter, Socket, Type};
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use std::ffi::CString;
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use std::num::NonZeroUsize;
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use std::os::fd::AsRawFd;
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use std::pin::Pin;
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use std::task::{Context, Poll};
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use std::{mem, ptr};
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use tokio::io::unix::AsyncFd;

pub const TCP_PROTOCOL: u8 = 6;
const IPV4_HEADER_BYTES: usize = 20;
const IPV6_HEADER_BYTES: usize = 40;
const TCP_HEADER_BYTES: usize = 20;
const MAX_TCP_OPTIONS_BYTES: usize = 40;
const MAX_PACKET_BYTES: usize = u16::MAX as usize;
const MAX_DATAGRAM_BYTES: usize = MAX_PACKET_BYTES - IPV6_HEADER_BYTES - TCP_HEADER_BYTES;
const TFO_OPTION_KIND: u8 = 34;
const REPLAY_WINDOW_SIZE: usize = 64;
const REPLAY_WINDOW_BYTES: u32 = 64 * 65_535;
const SYN_MSS: u16 = 1460;
const SYN_WINDOW_SCALE: u8 = 7;
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
const RAW_PACKET_BUFFER_BYTES: usize = MAX_PACKET_BYTES;
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
const RAW_SEND_BATCH_SIZE: usize = 10;
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
const RAW_RECV_BATCH_SIZE: usize = 8;
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
const RAW_GRO_SEGMENTS: usize = 4;

/// The two underlay endpoints that identify one `FakeTCP` path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FourTuple {
    pub source: SocketAddr,
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
    ClientToServer,
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
    fast_open_cookie: Option<Vec<u8>>,
}

impl TcpOptions {
    #[must_use]
    pub fn for_syn(cookie: Option<&[u8]>) -> Self {
        Self {
            mss: Some(SYN_MSS),
            sack_permitted: true,
            timestamps: None,
            window_scale: Some(SYN_WINDOW_SCALE),
            fast_open_cookie: cookie.map(ToOwned::to_owned),
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
        self.fast_open_cookie.as_deref()
    }

    #[inline]
    const fn is_empty(&self) -> bool {
        self.mss.is_none()
            && !self.sack_permitted
            && self.timestamps.is_none()
            && self.window_scale.is_none()
            && self.fast_open_cookie.is_none()
    }

    fn encode(&self) -> Result<Vec<u8>, CarrierError> {
        let mut bytes = vec![0; MAX_TCP_OPTIONS_BYTES];
        let length = self.encode_into(&mut bytes)?;
        bytes.truncate(length);
        Ok(bytes)
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
        if let Some(cookie) = &self.fast_open_cookie {
            if cookie.len() > 16 {
                return Err(CarrierError::InvalidTcpOption);
            }
            let option_length = 2usize.saturating_add(cookie.len());
            let option_length =
                u8::try_from(option_length).map_err(|_| CarrierError::InvalidTcpOption)?;
            append_option(bytes, &mut length, &[TFO_OPTION_KIND, option_length])?;
            append_option(bytes, &mut length, cookie)?;
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
                            options.fast_open_cookie = Some(value.to_vec());
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
        let options = self.options.encode()?;
        let tcp_length = TCP_HEADER_BYTES
            .checked_add(options.len())
            .and_then(|length| length.checked_add(self.payload.len()))
            .ok_or(CarrierError::PacketTooLarge)?;
        if tcp_length > MAX_PACKET_BYTES {
            return Err(CarrierError::PacketTooLarge);
        }
        let tcp = self.encode_tcp(&options)?;
        if self.source.is_ipv4() {
            self.encode_ipv4(&tcp)
        } else {
            self.encode_ipv6(&tcp)
        }
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

    fn encode_tcp(&self, options: &[u8]) -> Result<Vec<u8>, CarrierError> {
        let header_length = TCP_HEADER_BYTES
            .checked_add(options.len())
            .ok_or(CarrierError::PacketTooLarge)?;
        let data_offset =
            u8::try_from(header_length / 4).map_err(|_| CarrierError::TcpOptionsTooLong)?;
        let mut tcp = Vec::with_capacity(header_length + self.payload.len());
        tcp.extend_from_slice(&self.source.port().to_be_bytes());
        tcp.extend_from_slice(&self.destination.port().to_be_bytes());
        tcp.extend_from_slice(&self.sequence.to_be_bytes());
        tcp.extend_from_slice(&self.acknowledgment.to_be_bytes());
        tcp.push(data_offset << 4);
        tcp.push(self.flags.bits());
        tcp.extend_from_slice(&self.window.to_be_bytes());
        tcp.extend_from_slice(&[0, 0]);
        tcp.extend_from_slice(&[0, 0]);
        tcp.extend_from_slice(options);
        tcp.extend_from_slice(&self.payload);
        let checksum = tcp_checksum(self.source, self.destination, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
        Ok(tcp)
    }

    fn encode_ipv4(&self, tcp: &[u8]) -> Result<Vec<u8>, CarrierError> {
        let source = match self.source.ip() {
            IpAddr::V4(value) => value,
            IpAddr::V6(_) => return Err(CarrierError::InvalidTuple),
        };
        let destination = match self.destination.ip() {
            IpAddr::V4(value) => value,
            IpAddr::V6(_) => return Err(CarrierError::InvalidTuple),
        };
        let total_length = IPV4_HEADER_BYTES
            .checked_add(tcp.len())
            .ok_or(CarrierError::PacketTooLarge)?;
        let total_length = u16::try_from(total_length).map_err(|_| CarrierError::PacketTooLarge)?;
        let mut packet = vec![0; IPV4_HEADER_BYTES];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total_length.to_be_bytes());
        packet[6] = 0x40;
        packet[8] = 64;
        packet[9] = TCP_PROTOCOL;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        let checksum = ipv4_header_checksum(source, destination, total_length);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet.extend_from_slice(tcp);
        Ok(packet)
    }

    fn encode_ipv6(&self, tcp: &[u8]) -> Result<Vec<u8>, CarrierError> {
        let source = match self.source.ip() {
            IpAddr::V6(value) => value,
            IpAddr::V4(_) => return Err(CarrierError::InvalidTuple),
        };
        let destination = match self.destination.ip() {
            IpAddr::V6(value) => value,
            IpAddr::V4(_) => return Err(CarrierError::InvalidTuple),
        };
        let payload_length = u16::try_from(tcp.len()).map_err(|_| CarrierError::PacketTooLarge)?;
        let mut packet = vec![0; IPV6_HEADER_BYTES];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&payload_length.to_be_bytes());
        packet[6] = TCP_PROTOCOL;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet.extend_from_slice(tcp);
        Ok(packet)
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
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    #[must_use]
    pub const fn was_syn(&self) -> bool {
        self.was_syn
    }

    #[must_use]
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
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    #[must_use]
    pub const fn was_syn(&self) -> bool {
        self.was_syn
    }

    #[must_use]
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
    acknowledgment: u32,
    received: ReplayWindow,
    sent_syn: bool,
}

impl FakeTcpCarrier {
    /// Creates one independent carrier state.  A changed four-tuple must create a new state.
    ///
    /// # Errors
    ///
    /// Returns an error for an unusable or mixed-family tuple.
    pub fn new(
        tuple: FourTuple,
        direction: CarrierDirection,
        syn_data: SynDataMode,
    ) -> Result<Self, CarrierError> {
        tuple.validate()?;
        let pseudo_header_prefix = tcp_pseudo_header_prefix(tuple.source, tuple.destination)
            .ok_or(CarrierError::InvalidTuple)?;
        let send_sequence = initial_sequence(tuple, direction)?;
        Ok(Self {
            tuple,
            pseudo_header_prefix,
            syn_data,
            send_sequence,
            acknowledgment: 0,
            received: ReplayWindow::default(),
            sent_syn: false,
        })
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
    /// Returns an error for a malformed, replayed, or wrong-path packet.
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
    /// The input is not retained after the method returns. The carrier sequence/replay state is
    /// updated before the borrowed result is returned.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed, replayed, or wrong-path packet.
    pub fn decode_datagram_borrowed<'a>(
        &mut self,
        packet: &'a [u8],
    ) -> Result<BorrowedDecodedDatagram<'a>, CarrierError> {
        let packet = decode_packet_view(packet, Some(self.pseudo_header_prefix))?;
        let expected = self.tuple.reverse();
        if packet.source != expected.source || packet.destination != expected.destination {
            return Err(CarrierError::WrongTuple);
        }
        if packet.payload.is_empty() {
            return Err(CarrierError::EmptyPayload);
        }
        if self.received.contains(packet.sequence) {
            return Err(CarrierError::Replay);
        }
        if packet.flags.is_syn() {
            let SynDataMode::Cookie(expected_cookie) = self.syn_data else {
                return Err(CarrierError::SynDataDisabled);
            };
            if packet.fast_open_cookie != Some(expected_cookie.as_slice()) {
                return Err(CarrierError::SynCookieRejected);
            }
        }
        self.received.accept(packet.sequence)?;
        if self.received.largest() == Some(packet.sequence) {
            let consumed = u32::try_from(packet.payload.len())
                .unwrap_or(u32::MAX)
                .saturating_add(u32::from(packet.flags.is_syn()));
            self.acknowledgment = packet.sequence.wrapping_add(consumed);
        }
        Ok(BorrowedDecodedDatagram {
            sequence: packet.sequence,
            was_syn: packet.flags.is_syn(),
            payload: packet.payload,
        })
    }

    #[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
    const fn sent_syn(&self) -> bool {
        self.sent_syn
    }

    fn encode(
        &mut self,
        datagram: &[u8],
        flags: TcpFlags,
        cookie: Option<&[u8]>,
    ) -> Result<Vec<u8>, CarrierError> {
        let ip_header_length = if self.tuple.source.is_ipv4() {
            IPV4_HEADER_BYTES
        } else {
            IPV6_HEADER_BYTES
        };
        let capacity = ip_header_length
            .checked_add(TCP_HEADER_BYTES)
            .and_then(|length| length.checked_add(MAX_TCP_OPTIONS_BYTES))
            .and_then(|length| length.checked_add(datagram.len()))
            .ok_or(CarrierError::PacketTooLarge)?;
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
            TcpOptions::for_syn(cookie)
        } else {
            TcpOptions::default()
        };
        let packet_length = encode_packet_into(
            self.tuple.source,
            self.tuple.destination,
            self.send_sequence,
            self.acknowledgment,
            flags,
            u16::MAX,
            &options,
            datagram,
            output,
            self.pseudo_header_prefix,
        )?;
        self.send_sequence = self
            .send_sequence
            .checked_add(consumed)
            .ok_or(CarrierError::SequenceExhausted)?;
        Ok(packet_length)
    }
}

/// A Linux raw-IP adapter that presents `FakeTCP` packets to the current `noq` backend as datagrams.
///
/// One adapter is bound to one four-tuple. Multipath therefore creates one adapter state per
/// QUICP path while retaining one QUICP session and session ID above them. `noq` is an
/// implementation backend here, not the QUICP wire contract. The adapter is intentionally
/// Linux-only until equivalent source-address and raw-socket controls are verified on another
/// operating system. Receive uses an `IPPROTO_TCP` raw socket for tuple filtering. Transmit uses
/// the default `IPPROTO_TCP` raw socket without `IP_HDRINCL`; the explicit `packet_socket` option
/// switches both directions to filtered `AF_PACKET` sockets and requires a resolvable
/// interface/neighbor. On Linux, the packet receive socket opportunistically uses a bounded
/// `TPACKET_V2` ring (64 128-KiB frames) and falls back to `recvmmsg` when the kernel cannot set
/// up the ring.
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
const PACKET_RING_FRAME_SIZE: usize = 128 * 1024;
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
const PACKET_RING_FRAME_COUNT: usize = 64;

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
const PACKET_VERSION_OPTION: libc::c_int = 10;
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
const PACKET_RX_RING_OPTION: libc::c_int = 5;
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
const PACKET_TPACKET_V2: libc::c_int = 1;

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[derive(Debug)]
struct PacketRxRing {
    mapping: std::ptr::NonNull<u8>,
    mapping_len: usize,
    frame_size: usize,
    frame_count: usize,
    next_frame: usize,
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[allow(unsafe_code)]
unsafe impl Send for PacketRxRing {}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[allow(unsafe_code)]
unsafe impl Sync for PacketRxRing {}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
impl PacketRxRing {
    fn try_new(socket: &Socket) -> Option<Self> {
        Self::new(socket).ok()
    }

    #[allow(unsafe_code)]
    fn new(socket: &Socket) -> std::io::Result<Self> {
        let version = PACKET_TPACKET_V2;
        set_packet_option(socket, PACKET_VERSION_OPTION, &version)?;
        let block_size = PACKET_RING_FRAME_SIZE;
        let block_count = PACKET_RING_FRAME_COUNT;
        let frame_size = PACKET_RING_FRAME_SIZE;
        let frame_count = PACKET_RING_FRAME_COUNT;
        let request = libc::tpacket_req {
            tp_block_size: libc::c_uint::try_from(block_size)
                .expect("packet ring block size fits c_uint"),
            tp_block_nr: libc::c_uint::try_from(block_count)
                .expect("packet ring block count fits c_uint"),
            tp_frame_size: libc::c_uint::try_from(frame_size)
                .expect("packet ring frame size fits c_uint"),
            tp_frame_nr: libc::c_uint::try_from(frame_count)
                .expect("packet ring frame count fits c_uint"),
        };
        set_packet_option(socket, PACKET_RX_RING_OPTION, &request)?;
        let mapping_len = block_size.checked_mul(block_count).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "packet ring size overflow",
            )
        })?;
        let mapping = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mapping_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                socket.as_raw_fd(),
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            let error = std::io::Error::last_os_error();
            let _ = clear_packet_ring(socket);
            return Err(error);
        }
        let Some(mapping) = std::ptr::NonNull::new(mapping.cast::<u8>()) else {
            let _ = clear_packet_ring(socket);
            return Err(std::io::Error::other(
                "packet ring mmap returned a null pointer",
            ));
        };
        Ok(Self {
            mapping,
            mapping_len,
            frame_size,
            frame_count,
            next_frame: 0,
        })
    }

    #[allow(unsafe_code)]
    fn with_next_packet<T, F>(&mut self, callback: F) -> std::io::Result<Option<T>>
    where
        F: FnOnce(&[u8]) -> std::io::Result<T>,
    {
        let frame_offset = self
            .next_frame
            .checked_mul(self.frame_size)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "packet ring frame offset overflow",
                )
            })?;
        let frame = unsafe { self.mapping.as_ptr().add(frame_offset) };
        let header = frame.cast::<libc::tpacket2_hdr>();
        let status = unsafe { ptr::read_volatile(ptr::addr_of!((*header).tp_status)) };
        if status & libc::TP_STATUS_USER == 0 {
            return Ok(None);
        }
        fence(Ordering::Acquire);
        let snaplen =
            usize::try_from(unsafe { ptr::read_unaligned(ptr::addr_of!((*header).tp_snaplen)) })
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "packet ring snaplen overflow",
                    )
                });
        let snaplen = match snaplen {
            Ok(snaplen) => snaplen,
            Err(error) => {
                self.release_frame(header);
                return Err(error);
            }
        };
        let packet_offset =
            unsafe { usize::from(ptr::read_unaligned(ptr::addr_of!((*header).tp_mac))) };
        let packet_end = packet_offset.checked_add(snaplen);
        let packet_end = match packet_end {
            Some(end) if end <= self.frame_size => end,
            _ => {
                self.release_frame(header);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "packet ring packet exceeds frame",
                ));
            }
        };
        let packet = unsafe {
            std::slice::from_raw_parts(frame.add(packet_offset), packet_end - packet_offset)
        };
        let result = callback(packet);
        self.release_frame(header);
        result.map(Some)
    }

    #[allow(unsafe_code)]
    fn has_user_frame(&self) -> std::io::Result<bool> {
        let frame_offset = self
            .next_frame
            .checked_mul(self.frame_size)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "packet ring frame offset overflow",
                )
            })?;
        let frame = unsafe { self.mapping.as_ptr().add(frame_offset) };
        let header = frame.cast::<libc::tpacket2_hdr>();
        let status = unsafe { ptr::read_volatile(ptr::addr_of!((*header).tp_status)) };
        Ok(status & libc::TP_STATUS_USER != 0)
    }

    #[allow(unsafe_code)]
    fn release_frame(&mut self, header: *mut libc::tpacket2_hdr) {
        fence(Ordering::Release);
        unsafe {
            ptr::write_volatile(
                ptr::addr_of_mut!((*header).tp_status),
                libc::TP_STATUS_KERNEL,
            );
        }
        self.next_frame = (self.next_frame + 1) % self.frame_count;
    }
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
impl Drop for PacketRxRing {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        unsafe {
            let _ = libc::munmap(self.mapping.as_ptr().cast(), self.mapping_len);
        }
    }
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[allow(unsafe_code)]
fn set_packet_option<T>(socket: &Socket, option: libc::c_int, value: &T) -> std::io::Result<()> {
    let length = libc::socklen_t::try_from(mem::size_of::<T>())
        .expect("packet socket option size fits socklen_t");
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_PACKET,
            option,
            std::ptr::from_ref(value).cast(),
            length,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[allow(unsafe_code)]
fn clear_packet_ring(socket: &Socket) -> std::io::Result<()> {
    let request = libc::tpacket_req {
        tp_block_size: 0,
        tp_block_nr: 0,
        tp_frame_size: 0,
        tp_frame_nr: 0,
    };
    set_packet_option(socket, PACKET_RX_RING_OPTION, &request)
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[derive(Debug)]
pub struct FakeTcpSocket {
    io: Arc<AsyncFd<Socket>>,
    send_io: Arc<AsyncFd<Socket>>,
    receive_ring: Option<PacketRxRing>,
    send_mode: RawSendMode,
    tuple: FourTuple,
    inbound: FakeTcpCarrier,
    outbound: Arc<Mutex<FakeTcpCarrier>>,
    server_side: bool,
    receive_buffer: Vec<u8>,
    receive_batch_count: usize,
    receive_batch_index: usize,
    receive_batch_lengths: [usize; RAW_RECV_BATCH_SIZE],
    receive_pending: Option<DecodedRawPacket>,
    receive_direct_pending: Option<usize>,
    decode_rejects: u64,
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[derive(Clone, Copy, Debug)]
struct DecodedRawPacket {
    batch_index: usize,
    payload_offset: usize,
    payload_length: usize,
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[derive(Clone, Copy, Debug)]
enum RingPayloadCopy {
    Skipped,
    Copied(usize),
    Pending(usize),
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[derive(Clone, Copy, Debug)]
enum RawSendMode {
    Ip,
    Packet,
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[derive(Clone, Copy, Debug)]
struct PacketTarget {
    ifindex: libc::c_int,
    destination: [u8; 6],
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
impl FakeTcpSocket {
    /// Binds a raw IPv4 TCP socket for one `FakeTCP` path.
    ///
    /// # Errors
    ///
    /// Returns an OS error when raw-socket privileges, binding, or nonblocking setup is denied.
    pub fn bind(
        tuple: FourTuple,
        outbound_direction: CarrierDirection,
        syn_data: SynDataMode,
        packet_socket: bool,
    ) -> std::io::Result<Self> {
        tuple.validate().map_err(carrier_io_error)?;
        if !tuple.source.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "FakeTcpSocket currently supports IPv4 raw sockets only",
            ));
        }
        let packet_target = packet_socket
            .then(|| resolve_packet_target(tuple.destination))
            .transpose()?;
        let (socket, receive_ring) = if let Some(target) = packet_target {
            let socket = Socket::new(
                Domain::PACKET,
                Type::DGRAM,
                Some(Protocol::from(libc::c_int::from(packet_protocol()))),
            )?;
            socket.attach_filter(&tuple_filter(tuple)?)?;
            let receive_ring = PacketRxRing::try_new(&socket);
            bind_packet_receive_socket(&socket, target)?;
            (socket, receive_ring)
        } else {
            let socket = Socket::new_raw(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
            socket.set_header_included_v4(true)?;
            socket.bind(&SockAddr::from(tuple.source))?;
            socket.attach_filter(&tuple_filter(tuple)?)?;
            (socket, None)
        };
        socket.set_nonblocking(true)?;
        let io = Arc::new(AsyncFd::new(socket)?);
        let (send_socket, send_mode) = if let Some(target) = packet_target {
            let socket = Socket::new(
                Domain::PACKET,
                Type::DGRAM,
                Some(Protocol::from(libc::c_int::from(packet_protocol()))),
            )?;
            bind_packet_socket(&socket, target)?;
            (socket, RawSendMode::Packet)
        } else {
            let socket = Socket::new_raw(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
            socket.set_header_included_v4(false)?;
            socket.bind(&SockAddr::from(tuple.source))?;
            (socket, RawSendMode::Ip)
        };
        send_socket.set_nonblocking(true)?;
        let send_io = Arc::new(AsyncFd::new(send_socket)?);
        let inbound =
            FakeTcpCarrier::new(tuple, outbound_direction, syn_data).map_err(carrier_io_error)?;
        let outbound =
            FakeTcpCarrier::new(tuple, outbound_direction, syn_data).map_err(carrier_io_error)?;
        Ok(Self {
            io,
            send_io,
            receive_ring,
            send_mode,
            tuple,
            inbound,
            outbound: Arc::new(Mutex::new(outbound)),
            server_side: outbound_direction == CarrierDirection::ServerToClient,
            receive_buffer: vec![0; RAW_PACKET_BUFFER_BYTES * RAW_RECV_BATCH_SIZE],
            receive_batch_count: 0,
            receive_batch_index: 0,
            receive_batch_lengths: [0; RAW_RECV_BATCH_SIZE],
            receive_pending: None,
            receive_direct_pending: None,
            decode_rejects: 0,
        })
    }

    /// Number of underlay packets that failed carrier decode and were dropped.
    #[must_use]
    pub const fn rejected_datagrams(&self) -> u64 {
        self.decode_rejects
    }

    fn next_decoded_packet(&mut self) -> std::io::Result<Option<DecodedRawPacket>> {
        if let Some(packet) = self.receive_pending.take() {
            return Ok(Some(packet));
        }
        while self.receive_batch_index < self.receive_batch_count {
            let batch_index = self.receive_batch_index;
            self.receive_batch_index += 1;
            let length = self.receive_batch_lengths[batch_index];
            let start = batch_index * RAW_PACKET_BUFFER_BYTES;
            let end = start.checked_add(length).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "raw packet length overflow",
                )
            })?;
            let Some(packet) = self.receive_buffer.get(start..end) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "raw packet exceeds receive storage",
                ));
            };
            let decoded = match self.inbound.decode_datagram_borrowed(packet) {
                Ok(decoded) => decoded,
                Err(_error) => {
                    self.decode_rejects = self.decode_rejects.saturating_add(1);
                    continue;
                }
            };
            let payload_length = decoded.payload().len();
            return Ok(Some(DecodedRawPacket {
                batch_index,
                payload_offset: length - payload_length,
                payload_length,
            }));
        }
        Ok(None)
    }

    fn decoded_payload(&self, packet: DecodedRawPacket) -> std::io::Result<&[u8]> {
        let packet_start = packet.batch_index * RAW_PACKET_BUFFER_BYTES;
        let payload_start = packet_start
            .checked_add(packet.payload_offset)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "raw payload offset overflow",
                )
            })?;
        let payload_end = payload_start
            .checked_add(packet.payload_length)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "raw payload length overflow",
                )
            })?;
        self.receive_buffer
            .get(payload_start..payload_end)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "raw payload exceeds receive storage",
                )
            })
    }

    fn copy_next_ring_payload(
        &mut self,
        target: &mut [u8],
        offset: usize,
        expected_stride: Option<usize>,
    ) -> std::io::Result<Option<RingPayloadCopy>> {
        let Some(ring) = self.receive_ring.as_mut() else {
            return Err(std::io::Error::other("FakeTCP receive ring is unavailable"));
        };
        let inbound = &mut self.inbound;
        let pending_storage = &mut self.receive_buffer;
        let outcome = ring.with_next_packet(|packet| {
            let decoded = match inbound.decode_datagram_borrowed(packet) {
                Ok(decoded) => decoded,
                Err(_error) => return Ok(RingPayloadCopy::Skipped),
            };
            let payload = decoded.payload();
            if payload.len() > RAW_PACKET_BUFFER_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "QUICP payload exceeds receive storage",
                ));
            }
            let same_stride = expected_stride.is_none_or(|stride| stride == payload.len());
            if same_stride {
                let end = offset.checked_add(payload.len()).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "QUICP payload offset overflow",
                    )
                })?;
                let Some(destination) = target.get_mut(offset..end) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "QUICP payload exceeds receive buffer",
                    ));
                };
                destination.copy_from_slice(payload);
                Ok(RingPayloadCopy::Copied(payload.len()))
            } else {
                pending_storage[..payload.len()].copy_from_slice(payload);
                Ok(RingPayloadCopy::Pending(payload.len()))
            }
        })?;
        if matches!(outcome, Some(RingPayloadCopy::Skipped)) {
            self.decode_rejects = self.decode_rejects.saturating_add(1);
        }
        Ok(outcome)
    }

    #[allow(clippy::too_many_lines)]
    fn poll_recv_ring(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let slots = bufs.len().min(meta.len());
        let mut received_count = 0;
        loop {
            while received_count < slots {
                let mut stride = None;
                let mut group_count = 0;
                loop {
                    if group_count >= RAW_GRO_SEGMENTS {
                        break;
                    }
                    if let Some(stride) = stride {
                        let Some(end) = group_count
                            .checked_add(1)
                            .and_then(|count| count.checked_mul(stride))
                        else {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "QUICP receive group length overflow",
                            )));
                        };
                        if end > bufs[received_count].len() {
                            break;
                        }
                    }
                    let copied = if let Some(length) = self.receive_direct_pending.take() {
                        let Some(destination) = bufs[received_count]
                            .get_mut(group_count * length..(group_count + 1) * length)
                        else {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "pending QUICP payload exceeds receive buffer",
                            )));
                        };
                        destination.copy_from_slice(&self.receive_buffer[..length]);
                        Some(RingPayloadCopy::Copied(length))
                    } else {
                        self.copy_next_ring_payload(
                            &mut bufs[received_count],
                            group_count * stride.unwrap_or(0),
                            stride,
                        )?
                    };
                    match copied {
                        None => {
                            if group_count == 0 {
                                break;
                            }
                            break;
                        }
                        Some(RingPayloadCopy::Skipped) => {}
                        Some(RingPayloadCopy::Copied(length)) => {
                            if stride.is_none() {
                                stride = Some(length);
                            }
                            group_count += 1;
                        }
                        Some(RingPayloadCopy::Pending(length)) => {
                            self.receive_direct_pending = Some(length);
                            break;
                        }
                    }
                }
                let Some(stride) = stride else {
                    break;
                };
                let mut received = RecvMeta::default();
                received.addr = self.tuple.destination;
                received.len = group_count * stride;
                received.stride = stride;
                received.dst_ip = Some(self.tuple.source.ip());
                meta[received_count] = received;
                received_count += 1;
            }

            let mut guard = match self.io.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending if received_count > 0 => return Poll::Ready(Ok(received_count)),
                Poll::Pending => return Poll::Pending,
            };
            let result = guard.try_io(|_| {
                let Some(ring) = self.receive_ring.as_ref() else {
                    return Err(std::io::Error::other("FakeTCP receive ring is unavailable"));
                };
                if ring.has_user_frame()? {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "packet ring has no user-owned frames",
                    ))
                }
            });
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_would_block) if received_count > 0 => {
                    return Poll::Ready(Ok(received_count));
                }
                Err(_would_block) => return Poll::Pending,
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
fn resolve_packet_target(destination: SocketAddr) -> std::io::Result<PacketTarget> {
    let IpAddr::V4(destination) = destination.ip() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "AF_PACKET FakeTCP transmit currently supports IPv4 only",
        ));
    };
    if destination.is_loopback() {
        return Ok(PacketTarget {
            ifindex: interface_index("lo")?,
            destination: [0; 6],
        });
    }
    let route = best_route(destination)?;
    let next_hop = if route.gateway == 0 {
        destination
    } else {
        Ipv4Addr::from(route.gateway)
    };
    Ok(PacketTarget {
        ifindex: interface_index(&route.interface)?,
        destination: arp_neighbor(route.interface.as_str(), next_hop)?,
    })
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[derive(Debug)]
struct RouteEntry {
    interface: String,
    gateway: u32,
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
fn best_route(destination: Ipv4Addr) -> std::io::Result<RouteEntry> {
    let destination = u32::from(destination);
    let contents = std::fs::read_to_string("/proc/net/route")?;
    let mut best: Option<(u32, RouteEntry)> = None;
    for line in contents.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let (Ok(route_destination), Ok(gateway), Ok(flags), Ok(mask)) = (
            u32::from_str_radix(fields[1], 16),
            u32::from_str_radix(fields[2], 16),
            u32::from_str_radix(fields[3], 16),
            u32::from_str_radix(fields[7], 16),
        ) else {
            continue;
        };
        let mask = u32::from_le(mask);
        if flags & 1 == 0 || destination & mask != u32::from_le(route_destination) & mask {
            continue;
        }
        let prefix = mask.count_ones();
        if best.as_ref().is_some_and(|(current, _)| *current >= prefix) {
            continue;
        }
        best = Some((
            prefix,
            RouteEntry {
                interface: fields[0].to_owned(),
                gateway: u32::from_le(gateway),
            },
        ));
    }
    best.map(|(_, route)| route).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no usable IPv4 route for AF_PACKET FakeTCP transmit",
        )
    })
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
fn arp_neighbor(interface: &str, address: Ipv4Addr) -> std::io::Result<[u8; 6]> {
    let contents = std::fs::read_to_string("/proc/net/arp")?;
    for line in contents.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 6 || fields[0] != address.to_string() || fields[5] != interface {
            continue;
        }
        let Ok(flags) = u32::from_str_radix(fields[2], 16) else {
            continue;
        };
        if flags & 0x2 == 0 {
            continue;
        }
        let octets: Vec<_> = fields[3]
            .split(':')
            .filter_map(|part| u8::from_str_radix(part, 16).ok())
            .collect();
        if octets.len() == 6 && octets.iter().any(|octet| *octet != 0) {
            let address = octets.as_slice().try_into().expect("six-byte ARP address");
            return Ok(address);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no resolved ARP neighbor for AF_PACKET FakeTCP transmit",
    ))
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[allow(unsafe_code)]
fn interface_index(interface: &str) -> std::io::Result<libc::c_int> {
    let name = CString::new(interface).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name contains NUL",
        )
    })?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(std::io::Error::last_os_error());
    }
    libc::c_int::try_from(index).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "interface index overflows c_int",
        )
    })
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
fn packet_sockaddr(target: PacketTarget) -> libc::sockaddr_ll {
    let mut address = [0; 8];
    address[..target.destination.len()].copy_from_slice(&target.destination);
    libc::sockaddr_ll {
        sll_family: libc::c_ushort::try_from(libc::AF_PACKET).expect("AF_PACKET fits c_ushort"),
        sll_protocol: packet_protocol(),
        sll_ifindex: target.ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: if target.destination == [0; 6] { 0 } else { 6 },
        sll_addr: address,
    }
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
fn packet_protocol() -> libc::c_ushort {
    u16::try_from(libc::ETH_P_IP)
        .expect("ETH_P_IP fits u16")
        .to_be()
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[allow(unsafe_code)]
fn bind_packet_socket(socket: &Socket, target: PacketTarget) -> std::io::Result<()> {
    let address = packet_sockaddr(target);
    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_ll>())
                .expect("sockaddr_ll size fits socklen_t"),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[allow(unsafe_code)]
fn bind_packet_receive_socket(socket: &Socket, target: PacketTarget) -> std::io::Result<()> {
    let address = packet_sockaddr(PacketTarget {
        ifindex: target.ifindex,
        destination: [0; 6],
    });
    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_ll>())
                .expect("sockaddr_ll size fits socklen_t"),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
fn tuple_filter(tuple: FourTuple) -> std::io::Result<[SockFilter; 18]> {
    // ponytail: fixed IPv4/TCP offsets match this encoder; use an IHL-aware filter if
    // externally supplied packets with IPv4 options become supported.
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (tuple.destination.ip(), tuple.source.ip())
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "FakeTCP tuple filter currently supports IPv4 only",
        ));
    };
    let source = u32::from_be_bytes(source.octets());
    let destination = u32::from_be_bytes(destination.octets());
    let source_port = u32::from(tuple.destination.port());
    let destination_port = u32::from(tuple.source.port());
    Ok([
        SockFilter::new(0x30, 0, 0, 0),
        SockFilter::new(0x54, 0, 0, 0xf0),
        SockFilter::new(0x15, 0, 14, 0x40),
        SockFilter::new(0x30, 0, 0, 9),
        SockFilter::new(0x15, 0, 12, u32::from(TCP_PROTOCOL)),
        SockFilter::new(0x20, 0, 0, 12),
        SockFilter::new(0x15, 0, 10, source),
        SockFilter::new(0x20, 0, 0, 16),
        SockFilter::new(0x15, 0, 8, destination),
        SockFilter::new(0x28, 0, 0, 20),
        SockFilter::new(0x15, 0, 6, source_port),
        SockFilter::new(0x28, 0, 0, 22),
        SockFilter::new(0x15, 0, 4, destination_port),
        SockFilter::new(0x30, 0, 0, 33),
        SockFilter::new(0x54, 0, 0, 0x0a),
        SockFilter::new(0x15, 1, 0, 0),
        SockFilter::new(0x06, 0, 0, u32::MAX),
        SockFilter::new(0x06, 0, 0, 0),
    ])
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[allow(unsafe_code, clippy::too_many_arguments, clippy::too_many_lines)]
fn send_raw_batch(
    socket: &Socket,
    destination: &SockAddr,
    mode: RawSendMode,
    storage: &[u8],
    packet_capacity: usize,
    lengths: &[usize],
    first: usize,
) -> std::io::Result<usize> {
    let count = lengths.len().saturating_sub(first).min(RAW_SEND_BATCH_SIZE);
    if count == 0 {
        return Ok(0);
    }

    let packet_at = |index: usize| -> std::io::Result<&[u8]> {
        let length = lengths[index];
        let offset = index.checked_mul(packet_capacity).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "header offset overflow")
        })?;
        storage
            .get(
                offset..offset.checked_add(length).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "header length overflow")
                })?,
            )
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "packet header exceeds send storage",
                )
            })
    };

    let wire_packet = |index: usize| -> std::io::Result<&[u8]> {
        let packet = packet_at(index)?;
        match mode {
            RawSendMode::Ip => Ok(packet.get(IPV4_HEADER_BYTES..).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "raw packet is missing an IPv4 header",
                )
            })?),
            RawSendMode::Packet => Ok(packet),
        }
    };

    if count == 1 {
        let packet = wire_packet(first)?;
        let sent = match mode {
            RawSendMode::Ip => socket.send_to(packet, destination)?,
            RawSendMode::Packet => socket.send(packet)?,
        };
        if sent != packet.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "raw FakeTCP packet was only partially sent",
            ));
        }
        return Ok(1);
    }

    let mut iovs = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }; RAW_SEND_BATCH_SIZE];
    let mut messages = unsafe { mem::zeroed::<[libc::mmsghdr; RAW_SEND_BATCH_SIZE]>() };
    for (index, message) in messages.iter_mut().enumerate().take(count) {
        let packet = wire_packet(first + index)?;
        iovs[index].iov_base = packet.as_ptr().cast_mut().cast();
        iovs[index].iov_len = packet.len();
        let (address, length) = match mode {
            RawSendMode::Ip => (destination.as_ptr().cast_mut().cast(), destination.len()),
            RawSendMode::Packet => (ptr::null_mut(), 0),
        };
        message.msg_hdr.msg_name = address;
        message.msg_hdr.msg_namelen = length;
        message.msg_hdr.msg_iov = &raw mut iovs[index];
        message.msg_hdr.msg_iovlen = 1;
    }
    let sent = loop {
        // SAFETY: every iovec points into `storage`, which remains borrowed for the syscall;
        // each destination pointer refers to the live `SockAddr` argument.
        let sent = unsafe {
            libc::sendmmsg(
                socket.as_raw_fd(),
                messages.as_mut_ptr(),
                libc::c_uint::try_from(count).expect("raw send batch size fits libc"),
                0,
            )
        };
        if sent >= 0 {
            break usize::try_from(sent).expect("successful sendmmsg count is non-negative");
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    };
    for (index, message) in messages.iter().enumerate().take(sent) {
        if message.msg_len as usize != wire_packet(first + index)?.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "raw FakeTCP packet was only partially sent",
            ));
        }
    }
    Ok(sent)
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[allow(unsafe_code)]
fn receive_raw_batch(
    socket: &Socket,
    storage: &mut [u8],
    lengths: &mut [usize; RAW_RECV_BATCH_SIZE],
) -> std::io::Result<usize> {
    let mut iovs = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }; RAW_RECV_BATCH_SIZE];
    let mut messages = unsafe { mem::zeroed::<[libc::mmsghdr; RAW_RECV_BATCH_SIZE]>() };
    for index in 0..RAW_RECV_BATCH_SIZE {
        let offset = index.checked_mul(RAW_PACKET_BUFFER_BYTES).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "raw receive offset overflow",
            )
        })?;
        let packet = storage
            .get_mut(offset..offset + RAW_PACKET_BUFFER_BYTES)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "raw receive storage is too small",
                )
            })?;
        iovs[index].iov_base = packet.as_mut_ptr().cast();
        iovs[index].iov_len = packet.len();
        messages[index].msg_hdr.msg_iov = &raw mut iovs[index];
        messages[index].msg_hdr.msg_iovlen = 1;
    }
    let received = loop {
        // SAFETY: every iovec points into `storage`, and the storage and message arrays remain
        // borrowed until the syscall returns.
        let received = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                messages.as_mut_ptr(),
                libc::c_uint::try_from(RAW_RECV_BATCH_SIZE)
                    .expect("raw receive batch size fits libc"),
                0,
                ptr::null_mut(),
            )
        };
        if received >= 0 {
            break usize::try_from(received).expect("successful recvmmsg count is non-negative");
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    };
    for (index, length) in lengths.iter_mut().enumerate().take(received) {
        if messages[index].msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "raw FakeTCP packet was truncated",
            ));
        }
        *length = usize::try_from(messages[index].msg_len).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "raw packet length overflow",
            )
        })?;
    }
    Ok(received)
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
impl AsyncUdpSocket for FakeTcpSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(FakeTcpSender {
            io: Arc::clone(&self.send_io),
            send_mode: self.send_mode,
            tuple: self.tuple,
            carrier: Arc::clone(&self.outbound),
            server_side: self.server_side,
            pending: vec![0; RAW_PACKET_BUFFER_BYTES],
            pending_segment: 0,
            pending_segments: 0,
            pending_segment_size: 0,
            pending_batch_count: 0,
            pending_batch_sent: 0,
            pending_batch_capacity: 0,
            pending_batch_lengths: [0; RAW_SEND_BATCH_SIZE],
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no receive buffer",
            )));
        }
        let slots = bufs.len().min(meta.len());
        if self.receive_ring.is_some() {
            return self.poll_recv_ring(cx, bufs, meta);
        }
        let mut received_count = 0;
        loop {
            while received_count < slots {
                let Some(first) = self.next_decoded_packet()? else {
                    break;
                };
                let stride = first.payload_length;
                if stride > bufs[received_count].len() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "QUICP datagram exceeds receive buffer",
                    )));
                }
                let max_group = bufs[received_count]
                    .len()
                    .checked_div(stride.max(1))
                    .unwrap_or(1)
                    .clamp(1, RAW_GRO_SEGMENTS);
                let first_payload = self.decoded_payload(first)?;
                bufs[received_count][..stride].copy_from_slice(first_payload);
                let mut group_count = 1;
                while group_count < max_group {
                    let Some(next) = self.next_decoded_packet()? else {
                        break;
                    };
                    if next.payload_length != stride {
                        self.receive_pending = Some(next);
                        break;
                    }
                    let payload = self.decoded_payload(next)?;
                    let start = group_count * stride;
                    bufs[received_count][start..start + stride].copy_from_slice(payload);
                    group_count += 1;
                }
                let mut received = RecvMeta::default();
                received.addr = self.tuple.destination;
                received.len = group_count * stride;
                received.stride = stride;
                received.dst_ip = Some(self.tuple.source.ip());
                meta[received_count] = received;
                received_count += 1;
                if received_count == slots {
                    return Poll::Ready(Ok(received_count));
                }
            }
            self.receive_batch_count = 0;
            self.receive_batch_index = 0;

            let mut guard = match self.io.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending if received_count > 0 => return Poll::Ready(Ok(received_count)),
                Poll::Pending => return Poll::Pending,
            };
            let result = guard.try_io(|inner| {
                receive_raw_batch(
                    inner.get_ref(),
                    &mut self.receive_buffer,
                    &mut self.receive_batch_lengths,
                )
            });
            match result {
                Ok(Ok(count)) if count > 0 => {
                    self.receive_batch_count = count;
                }
                Ok(Ok(_)) => {
                    if received_count > 0 {
                        return Poll::Ready(Ok(received_count));
                    }
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_would_block) if received_count > 0 => {
                    return Poll::Ready(Ok(received_count));
                }
                Err(_would_block) => {}
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.tuple.source)
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        // Reuse noq's GRO contract to amortize one BytesMut copy over a bounded packet group.
        NonZeroUsize::new(RAW_GRO_SEGMENTS).expect("non-zero receive segment batch")
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
#[derive(Debug)]
struct FakeTcpSender {
    io: Arc<AsyncFd<Socket>>,
    send_mode: RawSendMode,
    tuple: FourTuple,
    carrier: Arc<Mutex<FakeTcpCarrier>>,
    server_side: bool,
    pending: Vec<u8>,
    pending_segment: usize,
    pending_segments: usize,
    pending_segment_size: usize,
    pending_batch_count: usize,
    pending_batch_sent: usize,
    pending_batch_capacity: usize,
    pending_batch_lengths: [usize; RAW_SEND_BATCH_SIZE],
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
impl UdpSender for FakeTcpSender {
    #[allow(clippy::too_many_lines)]
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if transmit.destination != self.tuple.destination {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "FakeTCP sender destination does not match its path",
            )));
        }
        if transmit
            .src_ip
            .is_some_and(|source| source != self.tuple.source.ip())
        {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "FakeTCP sender source does not match its path",
            )));
        }
        let destination = SockAddr::from(self.tuple.destination);
        if self.pending_segments == 0 {
            let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
            if segment_size == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "FakeTCP sender received invalid segmentation metadata",
                )));
            }
            self.pending_segment_size = segment_size;
            self.pending_segments = transmit.contents.len().div_ceil(segment_size);
        }
        loop {
            if self.pending_batch_count == 0 {
                let this = self.as_mut().get_mut();
                let remaining = this.pending_segments - this.pending_segment;
                let batch_count = remaining.min(RAW_SEND_BATCH_SIZE);
                let server_side = this.server_side;
                let Ok(mut carrier) = this.carrier.lock() else {
                    return Poll::Ready(Err(std::io::Error::other("FakeTCP send state poisoned")));
                };
                let ip_header_bytes = if this.tuple.source.is_ipv4() {
                    IPV4_HEADER_BYTES
                } else {
                    IPV6_HEADER_BYTES
                };
                let packet_capacity = this
                    .pending_segment_size
                    .checked_add(ip_header_bytes + TCP_HEADER_BYTES + MAX_TCP_OPTIONS_BYTES)
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "raw FakeTCP packet capacity overflow",
                        )
                    });
                let packet_capacity = match packet_capacity {
                    Ok(capacity) => capacity,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                let Some(storage_len) = packet_capacity.checked_mul(batch_count) else {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "raw FakeTCP header batch capacity overflow",
                    )));
                };
                if this.pending.len() < storage_len {
                    this.pending.resize(storage_len, 0);
                }
                for index in 0..batch_count {
                    let segment = this.pending_segment + index;
                    let start = segment * this.pending_segment_size;
                    let end = (start + this.pending_segment_size).min(transmit.contents.len());
                    let output_start = index * packet_capacity;
                    let output_end = output_start + packet_capacity;
                    let encoded = if carrier.sent_syn() {
                        carrier.encode_datagram_into(
                            &transmit.contents[start..end],
                            &mut this.pending[output_start..output_end],
                        )
                    } else if server_side {
                        carrier.encode_syn_ack_into(
                            &transmit.contents[start..end],
                            &mut this.pending[output_start..output_end],
                        )
                    } else {
                        carrier.encode_syn_into(
                            &transmit.contents[start..end],
                            &mut this.pending[output_start..output_end],
                        )
                    };
                    match encoded.map_err(carrier_io_error) {
                        Ok(length) => this.pending_batch_lengths[index] = length,
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
                this.pending_batch_count = batch_count;
                this.pending_batch_sent = 0;
                this.pending_batch_capacity = packet_capacity;
            }
            let mut guard = match self.io.poll_write_ready(cx) {
                Poll::Ready(result) => match result {
                    Ok(guard) => guard,
                    Err(error) => return Poll::Ready(Err(error)),
                },
                Poll::Pending => return Poll::Pending,
            };
            let result = guard.try_io(|inner| {
                send_raw_batch(
                    inner.get_ref(),
                    &destination,
                    self.send_mode,
                    &self.pending,
                    self.pending_batch_capacity,
                    &self.pending_batch_lengths[..self.pending_batch_count],
                    self.pending_batch_sent,
                )
            });
            match result {
                Ok(Ok(sent)) => {
                    if sent == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "raw FakeTCP batch sent no packets",
                        )));
                    }
                    self.pending_batch_sent += sent;
                    self.pending_segment += sent;
                    if self.pending_batch_sent == self.pending_batch_count {
                        self.pending_batch_count = 0;
                        self.pending_batch_sent = 0;
                        self.pending_batch_capacity = 0;
                    }
                    if self.pending_segment == self.pending_segments {
                        self.pending_segment = 0;
                        self.pending_segments = 0;
                        self.pending_segment_size = 0;
                        return Poll::Ready(Ok(()));
                    }
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_would_block) => {}
            }
        }
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::new(RAW_SEND_BATCH_SIZE).expect("non-zero segment batch")
    }
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
fn carrier_io_error(error: CarrierError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

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

#[derive(Clone, Debug)]
struct ReplayWindow {
    sequences: [u32; REPLAY_WINDOW_SIZE],
    len: usize,
    next: usize,
    largest: Option<u32>,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            sequences: [0; REPLAY_WINDOW_SIZE],
            len: 0,
            next: 0,
            largest: None,
        }
    }
}

impl ReplayWindow {
    const fn largest(&self) -> Option<u32> {
        self.largest
    }

    fn contains(&self, sequence: u32) -> bool {
        if let Some(largest) = self.largest {
            let forward = sequence.wrapping_sub(largest);
            if forward != 0 && forward < 0x8000_0000 {
                return false;
            }
        }
        self.sequences[..self.len].contains(&sequence)
    }

    fn accept(&mut self, sequence: u32) -> Result<(), CarrierError> {
        if self.contains(sequence) {
            return Err(CarrierError::Replay);
        }
        if let Some(largest) = self.largest {
            let forward = sequence.wrapping_sub(largest);
            if forward < 0x8000_0000 {
                self.largest = Some(sequence);
            } else if largest.wrapping_sub(sequence) >= REPLAY_WINDOW_BYTES {
                return Err(CarrierError::ReplayWindowExceeded);
            }
        } else {
            self.largest = Some(sequence);
        }
        if self.len < REPLAY_WINDOW_SIZE {
            self.sequences[self.len] = sequence;
            self.len += 1;
        } else {
            self.sequences[self.next] = sequence;
            self.next = (self.next + 1) % REPLAY_WINDOW_SIZE;
        }
        Ok(())
    }
}

fn append_address(output: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(value) => {
            output.push(4);
            output.extend_from_slice(&value.octets());
        }
        IpAddr::V6(value) => {
            output.push(6);
            output.extend_from_slice(&value.octets());
        }
    }
    output.extend_from_slice(&address.port().to_be_bytes());
}

fn initial_sequence(tuple: FourTuple, direction: CarrierDirection) -> Result<u32, CarrierError> {
    let mut input = Vec::with_capacity(40);
    append_address(&mut input, tuple.source);
    append_address(&mut input, tuple.destination);
    input.push(direction.bit());
    let checksum = crc32c::crc32c(&input);
    let mut random = [0; 4];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| CarrierError::Randomness)?;
    Ok(u32::from_be_bytes(random) ^ checksum)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
static SIMD_LEVEL: OnceLock<Level> = OnceLock::new();

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fearless_simd::kernel!(
    #[inline]
    #[allow(clippy::chunks_exact_to_as_chunks)]
    fn checksum_blocks_avx2(avx2: Avx2, input: &[u8]) -> u32 {
        let adjust = _mm256_set1_epi16(i16::MIN);
        let ones = _mm256_set1_epi16(1);
        let pair_bias = _mm256_set1_epi32(65_536);
        let byte_swap = _mm256_setr_epi8(
            1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11,
            10, 13, 12, 15, 14,
        );
        let mut sum0 = _mm256_setzero_si256();
        let mut sum1 = _mm256_setzero_si256();
        macro_rules! add_block {
            ($sum:ident, $chunk:expr) => {{
                let input: &[u8; 32] = $chunk.try_into().expect("exact 32-byte checksum block");
                let bytes: fearless_simd::u8x32<Avx2> = avx2.load_array_ref_u8x32(input);
                let input: __m256i = bytes.into();
                let swapped = _mm256_shuffle_epi8(input, byte_swap);
                // Convert unsigned 16-bit words to signed values before using madd, then add
                // back the constant bias for each pair. This avoids two unpack operations.
                let adjusted = _mm256_sub_epi16(swapped, adjust);
                let pair_sums = _mm256_madd_epi16(adjusted, ones);
                $sum = _mm256_add_epi32($sum, _mm256_add_epi32(pair_sums, pair_bias));
            }};
        }
        for chunk in input.chunks_exact(64) {
            let mut blocks = chunk.chunks_exact(32);
            add_block!(sum0, blocks.next().expect("two checksum blocks"));
            add_block!(sum1, blocks.next().expect("two checksum blocks"));
        }
        let unrolled_len = input.len() / 64 * 64;
        let mut sum = _mm256_add_epi32(sum0, sum1);
        for chunk in input[unrolled_len..].chunks_exact(32) {
            add_block!(sum, chunk);
        }
        let sum = _mm_add_epi32(
            _mm256_castsi256_si128(sum),
            _mm256_extracti128_si256::<1>(sum),
        );
        let sum = _mm_hadd_epi32(sum, sum);
        let sum = _mm_hadd_epi32(sum, sum);
        u32::try_from(_mm_cvtsi128_si32(sum)).unwrap_or_default()
    }
);

#[inline]
fn internet_checksum(input: &[u8]) -> u16 {
    !u16::try_from(fold_checksum(checksum_sum(input))).unwrap_or(u16::MAX)
}

#[allow(clippy::chunks_exact_to_as_chunks)]
#[inline]
fn checksum_sum_scalar(input: &[u8]) -> u32 {
    // The maximum IP packet keeps this accumulator below u32::MAX; folding once enables
    // LLVM to vectorize the hot payload loop.
    let mut sum = 0u32;
    let mut chunks = input.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u32::from(byte) << 8;
    }
    sum
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
fn checksum_sum_avx2(avx2: Avx2, input: &[u8]) -> u32 {
    let block_len = input.len() / 32 * 32;
    checksum_blocks_avx2(avx2, &input[..block_len]) + checksum_sum_scalar(&input[block_len..])
}

#[inline]
fn checksum_sum(input: &[u8]) -> u32 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if input.len() >= 256
        && let Some(avx2) = SIMD_LEVEL.get_or_init(Level::new).as_avx2()
    {
        return checksum_sum_avx2(avx2, input);
    }
    checksum_sum_scalar(input)
}

#[cfg(all(test, any(target_arch = "x86", target_arch = "x86_64")))]
mod checksum_tests {
    use super::{Level, SIMD_LEVEL, checksum_sum_avx2, checksum_sum_scalar};

    #[test]
    fn avx2_checksum_matches_scalar_for_all_lengths() {
        let Some(avx2) = SIMD_LEVEL.get_or_init(Level::new).as_avx2() else {
            return;
        };
        for size in 0..=4096 {
            let input: Vec<u8> = (0..size)
                .map(|value| u8::try_from(value % 256).unwrap_or_default())
                .collect();
            assert_eq!(
                checksum_sum_avx2(avx2, &input),
                checksum_sum_scalar(&input),
                "length {size}"
            );
        }
    }
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
    let mut message = Vec::with_capacity(48);
    append_address(&mut message, tuple.source);
    append_address(&mut message, tuple.destination);
    message.extend_from_slice(&epoch.to_be_bytes());
    let tag = hmac::sign(&key, &message);
    let mut cookie = [0; 16];
    cookie.copy_from_slice(&tag.as_ref()[..16]);
    cookie
}

/// Verifies a SYN cookie without maintaining per-client handshake state.
#[must_use]
pub fn verify_syn_cookie(secret: &[u8], tuple: FourTuple, epoch: u64, cookie: &[u8]) -> bool {
    cookie.ct_eq(&issue_syn_cookie(secret, tuple, epoch)).into()
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CarrierError {
    #[error("invalid FakeTCP four-tuple")]
    InvalidTuple,
    #[error("unsupported IP version")]
    UnsupportedIpVersion,
    #[error("packet is too short")]
    PacketTooShort,
    #[error("packet is too large")]
    PacketTooLarge,
    #[error("output buffer capacity {available} is smaller than packet size {required}")]
    OutputTooSmall { required: usize, available: usize },
    #[error("invalid IPv4/IPv6 header")]
    InvalidIpHeader,
    #[error("invalid TCP header")]
    InvalidTcpHeader,
    #[error("invalid TCP option")]
    InvalidTcpOption,
    #[error("TCP options exceed 40 bytes")]
    TcpOptionsTooLong,
    #[error("datagram exceeds the carrier limit")]
    DatagramTooLarge,
    #[error("SYN data is disabled")]
    SynDataDisabled,
    #[error("SYN data cookie was rejected")]
    SynCookieRejected,
    #[error("carrier state transition is invalid")]
    InvalidState,
    #[error("packet tuple does not match the carrier path")]
    WrongTuple,
    #[error("packet has no carrier payload")]
    EmptyPayload,
    #[error("carrier sequence was already received")]
    Replay,
    #[error("carrier sequence is outside the replay window")]
    ReplayWindowExceeded,
    #[error("carrier sequence space is exhausted; create a new path")]
    SequenceExhausted,
    #[error("system randomness is unavailable")]
    Randomness,
}
