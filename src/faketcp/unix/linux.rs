//! Linux Tier 0 raw-carrier backend.
//!
//! This module owns Linux-only `AF_PACKET`, `TPACKET_V2`, route/ARP discovery, and batched syscalls.

use super::super::{Arc, IpAddr, Ipv4Addr, SocketAddr, TCP_PROTOCOL, Vec};
use super::{
    FakeTcpCarrier, FourTuple, IPV4_HEADER_BYTES, MAX_DECODE_REJECTS_PER_POLL,
    RAW_PACKET_BUFFER_BYTES, RawSendMode, receive_one_raw_packet, reject_budget_exhausted,
};
use noq::udp::RecvMeta;
use socket2::SockFilter;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::ffi::CString;
use std::io::IoSliceMut;
use std::mem;
use std::os::fd::AsRawFd;
use std::ptr;
use std::sync::atomic::{Ordering, fence};
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;

pub(super) const SEND_BATCH_SIZE: usize = 10;
pub(super) const RECV_BATCH_SIZE: usize = 8;
pub(super) const GRO_SEGMENTS: usize = 4;

const PACKET_RING_FRAME_SIZE: usize = 128 * 1024;
const PACKET_RING_FRAME_COUNT: usize = 64;

const PACKET_VERSION_OPTION: libc::c_int = 10;
const PACKET_RX_RING_OPTION: libc::c_int = 5;
const PACKET_TPACKET_V2: libc::c_int = 1;

#[derive(Debug)]
struct PacketRxRing {
    mapping: std::ptr::NonNull<u8>,
    mapping_len: usize,
    frame_size: usize,
    frame_count: usize,
    next_frame: usize,
}

#[allow(unsafe_code)]
unsafe impl Send for PacketRxRing {}

#[allow(unsafe_code)]
unsafe impl Sync for PacketRxRing {}

impl PacketRxRing {
    fn try_new(socket: &Socket) -> Option<Self> {
        Self::new(socket).ok()
    }

    #[allow(unsafe_code, clippy::cast_ptr_alignment)]
    fn new(socket: &Socket) -> std::io::Result<Self> {
        let version = PACKET_TPACKET_V2;
        set_packet_option(socket, PACKET_VERSION_OPTION, &version)?;
        let copy_threshold: libc::c_int = 1;
        set_packet_option(socket, libc::PACKET_COPY_THRESH, &copy_threshold)?;
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

    #[allow(unsafe_code, clippy::cast_ptr_alignment)]
    fn with_next_packet<T, F>(&mut self, callback: F) -> std::io::Result<Option<T>>
    where
        F: FnOnce(&[u8], Option<usize>) -> std::io::Result<T>,
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
        let packet_len =
            usize::try_from(unsafe { ptr::read_unaligned(ptr::addr_of!((*header).tp_len)) })
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "packet ring length overflow",
                    )
                });
        let packet_len = match packet_len {
            Ok(packet_len) => packet_len,
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
        let copied_len =
            (status & libc::TP_STATUS_COPY != 0 && snaplen < packet_len).then_some(packet_len);
        let result = callback(packet, copied_len);
        self.release_frame(header);
        result.map(Some)
    }

    #[allow(unsafe_code, clippy::cast_ptr_alignment)]
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

impl Drop for PacketRxRing {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        unsafe {
            let _ = libc::munmap(self.mapping.as_ptr().cast(), self.mapping_len);
        }
    }
}

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

#[derive(Clone, Copy, Debug)]
enum RingPayloadCopy {
    Skipped,
    Copied(usize),
    Pending(usize),
}

#[derive(Clone, Copy, Debug)]
struct PacketTarget {
    ifindex: libc::c_int,
    destination: [u8; 6],
}

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

#[derive(Debug)]
pub(super) struct RawPlatform {
    io: Arc<AsyncFd<Socket>>,
    send_io: Arc<AsyncFd<Socket>>,
    receive_ring: Option<PacketRxRing>,
    send_mode: RawSendMode,
    receive_direct_pending: Option<usize>,
}

impl RawPlatform {
    pub(super) const SEND_BATCH_SIZE: usize = SEND_BATCH_SIZE;
    pub(super) const RECV_BATCH_SIZE: usize = RECV_BATCH_SIZE;
    pub(super) const GRO_SEGMENTS: usize = GRO_SEGMENTS;

    pub(super) fn bind(tuple: FourTuple, packet_socket: bool) -> std::io::Result<Self> {
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
        Ok(Self {
            io,
            send_io,
            receive_ring,
            send_mode,
            receive_direct_pending: None,
        })
    }

    pub(super) fn recv_io(&self) -> &AsyncFd<Socket> {
        &self.io
    }

    pub(super) fn send_io(&self) -> &Arc<AsyncFd<Socket>> {
        &self.send_io
    }

    pub(super) const fn send_mode(&self) -> RawSendMode {
        self.send_mode
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn poll_recv_ring(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
        tuple: FourTuple,
        inbound: &mut FakeTcpCarrier,
        receive_buffer: &mut [u8],
        decode_rejects: &mut u64,
    ) -> Option<Poll<std::io::Result<usize>>> {
        self.receive_ring.as_ref()?;
        Some(self.poll_recv_ring_inner(
            cx,
            bufs,
            meta,
            tuple,
            inbound,
            receive_buffer,
            decode_rejects,
        ))
    }

    fn copy_next_ring_payload(
        &mut self,
        target: &mut [u8],
        offset: usize,
        expected_stride: Option<usize>,
        inbound: &mut FakeTcpCarrier,
        receive_buffer: &mut [u8],
        decode_rejects: &mut u64,
    ) -> std::io::Result<Option<RingPayloadCopy>> {
        let Some(ring) = self.receive_ring.as_mut() else {
            return Err(std::io::Error::other("FakeTCP receive ring is unavailable"));
        };
        let pending_storage = receive_buffer;
        let socket = self.io.get_ref();
        let outcome = ring.with_next_packet(|ring_packet, copied_len| {
            if let Some(expected_len) = copied_len {
                let received = receive_one_raw_packet(
                    socket,
                    &mut pending_storage[..RAW_PACKET_BUFFER_BYTES],
                )?;
                if received != expected_len {
                    return Ok(RingPayloadCopy::Skipped);
                }
                let decoded = match inbound.decode_datagram_borrowed(&pending_storage[..received]) {
                    Ok(decoded) => decoded,
                    Err(_error) => return Ok(RingPayloadCopy::Skipped),
                };
                let payload_len = decoded.payload().len();
                let payload_start = (decoded.payload().as_ptr() as usize)
                    .checked_sub(pending_storage.as_ptr() as usize)
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "copied QUICP payload precedes receive storage",
                        )
                    })?;
                let payload_end = payload_start.checked_add(payload_len).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "copied QUICP payload length overflow",
                    )
                })?;
                if payload_end > received {
                    return Ok(RingPayloadCopy::Skipped);
                }
                let same_stride = expected_stride.is_none_or(|stride| stride == payload_len);
                if same_stride {
                    let end = offset.checked_add(payload_len).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "QUICP payload offset overflow",
                        )
                    })?;
                    let Some(destination) = target.get_mut(offset..end) else {
                        return Ok(RingPayloadCopy::Skipped);
                    };
                    destination.copy_from_slice(&pending_storage[payload_start..payload_end]);
                    return Ok(RingPayloadCopy::Copied(payload_len));
                }
                if payload_len > target.len() {
                    return Ok(RingPayloadCopy::Skipped);
                }
                pending_storage.copy_within(payload_start..payload_end, 0);
                return Ok(RingPayloadCopy::Pending(payload_len));
            }

            let decoded = match inbound.decode_datagram_borrowed(ring_packet) {
                Ok(decoded) => decoded,
                Err(_error) => return Ok(RingPayloadCopy::Skipped),
            };
            let payload = decoded.payload();
            if payload.len() > RAW_PACKET_BUFFER_BYTES {
                return Ok(RingPayloadCopy::Skipped);
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
                    return Ok(RingPayloadCopy::Skipped);
                };
                destination.copy_from_slice(payload);
                Ok(RingPayloadCopy::Copied(payload.len()))
            } else {
                if payload.len() > target.len() {
                    return Ok(RingPayloadCopy::Skipped);
                }
                let payload_len = payload.len();
                pending_storage[..payload_len].copy_from_slice(payload);
                Ok(RingPayloadCopy::Pending(payload_len))
            }
        })?;
        if matches!(outcome, Some(RingPayloadCopy::Skipped)) {
            *decode_rejects = (*decode_rejects).saturating_add(1);
        }
        Ok(outcome)
    }

    #[allow(clippy::too_many_lines)]
    #[allow(clippy::too_many_arguments)]
    fn poll_recv_ring_inner(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
        tuple: FourTuple,
        inbound: &mut FakeTcpCarrier,
        receive_buffer: &mut [u8],
        decode_rejects: &mut u64,
    ) -> Poll<std::io::Result<usize>> {
        let slots = bufs.len().min(meta.len());
        let mut received_count = 0;
        let mut reject_budget = MAX_DECODE_REJECTS_PER_POLL;
        loop {
            while received_count < slots {
                let mut stride = None;
                let mut group_count = 0;
                loop {
                    if group_count >= GRO_SEGMENTS {
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
                        if let Some(destination) = bufs[received_count]
                            .get_mut(group_count * length..(group_count + 1) * length)
                        {
                            destination.copy_from_slice(&receive_buffer[..length]);
                            Some(RingPayloadCopy::Copied(length))
                        } else {
                            *decode_rejects = (*decode_rejects).saturating_add(1);
                            Some(RingPayloadCopy::Skipped)
                        }
                    } else {
                        self.copy_next_ring_payload(
                            &mut bufs[received_count],
                            group_count * stride.unwrap_or(0),
                            stride,
                            inbound,
                            receive_buffer,
                            decode_rejects,
                        )?
                    };
                    match copied {
                        None => {
                            if group_count == 0 {
                                break;
                            }
                            break;
                        }
                        Some(RingPayloadCopy::Skipped) => {
                            if reject_budget_exhausted(&mut reject_budget) {
                                break;
                            }
                        }
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
                if reject_budget == 0 {
                    break;
                }
                let Some(stride) = stride else {
                    break;
                };
                let mut received = RecvMeta::default();
                received.addr = tuple.destination;
                received.len = group_count * stride;
                received.stride = stride;
                received.dst_ip = Some(tuple.source.ip());
                meta[received_count] = received;
                received_count += 1;
            }

            if reject_budget == 0 {
                cx.waker().wake_by_ref();
                return if received_count > 0 {
                    Poll::Ready(Ok(received_count))
                } else {
                    Poll::Pending
                };
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

#[derive(Debug)]
struct RouteEntry {
    interface: String,
    gateway: u32,
}

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

fn packet_protocol() -> libc::c_ushort {
    u16::try_from(libc::ETH_P_IP)
        .expect("ETH_P_IP fits u16")
        .to_be()
}

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

#[allow(unsafe_code, clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn send_batch(
    socket: &Socket,
    destination: &SockAddr,
    mode: RawSendMode,
    storage: &[u8],
    packet_capacity: usize,
    lengths: &[usize],
    first: usize,
) -> std::io::Result<usize> {
    let count = lengths.len().saturating_sub(first).min(SEND_BATCH_SIZE);
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
    }; SEND_BATCH_SIZE];
    let mut messages = unsafe { mem::zeroed::<[libc::mmsghdr; SEND_BATCH_SIZE]>() };
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

#[allow(unsafe_code)]
pub(super) fn receive_batch(
    socket: &Socket,
    storage: &mut [u8],
    lengths: &mut [usize; RECV_BATCH_SIZE],
) -> std::io::Result<usize> {
    let mut iovs = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }; RECV_BATCH_SIZE];
    let mut messages = unsafe { mem::zeroed::<[libc::mmsghdr; RECV_BATCH_SIZE]>() };
    for index in 0..RECV_BATCH_SIZE {
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
                libc::c_uint::try_from(RECV_BATCH_SIZE).expect("raw receive batch size fits libc"),
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
            *length = 0;
            continue;
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
