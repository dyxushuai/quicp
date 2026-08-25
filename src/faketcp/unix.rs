//! Unix Tokio raw-socket adapter for the `FakeTCP` carrier.
//!
//! The packet codec and receive grouping are shared here. OS-specific socket setup, batching,
//! filtering, and ring support live in the sibling Linux and macOS backends.
//!
//! The parent module gates Tokio and Unix availability. These selectors remain target-based
//! because `AF_PACKET` and Darwin IP raw sockets are different kernel APIs, not optional backends.

use super::{
    Arc, CarrierDirection, CarrierError, FakeTcpCarrier, FourTuple, IPV4_HEADER_BYTES,
    IPV6_HEADER_BYTES, MAX_PACKET_BYTES, MAX_TCP_OPTIONS_BYTES, SocketAddr, SynDataMode,
    TCP_HEADER_BYTES, Vec, vec,
};
use noq::udp::{RecvMeta, Transmit};
use noq::{AsyncUdpSocket, UdpSender};
use socket2::{SockAddr, Socket};
use std::io::Read;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;

#[cfg(target_os = "linux")]
#[path = "unix/linux.rs"]
mod linux;
#[cfg(target_os = "macos")]
#[path = "unix/macos.rs"]
mod macos;
#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!(
    "QUICP raw FakeTCP is not implemented for this Unix target; use the host-driven carrier or add an explicit platform adapter"
);
use platform::RawPlatform;

const RAW_PACKET_BUFFER_BYTES: usize = MAX_PACKET_BYTES;
pub(super) const MAX_DECODE_REJECTS_PER_POLL: usize = 64;

pub(super) fn reject_budget_exhausted(reject_budget: &mut usize) -> bool {
    *reject_budget = reject_budget.saturating_sub(1);
    *reject_budget == 0
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(super) enum RawSendMode {
    Ip,
    Packet,
}

pub(super) fn receive_one_raw_packet(
    socket: &Socket,
    storage: &mut [u8],
) -> std::io::Result<usize> {
    let mut socket = socket;
    loop {
        match socket.read(storage) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct DecodedRawPacket {
    batch_index: usize,
    payload_offset: usize,
    payload_length: usize,
}

#[derive(Debug)]
pub struct FakeTcpSocket {
    platform: RawPlatform,
    tuple: FourTuple,
    inbound: FakeTcpCarrier,
    outbound: Arc<Mutex<FakeTcpCarrier>>,
    server_side: bool,
    receive_buffer: Vec<u8>,
    receive_batch_count: usize,
    receive_batch_index: usize,
    receive_batch_lengths: [usize; RawPlatform::RECV_BATCH_SIZE],
    receive_pending: Option<DecodedRawPacket>,
    decode_rejects: u64,
}

impl FakeTcpSocket {
    /// Binds a privileged raw IPv4 TCP socket for one `FakeTCP` path.
    ///
    /// Linux may select `AF_PACKET` with `packet_socket`; macOS uses the IP raw-socket fallback.
    ///
    /// # Errors
    ///
    /// Returns an OS error when raw-socket privileges, binding, or nonblocking setup is denied.
    pub fn bind(
        tuple: FourTuple,
        outbound_direction: CarrierDirection,
        syn_data: SynDataMode,
        syn_mss: u16,
        outer_mtu: u16,
        packet_socket: bool,
    ) -> std::io::Result<Self> {
        tuple.validate().map_err(carrier_io_error)?;
        if !tuple.source.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "FakeTcpSocket currently supports IPv4 raw sockets only",
            ));
        }
        let platform = RawPlatform::bind(tuple, packet_socket)?;
        let (inbound, outbound) =
            FakeTcpCarrier::pair_with_mtu(tuple, outbound_direction, syn_data, syn_mss, outer_mtu)
                .map_err(carrier_io_error)?;
        Ok(Self {
            platform,
            tuple,
            inbound,
            outbound: Arc::new(Mutex::new(outbound)),
            server_side: outbound_direction == CarrierDirection::ServerToClient,
            receive_buffer: vec![0; RAW_PACKET_BUFFER_BYTES * RawPlatform::RECV_BATCH_SIZE],
            receive_batch_count: 0,
            receive_batch_index: 0,
            receive_batch_lengths: [0; RawPlatform::RECV_BATCH_SIZE],
            receive_pending: None,
            decode_rejects: 0,
        })
    }

    /// Number of underlay packets that failed carrier decode and were dropped.
    #[must_use]
    pub const fn rejected_datagrams(&self) -> u64 {
        self.decode_rejects
    }

    fn next_decoded_packet(
        &mut self,
        reject_budget: &mut usize,
    ) -> std::io::Result<Option<DecodedRawPacket>> {
        if *reject_budget == 0 {
            return Ok(None);
        }
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
                    if reject_budget_exhausted(reject_budget) {
                        return Ok(None);
                    }
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
}

impl AsyncUdpSocket for FakeTcpSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(FakeTcpSender {
            io: Arc::clone(self.platform.send_io()),
            send_mode: self.platform.send_mode(),
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
            pending_batch_lengths: [0; RawPlatform::SEND_BATCH_SIZE],
        })
    }

    #[allow(clippy::too_many_lines)]
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
        if let Some(result) = self.platform.poll_recv_ring(
            cx,
            bufs,
            meta,
            self.tuple,
            &mut self.inbound,
            &mut self.receive_buffer,
            &mut self.decode_rejects,
        ) {
            return result;
        }
        let mut received_count = 0;
        let mut reject_budget = MAX_DECODE_REJECTS_PER_POLL;
        loop {
            while received_count < slots {
                let Some(first) = self.next_decoded_packet(&mut reject_budget)? else {
                    break;
                };
                let stride = first.payload_length;
                if stride > bufs[received_count].len() {
                    self.decode_rejects = self.decode_rejects.saturating_add(1);
                    reject_budget_exhausted(&mut reject_budget);
                    continue;
                }
                let max_group = bufs[received_count]
                    .len()
                    .checked_div(stride.max(1))
                    .unwrap_or(1)
                    .clamp(1, RawPlatform::GRO_SEGMENTS);
                let first_payload = self.decoded_payload(first)?;
                bufs[received_count][..stride].copy_from_slice(first_payload);
                let mut group_count = 1;
                while group_count < max_group {
                    let Some(next) = self.next_decoded_packet(&mut reject_budget)? else {
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
            if reject_budget == 0 {
                cx.waker().wake_by_ref();
                return if received_count > 0 {
                    Poll::Ready(Ok(received_count))
                } else {
                    Poll::Pending
                };
            }
            self.receive_batch_count = 0;
            self.receive_batch_index = 0;

            let mut guard = match self.platform.recv_io().poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending if received_count > 0 => return Poll::Ready(Ok(received_count)),
                Poll::Pending => return Poll::Pending,
            };
            let result = guard.try_io(|inner| {
                platform::receive_batch(
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
        NonZeroUsize::new(RawPlatform::GRO_SEGMENTS).expect("non-zero receive segment batch")
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

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
    pending_batch_lengths: [usize; RawPlatform::SEND_BATCH_SIZE],
}

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
                let batch_count = remaining.min(RawPlatform::SEND_BATCH_SIZE);
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
                    let encoded = if carrier.sent_syn {
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
                platform::send_batch(
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
        NonZeroUsize::new(RawPlatform::SEND_BATCH_SIZE).expect("non-zero segment batch")
    }
}

fn carrier_io_error(error: CarrierError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}
