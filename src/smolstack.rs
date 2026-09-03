//! Executor-facing smoltcp device plumbing.
//!
//! The stack itself remains single-owner, as smoltcp requires.  Only complete IP packets cross
//! the executor boundary through bounded lock-free queues; TCP socket state is never shared
//! between executor tasks.

use std::io;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use smoltcp::iface::{Interface, PollIngressSingleResult, PollResult, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use thiserror::Error;

use crate::packet_ring::PacketRing;

/// Default IP packet MTU.
pub const DEFAULT_MTU: usize = 1500;
/// Default maximum packets processed by one bounded poll.
pub const DEFAULT_POLL_BUDGET: usize = 32;
/// Default byte capacity of each smoltcp TCP flow half.
pub const DEFAULT_FLOW_BUFFER_BYTES: usize = 32 * 1024;

/// Preallocated smoltcp TCP socket buffers.  A flow owns exactly one receive and one send buffer;
/// the Tokio packet rings are accounted for separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpFlowBuffers {
    /// Receive-buffer bytes reserved for one TCP flow.
    pub receive_bytes: usize,
    /// Send-buffer bytes reserved for one TCP flow.
    pub send_bytes: usize,
}

impl Default for TcpFlowBuffers {
    fn default() -> Self {
        Self {
            receive_bytes: DEFAULT_FLOW_BUFFER_BYTES,
            send_bytes: DEFAULT_FLOW_BUFFER_BYTES,
        }
    }
}

impl TcpFlowBuffers {
    /// Allocates one smoltcp TCP socket with the configured bounded buffers.
    ///
    /// # Errors
    ///
    /// Returns an error when either buffer is zero.
    pub fn into_socket(self) -> Result<smoltcp::socket::tcp::Socket<'static>, SmoltcpError> {
        if self.receive_bytes == 0 || self.send_bytes == 0 {
            return Err(SmoltcpError::ZeroFlowBuffer);
        }
        Ok(smoltcp::socket::tcp::Socket::new(
            smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; self.receive_bytes]),
            smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; self.send_bytes]),
        ))
    }
}

/// Attempts to read from a smoltcp TCP socket using only a short-lived borrow.
pub fn poll_tcp_read(
    socket: &mut smoltcp::socket::tcp::Socket<'_>,
    cx: &mut Context<'_>,
    output: &mut [u8],
) -> Poll<io::Result<usize>> {
    if output.is_empty() {
        return Poll::Ready(Ok(0));
    }
    if socket.can_recv() {
        return match socket.recv_slice(output) {
            Ok(read) => Poll::Ready(Ok(read)),
            Err(smoltcp::socket::tcp::RecvError::Finished) => Poll::Ready(Ok(0)),
            Err(smoltcp::socket::tcp::RecvError::InvalidState) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "smoltcp TCP receive failed",
            ))),
        };
    }
    if !socket.may_recv() {
        return Poll::Ready(Ok(0));
    }
    socket.register_recv_waker(cx.waker());
    Poll::Pending
}

/// Attempts to write to a smoltcp TCP socket using only a short-lived borrow.
pub fn poll_tcp_write(
    socket: &mut smoltcp::socket::tcp::Socket<'_>,
    cx: &mut Context<'_>,
    input: &[u8],
) -> Poll<io::Result<usize>> {
    if input.is_empty() {
        return Poll::Ready(Ok(0));
    }
    if socket.can_send() {
        return match socket.send_slice(input) {
            Ok(0) => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
            Ok(written) => Poll::Ready(Ok(written)),
            Err(smoltcp::socket::tcp::SendError::InvalidState) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smoltcp TCP send failed",
            ))),
        };
    }
    if !socket.may_send() {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "smoltcp TCP send half is closed",
        )));
    }
    socket.register_send_waker(cx.waker());
    Poll::Pending
}

/// Admission and scheduling limits for the smoltcp runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmoltcpConfig {
    /// Complete-IP-packet MTU.
    pub mtu: usize,
    /// Maximum ingress packets processed per poll slice.
    pub max_packets_per_poll: NonZeroUsize,
}

impl Default for SmoltcpConfig {
    fn default() -> Self {
        Self {
            mtu: DEFAULT_MTU,
            max_packets_per_poll: NonZeroUsize::new(DEFAULT_POLL_BUDGET)
                .unwrap_or(NonZeroUsize::MIN),
        }
    }
}

impl SmoltcpConfig {
    /// Validates a bounded IP-medium configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for an MTU outside the IPv4/IPv6 safe range.
    pub fn validate(self) -> Result<(), SmoltcpError> {
        if !(576..=9000).contains(&self.mtu) {
            return Err(SmoltcpError::InvalidMtu(self.mtu));
        }
        Ok(())
    }
}

/// A packet device backed by two bounded lock-free queues.
///
/// An outstanding token keeps the device borrowed, preserving each queue's single-producer and
/// single-consumer contract.
///
/// ```compile_fail
/// use quicp::platform::{PlatformPacketBridge, PlatformPacketConfig};
/// use quicp::smolstack::SmoltcpConfig;
/// use smoltcp::phy::Device;
/// use smoltcp::time::Instant;
///
/// let bridge = PlatformPacketBridge::new(PlatformPacketConfig::default()).unwrap();
/// let mut device = bridge.smoltcp_device(SmoltcpConfig::default()).unwrap();
/// let first = device.transmit(Instant::ZERO).unwrap();
/// let second = device.transmit(Instant::ZERO).unwrap();
/// drop((first, second));
/// ```
#[derive(Debug)]
pub struct RingDevice {
    ingress: Arc<PacketRing>,
    egress: Arc<PacketRing>,
    capabilities: DeviceCapabilities,
    mtu: usize,
    owner: Option<Arc<AtomicBool>>,
}

impl RingDevice {
    /// Creates an IP-medium device for [`crate::platform::PlatformPacketBridge`].
    ///
    /// # Errors
    ///
    /// Returns an error when the MTU is outside the supported range.
    pub(crate) fn new(
        ingress: Arc<PacketRing>,
        egress: Arc<PacketRing>,
        config: SmoltcpConfig,
    ) -> Result<Self, SmoltcpError> {
        config.validate()?;
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = config.mtu;
        capabilities.max_burst_size = Some(config.max_packets_per_poll.get());
        Ok(Self {
            ingress,
            egress,
            capabilities,
            mtu: config.mtu,
            owner: None,
        })
    }

    pub(crate) fn with_owner(mut self, active: Arc<AtomicBool>) -> Self {
        self.owner = Some(active);
        self
    }
}

impl Drop for RingDevice {
    fn drop(&mut self) {
        if let Some(owner) = &self.owner {
            owner.store(false, Ordering::Release);
        }
    }
}

impl Device for RingDevice {
    type RxToken<'a>
        = RingRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = RingTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // smoltcp returns a transmit token together with every receive token.  Do not consume an
        // ingress packet when the bounded egress pool cannot provide that token: doing so would
        // make a stack-generated response an unobservable drop under backpressure.
        if !self.egress.can_push(self.mtu) {
            return None;
        }
        let packet = self.ingress.pop()?;
        Some((
            RingRxToken {
                packet: Some(packet),
                recycle: Arc::clone(&self.ingress),
                _device: PhantomData,
            },
            RingTxToken {
                queue: Arc::clone(&self.egress),
                mtu: self.mtu,
                _device: PhantomData,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.egress.can_push(self.mtu).then(|| RingTxToken {
            queue: Arc::clone(&self.egress),
            mtu: self.mtu,
            _device: PhantomData,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

/// smoltcp receive token borrowing one packet and its device owner.
#[derive(Debug)]
pub struct RingRxToken<'a> {
    packet: Option<Vec<u8>>,
    recycle: Arc<PacketRing>,
    _device: PhantomData<&'a mut RingDevice>,
}

impl RxToken for RingRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.packet.as_deref().unwrap_or_default())
    }
}

impl Drop for RingRxToken<'_> {
    fn drop(&mut self) {
        if let Some(packet) = self.packet.take() {
            self.recycle.recycle_buffer(packet);
        }
    }
}

/// smoltcp transmit token borrowing the bounded egress queue and device owner.
#[derive(Debug)]
pub struct RingTxToken<'a> {
    queue: Arc<PacketRing>,
    mtu: usize,
    _device: PhantomData<&'a mut RingDevice>,
}

impl TxToken for RingTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // The smoltcp contract normally supplies a length no larger than the interface MTU.
        // Bound a violating caller before any allocation so a bad token cannot request an
        // arbitrary buffer. The callback receives the bounded slice and the packet is discarded
        // after the callback when the requested length was invalid.
        let bounded_len = len.min(self.mtu);
        let mut packet = self
            .queue
            .acquire_buffer(bounded_len)
            .unwrap_or_else(|| vec![0; bounded_len]);
        let result = f(&mut packet);
        if len <= self.mtu {
            // `transmit` checked capacity before handing out this token. Under the SPSC
            // contract the consumer can only make room, so a full result means the caller
            // violated the single-producer ownership rule; drop the packet instead of writing
            // to the consumer-owned free queue.
            let _ = self.queue.push(packet);
        } else {
            self.queue.recycle_buffer(packet);
        }
        result
    }
}

/// Runs a bounded ingress/egress slice. Any executor or event loop can call this after a packet
/// wakeup and yield when the budget is consumed, preventing a permanently busy device from
/// starving the QUICP engine.
pub fn poll_bounded<D: Device + ?Sized>(
    interface: &mut Interface,
    device: &mut D,
    sockets: &mut SocketSet<'_>,
    timestamp: Instant,
    max_packets: NonZeroUsize,
) -> PollResult {
    let mut changed = false;
    for _ in 0..max_packets.get() {
        match interface.poll_ingress_single(timestamp, device, sockets) {
            PollIngressSingleResult::None => break,
            PollIngressSingleResult::PacketProcessed => {}
            PollIngressSingleResult::SocketStateChanged => changed = true,
        }
    }
    if interface.poll_egress(timestamp, device, sockets) == PollResult::SocketStateChanged {
        changed = true;
    }
    if changed {
        PollResult::SocketStateChanged
    } else {
        PollResult::None
    }
}

/// smoltcp adapter limit-validation errors.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum SmoltcpError {
    /// MTU falls outside the supported IPv4/IPv6 range.
    #[error("smoltcp MTU {0} is outside 576..=9000")]
    InvalidMtu(usize),
    /// A TCP receive or send buffer was zero bytes.
    #[error("smoltcp TCP flow buffers must be nonzero")]
    ZeroFlowBuffer,
}
