//! Host-driven datagram carrier for runtime-neutral QUICP integrations.
//!
//! A platform adapter copies datagrams into [`HostDatagramSocket::ingress_datagram`] and drains
//! [`HostDatagramSocket::poll_egress_datagram_into`].  The socket owns bounded, preallocated
//! storage; no caller pointer is retained after either method returns.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use noq::udp::{RecvMeta, Transmit};
use noq::{AsyncUdpSocket, UdpSender};
use thiserror::Error;

use crate::packet_ring::{PacketRing, RingError};

/// A bounded, fixed-peer datagram socket driven by a host event loop.
///
/// The host side owns the input/output buffers and calls the two `*_datagram` methods.  The QUIC
/// endpoint sees the same object through the private transport adapter. One socket represents one
/// local address and one remote peer; multipath uses one socket per path. Clones may be shared
/// between host threads: per-direction guards preserve one logical producer and consumer for the
/// SPSC rings, while the endpoint runtime remains single-owner.
#[derive(Clone)]
pub struct HostDatagramSocket {
    inner: Arc<HostDatagramInner>,
}

impl fmt::Debug for HostDatagramSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostDatagramSocket")
            .field("local", &self.inner.local)
            .field("peer", &self.inner.peer)
            .field("mtu", &self.inner.mtu)
            .finish_non_exhaustive()
    }
}

impl HostDatagramSocket {
    /// Creates a fixed-peer socket with preallocated ingress and egress queues.
    ///
    /// `packet_capacity` is the number of datagrams in each direction. `mtu` is the maximum size
    /// of one datagram and must be nonzero. The two directions reserve
    /// `packet_capacity * mtu` bytes each.
    ///
    /// # Errors
    ///
    /// Returns an error when a capacity, MTU, or checked byte-budget calculation is invalid.
    pub fn new(
        local: SocketAddr,
        peer: SocketAddr,
        packet_capacity: usize,
        mtu: usize,
    ) -> Result<Self, HostDatagramError> {
        if packet_capacity == 0 {
            return Err(HostDatagramError::ZeroCapacity);
        }
        if mtu == 0 {
            return Err(HostDatagramError::ZeroMtu);
        }
        let byte_budget = packet_capacity
            .checked_mul(mtu)
            .ok_or(HostDatagramError::BudgetOverflow)?;
        let ingress = PacketRing::with_preallocated(packet_capacity, byte_budget, mtu)
            .map_err(|error| HostDatagramError::from_ring(&error))?;
        let egress = PacketRing::with_preallocated(packet_capacity, byte_budget, mtu)
            .map_err(|error| HostDatagramError::from_ring(&error))?;
        Ok(Self {
            inner: Arc::new(HostDatagramInner {
                local,
                peer,
                mtu,
                ingress: Arc::new(ingress),
                egress: Arc::new(egress),
                ingress_producer: Mutex::new(()),
                ingress_consumer: Mutex::new(()),
                egress_consumer: Mutex::new(()),
                egress_producer: Mutex::new(()),
                recv_waker: Mutex::new(None),
                send_waker: Mutex::new(None),
            }),
        })
    }

    /// Copies one host-owned datagram into the QUIC receive queue.
    ///
    /// The input is not retained after this call returns.
    ///
    /// # Errors
    ///
    /// Returns an error when the datagram is outside the MTU or the bounded queue is full.
    pub fn ingress_datagram(&self, packet: &[u8]) -> Result<(), HostDatagramError> {
        self.ingress_datagram_from(self.inner.peer, packet)
    }

    /// Copies one datagram after checking the host-observed source address.
    ///
    /// Use this form when the platform API exposes the underlay source address. It prevents a
    /// packet for another path from being relabeled as this socket's fixed peer.
    ///
    /// # Errors
    ///
    /// Returns an error when the source is not the configured peer, the datagram is outside the
    /// MTU, or the bounded queue is full.
    pub fn ingress_datagram_from(
        &self,
        source: SocketAddr,
        packet: &[u8],
    ) -> Result<(), HostDatagramError> {
        if source != self.inner.peer {
            return Err(HostDatagramError::PeerMismatch {
                expected: self.inner.peer,
                actual: source,
            });
        }
        self.check_len(packet.len())?;
        let _producer = lock_recover(&self.inner.ingress_producer);
        self.inner
            .ingress
            .push_copy(packet)
            .map_err(|error| HostDatagramError::from_ring(&error))?;
        if let Some(waker) = lock_recover(&self.inner.recv_waker).take() {
            waker.wake();
        }
        Ok(())
    }

    /// Copies one queued QUIC datagram into a host-owned output buffer.
    ///
    /// A too-small output buffer leaves the datagram queued.
    ///
    /// # Errors
    ///
    /// Returns an error when the output buffer cannot hold the next datagram.
    pub fn poll_egress_datagram_into(
        &self,
        output: &mut [u8],
    ) -> Result<Option<usize>, HostDatagramError> {
        let _consumer = lock_recover(&self.inner.egress_consumer);
        let result = self
            .inner
            .egress
            .pop_into(output)
            .map_err(|error| HostDatagramError::from_ring(&error));
        if matches!(result, Ok(Some(_)))
            && let Some(waker) = lock_recover(&self.inner.send_waker).take()
        {
            waker.wake();
        }
        result
    }

    /// Returns the number of queued datagrams waiting for the host.
    #[must_use]
    pub fn egress_len(&self) -> usize {
        self.inner.egress.len()
    }

    /// Returns the number of datagrams waiting for the QUIC endpoint.
    #[must_use]
    pub fn ingress_len(&self) -> usize {
        self.inner.ingress.len()
    }

    #[must_use]
    /// Returns the local address presented to the QUIC endpoint.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local
    }

    #[must_use]
    /// Returns the only remote peer accepted by this carrier.
    pub fn peer_addr(&self) -> SocketAddr {
        self.inner.peer
    }

    #[must_use]
    /// Returns the maximum host datagram size accepted by this carrier.
    pub fn mtu(&self) -> usize {
        self.inner.mtu
    }

    fn check_len(&self, len: usize) -> Result<(), HostDatagramError> {
        if len == 0 || len > self.inner.mtu {
            return Err(HostDatagramError::PacketOutsideMtu {
                len,
                mtu: self.inner.mtu,
            });
        }
        Ok(())
    }
}

impl AsyncUdpSocket for HostDatagramSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(HostDatagramSender {
            inner: Arc::clone(&self.inner),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "host datagram receive requires one buffer and one metadata slot",
            )));
        }

        let _consumer = lock_recover(&self.inner.ingress_consumer);
        loop {
            match self.inner.ingress.pop_into(&mut bufs[0][..]) {
                Ok(Some(len)) => {
                    meta[0] = RecvMeta::default();
                    meta[0].addr = self.inner.peer;
                    meta[0].len = len;
                    meta[0].stride = len;
                    return Poll::Ready(Ok(1));
                }
                Err(RingError::BufferTooSmall { required, capacity }) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("host receive buffer {capacity} is smaller than {required}"),
                    )));
                }
                Err(error) => return Poll::Ready(Err(io::Error::other(error.to_string()))),
                Ok(None) => {
                    register_waker(&self.inner.recv_waker, cx.waker());
                    if self.inner.ingress.is_empty() {
                        return Poll::Pending;
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.inner.local)
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct HostDatagramSender {
    inner: Arc<HostDatagramInner>,
}

impl UdpSender for HostDatagramSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if transmit.destination != this.inner.peer
            || transmit
                .src_ip
                .is_some_and(|source| source != this.inner.local.ip())
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "host datagram destination or source does not match socket",
            )));
        }
        if transmit.segment_size.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "host datagram socket does not support segmented sends",
            )));
        }
        if transmit.contents.is_empty() || transmit.contents.len() > this.inner.mtu {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "host datagram exceeds the configured MTU",
            )));
        }

        let _producer = lock_recover(&this.inner.egress_producer);
        if !this.inner.egress.can_fit(transmit.contents.len())
            || !this.inner.egress.has_buffer_for(transmit.contents.len())
        {
            register_waker(&this.inner.send_waker, cx.waker());
            if !this.inner.egress.can_fit(transmit.contents.len())
                || !this.inner.egress.has_buffer_for(transmit.contents.len())
            {
                return Poll::Pending;
            }
        }
        match this.inner.egress.push_copy(transmit.contents) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(RingError::Full(_)) => {
                register_waker(&this.inner.send_waker, cx.waker());
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(io::Error::other(error.to_string()))),
        }
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }
}

#[derive(Debug)]
struct HostDatagramInner {
    local: SocketAddr,
    peer: SocketAddr,
    mtu: usize,
    ingress: Arc<PacketRing>,
    egress: Arc<PacketRing>,
    ingress_producer: Mutex<()>,
    ingress_consumer: Mutex<()>,
    egress_consumer: Mutex<()>,
    egress_producer: Mutex<()>,
    recv_waker: Mutex<Option<Waker>>,
    send_waker: Mutex<Option<Waker>>,
}

/// Host-carrier construction, peer-validation, and bounded-queue errors.
#[derive(Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum HostDatagramError {
    /// Queue capacity was zero.
    #[error("host datagram queue capacity must be nonzero")]
    ZeroCapacity,
    /// MTU was zero.
    #[error("host datagram MTU must be nonzero")]
    ZeroMtu,
    /// The checked queue byte budget overflowed.
    #[error("host datagram queue budget overflowed")]
    BudgetOverflow,
    /// A datagram was empty or exceeded the configured MTU.
    #[error("host datagram length {len} is outside MTU {mtu}")]
    PacketOutsideMtu {
        /// Observed datagram length.
        len: usize,
        /// Configured MTU.
        mtu: usize,
    },
    /// A received datagram did not come from the fixed peer.
    #[error("host datagram peer {actual} does not match {expected}")]
    PeerMismatch {
        /// Configured peer address.
        expected: SocketAddr,
        /// Host-observed source address.
        actual: SocketAddr,
    },
    /// The bounded packet queue has no free slot or byte budget.
    #[error("host datagram queue is full")]
    QueueFull,
    /// The caller-owned output buffer cannot hold the next datagram.
    #[error("host datagram output buffer {capacity} is smaller than {required}")]
    BufferTooSmall {
        /// Required datagram bytes.
        required: usize,
        /// Supplied output capacity.
        capacity: usize,
    },
}

impl HostDatagramError {
    fn from_ring(error: &RingError) -> Self {
        match error {
            RingError::Full(_) => Self::QueueFull,
            RingError::TooLarge { len, max } => Self::PacketOutsideMtu {
                len: *len,
                mtu: *max,
            },
            RingError::BufferTooSmall { required, capacity } => Self::BufferTooSmall {
                required: *required,
                capacity: *capacity,
            },
            RingError::ZeroCapacity
            | RingError::ZeroByteBudget
            | RingError::ZeroSlotCapacity
            | RingError::PoolBudgetExceeded { .. }
            | RingError::PoolInitializationFailed => Self::BudgetOverflow,
        }
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn register_waker(waiter: &Mutex<Option<Waker>>, waker: &Waker) {
    let mut waiter = lock_recover(waiter);
    if waiter
        .as_ref()
        .is_none_or(|registered| !registered.will_wake(waker))
    {
        *waiter = Some(waker.clone());
    }
}
