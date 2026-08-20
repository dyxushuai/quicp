//! Platform-neutral packet ownership for TUN and mobile FFI adapters.
//!
//! Platform code supplies and drains complete IP packets.  smoltcp remains single-owner and is
//! driven by the task that owns [`RingDevice`]; no executor or operating-system handle crosses
//! this boundary.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use thiserror::Error;

use crate::packet_ring::{PacketRing, RingError};
use crate::smolstack::{RingDevice, SmoltcpConfig, SmoltcpError};

/// Default number of packet slots exposed to a platform adapter.
pub const DEFAULT_PLATFORM_PACKET_CAPACITY: usize = 256;
/// Default per-direction byte budget exposed to a platform adapter.
pub const DEFAULT_PLATFORM_BYTE_BUDGET: usize = 8 * 1024 * 1024;

/// Bounded packet queues shared by a platform adapter and the smoltcp owner task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformPacketConfig {
    pub packet_capacity: usize,
    /// Maximum bytes reserved independently for ingress and egress.
    pub byte_budget: usize,
    pub smoltcp: SmoltcpConfig,
}

impl Default for PlatformPacketConfig {
    fn default() -> Self {
        Self {
            packet_capacity: DEFAULT_PLATFORM_PACKET_CAPACITY,
            byte_budget: DEFAULT_PLATFORM_BYTE_BUDGET,
            smoltcp: SmoltcpConfig::default(),
        }
    }
}

/// A safe, allocation-owning packet seam for TUN, `VpnService`, and `packetFlow` adapters.
///
/// Concurrent platform calls are serialized per direction, so the internal rings still observe
/// one logical producer and one logical consumer. smoltcp itself remains single-owner.
#[derive(Clone, Debug)]
pub struct PlatformPacketBridge {
    ingress: Arc<PacketRing>,
    egress: Arc<PacketRing>,
    mtu: usize,
    ingress_producer: Arc<Mutex<()>>,
    egress_consumer: Arc<Mutex<()>>,
    smoltcp_owner: Arc<AtomicBool>,
}

impl PlatformPacketBridge {
    /// Creates a bounded bridge and validates the smoltcp packet limits.
    ///
    /// # Errors
    ///
    /// Returns an error when a queue budget or smoltcp configuration is invalid.
    pub fn new(config: PlatformPacketConfig) -> Result<Self, PlatformError> {
        config.smoltcp.validate()?;
        let ingress = Arc::new(
            PacketRing::with_preallocated(
                config.packet_capacity,
                config.byte_budget,
                config.smoltcp.mtu,
            )
            .map_err(PlatformError::from_ring)?,
        );
        let egress = Arc::new(
            PacketRing::with_preallocated(
                config.packet_capacity,
                config.byte_budget,
                config.smoltcp.mtu,
            )
            .map_err(PlatformError::from_ring)?,
        );
        Ok(Self {
            ingress,
            egress,
            mtu: config.smoltcp.mtu,
            ingress_producer: Arc::new(Mutex::new(())),
            egress_consumer: Arc::new(Mutex::new(())),
            smoltcp_owner: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Enqueues one complete IP packet from the platform into smoltcp.
    ///
    /// # Errors
    ///
    /// Returns an error when the packet is empty, exceeds the MTU, or the ingress queue is full.
    pub fn ingress_ip(&self, packet: Vec<u8>) -> Result<(), PlatformError> {
        if packet.is_empty() || packet.len() > self.mtu {
            return Err(PlatformError::PacketOutsideMtu {
                len: packet.len(),
                mtu: self.mtu,
            });
        }
        let _guard = lock_recover(&self.ingress_producer);
        self.ingress
            .push(packet)
            .map_err(PlatformError::from_ring)?;
        Ok(())
    }

    /// Copies a borrowed complete IP packet into the preallocated ingress pool.
    ///
    /// The input slice is not retained after this call returns.
    ///
    /// # Errors
    ///
    /// Returns an error when the packet is empty, exceeds the MTU, or the ingress queue is full.
    pub fn ingress_ip_borrowed(&self, packet: &[u8]) -> Result<(), PlatformError> {
        if packet.is_empty() || packet.len() > self.mtu {
            return Err(PlatformError::PacketOutsideMtu {
                len: packet.len(),
                mtu: self.mtu,
            });
        }
        let _guard = lock_recover(&self.ingress_producer);
        self.ingress
            .push_copy(packet)
            .map_err(PlatformError::from_ring)?;
        Ok(())
    }

    /// Returns an owned copy of one complete IP packet produced by smoltcp and recycles its pool
    /// slot. Prefer [`Self::poll_egress_ip_into`] at foreign-function boundaries.
    #[must_use]
    pub fn poll_egress_ip(&self) -> Option<Vec<u8>> {
        let _guard = lock_recover(&self.egress_consumer);
        let packet = self.egress.pop()?;
        let owned = packet.clone();
        self.egress.recycle_buffer(packet);
        Some(owned)
    }

    /// Copies one complete IP packet into a caller-owned buffer and recycles its slab slot.
    ///
    /// # Errors
    ///
    /// Returns an error without dequeuing when the output buffer is too small.
    pub fn poll_egress_ip_into(&self, output: &mut [u8]) -> Result<Option<usize>, PlatformError> {
        let _guard = lock_recover(&self.egress_consumer);
        self.egress
            .pop_into(output)
            .map_err(PlatformError::from_ring)
    }

    /// Builds the single-owner smoltcp device for this bridge.
    ///
    /// A bridge permits only one active device owner at a time.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied smoltcp configuration is invalid, its MTU differs from
    /// the bridge, or another device owner is active.
    pub fn smoltcp_device(&self, config: SmoltcpConfig) -> Result<RingDevice, PlatformError> {
        config.validate()?;
        if config.mtu != self.mtu {
            return Err(PlatformError::SmoltcpMtuMismatch {
                expected: self.mtu,
                actual: config.mtu,
            });
        }
        self.smoltcp_owner
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| PlatformError::SmoltcpOwnerBusy)?;
        let device = RingDevice::new(Arc::clone(&self.ingress), Arc::clone(&self.egress), config);
        match device {
            Ok(device) => Ok(device.with_owner(Arc::clone(&self.smoltcp_owner))),
            Err(error) => {
                self.smoltcp_owner.store(false, Ordering::Release);
                Err(error.into())
            }
        }
    }

    #[must_use]
    pub fn ingress_len(&self) -> usize {
        self.ingress.len()
    }

    #[must_use]
    pub fn egress_len(&self) -> usize {
        self.egress.len()
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum PlatformError {
    #[error("packet queue capacity must be nonzero")]
    ZeroPacketCapacity,
    #[error("packet queue byte budget must be nonzero")]
    ZeroByteBudget,
    #[error("packet pool reservation exceeds byte budget")]
    PoolBudgetExceeded,
    #[error("packet queue is full or packet exceeds its byte budget")]
    PacketQueueFull,
    #[error("output buffer capacity {capacity} is smaller than required {required}")]
    BufferTooSmall { required: usize, capacity: usize },
    #[error(transparent)]
    Smoltcp(#[from] SmoltcpError),
    #[error("smoltcp owner is already active for this packet bridge")]
    SmoltcpOwnerBusy,
    #[error("smoltcp device MTU {actual} does not match packet bridge MTU {expected}")]
    SmoltcpMtuMismatch { expected: usize, actual: usize },
    #[error("IP packet length {len} is outside MTU {mtu}")]
    PacketOutsideMtu { len: usize, mtu: usize },
}

impl PlatformError {
    #[allow(clippy::needless_pass_by_value)]
    fn from_ring(error: RingError) -> Self {
        match error {
            RingError::ZeroCapacity => Self::ZeroPacketCapacity,
            RingError::ZeroByteBudget | RingError::ZeroSlotCapacity => Self::ZeroByteBudget,
            RingError::PoolBudgetExceeded { .. } | RingError::PoolInitializationFailed => {
                Self::PoolBudgetExceeded
            }
            RingError::BufferTooSmall { required, capacity } => {
                Self::BufferTooSmall { required, capacity }
            }
            RingError::Full(_) | RingError::TooLarge { .. } => Self::PacketQueueFull,
        }
    }
}
