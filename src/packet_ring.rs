//! Bounded packet ownership between the TUN/smoltcp runner and QUICP.
//!
//! Every packet buffer is allocated at construction and has one owner: the free pool, a queued
//! packet, or a read/write lease. Only short pool operations hold the mutex; callbacks do not.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::vec::Vec;

use thiserror::Error;

/// A bounded, allocation-owning packet queue.
///
/// Holding one of the fixed pool's buffers also reserves a queue slot. Dropping a lease returns
/// its buffer to the pool, including when a callback unwinds.
#[derive(Debug)]
pub struct PacketRing {
    // ponytail: one short pool lock; split directions only if measured contention justifies it.
    pool: Mutex<PacketPool>,
    slot_capacity: usize,
}

/// The mutex provides the exclusive borrow required for every queue and free-list mutation.
/// Neither collection can exceed its initial capacity: leases move buffers, never create them.
#[derive(Debug)]
struct PacketPool {
    queued: VecDeque<Vec<u8>>,
    free: Vec<Vec<u8>>,
}

impl PacketRing {
    /// Creates a ring with a preallocated fixed-size packet pool.
    ///
    /// Each slot is allocated once and returned to the pool when its read lease is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error when the packet count or slot size is zero, or a reservation overflows.
    pub fn new(capacity: usize, slot_capacity: usize) -> Result<Self, RingError> {
        if capacity == 0 {
            return Err(RingError::ZeroCapacity);
        }
        if slot_capacity == 0 {
            return Err(RingError::ZeroSlotCapacity);
        }
        capacity
            .checked_mul(slot_capacity)
            .ok_or(RingError::CapacityOverflow)?;
        capacity
            .checked_mul(core::mem::size_of::<Vec<u8>>())
            .ok_or(RingError::CapacityOverflow)?;
        Ok(Self {
            pool: Mutex::new(PacketPool {
                queued: VecDeque::with_capacity(capacity),
                free: (0..capacity)
                    .map(|_| Vec::with_capacity(slot_capacity))
                    .collect(),
            }),
            slot_capacity,
        })
    }

    /// Copies a borrowed packet into the ring, reusing a preallocated slot when available.
    ///
    /// A pooled ring performs no heap allocation on the successful path.  The input slice is
    /// never retained after this call returns.
    ///
    /// # Errors
    ///
    /// Returns an error when the packet exceeds the slot size or no queue/pool slot is available.
    pub fn push_copy(&self, packet: &[u8]) -> Result<(), RingError> {
        if packet.len() > self.slot_capacity {
            return Err(RingError::TooLarge {
                len: packet.len(),
                max: self.slot_capacity,
            });
        }
        let write = self.write().ok_or(RingError::Full)?;
        write.consume(packet.len(), |output| output.copy_from_slice(packet));
        Ok(())
    }

    /// Removes the oldest packet and recycles its buffer when the lease is dropped.
    #[cfg(any(feature = "platform-smoltcp", test))]
    pub fn read(&self) -> Option<ReadPacket<'_>> {
        Some(ReadPacket {
            packet: lock_recover(&self.pool).queued.pop_front()?,
            ring: self,
        })
    }

    /// Copies the oldest packet into a caller-owned buffer and recycles the slot.
    ///
    /// The packet remains queued when `output` is too small.
    ///
    /// # Errors
    ///
    /// Returns [`RingError::BufferTooSmall`] without dequeuing when the output cannot hold the
    /// packet.
    pub fn pop_into(&self, output: &mut [u8]) -> Result<Option<usize>, RingError> {
        let mut pool = lock_recover(&self.pool);
        let Some(required) = pool.queued.front().map(Vec::len) else {
            return Ok(None);
        };
        if required > output.len() {
            return Err(RingError::BufferTooSmall {
                required,
                capacity: output.len(),
            });
        }
        let Some(packet) = pool.queued.pop_front() else {
            return Ok(None);
        };
        drop(pool);
        let length = packet.len();
        output[..length].copy_from_slice(&packet);
        self.recycle(packet);
        Ok(Some(length))
    }

    /// Reserves one preallocated packet slot until the lease is consumed or dropped.
    pub fn write(&self) -> Option<WritePacket<'_>> {
        let packet = lock_recover(&self.pool).free.pop()?;
        // Every buffer belongs to this fixed pool, so acquiring one also reserves a queue slot.
        Some(WritePacket {
            packet: Some(packet),
            ring: self,
        })
    }

    fn recycle(&self, mut packet: Vec<u8>) {
        packet.clear();
        lock_recover(&self.pool).free.push(packet);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        lock_recover(&self.pool).queued.is_empty()
    }
}

/// A consumer-owned packet whose buffer returns to the pool even during unwinding.
#[cfg(any(feature = "platform-smoltcp", test))]
#[derive(Debug)]
pub struct ReadPacket<'a> {
    packet: Vec<u8>,
    ring: &'a PacketRing,
}

#[cfg(any(feature = "platform-smoltcp", test))]
impl ReadPacket<'_> {
    pub fn consume<R>(self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.packet)
    }
}

#[cfg(any(feature = "platform-smoltcp", test))]
impl Drop for ReadPacket<'_> {
    fn drop(&mut self) {
        self.ring.recycle(core::mem::take(&mut self.packet));
    }
}

/// A reserved packet slot whose buffer returns to the pool unless it is queued.
#[derive(Debug)]
pub struct WritePacket<'a> {
    packet: Option<Vec<u8>>,
    ring: &'a PacketRing,
}

impl WritePacket<'_> {
    pub fn consume<R>(mut self, len: usize, f: impl FnOnce(&mut [u8]) -> R) -> R {
        let packet = self.packet.as_mut().expect("reserved packet");
        packet.clear();
        packet.resize(len.min(self.ring.slot_capacity), 0);
        let result = f(packet);
        if len <= self.ring.slot_capacity {
            let packet = self.packet.take().expect("reserved packet");
            lock_recover(&self.ring.pool).queued.push_back(packet);
        }
        result
    }
}

impl Drop for WritePacket<'_> {
    fn drop(&mut self) {
        if let Some(packet) = self.packet.take() {
            self.ring.recycle(packet);
        }
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug, Error, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum RingError {
    #[error("packet ring capacity must be nonzero")]
    ZeroCapacity,
    #[error("packet ring slot capacity must be nonzero")]
    ZeroSlotCapacity,
    #[error("packet ring reservation overflows usize")]
    CapacityOverflow,
    #[error("packet length {len} exceeds ring slot capacity {max}")]
    TooLarge { len: usize, max: usize },
    #[error("output buffer capacity {capacity} is smaller than required {required}")]
    BufferTooSmall { required: usize, capacity: usize },
    #[error("packet ring is full")]
    Full,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::{PacketRing, RingError};

    #[test]
    fn non_power_of_two_ring_wraps_without_reusing_live_slots() {
        let ring = PacketRing::new(3, 2).expect("ring");
        for batch in 0..4 {
            for value in 0..3 {
                ring.push_copy(&[batch, value]).expect("available slot");
            }
            assert_eq!(ring.push_copy(&[99]), Err(RingError::Full));
            for value in 0..3 {
                ring.read().expect("packet").consume(|packet| {
                    assert_eq!(packet, [batch, value]);
                });
            }
            assert!(ring.read().is_none());
            assert!(ring.is_empty());
        }
    }

    #[test]
    fn ring_rejects_packet_and_slot_overflow_without_silent_drop() {
        let ring = PacketRing::new(1, 4).expect("ring");
        assert!(matches!(
            ring.push_copy(&[1, 2, 3, 4, 5]),
            Err(RingError::TooLarge { .. })
        ));
        ring.push_copy(&[1, 2, 3]).expect("first push");
        assert_eq!(ring.push_copy(&[4]), Err(RingError::Full));
        let mut output = [0; 4];
        assert_eq!(ring.pop_into(&mut output).expect("first packet"), Some(3));
        assert_eq!(&output[..3], [1, 2, 3]);
    }

    #[test]
    fn preallocated_ring_reuses_packet_buffers() {
        let ring = PacketRing::new(1, 8).expect("ring");
        ring.push_copy(&[1, 2, 3]).expect("push");
        let pointer = ring.read().expect("read").consume(|packet| {
            assert!(ring.is_empty(), "read callbacks do not hold the pool lock");
            packet.as_ptr()
        });
        ring.write().expect("reused buffer").consume(4, |packet| {
            assert!(ring.is_empty(), "write callbacks do not hold the pool lock");
            assert_eq!(packet.as_ptr(), pointer);
        });
    }

    #[test]
    fn cancelled_writes_preserve_the_preallocated_pool() {
        let ring = PacketRing::new(1, 8).expect("ring");
        let pointer = ring.write().expect("write").consume(usize::MAX, |packet| {
            assert_eq!(packet.len(), 8);
            packet.as_ptr()
        });
        assert!(ring.is_empty());
        drop(ring.write().expect("unused write"));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ring.write().expect("panicking write").consume(1, |_| {
                    panic!("cancel packet");
                });
            }))
            .is_err()
        );
        assert!(ring.is_empty());
        ring.write().expect("reused write").consume(1, |packet| {
            assert_eq!(packet.as_ptr(), pointer);
            packet[0] = 7;
        });
        assert!(ring.write().is_none());
        ring.read().expect("committed packet").consume(|packet| {
            assert_eq!(packet, [7]);
            assert_eq!(packet.as_ptr(), pointer);
        });
    }

    #[test]
    fn outstanding_write_leases_reserve_queue_slots_and_recycle_on_drop() {
        let ring = PacketRing::new(2, 8).expect("ring");
        let first = ring.write().expect("first slot");
        let second = ring.write().expect("second slot");
        assert!(ring.write().is_none());
        drop((first, second));
        ring.push_copy(&[1]).expect("first returned slot");
        ring.push_copy(&[2]).expect("second returned slot");
        assert_eq!(ring.push_copy(&[3]), Err(RingError::Full));
    }

    #[test]
    fn ring_rejects_invalid_pool_dimensions() {
        assert!(matches!(
            PacketRing::new(0, 1),
            Err(RingError::ZeroCapacity)
        ));
        assert!(matches!(
            PacketRing::new(1, 0),
            Err(RingError::ZeroSlotCapacity)
        ));
        assert!(matches!(
            PacketRing::new(usize::MAX, 1),
            Err(RingError::CapacityOverflow)
        ));
    }

    #[test]
    fn pop_into_keeps_a_packet_when_the_output_buffer_is_small() {
        let ring = PacketRing::new(1, 8).expect("ring");
        ring.push_copy(&[1, 2, 3]).expect("push");
        let mut small = [0; 2];
        assert!(matches!(
            ring.pop_into(&mut small),
            Err(RingError::BufferTooSmall {
                required: 3,
                capacity: 2
            })
        ));
        let mut output = [0; 8];
        assert_eq!(ring.pop_into(&mut output).expect("pop"), Some(3));
        assert_eq!(&output[..3], [1, 2, 3]);
        assert!(ring.write().is_some());
    }

    #[test]
    fn ring_transfers_packets_between_two_threads() {
        const COUNT: usize = 100_000;
        let ring = Arc::new(PacketRing::new(64, 1).expect("ring"));
        let producer_ring = Arc::clone(&ring);
        let producer = thread::spawn(move || {
            for value in 0..COUNT {
                loop {
                    if producer_ring
                        .push_copy(&[u8::try_from(value % 251).expect("value fits")])
                        .is_ok()
                    {
                        break;
                    }
                    std::hint::spin_loop();
                }
            }
        });

        for value in 0..COUNT {
            loop {
                let mut packet = [0];
                if ring.pop_into(&mut packet).expect("pop").is_some() {
                    assert_eq!(packet, [u8::try_from(value % 251).expect("value fits")]);
                    break;
                }
                std::hint::spin_loop();
            }
        }
        producer.join().expect("producer");
        assert!(ring.is_empty());
    }

    #[test]
    fn ring_serializes_concurrent_producers_and_consumers() {
        const WORKERS: usize = 4;
        const PER_WORKER: usize = 1000;
        let ring = Arc::new(PacketRing::new(8, 8).expect("ring"));
        let producers = (0..WORKERS)
            .map(|worker| {
                let ring = Arc::clone(&ring);
                thread::spawn(move || {
                    for offset in 0..PER_WORKER {
                        if let Some(write) = ring.write() {
                            write.consume(usize::MAX, |_| ());
                        }
                        let packet = (worker * PER_WORKER + offset).to_le_bytes();
                        loop {
                            match ring.push_copy(&packet) {
                                Ok(()) => break,
                                Err(RingError::Full) => thread::yield_now(),
                                Err(error) => panic!("unexpected write error: {error}"),
                            }
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        let consumers = (0..WORKERS)
            .map(|_| {
                let ring = Arc::clone(&ring);
                thread::spawn(move || {
                    let mut received = Vec::with_capacity(PER_WORKER);
                    while received.len() < PER_WORKER {
                        let mut packet = [0; core::mem::size_of::<usize>()];
                        if ring.pop_into(&mut packet).expect("read").is_some() {
                            received.push(usize::from_le_bytes(packet));
                        } else {
                            thread::yield_now();
                        }
                    }
                    received
                })
            })
            .collect::<Vec<_>>();
        for producer in producers {
            producer.join().expect("producer");
        }
        let mut received = consumers
            .into_iter()
            .flat_map(|consumer| consumer.join().expect("consumer"))
            .collect::<Vec<_>>();
        received.sort_unstable();
        assert_eq!(received, (0..WORKERS * PER_WORKER).collect::<Vec<_>>());
        assert!(ring.is_empty());
    }
}
