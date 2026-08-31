//! Bounded packet ownership between the TUN/smoltcp runner and QUICP.
//!
//! Each ring is single-producer/single-consumer (SPSC) and reserves every packet slot at
//! construction.

#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::{boxed::Box, vec::Vec};

use thiserror::Error;

/// A bounded, allocation-owning packet queue for exactly one producer and one consumer.
///
/// The ingress and egress rings each have one producer and one consumer.  Cloning the containing
/// `Arc` is fine for passing a ring to those two owners, but concurrent calls from multiple
/// producers or multiple consumers are not supported.
#[derive(Debug)]
pub struct PacketRing {
    queue: SpscQueue<Vec<u8>>,
    free: SpscQueue<Vec<u8>>,
    slot_capacity: usize,
}

impl PacketRing {
    /// Creates a ring with a preallocated fixed-size packet pool.
    ///
    /// Each slot is allocated once and returned to the pool after a consumer calls
    /// [`PacketRing::recycle_buffer`].
    ///
    /// # Errors
    ///
    /// Returns an error when the packet count or slot size is zero, or their product overflows.
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
        let free = SpscQueue::new(capacity);
        for _ in 0..capacity {
            free.push(Vec::with_capacity(slot_capacity))
                .map_err(|_| RingError::CapacityOverflow)?;
        }
        Ok(Self {
            queue: SpscQueue::new(capacity),
            free,
            slot_capacity,
        })
    }

    /// Enqueues one owned packet without copying it.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet exceeds the fixed slot size or the queue is full.
    pub fn push(&self, packet: Vec<u8>) -> Result<(), RingError> {
        if packet.len() > self.slot_capacity {
            return Err(RingError::TooLarge {
                len: packet.len(),
                max: self.slot_capacity,
            });
        }
        match self.queue.push(packet) {
            Ok(()) => Ok(()),
            Err(_) => Err(RingError::Full),
        }
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
        if !self.can_push(packet.len()) {
            return Err(RingError::Full);
        }
        let mut buffer = self.acquire_buffer(0).ok_or(RingError::Full)?;
        buffer.extend_from_slice(packet);
        self.push(buffer)
    }

    /// Removes the oldest packet, if one is available.
    #[cfg(any(feature = "platform-smoltcp", test))]
    pub fn pop(&self) -> Option<Vec<u8>> {
        self.queue.pop()
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
        let Some(required) = self.queue.front_len() else {
            return Ok(None);
        };
        if required > output.len() {
            return Err(RingError::BufferTooSmall {
                required,
                capacity: output.len(),
            });
        }
        let Some(packet) = self.queue.pop() else {
            return Ok(None);
        };
        let length = packet.len();
        output[..length].copy_from_slice(&packet);
        self.recycle_buffer(packet);
        Ok(Some(length))
    }

    /// Acquires a reusable packet buffer.
    ///
    /// Only the single producer may call this method.
    ///
    /// `None` means that the pool is exhausted or the requested packet does not fit its fixed
    /// slot size.
    pub fn acquire_buffer(&self, len: usize) -> Option<Vec<u8>> {
        if len > self.slot_capacity {
            return None;
        }
        let mut buffer = self.free.pop()?;
        buffer.clear();
        buffer.resize(len, 0);
        Some(buffer)
    }

    /// Returns a packet buffer to the fixed-size pool.
    ///
    /// Only the single consumer may call this method.
    pub fn recycle_buffer(&self, mut packet: Vec<u8>) {
        if packet.capacity() < self.slot_capacity {
            return;
        }
        packet.clear();
        let _ = self.free.push(packet);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    #[must_use]
    pub fn can_push(&self, packet_len: usize) -> bool {
        packet_len <= self.slot_capacity
            && self.queue.len() < self.queue.capacity()
            && !self.free.is_empty()
    }
}

/// A bounded lock-free queue with one producer and one consumer.
#[derive(Debug)]
struct SpscQueue<T> {
    slots: Box<[SpscSlot<T>]>,
    head: AtomicUsize,
    tail: AtomicUsize,
}

#[derive(Debug)]
struct SpscSlot<T> {
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: a slot is only accessed by the single producer before publication or by the single
// consumer after publication. The atomic indices establish the happens-before edges.
unsafe impl<T: Send> Send for SpscQueue<T> {}
// SAFETY: the SPSC ownership contract prevents concurrent access to the same slot. Atomic indices
// synchronize publication and reclamation across the two owners.
unsafe impl<T: Send> Sync for SpscQueue<T> {}

impl<T> SpscQueue<T> {
    fn new(capacity: usize) -> Self {
        let slots = (0..capacity)
            .map(|_| SpscSlot {
                value: UnsafeCell::new(MaybeUninit::uninit()),
            })
            .collect();
        Self {
            slots,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    fn push(&self, value: T) -> Result<(), T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) == self.capacity() {
            return Err(value);
        }
        let slot = &self.slots[tail % self.capacity()];
        // SAFETY: the producer owns this slot until the release-store below publishes it.
        unsafe { (*slot.value.get()).write(value) };
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    fn pop(&self) -> Option<T> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let slot = &self.slots[head % self.capacity()];
        // SAFETY: the acquire-load observes a fully initialized slot published by the producer.
        let value = unsafe { (*slot.value.get()).assume_init_read() };
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Some(value)
    }

    fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }

    fn is_empty(&self) -> bool {
        SpscQueue::<T>::len(self) == 0
    }

    const fn capacity(&self) -> usize {
        self.slots.len()
    }
}

impl SpscQueue<Vec<u8>> {
    fn front_len(&self) -> Option<usize> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let slot = &self.slots[head % self.capacity()];
        // SAFETY: this is the single consumer, and copying the length does not let a reference
        // escape before the subsequent pop.
        Some(unsafe { (*slot.value.get()).assume_init_ref().len() })
    }
}

impl<T> Drop for SpscQueue<T> {
    fn drop(&mut self) {
        while SpscQueue::<T>::pop(self).is_some() {}
    }
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
        let mut packet = ring.acquire_buffer(3).expect("buffer");
        packet.copy_from_slice(&[1, 2, 3]);
        ring.push(packet).expect("push");
        let packet = ring.pop().expect("pop");
        let pointer = packet.as_ptr();
        ring.recycle_buffer(packet);
        let packet = ring.acquire_buffer(4).expect("reused buffer");
        assert_eq!(packet.as_ptr(), pointer);
    }

    #[test]
    fn full_ring_rejection_preserves_consumer_owned_pool() {
        let ring = PacketRing::new(1, 8).expect("ring");
        let mut pooled = ring.acquire_buffer(1).expect("pooled buffer");
        pooled[0] = 1;
        let pooled_pointer = pooled.as_ptr();
        ring.push(pooled).expect("fill ring");

        let mut rejected = Vec::with_capacity(8);
        rejected.push(2);
        assert_eq!(ring.push(rejected), Err(RingError::Full));

        let packet = ring.pop().expect("pop pooled packet");
        ring.recycle_buffer(packet);
        let reused = ring.acquire_buffer(1).expect("reused pooled buffer");
        assert_eq!(reused.as_ptr(), pooled_pointer);
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
        assert!(ring.can_push(8));
    }

    #[test]
    fn spsc_ring_transfers_packets_between_two_threads() {
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
}
