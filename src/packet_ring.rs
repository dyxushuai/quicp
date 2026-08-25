//! Bounded packet ownership between the TUN/smoltcp runner and QUICP.
//!
//! Each ring is single-producer/single-consumer (SPSC).  The byte budget is tracked separately so
//! a queue with many tiny packets cannot consume an unbounded amount of memory through packet
//! vectors.

#![allow(unsafe_code)]

use alloc::{boxed::Box, vec, vec::Vec};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

use thiserror::Error;

/// A bounded, allocation-owning packet queue for exactly one producer and one consumer.
///
/// The ingress and egress rings each have one producer and one consumer.  Cloning the containing
/// `Arc` is fine for passing a ring to those two owners, but concurrent calls from multiple
/// producers or multiple consumers are not supported.
#[derive(Debug)]
pub struct PacketRing {
    queue: SpscQueue<Vec<u8>>,
    free: Option<SpscQueue<Vec<u8>>>,
    slot_capacity: Option<usize>,
    bytes: ByteCounters,
    byte_budget: usize,
}

impl PacketRing {
    /// Creates a ring with independent packet-slot and byte budgets.
    ///
    /// # Errors
    ///
    /// Returns an error when either budget is zero.
    #[allow(dead_code)]
    pub fn new(capacity: usize, byte_budget: usize) -> Result<Self, RingError> {
        if capacity == 0 {
            return Err(RingError::ZeroCapacity);
        }
        if byte_budget == 0 {
            return Err(RingError::ZeroByteBudget);
        }
        Ok(Self {
            queue: SpscQueue::new(capacity),
            free: None,
            slot_capacity: None,
            bytes: ByteCounters::default(),
            byte_budget,
        })
    }

    /// Creates a ring with a preallocated fixed-size packet pool.
    ///
    /// Each slot is allocated once and returned to the pool after a consumer calls
    /// [`PacketRing::recycle_buffer`].  The aggregate reservation is charged to the byte budget
    /// so the pool cannot silently exceed the configured memory limit.
    ///
    /// # Errors
    ///
    /// Returns an error when a budget is zero, a slot is zero, or the pool reservation exceeds
    /// the byte budget.
    pub fn with_preallocated(
        capacity: usize,
        byte_budget: usize,
        slot_capacity: usize,
    ) -> Result<Self, RingError> {
        if capacity == 0 {
            return Err(RingError::ZeroCapacity);
        }
        if byte_budget == 0 {
            return Err(RingError::ZeroByteBudget);
        }
        if slot_capacity == 0 {
            return Err(RingError::ZeroSlotCapacity);
        }
        let reservation =
            capacity
                .checked_mul(slot_capacity)
                .ok_or(RingError::PoolBudgetExceeded {
                    slots: capacity,
                    slot_capacity,
                    byte_budget,
                })?;
        if reservation > byte_budget {
            return Err(RingError::PoolBudgetExceeded {
                slots: capacity,
                slot_capacity,
                byte_budget,
            });
        }
        let free = SpscQueue::new(capacity);
        for _ in 0..capacity {
            free.push(Vec::with_capacity(slot_capacity))
                .map_err(|_| RingError::PoolInitializationFailed)?;
        }
        Ok(Self {
            queue: SpscQueue::new(capacity),
            free: Some(free),
            slot_capacity: Some(slot_capacity),
            bytes: ByteCounters::default(),
            byte_budget,
        })
    }

    /// Enqueues one owned packet without copying it.
    ///
    /// # Errors
    ///
    /// Returns the packet inside [`RingError::Full`] if a slot or byte budget is exhausted.
    pub fn push(&self, packet: Vec<u8>) -> Result<(), RingError> {
        if packet.len() > self.byte_budget {
            return Err(RingError::TooLarge {
                len: packet.len(),
                max: self.byte_budget,
            });
        }
        let produced = self.bytes.produced.0.load(Ordering::Relaxed);
        let consumed = self.bytes.consumed.0.load(Ordering::Acquire);
        let used = produced.wrapping_sub(consumed);
        if used
            .checked_add(packet.len())
            .is_none_or(|total| total > self.byte_budget)
        {
            return Err(RingError::Full(packet));
        }
        self.bytes
            .produced
            .0
            .store(produced.wrapping_add(packet.len()), Ordering::Release);
        match self.queue.push(packet) {
            Ok(()) => Ok(()),
            Err(packet) => {
                self.bytes.produced.0.store(produced, Ordering::Release);
                Err(RingError::Full(packet))
            }
        }
    }

    /// Copies a borrowed packet into the ring, reusing a preallocated slot when available.
    ///
    /// A pooled ring performs no heap allocation on the successful path.  The input slice is
    /// never retained after this call returns.
    ///
    /// # Errors
    ///
    /// Returns an error when the packet exceeds the byte budget or no queue/pool slot is
    /// available. The `Full` error carries an empty vector because the input is borrowed.
    pub fn push_copy(&self, packet: &[u8]) -> Result<(), RingError> {
        if packet.len() > self.byte_budget {
            return Err(RingError::TooLarge {
                len: packet.len(),
                max: self.byte_budget,
            });
        }
        if !self.can_fit(packet.len()) || !self.has_buffer_for(packet.len()) {
            return Err(RingError::Full(Vec::new()));
        }
        let mut buffer = self
            .acquire_buffer(0)
            .ok_or_else(|| RingError::Full(Vec::new()))?;
        // Extending an empty preallocated Vec writes the payload directly into spare capacity;
        // requesting `packet.len()` above would zero-fill it before this copy.
        buffer.extend_from_slice(packet);
        match self.push(buffer) {
            Ok(()) => Ok(()),
            Err(RingError::Full(_buffer)) => Err(RingError::Full(Vec::new())),
            Err(error) => Err(error),
        }
    }

    /// Removes the oldest packet, if one is available.
    #[allow(dead_code)]
    pub fn pop(&self) -> Option<Vec<u8>> {
        let packet = self.queue.pop()?;
        let consumed = self.bytes.consumed.0.load(Ordering::Relaxed);
        self.bytes
            .consumed
            .0
            .store(consumed.wrapping_add(packet.len()), Ordering::Release);
        Some(packet)
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
        let Some(required) = self.queue.peek().map(Vec::len) else {
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
        let consumed = self.bytes.consumed.0.load(Ordering::Relaxed);
        self.bytes
            .consumed
            .0
            .store(consumed.wrapping_add(length), Ordering::Release);
        self.recycle_buffer(packet);
        Ok(Some(length))
    }

    /// Acquires a reusable packet buffer, or allocates one for a non-pooled ring.
    ///
    /// Only the single producer may call this method.
    ///
    /// A pooled ring never allocates after construction.  `None` means that the pool is
    /// exhausted or the requested packet does not fit its fixed slot size.
    pub fn acquire_buffer(&self, len: usize) -> Option<Vec<u8>> {
        if len > self.byte_budget {
            return None;
        }
        match (&self.free, self.slot_capacity) {
            (Some(free), Some(slot_capacity)) if len <= slot_capacity => {
                let mut buffer = free.pop()?;
                buffer.clear();
                buffer.resize(len, 0);
                Some(buffer)
            }
            (None, None) => Some(vec![0; len]),
            _ => None,
        }
    }

    /// Returns a packet buffer to the fixed-size pool when one is configured.
    ///
    /// Only the single consumer may call this method.
    pub fn recycle_buffer(&self, mut packet: Vec<u8>) {
        let Some((free, slot_capacity)) = self.free.as_ref().zip(self.slot_capacity) else {
            return;
        };
        if packet.capacity() != slot_capacity {
            return;
        }
        packet.clear();
        let _ = free.push(packet);
    }

    #[must_use]
    pub fn has_buffer_for(&self, len: usize) -> bool {
        match (&self.free, self.slot_capacity) {
            (Some(free), Some(slot_capacity)) => len <= slot_capacity && !free.is_empty(),
            (None, None) => len <= self.byte_budget,
            _ => false,
        }
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn available_buffers(&self) -> Option<usize> {
        self.free.as_ref().map(SpscQueue::len)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
            .produced
            .0
            .load(Ordering::Acquire)
            .wrapping_sub(self.bytes.consumed.0.load(Ordering::Acquire))
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.queue.capacity()
    }

    #[must_use]
    pub fn can_fit(&self, max_packet_bytes: usize) -> bool {
        self.len() < self.capacity()
            && self
                .bytes()
                .checked_add(max_packet_bytes)
                .is_some_and(|total| total <= self.byte_budget)
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

#[derive(Debug, Default)]
struct ByteCounters {
    produced: CachePadded<AtomicUsize>,
    consumed: CachePadded<AtomicUsize>,
}

#[repr(align(64))]
#[derive(Debug)]
struct CachePadded<T>(T);

impl Default for CachePadded<AtomicUsize> {
    fn default() -> Self {
        Self(AtomicUsize::new(0))
    }
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

    fn peek(&self) -> Option<&T> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let slot = &self.slots[head % self.capacity()];
        // SAFETY: the acquire-load observes an initialized slot. The consumer keeps the slot
        // occupied until it calls `pop`, so the returned reference cannot be concurrently reused.
        Some(unsafe { (*slot.value.get()).assume_init_ref() })
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
    #[error("packet ring byte budget must be nonzero")]
    ZeroByteBudget,
    #[error("packet ring slot capacity must be nonzero")]
    ZeroSlotCapacity,
    #[error("packet pool reservation {slots}x{slot_capacity} exceeds byte budget {byte_budget}")]
    PoolBudgetExceeded {
        slots: usize,
        slot_capacity: usize,
        byte_budget: usize,
    },
    #[error("packet pool initialization failed")]
    PoolInitializationFailed,
    #[error("packet length {len} exceeds ring byte budget {max}")]
    TooLarge { len: usize, max: usize },
    #[error("output buffer capacity {capacity} is smaller than required {required}")]
    BufferTooSmall { required: usize, capacity: usize },
    #[error("packet ring is full")]
    Full(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use std::sync::Arc;
    use std::thread;

    use super::{PacketRing, RingError};

    #[test]
    fn bounded_ring_moves_packets_without_copying_the_payload() {
        let ring = PacketRing::new(2, 8).expect("ring");
        let packet = vec![1, 2, 3];
        let pointer = packet.as_ptr();
        ring.push(packet).expect("push");
        let packet = ring.pop().expect("pop");
        assert_eq!(packet, [1, 2, 3]);
        assert_eq!(packet.as_ptr(), pointer);
        assert_eq!(ring.bytes(), 0);
    }

    #[test]
    fn ring_rejects_byte_budget_and_slot_overflow_without_silent_drop() {
        let ring = PacketRing::new(1, 4).expect("ring");
        assert!(matches!(
            ring.push(vec![1, 2, 3, 4, 5]),
            Err(RingError::TooLarge { .. })
        ));
        ring.push(vec![1, 2, 3]).expect("first push");
        let error = ring.push(vec![4]).expect_err("slot is full");
        assert!(matches!(error, RingError::Full(_)));
        assert_eq!(ring.pop().expect("first packet"), [1, 2, 3]);
    }

    #[test]
    fn preallocated_ring_reuses_packet_buffers() {
        let ring = PacketRing::with_preallocated(1, 8, 8).expect("ring");
        assert_eq!(ring.available_buffers(), Some(1));
        let mut packet = ring.acquire_buffer(3).expect("buffer");
        packet.copy_from_slice(&[1, 2, 3]);
        ring.push(packet).expect("push");
        let packet = ring.pop().expect("pop");
        let pointer = packet.as_ptr();
        ring.recycle_buffer(packet);
        assert_eq!(ring.available_buffers(), Some(1));
        let packet = ring.acquire_buffer(4).expect("reused buffer");
        assert_eq!(packet.as_ptr(), pointer);
    }

    #[test]
    fn preallocated_ring_charges_the_pool_to_the_budget() {
        assert!(matches!(
            PacketRing::with_preallocated(2, 3, 2),
            Err(RingError::PoolBudgetExceeded { .. })
        ));
    }

    #[test]
    fn pop_into_keeps_a_packet_when_the_output_buffer_is_small() {
        let ring = PacketRing::with_preallocated(1, 8, 8).expect("ring");
        ring.push_copy(&[1, 2, 3]).expect("push");
        let mut small = [0; 2];
        assert!(matches!(
            ring.pop_into(&mut small),
            Err(RingError::BufferTooSmall {
                required: 3,
                capacity: 2
            })
        ));
        assert_eq!(ring.len(), 1);
        let mut output = [0; 8];
        assert_eq!(ring.pop_into(&mut output).expect("pop"), Some(3));
        assert_eq!(&output[..3], [1, 2, 3]);
        assert_eq!(ring.available_buffers(), Some(1));
    }

    #[test]
    fn spsc_ring_transfers_packets_between_two_threads() {
        const COUNT: usize = 100_000;
        let ring = Arc::new(PacketRing::new(64, COUNT).expect("ring"));
        let producer_ring = Arc::clone(&ring);
        let producer = thread::spawn(move || {
            for value in 0..COUNT {
                let packet = vec![u8::try_from(value % 251).expect("value fits")];
                loop {
                    if producer_ring.push(packet.clone()).is_ok() {
                        break;
                    }
                    std::hint::spin_loop();
                }
            }
        });

        for value in 0..COUNT {
            loop {
                if let Some(packet) = ring.pop() {
                    assert_eq!(packet, [u8::try_from(value % 251).expect("value fits")]);
                    break;
                }
                std::hint::spin_loop();
            }
        }
        producer.join().expect("producer");
        assert!(ring.is_empty());
        assert_eq!(ring.bytes(), 0);
    }
}
