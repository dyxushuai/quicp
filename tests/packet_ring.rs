use std::sync::Arc;
use std::thread;

#[path = "../src/packet_ring.rs"]
mod packet_ring;
use packet_ring::{PacketRing, RingError};

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
