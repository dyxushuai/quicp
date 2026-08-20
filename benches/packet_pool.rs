use std::hint::black_box;
use std::time::Instant;

#[path = "../src/packet_ring.rs"]
mod packet_ring;
use packet_ring::PacketRing;

#[cfg(debug_assertions)]
const ITERATIONS: usize = 50_000;
#[cfg(not(debug_assertions))]
const ITERATIONS: usize = 1_000_000;

const PAYLOADS: &[usize] = &[64, 1200, 4096];

fn main() {
    println!(
        "payload_bytes,owned_ns_per_packet,pooled_copy_ns_per_packet,owned_payload_gbps,pooled_payload_gbps"
    );
    for &payload_size in PAYLOADS {
        let owned = owned_round_trip(payload_size);
        let pooled = pooled_copy_round_trip(payload_size);
        let owned_ns = owned / u128::from(ITERATIONS as u64);
        let pooled_ns = pooled / u128::from(ITERATIONS as u64);
        println!(
            "{payload_size},{owned_ns},{pooled_ns},{},{}",
            gbps(payload_size, owned_ns),
            gbps(payload_size, pooled_ns),
        );
    }
}

fn owned_round_trip(payload_size: usize) -> u128 {
    let ring = PacketRing::new(1, payload_size).expect("owned ring");
    let input = vec![0x5a; payload_size];
    let mut output = vec![0; payload_size];
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        ring.push(input.clone()).expect("owned push");
        let packet = ring.pop().expect("owned pop");
        output.copy_from_slice(&packet);
        black_box(&output);
    }
    start.elapsed().as_nanos()
}

fn pooled_copy_round_trip(payload_size: usize) -> u128 {
    let ring = PacketRing::with_preallocated(1, payload_size, payload_size).expect("pooled ring");
    let input = vec![0x5a; payload_size];
    let mut output = vec![0; payload_size];
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        ring.push_copy(&input).expect("pooled push");
        black_box(ring.pop_into(&mut output).expect("pooled pop"));
    }
    start.elapsed().as_nanos()
}

fn gbps(payload_size: usize, elapsed_nanos_per_packet: u128) -> String {
    let milli_gbps = u128::try_from(payload_size)
        .expect("payload size fits u128")
        .saturating_mul(8_000)
        .checked_div(elapsed_nanos_per_packet)
        .unwrap_or(0);
    format!("{}.{:03}", milli_gbps / 1_000, milli_gbps % 1_000)
}
