#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use quicp::{CarrierDirection, FakeTcpCarrier, FourTuple, SynDataMode};

#[cfg(debug_assertions)]
const SAMPLES: usize = 10_000;
#[cfg(not(debug_assertions))]
const SAMPLES: usize = 200_000;

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(pointer, layout, size) }
    }
}

fn main() {
    println!(
        "payload_bytes,owned_ns_per_packet,borrowed_ns_per_packet,owned_payload_gbps,borrowed_payload_gbps,owned_allocations,borrowed_allocations"
    );
    let samples = u128::try_from(SAMPLES).expect("sample count");
    for payload_size in [64, 1_200, 4_096] {
        let tuple = FourTuple::new(
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), 40_000)),
            SocketAddr::from((Ipv4Addr::new(198, 51, 100, 20), 443)),
        );
        let packets = encoded_packets(tuple, payload_size);

        let mut owned = FakeTcpCarrier::new(
            tuple.reverse(),
            CarrierDirection::ServerToClient,
            SynDataMode::Disabled,
        )
        .expect("owned receiver");
        ALLOCATIONS.store(0, Ordering::Relaxed);
        let start = Instant::now();
        for packet in &packets {
            let decoded = owned.decode_datagram(packet).expect("owned decode");
            black_box(decoded.payload().len());
        }
        let owned_ns = start.elapsed().as_nanos() / samples;
        let owned_allocations = ALLOCATIONS.load(Ordering::Relaxed);

        let mut borrowed = FakeTcpCarrier::new(
            tuple.reverse(),
            CarrierDirection::ServerToClient,
            SynDataMode::Disabled,
        )
        .expect("borrowed receiver");
        ALLOCATIONS.store(0, Ordering::Relaxed);
        let start = Instant::now();
        for packet in &packets {
            let decoded = borrowed
                .decode_datagram_borrowed(packet)
                .expect("borrowed decode");
            black_box(decoded.payload().len());
        }
        let borrowed_ns = start.elapsed().as_nanos() / samples;
        let borrowed_allocations = ALLOCATIONS.load(Ordering::Relaxed);

        println!(
            "{payload_size},{owned_ns},{borrowed_ns},{},{},{},{}",
            gbps(payload_size, owned_ns),
            gbps(payload_size, borrowed_ns),
            owned_allocations,
            borrowed_allocations,
        );
    }
}

fn encoded_packets(tuple: FourTuple, payload_size: usize) -> Vec<Vec<u8>> {
    let payload = vec![0x5a; payload_size];
    let mut sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("sender");
    let mut packets = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        packets.push(sender.encode_datagram(&payload).expect("packet"));
    }
    packets
}

fn gbps(payload_size: usize, elapsed_nanos_per_packet: u128) -> String {
    let milli_gbps = u128::try_from(payload_size)
        .expect("payload size fits u128")
        .saturating_mul(8_000)
        .checked_div(elapsed_nanos_per_packet)
        .unwrap_or(0);
    format!("{}.{:03}", milli_gbps / 1_000, milli_gbps % 1_000)
}
