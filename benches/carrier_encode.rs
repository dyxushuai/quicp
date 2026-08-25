#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use quicp::{CarrierDirection, FakeTcpCarrier, FourTuple, SynDataMode};

#[cfg(debug_assertions)]
const ITERATIONS: usize = 50_000;
#[cfg(not(debug_assertions))]
const ITERATIONS: usize = 1_000_000;

const PAYLOADS: &[usize] = &[64, 1200, 4096];
const OUTPUT_BYTES: usize = u16::MAX as usize;

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

struct Measurement {
    nanos: u128,
    allocations: usize,
}

fn main() {
    println!(
        "payload_bytes,vec_ns_per_packet,buffer_ns_per_packet,vec_payload_gbps,buffer_payload_gbps,vec_allocations,buffer_allocations"
    );
    for &payload_size in PAYLOADS {
        let vec_path = vec_encode(payload_size);
        let buffer_path = buffer_encode(payload_size);
        let vec_ns = vec_path.nanos / u128::from(ITERATIONS as u64);
        let buffer_ns = buffer_path.nanos / u128::from(ITERATIONS as u64);
        println!(
            "{payload_size},{vec_ns},{buffer_ns},{},{},{},{}",
            gbps(payload_size, vec_path.nanos),
            gbps(payload_size, buffer_path.nanos),
            vec_path.allocations,
            buffer_path.allocations,
        );
    }
}

fn vec_encode(payload_size: usize) -> Measurement {
    let mut carrier = new_carrier();
    let payload = vec![0x5a; payload_size];
    ALLOCATIONS.store(0, Ordering::Relaxed);
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let packet = carrier.encode_datagram(&payload).expect("Vec packet");
        black_box(packet);
    }
    Measurement {
        nanos: start.elapsed().as_nanos(),
        allocations: ALLOCATIONS.load(Ordering::Relaxed),
    }
}

fn buffer_encode(payload_size: usize) -> Measurement {
    let mut carrier = new_carrier();
    let payload = vec![0x5a; payload_size];
    let mut output = vec![0; OUTPUT_BYTES];
    ALLOCATIONS.store(0, Ordering::Relaxed);
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let length = carrier
            .encode_datagram_into(&payload, &mut output)
            .expect("buffer packet");
        black_box(&output[..length]);
    }
    Measurement {
        nanos: start.elapsed().as_nanos(),
        allocations: ALLOCATIONS.load(Ordering::Relaxed),
    }
}

fn new_carrier() -> FakeTcpCarrier {
    FakeTcpCarrier::new(
        FourTuple::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_001)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 44_443)),
        ),
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier")
}

fn gbps(payload_size: usize, elapsed_nanos: u128) -> String {
    let milli_gbps = u128::try_from(payload_size)
        .expect("payload size fits u128")
        .saturating_mul(u128::from(ITERATIONS as u64))
        .saturating_mul(8_000)
        .checked_div(elapsed_nanos)
        .unwrap_or(0);
    format!("{}.{:03}", milli_gbps / 1_000, milli_gbps % 1_000)
}
