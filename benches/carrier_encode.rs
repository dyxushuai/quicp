use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use quicp::faketcp::{CarrierDirection, CarrierError, FakeTcpCarrier, FourTuple, SynDataMode};

#[cfg(debug_assertions)]
const ITERATIONS: usize = 50_000;
#[cfg(not(debug_assertions))]
const ITERATIONS: usize = 1_000_000;

const PAYLOADS: &[usize] = &[64, 1200, 4096];
const OUTPUT_BYTES: usize = u16::MAX as usize;

fn main() {
    println!(
        "payload_bytes,vec_ns_per_packet,buffer_ns_per_packet,vec_payload_gbps,buffer_payload_gbps"
    );
    for &payload_size in PAYLOADS {
        let vec_path = vec_encode(payload_size);
        let buffer_path = buffer_encode(payload_size);
        let vec_ns = vec_path / u128::from(ITERATIONS as u64);
        let buffer_ns = buffer_path / u128::from(ITERATIONS as u64);
        println!(
            "{payload_size},{vec_ns},{buffer_ns},{},{}",
            gbps(payload_size, vec_path),
            gbps(payload_size, buffer_path),
        );
    }
}

fn vec_encode(payload_size: usize) -> u128 {
    let mut carrier = new_carrier();
    let payload = vec![0x5a; payload_size];
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let packet = match carrier.encode_datagram(&payload) {
            Ok(packet) => packet,
            Err(CarrierError::SequenceExhausted) => {
                carrier = new_carrier();
                carrier.encode_datagram(&payload).expect("Vec packet")
            }
            Err(error) => panic!("Vec packet: {error}"),
        };
        black_box(packet);
    }
    start.elapsed().as_nanos()
}

fn buffer_encode(payload_size: usize) -> u128 {
    let mut carrier = new_carrier();
    let payload = vec![0x5a; payload_size];
    let mut output = vec![0; OUTPUT_BYTES];
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let length = match carrier.encode_datagram_into(&payload, &mut output) {
            Ok(length) => length,
            Err(CarrierError::SequenceExhausted) => {
                carrier = new_carrier();
                carrier
                    .encode_datagram_into(&payload, &mut output)
                    .expect("buffer packet")
            }
            Err(error) => panic!("buffer packet: {error}"),
        };
        black_box(&output[..length]);
    }
    start.elapsed().as_nanos()
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
