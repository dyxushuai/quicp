use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use quicp::faketcp::{CarrierDirection, FakeTcpCarrier, FourTuple, SynDataMode};

const SAMPLES: usize = if cfg!(debug_assertions) {
    10_000
} else {
    200_000
};

fn main() {
    println!(
        "payload_bytes,owned_ns_per_packet,borrowed_ns_per_packet,owned_payload_gbps,borrowed_payload_gbps"
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
        let start = Instant::now();
        for packet in &packets {
            let decoded = owned.decode_datagram(packet).expect("owned decode");
            black_box(decoded.payload().len());
        }
        let owned_ns = start.elapsed().as_nanos() / samples;

        let mut borrowed = FakeTcpCarrier::new(
            tuple.reverse(),
            CarrierDirection::ServerToClient,
            SynDataMode::Disabled,
        )
        .expect("borrowed receiver");
        let start = Instant::now();
        for packet in &packets {
            let decoded = borrowed
                .decode_datagram_borrowed(packet)
                .expect("borrowed decode");
            black_box(decoded.payload().len());
        }
        let borrowed_ns = start.elapsed().as_nanos() / samples;

        println!(
            "{payload_size},{owned_ns},{borrowed_ns},{},{}",
            gbps(payload_size, owned_ns),
            gbps(payload_size, borrowed_ns),
        );
    }
}

fn encoded_packets(tuple: FourTuple, payload_size: usize) -> Vec<Vec<u8>> {
    let payload = vec![0x5a; payload_size];
    for _ in 0..16 {
        let mut sender = FakeTcpCarrier::new(
            tuple,
            CarrierDirection::ClientToServer,
            SynDataMode::Disabled,
        )
        .expect("sender");
        let mut packets = Vec::with_capacity(SAMPLES);
        let mut exhausted = false;
        for _ in 0..SAMPLES {
            match sender.encode_datagram(&payload) {
                Ok(packet) => packets.push(packet),
                Err(quicp::faketcp::CarrierError::SequenceExhausted) => {
                    exhausted = true;
                    break;
                }
                Err(error) => panic!("packet: {error}"),
            }
        }
        if !exhausted {
            return packets;
        }
    }
    panic!("could not generate a non-exhausting carrier sample");
}

fn gbps(payload_size: usize, elapsed_nanos_per_packet: u128) -> String {
    let milli_gbps = u128::try_from(payload_size)
        .expect("payload size fits u128")
        .saturating_mul(8_000)
        .checked_div(elapsed_nanos_per_packet)
        .unwrap_or(0);
    format!("{}.{:03}", milli_gbps / 1_000, milli_gbps % 1_000)
}
