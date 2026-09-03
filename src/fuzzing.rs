//! Fuzz-only dispatch into every peer-controlled QUICP decoder and recovery state machine.

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Range;

use bytes::Bytes;

use crate::fec::Decoder;
use crate::recovery::{AckRanges, Reassembler, ReplayBuffer};
use crate::session::{ReplayAdmission, ReplayToken};

const MAX_FUZZ_BYTES: usize = 4096;

/// Dispatches one bounded fuzz input by its first byte.
pub fn protocol(input: &[u8]) {
    let Some((&tag, data)) = input.split_first() else {
        return;
    };
    match tag % 9 {
        0 => {
            let _ = crate::wire::decode_control(data, 32);
        }
        1 => {
            let _ = crate::wire::decode_source(data, 32, MAX_FUZZ_BYTES);
        }
        2 => {
            let _ = crate::wire::decode_repair(data, MAX_FUZZ_BYTES);
        }
        3 => fuzz_token(data),
        4 => fuzz_ack_ranges(data),
        5 => fuzz_replay(data),
        6 => fuzz_reassembly(data),
        7 => fuzz_decoder(data),
        _ => fuzz_faketcp(data),
    }
}

fn fuzz_token(data: &[u8]) {
    let Ok(token) = ReplayToken::from_bytes(data) else {
        return;
    };
    let admission = ReplayAdmission::new(&[0x5a; 32], 1, 8).expect("fixed policy is valid");
    let _ = admission.admit(&token, 1, 1, 1);
}

fn fuzz_ack_ranges(data: &[u8]) {
    let (contiguous, sent_offset, ranges) = split_ranges(data);
    let _ = AckRanges::from_wire(contiguous, ranges, 32, sent_offset);
}

fn fuzz_replay(data: &[u8]) {
    let (contiguous, sent_offset, ranges) = split_ranges(data);
    let Ok(ack) = AckRanges::from_wire(contiguous, ranges, 32, sent_offset) else {
        return;
    };
    let mut replay = ReplayBuffer::new(MAX_FUZZ_BYTES);
    for (index, chunk) in data.chunks(64).take(64).enumerate() {
        let _ = replay.retain((index * 64) as u64, Bytes::copy_from_slice(chunk));
    }
    let _ = replay.acknowledge(&ack);
}

fn fuzz_reassembly(data: &[u8]) {
    let mut reassembler = Reassembler::new(MAX_FUZZ_BYTES);
    for chunk in data.chunks(72).take(56) {
        let Some((&offset, bytes)) = chunk.split_first() else {
            continue;
        };
        let _ =
            reassembler.insert_record(u64::from(offset) * 8, Bytes::copy_from_slice(bytes), false);
    }
    let mut output = [0; 256];
    let _ = reassembler.read(&mut output);
    let _ = reassembler.set_final_offset(u64::try_from(data.len()).unwrap_or(u64::MAX));
}

fn fuzz_decoder(data: &[u8]) {
    let mut decoder = Decoder::new(64, 32, 256);
    for (symbol_id, chunk) in data.chunks(128).take(32).enumerate() {
        if chunk.is_empty() {
            continue;
        }
        let _ = decoder.add_source(symbol_id as u32, Bytes::copy_from_slice(chunk), 4096);
        let _ = decoder.add_repair(0, 4, symbol_id as u32, 7, chunk, 4096);
    }
}

fn fuzz_faketcp(data: &[u8]) {
    let tuple = crate::faketcp::FourTuple::new(
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 40_000)),
        SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 443)),
    );
    let mut carrier = crate::faketcp::FakeTcpCarrier::new(
        tuple,
        crate::faketcp::CarrierDirection::ClientToServer,
        crate::faketcp::SynDataMode::Disabled,
    )
    .expect("fixed tuple is valid");
    let _ = carrier.decode_datagram_borrowed(data);
}

fn split_ranges(data: &[u8]) -> (u64, u64, Vec<Range<u64>>) {
    let contiguous = read_u64(data.get(..8).unwrap_or_default());
    let sent_offset = read_u64(data.get(8..16).unwrap_or_default());
    let ranges = data
        .get(16..)
        .unwrap_or_default()
        .chunks_exact(16)
        .take(32)
        .map(|chunk| read_u64(&chunk[..8])..read_u64(&chunk[8..]))
        .collect();
    (contiguous, sent_offset, ranges)
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut value = [0; 8];
    value[..bytes.len()].copy_from_slice(bytes);
    u64::from_be_bytes(value)
}
