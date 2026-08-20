use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use quicp::faketcp::{CarrierDirection, FakeTcpCarrier, FakeTcpPacket, FourTuple, SynDataMode};

fn tuple() -> FourTuple {
    FourTuple::new(
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), 40_000)),
        SocketAddr::from((Ipv4Addr::new(198, 51, 100, 20), 443)),
    )
}

fn fill_pseudorandom(bytes: &mut [u8], state: &mut u64) {
    for byte in bytes {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        *byte = (*state >> 56) as u8;
    }
}

#[test]
fn syn_data_is_a_tcp_packet_with_one_quicp_datagram() {
    let tuple = tuple();
    let mut sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Cookie([3; 16]),
    )
    .expect("carrier");
    let mut receiver = FakeTcpCarrier::new(
        tuple.reverse(),
        CarrierDirection::ServerToClient,
        SynDataMode::Cookie([3; 16]),
    )
    .expect("carrier");

    let datagram = b"quicp initial packet";
    let packet = sender.encode_syn(datagram).expect("SYN packet");
    let parsed = FakeTcpPacket::decode(&packet).expect("TCP-shaped packet");
    assert!(parsed.flags().is_syn());
    assert!(parsed.options().fast_open_cookie().is_some());
    assert_eq!(parsed.payload(), datagram);

    let decoded = receiver.decode_datagram(&packet).expect("packet");
    assert_eq!(decoded.payload(), datagram);
    assert!(decoded.was_syn());
}

#[test]
fn out_of_order_datagrams_are_delivered_without_carrier_reassembly() {
    let tuple = tuple();
    let mut sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let mut receiver = FakeTcpCarrier::new(
        tuple.reverse(),
        CarrierDirection::ServerToClient,
        SynDataMode::Disabled,
    )
    .expect("carrier");

    let first = sender.encode_datagram(b"first").expect("first packet");
    let second = sender.encode_datagram(b"second").expect("second packet");

    assert_eq!(
        receiver.decode_datagram(&second).unwrap().payload(),
        b"second"
    );
    assert_eq!(
        receiver.decode_datagram(&first).unwrap().payload(),
        b"first"
    );
}

#[test]
fn malformed_packet_and_replayed_datagram_are_rejected() {
    let tuple = tuple();
    let mut sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let mut receiver = FakeTcpCarrier::new(
        tuple.reverse(),
        CarrierDirection::ServerToClient,
        SynDataMode::Disabled,
    )
    .expect("carrier");

    let mut packet = sender.encode_datagram(b"payload").expect("packet");
    let index = packet.len() - 1;
    packet[index] ^= 1;
    assert!(receiver.decode_datagram(&packet).is_err());

    let packet = sender.encode_datagram(b"payload").expect("packet");
    assert_eq!(
        receiver.decode_datagram(&packet).unwrap().payload(),
        b"payload"
    );
    assert!(receiver.decode_datagram(&packet).is_err());
}

#[test]
fn ipv6_packet_and_stateless_syn_cookie_round_trip() {
    let tuple = FourTuple::new(
        SocketAddr::from((Ipv6Addr::LOCALHOST, 40_000)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 443)),
    );
    let packet = FakeTcpPacket::decode(
        &FakeTcpPacket::decode(
            &quicp::faketcp::FakeTcpCarrier::new(
                tuple,
                CarrierDirection::ClientToServer,
                SynDataMode::Cookie([4; 16]),
            )
            .expect("carrier")
            .encode_syn(b"ipv6")
            .expect("packet"),
        )
        .expect("decoded packet")
        .encode()
        .expect("re-encoded packet"),
    )
    .expect("round trip");
    assert_eq!(packet.source(), tuple.source);
    assert_eq!(packet.destination(), tuple.destination);

    let cookie = quicp::faketcp::issue_syn_cookie(b"cookie-secret", tuple, 7);
    assert!(quicp::faketcp::verify_syn_cookie(
        b"cookie-secret",
        tuple,
        7,
        &cookie
    ));
    assert!(!quicp::faketcp::verify_syn_cookie(
        b"cookie-secret",
        tuple,
        8,
        &cookie
    ));
    assert_eq!(
        cookie,
        quicp::faketcp::issue_syn_cookie(b"cookie-secret", tuple.reverse(), 7)
    );
    assert!(quicp::faketcp::verify_syn_cookie(
        b"cookie-secret",
        tuple.reverse(),
        7,
        &cookie
    ));
}

#[test]
fn carrier_payload_is_the_original_quicp_datagram() {
    let tuple = tuple();
    let mut sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let mut receiver = FakeTcpCarrier::new(
        tuple.reverse(),
        CarrierDirection::ServerToClient,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let packet = sender.encode_datagram(b"short").expect("packet");
    let parsed = FakeTcpPacket::decode(&packet).expect("packet");
    assert_eq!(parsed.payload(), b"short");
    assert_eq!(
        receiver.decode_datagram(&packet).unwrap().payload(),
        b"short"
    );
}

#[test]
fn borrowed_decode_keeps_payload_in_the_input_packet() {
    let tuple = tuple();
    let mut sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let mut receiver = FakeTcpCarrier::new(
        tuple.reverse(),
        CarrierDirection::ServerToClient,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let packet = sender.encode_datagram(b"borrowed").expect("packet");
    let packet_start = packet.as_ptr() as usize;
    let packet_end = packet_start + packet.len();
    let decoded = receiver
        .decode_datagram_borrowed(&packet)
        .expect("borrowed packet");
    let payload_start = decoded.payload().as_ptr() as usize;
    assert_eq!(decoded.payload(), b"borrowed");
    assert!(payload_start >= packet_start);
    assert!(payload_start + decoded.payload().len() <= packet_end);
}

#[test]
fn carrier_encodes_into_caller_storage_and_preserves_state_on_short_output() {
    let tuple = tuple();
    let mut sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let mut short = [0; 1];
    assert!(matches!(
        sender.encode_datagram_into(b"payload", &mut short),
        Err(quicp::faketcp::CarrierError::OutputTooSmall { .. })
    ));

    let mut output = [0; 1500];
    let length = sender
        .encode_datagram_into(b"payload", &mut output)
        .expect("encoded packet");
    let parsed = FakeTcpPacket::decode(&output[..length]).expect("packet");
    assert_eq!(parsed.payload(), b"payload");
}

#[test]
fn caller_owned_encoder_clears_checksum_before_buffer_reuse() {
    let tuple = tuple();
    let mut sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let mut output = [0; 1500];
    sender
        .encode_datagram_into(b"first", &mut output)
        .expect("first packet");
    let length = sender
        .encode_datagram_into(b"second", &mut output)
        .expect("second packet");
    let parsed = FakeTcpPacket::decode(&output[..length]).expect("reused output packet");
    assert_eq!(parsed.payload(), b"second");
}

#[test]
fn packet_encode_into_matches_the_owned_encoder() {
    let tuple = tuple();
    let mut sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let owned = sender.encode_datagram(b"payload").expect("packet");
    let parsed = FakeTcpPacket::decode(&owned).expect("packet");
    let mut output = vec![0; owned.len()];
    let length = parsed.encode_into(&mut output).expect("encoded packet");
    assert_eq!(&output[..length], owned);
}

#[test]
fn large_payload_checksum_round_trips_at_odd_and_maximum_lengths() {
    for size in [4095, 4096, 65_475] {
        let tuple = tuple();
        let mut sender = FakeTcpCarrier::new(
            tuple,
            CarrierDirection::ClientToServer,
            SynDataMode::Disabled,
        )
        .expect("carrier");
        let mut receiver = FakeTcpCarrier::new(
            tuple.reverse(),
            CarrierDirection::ServerToClient,
            SynDataMode::Disabled,
        )
        .expect("carrier");
        let datagram = vec![0xa5; size];
        let packet = sender.encode_datagram(&datagram).expect("packet");
        assert_eq!(
            receiver.decode_datagram(&packet).unwrap().payload(),
            datagram
        );
    }
}

#[test]
fn tcp_sequence_and_acknowledgment_cover_carrier_payloads() {
    let tuple = tuple();
    let mut sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let mut receiver = FakeTcpCarrier::new(
        tuple.reverse(),
        CarrierDirection::ServerToClient,
        SynDataMode::Disabled,
    )
    .expect("carrier");

    let first = sender.encode_datagram(b"first").expect("first packet");
    let parsed = FakeTcpPacket::decode(&first).expect("first packet");
    receiver.decode_datagram(&first).expect("first datagram");
    let second = sender.encode_datagram(b"second").expect("second packet");
    let parsed_second = FakeTcpPacket::decode(&second).expect("second packet");
    assert_eq!(
        parsed_second.sequence(),
        parsed
            .sequence()
            .wrapping_add(u32::try_from(parsed.payload().len()).expect("payload length"))
    );

    let reply = receiver.encode_datagram(b"reply").expect("reply packet");
    let parsed_reply = FakeTcpPacket::decode(&reply).expect("reply packet");
    assert_eq!(
        parsed_reply.acknowledgment(),
        parsed
            .sequence()
            .wrapping_add(u32::try_from(parsed.payload().len()).expect("payload length"))
    );
}

#[test]
fn deterministic_payload_corpus_round_trips_ipv4_and_ipv6() {
    let tuples = [
        tuple(),
        FourTuple::new(
            SocketAddr::from((Ipv6Addr::LOCALHOST, 40_000)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 443)),
        ),
    ];
    let mut state = 0x51c0_ffee_d15c_a11eu64;
    let mut lengths = vec![1, 31, 32, 33, 255, 256, 257, 4095, 4096, 4097];
    lengths.extend((0..64).map(|_| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        usize::try_from(state % 8192).expect("bounded length")
    }));

    for tuple in tuples {
        let mut sender = FakeTcpCarrier::new(
            tuple,
            CarrierDirection::ClientToServer,
            SynDataMode::Disabled,
        )
        .expect("carrier");
        let mut receiver = FakeTcpCarrier::new(
            tuple.reverse(),
            CarrierDirection::ServerToClient,
            SynDataMode::Disabled,
        )
        .expect("carrier");
        for &length in &lengths {
            let mut payload = vec![0; length];
            fill_pseudorandom(&mut payload, &mut state);
            let packet = sender.encode_datagram(&payload).expect("packet");
            assert_eq!(FakeTcpPacket::decode(&packet).unwrap().payload(), payload);
            assert_eq!(
                receiver
                    .decode_datagram_borrowed(&packet)
                    .unwrap()
                    .payload(),
                payload
            );
        }
    }
}

#[test]
fn malformed_corpus_does_not_poison_carrier_state() {
    let tuple = tuple();
    let mut sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let packet = sender.encode_datagram(b"complete").expect("packet");

    for length in 0..packet.len() {
        let mut receiver = FakeTcpCarrier::new(
            tuple.reverse(),
            CarrierDirection::ServerToClient,
            SynDataMode::Disabled,
        )
        .expect("carrier");
        assert!(
            receiver
                .decode_datagram_borrowed(&packet[..length])
                .is_err()
        );
        assert_eq!(
            receiver
                .decode_datagram_borrowed(&packet)
                .unwrap()
                .payload(),
            b"complete"
        );
    }

    let mut state = 0xbadc_0ffe_e0dd_f00du64;
    for length in 0..256 {
        let mut input = vec![0; length];
        fill_pseudorandom(&mut input, &mut state);
        if let Ok(packet) = FakeTcpPacket::decode(&input) {
            let encoded = packet.encode().expect("decoded packet re-encodes");
            assert_eq!(FakeTcpPacket::decode(&encoded).unwrap(), packet);
        }
    }
}
