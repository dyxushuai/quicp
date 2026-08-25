use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(feature = "internal-bench")]
use quicp::faketcp::FakeTcpPacket;
use quicp::{
    CarrierConfig, CarrierDirection, CarrierError, FakeTcpCarrier, FourTuple, SynDataMode,
};

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
    let decoded = receiver.decode_datagram(&packet).expect("packet");
    assert_eq!(decoded.payload(), datagram);
    assert!(decoded.was_syn());
}

#[cfg(feature = "internal-bench")]
#[test]
fn configured_outer_mtu_controls_family_mss_and_packet_size() {
    let ipv4 = tuple();
    let mut ipv4_sender = FakeTcpCarrier::new_with_mtu(
        ipv4,
        CarrierDirection::ClientToServer,
        SynDataMode::Cookie([7; 16]),
        1460,
        1500,
    )
    .unwrap();
    let ipv4_packet = ipv4_sender.encode_syn(b"ipv4").unwrap();
    assert_eq!(
        FakeTcpPacket::decode(&ipv4_packet).unwrap().options().mss(),
        Some(1460)
    );

    let ipv6 = FourTuple::new(
        SocketAddr::from((Ipv6Addr::LOCALHOST, 40_000)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 443)),
    );
    let mut ipv6_sender = FakeTcpCarrier::new_with_mtu(
        ipv6,
        CarrierDirection::ClientToServer,
        SynDataMode::Cookie([7; 16]),
        1440,
        1500,
    )
    .unwrap();
    let ipv6_packet = ipv6_sender.encode_syn(b"ipv6").unwrap();
    assert_eq!(
        FakeTcpPacket::decode(&ipv6_packet).unwrap().options().mss(),
        Some(1440)
    );

    let mut bounded_sender = FakeTcpCarrier::new_with_mtu(
        ipv4,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
        1360,
        1400,
    )
    .unwrap();
    assert_eq!(
        bounded_sender.encode_datagram(&vec![0; 1361]),
        Err(CarrierError::PacketTooLarge)
    );
    assert!(matches!(
        FakeTcpCarrier::new_with_mtu(
            ipv4,
            CarrierDirection::ClientToServer,
            SynDataMode::Disabled,
            1461,
            1500,
        ),
        Err(CarrierError::InvalidMss {
            mss: 1461,
            maximum: 1460,
        })
    ));

    let mut mtu_limited_receiver = FakeTcpCarrier::new_with_mtu(
        ipv4.reverse(),
        CarrierDirection::ServerToClient,
        SynDataMode::Disabled,
        960,
        1000,
    )
    .unwrap();
    let oversized_packet = ipv4_sender.encode_datagram(&vec![0; 1001]).unwrap();
    assert_eq!(
        mtu_limited_receiver.decode_datagram(&oversized_packet),
        Err(CarrierError::PacketTooLarge)
    );
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
fn malformed_packets_are_rejected_but_duplicates_reach_quicp() {
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
    assert_eq!(
        receiver.decode_datagram(&packet).unwrap().payload(),
        b"payload"
    );
}

#[test]
fn forward_carrier_sequence_cannot_block_older_quicp_datagrams() {
    let tuple = tuple();
    let payload = vec![7; 60_000];
    let mut sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let first = sender.encode_datagram(&payload).expect("first packet");
    let mut receiver = FakeTcpCarrier::new(
        tuple.reverse(),
        CarrierDirection::ServerToClient,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let mut far_ahead = Vec::new();
    for _ in 0..72 {
        far_ahead = sender.encode_datagram(&payload).expect("later packet");
    }

    receiver
        .decode_datagram_borrowed(&far_ahead)
        .expect("far-ahead packet");
    assert_eq!(
        receiver
            .decode_datagram_borrowed(&first)
            .expect("older QUICP packet remains admissible")
            .payload(),
        payload
    );
}

#[test]
fn ipv6_packet_and_stateless_syn_cookie_round_trip() {
    let tuple = FourTuple::new(
        SocketAddr::from((Ipv6Addr::LOCALHOST, 40_000)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 443)),
    );
    let config = CarrierConfig::default();
    let client_mode = config.syn_data_mode(b"cookie-secret", tuple, 7);
    let server_mode = config.syn_data_mode(b"cookie-secret", tuple.reverse(), 7);
    assert_eq!(client_mode, server_mode);
    assert_ne!(
        client_mode,
        config.syn_data_mode(b"cookie-secret", tuple, 8)
    );
    let mut sender =
        FakeTcpCarrier::new(tuple, CarrierDirection::ClientToServer, client_mode).unwrap();
    let mut receiver = FakeTcpCarrier::new(
        tuple.reverse(),
        CarrierDirection::ServerToClient,
        server_mode,
    )
    .unwrap();
    let packet = sender.encode_syn(b"ipv6").unwrap();
    assert_eq!(
        receiver.decode_datagram(&packet).unwrap().payload(),
        b"ipv6"
    );
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
        Err(CarrierError::OutputTooSmall { .. })
    ));

    let mut output = [0; 1500];
    let length = sender
        .encode_datagram_into(b"payload", &mut output)
        .expect("encoded packet");
    let mut receiver = FakeTcpCarrier::new(
        tuple.reverse(),
        CarrierDirection::ServerToClient,
        SynDataMode::Disabled,
    )
    .unwrap();
    assert_eq!(
        receiver
            .decode_datagram(&output[..length])
            .unwrap()
            .payload(),
        b"payload"
    );
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
    let mut receiver = FakeTcpCarrier::new(
        tuple.reverse(),
        CarrierDirection::ServerToClient,
        SynDataMode::Disabled,
    )
    .unwrap();
    assert_eq!(
        receiver
            .decode_datagram(&output[..length])
            .unwrap()
            .payload(),
        b"second"
    );
}

#[test]
fn carrier_encode_into_matches_the_owned_encoder_semantics() {
    let tuple = tuple();
    let mut owned_sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let owned = owned_sender.encode_datagram(b"payload").expect("packet");
    let mut buffered_sender = FakeTcpCarrier::new(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
    )
    .expect("carrier");
    let mut output = vec![0; owned.len()];
    let length = buffered_sender
        .encode_datagram_into(b"payload", &mut output)
        .expect("encoded packet");
    let mut owned_receiver = FakeTcpCarrier::new(
        tuple.reverse(),
        CarrierDirection::ServerToClient,
        SynDataMode::Disabled,
    )
    .unwrap();
    let mut buffered_receiver = FakeTcpCarrier::new(
        tuple.reverse(),
        CarrierDirection::ServerToClient,
        SynDataMode::Disabled,
    )
    .unwrap();
    let owned = owned_receiver.decode_datagram(&owned).unwrap();
    let buffered = buffered_receiver
        .decode_datagram(&output[..length])
        .unwrap();
    assert_eq!(buffered.payload(), owned.payload());
    assert_eq!(buffered.was_syn(), owned.was_syn());
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
#[cfg(feature = "internal-bench")]
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
#[cfg(feature = "internal-bench")]
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
