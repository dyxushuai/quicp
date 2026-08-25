use quicp::platform::{PlatformError, PlatformPacketBridge, PlatformPacketConfig};
use quicp::smolstack::SmoltcpConfig;
use smoltcp::phy::{Device, TxToken};
use smoltcp::time::Instant;
use std::sync::Arc;
use std::thread;

#[test]
fn platform_bridge_exposes_bounded_complete_ip_packet_seam() {
    let bridge = PlatformPacketBridge::new(PlatformPacketConfig::default()).expect("bridge");
    let packet = vec![0x45; 64];
    bridge.ingress_ip(packet.clone()).expect("ingress");
    assert_eq!(bridge.ingress_len(), 1);
    assert_eq!(bridge.poll_egress_ip(), None);
}

#[test]
fn platform_bridge_copies_borrowed_ingress_into_the_pool() {
    let bridge = PlatformPacketBridge::new(PlatformPacketConfig::default()).expect("bridge");
    let packet = [0x45; 64];
    bridge
        .ingress_ip_borrowed(&packet)
        .expect("borrowed ingress");
    assert_eq!(bridge.ingress_len(), 1);
}

#[test]
fn platform_bridge_drains_egress_into_host_memory() {
    let bridge = PlatformPacketBridge::new(PlatformPacketConfig::default()).expect("bridge");
    let mut device = bridge
        .smoltcp_device(SmoltcpConfig::default())
        .expect("device");
    let tx = device.transmit(Instant::ZERO).expect("tx");
    tx.consume(4, |packet| packet.copy_from_slice(&[8, 9, 10, 11]));
    let mut small = [0; 3];
    assert!(matches!(
        bridge.poll_egress_ip_into(&mut small),
        Err(PlatformError::BufferTooSmall {
            required: 4,
            capacity: 3
        })
    ));
    assert_eq!(bridge.egress_len(), 1);
    let mut output = [0; 1500];
    assert_eq!(
        bridge.poll_egress_ip_into(&mut output).expect("egress"),
        Some(4)
    );
    assert_eq!(&output[..4], [8, 9, 10, 11]);
}

#[test]
fn owned_egress_keeps_the_preallocated_pool_live() {
    let config = PlatformPacketConfig {
        packet_capacity: 1,
        byte_budget: 1500,
        smoltcp: SmoltcpConfig::default(),
    };
    let bridge = PlatformPacketBridge::new(config).expect("bridge");
    let mut device = bridge.smoltcp_device(config.smoltcp).expect("device");

    for value in [1, 2] {
        let tx = device.transmit(Instant::ZERO).expect("tx slot");
        tx.consume(1, |packet| packet[0] = value);
        assert_eq!(bridge.poll_egress_ip(), Some(vec![value]));
    }
}

#[test]
fn platform_bridge_rejects_a_device_with_a_different_mtu() {
    let bridge = PlatformPacketBridge::new(PlatformPacketConfig::default()).expect("bridge");
    let mismatched = SmoltcpConfig {
        mtu: 9000,
        ..SmoltcpConfig::default()
    };

    assert!(matches!(
        bridge.smoltcp_device(mismatched),
        Err(PlatformError::SmoltcpMtuMismatch {
            expected: 1500,
            actual: 9000
        })
    ));
    bridge
        .smoltcp_device(SmoltcpConfig::default())
        .expect("mismatch must not retain ownership");
}

#[test]
fn platform_bridge_rejects_empty_and_oversized_packets() {
    let bridge = PlatformPacketBridge::new(PlatformPacketConfig::default()).expect("bridge");
    assert!(matches!(
        bridge.ingress_ip(Vec::new()),
        Err(PlatformError::PacketOutsideMtu { len: 0, mtu: 1500 })
    ));
    assert!(matches!(
        bridge.ingress_ip(vec![0; 1501]),
        Err(PlatformError::PacketOutsideMtu {
            len: 1501,
            mtu: 1500
        })
    ));
    assert!(matches!(
        bridge.ingress_ip_borrowed(&[]),
        Err(PlatformError::PacketOutsideMtu { len: 0, mtu: 1500 })
    ));
    assert!(matches!(
        bridge.ingress_ip_borrowed(&[0; 1501]),
        Err(PlatformError::PacketOutsideMtu {
            len: 1501,
            mtu: 1500
        })
    ));
}

#[test]
fn smoltcp_tx_token_bounds_a_malformed_length() {
    let config = PlatformPacketConfig {
        packet_capacity: 1,
        byte_budget: 1500,
        smoltcp: SmoltcpConfig::default(),
    };
    let bridge = PlatformPacketBridge::new(config).expect("bridge");
    let mut device = bridge.smoltcp_device(config.smoltcp).expect("device");
    let tx = device.transmit(Instant::ZERO).expect("tx slot");
    tx.consume(usize::MAX, |packet| {
        assert_eq!(packet.len(), config.smoltcp.mtu);
    });
    assert_eq!(bridge.egress_len(), 0);
    assert!(device.transmit(Instant::ZERO).is_some());
}

#[test]
fn platform_bridge_serializes_parallel_ingress_calls() {
    let bridge =
        Arc::new(PlatformPacketBridge::new(PlatformPacketConfig::default()).expect("bridge"));
    let workers = (0..4)
        .map(|_| {
            let bridge = Arc::clone(&bridge);
            thread::spawn(move || {
                for _ in 0..16 {
                    bridge.ingress_ip_borrowed(&[0x45; 64]).expect("ingress");
                }
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().expect("worker");
    }
    assert_eq!(bridge.ingress_len(), 64);
}

#[test]
fn platform_bridge_allows_only_one_smoltcp_owner() {
    let bridge = PlatformPacketBridge::new(PlatformPacketConfig::default()).expect("bridge");
    let device = bridge
        .smoltcp_device(SmoltcpConfig::default())
        .expect("first device");
    assert!(matches!(
        bridge.smoltcp_device(SmoltcpConfig::default()),
        Err(PlatformError::SmoltcpOwnerBusy)
    ));
    drop(device);
    bridge
        .smoltcp_device(SmoltcpConfig::default())
        .expect("owner after drop");
}
