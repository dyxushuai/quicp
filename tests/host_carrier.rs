use std::future::poll_fn;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use noq::AsyncUdpSocket;
use noq::udp::{RecvMeta, Transmit};
use quicp::config::Config;
use quicp::{
    CanonicalHost, Client, HostDatagramError, HostDatagramSocket, HostRuntime, OpenRequest,
    QuicpFlow, RecoveryConfig, RecoveryMode, Server, TransportError,
};

fn local() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 10_000).into()
}

fn peer() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 10_001).into()
}

#[test]
fn host_endpoint_rejects_local_addresses_outside_configured_policy() {
    let runtime = Arc::new(HostRuntime::new());
    let client_config = Config::parse(
        r#"
role = "client"
allow_insecure = true

[multipath]
mode = "off"

[[multipath.candidates]]
local_ip = "127.0.0.2"
server_addr = "127.0.0.1:10001"
"#,
    )
    .unwrap()
    .client()
    .unwrap()
    .clone();
    assert!(
        Client::from_host_socket(
            &client_config,
            HostDatagramSocket::new(local(), peer(), 1, 1200).unwrap(),
            Arc::clone(&runtime),
        )
        .is_err()
    );

    let server_config = Config::parse(
        r#"
role = "server"
listen_addrs = ["127.0.0.2:10001"]
allow_insecure = true
"#,
    )
    .unwrap()
    .server()
    .unwrap()
    .clone();
    assert!(
        Server::from_host_socket(
            &server_config,
            HostDatagramSocket::new(peer(), local(), 1, 1200).unwrap(),
            runtime.clone(),
        )
        .is_err()
    );
    runtime.shutdown().unwrap();
}

#[test]
fn host_carrier_rejects_required_pmtu_when_it_may_fragment() {
    let config = Config::parse(
        r#"
role = "client"
allow_insecure = true

[multipath]
mode = "off"

[[multipath.candidates]]
local_ip = "127.0.0.1"
server_addr = "127.0.0.1:10001"

[transport.mtu]
pmtu = "required"
"#,
    )
    .unwrap()
    .client()
    .unwrap()
    .clone();
    let error = Client::from_host_socket(
        &config,
        HostDatagramSocket::new(local(), peer(), 1, 1200).unwrap(),
        Arc::new(HostRuntime::new()),
    )
    .expect_err("fragmenting host carrier must reject required PMTU discovery");
    assert!(matches!(
        error,
        TransportError::Config(quicp::ConfigError::PmtuRequiresNonFragmentingCarrier)
    ));
}

#[test]
fn host_endpoint_rejects_a_closed_runtime() {
    let config = Config::parse(
        r#"
role = "client"
allow_insecure = true

[multipath]
mode = "off"

[[multipath.candidates]]
local_ip = "127.0.0.1"
server_addr = "127.0.0.1:10001"
"#,
    )
    .unwrap()
    .client()
    .unwrap()
    .clone();
    let runtime = Arc::new(HostRuntime::new());
    runtime.shutdown().unwrap();
    let error = Client::from_host_socket(
        &config,
        HostDatagramSocket::new(local(), peer(), 1, 1200).unwrap(),
        runtime,
    )
    .expect_err("closed runtime must fail endpoint construction");
    assert!(
        matches!(error, TransportError::Io(ref error) if error.kind() == io::ErrorKind::BrokenPipe)
    );
}

#[derive(Debug, Default)]
struct WakeProbe(AtomicUsize);

impl Wake for WakeProbe {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Release);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Release);
    }
}

fn transmit(contents: &[u8]) -> Transmit<'_> {
    Transmit {
        destination: peer(),
        ecn: None,
        contents,
        segment_size: None,
        src_ip: None,
    }
}

#[test]
fn host_carrier_round_trips_caller_owned_datagrams() {
    let socket = HostDatagramSocket::new(local(), peer(), 2, 1200).unwrap();
    let input = b"incoming";
    socket.ingress_datagram(input).unwrap();

    let mut recv_socket = socket.clone();
    let mut receive_buffer = [0u8; 1200];
    let mut bufs = [IoSliceMut::new(&mut receive_buffer)];
    let mut metas = [RecvMeta::default()];
    let probe = Arc::new(WakeProbe::default());
    let waker = Waker::from(Arc::clone(&probe));
    let read_count =
        ready_ok(recv_socket.poll_recv(&mut Context::from_waker(&waker), &mut bufs, &mut metas));
    assert_eq!(read_count, 1);
    assert_eq!(&receive_buffer[..metas[0].len], input);
    assert_eq!(metas[0].addr, peer());
    assert_eq!(metas[0].dst_ip, Some(local().ip()));

    let mut sender = socket.create_sender();
    ready_poll(
        sender
            .as_mut()
            .poll_send(&transmit(b"outgoing"), &mut Context::from_waker(&waker)),
    )
    .unwrap();
    let mut output = [0u8; 1200];
    assert_eq!(socket.poll_egress_datagram_into(&mut output), Ok(Some(8)));
    assert_eq!(&output[..8], b"outgoing");
}

#[test]
fn cloned_host_carrier_serializes_concurrent_ingress() {
    let socket = HostDatagramSocket::new(local(), peer(), 2, 1200).unwrap();
    std::thread::scope(|scope| {
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            let socket = socket.clone();
            scope.spawn(move || socket.ingress_datagram(payload).unwrap());
        }
    });
    let mut receiver = socket;
    let mut packets = Vec::new();
    for _ in 0..2 {
        let mut input = [0u8; 1200];
        let mut bufs = [IoSliceMut::new(&mut input)];
        let mut metas = [RecvMeta::default()];
        ready_ok(receiver.poll_recv(
            &mut Context::from_waker(Waker::noop()),
            &mut bufs,
            &mut metas,
        ));
        packets.push(input[..metas[0].len].to_vec());
    }
    packets.sort();
    assert_eq!(packets, [b"first".to_vec(), b"second".to_vec()]);
}

#[test]
fn host_carrier_preserves_datagram_reordering() {
    let sender_socket = HostDatagramSocket::new(local(), peer(), 4, 1200).unwrap();
    let receiver_socket = HostDatagramSocket::new(peer(), local(), 4, 1200).unwrap();
    let probe = Arc::new(WakeProbe::default());
    let waker = Waker::from(Arc::clone(&probe));
    let mut sender = sender_socket.create_sender();
    for payload in [b"first".as_slice(), b"second".as_slice()] {
        ready_poll(
            sender
                .as_mut()
                .poll_send(&transmit(payload), &mut Context::from_waker(&waker)),
        )
        .unwrap();
    }

    let mut packets = Vec::new();
    let mut output = [0u8; 1200];
    while let Some(length) = sender_socket
        .poll_egress_datagram_into(&mut output)
        .unwrap()
    {
        packets.push(output[..length].to_vec());
    }
    assert_eq!(packets.len(), 2);
    for packet in packets.into_iter().rev() {
        receiver_socket
            .ingress_datagram_from(local(), &packet)
            .unwrap();
    }

    let mut receiver = receiver_socket;
    for expected in [b"second".as_slice(), b"first".as_slice()] {
        let mut input = [0u8; 1200];
        let mut bufs = [IoSliceMut::new(&mut input)];
        let mut metas = [RecvMeta::default()];
        assert_eq!(
            ready_ok(receiver.poll_recv(&mut Context::from_waker(&waker), &mut bufs, &mut metas,)),
            1
        );
        assert_eq!(&input[..metas[0].len], expected);
    }
}

#[test]
fn host_carrier_reports_permanent_path_failure() {
    let socket = HostDatagramSocket::new(local(), peer(), 1, 1200).unwrap();
    socket.mark_unavailable();
    assert_eq!(
        socket.ingress_datagram(b"late"),
        Err(HostDatagramError::Unavailable)
    );
    assert_eq!(
        socket.poll_egress_datagram_into(&mut [0; 1200]),
        Err(HostDatagramError::Unavailable)
    );
}

#[test]
fn host_carrier_preserves_small_output_and_wakes_backpressure() {
    let socket = HostDatagramSocket::new(local(), peer(), 1, 1200).unwrap();
    let probe = Arc::new(WakeProbe::default());
    let waker = Waker::from(Arc::clone(&probe));
    let mut sender = socket.create_sender();
    ready_poll(
        sender
            .as_mut()
            .poll_send(&transmit(b"first"), &mut Context::from_waker(&waker)),
    )
    .unwrap();
    assert!(matches!(
        sender
            .as_mut()
            .poll_send(&transmit(b"second"), &mut Context::from_waker(&waker)),
        Poll::Pending
    ));

    let mut too_small = [0u8; 2];
    assert_eq!(
        socket.poll_egress_datagram_into(&mut too_small),
        Err(HostDatagramError::BufferTooSmall {
            required: 5,
            capacity: 2
        })
    );
    let mut output = [0u8; 1200];
    assert_eq!(socket.poll_egress_datagram_into(&mut output), Ok(Some(5)));
    assert!(probe.0.load(Ordering::Acquire) > 0);
    ready_poll(
        sender
            .as_mut()
            .poll_send(&transmit(b"second"), &mut Context::from_waker(&waker)),
    )
    .unwrap();

    let mut receiver = socket.clone();
    let mut receive_buffer = [0u8; 1200];
    let mut bufs = [IoSliceMut::new(&mut receive_buffer)];
    let mut metas = [RecvMeta::default()];
    assert!(matches!(
        receiver.poll_recv(&mut Context::from_waker(&waker), &mut bufs, &mut metas),
        Poll::Pending
    ));
    socket.ingress_datagram(b"wake").unwrap();
    assert!(probe.0.load(Ordering::Acquire) > 0);
}

#[test]
fn host_carrier_rejects_wrong_route_and_invalid_sizes() {
    let socket = HostDatagramSocket::new(local(), peer(), 1, 4).unwrap();
    assert_eq!(
        socket.ingress_datagram(b"12345"),
        Err(HostDatagramError::PacketOutsideMtu { len: 5, mtu: 4 })
    );
    assert!(matches!(
        socket.ingress_datagram_from(local(), b"x"),
        Err(HostDatagramError::PeerMismatch { .. })
    ));

    let mut sender = socket.create_sender();
    let wrong = Transmit {
        destination: local(),
        ecn: None,
        contents: b"x",
        segment_size: None,
        src_ip: None,
    };
    let probe = Arc::new(WakeProbe::default());
    let waker = Waker::from(Arc::clone(&probe));
    match sender
        .as_mut()
        .poll_send(&wrong, &mut Context::from_waker(&waker))
    {
        Poll::Ready(Err(error)) => assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput),
        other => panic!("unexpected poll result: {other:?}"),
    }
}

#[test]
fn host_endpoint_facade_builds_without_platform_socket() {
    let client_config = Config::parse(
        r#"
role = "client"
allow_insecure = true

[multipath]
mode = "off"

[[multipath.candidates]]
local_ip = "127.0.0.1"
server_addr = "127.0.0.1:10001"
"#,
    )
    .unwrap()
    .client()
    .unwrap()
    .clone();
    let server_config = Config::parse(
        r#"
role = "server"
listen_addrs = ["127.0.0.1:10001"]
allow_insecure = true
"#,
    )
    .unwrap()
    .server()
    .unwrap()
    .clone();

    let runtime = Arc::new(HostRuntime::new());
    let client_socket = HostDatagramSocket::new(local(), peer(), 4, 1200).unwrap();
    let server_socket = HostDatagramSocket::new(peer(), local(), 4, 1200).unwrap();
    let _client = Client::from_host_socket(&client_config, client_socket, runtime.clone()).unwrap();
    let _server = Server::from_host_socket(&server_config, server_socket, runtime.clone()).unwrap();
    runtime.shutdown().unwrap();
}

#[test]
fn host_endpoint_facade_drives_adaptive_no_tls_flow_loopback() {
    drive_no_tls_flow_loopback(
        RecoveryMode::Adaptive,
        RecoveryMode::Adaptive,
        LossPattern::Clean,
        false,
    );
}

#[test]
fn host_endpoint_facade_recovers_single_loss() {
    drive_no_tls_flow_loopback(
        RecoveryMode::Adaptive,
        RecoveryMode::Adaptive,
        LossPattern::Single,
        false,
    );
}

#[test]
fn host_endpoint_facade_survives_deterministic_random_loss() {
    drive_no_tls_flow_loopback(
        RecoveryMode::Adaptive,
        RecoveryMode::Adaptive,
        LossPattern::Random,
        false,
    );
}

#[test]
fn host_endpoint_facade_survives_packet_reordering() {
    drive_no_tls_flow_loopback(
        RecoveryMode::Adaptive,
        RecoveryMode::Adaptive,
        LossPattern::Reorder,
        false,
    );
}

#[test]
fn host_endpoint_facade_suppresses_duplicate_delivery() {
    drive_no_tls_flow_loopback(
        RecoveryMode::Adaptive,
        RecoveryMode::Adaptive,
        LossPattern::Duplicate,
        false,
    );
}

#[test]
fn host_endpoint_facade_replays_after_repair_loss() {
    drive_no_tls_flow_loopback(
        RecoveryMode::Adaptive,
        RecoveryMode::Adaptive,
        LossPattern::RepairLoss,
        false,
    );
}

#[test]
fn host_endpoint_facade_drives_reliable_no_tls_flow_loopback() {
    drive_no_tls_flow_loopback(
        RecoveryMode::ReliableOnly,
        RecoveryMode::ReliableOnly,
        LossPattern::Clean,
        false,
    );
}

#[test]
fn host_endpoint_facade_falls_back_after_residual_loss() {
    drive_no_tls_flow_loopback(
        RecoveryMode::Adaptive,
        RecoveryMode::Adaptive,
        LossPattern::Burst,
        false,
    );
}

#[test]
fn adaptive_host_falls_back_when_peer_omits_datagram() {
    drive_no_tls_flow_loopback(
        RecoveryMode::Adaptive,
        RecoveryMode::ReliableOnly,
        LossPattern::Clean,
        false,
    );
}

#[test]
fn required_adaptive_host_rejects_peer_without_datagram() {
    drive_no_tls_flow_loopback(
        RecoveryMode::Adaptive,
        RecoveryMode::ReliableOnly,
        LossPattern::Clean,
        true,
    );
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LossPattern {
    Clean,
    Single,
    Burst,
    Random,
    Reorder,
    Duplicate,
    RepairLoss,
}

#[allow(clippy::too_many_lines)]
fn drive_no_tls_flow_loopback(
    client_recovery_mode: RecoveryMode,
    server_recovery_mode: RecoveryMode,
    loss: LossPattern,
    client_require_adaptive: bool,
) {
    let adaptive = client_recovery_mode == RecoveryMode::Adaptive
        && server_recovery_mode == RecoveryMode::Adaptive;
    let runtime = Arc::new(HostRuntime::new());
    let client_socket = HostDatagramSocket::new(local(), peer(), 64, 1500).unwrap();
    let server_socket = HostDatagramSocket::new(peer(), local(), 64, 1500).unwrap();
    let client_config = Config::parse(
        r#"
role = "client"
allow_insecure = true

[multipath]
mode = "off"

[[multipath.candidates]]
local_ip = "127.0.0.1"
server_addr = "127.0.0.1:10001"
"#,
    )
    .unwrap()
    .client()
    .unwrap()
    .clone();
    let client_config = client_config
        .clone()
        .with_transport(
            client_config
                .transport()
                .clone()
                .with_recovery(RecoveryConfig {
                    mode: client_recovery_mode,
                    require_adaptive: client_require_adaptive,
                    ..RecoveryConfig::default()
                }),
        )
        .unwrap();
    let server_config = Config::parse(
        r#"
role = "server"
listen_addrs = ["127.0.0.1:10001"]
allow_insecure = true
"#,
    )
    .unwrap()
    .server()
    .unwrap()
    .clone();
    let server_config = server_config
        .clone()
        .with_transport(
            server_config
                .transport()
                .clone()
                .with_recovery(RecoveryConfig {
                    mode: server_recovery_mode,
                    ..RecoveryConfig::default()
                }),
        )
        .unwrap();
    let client =
        Client::from_host_socket(&client_config, client_socket.clone(), runtime.clone()).unwrap();
    let server =
        Server::from_host_socket(&server_config, server_socket.clone(), runtime.clone()).unwrap();

    let expected = OpenRequest::new(
        CanonicalHost::parse("www.example.com").unwrap(),
        443u16.try_into().unwrap(),
    );
    let expected_client = expected.clone();
    let server_received = Arc::new(Mutex::new(Vec::new()));
    let server_received_task = Arc::clone(&server_received);
    let server_recovered = Arc::new(AtomicU64::new(0));
    let server_recovered_task = Arc::clone(&server_recovered);
    let retained_server_flow = Arc::new(Mutex::new(None));
    let retained_server_flow_task = Arc::clone(&retained_server_flow);
    let server_status = Arc::new(AtomicU8::new(0));
    let server_status_task = Arc::clone(&server_status);
    runtime
        .spawn(Box::pin(async move {
            let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
                let incoming = server.accept().await?;
                let connection = incoming.handshake().await?;
                let pending = connection.accept_flow(true).await?;
                assert_eq!(pending.request(), &expected);
                let mut flow = pending.accept().await?;
                let mut buffer = [0u8; 512];
                let mut received = [0u8; 5];
                let mut offset = 0;
                while offset < received.len() {
                    let length =
                        poll_fn(|cx| QuicpFlow::poll_read(Pin::new(&mut flow), cx, &mut buffer))
                            .await?;
                    if length == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "request ended early",
                        )
                        .into());
                    }
                    received[offset..offset + length].copy_from_slice(&buffer[..length]);
                    offset += length;
                }
                *server_received_task.lock().unwrap() = received.to_vec();
                flow_write_all(&mut flow, b"reply").await?;
                let mut second = [0u8; 5];
                let mut offset = 0;
                while offset < second.len() {
                    let length =
                        poll_fn(|cx| QuicpFlow::poll_read(Pin::new(&mut flow), cx, &mut buffer))
                            .await?;
                    if length == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "second request ended early",
                        )
                        .into());
                    }
                    second[offset..offset + length].copy_from_slice(&buffer[..length]);
                    offset += length;
                }
                assert_eq!(&second, b"again");
                server_recovered_task
                    .store(connection.recovery_snapshot().recovered, Ordering::Release);
                flow_write_all(&mut flow, b"reply").await?;
                let mut large = vec![0u8; 4096];
                let mut offset = 0;
                while offset < large.len() {
                    let length = poll_fn(|cx| {
                        QuicpFlow::poll_read(Pin::new(&mut flow), cx, &mut large[offset..])
                    })
                    .await?;
                    if length == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "large request ended early",
                        )
                        .into());
                    }
                    offset += length;
                }
                assert_eq!(large, vec![0x5a; 4096]);
                flow_write_all(&mut flow, b"reply").await?;
                *retained_server_flow_task.lock().unwrap() = Some(flow);
                server_status_task.store(1, Ordering::Release);
                std::future::pending().await
            }
            .await;
            if result.is_err() {
                server_status_task.store(2, Ordering::Release);
            }
        }))
        .expect("spawn server task");

    let client_status = Arc::new(AtomicU8::new(0));
    let client_status_task = Arc::clone(&client_status);
    let client_replayed = Arc::new(AtomicU64::new(0));
    let client_replayed_task = Arc::clone(&client_replayed);
    let client_repairs = Arc::new(AtomicU64::new(0));
    let client_repairs_task = Arc::clone(&client_repairs);
    let client_sources = Arc::new(AtomicU64::new(0));
    let client_sources_task = Arc::clone(&client_sources);
    let client_fallback = Arc::new(AtomicU64::new(0));
    let client_fallback_task = Arc::clone(&client_fallback);
    let client_connection = Arc::new(Mutex::new(None));
    let client_connection_task = Arc::clone(&client_connection);
    let drop_client_packet = Arc::new(AtomicU8::new(0));
    let drop_client_packet_task = Arc::clone(&drop_client_packet);
    runtime
        .spawn(Box::pin(async move {
            let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
                let connection = client.connect().await?;
                *client_connection_task.lock().unwrap() = Some(connection.clone());
                let mut flow = connection.open_flow(expected_client, true).await?;
                flow_write_without_flush(&mut flow, b"hello").await?;
                let mut reply = [0u8; 5];
                let mut offset = 0;
                while offset < reply.len() {
                    let length = poll_fn(|cx| {
                        QuicpFlow::poll_read(Pin::new(&mut flow), cx, &mut reply[offset..])
                    })
                    .await?;
                    if length == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "reply ended early",
                        )
                        .into());
                    }
                    offset += length;
                }
                assert_eq!(&reply, b"reply");
                assert!(flow.nodelay());
                flow.set_nodelay(false);
                assert!(!flow.nodelay());
                // Delayed logical ACKs leave this as the next source-bearing QUIC packet. Erase it
                // so the repair symbol, rather than QUIC stream retransmission, fills the gap.
                if adaptive && loss != LossPattern::Clean {
                    drop_client_packet_task.store(
                        if loss == LossPattern::Burst { 200 } else { 1 },
                        Ordering::Release,
                    );
                }
                flow_write_without_flush(&mut flow, b"again").await?;
                poll_fn(|cx| QuicpFlow::poll_flush(Pin::new(&mut flow), cx)).await?;
                let mut second_reply = [0u8; 5];
                let mut offset = 0;
                while offset < second_reply.len() {
                    let length = poll_fn(|cx| {
                        QuicpFlow::poll_read(Pin::new(&mut flow), cx, &mut second_reply[offset..])
                    })
                    .await?;
                    if length == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "second reply ended early",
                        )
                        .into());
                    }
                    offset += length;
                }
                assert_eq!(&second_reply, b"reply");
                flow_write_without_flush(&mut flow, &[0x5a; 4096]).await?;
                poll_fn(|cx| QuicpFlow::poll_flush(Pin::new(&mut flow), cx)).await?;
                let mut third_reply = [0u8; 5];
                let mut offset = 0;
                while offset < third_reply.len() {
                    let length = poll_fn(|cx| {
                        QuicpFlow::poll_read(Pin::new(&mut flow), cx, &mut third_reply[offset..])
                    })
                    .await?;
                    if length == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "third reply ended early",
                        )
                        .into());
                    }
                    offset += length;
                }
                assert_eq!(&third_reply, b"reply");
                let recovery = connection.recovery_snapshot();
                client_replayed_task.store(recovery.replayed, Ordering::Release);
                client_repairs_task.store(recovery.repair_sent, Ordering::Release);
                client_sources_task.store(recovery.source_sent, Ordering::Release);
                client_fallback_task.store(recovery.fallback, Ordering::Release);
                Ok(())
            }
            .await;
            client_status_task.store(u8::from(result.is_err()) + 1, Ordering::Release);
        }))
        .expect("spawn client task");

    let mut dropped_packets = 0;
    let mut random_ordinal = 0;
    let mut reordered_packet = None;
    let mut repair_drop_armed = false;
    for elapsed_ms in 0..5_000 {
        dropped_packets += relay_with_loss(
            &client_socket,
            &server_socket,
            &drop_client_packet,
            loss,
            &mut random_ordinal,
            &mut reordered_packet,
        );
        relay(&server_socket, &client_socket);
        runtime
            .drive(
                Duration::from_millis(elapsed_ms),
                NonZeroUsize::new(128).unwrap(),
            )
            .unwrap();
        if loss == LossPattern::RepairLoss
            && !repair_drop_armed
            && drop_client_packet.load(Ordering::Acquire) == 0
            && client_connection
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|connection| connection.recovery_snapshot().repair_sent != 0)
        {
            drop_client_packet.store(1, Ordering::Release);
            repair_drop_armed = true;
        }
        if loss == LossPattern::Burst && drop_client_packet.load(Ordering::Acquire) != 0 {
            dropped_packets += relay_blackhole(&client_socket);
            drop_client_packet.fetch_sub(1, Ordering::AcqRel);
        } else {
            dropped_packets += relay_with_loss(
                &client_socket,
                &server_socket,
                &drop_client_packet,
                loss,
                &mut random_ordinal,
                &mut reordered_packet,
            );
        }
        relay(&server_socket, &client_socket);
        if server_status.load(Ordering::Acquire) != 0 && client_status.load(Ordering::Acquire) != 0
        {
            break;
        }
    }

    if client_require_adaptive && server_recovery_mode == RecoveryMode::ReliableOnly {
        assert_eq!(client_status.load(Ordering::Acquire), 2);
        runtime.shutdown().unwrap();
        return;
    }
    assert_eq!(server_status.load(Ordering::Acquire), 1);
    assert_eq!(client_status.load(Ordering::Acquire), 1);
    assert_eq!(&*server_received.lock().unwrap(), b"hello");
    if adaptive {
        match loss {
            LossPattern::Clean => {
                assert_eq!(dropped_packets, 0);
                assert_eq!(server_recovered.load(Ordering::Acquire), 0);
                assert_eq!(client_replayed.load(Ordering::Acquire), 0);
                assert_eq!(client_fallback.load(Ordering::Acquire), 0);
                assert_eq!(client_repairs.load(Ordering::Acquire), 0);
            }
            LossPattern::Single => {
                assert_eq!(dropped_packets, 1);
                assert_eq!(server_recovered.load(Ordering::Acquire), 1);
                assert_eq!(client_replayed.load(Ordering::Acquire), 0);
                assert_eq!(client_fallback.load(Ordering::Acquire), 0);
                assert_eq!(client_repairs.load(Ordering::Acquire), 1);
            }
            LossPattern::Burst => {
                assert!(dropped_packets > 0);
                assert!(client_replayed.load(Ordering::Acquire) > 0);
                assert!(client_fallback.load(Ordering::Acquire) > 0);
            }
            LossPattern::Random => {
                assert!(dropped_packets > 0);
                assert!(
                    server_recovered.load(Ordering::Acquire)
                        + client_replayed.load(Ordering::Acquire)
                        + client_fallback.load(Ordering::Acquire)
                        > 0
                );
            }
            LossPattern::Reorder | LossPattern::Duplicate => {
                assert_eq!(dropped_packets, 1);
                assert_eq!(client_replayed.load(Ordering::Acquire), 0);
                assert_eq!(client_fallback.load(Ordering::Acquire), 0);
            }
            LossPattern::RepairLoss => {
                assert_eq!(dropped_packets, 2);
                assert!(client_repairs.load(Ordering::Acquire) > 0);
                assert_eq!(server_recovered.load(Ordering::Acquire), 0);
                assert!(
                    client_replayed.load(Ordering::Acquire)
                        + client_fallback.load(Ordering::Acquire)
                        > 0
                );
            }
        }
        assert!(
            client_sources.load(Ordering::Acquire) >= 3,
            "source count: {}",
            client_sources.load(Ordering::Acquire)
        );
    } else {
        assert_eq!(server_recovered.load(Ordering::Acquire), 0);
        assert_eq!(client_repairs.load(Ordering::Acquire), 0);
        assert_eq!(client_sources.load(Ordering::Acquire), 0);
        assert!(client_fallback.load(Ordering::Acquire) >= 4);
    }
    runtime.shutdown().unwrap();
    let mut flow = retained_server_flow.lock().unwrap().take().unwrap();
    assert!(matches!(
        QuicpFlow::poll_flush(Pin::new(&mut flow), &mut Context::from_waker(Waker::noop()),),
        Poll::Ready(Err(_))
    ));
}

fn relay(from: &HostDatagramSocket, to: &HostDatagramSocket) {
    let mut packet = [0u8; 1500];
    while let Some(len) = from.poll_egress_datagram_into(&mut packet).unwrap() {
        to.ingress_datagram_from(from.local_addr(), &packet[..len])
            .unwrap();
    }
}

fn relay_with_loss(
    from: &HostDatagramSocket,
    to: &HostDatagramSocket,
    armed: &AtomicU8,
    loss: LossPattern,
    random_ordinal: &mut u64,
    reordered_packet: &mut Option<Vec<u8>>,
) -> usize {
    if armed.load(Ordering::Acquire) == 0 {
        relay(from, to);
        return 0;
    }
    match loss {
        LossPattern::Burst => relay_blackhole(from),
        LossPattern::Random => relay_random(from, to, random_ordinal),
        LossPattern::Reorder => relay_reordering_pair(from, to, armed, reordered_packet),
        LossPattern::Duplicate => relay_duplicating_first(from, to, armed),
        LossPattern::Clean | LossPattern::Single | LossPattern::RepairLoss => {
            relay_dropping_prefix(from, to, armed)
        }
    }
}

fn relay_reordering_pair(
    from: &HostDatagramSocket,
    to: &HostDatagramSocket,
    armed: &AtomicU8,
    held: &mut Option<Vec<u8>>,
) -> usize {
    let mut packet = [0u8; 1500];
    let mut reordered = 0;
    while let Some(len) = from.poll_egress_datagram_into(&mut packet).unwrap() {
        if armed.load(Ordering::Acquire) != 0 {
            if let Some(first) = held.take() {
                to.ingress_datagram_from(from.local_addr(), &packet[..len])
                    .unwrap();
                to.ingress_datagram_from(from.local_addr(), &first).unwrap();
                armed.fetch_sub(1, Ordering::AcqRel);
                reordered += 1;
            } else {
                *held = Some(packet[..len].to_vec());
            }
            continue;
        }
        to.ingress_datagram_from(from.local_addr(), &packet[..len])
            .unwrap();
    }
    reordered
}

fn relay_duplicating_first(
    from: &HostDatagramSocket,
    to: &HostDatagramSocket,
    armed: &AtomicU8,
) -> usize {
    let mut packet = [0u8; 1500];
    let mut duplicated = 0;
    while let Some(len) = from.poll_egress_datagram_into(&mut packet).unwrap() {
        to.ingress_datagram_from(from.local_addr(), &packet[..len])
            .unwrap();
        if armed.swap(0, Ordering::AcqRel) != 0 {
            to.ingress_datagram_from(from.local_addr(), &packet[..len])
                .unwrap();
            duplicated += 1;
        }
    }
    duplicated
}

fn relay_dropping_prefix(
    from: &HostDatagramSocket,
    to: &HostDatagramSocket,
    remaining: &AtomicU8,
) -> usize {
    let mut packet = [0u8; 1500];
    let mut dropped = 0;
    while let Some(len) = from.poll_egress_datagram_into(&mut packet).unwrap() {
        let pending = remaining.load(Ordering::Acquire);
        if pending != 0 && remaining.fetch_sub(1, Ordering::AcqRel) != 0 {
            dropped += 1;
            continue;
        }
        to.ingress_datagram_from(from.local_addr(), &packet[..len])
            .unwrap();
    }
    dropped
}

fn relay_random(from: &HostDatagramSocket, to: &HostDatagramSocket, ordinal: &mut u64) -> usize {
    let mut packet = [0u8; 1500];
    let mut dropped = 0;
    while let Some(len) = from.poll_egress_datagram_into(&mut packet).unwrap() {
        *ordinal = ordinal
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        if *ordinal == 1 || ordinal.rotate_right(17).is_multiple_of(16) {
            dropped += 1;
            continue;
        }
        to.ingress_datagram_from(from.local_addr(), &packet[..len])
            .unwrap();
    }
    dropped
}

fn relay_blackhole(from: &HostDatagramSocket) -> usize {
    let mut packet = [0u8; 1500];
    let mut dropped = 0;
    while from
        .poll_egress_datagram_into(&mut packet)
        .unwrap()
        .is_some()
    {
        dropped += 1;
    }
    dropped
}

async fn flow_write_all(flow: &mut QuicpFlow, payload: &[u8]) -> io::Result<()> {
    flow_write_without_flush(flow, payload).await?;
    poll_fn(|cx| QuicpFlow::poll_flush(Pin::new(&mut *flow), cx)).await
}

async fn flow_write_without_flush(flow: &mut QuicpFlow, payload: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < payload.len() {
        let written =
            poll_fn(|cx| QuicpFlow::poll_write(Pin::new(&mut *flow), cx, &payload[offset..]))
                .await?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "flow accepted no bytes",
            ));
        }
        offset += written;
    }
    Ok(())
}

fn ready_ok<T, E>(poll: Poll<Result<T, E>>) -> T {
    match poll {
        Poll::Ready(Ok(value)) => value,
        Poll::Ready(Err(_)) => panic!("poll returned an error"),
        Poll::Pending => panic!("poll unexpectedly pending"),
    }
}

fn ready_poll<T>(poll: Poll<T>) -> T {
    match poll {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("poll unexpectedly pending"),
    }
}
