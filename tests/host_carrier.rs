use std::future::poll_fn;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use noq::AsyncUdpSocket;
use noq::udp::{RecvMeta, Transmit};
use quicp::config::Config;
use quicp::{
    CanonicalHost, Client, HostDatagramError, HostDatagramSocket, HostRuntime, OpenRequest,
    QuicpFlow, Server, TransportError,
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
name = "host"
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
name = "host"
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
    assert_eq!(socket.egress_len(), 0);
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
    assert_eq!(socket.egress_len(), 1);

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
name = "host"
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
#[allow(clippy::too_many_lines)]
fn host_endpoint_facade_drives_no_tls_flow_loopback() {
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
name = "host"
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
                drop(connection);
                let mut buffer = [0u8; 32];
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
                flow_write_all(&mut flow, b"reply").await?;
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
    runtime
        .spawn(Box::pin(async move {
            let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
                let connection = client.connect().await?;
                let mut flow = connection.open_flow(expected_client, true).await?;
                drop(connection);
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
                Ok(())
            }
            .await;
            client_status_task.store(u8::from(result.is_err()) + 1, Ordering::Release);
        }))
        .expect("spawn client task");

    for elapsed_ms in 0..5_000 {
        relay(&client_socket, &server_socket);
        relay(&server_socket, &client_socket);
        runtime
            .drive(
                Duration::from_millis(elapsed_ms),
                NonZeroUsize::new(128).unwrap(),
            )
            .unwrap();
        relay(&client_socket, &server_socket);
        relay(&server_socket, &client_socket);
        if server_status.load(Ordering::Acquire) != 0 && client_status.load(Ordering::Acquire) != 0
        {
            break;
        }
    }

    assert_eq!(server_status.load(Ordering::Acquire), 1);
    assert_eq!(client_status.load(Ordering::Acquire), 1);
    assert_eq!(&*server_received.lock().unwrap(), b"hello");
    runtime.shutdown().unwrap();
}

fn relay(from: &HostDatagramSocket, to: &HostDatagramSocket) {
    let mut packet = [0u8; 1500];
    while let Some(len) = from.poll_egress_datagram_into(&mut packet).unwrap() {
        to.ingress_datagram_from(from.local_addr(), &packet[..len])
            .unwrap();
    }
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
