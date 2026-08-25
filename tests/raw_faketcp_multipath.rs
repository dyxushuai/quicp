#![cfg(all(
    target_os = "linux",
    feature = "runtime-tokio",
    feature = "internal-bench"
))]

use std::env;
use std::future::poll_fn;
use std::io::IoSliceMut;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use noq::udp::{RecvMeta, Transmit};
use noq::{AsyncUdpSocket, FourTuple as QuicTuple, PathError, PathId, PathStatus, UdpSender};
use quicp::config::{
    CarrierConfig, ClientConfig, CongestionControl, Multipath, PathCandidate, ServerConfig,
    SynDataPolicy,
};
use quicp::faketcp::{CarrierDirection, FakeTcpSocket, FourTuple, SynDataMode};
use quicp::flow::{QuicpFlow, accept_flow};
use quicp::transport::{
    Client, Connection, Server, build_fake_tcp_client_endpoint, build_fake_tcp_server_endpoint,
};
use quicp::wire::{CanonicalHost, OpenRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SYN_COOKIE: SynDataMode = SynDataMode::Cookie([0x24; 16]);

fn raw_test_carrier() -> CarrierConfig {
    static CARRIER: OnceLock<CarrierConfig> = OnceLock::new();
    CARRIER
        .get_or_init(|| {
            let home = env::var_os("HOME").expect("HOME is required for raw carrier tests");
            let directory = tempfile::tempdir_in(home).expect("trusted test directory");
            let secret_path = directory.path().join("carrier-cookie.secret");
            std::fs::write(&secret_path, b"quicp raw test cookie secret")
                .expect("test cookie secret");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
                    .expect("test cookie permissions");
            }
            let carrier =
                CarrierConfig::new(SynDataPolicy::Cookie, secret_path, CongestionControl::Cubic)
                    .expect("test carrier config");
            std::mem::forget(directory);
            carrier
        })
        .clone()
}

async fn send_datagram(sender: &mut Pin<Box<dyn UdpSender>>, tuple: FourTuple, contents: &[u8]) {
    let transmit = Transmit {
        destination: tuple.destination,
        ecn: None,
        contents,
        segment_size: None,
        src_ip: Some(tuple.source.ip()),
    };
    poll_fn(|cx| sender.as_mut().poll_send(&transmit, cx))
        .await
        .unwrap();
}

async fn receive_datagram(receiver: &mut FakeTcpSocket) -> Vec<u8> {
    let mut storage = [0; 5_888];
    let mut meta = [RecvMeta::default()];
    let datagram_count = poll_fn(|cx| {
        let mut bufs = [IoSliceMut::new(&mut storage)];
        Pin::new(&mut *receiver).poll_recv(cx, &mut bufs, &mut meta)
    })
    .await
    .unwrap();
    assert_eq!(datagram_count, 1);
    storage[..meta[0].len].to_vec()
}

async fn wait_for_backup_ready(connection: &Connection) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !connection.backup_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("backup path did not become ready");
}

#[tokio::test]
#[ignore = "requires CAP_NET_RAW"]
async fn oversized_carrier_datagram_is_dropped_without_killing_socket() {
    for (offset, packet_socket) in [(0, false), (1, true)] {
        let client_tuple = FourTuple::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_882 + offset)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 44_882 + offset)),
        );
        let mut receiver = FakeTcpSocket::bind(
            client_tuple.reverse(),
            CarrierDirection::ServerToClient,
            SYN_COOKIE,
            quicp::faketcp::DEFAULT_SYN_MSS,
            u16::MAX,
            packet_socket,
        )
        .unwrap();
        let sender_socket = FakeTcpSocket::bind(
            client_tuple,
            CarrierDirection::ClientToServer,
            SYN_COOKIE,
            quicp::faketcp::DEFAULT_SYN_MSS,
            u16::MAX,
            packet_socket,
        )
        .unwrap();
        let mut sender = sender_socket.create_sender();
        send_datagram(&mut sender, client_tuple, b"first").await;
        assert_eq!(receive_datagram(&mut receiver).await, b"first");
        send_datagram(&mut sender, client_tuple, &vec![0x5a; 6_000]).await;
        let receive_valid =
            tokio::time::timeout(Duration::from_secs(2), receive_datagram(&mut receiver));
        let send_valid = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            send_datagram(&mut sender, client_tuple, b"valid").await;
        };
        let (valid, ()) = tokio::join!(receive_valid, send_valid);
        assert_eq!(
            valid.unwrap_or_else(|_| panic!(
                "valid packet was not delivered; packet_socket={packet_socket}"
            )),
            b"valid"
        );
        assert_eq!(receiver.rejected_datagrams(), 1);
    }
}

#[tokio::test]
#[ignore = "requires CAP_NET_RAW and tuple-scoped RST suppression"]
async fn client_facade_validates_backup_before_opening_flow() {
    let primary = FourTuple::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 40_884)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 44_884)),
    );
    let backup = FourTuple::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 40_885)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 44_885)),
    );
    let client_config = cross_host_config(primary, backup);
    let server_config = cross_host_server_config(primary, backup);
    let client = Client::bind_fake_tcp(&client_config, &[primary, backup]).unwrap();
    let server =
        Server::bind_fake_tcp(&server_config, &[primary.reverse(), backup.reverse()]).unwrap();
    let server_connection = async { server.accept().await.unwrap().handshake().await.unwrap() };
    let client_connection = client.connect();
    let (server_connection, client_connection) = tokio::join!(server_connection, client_connection);
    let client_connection = client_connection.unwrap();
    wait_for_backup_ready(&client_connection).await;

    let server_flow = async {
        server_connection
            .accept_flow(true)
            .await
            .unwrap()
            .accept()
            .await
            .unwrap()
    };
    let client_flow = async {
        client_connection
            .open_flow(
                OpenRequest::new(
                    CanonicalHost::parse("example.com").unwrap(),
                    NonZeroU16::new(443).unwrap(),
                ),
                true,
            )
            .await
            .unwrap()
    };
    let (mut server_flow, mut client_flow) = tokio::join!(server_flow, client_flow);
    client_flow.write_all(b"ready").await.unwrap();
    client_flow.flush().await.unwrap();
    let mut received = [0; 5];
    server_flow.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"ready");
}

#[tokio::test]
#[ignore = "requires CAP_NET_RAW and tuple-scoped RST suppression"]
#[allow(clippy::too_many_lines)]
async fn raw_faketcp_failover_keeps_same_flow() {
    let primary = FourTuple::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 40_880)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 44_880)),
    );
    let backup = FourTuple::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 40_881)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 44_881)),
    );
    let client = cross_host_config(primary, backup);
    let server = cross_host_server_config(primary, backup);
    let client_paths = [primary, backup];
    let server_paths = [primary.reverse(), backup.reverse()];
    let server_endpoint = build_fake_tcp_server_endpoint(&server, &server_paths).unwrap();
    let client_endpoint = build_fake_tcp_client_endpoint(&client, &client_paths).unwrap();

    let server_connection = async {
        server_endpoint
            .accept()
            .await
            .expect("incoming connection")
            .await
            .unwrap()
    };
    let client_connection = async {
        client_endpoint
            .connect(primary.destination, "quicp")
            .unwrap()
            .await
            .unwrap()
    };
    let (server_connection, client_connection) = tokio::join!(server_connection, client_connection);
    let stable_id = client_connection.stable_id();
    let backup_path = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match client_connection
                .open_path(
                    QuicTuple::new(backup.destination, Some(backup.source.ip())),
                    PathStatus::Backup,
                )
                .await
            {
                Ok(path) => break path,
                Err(PathError::RemoteCidsExhausted) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("backup path failed: {error}"),
            }
        }
    })
    .await
    .expect("backup path timed out");
    assert_eq!(backup_path.status().unwrap(), PathStatus::Backup);

    let server_flow = async {
        accept_flow(&server_connection, true)
            .await
            .unwrap()
            .accept()
            .await
            .unwrap()
    };
    let client_flow = async {
        QuicpFlow::open(
            &client_connection,
            OpenRequest::new(
                CanonicalHost::parse("example.com").unwrap(),
                NonZeroU16::new(443).unwrap(),
            ),
            true,
        )
        .await
        .unwrap()
    };
    let (mut server_flow, mut client_flow) = tokio::join!(server_flow, client_flow);
    client_flow.write_all(b"before").await.unwrap();
    client_flow.flush().await.unwrap();
    let mut before = [0; 6];
    server_flow.read_exact(&mut before).await.unwrap();
    assert_eq!(&before, b"before");
    let backup_tx_before = backup_path.stats().udp_tx.bytes;

    client_connection
        .path(PathId::ZERO)
        .expect("primary path")
        .close()
        .unwrap();
    client_flow.write_all(b"after").await.unwrap();
    client_flow.flush().await.unwrap();
    let mut after = [0; 5];
    tokio::time::timeout(Duration::from_secs(5), server_flow.read_exact(&mut after))
        .await
        .expect("flow did not fail over")
        .unwrap();
    assert_eq!(&after, b"after");
    assert!(backup_path.stats().udp_tx.bytes > backup_tx_before);
    assert_eq!(client_connection.stable_id(), stable_id);
}

const CROSS_PRIMARY_CLIENT_PORT: u16 = 41_080;
const CROSS_PRIMARY_SERVER_PORT: u16 = 45_080;
const CROSS_BACKUP_CLIENT_PORT: u16 = 41_081;
const CROSS_BACKUP_SERVER_PORT: u16 = 45_081;
const CROSS_SOAK_MESSAGES: usize = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CrossHostScenario {
    Failover,
    BackupUnavailable,
    BothBlackhole,
    Soak,
}

impl CrossHostScenario {
    fn from_env() -> Self {
        match env::var("QUICP_RAW_SCENARIO").as_deref() {
            Ok("backup-unavailable") => Self::BackupUnavailable,
            Ok("both-blackhole") => Self::BothBlackhole,
            Ok("soak") => Self::Soak,
            Ok("failover") | Err(_) => Self::Failover,
            Ok(scenario) => panic!(
                "QUICP_RAW_SCENARIO must be failover, backup-unavailable, both-blackhole, or soak, got {scenario}"
            ),
        }
    }
}

fn soak_payload(index: usize) -> [u8; 16] {
    let mut payload = [0x5a; 16];
    payload[..8].copy_from_slice(&(index as u64).to_be_bytes());
    payload
}

fn cross_host_blackhole_delay() -> Duration {
    // External `tc` orchestration can increase this window after CROSS_FLOW_READY; one second
    // remains the default for the existing harness behavior.
    env::var("QUICP_RAW_BLACKHOLE_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(Duration::from_secs(1), Duration::from_millis)
}

fn cross_host_config(local: FourTuple, backup: FourTuple) -> ClientConfig {
    let primary = PathCandidate::new("primary", local.source.ip(), local.destination).unwrap();
    let backup = PathCandidate::new("backup", backup.source.ip(), backup.destination).unwrap();
    ClientConfig::insecure(
        Multipath::failover(primary, backup).unwrap(),
        raw_test_carrier(),
    )
    .unwrap()
}

fn cross_host_server_config(primary: FourTuple, backup: FourTuple) -> ServerConfig {
    ServerConfig::insecure(
        vec![primary.destination, backup.destination],
        raw_test_carrier(),
    )
    .unwrap()
}

fn cross_host_ip(name: &str) -> Ipv4Addr {
    env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set for the cross-host raw test"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} must be an IPv4 address"))
}

async fn run_cross_host_server(primary: FourTuple, backup: FourTuple, scenario: CrossHostScenario) {
    let server = Server::bind_fake_tcp(
        &cross_host_server_config(primary, backup),
        &[primary.reverse(), backup.reverse()],
    )
    .unwrap();
    if scenario == CrossHostScenario::BackupUnavailable {
        let _ = tokio::time::timeout(Duration::from_secs(30), async {
            if let Ok(incoming) = server.accept().await
                && let Ok(Ok(connection)) =
                    tokio::time::timeout(Duration::from_secs(5), incoming.handshake()).await
            {
                tokio::time::sleep(Duration::from_secs(25)).await;
                drop(connection);
            }
        })
        .await;
        println!("cross-host server observed backup-unavailable close without opening a flow");
        return;
    }
    let connection = tokio::time::timeout(Duration::from_secs(20), async {
        server.accept().await.unwrap().handshake().await.unwrap()
    })
    .await
    .expect("cross-host server handshake timed out");
    let mut flow = tokio::time::timeout(Duration::from_secs(20), async {
        connection
            .accept_flow(true)
            .await
            .unwrap()
            .accept()
            .await
            .unwrap()
    })
    .await
    .expect("cross-host server flow timed out");
    let mut before = [0; 6];
    flow.read_exact(&mut before).await.unwrap();
    assert_eq!(&before, b"before");
    if scenario == CrossHostScenario::Soak {
        for index in 0..CROSS_SOAK_MESSAGES {
            let expected = soak_payload(index);
            let mut received = [0; 16];
            tokio::time::timeout(Duration::from_secs(30), flow.read_exact(&mut received))
                .await
                .expect("cross-host soak payload timed out")
                .unwrap();
            assert_eq!(received, expected);
        }
        println!("cross-host server observed {CROSS_SOAK_MESSAGES}-message same-flow soak");
        return;
    }
    let mut after = [0; 5];
    let result = tokio::time::timeout(Duration::from_secs(25), flow.read_exact(&mut after)).await;
    if scenario == CrossHostScenario::BothBlackhole {
        assert!(result.is_err() || result.as_ref().is_ok_and(Result::is_err));
        println!("cross-host server observed both-path fail-closed behavior");
    } else {
        result.expect("cross-host flow did not fail over").unwrap();
        assert_eq!(&after, b"after");
        println!("cross-host server observed same-flow failover");
    }
}

async fn run_cross_host_client(primary: FourTuple, backup: FourTuple, scenario: CrossHostScenario) {
    let client =
        Client::bind_fake_tcp(&cross_host_config(primary, backup), &[primary, backup]).unwrap();
    if scenario == CrossHostScenario::BackupUnavailable {
        let connection = tokio::time::timeout(Duration::from_secs(20), client.connect()).await;
        assert!(matches!(connection, Err(_) | Ok(Err(_))));
        println!("cross-host client failed closed before backup became ready");
        return;
    }
    let connection = tokio::time::timeout(Duration::from_secs(20), client.connect())
        .await
        .expect("cross-host client handshake timed out")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !connection.backup_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cross-host backup path did not become ready");
    let mut flow = tokio::time::timeout(
        Duration::from_secs(20),
        connection.open_flow(
            OpenRequest::new(
                CanonicalHost::parse("example.com").unwrap(),
                NonZeroU16::new(443).unwrap(),
            ),
            true,
        ),
    )
    .await
    .expect("cross-host flow open timed out")
    .unwrap();
    flow.write_all(b"before").await.unwrap();
    flow.flush().await.unwrap();
    println!("CROSS_FLOW_READY");
    if scenario == CrossHostScenario::Soak {
        for index in 0..CROSS_SOAK_MESSAGES {
            flow.write_all(&soak_payload(index)).await.unwrap();
            flow.flush().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        println!("cross-host client completed {CROSS_SOAK_MESSAGES}-message same-flow soak");
        return;
    }
    tokio::time::sleep(cross_host_blackhole_delay()).await;
    if scenario == CrossHostScenario::BothBlackhole {
        let write_result = tokio::time::timeout(Duration::from_secs(25), async {
            flow.write_all(b"after").await?;
            flow.flush().await
        })
        .await;
        println!("cross-host both-blackhole write result: {write_result:?}");
        tokio::time::sleep(Duration::from_secs(25)).await;
    } else {
        flow.write_all(b"after").await.unwrap();
        flow.flush().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

#[tokio::test]
#[ignore = "requires two Linux hosts, CAP_NET_RAW, tc blackhole, and tuple-scoped RST suppression"]
#[allow(clippy::too_many_lines)]
async fn raw_faketcp_cross_host_failover() {
    // The environment always describes the canonical client-to-server tuple; the server helper
    // reverses it before binding its outbound carrier paths.
    let local_ip = cross_host_ip("QUICP_RAW_LOCAL_IP");
    let peer_ip = cross_host_ip("QUICP_RAW_PEER_IP");
    let primary = FourTuple::new(
        SocketAddr::from((local_ip, CROSS_PRIMARY_CLIENT_PORT)),
        SocketAddr::from((peer_ip, CROSS_PRIMARY_SERVER_PORT)),
    );
    let backup = FourTuple::new(
        SocketAddr::from((local_ip, CROSS_BACKUP_CLIENT_PORT)),
        SocketAddr::from((peer_ip, CROSS_BACKUP_SERVER_PORT)),
    );
    let scenario = CrossHostScenario::from_env();
    match env::var("QUICP_RAW_ROLE")
        .expect("QUICP_RAW_ROLE must be set for the cross-host raw test")
        .as_str()
    {
        "client" => run_cross_host_client(primary, backup, scenario).await,
        "server" => run_cross_host_server(primary, backup, scenario).await,
        role => panic!("QUICP_RAW_ROLE must be client or server, got {role}"),
    }
}
