#![cfg(target_os = "linux")]

use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::OnceLock;
use std::time::Duration;

use quicp::{
    CanonicalHost, CarrierConfig, Client, ClientConfig, Connection, FourTuple, Multipath,
    OpenRequest, PathCandidate, PathHealth, QuicpTransportConfig, Server, ServerConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
            let carrier = CarrierConfig::new(secret_path).expect("test carrier config");
            std::mem::forget(directory);
            carrier
        })
        .clone()
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

fn cross_soak_messages() -> usize {
    env::var("QUICP_RAW_SOAK_MESSAGES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|messages| *messages != 0)
        .unwrap_or(CROSS_SOAK_MESSAGES)
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
    let primary = PathCandidate::new(local.source.ip(), local.destination).unwrap();
    let backup = PathCandidate::new(backup.source.ip(), backup.destination).unwrap();
    ClientConfig::insecure(
        Multipath::failover(primary, backup).unwrap(),
        raw_test_carrier(),
    )
    .unwrap()
    .with_transport(cross_host_transport())
    .unwrap()
}

fn cross_host_server_config(primary: FourTuple, backup: FourTuple) -> ServerConfig {
    ServerConfig::insecure(
        vec![primary.destination, backup.destination],
        raw_test_carrier(),
    )
    .unwrap()
    .with_transport(cross_host_transport())
    .unwrap()
}

fn cross_host_transport() -> QuicpTransportConfig {
    QuicpTransportConfig {
        idle_timeout: Duration::from_secs(10),
        keep_alive_interval: Duration::from_secs(1),
        path_idle_timeout: Duration::from_secs(3),
        ..QuicpTransportConfig::default()
    }
}

fn cross_host_ip(name: &str) -> Ipv4Addr {
    env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set for the cross-host raw test"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} must be an IPv4 address"))
}

fn cross_host_ip_or(name: &str, fallback: Ipv4Addr) -> Ipv4Addr {
    env::var(name).map_or(fallback, |value| {
        value
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be an IPv4 address"))
    })
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
        let messages = cross_soak_messages();
        for index in 0..messages {
            let expected = soak_payload(index);
            let mut received = [0; 16];
            tokio::time::timeout(Duration::from_secs(30), flow.read_exact(&mut received))
                .await
                .expect("cross-host soak payload timed out")
                .unwrap();
            assert_eq!(received, expected);
        }
        println!("cross-host server observed {messages}-message same-flow soak");
        return;
    }
    let mut after = [0; 5];
    let result = tokio::time::timeout(Duration::from_secs(25), flow.read_exact(&mut after)).await;
    if scenario == CrossHostScenario::BothBlackhole {
        assert!(result.is_ok_and(|read| read.is_err()));
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
        let messages = cross_soak_messages();
        for index in 0..messages {
            flow.write_all(&soak_payload(index)).await.unwrap();
            flow.flush().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        println!("cross-host client completed {messages}-message same-flow soak");
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
        tokio::time::sleep(Duration::from_secs(12)).await;
        assert_eq!(connection.path_health(), Some(PathHealth::Failed));
        assert!(!connection.backup_ready());
        let reopened = tokio::time::timeout(
            Duration::from_secs(1),
            connection.open_flow(
                OpenRequest::new(
                    CanonicalHost::parse("closed.example").unwrap(),
                    NonZeroU16::new(443).unwrap(),
                ),
                true,
            ),
        )
        .await;
        assert!(reopened.is_ok_and(|flow| flow.is_err()));
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
    let backup_local_ip = cross_host_ip_or("QUICP_RAW_BACKUP_LOCAL_IP", local_ip);
    let backup_peer_ip = cross_host_ip_or("QUICP_RAW_BACKUP_PEER_IP", peer_ip);
    let primary = FourTuple::new(
        SocketAddr::from((local_ip, CROSS_PRIMARY_CLIENT_PORT)),
        SocketAddr::from((peer_ip, CROSS_PRIMARY_SERVER_PORT)),
    );
    let backup = FourTuple::new(
        SocketAddr::from((backup_local_ip, CROSS_BACKUP_CLIENT_PORT)),
        SocketAddr::from((backup_peer_ip, CROSS_BACKUP_SERVER_PORT)),
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
