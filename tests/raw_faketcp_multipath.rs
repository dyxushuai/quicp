#![cfg(all(target_os = "linux", feature = "runtime-tokio"))]

use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::time::Duration;

use noq::{FourTuple as QuicTuple, PathError, PathId, PathStatus};
use quicp::config::{
    CarrierConfig, ClientConfig, Ipv4Pool, Multipath, MultipathMode, PathCandidate, ServerConfig,
    ZeroRttMode,
};
use quicp::faketcp::{FourTuple, SynDataMode};
use quicp::flow::{QuicpFlow, accept_flow};
use quicp::transport::{build_fake_tcp_client_endpoint, build_fake_tcp_server_endpoint};
use quicp::wire::{CanonicalHost, OpenRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SYN_COOKIE: SynDataMode = SynDataMode::Cookie([0x24; 16]);

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
    let directory = tempfile::tempdir().unwrap();
    let client = ClientConfig {
        journal_path: directory.path().join("fakeip.journal"),
        fake_ip_pool: "198.18.0.0/15".parse::<Ipv4Pool>().unwrap(),
        fake_dns_addr: Ipv4Addr::new(198, 18, 0, 1),
        zero_rtt: ZeroRttMode::Off,
        tls: None,
        multipath: Multipath {
            mode: MultipathMode::Failover,
            candidates: [primary, backup]
                .into_iter()
                .zip(["primary", "backup"])
                .map(|(tuple, name)| PathCandidate {
                    name: name.to_owned(),
                    local_ip: tuple.source.ip(),
                    server_addr: tuple.destination,
                })
                .collect(),
        },
        carrier: CarrierConfig::default(),
    };
    let server = ServerConfig {
        listen_addrs: vec![primary.destination, backup.destination],
        tls: None,
        carrier: CarrierConfig::default(),
    };
    let client_paths = [(primary, SYN_COOKIE), (backup, SYN_COOKIE)];
    let server_paths = [
        (primary.reverse(), SYN_COOKIE),
        (backup.reverse(), SYN_COOKIE),
    ];
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
        accept_flow(&server_connection)
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
