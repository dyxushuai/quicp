#[cfg(target_os = "linux")]
use std::hint::black_box;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use quicp::config::{
    CarrierConfig, ClientConfig, Ipv4Pool, Multipath, MultipathMode, PathCandidate, ServerConfig,
    ZeroRttMode,
};
#[cfg(target_os = "linux")]
use quicp::faketcp::{FourTuple, SynDataMode};
#[cfg(target_os = "linux")]
use quicp::flow::{QuicpFlow, accept_flow};
#[cfg(target_os = "linux")]
use quicp::transport::{
    TransportError, build_fake_tcp_client_endpoint, build_fake_tcp_server_endpoint,
};
#[cfg(target_os = "linux")]
use quicp::wire::{CanonicalHost, OpenRequest};
#[cfg(target_os = "linux")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(target_os = "linux")]
use tokio::net::{TcpListener, TcpStream};

#[cfg(debug_assertions)]
#[cfg(target_os = "linux")]
const TOTAL_BYTES: usize = 512 * 1024;
#[cfg(not(debug_assertions))]
#[cfg(target_os = "linux")]
const TOTAL_BYTES: usize = 8 * 1024 * 1024;
#[cfg(target_os = "linux")]
const PAYLOADS: &[usize] = &[64, 1200, 4096];
#[cfg(target_os = "linux")]
const DEADLINE: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
const SYN_COOKIE: SynDataMode = SynDataMode::Cookie([0x24; 16]);

#[cfg(target_os = "linux")]
fn main() -> io::Result<()> {
    println!("payload_bytes,quicp_ns_per_payload,tcp_ns_per_payload,quicp_gbps,tcp_gbps");
    let directory = tempfile::tempdir()?;
    let total_bytes = std::env::var("QUICP_TOTAL_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(TOTAL_BYTES);
    let payloads = std::env::var("QUICP_PAYLOAD_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map_or_else(|| PAYLOADS.to_vec(), |payload| vec![payload]);
    for (sample, payload_size) in payloads.into_iter().enumerate() {
        let iterations = total_bytes.div_ceil(payload_size);
        let quicp = match quicp_sample(payload_size, iterations, sample, directory.path()) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                println!("raw QUICP bench skipped: CAP_NET_RAW is required");
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if std::env::var_os("QUICP_ONLY").is_some() {
            let quicp_ns = quicp / u128::from(iterations as u64);
            println!(
                "{payload_size},{quicp_ns},,{},",
                gbps(payload_size, quicp_ns)
            );
            continue;
        }
        let tcp = tcp_sample(payload_size, iterations)?;
        let quicp_ns = quicp / u128::from(iterations as u64);
        let tcp_ns = tcp / u128::from(iterations as u64);
        println!(
            "{payload_size},{quicp_ns},{tcp_ns},{},{}",
            gbps(payload_size, quicp_ns),
            gbps(payload_size, tcp_ns),
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("raw QUICP/TCP bench skipped: Linux raw sockets are required");
}

#[cfg(target_os = "linux")]
fn quicp_sample(
    payload_size: usize,
    iterations: usize,
    sample: usize,
    directory: &Path,
) -> io::Result<u128> {
    let tuple = bench_tuple(sample);
    let client = client_config(tuple, directory);
    let server = ServerConfig {
        listen_addrs: vec![tuple.destination],
        tls: None,
        carrier: CarrierConfig {
            packet_socket: packet_socket_enabled(),
            ..CarrierConfig::default()
        },
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        tokio::time::timeout(
            DEADLINE,
            run_quicp(payload_size, iterations, tuple, client, server),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "raw QUICP bench timed out"))?
    })
}

#[cfg(target_os = "linux")]
fn bench_tuple(sample: usize) -> FourTuple {
    let process_offset = u16::try_from(std::process::id() % 1000).expect("process offset");
    let sample_offset = u16::try_from(sample).expect("sample offset");
    let offset = (process_offset + sample_offset) % 1000;
    FourTuple::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000_u16 + offset)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 44_000_u16 + offset)),
    )
}

#[cfg(target_os = "linux")]
async fn run_quicp(
    payload_size: usize,
    iterations: usize,
    tuple: FourTuple,
    client: ClientConfig,
    server: ServerConfig,
) -> io::Result<u128> {
    let server_endpoint = build_fake_tcp_server_endpoint(&server, &[(tuple.reverse(), SYN_COOKIE)])
        .map_err(transport_error)?;
    let server_addr = server_endpoint.local_addr()?;
    let client_endpoint =
        build_fake_tcp_client_endpoint(&client, &[(tuple, SYN_COOKIE)]).map_err(transport_error)?;

    let server_connection = async {
        let incoming = server_endpoint
            .accept()
            .await
            .ok_or_else(|| io::Error::other("raw QUICP server stopped"))?;
        incoming.await.map_err(debug_io_error)
    };
    let client_connection = async {
        client_endpoint
            .connect(server_addr, "quicp")
            .map_err(debug_io_error)?
            .await
            .map_err(debug_io_error)
    };
    let (server_connection, client_connection) =
        tokio::try_join!(server_connection, client_connection)?;

    let server_flow = async {
        let pending = accept_flow(&server_connection)
            .await
            .map_err(debug_io_error)?;
        pending.accept().await.map_err(debug_io_error)
    };
    let client_flow = async {
        let host = CanonicalHost::parse("example.com").map_err(debug_io_error)?;
        QuicpFlow::open(
            &client_connection,
            OpenRequest::new(host, std::num::NonZeroU16::new(443).expect("port")),
        )
        .await
        .map_err(debug_io_error)
    };
    let (mut server_flow, mut client_flow) = tokio::try_join!(server_flow, client_flow)?;

    let payload = vec![0x5a; payload_size];
    let mut received = vec![0; payload_size];
    let start = Instant::now();
    let sender = async {
        for _ in 0..iterations {
            client_flow
                .write_all(&payload)
                .await
                .map_err(debug_io_error)?;
        }
        client_flow.shutdown().await.map_err(debug_io_error)
    };
    let read_task = async {
        for _ in 0..iterations {
            server_flow
                .read_exact(&mut received)
                .await
                .map_err(debug_io_error)?;
            black_box(&received);
        }
        Ok::<(), io::Error>(())
    };
    tokio::try_join!(sender, read_task)?;
    Ok(start.elapsed().as_nanos())
}

#[cfg(target_os = "linux")]
fn client_config(tuple: FourTuple, directory: &Path) -> ClientConfig {
    ClientConfig {
        journal_path: directory.join("fakeip.journal"),
        fake_ip_pool: "198.18.0.0/15".parse::<Ipv4Pool>().expect("pool"),
        fake_dns_addr: Ipv4Addr::new(198, 18, 0, 1),
        zero_rtt: ZeroRttMode::Off,
        tls: None,
        multipath: Multipath {
            mode: MultipathMode::Off,
            candidates: vec![PathCandidate {
                name: "primary".to_owned(),
                local_ip: tuple.source.ip(),
                server_addr: tuple.destination,
            }],
        },
        carrier: CarrierConfig {
            packet_socket: packet_socket_enabled(),
            ..CarrierConfig::default()
        },
    }
}

#[cfg(target_os = "linux")]
fn packet_socket_enabled() -> bool {
    std::env::var_os("QUICP_IP_RAW").is_none()
}

#[cfg(target_os = "linux")]
fn tcp_sample(payload_size: usize, iterations: usize) -> io::Result<u128> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        tokio::time::timeout(DEADLINE, run_tcp(payload_size, iterations))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP bench timed out"))?
    })
}

#[cfg(target_os = "linux")]
async fn run_tcp(payload_size: usize, iterations: usize) -> io::Result<u128> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let server = async {
        let (mut stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let mut received = vec![0; payload_size];
        for _ in 0..iterations {
            stream.read_exact(&mut received).await?;
            black_box(&received);
        }
        Ok::<(), io::Error>(())
    };
    let mut client = TcpStream::connect(address).await?;
    client.set_nodelay(true)?;
    let payload = vec![0x5a; payload_size];
    let start = Instant::now();
    let sender = async {
        for _ in 0..iterations {
            client.write_all(&payload).await?;
        }
        client.shutdown().await
    };
    tokio::try_join!(sender, server)?;
    Ok(start.elapsed().as_nanos())
}

#[cfg(target_os = "linux")]
fn transport_error(error: TransportError) -> io::Error {
    match error {
        TransportError::Io(error) => error,
        error => io::Error::other(error),
    }
}

#[cfg(target_os = "linux")]
fn debug_io_error(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

#[cfg(target_os = "linux")]
fn gbps(payload_size: usize, elapsed_nanos_per_payload: u128) -> String {
    let milli_gbps = u128::try_from(payload_size)
        .expect("payload size fits u128")
        .saturating_mul(8_000)
        .checked_div(elapsed_nanos_per_payload)
        .unwrap_or(0);
    format!("{}.{:03}", milli_gbps / 1_000, milli_gbps % 1_000)
}
