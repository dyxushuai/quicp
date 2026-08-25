#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::hint::black_box;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use quicp::config::{
    CarrierConfig, ClientConfig, CongestionControl, Multipath, PathCandidate, ServerConfig,
    SynDataPolicy,
};
#[cfg(target_os = "linux")]
use quicp::faketcp::FourTuple;
#[cfg(target_os = "linux")]
use quicp::flow::{QuicpFlow, accept_flow};
#[cfg(target_os = "linux")]
use quicp::transport::{
    TransportError, build_fake_tcp_client_endpoint_with_options,
    build_fake_tcp_server_endpoint_with_options,
};
#[cfg(target_os = "linux")]
use quicp::wire::{CanonicalHost, OpenRequest};
#[cfg(target_os = "linux")]
use quicp::{PluginRegistry, QueqiaoPlugin, TransportOptions};
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
const SAMPLES: usize = 5;
#[cfg(target_os = "linux")]
const DEADLINE: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
fn main() -> io::Result<()> {
    assert_eq!(quantile(&[5, 1, 3, 2, 4], 50), 3);
    let nodelay = std::env::var("QUICP_NODELAY")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(true);
    let congestion = std::env::var("QUICP_CONGESTION")
        .unwrap_or_else(|_| "cubic".to_owned())
        .to_ascii_lowercase();
    if congestion != "cubic" && congestion != "queqiao" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUICP_CONGESTION must be cubic or queqiao",
        ));
    }
    println!("# quicp_nodelay={nodelay}");
    println!("# quicp_congestion={congestion}");
    println!(
        "payload_bytes,quicp_median_ns,quicp_p95_ns,quicp_p99_ns,tcp_median_ns,tcp_p95_ns,tcp_p99_ns,quicp_median_gbps,tcp_median_gbps"
    );
    let total_bytes = std::env::var("QUICP_TOTAL_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(TOTAL_BYTES);
    let payloads = std::env::var("QUICP_PAYLOAD_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map_or_else(|| PAYLOADS.to_vec(), |payload| vec![payload]);
    for payload_size in payloads {
        let iterations = total_bytes.div_ceil(payload_size);
        let mut quicp_samples = Vec::with_capacity(SAMPLES);
        let mut tcp_samples = Vec::with_capacity(SAMPLES);
        for sample in 0..SAMPLES {
            let quicp = match quicp_sample(payload_size, iterations, sample, nodelay, &congestion) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "raw QUICP bench requires CAP_NET_RAW",
                    ));
                }
                Err(error) => return Err(error),
            };
            quicp_samples.push(quicp / u128::from(iterations as u64));
            if std::env::var_os("QUICP_ONLY").is_none() {
                let tcp = tcp_sample(payload_size, iterations)?;
                tcp_samples.push(tcp / u128::from(iterations as u64));
            }
        }
        let quicp_median = quantile(&quicp_samples, 50);
        let quicp_p95 = quantile(&quicp_samples, 95);
        let quicp_p99 = quantile(&quicp_samples, 99);
        if tcp_samples.is_empty() {
            println!(
                "{payload_size},{quicp_median},{quicp_p95},{quicp_p99},,,,{},",
                gbps(payload_size, quicp_median),
            );
        } else {
            let tcp_median = quantile(&tcp_samples, 50);
            let tcp_p95 = quantile(&tcp_samples, 95);
            let tcp_p99 = quantile(&tcp_samples, 99);
            println!(
                "{payload_size},{quicp_median},{quicp_p95},{quicp_p99},{tcp_median},{tcp_p95},{tcp_p99},{},{}",
                gbps(payload_size, quicp_median),
                gbps(payload_size, tcp_median),
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn quantile(samples: &[u128], percentile: usize) -> u128 {
    assert_ne!(samples.len(), 0);
    assert!(percentile > 0 && percentile <= 100);
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = (sorted.len() * percentile).div_ceil(100).saturating_sub(1);
    sorted[rank]
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
    nodelay: bool,
    congestion: &str,
) -> io::Result<u128> {
    let tuple = bench_tuple(sample);
    let (_secret_directory, carrier) = benchmark_carrier()?;
    let client = client_config(tuple, carrier.clone());
    let server = ServerConfig::insecure(
        vec![tuple.destination],
        carrier.with_packet_socket(packet_socket_enabled()),
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let options = transport_options(congestion)?;
    runtime.block_on(async move {
        tokio::time::timeout(
            DEADLINE,
            run_quicp(
                payload_size,
                iterations,
                tuple,
                client,
                server,
                nodelay,
                options,
            ),
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
    nodelay: bool,
    options: TransportOptions,
) -> io::Result<u128> {
    let server_endpoint =
        build_fake_tcp_server_endpoint_with_options(&server, &[tuple.reverse()], &options)
            .map_err(transport_error)?;
    let server_addr = server_endpoint.local_addr()?;
    let client_endpoint = build_fake_tcp_client_endpoint_with_options(&client, &[tuple], &options)
        .map_err(transport_error)?;

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
        let pending = accept_flow(&server_connection, true)
            .await
            .map_err(debug_io_error)?;
        pending.accept().await.map_err(debug_io_error)
    };
    let client_flow = async {
        let host = CanonicalHost::parse("example.com").map_err(debug_io_error)?;
        QuicpFlow::open(
            &client_connection,
            OpenRequest::new(host, std::num::NonZeroU16::new(443).expect("port")),
            true,
        )
        .await
        .map_err(debug_io_error)
    };
    let (mut server_flow, mut client_flow) = tokio::try_join!(server_flow, client_flow)?;
    client_flow.set_nodelay(nodelay);

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
fn transport_options(congestion: &str) -> io::Result<TransportOptions> {
    if congestion == "cubic" {
        return Ok(TransportOptions::default());
    }
    let mut registry = PluginRegistry::new();
    registry
        .register(QueqiaoPlugin::default())
        .map_err(|error| io::Error::other(error.to_string()))?;
    registry
        .build_transport_options()
        .map_err(|error| io::Error::other(error.to_string()))
}

#[cfg(target_os = "linux")]
fn client_config(tuple: FourTuple, carrier: CarrierConfig) -> ClientConfig {
    ClientConfig::insecure(
        Multipath::single(
            PathCandidate::new("primary", tuple.source.ip(), tuple.destination).unwrap(),
        )
        .unwrap(),
        carrier.with_packet_socket(packet_socket_enabled()),
    )
    .unwrap()
}

#[cfg(target_os = "linux")]
fn benchmark_carrier() -> io::Result<(tempfile::TempDir, CarrierConfig)> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is required for the bench"))?;
    let directory = tempfile::tempdir_in(home)?;
    let secret_path = directory.path().join("carrier-cookie.secret");
    fs::write(&secret_path, b"quicp benchmark cookie secret")?;
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))?;
    let carrier = CarrierConfig::new(SynDataPolicy::Cookie, secret_path, CongestionControl::Cubic)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    Ok((directory, carrier))
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
