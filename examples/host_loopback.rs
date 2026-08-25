//! Runtime-neutral QUICP loopback using caller-owned datagram queues.
//!
//! This is the smallest complete host event-loop example. A mobile packet loop can replace
//! `pump` with its underlay read/write calls and keep the same `HostRuntime::drive` contract.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use quicp::config::{CarrierConfig, ClientConfig, Multipath, PathCandidate, ServerConfig};
use quicp::{
    Client, HeaderProtectionFactory, HeaderProtectionKeys, HeaderProtectionSide, HostDatagramError,
    HostDatagramSocket, HostRuntime, PluginRegistry, QueqiaoPlugin, QuicpHeaderProtector, Server,
};

const CLIENT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19_000);
const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19_001);

#[derive(Debug)]
struct ProbeProtector;

impl QuicpHeaderProtector for ProbeProtector {
    fn decrypt(&self, _packet_number_offset: usize, _packet: &mut [u8]) {}

    fn encrypt(&self, _packet_number_offset: usize, _packet: &mut [u8]) {}

    fn sample_size(&self) -> usize {
        1
    }
}

#[derive(Debug)]
struct ProbeHeaderFactory;

impl HeaderProtectionFactory for ProbeHeaderFactory {
    fn build(&self, _side: HeaderProtectionSide) -> HeaderProtectionKeys {
        HeaderProtectionKeys::new(Arc::new(ProbeProtector), Arc::new(ProbeProtector))
    }
}

fn client_config() -> ClientConfig {
    ClientConfig::insecure(
        Multipath::single(PathCandidate::new("host", CLIENT.ip(), SERVER).unwrap()).unwrap(),
        CarrierConfig::default(),
    )
    .unwrap()
}

fn server_config() -> ServerConfig {
    ServerConfig::insecure(vec![SERVER], CarrierConfig::default()).unwrap()
}

fn pump(from: &HostDatagramSocket, to: &HostDatagramSocket) -> Result<usize, HostDatagramError> {
    let mut packet = [0u8; 1500];
    let mut moved = 0;
    while let Some(len) = from.poll_egress_datagram_into(&mut packet)? {
        to.ingress_datagram_from(from.local_addr(), &packet[..len])?;
        moved += 1;
    }
    Ok(moved)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Arc::new(HostRuntime::new());
    let client_io = HostDatagramSocket::new(CLIENT, SERVER, 64, 1500)?;
    let server_io = HostDatagramSocket::new(SERVER, CLIENT, 64, 1500)?;

    let mut plugins = PluginRegistry::new();
    plugins.register(QueqiaoPlugin::default())?;
    let options = plugins
        .build_transport_options()?
        .with_header_protection_factory(Arc::new(ProbeHeaderFactory));

    let client = Client::from_host_socket_with_options(
        &client_config(),
        client_io.clone(),
        runtime.clone(),
        &options,
    )?;
    let server = Server::from_host_socket_with_options(
        &server_config(),
        server_io.clone(),
        runtime.clone(),
        &options,
    )?;
    let client_status = Arc::new(AtomicU8::new(0));
    let server_status = Arc::new(AtomicU8::new(0));

    let server_status_task = Arc::clone(&server_status);
    runtime
        .spawn(Box::pin(async move {
            let result = async {
                let incoming = server.accept().await?;
                incoming.handshake().await
            }
            .await;
            server_status_task.store(u8::from(result.is_err()) + 1, Ordering::Release);
        }))
        .expect("spawn server task");
    let client_status_task = Arc::clone(&client_status);
    runtime
        .spawn(Box::pin(async move {
            let result = client.connect().await;
            client_status_task.store(u8::from(result.is_err()) + 1, Ordering::Release);
        }))
        .expect("spawn client task");

    for tick in 0..4_000u64 {
        pump(&client_io, &server_io)?;
        pump(&server_io, &client_io)?;
        runtime.drive(
            Duration::from_millis(tick),
            NonZeroUsize::new(256).expect("nonzero task budget"),
        )?;
        if client_status.load(Ordering::Acquire) != 0 && server_status.load(Ordering::Acquire) != 0
        {
            break;
        }
    }
    let connected =
        client_status.load(Ordering::Acquire) == 1 && server_status.load(Ordering::Acquire) == 1;
    runtime.shutdown()?;
    if !connected {
        return Err("host loopback handshake did not complete".into());
    }
    println!("QUICP host loopback handshake succeeded");
    Ok(())
}
