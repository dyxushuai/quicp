#![allow(dead_code)]

use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use quicp::{
    CarrierConfig, ClientConfig, HostDatagramError, HostDatagramSocket, HostRuntime, Multipath,
    PathCandidate, QuicpFlow, ServerConfig,
};

pub const CLIENT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19_000);
pub const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19_001);

pub fn client_config() -> Result<ClientConfig, quicp::ConfigError> {
    ClientConfig::insecure(
        Multipath::single(PathCandidate::new(CLIENT.ip(), SERVER)?)?,
        CarrierConfig::default(),
    )
}

pub fn server_config() -> Result<ServerConfig, quicp::ConfigError> {
    ServerConfig::insecure(vec![SERVER], CarrierConfig::default())
}

pub fn pump(
    from: &HostDatagramSocket,
    to: &HostDatagramSocket,
) -> Result<usize, HostDatagramError> {
    let mut packet = [0u8; 1500];
    let mut moved = 0;
    while let Some(length) = from.poll_egress_datagram_into(&mut packet)? {
        to.ingress_datagram_from(from.local_addr(), &packet[..length])?;
        moved += 1;
    }
    Ok(moved)
}

pub fn drive_until(
    runtime: &HostRuntime,
    client_io: &HostDatagramSocket,
    server_io: &HostDatagramSocket,
    done: impl FnMut() -> bool,
) -> Result<(), Box<dyn std::error::Error>> {
    drive_until_from(runtime, client_io, server_io, 0, done).map(|_| ())
}

pub fn drive_until_from(
    runtime: &HostRuntime,
    client_io: &HostDatagramSocket,
    server_io: &HostDatagramSocket,
    start_millis: u64,
    mut done: impl FnMut() -> bool,
) -> Result<u64, Box<dyn std::error::Error>> {
    for tick in start_millis..=start_millis.saturating_add(4_000) {
        pump(client_io, server_io)?;
        pump(server_io, client_io)?;
        runtime.drive(
            Duration::from_millis(tick),
            NonZeroUsize::new(256).expect("nonzero task budget"),
        )?;
        pump(client_io, server_io)?;
        pump(server_io, client_io)?;
        if done() {
            return Ok(tick);
        }
    }
    Err("host event loop did not complete within four seconds".into())
}

pub async fn write_all(flow: &mut QuicpFlow, payload: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < payload.len() {
        let written =
            poll_fn(|cx| QuicpFlow::poll_write(Pin::new(&mut *flow), cx, &payload[offset..]))
                .await?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "QUICP flow accepted no bytes",
            ));
        }
        offset += written;
    }
    poll_fn(|cx| QuicpFlow::poll_flush(Pin::new(&mut *flow), cx)).await
}

pub async fn shutdown(flow: &mut QuicpFlow) -> io::Result<()> {
    poll_fn(|cx| QuicpFlow::poll_shutdown(Pin::new(&mut *flow), cx)).await
}

pub async fn read_exact(flow: &mut QuicpFlow, output: &mut [u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < output.len() {
        let read =
            poll_fn(|cx| QuicpFlow::poll_read(Pin::new(&mut *flow), cx, &mut output[offset..]))
                .await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "QUICP flow closed before the message completed",
            ));
        }
        offset += read;
    }
    Ok(())
}

pub fn new_host_pair()
-> Result<(Arc<HostRuntime>, HostDatagramSocket, HostDatagramSocket), HostDatagramError> {
    let runtime = Arc::new(HostRuntime::new());
    let client_io = HostDatagramSocket::new(CLIENT, SERVER, 64, 1500)?;
    let server_io = HostDatagramSocket::new(SERVER, CLIENT, 64, 1500)?;
    Ok((runtime, client_io, server_io))
}
