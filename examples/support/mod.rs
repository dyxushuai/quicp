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
        Multipath::single(PathCandidate::new("host", CLIENT.ip(), SERVER)?)?,
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

#[allow(dead_code)]
pub fn drive_until(
    runtime: &HostRuntime,
    client_io: &HostDatagramSocket,
    server_io: &HostDatagramSocket,
    mut done: impl FnMut() -> bool,
) -> Result<(), Box<dyn std::error::Error>> {
    for tick in 0..=4_000u64 {
        pump(client_io, server_io)?;
        pump(server_io, client_io)?;
        runtime.drive(
            Duration::from_millis(tick),
            NonZeroUsize::new(256).expect("nonzero task budget"),
        )?;
        pump(client_io, server_io)?;
        pump(server_io, client_io)?;
        if done() {
            return Ok(());
        }
    }
    Err("host event loop did not complete within four seconds".into())
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
