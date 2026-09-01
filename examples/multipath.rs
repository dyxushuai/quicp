//! A runtime-neutral QUICP flow surviving primary underlay failure.

mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use quicp::{
    CanonicalHost, CarrierConfig, Client, Connection, HostDatagramSocket, HostRuntime, Multipath,
    OpenRequest, PathCandidate, QuicpFlow, Server, ServerConfig,
};

const MESSAGE: &[u8] = b"same flow on the backup path";

fn address(host: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, host)), port)
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client_addrs = [address(1, 20_000), address(3, 20_002)];
    let server_addrs = [address(2, 20_001), address(4, 20_003)];
    let client_paths = [
        HostDatagramSocket::new(client_addrs[0], server_addrs[0], 64, 1500)?,
        HostDatagramSocket::new(client_addrs[1], server_addrs[1], 64, 1500)?,
    ];
    let server_paths = [
        HostDatagramSocket::new(server_addrs[0], client_addrs[0], 64, 1500)?,
        HostDatagramSocket::new(server_addrs[1], client_addrs[1], 64, 1500)?,
    ];
    let runtime = Arc::new(HostRuntime::new());
    let client_config = quicp::ClientConfig::insecure(
        Multipath::failover(
            PathCandidate::new(client_addrs[0].ip(), server_addrs[0])?,
            PathCandidate::new(client_addrs[1].ip(), server_addrs[1])?,
        )?,
        CarrierConfig::default(),
    )?;
    let server_config = ServerConfig::insecure(server_addrs.to_vec(), CarrierConfig::default())?;
    let client = Client::from_host_sockets(&client_config, &client_paths, Arc::clone(&runtime))?;
    let server = Server::from_host_sockets(&server_config, &server_paths, Arc::clone(&runtime))?;
    let connection = Arc::new(Mutex::new(None::<Connection>));
    let flow = Arc::new(Mutex::new(None::<QuicpFlow>));
    let server_waiting = Arc::new(AtomicBool::new(false));
    let delivered = Arc::new(AtomicBool::new(false));

    let connection_task = Arc::clone(&connection);
    let flow_task = Arc::clone(&flow);
    runtime.spawn(Box::pin(async move {
        let connection = client.connect().await.expect("multipath connect");
        let request = OpenRequest::new(
            CanonicalHost::parse("multipath.example").expect("canonical host"),
            NonZeroU16::new(443).expect("nonzero port"),
        );
        let opened = connection
            .open_flow(request, true)
            .await
            .expect("open flow");
        *connection_task
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(connection);
        *flow_task.lock().unwrap_or_else(PoisonError::into_inner) = Some(opened);
    }))?;

    let server_waiting_task = Arc::clone(&server_waiting);
    let delivered_task = Arc::clone(&delivered);
    runtime.spawn(Box::pin(async move {
        let connection = server
            .accept()
            .await
            .expect("accept")
            .handshake()
            .await
            .expect("handshake");
        let mut flow = connection
            .accept_flow(true)
            .await
            .expect("accept flow")
            .accept()
            .await
            .expect("admit flow");
        server_waiting_task.store(true, Ordering::Release);
        let mut received = [0; MESSAGE.len()];
        support::read_exact(&mut flow, &mut received)
            .await
            .expect("read after failover");
        assert_eq!(&received, MESSAGE);
        delivered_task.store(true, Ordering::Release);
    }))?;

    let mut tick = drive_until(&runtime, &client_paths, &server_paths, 0, true, || {
        server_waiting.load(Ordering::Acquire)
            && flow
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_some()
            && connection
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .is_some_and(Connection::backup_ready)
    })?;
    client_paths[0].mark_unavailable();
    server_paths[0].mark_unavailable();

    let mut flow = flow
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .expect("client flow");
    runtime.spawn(Box::pin(async move {
        support::write_all(&mut flow, MESSAGE)
            .await
            .expect("write after failover");
        support::shutdown(&mut flow)
            .await
            .expect("shutdown after failover");
    }))?;
    tick = drive_until(
        &runtime,
        &client_paths,
        &server_paths,
        tick + 1,
        false,
        || delivered.load(Ordering::Acquire),
    )?;
    runtime.shutdown()?;
    println!("multipath failover succeeded at host tick {tick} ms");
    Ok(())
}

fn drive_until(
    runtime: &HostRuntime,
    client: &[HostDatagramSocket; 2],
    server: &[HostDatagramSocket; 2],
    start: u64,
    primary: bool,
    mut done: impl FnMut() -> bool,
) -> Result<u64, Box<dyn std::error::Error>> {
    for tick in start..=start + 20_000 {
        for path in usize::from(!primary)..2 {
            support::pump(&client[path], &server[path])?;
            support::pump(&server[path], &client[path])?;
        }
        runtime.drive(
            Duration::from_millis(tick),
            NonZeroUsize::new(256).expect("nonzero budget"),
        )?;
        if done() {
            return Ok(tick);
        }
    }
    Err("multipath example timed out".into())
}
