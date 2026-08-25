//! A complete runtime-neutral QUICP echo flow.
//!
//! The host owns both datagram queues in this loopback example. Replace [`support::pump`] with
//! the platform underlay read/write calls in a real integration; the flow code stays unchanged.

mod support;

use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use quicp::{CanonicalHost, Client, OpenRequest, Server};

const MESSAGE: &[u8] = b"hello from quicp";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (runtime, client_io, server_io) = support::new_host_pair()?;
    let client = Client::from_host_socket(
        &support::client_config()?,
        client_io.clone(),
        Arc::clone(&runtime),
    )?;
    let server = Server::from_host_socket(
        &support::server_config()?,
        server_io.clone(),
        runtime.clone(),
    )?;
    let client_status = Arc::new(AtomicU8::new(0));
    let server_status = Arc::new(AtomicU8::new(0));

    let server_status_task = Arc::clone(&server_status);
    runtime.spawn(Box::pin(async move {
        let result = async {
            let incoming = server
                .accept()
                .await
                .map_err(|error| format!("accept: {error}"))?;
            let connection = incoming
                .handshake()
                .await
                .map_err(|error| format!("handshake: {error}"))?;
            let pending = connection
                .accept_flow(true)
                .await
                .map_err(|error| format!("accept flow: {error}"))?;
            let mut flow = pending
                .accept()
                .await
                .map_err(|error| format!("accept pending flow: {error}"))?;
            drop(connection);
            let mut received = [0; MESSAGE.len()];
            support::read_exact(&mut flow, &mut received)
                .await
                .map_err(|error| format!("server read: {error}"))?;
            if received != MESSAGE {
                return Err("echo server received an unexpected message".to_owned());
            }
            support::write_all(&mut flow, &received)
                .await
                .map_err(|error| format!("server write: {error}"))?;
            server_status_task.store(1, Ordering::Release);
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok::<(), String>(())
        }
        .await;
        if let Err(error) = result {
            eprintln!("echo server: {error}");
            server_status_task.store(2, Ordering::Release);
        }
    }))?;

    let client_status_task = Arc::clone(&client_status);
    runtime.spawn(Box::pin(async move {
        let result = async {
            let connection = client
                .connect()
                .await
                .map_err(|error| format!("connect: {error}"))?;
            let request = OpenRequest::new(
                CanonicalHost::parse("echo.example").map_err(|error| format!("host: {error}"))?,
                NonZeroU16::new(7).expect("nonzero echo port"),
            );
            let mut flow = connection
                .open_flow(request, true)
                .await
                .map_err(|error| format!("open flow: {error}"))?;
            drop(connection);
            support::write_all(&mut flow, MESSAGE)
                .await
                .map_err(|error| format!("client write: {error}"))?;
            let mut reply = [0; MESSAGE.len()];
            support::read_exact(&mut flow, &mut reply)
                .await
                .map_err(|error| format!("client read: {error}"))?;
            if reply != MESSAGE {
                return Err("echo client received an unexpected reply".to_owned());
            }
            Ok::<(), String>(())
        }
        .await;
        let failed = result.is_err();
        if let Err(error) = result {
            eprintln!("echo client: {error}");
        }
        client_status_task.store(u8::from(failed) + 1, Ordering::Release);
    }))?;

    support::drive_until(&runtime, &client_io, &server_io, || {
        client_status.load(Ordering::Acquire) != 0 && server_status.load(Ordering::Acquire) != 0
    })?;
    let succeeded =
        client_status.load(Ordering::Acquire) == 1 && server_status.load(Ordering::Acquire) == 1;
    runtime.shutdown()?;
    if !succeeded {
        return Err("QUICP echo failed".into());
    }
    println!("QUICP echo succeeded: {} bytes", MESSAGE.len());
    Ok(())
}
