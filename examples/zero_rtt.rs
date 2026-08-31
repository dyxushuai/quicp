//! Replay-safe application 0-RTT with an ordinary fallback.

mod support;

use std::num::NonZeroU16;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use quicp::{
    ApplicationError, CanonicalHost, Client, Connection, OpenRequest, ReplayAdmission, ReplayToken,
    Server,
};

const INITIAL: &[u8] = b"idempotent early request";

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (runtime, client_io, server_io) = support::new_host_pair()?;
    let client = Arc::new(Client::from_host_socket(
        &support::client_config()?,
        client_io.clone(),
        Arc::clone(&runtime),
    )?);
    let server = Arc::new(Server::from_host_socket(
        &support::server_config()?,
        server_io.clone(),
        Arc::clone(&runtime),
    )?);
    let admission = Arc::new(ReplayAdmission::new(&[0x5a; 32], 7, 64)?);
    let token = Arc::new(Mutex::new(None::<ReplayToken>));
    let first_client = Arc::new(Mutex::new(None::<Connection>));

    let server_task = Arc::clone(&server);
    let admission_task = Arc::clone(&admission);
    let token_task = Arc::clone(&token);
    runtime.spawn(Box::pin(async move {
        let connection = server_task
            .accept()
            .await
            .expect("first accept")
            .handshake()
            .await
            .expect("first handshake");
        let pending = connection.accept_flow(true).await.expect("prime accept");
        assert_eq!(pending.request().host.as_str(), "prime.example");
        drop(pending.accept().await.expect("prime admission"));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_secs();
        let issued = connection
            .issue_replay_token(&admission_task, now, 60)
            .expect("issue replay token");
        *token_task.lock().unwrap_or_else(PoisonError::into_inner) = Some(issued);
    }))?;
    let client_task = Arc::clone(&client);
    let first_client_task = Arc::clone(&first_client);
    runtime.spawn(Box::pin(async move {
        let connection = client_task.connect().await.expect("first connect");
        let prime = OpenRequest::new(
            CanonicalHost::parse("prime.example").expect("prime host"),
            NonZeroU16::new(443).expect("nonzero port"),
        );
        drop(connection.open_flow(prime, true).await.expect("prime flow"));
        *first_client_task
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(connection);
    }))?;
    let elapsed = support::drive_until_from(&runtime, &client_io, &server_io, 0, || {
        token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
            && first_client
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_some()
    })?;
    if let Some(connection) = first_client
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    {
        connection.close(ApplicationError::FlowAbort, b"resume with replay-safe flow");
    }

    let token = token
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .expect("issued token");
    let request = OpenRequest::new(
        CanonicalHost::parse("early.example")?,
        NonZeroU16::new(443).expect("nonzero port"),
    );
    let server_status = Arc::new(AtomicU8::new(0));
    let client_status = Arc::new(AtomicU8::new(0));
    let server_task = Arc::clone(&server);
    let admission_task = Arc::clone(&admission);
    let status_task = Arc::clone(&server_status);
    runtime.spawn(Box::pin(async move {
        let result = async {
            let connection = server_task.accept().await?.accept_replay_safe()?;
            let pending = connection
                .accept_replay_safe_flow(&admission_task, true)
                .await?;
            if pending.initial_data() != INITIAL {
                return Err("unexpected initial bytes".into());
            }
            let mut flow = pending.accept().await?;
            let mut received = [0; INITIAL.len()];
            support::read_exact(&mut flow, &mut received).await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        status_task.store(if result.is_ok() { 1 } else { 2 }, Ordering::Release);
    }))?;
    let client_task = Arc::clone(&client);
    let status_task = Arc::clone(&client_status);
    runtime.spawn(Box::pin(async move {
        let result = client_task
            .connect_replay_safe(&token, 9, request, INITIAL, true)
            .await;
        status_task.store(if result.is_ok() { 1 } else { 2 }, Ordering::Release);
    }))?;
    support::drive_until_from(&runtime, &client_io, &server_io, elapsed + 1, || {
        server_status.load(Ordering::Acquire) != 0 && client_status.load(Ordering::Acquire) != 0
    })?;
    runtime.shutdown()?;
    if server_status.load(Ordering::Acquire) != 1 || client_status.load(Ordering::Acquire) != 1 {
        return Err("replay-safe flow failed".into());
    }
    println!(
        "replay-safe initial delivery succeeded: {} bytes",
        INITIAL.len()
    );
    Ok(())
}
