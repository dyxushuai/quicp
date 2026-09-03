#![allow(unsafe_code)]

use quicp::ffi::{
    ABI_VERSION, FfiBytes, FfiEngine, FfiEngineConfig, FfiPathConfig, FfiRecoveryMode,
    FfiRecoverySnapshot, FfiRole, FfiSocketAddress, FfiStatus, FfiTlsConfig, MAX_ENGINE_HOST_BYTES,
    quicp_engine_accept_pending_flow, quicp_engine_close, quicp_engine_configure_replay_admission,
    quicp_engine_connection_state, quicp_engine_create, quicp_engine_create_tls,
    quicp_engine_drive, quicp_engine_egress, quicp_engine_ingress, quicp_engine_issue_replay_token,
    quicp_engine_open_flow, quicp_engine_open_replay_safe_flow, quicp_engine_path_unavailable,
    quicp_engine_poll_flow_request, quicp_engine_poll_replay_safe_flow_request,
    quicp_engine_recovery_snapshot, quicp_engine_reject_pending_flow, quicp_flow_close,
    quicp_flow_flush, quicp_flow_read, quicp_flow_shutdown, quicp_flow_write,
};

#[repr(C, align(8))]
struct AlignedConfig(FfiEngineConfig);

fn address(port: u16) -> FfiSocketAddress {
    address_on(1, port)
}

fn address_on(host: u8, port: u16) -> FfiSocketAddress {
    let mut address = [0; 16];
    address[..4].copy_from_slice(&[127, 0, 0, host]);
    FfiSocketAddress {
        family: 4,
        port,
        reserved: 0,
        address,
    }
}

fn config(role: FfiRole, local: u16, peer: u16) -> FfiEngineConfig {
    FfiEngineConfig {
        abi_version: ABI_VERSION,
        role: role as u32,
        path_count: 1,
        paths: [
            FfiPathConfig {
                local: address(local),
                peer: address(peer),
            },
            FfiPathConfig::default(),
        ],
        packet_capacity: 64,
        mtu: 1500,
        recovery_mode: FfiRecoveryMode::Adaptive as u32,
    }
}

fn multipath_config(role: FfiRole, local: [(u8, u16); 2], peer: [(u8, u16); 2]) -> FfiEngineConfig {
    FfiEngineConfig {
        abi_version: ABI_VERSION,
        role: role as u32,
        path_count: 2,
        paths: [
            FfiPathConfig {
                local: address_on(local[0].0, local[0].1),
                peer: address_on(peer[0].0, peer[0].1),
            },
            FfiPathConfig {
                local: address_on(local[1].0, local[1].1),
                peer: address_on(peer[1].0, peer[1].1),
            },
        ],
        packet_capacity: 64,
        mtu: 1500,
        recovery_mode: FfiRecoveryMode::Adaptive as u32,
    }
}

#[test]
fn engine_rejects_abi_mismatch_before_creation() {
    let mut invalid = config(FfiRole::Client, 40_000, 40_001);
    invalid.abi_version = ABI_VERSION - 1;
    let mut engine: *mut FfiEngine = std::ptr::dangling_mut();

    assert_eq!(
        unsafe { quicp_engine_create(&raw const invalid, &raw mut engine) },
        FfiStatus::InvalidArgument
    );
    assert!(engine.is_null());
}

#[test]
fn engine_rejects_invalid_create_pointers() {
    let valid = config(FfiRole::Client, 40_010, 40_011);
    let mut engine: *mut FfiEngine = std::ptr::dangling_mut();

    assert_eq!(
        unsafe { quicp_engine_create(std::ptr::null(), &raw mut engine) },
        FfiStatus::InvalidArgument
    );
    assert_eq!(
        unsafe { quicp_engine_create(&raw const valid, std::ptr::null_mut()) },
        FfiStatus::InvalidArgument
    );
    assert_eq!(
        unsafe {
            quicp_engine_create(
                std::ptr::without_provenance::<FfiEngineConfig>(1),
                &raw mut engine,
            )
        },
        FfiStatus::InvalidArgument
    );

    let mut overlapping = AlignedConfig(valid);
    let config_pointer = std::ptr::from_ref(&overlapping.0);
    let output_pointer = std::ptr::from_mut(&mut overlapping).cast::<*mut FfiEngine>();
    assert_eq!(
        unsafe { quicp_engine_create(config_pointer, output_pointer) },
        FfiStatus::InvalidArgument
    );
}

#[test]
fn engine_rejects_unbounded_queue_configuration() {
    let mut invalid_role = config(FfiRole::Client, 40_000, 40_001);
    invalid_role.role = u32::MAX;
    let mut invalid_capacity = config(FfiRole::Client, 40_000, 40_001);
    invalid_capacity.packet_capacity = u32::MAX;
    let mut invalid_mtu = config(FfiRole::Client, 40_000, 40_001);
    invalid_mtu.mtu = u32::MAX;
    let mut excessive_bytes = config(FfiRole::Client, 40_000, 40_001);
    excessive_bytes.packet_capacity = 4096;
    excessive_bytes.mtu = 65_527;
    let mut invalid_recovery = config(FfiRole::Client, 40_000, 40_001);
    invalid_recovery.recovery_mode = u32::MAX;

    for invalid in [
        invalid_role,
        invalid_capacity,
        invalid_mtu,
        excessive_bytes,
        invalid_recovery,
    ] {
        let mut engine: *mut FfiEngine = std::ptr::dangling_mut();
        // SAFETY: The config and output pointer are live for the complete call.
        assert_eq!(
            unsafe { quicp_engine_create(&raw const invalid, &raw mut engine) },
            FfiStatus::InvalidArgument
        );
        assert!(engine.is_null());
    }
}

unsafe fn create(config: &FfiEngineConfig) -> *mut FfiEngine {
    let mut engine = std::ptr::null_mut();
    // SAFETY: The config and output pointer are live for the complete call.
    assert_eq!(
        unsafe { quicp_engine_create(config, &raw mut engine) },
        FfiStatus::Ok
    );
    engine
}

#[test]
fn engine_rejects_decreasing_time_without_poisoning_drive() {
    unsafe {
        let mut engine = create(&config(FfiRole::Client, 40_020, 40_021));
        let mut processed = 0;
        assert_eq!(
            quicp_engine_drive(engine, 10, 32, &raw mut processed),
            FfiStatus::Ok
        );
        assert_eq!(
            quicp_engine_drive(engine, 9, 32, &raw mut processed),
            FfiStatus::InvalidArgument
        );
        assert_eq!(
            quicp_engine_drive(engine, 11, 32, &raw mut processed),
            FfiStatus::Ok
        );
        assert_eq!(quicp_engine_close(&raw mut engine), FfiStatus::Ok);
        assert!(engine.is_null());
        assert_eq!(quicp_engine_close(&raw mut engine), FfiStatus::Closed);
    }
}

#[test]
fn engine_egress_buffer_too_small_preserves_datagram() {
    unsafe {
        let mut engine = create(&config(FfiRole::Client, 40_030, 40_031));
        let mut required = 0;
        let mut byte = 0;
        for elapsed in (0..32).map(|tick| tick * 1_000_000) {
            let mut processed = 0;
            assert_eq!(
                quicp_engine_drive(engine, elapsed, 256, &raw mut processed),
                FfiStatus::Ok
            );
            match quicp_engine_egress(engine, 0, &raw mut byte, 1, &raw mut required) {
                FfiStatus::WouldBlock => {}
                FfiStatus::BufferTooSmall => break,
                status => panic!("unexpected egress status: {status:?}"),
            }
        }
        assert!(required > 1);
        let mut packet = vec![0; required as usize];
        let mut length = 0;
        assert_eq!(
            quicp_engine_egress(
                engine,
                0,
                packet.as_mut_ptr(),
                u32::try_from(packet.len()).unwrap(),
                &raw mut length,
            ),
            FfiStatus::Ok
        );
        assert_eq!(length, required);
        assert_eq!(quicp_engine_close(&raw mut engine), FfiStatus::Ok);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn synchronous_engine_resumes_same_flow_bytes_after_backpressure() {
    // SAFETY: This test preserves exclusive ownership of both opaque engine pointers.
    unsafe {
        let mut client = create(&config(FfiRole::Client, 40_040, 40_041));
        let mut server = create(&config(FfiRole::Server, 40_041, 40_040));
        let mut elapsed = 0;
        for _ in 0..6_000 {
            progress(client, server, elapsed);
            elapsed += 1_000_000;
            if quicp_engine_connection_state(client) == FfiStatus::Ok
                && quicp_engine_connection_state(server) == FfiStatus::Ok
            {
                break;
            }
        }
        assert_eq!(quicp_engine_connection_state(client), FfiStatus::Ok);
        assert_eq!(quicp_engine_connection_state(server), FfiStatus::Ok);

        let host = b"backpressure.example";
        let mut client_flow = 0;
        let mut server_flow = 0;
        let mut server_request = 0;
        for _ in 0..1_000 {
            let _ = quicp_engine_open_flow(
                client,
                host.as_ptr(),
                u32::try_from(host.len()).unwrap(),
                443,
                &raw mut client_flow,
            );
            if server_flow == 0 {
                let _ = accept_request(server, false, &mut server_request, &mut server_flow);
            }
            progress(client, server, elapsed);
            elapsed += 1_000_000;
            if client_flow != 0 && server_flow != 0 {
                break;
            }
        }
        assert_ne!(client_flow, 0);
        assert_ne!(server_flow, 0);

        let payload: Vec<u8> = (0..384 * 1024)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        let mut accepted = 0;
        let mut blocked = false;
        for _ in 0..32 {
            let mut written = 0;
            match quicp_flow_write(
                client,
                client_flow,
                payload[accepted..].as_ptr(),
                u32::try_from(payload.len() - accepted).unwrap(),
                &raw mut written,
            ) {
                FfiStatus::Ok => {
                    assert_ne!(written, 0);
                    accepted += written as usize;
                }
                FfiStatus::WouldBlock => {
                    assert_eq!(written, 0);
                    blocked = true;
                    break;
                }
                status => panic!("write before progress failed: {status:?}"),
            }
        }
        assert!(blocked, "replay capacity never applied backpressure");
        assert!(accepted < payload.len());

        let mut received = Vec::with_capacity(payload.len());
        let mut output = [0; 16 * 1024];
        for _ in 0..10_000 {
            let flush = quicp_flow_flush(client, client_flow);
            assert!(matches!(flush, FfiStatus::Ok | FfiStatus::WouldBlock));
            progress(client, server, elapsed);
            elapsed += 1_000_000;

            loop {
                let mut read = 0;
                match quicp_flow_read(
                    server,
                    server_flow,
                    output.as_mut_ptr(),
                    u32::try_from(output.len()).unwrap(),
                    &raw mut read,
                ) {
                    FfiStatus::Ok => {
                        assert_ne!(read, 0);
                        received.extend_from_slice(&output[..read as usize]);
                    }
                    FfiStatus::WouldBlock => break,
                    status => panic!("read after progress failed: {status:?}"),
                }
            }

            if accepted < payload.len() {
                let mut written = 0;
                match quicp_flow_write(
                    client,
                    client_flow,
                    payload[accepted..].as_ptr(),
                    u32::try_from(payload.len() - accepted).unwrap(),
                    &raw mut written,
                ) {
                    FfiStatus::Ok => {
                        assert_ne!(written, 0);
                        accepted += written as usize;
                    }
                    FfiStatus::WouldBlock => assert_eq!(written, 0),
                    status => panic!("resumed write failed: {status:?}"),
                }
            }
            if accepted == payload.len() && received.len() == payload.len() {
                break;
            }
        }

        assert_eq!(accepted, payload.len());
        assert_eq!(received, payload);
        assert_eq!(quicp_flow_close(client, client_flow), FfiStatus::Ok);
        assert_eq!(quicp_flow_close(server, server_flow), FfiStatus::Ok);
        assert_eq!(quicp_engine_close(&raw mut client), FfiStatus::Ok);
        assert_eq!(quicp_engine_close(&raw mut server), FfiStatus::Ok);
    }
}

fn ffi_bytes(bytes: &[u8]) -> FfiBytes {
    FfiBytes {
        data: bytes.as_ptr(),
        length: u32::try_from(bytes.len()).unwrap(),
    }
}

#[cfg(not(feature = "tls-rustls"))]
#[test]
fn tls_entry_point_fails_closed_when_feature_is_disabled() {
    let config = config(FfiRole::Client, 42_000, 42_001);
    let path = b"/unused.pem";
    let tls = FfiTlsConfig {
        server_name: ffi_bytes(b"server.example"),
        ca_certificate: ffi_bytes(path),
        certificate: ffi_bytes(path),
        private_key: ffi_bytes(path),
    };
    let mut engine: *mut FfiEngine = std::ptr::dangling_mut();

    // SAFETY: Config, TLS strings, and output remain live for the complete call.
    assert_eq!(
        unsafe { quicp_engine_create_tls(&raw const config, &raw const tls, &raw mut engine,) },
        FfiStatus::InvalidArgument
    );
    assert!(engine.is_null());
}

#[cfg(feature = "tls-rustls")]
unsafe fn create_tls(config: &FfiEngineConfig, tls: &FfiTlsConfig) -> *mut FfiEngine {
    let mut engine = std::ptr::null_mut();
    // SAFETY: Config, TLS strings, and output remain live for the complete call.
    assert_eq!(
        unsafe { quicp_engine_create_tls(config, tls, &raw mut engine) },
        FfiStatus::Ok
    );
    engine
}

unsafe fn pump(from: *mut FfiEngine, to: *mut FfiEngine, path: u32, deliver: bool) -> usize {
    let mut moved = 0;
    loop {
        let mut packet = [0; 2048];
        let mut length = 0;
        // SAFETY: Both engines and buffers remain live and calls are serialized.
        match unsafe { quicp_engine_egress(from, path, packet.as_mut_ptr(), 2048, &raw mut length) }
        {
            FfiStatus::Ok if deliver => {
                assert_eq!(
                    unsafe { quicp_engine_ingress(to, path, packet.as_ptr(), length) },
                    FfiStatus::Ok
                );
                moved += 1;
            }
            FfiStatus::Ok => moved += 1,
            FfiStatus::WouldBlock => break,
            status => panic!("egress failed: {status:?}"),
        }
    }
    moved
}

unsafe fn progress(client: *mut FfiEngine, server: *mut FfiEngine, elapsed: u64) {
    let _ = unsafe { progress_paths(client, server, elapsed, 1, true) };
}

unsafe fn accept_request(
    server: *mut FfiEngine,
    replay: bool,
    request: &mut u64,
    flow: &mut u64,
) -> FfiStatus {
    if *request != 0 {
        let status = unsafe { quicp_engine_accept_pending_flow(server, *request, flow) };
        if status != FfiStatus::WouldBlock {
            *request = 0;
        }
        return status;
    }
    let mut host = [0; MAX_ENGINE_HOST_BYTES];
    let mut host_length = 0;
    let mut port = 0;
    let mut initial = vec![0; 32 * 1024];
    let mut initial_length = 0;
    let status = if replay {
        unsafe {
            quicp_engine_poll_replay_safe_flow_request(
                server,
                request,
                host.as_mut_ptr(),
                u32::try_from(host.len()).unwrap(),
                &raw mut host_length,
                &raw mut port,
                initial.as_mut_ptr(),
                u32::try_from(initial.len()).unwrap(),
                &raw mut initial_length,
            )
        }
    } else {
        unsafe {
            quicp_engine_poll_flow_request(
                server,
                request,
                host.as_mut_ptr(),
                u32::try_from(host.len()).unwrap(),
                &raw mut host_length,
                &raw mut port,
                initial.as_mut_ptr(),
                u32::try_from(initial.len()).unwrap(),
                &raw mut initial_length,
            )
        }
    };
    if status == FfiStatus::Ok {
        assert_ne!(*request, 0);
        return unsafe { quicp_engine_accept_pending_flow(server, *request, flow) };
    }
    status
}

unsafe fn progress_paths(
    client: *mut FfiEngine,
    server: *mut FfiEngine,
    elapsed: u64,
    path_count: u32,
    primary: bool,
) -> usize {
    let mut processed = 0;
    for engine in [client, server] {
        // SAFETY: Engines and output remain live and calls are serialized.
        assert_eq!(
            unsafe { quicp_engine_drive(engine, elapsed, 256, &raw mut processed) },
            FfiStatus::Ok
        );
    }
    // SAFETY: Both engines are live and pumped one direction at a time.
    let mut backup_packets = 0;
    for path in 0..path_count {
        if path == 0 && !primary {
            continue;
        }
        let deliver = path != 0 || primary;
        unsafe {
            let moved = pump(client, server, path, deliver) + pump(server, client, path, deliver);
            if path != 0 {
                backup_packets += moved;
            }
        }
    }
    backup_packets
}

#[test]
#[allow(clippy::too_many_lines)]
fn synchronous_engine_connects_and_exchanges_flow_bytes() {
    // SAFETY: This test preserves exclusive ownership of both opaque engine pointers.
    unsafe {
        let mut client = create(&config(FfiRole::Client, 40_000, 40_001));
        let mut server = create(&config(FfiRole::Server, 40_001, 40_000));
        let mut elapsed = 0;
        for _ in 0..6_000 {
            progress(client, server, elapsed);
            elapsed += 1_000_000;
            if quicp_engine_connection_state(client) == FfiStatus::Ok
                && quicp_engine_connection_state(server) == FfiStatus::Ok
            {
                break;
            }
        }
        assert_eq!(quicp_engine_connection_state(client), FfiStatus::Ok);
        assert_eq!(quicp_engine_connection_state(server), FfiStatus::Ok);

        let host = b"ffi.example";
        let mut client_flow = 0;
        let mut server_flow = 0;
        let mut server_request = 0;
        for _ in 0..1_000 {
            let _ = quicp_engine_open_flow(
                client,
                host.as_ptr(),
                u32::try_from(host.len()).unwrap(),
                443,
                &raw mut client_flow,
            );
            if server_flow == 0 {
                let _ = accept_request(server, false, &mut server_request, &mut server_flow);
            }
            progress(client, server, elapsed);
            elapsed += 1_000_000;
            if client_flow != 0 && server_flow != 0 {
                break;
            }
        }
        assert_ne!(client_flow, 0);
        assert_ne!(server_flow, 0);
        assert_eq!(quicp_flow_flush(server, client_flow), FfiStatus::Closed);
        assert_eq!(quicp_flow_flush(client, server_flow), FfiStatus::Closed);

        let payload = b"QUICP through the C engine";
        let mut written = 0;
        assert_eq!(
            quicp_flow_write(
                client,
                client_flow,
                payload.as_ptr(),
                u32::try_from(payload.len()).unwrap(),
                &raw mut written,
            ),
            FfiStatus::Ok
        );
        assert_eq!(written as usize, payload.len());
        let mut received = [0; 64];
        let mut read = 0;
        for _ in 0..1_000 {
            let _ = quicp_flow_flush(client, client_flow);
            progress(client, server, elapsed);
            elapsed += 1_000_000;
            if quicp_flow_read(
                server,
                server_flow,
                received.as_mut_ptr(),
                u32::try_from(received.len()).unwrap(),
                &raw mut read,
            ) == FfiStatus::Ok
            {
                break;
            }
        }
        assert_eq!(&received[..read as usize], payload);
        for _ in 0..1_000 {
            let status = quicp_flow_shutdown(client, client_flow);
            progress(client, server, elapsed);
            elapsed += 1_000_000;
            if status == FfiStatus::Ok {
                break;
            }
            assert_eq!(status, FfiStatus::WouldBlock);
        }
        for _ in 0..1_000 {
            read = u32::MAX;
            progress(client, server, elapsed);
            elapsed += 1_000_000;
            if quicp_flow_read(
                server,
                server_flow,
                received.as_mut_ptr(),
                u32::try_from(received.len()).unwrap(),
                &raw mut read,
            ) == FfiStatus::Ok
                && read == 0
            {
                break;
            }
        }
        assert_eq!(read, 0);
        let mut aliased = [0_u32; 2];
        assert_eq!(
            quicp_flow_read(
                server,
                server_flow,
                aliased.as_mut_ptr().cast(),
                u32::try_from(std::mem::size_of_val(&aliased)).unwrap(),
                aliased.as_mut_ptr(),
            ),
            FfiStatus::InvalidArgument
        );
        let mut snapshot = FfiRecoverySnapshot::default();
        assert_eq!(
            quicp_engine_recovery_snapshot(client, &raw mut snapshot),
            FfiStatus::Ok
        );
        assert!(snapshot.source_sent > 0);
        assert_eq!(quicp_flow_close(client, client_flow), FfiStatus::Ok);
        assert_eq!(quicp_flow_close(client, client_flow), FfiStatus::Closed);

        let denied_host = b"denied.example";
        let mut denied_flow = 0;
        let mut denied_request = 0;
        let mut request_host = [0; MAX_ENGINE_HOST_BYTES];
        let mut request_host_length = 0;
        let mut request_port = 0;
        let mut request_initial = [0; 1];
        let mut request_initial_length = 0;
        let mut open_status = FfiStatus::WouldBlock;
        let mut reject_status = FfiStatus::WouldBlock;
        for _ in 0..1_000 {
            open_status = quicp_engine_open_flow(
                client,
                denied_host.as_ptr(),
                u32::try_from(denied_host.len()).unwrap(),
                443,
                &raw mut denied_flow,
            );
            if denied_request == 0 {
                let status = quicp_engine_poll_flow_request(
                    server,
                    &raw mut denied_request,
                    request_host.as_mut_ptr(),
                    u32::try_from(request_host.len()).unwrap(),
                    &raw mut request_host_length,
                    &raw mut request_port,
                    request_initial.as_mut_ptr(),
                    u32::try_from(request_initial.len()).unwrap(),
                    &raw mut request_initial_length,
                );
                assert!(matches!(status, FfiStatus::Ok | FfiStatus::WouldBlock));
                if status == FfiStatus::Ok {
                    assert_eq!(&request_host[..request_host_length as usize], denied_host);
                    assert_eq!(request_port, 443);
                    assert_eq!(request_initial_length, 0);
                }
            } else if reject_status != FfiStatus::Ok {
                reject_status = quicp_engine_reject_pending_flow(server, denied_request);
            }
            progress(client, server, elapsed);
            elapsed += 1_000_000;
            if open_status == FfiStatus::Failed && reject_status == FfiStatus::Ok {
                break;
            }
        }
        assert_eq!(reject_status, FfiStatus::Ok);
        assert_eq!(open_status, FfiStatus::Failed);
        assert_eq!(denied_flow, 0);

        assert_eq!(quicp_engine_path_unavailable(client, 0), FfiStatus::Ok);
        for _ in 0..1_000 {
            let mut processed = 0;
            let _ = quicp_engine_drive(client, elapsed, 256, &raw mut processed);
            elapsed += 1_000_000;
            if quicp_engine_connection_state(client) == FfiStatus::Failed {
                break;
            }
        }
        assert_eq!(quicp_engine_connection_state(client), FfiStatus::Failed);
        assert_eq!(quicp_engine_close(&raw mut client), FfiStatus::Ok);
        assert_eq!(quicp_engine_close(&raw mut server), FfiStatus::Ok);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn synchronous_engine_exposes_replay_safe_profile() {
    // SAFETY: This test preserves exclusive ownership of both opaque engine pointers.
    unsafe {
        let mut client = create(&config(FfiRole::Client, 43_000, 43_001));
        let mut server = create(&config(FfiRole::Server, 43_001, 43_000));
        let secret = [0x5a; 32];
        assert_eq!(
            quicp_engine_configure_replay_admission(
                server,
                secret.as_ptr(),
                u32::try_from(secret.len()).unwrap(),
                7,
                u32::MAX,
            ),
            FfiStatus::InvalidArgument
        );
        assert_eq!(
            quicp_engine_configure_replay_admission(
                server,
                secret.as_ptr(),
                u32::try_from(secret.len()).unwrap(),
                7,
                16,
            ),
            FfiStatus::Ok
        );
        let mut elapsed = 0;
        for _ in 0..6_000 {
            progress(client, server, elapsed);
            elapsed += 1_000_000;
            if quicp_engine_connection_state(client) == FfiStatus::Ok
                && quicp_engine_connection_state(server) == FfiStatus::Ok
            {
                break;
            }
        }
        assert_eq!(quicp_engine_connection_state(client), FfiStatus::Ok);
        assert_eq!(quicp_engine_connection_state(server), FfiStatus::Ok);

        let prime_host = b"prime.example";
        let mut prime_client_flow = 0;
        let mut prime_server_flow = 0;
        let mut prime_request = 0;
        for _ in 0..1_000 {
            let _ = quicp_engine_open_flow(
                client,
                prime_host.as_ptr(),
                u32::try_from(prime_host.len()).unwrap(),
                443,
                &raw mut prime_client_flow,
            );
            if prime_server_flow == 0 {
                let _ = accept_request(server, false, &mut prime_request, &mut prime_server_flow);
            }
            progress(client, server, elapsed);
            elapsed += 1_000_000;
            if prime_client_flow != 0 && prime_server_flow != 0 {
                break;
            }
        }
        assert_ne!(prime_client_flow, 0);
        assert_ne!(prime_server_flow, 0);
        assert_eq!(quicp_flow_close(client, prime_client_flow), FfiStatus::Ok);
        assert_eq!(quicp_flow_close(server, prime_server_flow), FfiStatus::Ok);

        let now_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut token_length = 0;
        assert_eq!(
            quicp_engine_issue_replay_token(
                server,
                now_seconds,
                60,
                std::ptr::null_mut(),
                0,
                &raw mut token_length,
            ),
            FfiStatus::BufferTooSmall
        );
        let mut token = vec![0; token_length as usize];
        assert_eq!(
            quicp_engine_issue_replay_token(
                server,
                now_seconds,
                60,
                token.as_mut_ptr(),
                u32::try_from(token.len()).unwrap(),
                &raw mut token_length,
            ),
            FfiStatus::Ok
        );

        let host = b"early.example";
        let initial = b"replay-safe initial bytes";
        let mut client_flow = 0;
        let mut server_flow = 0;
        let mut server_request = 0;
        let mut client_status = FfiStatus::WouldBlock;
        let mut server_status = FfiStatus::WouldBlock;
        for _ in 0..2_000 {
            client_status = quicp_engine_open_replay_safe_flow(
                client,
                token.as_ptr(),
                token_length,
                42,
                host.as_ptr(),
                u32::try_from(host.len()).unwrap(),
                443,
                initial.as_ptr(),
                u32::try_from(initial.len()).unwrap(),
                &raw mut client_flow,
            );
            if server_flow == 0 {
                server_status = accept_request(server, true, &mut server_request, &mut server_flow);
            }
            progress(client, server, elapsed);
            elapsed += 1_000_000;
            if client_flow != 0 && server_flow != 0 {
                break;
            }
        }
        assert_ne!(
            client_flow, 0,
            "client status: {client_status:?}, server status: {server_status:?}, request: {server_request}"
        );
        assert_ne!(server_flow, 0, "server status: {server_status:?}");
        assert_ne!(client_flow, prime_client_flow);
        assert_ne!(server_flow, prime_server_flow);
        assert_eq!(
            quicp_flow_flush(client, prime_client_flow),
            FfiStatus::Closed
        );
        assert_eq!(
            quicp_flow_flush(server, prime_server_flow),
            FfiStatus::Closed
        );
        let mut received = [0; 64];
        let mut read = 0;
        for _ in 0..1_000 {
            progress(client, server, elapsed);
            elapsed += 1_000_000;
            if quicp_flow_read(
                server,
                server_flow,
                received.as_mut_ptr(),
                u32::try_from(received.len()).unwrap(),
                &raw mut read,
            ) == FfiStatus::Ok
            {
                break;
            }
        }
        assert_eq!(&received[..read as usize], initial);
        let mut snapshot = FfiRecoverySnapshot::default();
        assert_eq!(
            quicp_engine_recovery_snapshot(server, &raw mut snapshot),
            FfiStatus::Ok
        );
        assert_eq!(snapshot.early_accepted, 1);

        assert_eq!(quicp_flow_close(client, client_flow), FfiStatus::Ok);
        assert_eq!(quicp_flow_close(server, server_flow), FfiStatus::Ok);
        assert_eq!(quicp_engine_close(&raw mut client), FfiStatus::Ok);
        assert_eq!(quicp_engine_close(&raw mut server), FfiStatus::Ok);
    }
}

#[cfg(feature = "tls-rustls")]
#[test]
fn synchronous_engine_supports_mutual_tls() {
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    let directory = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    #[cfg(not(unix))]
    let directory = tempfile::tempdir().unwrap();
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(["server.example".to_owned()]).unwrap();
    let cert_path = directory.path().join("node.pem");
    let key_path = directory.path().join("node.key");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cert = cert_path.to_str().unwrap().as_bytes();
    let key = key_path.to_str().unwrap().as_bytes();
    let name = b"server.example";
    let client_tls = FfiTlsConfig {
        server_name: ffi_bytes(name),
        ca_certificate: ffi_bytes(cert),
        certificate: ffi_bytes(cert),
        private_key: ffi_bytes(key),
    };
    let server_tls = FfiTlsConfig {
        server_name: FfiBytes {
            data: std::ptr::null(),
            length: 0,
        },
        ca_certificate: ffi_bytes(cert),
        certificate: ffi_bytes(cert),
        private_key: ffi_bytes(key),
    };

    // SAFETY: This test preserves exclusive ownership of both opaque engine pointers.
    unsafe {
        let mut invalid = config(FfiRole::Client, 41_998, 41_999);
        invalid.abi_version -= 1;
        let mut rejected: *mut FfiEngine = std::ptr::dangling_mut();
        assert_eq!(
            quicp_engine_create_tls(&raw const invalid, &raw const client_tls, &raw mut rejected),
            FfiStatus::InvalidArgument
        );
        assert!(rejected.is_null());

        let mut client = create_tls(&config(FfiRole::Client, 42_000, 42_001), &client_tls);
        let mut server = create_tls(&config(FfiRole::Server, 42_001, 42_000), &server_tls);
        for elapsed in (0..6_000).map(|tick| tick * 1_000_000) {
            progress(client, server, elapsed);
            if quicp_engine_connection_state(client) == FfiStatus::Ok
                && quicp_engine_connection_state(server) == FfiStatus::Ok
            {
                break;
            }
        }
        assert_eq!(quicp_engine_connection_state(client), FfiStatus::Ok);
        assert_eq!(quicp_engine_connection_state(server), FfiStatus::Ok);
        assert_eq!(quicp_engine_close(&raw mut client), FfiStatus::Ok);
        assert_eq!(quicp_engine_close(&raw mut server), FfiStatus::Ok);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn synchronous_engine_keeps_flow_alive_after_primary_path_loss() {
    // SAFETY: This test preserves exclusive ownership of both opaque engine pointers.
    unsafe {
        let mut client = create(&multipath_config(
            FfiRole::Client,
            [(1, 41_000), (3, 41_002)],
            [(2, 41_001), (4, 41_003)],
        ));
        let mut server = create(&multipath_config(
            FfiRole::Server,
            [(2, 41_001), (4, 41_003)],
            [(1, 41_000), (3, 41_002)],
        ));
        let mut elapsed = 0;
        let mut backup_packets = 0;
        for _ in 0..5_000 {
            backup_packets += progress_paths(client, server, elapsed, 2, true);
            elapsed += 1_000_000;
            if quicp_engine_connection_state(client) == FfiStatus::Ok
                && quicp_engine_connection_state(server) == FfiStatus::Ok
            {
                break;
            }
        }
        assert_eq!(quicp_engine_connection_state(client), FfiStatus::Ok);
        assert_eq!(quicp_engine_connection_state(server), FfiStatus::Ok);

        let host = b"multipath.example";
        let mut client_flow = 0;
        let mut server_flow = 0;
        let mut server_request = 0;
        for _ in 0..5_000 {
            let _ = quicp_engine_open_flow(
                client,
                host.as_ptr(),
                u32::try_from(host.len()).unwrap(),
                443,
                &raw mut client_flow,
            );
            if server_flow == 0 {
                let _ = accept_request(server, false, &mut server_request, &mut server_flow);
            }
            backup_packets += progress_paths(client, server, elapsed, 2, true);
            elapsed += 1_000_000;
            if client_flow != 0 && server_flow != 0 {
                break;
            }
        }
        assert_ne!(client_flow, 0);
        assert_ne!(server_flow, 0);

        // Keep both underlays moving until backup validation and peer path status have propagated.
        for _ in 0..1_000 {
            backup_packets += progress_paths(client, server, elapsed, 2, true);
            elapsed += 1_000_000;
        }
        assert!(
            backup_packets > 0,
            "backup path validation made no progress"
        );

        let payload = b"in-flight QUICP data recovered after primary loss";
        let mut written = 0;
        assert_eq!(
            quicp_flow_write(
                client,
                client_flow,
                payload.as_ptr(),
                u32::try_from(payload.len()).unwrap(),
                &raw mut written,
            ),
            FfiStatus::Ok
        );
        let mut dropped = 0;
        for _ in 0..100 {
            let mut processed = 0;
            assert_eq!(
                quicp_engine_drive(client, elapsed, 256, &raw mut processed),
                FfiStatus::Ok
            );
            dropped += pump(client, server, 0, false);
            dropped += pump(client, server, 1, false);
            elapsed += 1_000_000;
            if dropped != 0 {
                break;
            }
        }
        assert!(
            dropped > 0,
            "no in-flight packet was dropped before failover"
        );
        assert_eq!(quicp_engine_path_unavailable(client, 0), FfiStatus::Ok);
        assert_eq!(quicp_engine_path_unavailable(server, 0), FfiStatus::Ok);

        let mut received = [0; 64];
        let mut read = 0;
        for _ in 0..5_000 {
            let _ = quicp_flow_flush(client, client_flow);
            let _ = progress_paths(client, server, elapsed, 2, false);
            elapsed += 1_000_000;
            if quicp_flow_read(
                server,
                server_flow,
                received.as_mut_ptr(),
                u32::try_from(received.len()).unwrap(),
                &raw mut read,
            ) == FfiStatus::Ok
            {
                break;
            }
        }
        assert_eq!(&received[..read as usize], payload);
        let mut snapshot = FfiRecoverySnapshot::default();
        assert_eq!(
            quicp_engine_recovery_snapshot(client, &raw mut snapshot),
            FfiStatus::Ok
        );
        assert!(snapshot.replayed > 0 || snapshot.fallback > 0);
        assert_eq!(quicp_engine_close(&raw mut client), FfiStatus::Ok);
        assert_eq!(quicp_engine_close(&raw mut server), FfiStatus::Ok);
    }
}
