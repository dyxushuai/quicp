//! Synchronous C ABI for a host-driven QUICP connection.
//!
//! Foreign buffers are borrowed for one call. One engine is single-owner and host-driven; no
//! Rust future, callback, collection, or retained foreign pointer crosses the ABI.

#![allow(unsafe_code)]

use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroUsize};
use std::panic::{AssertUnwindSafe, catch_unwind};
#[cfg(feature = "tls-rustls")]
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::wire::MAX_CANONICAL_HOST_BYTES;
use crate::{
    ApplicationError, CanonicalHost, CarrierConfig, Client, ClientConfig, Connection,
    HostDatagramError, HostDatagramSocket, HostRuntime, HostRuntimeError, MAX_QUIC_PAYLOAD,
    MIN_QUIC_PAYLOAD, Multipath, OpenRequest, OpenStatus, PathCandidate, PendingFlow, QuicpFlow,
    RecoveryMode, ReplayAdmission, ReplayToken, Server, ServerConfig,
};
#[cfg(feature = "tls-rustls")]
use crate::{ClientTls, ServerTls};

/// Current native ABI version.
pub const ABI_VERSION: u32 = 3;
const MAX_PATHS: usize = 2;
const MAX_FFI_STRING_BYTES: usize = 4096;
const MAX_EARLY_INITIAL_BYTES: usize = 32 * 1024;
static NEXT_FLOW_HANDLE: AtomicU64 = AtomicU64::new(1);
static NEXT_REQUEST_HANDLE: AtomicU64 = AtomicU64::new(1);
/// Maximum packet slots accepted per direction and path by the C engine.
pub const MAX_ENGINE_PACKET_CAPACITY: u32 = 4096;
/// Maximum canonical host bytes returned by a pending flow request.
pub const MAX_ENGINE_HOST_BYTES: usize = MAX_CANONICAL_HOST_BYTES;
/// Maximum aggregate packet-queue payload allocation accepted by the C engine.
pub const MAX_ENGINE_QUEUE_BYTES: usize = 64 * 1024 * 1024;

/// Stable C ABI statuses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FfiStatus {
    /// Completed.
    Ok = 0,
    /// Retry after ingress, egress, timer, or drive progress.
    WouldBlock = 1,
    /// The caller-owned output buffer is too small.
    BufferTooSmall = 2,
    /// A pointer, length, address, handle, or operation is invalid.
    InvalidArgument = 3,
    /// Connection establishment has not completed.
    NotReady = 4,
    /// The engine or flow is closed.
    Closed = 5,
    /// A panic was contained at the ABI boundary.
    Panic = 6,
    /// A protocol operation failed.
    Failed = 7,
}

/// Endpoint role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FfiRole {
    /// Initiates one connection.
    Client = 1,
    /// Accepts one connection.
    Server = 2,
}

/// Built-in recovery policy selected at engine creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FfiRecoveryMode {
    /// DATAGRAM-first adaptive recovery with reliable fallback.
    Adaptive = 1,
    /// Reliable control-stream transport only.
    ReliableOnly = 2,
}

/// ABI-stable IPv4 or IPv6 socket address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FfiSocketAddress {
    /// `4` or `6`.
    pub family: u32,
    /// Host-order port.
    pub port: u16,
    /// Must be zero.
    pub reserved: u16,
    /// IPv4 occupies the first four bytes and requires a zero tail.
    pub address: [u8; 16],
}

impl FfiSocketAddress {
    fn get(self) -> Option<SocketAddr> {
        if self.port == 0 || self.reserved != 0 {
            return None;
        }
        let ip = match self.family {
            4 if self.address[4..].iter().all(|byte| *byte == 0) => IpAddr::V4(Ipv4Addr::new(
                self.address[0],
                self.address[1],
                self.address[2],
                self.address[3],
            )),
            6 => IpAddr::V6(Ipv6Addr::from(self.address)),
            _ => return None,
        };
        Some(SocketAddr::new(ip, self.port))
    }
}

/// One fixed-peer underlay path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FfiPathConfig {
    /// Local address exposed to QUIC.
    pub local: FfiSocketAddress,
    /// Remote peer accepted on this path.
    pub peer: FfiSocketAddress,
}

/// Bounded no-TLS engine construction values.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FfiEngineConfig {
    /// Must equal [`ABI_VERSION`].
    pub abi_version: u32,
    /// [`FfiRole`] discriminant.
    pub role: u32,
    /// One for single path, two for primary/backup.
    pub path_count: u32,
    /// Primary, then optional backup.
    pub paths: [FfiPathConfig; MAX_PATHS],
    /// Datagram slots in each direction per path.
    pub packet_capacity: u32,
    /// Maximum underlay datagram bytes.
    pub mtu: u32,
    /// [`FfiRecoveryMode`] discriminant.
    pub recovery_mode: u32,
}

/// One UTF-8 string borrowed only for an engine-creation call.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FfiBytes {
    /// Readable bytes, not NUL terminated.
    pub data: *const u8,
    /// Exact byte length.
    pub length: u32,
}

/// Mutual-TLS identity and trust paths borrowed only during engine creation.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FfiTlsConfig {
    /// Client-authenticated DNS name; empty for a server engine.
    pub server_name: FfiBytes,
    /// Client: server CA. Server: client CA.
    pub ca_certificate: FfiBytes,
    /// Client or server certificate-chain path.
    pub certificate: FfiBytes,
    /// Client or server private-key path.
    pub private_key: FfiBytes,
}

#[derive(Debug)]
#[cfg_attr(not(feature = "tls-rustls"), derive(Clone, Copy))]
enum FfiSecurity {
    Insecure,
    #[cfg(feature = "tls-rustls")]
    ClientTls(ClientTls),
    #[cfg(feature = "tls-rustls")]
    ServerTls(ServerTls),
}

/// Recovery counters and gauges copied from one ready connection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FfiRecoverySnapshot {
    /// Source DATAGRAMs sent.
    pub source_sent: u64,
    /// Valid source DATAGRAMs received.
    pub source_received: u64,
    /// Repair DATAGRAMs sent.
    pub repair_sent: u64,
    /// Source symbols recovered from repairs.
    pub recovered: u64,
    /// Source records replayed.
    pub replayed: u64,
    /// Source records sent through reliable fallback.
    pub fallback: u64,
    /// Invalid or over-limit DATAGRAMs dropped.
    pub dropped: u64,
    /// Replay-safe early opens admitted.
    pub early_accepted: u64,
    /// Replay-safe early opens rejected.
    pub early_rejected: u64,
    /// Aggregate packets lost on outbound QUIC paths.
    pub path_lost_packets: u64,
    /// Largest current path RTT, in microseconds.
    pub max_path_rtt_micros: u64,
    /// DATAGRAMs waiting for backend send capacity.
    pub queued_datagrams: u64,
    /// Bytes retained in the source coding window.
    pub retained_source_bytes: u64,
}

#[derive(Debug)]
enum ConnectionState {
    Connecting,
    Ready(Connection),
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReplayOpen {
    token: ReplayToken,
    nonce: u64,
    initial: bytes::Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenOperation {
    request: OpenRequest,
    replay: Option<ReplayOpen>,
}

#[derive(Debug)]
enum OpenState {
    Idle,
    Pending(OpenOperation),
    Ready(OpenOperation, u64),
    Failed(OpenOperation),
}

#[derive(Debug)]
enum AcceptState {
    Idle,
    Receiving(bool),
    Offered {
        replay: bool,
        handle: u64,
        pending: PendingFlow,
    },
    Resolving {
        handle: u64,
        accept: bool,
    },
    Accepted {
        handle: u64,
        flow: u64,
    },
    Rejected(u64),
    ReceiveFailed(bool),
    ResolveFailed(u64),
}

#[derive(Debug)]
struct FlowSlot {
    handle: u64,
    flow: Option<QuicpFlow>,
}

#[derive(Debug)]
struct EngineState {
    connection: ConnectionState,
    open: OpenState,
    accept: AcceptState,
    flows: Vec<FlowSlot>,
}

impl EngineState {
    fn insert_flow(&mut self, flow: QuicpFlow) -> u64 {
        let handle = NEXT_FLOW_HANDLE.fetch_add(1, Ordering::Relaxed);
        if let Some(slot) = self.flows.iter_mut().find(|slot| slot.flow.is_none()) {
            slot.handle = handle;
            slot.flow = Some(flow);
            return handle;
        }
        self.flows.push(FlowSlot {
            handle,
            flow: Some(flow),
        });
        handle
    }

    fn flow_mut(&mut self, handle: u64) -> Option<&mut QuicpFlow> {
        self.flows
            .iter_mut()
            .find(|slot| slot.handle == handle)
            .and_then(|slot| slot.flow.as_mut())
    }

    fn remove_flow(&mut self, handle: u64) -> Option<QuicpFlow> {
        self.flows
            .iter_mut()
            .find(|slot| slot.handle == handle)
            .and_then(|slot| slot.flow.take())
    }
}

/// Opaque single-owner engine.
pub struct FfiEngine {
    role: FfiRole,
    runtime: Arc<HostRuntime>,
    sockets: Vec<HostDatagramSocket>,
    state: Arc<Mutex<EngineState>>,
    replay_admission: Mutex<Option<Arc<ReplayAdmission>>>,
}

impl FfiEngine {
    fn new(config: FfiEngineConfig, security: FfiSecurity) -> Result<Self, FfiStatus> {
        if config.abi_version != ABI_VERSION {
            return Err(FfiStatus::InvalidArgument);
        }
        let role = match config.role {
            1 => FfiRole::Client,
            2 => FfiRole::Server,
            _ => return Err(FfiStatus::InvalidArgument),
        };
        let recovery_mode = match config.recovery_mode {
            value if value == FfiRecoveryMode::Adaptive as u32 => RecoveryMode::Adaptive,
            value if value == FfiRecoveryMode::ReliableOnly as u32 => RecoveryMode::ReliableOnly,
            _ => return Err(FfiStatus::InvalidArgument),
        };
        let count = usize::try_from(config.path_count).map_err(|_| FfiStatus::InvalidArgument)?;
        let capacity = usize::try_from(config.packet_capacity)
            .ok()
            .filter(|value| (1..=MAX_ENGINE_PACKET_CAPACITY as usize).contains(value))
            .ok_or(FfiStatus::InvalidArgument)?;
        let mtu = u16::try_from(config.mtu)
            .ok()
            .filter(|value| (MIN_QUIC_PAYLOAD..=MAX_QUIC_PAYLOAD).contains(value))
            .ok_or(FfiStatus::InvalidArgument)?;
        if !(1..=MAX_PATHS).contains(&count) {
            return Err(FfiStatus::InvalidArgument);
        }
        let mtu = usize::from(mtu);
        let queue_bytes = count
            .checked_mul(2)
            .and_then(|value| value.checked_mul(capacity))
            .and_then(|value| value.checked_mul(mtu))
            .ok_or(FfiStatus::InvalidArgument)?;
        if queue_bytes > MAX_ENGINE_QUEUE_BYTES {
            return Err(FfiStatus::InvalidArgument);
        }
        let mut sockets = Vec::with_capacity(count);
        for path in &config.paths[..count] {
            let local = path.local.get().ok_or(FfiStatus::InvalidArgument)?;
            let peer = path.peer.get().ok_or(FfiStatus::InvalidArgument)?;
            if local.is_ipv4() != peer.is_ipv4() {
                return Err(FfiStatus::InvalidArgument);
            }
            sockets.push(
                HostDatagramSocket::new(local, peer, capacity, mtu)
                    .map_err(|_| FfiStatus::InvalidArgument)?,
            );
        }
        let runtime = Arc::new(HostRuntime::new());
        let state = Arc::new(Mutex::new(EngineState {
            connection: ConnectionState::Connecting,
            open: OpenState::Idle,
            accept: AcceptState::Idle,
            flows: Vec::new(),
        }));
        start(role, recovery_mode, security, &sockets, &runtime, &state)?;
        Ok(Self {
            role,
            runtime,
            sockets,
            state,
            replay_admission: Mutex::new(None),
        })
    }
}

impl Drop for FfiEngine {
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        if let ConnectionState::Ready(connection) = &state.connection {
            connection.close(ApplicationError::FlowAbort, b"foreign engine closed");
        }
        state.flows.clear();
        drop(state);
        let _ = self.runtime.shutdown();
    }
}

fn start(
    role: FfiRole,
    recovery_mode: RecoveryMode,
    security: FfiSecurity,
    sockets: &[HostDatagramSocket],
    runtime: &Arc<HostRuntime>,
    state: &Arc<Mutex<EngineState>>,
) -> Result<(), FfiStatus> {
    let shared = Arc::clone(state);
    match role {
        FfiRole::Client => {
            let candidates = sockets
                .iter()
                .map(|socket| PathCandidate::new(socket.local_addr().ip(), socket.peer_addr()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| FfiStatus::InvalidArgument)?;
            let multipath = match candidates.as_slice() {
                [primary] => Multipath::single(primary.clone()),
                [primary, backup] => Multipath::failover(primary.clone(), backup.clone()),
                _ => return Err(FfiStatus::InvalidArgument),
            }
            .map_err(|_| FfiStatus::InvalidArgument)?;
            let mut transport = crate::QuicpTransportConfig::default();
            transport.recovery.mode = recovery_mode;
            let config = match security {
                FfiSecurity::Insecure => {
                    ClientConfig::insecure(multipath, CarrierConfig::default())
                }
                #[cfg(feature = "tls-rustls")]
                FfiSecurity::ClientTls(tls) => {
                    ClientConfig::with_tls(tls, multipath, CarrierConfig::default())
                }
                #[cfg(feature = "tls-rustls")]
                FfiSecurity::ServerTls(_) => return Err(FfiStatus::InvalidArgument),
            }
            .and_then(|config| config.with_transport(transport))
            .map_err(|_| FfiStatus::InvalidArgument)?;
            let client = match sockets {
                [socket] => Client::from_host_socket(&config, socket.clone(), Arc::clone(runtime)),
                [primary, backup] => Client::from_host_sockets(
                    &config,
                    &[primary.clone(), backup.clone()],
                    Arc::clone(runtime),
                ),
                _ => return Err(FfiStatus::InvalidArgument),
            }
            .map_err(|_| FfiStatus::InvalidArgument)?;
            runtime
                .spawn(Box::pin(async move {
                    lock(&shared).connection = match client.connect().await {
                        Ok(connection) => ConnectionState::Ready(connection),
                        Err(_) => ConnectionState::Failed,
                    };
                }))
                .map_err(|_| FfiStatus::Failed)
        }
        FfiRole::Server => {
            let mut transport = crate::QuicpTransportConfig::default();
            transport.recovery.mode = recovery_mode;
            let listen = sockets.iter().map(HostDatagramSocket::local_addr).collect();
            let config = match security {
                FfiSecurity::Insecure => ServerConfig::insecure(listen, CarrierConfig::default()),
                #[cfg(feature = "tls-rustls")]
                FfiSecurity::ServerTls(tls) => {
                    ServerConfig::with_tls(listen, tls, CarrierConfig::default())
                }
                #[cfg(feature = "tls-rustls")]
                FfiSecurity::ClientTls(_) => return Err(FfiStatus::InvalidArgument),
            }
            .and_then(|config| config.with_transport(transport))
            .map_err(|_| FfiStatus::InvalidArgument)?;
            let server = match sockets {
                [socket] => Server::from_host_socket(&config, socket.clone(), Arc::clone(runtime)),
                [primary, backup] => Server::from_host_sockets(
                    &config,
                    &[primary.clone(), backup.clone()],
                    Arc::clone(runtime),
                ),
                _ => return Err(FfiStatus::InvalidArgument),
            }
            .map_err(|_| FfiStatus::InvalidArgument)?;
            runtime
                .spawn(Box::pin(async move {
                    lock(&shared).connection = match server.accept().await {
                        Ok(incoming) => match incoming.handshake().await {
                            Ok(connection) => ConnectionState::Ready(connection),
                            Err(_) => ConnectionState::Failed,
                        },
                        Err(_) => ConnectionState::Failed,
                    };
                }))
                .map_err(|_| FfiStatus::Failed)
        }
    }
}

fn boundary(operation: impl FnOnce() -> FfiStatus) -> FfiStatus {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(FfiStatus::Panic)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn valid_mut<T>(pointer: *mut T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}

fn disjoint<T, U>(left: *const T, left_count: usize, right: *const U, right_count: usize) -> bool {
    let Some(left_end) = (left as usize).checked_add(size_of::<T>().saturating_mul(left_count))
    else {
        return false;
    };
    let Some(right_end) = (right as usize).checked_add(size_of::<U>().saturating_mul(right_count))
    else {
        return false;
    };
    left_end <= right as usize || right_end <= left as usize
}

fn valid_engine_output<T>(engine: *mut FfiEngine, output: *mut T) -> bool {
    valid_mut(output) && disjoint(engine, 1, output, 1)
}

#[cfg(feature = "tls-rustls")]
unsafe fn ffi_string(value: FfiBytes, allow_empty: bool) -> Result<String, FfiStatus> {
    let length = usize::try_from(value.length).map_err(|_| FfiStatus::InvalidArgument)?;
    if length == 0 {
        return allow_empty
            .then(String::new)
            .ok_or(FfiStatus::InvalidArgument);
    }
    if value.data.is_null() || length > MAX_FFI_STRING_BYTES {
        return Err(FfiStatus::InvalidArgument);
    }
    let bytes = unsafe { std::slice::from_raw_parts(value.data, length) };
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| FfiStatus::InvalidArgument)
}

#[cfg(not(feature = "tls-rustls"))]
unsafe fn ffi_security(_role: u32, _tls: FfiTlsConfig) -> Result<FfiSecurity, FfiStatus> {
    Err(FfiStatus::InvalidArgument)
}

#[cfg(feature = "tls-rustls")]
unsafe fn ffi_security(role: u32, tls: FfiTlsConfig) -> Result<FfiSecurity, FfiStatus> {
    match role {
        value if value == FfiRole::Client as u32 => {
            let server_name = unsafe { ffi_string(tls.server_name, false)? };
            let ca = PathBuf::from(unsafe { ffi_string(tls.ca_certificate, false)? });
            let certificate = PathBuf::from(unsafe { ffi_string(tls.certificate, false)? });
            let key = PathBuf::from(unsafe { ffi_string(tls.private_key, false)? });
            ClientTls::new(server_name, ca, certificate, key)
                .map(FfiSecurity::ClientTls)
                .map_err(|_| FfiStatus::InvalidArgument)
        }
        value if value == FfiRole::Server as u32 => {
            let server_name = unsafe { ffi_string(tls.server_name, true)? };
            if !server_name.is_empty() {
                return Err(FfiStatus::InvalidArgument);
            }
            let ca = PathBuf::from(unsafe { ffi_string(tls.ca_certificate, false)? });
            let certificate = PathBuf::from(unsafe { ffi_string(tls.certificate, false)? });
            let key = PathBuf::from(unsafe { ffi_string(tls.private_key, false)? });
            ServerTls::new(certificate, key, ca)
                .map(FfiSecurity::ServerTls)
                .map_err(|_| FfiStatus::InvalidArgument)
        }
        _ => Err(FfiStatus::InvalidArgument),
    }
}

fn engine<'a>(pointer: *mut FfiEngine) -> Result<&'a FfiEngine, FfiStatus> {
    if pointer.is_null() || !pointer.is_aligned() {
        return Err(FfiStatus::InvalidArgument);
    }
    // SAFETY: The caller promises a live, exclusively called engine.
    Ok(unsafe { &*pointer })
}

/// Returns the ABI version.
#[unsafe(no_mangle)]
pub const extern "C" fn quicp_abi_version() -> u32 {
    ABI_VERSION
}

/// Creates a no-TLS engine.
///
/// # Safety
///
/// `config` must be readable and `out` writable. The returned engine is single-owner.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_create(
    config: *const FfiEngineConfig,
    out: *mut *mut FfiEngine,
) -> FfiStatus {
    boundary(|| {
        if config.is_null()
            || !config.is_aligned()
            || !valid_mut(out)
            || !disjoint(config, 1, out, 1)
        {
            return FfiStatus::InvalidArgument;
        }
        unsafe { out.write(std::ptr::null_mut()) };
        if unsafe { config.cast::<u32>().read() } != ABI_VERSION {
            return FfiStatus::InvalidArgument;
        }
        let config = unsafe { config.read() };
        match FfiEngine::new(config, FfiSecurity::Insecure) {
            Ok(value) => {
                unsafe { out.write(Box::into_raw(Box::new(value))) };
                FfiStatus::Ok
            }
            Err(status) => status,
        }
    })
}

/// Creates a mutual-TLS engine.
///
/// With `tls-rustls`, all strings are copied before return. Without it, this returns
/// [`FfiStatus::InvalidArgument`] without copying strings or constructing an engine.
///
/// # Safety
///
/// `config` and `tls` must be readable and `out` writable. Each non-empty [`FfiBytes`] must be
/// readable for its declared length. The returned engine is single-owner.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_create_tls(
    config: *const FfiEngineConfig,
    tls: *const FfiTlsConfig,
    out: *mut *mut FfiEngine,
) -> FfiStatus {
    boundary(|| {
        if config.is_null()
            || tls.is_null()
            || !config.is_aligned()
            || !tls.is_aligned()
            || !valid_mut(out)
            || !disjoint(config, 1, tls, 1)
            || !disjoint(config, 1, out, 1)
            || !disjoint(tls, 1, out, 1)
        {
            return FfiStatus::InvalidArgument;
        }
        unsafe { out.write(std::ptr::null_mut()) };
        if unsafe { config.cast::<u32>().read() } != ABI_VERSION {
            return FfiStatus::InvalidArgument;
        }
        let config = unsafe { config.read() };
        let tls = unsafe { tls.read() };
        let Ok(security) = (unsafe { ffi_security(config.role, tls) }) else {
            return FfiStatus::InvalidArgument;
        };
        match FfiEngine::new(config, security) {
            Ok(value) => {
                unsafe { out.write(Box::into_raw(Box::new(value))) };
                FfiStatus::Ok
            }
            Err(status) => status,
        }
    })
}

/// Advances bounded protocol work with monotonic nanoseconds since creation.
///
/// # Safety
///
/// `engine` must be live and `processed` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_drive(
    engine_pointer: *mut FfiEngine,
    elapsed_nanos: u64,
    max_tasks: u32,
    processed: *mut u32,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        let Some(max_tasks) = NonZeroUsize::new(max_tasks as usize) else {
            return FfiStatus::InvalidArgument;
        };
        if !valid_engine_output(engine_pointer, processed) {
            return FfiStatus::InvalidArgument;
        }
        match engine
            .runtime
            .drive(Duration::from_nanos(elapsed_nanos), max_tasks)
        {
            Ok(count) => {
                unsafe { processed.write(u32::try_from(count).unwrap_or(u32::MAX)) };
                FfiStatus::Ok
            }
            Err(HostRuntimeError::TaskPanicked) => {
                let mut state = lock(&engine.state);
                if let ConnectionState::Ready(connection) = &state.connection {
                    connection.close(ApplicationError::FlowAbort, b"host runtime task panicked");
                }
                state.connection = ConnectionState::Failed;
                FfiStatus::Failed
            }
            Err(HostRuntimeError::TimeWentBackwards | HostRuntimeError::TimeOutsideRange) => {
                FfiStatus::InvalidArgument
            }
            Err(HostRuntimeError::ConcurrentDrive) => FfiStatus::InvalidArgument,
            Err(HostRuntimeError::Closed) => FfiStatus::Closed,
        }
    })
}

/// Returns the next monotonic timer deadline.
///
/// # Safety
///
/// Both outputs must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_next_timer(
    engine_pointer: *mut FfiEngine,
    present: *mut u32,
    elapsed_nanos: *mut u64,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        if !valid_engine_output(engine_pointer, present)
            || !valid_engine_output(engine_pointer, elapsed_nanos)
            || !disjoint(present, 1, elapsed_nanos, 1)
        {
            return FfiStatus::InvalidArgument;
        }
        let timer = engine.runtime.next_timer();
        unsafe {
            present.write(u32::from(timer.is_some()));
            elapsed_nanos.write(timer.map_or(0, |value| {
                u64::try_from(value.as_nanos()).unwrap_or(u64::MAX)
            }));
        }
        FfiStatus::Ok
    })
}

/// Reports connection progress.
///
/// # Safety
///
/// `engine` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_connection_state(
    engine_pointer: *mut FfiEngine,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        match &lock(&engine.state).connection {
            ConnectionState::Connecting => FfiStatus::WouldBlock,
            ConnectionState::Ready(connection) if connection.is_closed() => FfiStatus::Failed,
            ConnectionState::Ready(_) => FfiStatus::Ok,
            ConnectionState::Failed => FfiStatus::Failed,
        }
    })
}

/// Copies the current recovery counters.
///
/// # Safety
///
/// `engine` must be live and `snapshot` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_recovery_snapshot(
    engine_pointer: *mut FfiEngine,
    snapshot: *mut FfiRecoverySnapshot,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        if !valid_engine_output(engine_pointer, snapshot) {
            return FfiStatus::InvalidArgument;
        }
        let state = lock(&engine.state);
        let connection = match &state.connection {
            ConnectionState::Connecting => return FfiStatus::NotReady,
            ConnectionState::Failed => return FfiStatus::Failed,
            ConnectionState::Ready(connection) if connection.is_closed() => {
                return FfiStatus::Failed;
            }
            ConnectionState::Ready(connection) => connection,
        };
        let value = connection.recovery_snapshot();
        unsafe {
            snapshot.write(FfiRecoverySnapshot {
                source_sent: value.source_sent,
                source_received: value.source_received,
                repair_sent: value.repair_sent,
                recovered: value.recovered,
                replayed: value.replayed,
                fallback: value.fallback,
                dropped: value.dropped,
                early_accepted: value.early_accepted,
                early_rejected: value.early_rejected,
                path_lost_packets: value.path_lost_packets,
                max_path_rtt_micros: value.max_path_rtt_micros,
                queued_datagrams: value.queued_datagrams,
                retained_source_bytes: value.retained_source_bytes,
            });
        }
        FfiStatus::Ok
    })
}

/// Pushes one complete underlay datagram into a path.
///
/// # Safety
///
/// `data` must be readable for `length`; it is not retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_ingress(
    engine_pointer: *mut FfiEngine,
    path: u32,
    data: *const u8,
    length: u32,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        let Some(socket) = usize::try_from(path)
            .ok()
            .and_then(|index| engine.sockets.get(index))
        else {
            return FfiStatus::InvalidArgument;
        };
        if data.is_null() || length == 0 || !disjoint(engine_pointer, 1, data, length as usize) {
            return FfiStatus::InvalidArgument;
        }
        let data = unsafe { std::slice::from_raw_parts(data, length as usize) };
        match socket.ingress_datagram(data) {
            Ok(()) => FfiStatus::Ok,
            Err(HostDatagramError::QueueFull) => FfiStatus::WouldBlock,
            Err(_) => FfiStatus::InvalidArgument,
        }
    })
}

/// Pops one complete underlay datagram from a path.
///
/// # Safety
///
/// `output` must be writable for `capacity`, and `length` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_egress(
    engine_pointer: *mut FfiEngine,
    path: u32,
    output: *mut u8,
    capacity: u32,
    length: *mut u32,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        let Some(socket) = usize::try_from(path)
            .ok()
            .and_then(|index| engine.sockets.get(index))
        else {
            return FfiStatus::InvalidArgument;
        };
        if output.is_null()
            || capacity == 0
            || !valid_engine_output(engine_pointer, length)
            || !disjoint(engine_pointer, 1, output, capacity as usize)
            || !disjoint(output, capacity as usize, length, 1)
        {
            return FfiStatus::InvalidArgument;
        }
        let output = unsafe { std::slice::from_raw_parts_mut(output, capacity as usize) };
        match socket.poll_egress_datagram_into(output) {
            Ok(Some(count)) => {
                unsafe { length.write(u32::try_from(count).unwrap_or(u32::MAX)) };
                FfiStatus::Ok
            }
            Ok(None) => FfiStatus::WouldBlock,
            Err(HostDatagramError::BufferTooSmall { required, .. }) => {
                unsafe { length.write(u32::try_from(required).unwrap_or(u32::MAX)) };
                FfiStatus::BufferTooSmall
            }
            Err(_) => FfiStatus::Failed,
        }
    })
}

/// Permanently marks one host-owned underlay path unavailable.
///
/// # Safety
///
/// `engine` must be live and calls on it serialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_path_unavailable(
    engine_pointer: *mut FfiEngine,
    path: u32,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        let Some(socket) = usize::try_from(path)
            .ok()
            .and_then(|index| engine.sockets.get(index))
        else {
            return FfiStatus::InvalidArgument;
        };
        socket.mark_unavailable();
        FfiStatus::Ok
    })
}

/// Starts or polls one client flow open. Repeat with the same host and port after `WOULD_BLOCK`.
///
/// # Safety
///
/// Host bytes must be readable and `flow` writable. Host bytes are copied before return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_open_flow(
    engine_pointer: *mut FfiEngine,
    host: *const u8,
    host_length: u32,
    port: u16,
    flow: *mut u64,
) -> FfiStatus {
    boundary(|| {
        let host_length = host_length as usize;
        if host.is_null()
            || host_length == 0
            || host_length > MAX_CANONICAL_HOST_BYTES
            || !valid_engine_output(engine_pointer, flow)
            || !disjoint(host, host_length, flow, 1)
        {
            return FfiStatus::InvalidArgument;
        }
        let host = unsafe { std::slice::from_raw_parts(host, host_length) };
        unsafe { poll_open(engine_pointer, host, port, None, flow) }
    })
}

/// Starts or polls one replay-safe client flow open on an established connection.
///
/// # Safety
///
/// All input buffers must be readable and disjoint from writable `flow`. Inputs are copied.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_open_replay_safe_flow(
    engine_pointer: *mut FfiEngine,
    token: *const u8,
    token_length: u32,
    nonce: u64,
    host: *const u8,
    host_length: u32,
    port: u16,
    initial: *const u8,
    initial_length: u32,
    flow: *mut u64,
) -> FfiStatus {
    boundary(|| {
        let token_length = token_length as usize;
        let host_length = host_length as usize;
        let initial_length = initial_length as usize;
        if token.is_null()
            || token_length != ReplayToken::BYTE_LEN
            || host.is_null()
            || host_length == 0
            || host_length > MAX_CANONICAL_HOST_BYTES
            || initial.is_null()
            || initial_length == 0
            || initial_length > MAX_EARLY_INITIAL_BYTES
            || !valid_engine_output(engine_pointer, flow)
            || !disjoint(token, token_length, flow, 1)
            || !disjoint(host, host_length, flow, 1)
            || !disjoint(initial, initial_length, flow, 1)
        {
            return FfiStatus::InvalidArgument;
        }
        let token = unsafe { std::slice::from_raw_parts(token, token_length) };
        let host = unsafe { std::slice::from_raw_parts(host, host_length) };
        let initial = unsafe { std::slice::from_raw_parts(initial, initial_length) };
        unsafe {
            poll_open(
                engine_pointer,
                host,
                port,
                Some((token, nonce, initial)),
                flow,
            )
        }
    })
}

unsafe fn poll_open(
    engine_pointer: *mut FfiEngine,
    host: &[u8],
    port: u16,
    replay: Option<(&[u8], u64, &[u8])>,
    flow: *mut u64,
) -> FfiStatus {
    let Ok(host) = std::str::from_utf8(host) else {
        return FfiStatus::InvalidArgument;
    };
    let Some(port) = NonZeroU16::new(port) else {
        return FfiStatus::InvalidArgument;
    };
    let Ok(engine) = engine(engine_pointer) else {
        return FfiStatus::InvalidArgument;
    };
    if engine.role != FfiRole::Client {
        return FfiStatus::InvalidArgument;
    }
    let mut state = lock(&engine.state);
    match &state.open {
        OpenState::Pending(active) if open_matches(active, host, port, replay) => {
            return FfiStatus::WouldBlock;
        }
        OpenState::Ready(active, handle) if open_matches(active, host, port, replay) => {
            unsafe { flow.write(*handle) };
            state.open = OpenState::Idle;
            return FfiStatus::Ok;
        }
        OpenState::Failed(active) if open_matches(active, host, port, replay) => {
            state.open = OpenState::Idle;
            return FfiStatus::Failed;
        }
        OpenState::Idle => {}
        _ => return FfiStatus::InvalidArgument,
    }
    let connection = match &state.connection {
        ConnectionState::Connecting => return FfiStatus::NotReady,
        ConnectionState::Failed => return FfiStatus::Failed,
        ConnectionState::Ready(connection) if connection.is_closed() => return FfiStatus::Failed,
        ConnectionState::Ready(connection) => connection.clone(),
    };
    let request = match CanonicalHost::parse(host) {
        Ok(host) => OpenRequest::new(host, port),
        Err(_) => return FfiStatus::InvalidArgument,
    };
    let replay = match replay {
        Some((token, nonce, initial)) => {
            let Ok(token) = ReplayToken::from_bytes(token) else {
                return FfiStatus::InvalidArgument;
            };
            Some(ReplayOpen {
                token,
                nonce,
                initial: bytes::Bytes::copy_from_slice(initial),
            })
        }
        None => None,
    };
    let operation = OpenOperation { request, replay };
    state.open = OpenState::Pending(operation.clone());
    drop(state);
    let shared = Arc::clone(&engine.state);
    let task_operation = operation.clone();
    if engine
        .runtime
        .spawn(Box::pin(async move {
            let result = match &task_operation.replay {
                Some(replay) => {
                    connection
                        .open_replay_safe(
                            &replay.token,
                            replay.nonce,
                            task_operation.request.clone(),
                            replay.initial.clone(),
                            true,
                        )
                        .await
                }
                None => {
                    connection
                        .open_flow(task_operation.request.clone(), true)
                        .await
                }
            };
            let mut state = lock(&shared);
            state.open = match result {
                Ok(flow) => {
                    let handle = state.insert_flow(flow);
                    OpenState::Ready(task_operation, handle)
                }
                Err(_) => OpenState::Failed(task_operation),
            };
        }))
        .is_err()
    {
        lock(&engine.state).open = OpenState::Failed(operation);
        return FfiStatus::Failed;
    }
    FfiStatus::WouldBlock
}

fn open_matches(
    active: &OpenOperation,
    host: &str,
    port: NonZeroU16,
    replay: Option<(&[u8], u64, &[u8])>,
) -> bool {
    active.request.host.as_str() == host
        && active.request.port == port
        && match (&active.replay, replay) {
            (None, None) => true,
            (Some(active), Some((token, nonce, initial))) => {
                active.token.as_bytes() == token
                    && active.nonce == nonce
                    && active.initial.as_ref() == initial
            }
            _ => false,
        }
}

/// Starts or polls one ordinary server OPEN without accepting it.
///
/// # Safety
///
/// Scalar outputs must be writable. Host and initial-data outputs are borrowed for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_poll_flow_request(
    engine_pointer: *mut FfiEngine,
    request: *mut u64,
    host: *mut u8,
    host_capacity: u32,
    host_length: *mut u32,
    port: *mut u16,
    initial: *mut u8,
    initial_capacity: u32,
    initial_length: *mut u32,
) -> FfiStatus {
    boundary(|| unsafe {
        poll_flow_request(
            engine_pointer,
            false,
            request,
            host,
            host_capacity,
            host_length,
            port,
            initial,
            initial_capacity,
            initial_length,
        )
    })
}

/// Starts or polls one replay-safe server OPEN without accepting it.
///
/// # Safety
///
/// Scalar outputs must be writable. Host and initial-data outputs are borrowed for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_poll_replay_safe_flow_request(
    engine_pointer: *mut FfiEngine,
    request: *mut u64,
    host: *mut u8,
    host_capacity: u32,
    host_length: *mut u32,
    port: *mut u16,
    initial: *mut u8,
    initial_capacity: u32,
    initial_length: *mut u32,
) -> FfiStatus {
    boundary(|| unsafe {
        poll_flow_request(
            engine_pointer,
            true,
            request,
            host,
            host_capacity,
            host_length,
            port,
            initial,
            initial_capacity,
            initial_length,
        )
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
unsafe fn poll_flow_request(
    engine_pointer: *mut FfiEngine,
    replay: bool,
    request: *mut u64,
    host: *mut u8,
    host_capacity: u32,
    host_length: *mut u32,
    port: *mut u16,
    initial: *mut u8,
    initial_capacity: u32,
    initial_length: *mut u32,
) -> FfiStatus {
    let Ok(engine) = engine(engine_pointer) else {
        return FfiStatus::InvalidArgument;
    };
    let host_capacity = host_capacity as usize;
    let initial_capacity = initial_capacity as usize;
    if engine.role != FfiRole::Server
        || !valid_engine_output(engine_pointer, request)
        || !valid_engine_output(engine_pointer, host_length)
        || !valid_engine_output(engine_pointer, port)
        || !valid_engine_output(engine_pointer, initial_length)
        || (host_capacity != 0
            && (host.is_null() || !disjoint(engine_pointer, 1, host, host_capacity)))
        || (initial_capacity != 0
            && (initial.is_null() || !disjoint(engine_pointer, 1, initial, initial_capacity)))
        || !disjoint(request, 1, host_length, 1)
        || !disjoint(request, 1, port, 1)
        || !disjoint(request, 1, initial_length, 1)
        || !disjoint(host_length, 1, port, 1)
        || !disjoint(host_length, 1, initial_length, 1)
        || !disjoint(port, 1, initial_length, 1)
        || (host_capacity != 0
            && (!disjoint(host, host_capacity, request, 1)
                || !disjoint(host, host_capacity, host_length, 1)
                || !disjoint(host, host_capacity, port, 1)
                || !disjoint(host, host_capacity, initial_length, 1)))
        || (initial_capacity != 0
            && (!disjoint(initial, initial_capacity, request, 1)
                || !disjoint(initial, initial_capacity, host_length, 1)
                || !disjoint(initial, initial_capacity, port, 1)
                || !disjoint(initial, initial_capacity, initial_length, 1)))
        || (host_capacity != 0
            && initial_capacity != 0
            && !disjoint(host, host_capacity, initial, initial_capacity))
    {
        return FfiStatus::InvalidArgument;
    }
    let admission = if replay {
        let Some(admission) = lock(&engine.replay_admission).clone() else {
            return FfiStatus::InvalidArgument;
        };
        Some(admission)
    } else {
        None
    };
    let mut state = lock(&engine.state);
    match &state.accept {
        AcceptState::Receiving(active) if *active == replay => return FfiStatus::WouldBlock,
        AcceptState::Offered {
            replay: active,
            handle,
            pending,
        } if *active == replay => {
            let host_bytes = pending.request().host.as_str().as_bytes();
            let initial_bytes = pending.initial_data();
            unsafe {
                request.write(*handle);
                host_length.write(u32::try_from(host_bytes.len()).unwrap_or(u32::MAX));
                port.write(pending.request().port.get());
                initial_length.write(u32::try_from(initial_bytes.len()).unwrap_or(u32::MAX));
            }
            if host_capacity < host_bytes.len() || initial_capacity < initial_bytes.len() {
                return FfiStatus::BufferTooSmall;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(host_bytes.as_ptr(), host, host_bytes.len());
                if !initial_bytes.is_empty() {
                    std::ptr::copy_nonoverlapping(
                        initial_bytes.as_ptr(),
                        initial,
                        initial_bytes.len(),
                    );
                }
            }
            return FfiStatus::Ok;
        }
        AcceptState::ReceiveFailed(active) if *active == replay => {
            state.accept = AcceptState::Idle;
            return FfiStatus::Failed;
        }
        AcceptState::Idle => {}
        _ => return FfiStatus::InvalidArgument,
    }
    let connection = match &state.connection {
        ConnectionState::Connecting => return FfiStatus::NotReady,
        ConnectionState::Failed => return FfiStatus::Failed,
        ConnectionState::Ready(connection) if connection.is_closed() => return FfiStatus::Failed,
        ConnectionState::Ready(connection) => connection.clone(),
    };
    state.accept = AcceptState::Receiving(replay);
    drop(state);
    let shared = Arc::clone(&engine.state);
    if engine
        .runtime
        .spawn(Box::pin(async move {
            let result = match admission {
                Some(admission) => connection.accept_replay_safe_flow(&admission, true).await,
                None => connection.accept_flow(true).await,
            };
            let mut state = lock(&shared);
            state.accept = match result {
                Ok(pending) => AcceptState::Offered {
                    replay,
                    handle: NEXT_REQUEST_HANDLE.fetch_add(1, Ordering::Relaxed),
                    pending,
                },
                Err(_) => AcceptState::ReceiveFailed(replay),
            };
        }))
        .is_err()
    {
        lock(&engine.state).accept = AcceptState::ReceiveFailed(replay);
        return FfiStatus::Failed;
    }
    FfiStatus::WouldBlock
}

/// Accepts one previously inspected flow request.
///
/// # Safety
///
/// `flow` must be writable and disjoint from the engine.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_accept_pending_flow(
    engine_pointer: *mut FfiEngine,
    request: u64,
    flow: *mut u64,
) -> FfiStatus {
    boundary(|| unsafe { poll_flow_decision(engine_pointer, request, true, flow) })
}

/// Rejects one previously inspected flow request with `POLICY_DENIED`.
///
/// # Safety
///
/// `engine` must be live and calls on it serialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_reject_pending_flow(
    engine_pointer: *mut FfiEngine,
    request: u64,
) -> FfiStatus {
    boundary(|| unsafe { poll_flow_decision(engine_pointer, request, false, std::ptr::null_mut()) })
}

unsafe fn poll_flow_decision(
    engine_pointer: *mut FfiEngine,
    request: u64,
    accept: bool,
    flow: *mut u64,
) -> FfiStatus {
    let Ok(engine) = engine(engine_pointer) else {
        return FfiStatus::InvalidArgument;
    };
    if engine.role != FfiRole::Server
        || request == 0
        || (accept && !valid_engine_output(engine_pointer, flow))
    {
        return FfiStatus::InvalidArgument;
    }
    let mut state = lock(&engine.state);
    match state.accept {
        AcceptState::Resolving {
            handle,
            accept: active,
        } if handle == request && active == accept => return FfiStatus::WouldBlock,
        AcceptState::Accepted {
            handle,
            flow: handle_flow,
        } if handle == request && accept => {
            unsafe { flow.write(handle_flow) };
            state.accept = AcceptState::Idle;
            return FfiStatus::Ok;
        }
        AcceptState::Rejected(handle) if handle == request && !accept => {
            state.accept = AcceptState::Idle;
            return FfiStatus::Ok;
        }
        AcceptState::ResolveFailed(active) if active == request => {
            state.accept = AcceptState::Idle;
            return FfiStatus::Failed;
        }
        AcceptState::Offered { handle, .. } if handle == request => {}
        _ => return FfiStatus::InvalidArgument,
    }
    let AcceptState::Offered {
        pending, handle, ..
    } = std::mem::replace(&mut state.accept, AcceptState::Idle)
    else {
        unreachable!("matching offered request")
    };
    state.accept = AcceptState::Resolving { handle, accept };
    drop(state);
    let shared = Arc::clone(&engine.state);
    if engine
        .runtime
        .spawn(Box::pin(async move {
            if accept {
                let result = pending.accept().await;
                let mut state = lock(&shared);
                state.accept = match result {
                    Ok(flow) => {
                        let flow = state.insert_flow(flow);
                        AcceptState::Accepted { handle, flow }
                    }
                    Err(_) => AcceptState::ResolveFailed(handle),
                };
            } else {
                let result = pending.reject(OpenStatus::PolicyDenied).await;
                lock(&shared).accept = if result.is_ok() {
                    AcceptState::Rejected(handle)
                } else {
                    AcceptState::ResolveFailed(handle)
                };
            }
        }))
        .is_err()
    {
        lock(&engine.state).accept = AcceptState::ResolveFailed(handle);
        return FfiStatus::Failed;
    }
    FfiStatus::WouldBlock
}

/// Installs replay admission policy for one server engine.
///
/// # Safety
///
/// `secret` must be readable and is copied before return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_configure_replay_admission(
    engine_pointer: *mut FfiEngine,
    secret: *const u8,
    secret_length: u32,
    epoch: u64,
    max_attempts: u32,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        let length = secret_length as usize;
        if engine.role != FfiRole::Server
            || secret.is_null()
            || !(32..=MAX_FFI_STRING_BYTES).contains(&length)
            || !disjoint(engine_pointer, 1, secret, length)
        {
            return FfiStatus::InvalidArgument;
        }
        let secret = unsafe { std::slice::from_raw_parts(secret, length) };
        let Ok(admission) = ReplayAdmission::new(secret, epoch, max_attempts as usize) else {
            return FfiStatus::InvalidArgument;
        };
        let mut slot = lock(&engine.replay_admission);
        if slot.is_some() {
            return FfiStatus::InvalidArgument;
        }
        *slot = Some(Arc::new(admission));
        FfiStatus::Ok
    })
}

/// Issues one replay token into caller-owned storage.
///
/// # Safety
///
/// `length` must be writable. `output` must be writable when capacity is sufficient.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_issue_replay_token(
    engine_pointer: *mut FfiEngine,
    now_seconds: u64,
    ttl_seconds: u64,
    output: *mut u8,
    capacity: u32,
    length: *mut u32,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        let capacity = capacity as usize;
        if engine.role != FfiRole::Server
            || !valid_engine_output(engine_pointer, length)
            || (capacity != 0
                && (output.is_null()
                    || !disjoint(engine_pointer, 1, output, capacity)
                    || !disjoint(output, capacity, length, 1)))
        {
            return FfiStatus::InvalidArgument;
        }
        let Some(admission) = lock(&engine.replay_admission).clone() else {
            return FfiStatus::InvalidArgument;
        };
        let state = lock(&engine.state);
        let ConnectionState::Ready(connection) = &state.connection else {
            return FfiStatus::NotReady;
        };
        let Ok(token) = connection.issue_replay_token(&admission, now_seconds, ttl_seconds) else {
            return FfiStatus::InvalidArgument;
        };
        let bytes = token.as_bytes();
        let Ok(required) = u32::try_from(bytes.len()) else {
            return FfiStatus::Failed;
        };
        unsafe { length.write(required) };
        if capacity < bytes.len() {
            return FfiStatus::BufferTooSmall;
        }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
        FfiStatus::Ok
    })
}

/// Reads ordered flow bytes.
///
/// # Safety
///
/// `output` and `read` must be writable and disjoint.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_flow_read(
    engine_pointer: *mut FfiEngine,
    handle: u64,
    output: *mut u8,
    capacity: u32,
    read: *mut u32,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        if output.is_null()
            || capacity == 0
            || !valid_engine_output(engine_pointer, read)
            || !disjoint(engine_pointer, 1, output, capacity as usize)
            || !disjoint(output, capacity as usize, read, 1)
        {
            return FfiStatus::InvalidArgument;
        }
        let output = unsafe { std::slice::from_raw_parts_mut(output, capacity as usize) };
        let mut state = lock(&engine.state);
        let Some(flow) = state.flow_mut(handle) else {
            return FfiStatus::Closed;
        };
        let mut context = Context::from_waker(std::task::Waker::noop());
        match QuicpFlow::poll_read(Pin::new(flow), &mut context, output) {
            Poll::Ready(Ok(count)) => {
                unsafe { read.write(u32::try_from(count).unwrap_or(u32::MAX)) };
                FfiStatus::Ok
            }
            Poll::Ready(Err(_)) => FfiStatus::Failed,
            Poll::Pending => FfiStatus::WouldBlock,
        }
    })
}

/// Writes flow bytes.
///
/// # Safety
///
/// `input` must be readable and `written` writable and disjoint.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_flow_write(
    engine_pointer: *mut FfiEngine,
    handle: u64,
    input: *const u8,
    length: u32,
    written: *mut u32,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        if input.is_null()
            || length == 0
            || !valid_engine_output(engine_pointer, written)
            || !disjoint(engine_pointer, 1, input, length as usize)
            || !disjoint(input, length as usize, written, 1)
        {
            return FfiStatus::InvalidArgument;
        }
        let input = unsafe { std::slice::from_raw_parts(input, length as usize) };
        let mut state = lock(&engine.state);
        let Some(flow) = state.flow_mut(handle) else {
            return FfiStatus::Closed;
        };
        let mut context = Context::from_waker(std::task::Waker::noop());
        match QuicpFlow::poll_write(Pin::new(flow), &mut context, input) {
            Poll::Ready(Ok(count)) => {
                unsafe { written.write(u32::try_from(count).unwrap_or(u32::MAX)) };
                FfiStatus::Ok
            }
            Poll::Ready(Err(_)) => FfiStatus::Failed,
            Poll::Pending => FfiStatus::WouldBlock,
        }
    })
}

/// Flushes accepted flow writes.
///
/// # Safety
///
/// Engine and handle must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_flow_flush(
    engine_pointer: *mut FfiEngine,
    handle: u64,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        let mut state = lock(&engine.state);
        let Some(flow) = state.flow_mut(handle) else {
            return FfiStatus::Closed;
        };
        let mut context = Context::from_waker(std::task::Waker::noop());
        match QuicpFlow::poll_flush(Pin::new(flow), &mut context) {
            Poll::Ready(Ok(())) => FfiStatus::Ok,
            Poll::Ready(Err(_)) => FfiStatus::Failed,
            Poll::Pending => FfiStatus::WouldBlock,
        }
    })
}

/// Flushes accepted writes and half-closes the flow send side.
///
/// # Safety
///
/// Engine and handle must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_flow_shutdown(
    engine_pointer: *mut FfiEngine,
    handle: u64,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        let mut state = lock(&engine.state);
        let Some(flow) = state.flow_mut(handle) else {
            return FfiStatus::Closed;
        };
        let mut context = Context::from_waker(std::task::Waker::noop());
        match QuicpFlow::poll_shutdown(Pin::new(flow), &mut context) {
            Poll::Ready(Ok(())) => FfiStatus::Ok,
            Poll::Ready(Err(_)) => FfiStatus::Failed,
            Poll::Pending => FfiStatus::WouldBlock,
        }
    })
}

/// Resets and releases one generation-checked flow handle.
///
/// # Safety
///
/// Engine must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_flow_close(
    engine_pointer: *mut FfiEngine,
    handle: u64,
) -> FfiStatus {
    boundary(|| {
        let Ok(engine) = engine(engine_pointer) else {
            return FfiStatus::InvalidArgument;
        };
        let Some(mut flow) = lock(&engine.state).remove_flow(handle) else {
            return FfiStatus::Closed;
        };
        match flow.reset(ApplicationError::FlowAbort) {
            Ok(()) => FfiStatus::Ok,
            Err(_) => FfiStatus::Failed,
        }
    })
}

/// Closes an engine and clears the caller's owner pointer.
///
/// # Safety
///
/// `engine` must point to the live owner variable returned by [`quicp_engine_create`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_engine_close(engine: *mut *mut FfiEngine) -> FfiStatus {
    boundary(|| {
        if !valid_mut(engine) {
            return FfiStatus::InvalidArgument;
        }
        let raw = unsafe { engine.read() };
        if raw.is_null() {
            return FfiStatus::Closed;
        }
        if !raw.is_aligned() {
            return FfiStatus::InvalidArgument;
        }
        if !disjoint(engine, 1, raw, 1) {
            return FfiStatus::InvalidArgument;
        }
        unsafe { engine.write(std::ptr::null_mut()) };
        unsafe { drop(Box::from_raw(raw)) };
        FfiStatus::Ok
    })
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Barrier};
    use std::task::{Context, Poll};

    use super::*;

    struct BlockingPoll {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }

    impl Future for BlockingPoll {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
            self.entered.wait();
            self.release.wait();
            Poll::Pending
        }
    }

    #[test]
    fn task_panic_latches_the_engine_failed() {
        let mut address = [0; 16];
        address[..4].copy_from_slice(&[127, 0, 0, 1]);
        let socket = |port| FfiSocketAddress {
            family: 4,
            port,
            reserved: 0,
            address,
        };
        let config = FfiEngineConfig {
            abi_version: ABI_VERSION,
            role: FfiRole::Client as u32,
            path_count: 1,
            paths: [
                FfiPathConfig {
                    local: socket(41_100),
                    peer: socket(41_101),
                },
                FfiPathConfig::default(),
            ],
            packet_capacity: 8,
            mtu: 1500,
            recovery_mode: FfiRecoveryMode::Adaptive as u32,
        };
        let engine = Box::new(FfiEngine::new(config, FfiSecurity::Insecure).unwrap());
        engine
            .runtime
            .spawn(Box::pin(async { panic!("contained test panic") }))
            .unwrap();
        let mut engine = Box::into_raw(engine);
        let mut processed = 0;
        assert_eq!(
            unsafe { quicp_engine_drive(engine, 0, 32, &raw mut processed) },
            FfiStatus::Failed
        );
        assert_eq!(
            unsafe { quicp_engine_connection_state(engine) },
            FfiStatus::Failed
        );
        assert_eq!(
            unsafe { quicp_engine_close(&raw mut engine) },
            FfiStatus::Ok
        );
    }

    #[test]
    fn concurrent_ffi_drive_is_rejected_without_poisoning_the_engine() {
        let mut address = [0; 16];
        address[..4].copy_from_slice(&[127, 0, 0, 1]);
        let socket = |port| FfiSocketAddress {
            family: 4,
            port,
            reserved: 0,
            address,
        };
        let config = FfiEngineConfig {
            abi_version: ABI_VERSION,
            role: FfiRole::Client as u32,
            path_count: 1,
            paths: [
                FfiPathConfig {
                    local: socket(41_110),
                    peer: socket(41_111),
                },
                FfiPathConfig::default(),
            ],
            packet_capacity: 8,
            mtu: 1500,
            recovery_mode: FfiRecoveryMode::Adaptive as u32,
        };
        let engine = Box::new(FfiEngine::new(config, FfiSecurity::Insecure).unwrap());
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        engine
            .runtime
            .spawn(Box::pin(BlockingPoll {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }))
            .unwrap();
        let mut engine = Box::into_raw(engine);
        let shared = engine as usize;
        let drive = std::thread::spawn(move || {
            let mut processed = 0;
            unsafe { quicp_engine_drive(shared as *mut FfiEngine, 0, 256, &raw mut processed) }
        });
        entered.wait();
        let mut processed = 0;
        assert_eq!(
            unsafe { quicp_engine_drive(engine, 0, 1, &raw mut processed) },
            FfiStatus::InvalidArgument
        );
        release.wait();
        assert_eq!(drive.join().unwrap(), FfiStatus::Ok);
        assert_eq!(
            unsafe { quicp_engine_drive(engine, 1, 1, &raw mut processed) },
            FfiStatus::Ok
        );
        assert_eq!(
            unsafe { quicp_engine_close(&raw mut engine) },
            FfiStatus::Ok
        );
    }
}
