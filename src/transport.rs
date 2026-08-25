use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
#[cfg(feature = "tls-rustls")]
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_core::Stream;
use noq::AsyncUdpSocket;
#[cfg(feature = "tls-rustls")]
use noq::crypto::rustls::{QuicClientConfig, QuicServerConfig};
#[cfg(feature = "tls-rustls")]
use noq::rustls::pki_types::pem::PemObject;
#[cfg(feature = "tls-rustls")]
use noq::rustls::pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(feature = "tls-rustls")]
use noq::rustls::server::WebPkiClientVerifier;
#[cfg(feature = "tls-rustls")]
use noq::rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use thiserror::Error;

use crate::config::{ClientConfig, ConfigError, MultipathMode, PmtuMode, ServerConfig};
#[cfg(feature = "tls-rustls")]
use crate::config::{TrustedFileMode, read_trusted_file};
use crate::congestion::TransportOptions;
use crate::faketcp::FourTuple;
use crate::flow::backend_error_code;
use crate::host_carrier::HostDatagramSocket;
use crate::host_runtime::HostRuntime;
use crate::multipath::{PathHealth, PathManager, PathRole};
use crate::no_security::{NoSecurityClientConfig, NoSecurityServerConfig};
use crate::session::{ApplicationError, ApplicationProfile};
use crate::{FlowError, OpenRequest, PendingFlow, QuicpFlow};

// The feature selects the executor adapter; child modules select only the OS syscalls they need.
#[cfg(feature = "runtime-tokio")]
#[path = "transport/tokio.rs"]
mod tokio_adapter;
#[cfg(all(test, unix, feature = "runtime-tokio"))]
pub(crate) use tokio_adapter::MultipathSocket;
#[cfg(all(test, unix, feature = "runtime-tokio"))]
pub(crate) use tokio_adapter::{
    SYN_COOKIE_EPOCH_SECONDS, configure_fake_tcp_paths, validate_fake_tcp_syn_data,
};
#[cfg(all(unix, feature = "runtime-tokio", feature = "internal-bench"))]
pub use tokio_adapter::{
    build_fake_tcp_client_endpoint, build_fake_tcp_client_endpoint_with_options,
    build_fake_tcp_server_endpoint, build_fake_tcp_server_endpoint_with_options,
};

#[cfg(feature = "tls-rustls")]
const MAX_TLS_FILE_BYTES: u64 = 1024 * 1024;
const BACKUP_PATH_RETRY_LIMIT: u8 = 16;
const BACKUP_PATH_RETRY_DELAY: Duration = Duration::from_millis(20);

#[derive(Clone, Copy, Debug)]
struct BackupPath {
    remote: SocketAddr,
    local_ip: IpAddr,
}

#[derive(Clone, Copy)]
struct ValidatedClientConfig<'a> {
    config: &'a ClientConfig,
}

impl<'a> ValidatedClientConfig<'a> {
    fn new(config: &'a ClientConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self { config })
    }
}

impl Deref for ValidatedClientConfig<'_> {
    type Target = ClientConfig;

    fn deref(&self) -> &Self::Target {
        self.config
    }
}

#[derive(Clone, Copy)]
struct ValidatedServerConfig<'a> {
    config: &'a ServerConfig,
}

impl<'a> ValidatedServerConfig<'a> {
    fn new(config: &'a ServerConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self { config })
    }
}

impl Deref for ValidatedServerConfig<'_> {
    type Target = ServerConfig;

    fn deref(&self) -> &Self::Target {
        self.config
    }
}

fn configured_backup_path(config: &ClientConfig) -> Option<BackupPath> {
    (config.multipath.mode == MultipathMode::Failover)
        .then(|| config.multipath.candidates.get(1))
        .flatten()
        .map(|candidate| BackupPath {
            remote: candidate.server_addr,
            local_ip: candidate.local_ip,
        })
}

/// A configured QUICP client endpoint.
#[derive(Debug)]
pub struct Client {
    endpoint: noq::Endpoint,
    server_addr: SocketAddr,
    server_name: String,
    runtime: Option<Arc<dyn noq::Runtime>>,
    backup_path: Option<BackupPath>,
    primary_tuple: Option<FourTuple>,
    flow_buffer_bytes: usize,
    default_nodelay: bool,
}

impl Client {
    #[cfg(all(test, feature = "runtime-tokio"))]
    fn from_endpoint(
        endpoint: noq::Endpoint,
        server_addr: SocketAddr,
        server_name: String,
    ) -> Self {
        Self::from_endpoint_with_runtime(
            endpoint,
            server_addr,
            server_name,
            None,
            None,
            None,
            crate::flow::RELAY_BUFFER_BYTES,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_endpoint_with_runtime(
        endpoint: noq::Endpoint,
        server_addr: SocketAddr,
        server_name: String,
        runtime: Option<Arc<dyn noq::Runtime>>,
        backup_path: Option<BackupPath>,
        primary_tuple: Option<FourTuple>,
        flow_buffer_bytes: usize,
        default_nodelay: bool,
    ) -> Self {
        Self {
            endpoint,
            server_addr,
            server_name,
            runtime,
            backup_path,
            primary_tuple,
            flow_buffer_bytes,
            default_nodelay,
        }
    }

    /// Creates a client endpoint from a host-owned datagram carrier and runtime.
    ///
    /// This constructor is the portable seam for iOS, Android, and other host event loops. The
    /// caller remains responsible for moving datagrams through `socket` and advancing `runtime`.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint or optional TLS configuration cannot be built.
    #[cfg(feature = "internal-bench")]
    pub fn from_socket(
        config: &ClientConfig,
        socket: Box<dyn noq::AsyncUdpSocket>,
        runtime: Arc<dyn noq::Runtime>,
        server_addr: SocketAddr,
        server_name: impl Into<String>,
    ) -> Result<Self, TransportError> {
        Self::from_socket_with_options_internal(
            ValidatedClientConfig::new(config)?,
            socket,
            runtime,
            server_addr,
            server_name,
            &TransportOptions::default(),
            None,
        )
    }

    /// Creates a client endpoint with runtime-neutral Rust extension options.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint construction or optional TLS configuration fails.
    #[cfg(feature = "internal-bench")]
    pub fn from_socket_with_options(
        config: &ClientConfig,
        socket: Box<dyn noq::AsyncUdpSocket>,
        runtime: Arc<dyn noq::Runtime>,
        server_addr: SocketAddr,
        server_name: impl Into<String>,
        options: &TransportOptions,
    ) -> Result<Self, TransportError> {
        Self::from_socket_with_options_internal(
            ValidatedClientConfig::new(config)?,
            socket,
            runtime,
            server_addr,
            server_name,
            options,
            None,
        )
    }

    fn from_socket_with_options_internal(
        config: ValidatedClientConfig<'_>,
        socket: Box<dyn noq::AsyncUdpSocket>,
        runtime: Arc<dyn noq::Runtime>,
        server_addr: SocketAddr,
        server_name: impl Into<String>,
        options: &TransportOptions,
        adapter_mtu: Option<u16>,
    ) -> Result<Self, TransportError> {
        if config.multipath.candidates[0].server_addr != server_addr {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client server address does not match the primary path candidate",
            )
            .into());
        }
        let runtime_for_client = Arc::clone(&runtime);
        let endpoint = build_client_endpoint_with_validated_config(
            config,
            socket,
            runtime,
            options,
            adapter_mtu,
        )?;
        Ok(Self::from_endpoint_with_runtime(
            endpoint,
            server_addr,
            server_name.into(),
            Some(runtime_for_client),
            configured_backup_path(&config),
            Some(FourTuple::new(
                SocketAddr::new(config.multipath.candidates[0].local_ip, 0),
                server_addr,
            )),
            config.transport().flow_write_buffer_bytes as usize,
            config.transport().default_nodelay,
        ))
    }

    /// Creates a portable client from the built-in host-driven carrier and runtime.
    ///
    /// This is the stable convenience seam for hosts that do not want to depend on the backend
    /// socket/runtime traits. The host still owns packet ingress/egress and bounded progress.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint or optional TLS configuration cannot be built.
    pub fn from_host_socket(
        config: &ClientConfig,
        socket: HostDatagramSocket,
        runtime: Arc<HostRuntime>,
    ) -> Result<Self, TransportError> {
        Self::from_host_socket_with_options(config, socket, runtime, &TransportOptions::default())
    }

    /// Creates a portable client from the built-in host-driven carrier with extension options.
    ///
    /// The host still owns packet ingress/egress and bounded runtime progress.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint or optional TLS configuration cannot be built.
    pub fn from_host_socket_with_options(
        config: &ClientConfig,
        socket: HostDatagramSocket,
        runtime: Arc<HostRuntime>,
        options: &TransportOptions,
    ) -> Result<Self, TransportError> {
        let config = ValidatedClientConfig::new(config)?;
        if config.multipath.mode != MultipathMode::Off {
            return Err(TransportError::UnsupportedMultipathCarrier);
        }
        let local_addr = socket.local_addr();
        let expected_local_ip = config.multipath.candidates[0].local_ip;
        if local_addr.ip() != expected_local_ip {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "host client local address {local_addr} does not match configured local IP {expected_local_ip}"
                ),
            )
            .into());
        }
        let server_addr = socket.peer_addr();
        let adapter_mtu = u16::try_from(socket.mtu()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "host datagram MTU exceeds u16")
        })?;
        let server_name = config
            .tls()
            .map_or_else(|| "quicp".to_owned(), |tls| tls.server_name().to_owned());
        Self::from_socket_with_options_internal(
            config,
            Box::new(socket),
            runtime,
            server_addr,
            server_name,
            options,
            Some(adapter_mtu),
        )
    }

    /// Connects to the configured server.
    ///
    /// # Errors
    ///
    /// Returns an error when connection setup or the handshake fails.
    pub async fn connect(&self) -> Result<Connection, ConnectionError> {
        let connecting = self
            .endpoint
            .connect(self.server_addr, &self.server_name)
            .map_err(|error| ConnectionError::Connect(Box::new(error)))?;
        let backend = connecting
            .await
            .map_err(|error| ConnectionError::Handshake(Box::new(error)))?;
        // Subscribe before opening the backup path; validation and the peer's status can be
        // reported back-to-back and the bounded stream must not lose either event.
        let path_events = backend.path_events();
        let backup_path = if let Some(backup) = self.backup_path {
            let Some(runtime) = self.runtime.as_ref() else {
                backend.close(
                    backend_error_code(ApplicationError::MultipathRequired),
                    b"missing multipath runtime",
                );
                return Err(ConnectionError::Multipath(Box::new(io::Error::other(
                    "multipath runtime is unavailable",
                ))));
            };
            let path = match open_backup_path(
                &backend,
                noq::FourTuple::new(backup.remote, Some(backup.local_ip)),
                runtime.as_ref(),
            )
            .await
            {
                Ok(path) => path,
                Err(error) => {
                    backend.close(
                        backend_error_code(ApplicationError::MultipathRequired),
                        b"backup path unavailable",
                    );
                    return Err(ConnectionError::Multipath(Box::new(error)));
                }
            };
            Some(path)
        } else {
            None
        };
        let path_manager =
            build_client_path_manager(self.primary_tuple, self.backup_path, backup_path.as_ref())
                .map_err(|error| {
                backend.close(
                    backend_error_code(ApplicationError::MultipathRequired),
                    b"invalid path state",
                );
                ConnectionError::Multipath(Box::new(error))
            })?;
        if let Some(runtime) = self.runtime.as_ref() {
            spawn_path_event_monitor(
                runtime,
                backend.weak_handle(),
                Arc::clone(&path_manager),
                runtime.now(),
                path_events,
            );
        }
        Ok(Connection::client(
            backend,
            backup_path,
            path_manager,
            self.flow_buffer_bytes,
            self.default_nodelay,
        ))
    }
}

fn build_client_path_manager(
    primary_tuple: Option<FourTuple>,
    backup_config: Option<BackupPath>,
    backup_path: Option<&noq::Path>,
) -> Result<Arc<Mutex<PathManager>>, crate::multipath::PathError> {
    let mode = backup_config.map_or(MultipathMode::Off, |_| MultipathMode::Failover);
    let mut manager = PathManager::new(mode);
    manager.begin_path(PathRole::Primary, noq::PathId::ZERO, 0)?;
    if let Some(tuple) = primary_tuple {
        manager.bind_carrier_tuple(noq::PathId::ZERO, tuple)?;
    }
    manager.established(noq::PathId::ZERO)?;
    manager.remote_status(noq::PathId::ZERO, noq::PathStatus::Available)?;
    if let (Some(backup_config), Some(backup_path)) = (backup_config, backup_path) {
        let id = backup_path.id();
        manager.begin_path(PathRole::Backup, id, 0)?;
        manager.bind_carrier_tuple(
            id,
            FourTuple::new(
                SocketAddr::new(backup_config.local_ip, 0),
                backup_config.remote,
            ),
        )?;
        manager.established(id)?;
    }
    Ok(Arc::new(Mutex::new(manager)))
}

fn spawn_path_event_monitor(
    runtime: &Arc<dyn noq::Runtime>,
    weak_connection: noq::WeakConnectionHandle,
    manager: Arc<Mutex<PathManager>>,
    epoch: std::time::Instant,
    mut events: noq::PathEvents,
) {
    let runtime = Arc::clone(runtime);
    let runtime_for_task = Arc::clone(&runtime);
    runtime.spawn(Box::pin(async move {
        loop {
            let event = std::future::poll_fn(|cx| Pin::new(&mut events).poll_next(cx)).await;
            let Some(event) = event else {
                return;
            };
            let now_seconds = runtime_for_task
                .now()
                .saturating_duration_since(epoch)
                .as_secs();
            let result = if let Ok(event) = event {
                lock_budget(&manager).apply_noq_event(&event, now_seconds)
            } else {
                lock_budget(&manager).event_lagged();
                Err(crate::multipath::PathError::Unreliable)
            };
            if result.is_err() {
                if let Some(connection) = weak_connection.upgrade() {
                    connection.close(
                        backend_error_code(ApplicationError::MultipathRequired),
                        b"unreliable path events",
                    );
                }
                return;
            }
        }
    }));
}

async fn open_backup_path(
    connection: &noq::Connection,
    network_path: noq::FourTuple,
    runtime: &dyn noq::Runtime,
) -> Result<noq::Path, noq::PathError> {
    for attempt in 0..BACKUP_PATH_RETRY_LIMIT {
        match connection
            .open_path(network_path, noq::PathStatus::Backup)
            .await
        {
            Ok(path) => return Ok(path),
            Err(noq::PathError::RemoteCidsExhausted) if attempt + 1 < BACKUP_PATH_RETRY_LIMIT => {
                let mut timer = runtime.new_timer(runtime.now() + BACKUP_PATH_RETRY_DELAY);
                poll_fn(|cx| timer.as_mut().poll(cx)).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(noq::PathError::RemoteCidsExhausted)
}

/// A configured QUICP server endpoint.
#[derive(Debug)]
pub struct Server {
    endpoint: noq::Endpoint,
    active_connections: Arc<ConnectionBudget>,
    flow_buffer_bytes: usize,
    default_nodelay: bool,
}

impl Server {
    #[cfg(all(test, feature = "runtime-tokio"))]
    fn from_endpoint(endpoint: noq::Endpoint) -> Self {
        Self::from_endpoint_with_limits(endpoint, 128, 16, crate::flow::RELAY_BUFFER_BYTES, true)
    }

    fn from_endpoint_with_config(endpoint: noq::Endpoint, config: &ServerConfig) -> Self {
        Self::from_endpoint_with_limits(
            endpoint,
            usize::from(config.transport().max_active_connections),
            usize::from(config.transport().max_active_connections_per_peer),
            config.transport().flow_write_buffer_bytes as usize,
            config.transport().default_nodelay,
        )
    }

    fn from_endpoint_with_limits(
        endpoint: noq::Endpoint,
        max_active_connections: usize,
        max_active_connections_per_peer: usize,
        flow_buffer_bytes: usize,
        default_nodelay: bool,
    ) -> Self {
        Self {
            endpoint,
            active_connections: Arc::new(ConnectionBudget::new(
                max_active_connections,
                max_active_connections_per_peer,
            )),
            flow_buffer_bytes,
            default_nodelay,
        }
    }

    /// Creates a server endpoint from a host-owned datagram carrier and runtime.
    ///
    /// The caller remains responsible for moving datagrams through `socket` and advancing
    /// `runtime`; no OS socket or executor is created by this constructor.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint or optional TLS configuration cannot be built.
    #[cfg(feature = "internal-bench")]
    pub fn from_socket(
        config: &ServerConfig,
        socket: Box<dyn noq::AsyncUdpSocket>,
        runtime: Arc<dyn noq::Runtime>,
    ) -> Result<Self, TransportError> {
        Self::from_socket_with_options_internal(
            ValidatedServerConfig::new(config)?,
            socket,
            runtime,
            &TransportOptions::default(),
            None,
        )
    }

    /// Creates a server endpoint with runtime-neutral Rust extension options.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint construction or optional TLS configuration fails.
    #[cfg(feature = "internal-bench")]
    pub fn from_socket_with_options(
        config: &ServerConfig,
        socket: Box<dyn noq::AsyncUdpSocket>,
        runtime: Arc<dyn noq::Runtime>,
        options: &TransportOptions,
    ) -> Result<Self, TransportError> {
        Self::from_socket_with_options_internal(
            ValidatedServerConfig::new(config)?,
            socket,
            runtime,
            options,
            None,
        )
    }

    fn from_socket_with_options_internal(
        config: ValidatedServerConfig<'_>,
        socket: Box<dyn noq::AsyncUdpSocket>,
        runtime: Arc<dyn noq::Runtime>,
        options: &TransportOptions,
        adapter_mtu: Option<u16>,
    ) -> Result<Self, TransportError> {
        let endpoint = build_server_endpoint_with_validated_config(
            config,
            socket,
            runtime,
            options,
            adapter_mtu,
        )?;
        Ok(Self::from_endpoint_with_config(endpoint, &config))
    }

    /// Creates a portable server from the built-in host-driven carrier and runtime.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint or optional TLS configuration cannot be built.
    pub fn from_host_socket(
        config: &ServerConfig,
        socket: HostDatagramSocket,
        runtime: Arc<HostRuntime>,
    ) -> Result<Self, TransportError> {
        Self::from_host_socket_with_options(config, socket, runtime, &TransportOptions::default())
    }

    /// Creates a portable server from the built-in host-driven carrier with extension options.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint or optional TLS configuration cannot be built.
    pub fn from_host_socket_with_options(
        config: &ServerConfig,
        socket: HostDatagramSocket,
        runtime: Arc<HostRuntime>,
        options: &TransportOptions,
    ) -> Result<Self, TransportError> {
        let config = ValidatedServerConfig::new(config)?;
        let local_addr = socket.local_addr();
        if !listen_addr_admits(&config.listen_addrs, local_addr) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "host server local address {local_addr} is outside the configured listen allowlist"
                ),
            )
            .into());
        }
        let adapter_mtu = u16::try_from(socket.mtu()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "host datagram MTU exceeds u16")
        })?;
        Self::from_socket_with_options_internal(
            config,
            Box::new(socket),
            runtime,
            options,
            Some(adapter_mtu),
        )
    }

    /// Accepts the next connection attempt without waiting for its handshake.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint is closed.
    pub async fn accept(&self) -> Result<IncomingConnection, ConnectionError> {
        self.endpoint
            .accept()
            .await
            .map(|incoming| IncomingConnection {
                peer: incoming.remote_address(),
                incoming,
                active_connections: Arc::clone(&self.active_connections),
                flow_buffer_bytes: self.flow_buffer_bytes,
                default_nodelay: self.default_nodelay,
            })
            .ok_or(ConnectionError::EndpointClosed)
    }
}

/// A server-side connection attempt whose handshake has not completed.
#[derive(Debug)]
pub struct IncomingConnection {
    incoming: noq::Incoming,
    peer: SocketAddr,
    active_connections: Arc<ConnectionBudget>,
    flow_buffer_bytes: usize,
    default_nodelay: bool,
}

impl IncomingConnection {
    /// Completes the connection handshake.
    ///
    /// # Errors
    ///
    /// Returns an error when the handshake fails.
    pub async fn handshake(self) -> Result<Connection, ConnectionError> {
        let Self {
            incoming,
            peer,
            active_connections,
            flow_buffer_bytes,
            default_nodelay,
        } = self;
        let Some(permit) = active_connections.try_acquire(peer) else {
            incoming.refuse();
            return Err(ConnectionError::ResourceLimit);
        };
        incoming
            .await
            .map(|backend| Connection::server(backend, permit, flow_buffer_bytes, default_nodelay))
            .map_err(|error| ConnectionError::Handshake(Box::new(error)))
    }
}

/// An established QUICP connection.
#[derive(Clone, Debug)]
pub struct Connection {
    backend: noq::Connection,
    permit: Option<Arc<ConnectionPermit>>,
    backup_path: Option<noq::Path>,
    path_manager: Option<Arc<Mutex<PathManager>>>,
    flow_buffer_bytes: usize,
    default_nodelay: bool,
}

impl Connection {
    fn client(
        backend: noq::Connection,
        backup_path: Option<noq::Path>,
        path_manager: Arc<Mutex<PathManager>>,
        flow_buffer_bytes: usize,
        default_nodelay: bool,
    ) -> Self {
        Self {
            backend,
            permit: None,
            backup_path,
            path_manager: Some(path_manager),
            flow_buffer_bytes,
            default_nodelay,
        }
    }

    fn server(
        backend: noq::Connection,
        permit: Arc<ConnectionPermit>,
        flow_buffer_bytes: usize,
        default_nodelay: bool,
    ) -> Self {
        Self {
            backend,
            permit: Some(permit),
            backup_path: None,
            path_manager: None,
            flow_buffer_bytes,
            default_nodelay,
        }
    }
}

impl Connection {
    /// Returns an identifier stable for the lifetime of this connection.
    #[must_use]
    pub fn stable_id(&self) -> usize {
        self.backend.stable_id()
    }

    /// Returns whether the configured client backup path is validated and usable.
    ///
    /// A value of `false` means that the connection is single-path, server-side, or that the
    /// validated backup path has since been abandoned or the peer has not advertised the expected
    /// status. This is a local state hint; it does not replace packet-level liveness.
    #[must_use]
    pub fn backup_ready(&self) -> bool {
        self.backup_path.as_ref().is_some_and(|path| {
            path.status().is_ok()
                && self.path_health().is_some_and(|health| {
                    matches!(health, PathHealth::Ready | PathHealth::Degraded)
                })
        })
    }

    /// Returns the locally observed health of this client connection's path set.
    ///
    /// Server-side connections return `None` because the server facade does not yet retain the
    /// client's path-role configuration.
    #[must_use]
    pub fn path_health(&self) -> Option<PathHealth> {
        self.path_manager
            .as_ref()
            .map(|manager| lock_budget(manager).health())
    }

    /// Opens one application flow.
    ///
    /// # Errors
    ///
    /// Returns an error when OPEN/STATUS exchange or stream setup fails.
    pub async fn open_flow(
        &self,
        request: OpenRequest,
        current_policy_authorized: bool,
    ) -> Result<QuicpFlow, FlowError> {
        QuicpFlow::open_backend(
            &self.backend,
            request,
            current_policy_authorized,
            self.permit.clone(),
            self.flow_buffer_bytes,
            self.default_nodelay,
        )
        .await
    }

    /// Accepts the next application flow.
    ///
    /// # Errors
    ///
    /// Returns an error when no stream is available or OPEN is invalid.
    pub async fn accept_flow(
        &self,
        current_policy_authorized: bool,
    ) -> Result<PendingFlow, FlowError> {
        crate::flow::accept_flow_backend(
            &self.backend,
            current_policy_authorized,
            self.permit.clone(),
            self.flow_buffer_bytes,
            self.default_nodelay,
        )
        .await
    }

    /// Closes this connection immediately.
    pub fn close(&self, error: ApplicationError, reason: &[u8]) {
        self.backend.close(backend_error_code(error), reason);
    }

    #[cfg(all(test, feature = "runtime-tokio"))]
    fn backend(&self) -> &noq::Connection {
        &self.backend
    }
}

#[derive(Debug)]
struct ConnectionBudget {
    state: Mutex<BudgetState>,
    max_active: usize,
    max_per_peer: usize,
}

impl ConnectionBudget {
    fn new(max_active: usize, max_per_peer: usize) -> Self {
        Self {
            state: Mutex::new(BudgetState {
                active: 0,
                per_peer: HashMap::new(),
            }),
            max_active,
            max_per_peer,
        }
    }

    fn try_acquire(self: &Arc<Self>, peer: SocketAddr) -> Option<Arc<ConnectionPermit>> {
        let mut state = lock_budget(&self.state);
        let peer_active = state.per_peer.get(&peer).copied().unwrap_or(0);
        if state.active >= self.max_active || peer_active >= self.max_per_peer {
            return None;
        }
        state.active += 1;
        *state.per_peer.entry(peer).or_default() += 1;
        Some(Arc::new(ConnectionPermit {
            budget: Arc::clone(self),
            peer,
        }))
    }
}

#[derive(Debug)]
struct BudgetState {
    active: usize,
    per_peer: HashMap<SocketAddr, usize>,
}

#[derive(Debug)]
pub(crate) struct ConnectionPermit {
    budget: Arc<ConnectionBudget>,
    peer: SocketAddr,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut state = lock_budget(&self.budget.state);
        state.active = state.active.saturating_sub(1);
        if let Some(active) = state.per_peer.get_mut(&self.peer) {
            *active = active.saturating_sub(1);
            if *active == 0 {
                state.per_peer.remove(&self.peer);
            }
        }
    }
}

fn lock_budget<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Connection establishment, endpoint-capacity, and multipath setup errors.
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// Starting a backend connection failed.
    #[error("starting QUICP connection: {0}")]
    Connect(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The QUIC handshake or QUICP admission failed.
    #[error("establishing QUICP connection: {0}")]
    Handshake(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The endpoint closed before producing a connection.
    #[error("QUICP endpoint is closed")]
    EndpointClosed,
    /// The server active-connection budget is exhausted.
    #[error("QUICP server active-connection limit reached")]
    ResourceLimit,
    /// Required multipath setup or monitoring failed.
    #[error("QUICP multipath setup failed: {0}")]
    Multipath(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Builds the current `noq` backend's TLS 1.3 profile.
///
/// TLS is an optional QUICP security layer, not part of the no-security protocol baseline. This
/// builder belongs to the temporary TLS-backed adapter and is not the QUICP core interface.
///
/// # Errors
///
/// Returns an error for unsafe files, malformed PEM, invalid certificates or keys, or an
/// incompatible crypto provider.
pub fn build_client_config(config: &ClientConfig) -> Result<noq::ClientConfig, TransportError> {
    build_client_config_with_options(config, &TransportOptions::default())
}

/// Builds a client backend configuration with runtime-neutral Rust extension options.
///
/// # Errors
///
/// Returns an error when security configuration or optional TLS material is invalid.
pub fn build_client_config_with_options(
    config: &ClientConfig,
    options: &TransportOptions,
) -> Result<noq::ClientConfig, TransportError> {
    build_client_config_with_options_and_payload(ValidatedClientConfig::new(config)?, options, None)
}

fn build_client_config_with_options_and_payload(
    config: ValidatedClientConfig<'_>,
    options: &TransportOptions,
    payload_ceiling: Option<u16>,
) -> Result<noq::ClientConfig, TransportError> {
    let custom_header_protection = options.custom_header_protection();
    if config.tls.is_some() && custom_header_protection.is_some() {
        return Err(TransportError::HeaderProtectionWithTls);
    }
    let profile_token = ApplicationProfile::from(config.multipath.mode).profile_token();
    let mut transport = match config.tls.as_ref() {
        Some(tls) => {
            #[cfg(feature = "tls-rustls")]
            {
                let mut crypto = RustlsClientConfig::builder_with_provider(Arc::new(
                    noq::rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[&noq::rustls::version::TLS13])
                .map_err(tls_error)?
                .with_root_certificates(load_roots(&tls.ca_cert)?)
                .with_client_auth_cert(
                    load_certificates(&tls.client_cert)?,
                    load_private_key(&tls.client_key)?,
                )
                .map_err(tls_error)?;
                crypto.alpn_protocols = vec![profile_token.to_vec()];
                // Transport 0-RTT is not part of the admitted QUICP profile.
                crypto.enable_early_data = false;
                noq::ClientConfig::new(Arc::new(
                    QuicClientConfig::try_from(crypto).map_err(tls_error)?,
                ))
            }
            #[cfg(not(feature = "tls-rustls"))]
            {
                let _ = tls;
                return Err(TransportError::TlsFeatureDisabled);
            }
        }
        None => noq::ClientConfig::new(Arc::new(NoSecurityClientConfig::new(
            profile_token,
            custom_header_protection,
        ))),
    };
    let transport_config = crate::multipath::backend_transport_config_with_options(
        config.multipath.mode,
        config.transport(),
        options.custom_congestion(),
        payload_ceiling,
    );
    transport.transport_config(Arc::new(transport_config));
    Ok(transport)
}

/// Builds the current `noq` backend's TLS 1.3 mutual-authentication profile for both QUICP
/// profile tokens.
///
/// # Errors
///
/// Returns an error for unsafe files, malformed PEM, invalid certificates or keys, or an
/// incompatible crypto provider.
pub fn build_server_config(config: &ServerConfig) -> Result<noq::ServerConfig, TransportError> {
    build_server_config_with_options(config, &TransportOptions::default())
}

/// Builds a server backend configuration with runtime-neutral Rust extension options.
///
/// # Errors
///
/// Returns an error when security configuration or optional TLS material is invalid.
pub fn build_server_config_with_options(
    config: &ServerConfig,
    options: &TransportOptions,
) -> Result<noq::ServerConfig, TransportError> {
    build_server_config_with_options_and_payload(ValidatedServerConfig::new(config)?, options, None)
}

fn build_server_config_with_options_and_payload(
    config: ValidatedServerConfig<'_>,
    options: &TransportOptions,
    payload_ceiling: Option<u16>,
) -> Result<noq::ServerConfig, TransportError> {
    let custom_header_protection = options.custom_header_protection();
    if config.tls.is_some() && custom_header_protection.is_some() {
        return Err(TransportError::HeaderProtectionWithTls);
    }
    let mut transport = match config.tls.as_ref() {
        Some(tls) => {
            #[cfg(feature = "tls-rustls")]
            {
                let provider = Arc::new(noq::rustls::crypto::ring::default_provider());
                let client_verifier = WebPkiClientVerifier::builder_with_provider(
                    Arc::new(load_roots(&tls.client_ca)?),
                    Arc::clone(&provider),
                )
                .build()
                .map_err(tls_error)?;
                let mut crypto = noq::rustls::ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&noq::rustls::version::TLS13])
                    .map_err(tls_error)?
                    .with_client_cert_verifier(client_verifier)
                    .with_single_cert(
                        load_certificates(&tls.server_cert)?,
                        load_private_key(&tls.server_key)?,
                    )
                    .map_err(tls_error)?;
                crypto.alpn_protocols = [
                    ApplicationProfile::SinglePath,
                    ApplicationProfile::Multipath,
                ]
                .into_iter()
                .map(|profile| profile.profile_token().to_vec())
                .collect();
                // Transport 0-RTT is not part of the admitted QUICP profile.
                crypto.max_early_data_size = 0;
                noq::ServerConfig::with_crypto(Arc::new(
                    QuicServerConfig::try_from(crypto).map_err(tls_error)?,
                ))
            }
            #[cfg(not(feature = "tls-rustls"))]
            {
                let _ = tls;
                return Err(TransportError::TlsFeatureDisabled);
            }
        }
        None => noq::ServerConfig::with_crypto(Arc::new(NoSecurityServerConfig::new(
            custom_header_protection,
        ))),
    };
    let transport_config = crate::multipath::backend_transport_config_with_options(
        MultipathMode::Failover,
        config.transport(),
        options.custom_congestion(),
        payload_ceiling,
    );
    transport
        .transport_config(Arc::new(transport_config))
        .max_incoming(usize::from(config.transport().max_pending_handshakes))
        .incoming_buffer_size(u64::from(config.transport().pending_handshake_buffer_bytes))
        .incoming_buffer_size_total(
            u64::from(config.transport().max_pending_handshakes)
                * u64::from(config.transport().pending_handshake_buffer_bytes),
        );
    Ok(transport)
}

/// Builds a client endpoint from a runtime-owned datagram socket.
///
/// The caller supplies both `noq` runtime traits, so Tokio or another runtime/event loop can
/// provide the carrier without changing QUICP's protocol or application configuration.
///
/// # Errors
///
/// Returns an error when endpoint construction or the optional TLS-backed adapter configuration
/// fails.
pub fn build_client_endpoint_with_socket(
    config: &ClientConfig,
    socket: Box<dyn noq::AsyncUdpSocket>,
    runtime: Arc<dyn noq::Runtime>,
) -> Result<noq::Endpoint, TransportError> {
    build_client_endpoint_with_socket_and_options(
        config,
        socket,
        runtime,
        &TransportOptions::default(),
    )
}

/// Builds a client endpoint with runtime-neutral Rust extension options.
///
/// # Errors
///
/// Returns an error when endpoint construction or optional TLS configuration fails.
pub fn build_client_endpoint_with_socket_and_options(
    config: &ClientConfig,
    socket: Box<dyn noq::AsyncUdpSocket>,
    runtime: Arc<dyn noq::Runtime>,
    options: &TransportOptions,
) -> Result<noq::Endpoint, TransportError> {
    build_client_endpoint_with_socket_and_options_and_mtu(config, socket, runtime, options, None)
}

fn build_client_endpoint_with_socket_and_options_and_mtu(
    config: &ClientConfig,
    socket: Box<dyn noq::AsyncUdpSocket>,
    runtime: Arc<dyn noq::Runtime>,
    options: &TransportOptions,
    adapter_mtu: Option<u16>,
) -> Result<noq::Endpoint, TransportError> {
    build_client_endpoint_with_validated_config(
        ValidatedClientConfig::new(config)?,
        socket,
        runtime,
        options,
        adapter_mtu,
    )
}

fn build_client_endpoint_with_validated_config(
    config: ValidatedClientConfig<'_>,
    socket: Box<dyn noq::AsyncUdpSocket>,
    runtime: Arc<dyn noq::Runtime>,
    options: &TransportOptions,
    adapter_mtu: Option<u16>,
) -> Result<noq::Endpoint, TransportError> {
    let payload_ceiling = effective_payload_ceiling(&config, socket.as_ref(), adapter_mtu)?;
    let mut endpoint_config = noq::EndpointConfig::default();
    endpoint_config.grease_quic_bit(config.tls.is_some());
    endpoint_config
        .max_udp_payload_size(payload_ceiling)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let endpoint = noq::Endpoint::new_with_abstract_socket(endpoint_config, None, socket, runtime)?;
    endpoint.set_default_client_config(build_client_config_with_options_and_payload(
        config,
        options,
        Some(payload_ceiling),
    )?);
    Ok(endpoint)
}

/// Builds a server endpoint from a runtime-owned datagram socket.
///
/// # Errors
///
/// Returns an error when endpoint construction or the optional TLS-backed adapter configuration
/// fails.
pub fn build_server_endpoint_with_socket(
    config: &ServerConfig,
    socket: Box<dyn noq::AsyncUdpSocket>,
    runtime: Arc<dyn noq::Runtime>,
) -> Result<noq::Endpoint, TransportError> {
    build_server_endpoint_with_socket_and_options(
        config,
        socket,
        runtime,
        &TransportOptions::default(),
    )
}

/// Builds a server endpoint with runtime-neutral Rust extension options.
///
/// # Errors
///
/// Returns an error when endpoint construction or optional TLS configuration fails.
pub fn build_server_endpoint_with_socket_and_options(
    config: &ServerConfig,
    socket: Box<dyn noq::AsyncUdpSocket>,
    runtime: Arc<dyn noq::Runtime>,
    options: &TransportOptions,
) -> Result<noq::Endpoint, TransportError> {
    build_server_endpoint_with_socket_and_options_and_mtu(config, socket, runtime, options, None)
}

fn build_server_endpoint_with_socket_and_options_and_mtu(
    config: &ServerConfig,
    socket: Box<dyn noq::AsyncUdpSocket>,
    runtime: Arc<dyn noq::Runtime>,
    options: &TransportOptions,
    adapter_mtu: Option<u16>,
) -> Result<noq::Endpoint, TransportError> {
    build_server_endpoint_with_validated_config(
        ValidatedServerConfig::new(config)?,
        socket,
        runtime,
        options,
        adapter_mtu,
    )
}

fn build_server_endpoint_with_validated_config(
    config: ValidatedServerConfig<'_>,
    socket: Box<dyn noq::AsyncUdpSocket>,
    runtime: Arc<dyn noq::Runtime>,
    options: &TransportOptions,
    adapter_mtu: Option<u16>,
) -> Result<noq::Endpoint, TransportError> {
    let payload_ceiling = effective_server_payload_ceiling(&config, socket.as_ref(), adapter_mtu)?;
    let mut endpoint_config = noq::EndpointConfig::default();
    endpoint_config.grease_quic_bit(config.tls.is_some());
    endpoint_config
        .max_udp_payload_size(payload_ceiling)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    Ok(noq::Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(build_server_config_with_options_and_payload(
            config,
            options,
            Some(payload_ceiling),
        )?),
        socket,
        runtime,
    )?)
}

fn effective_payload_ceiling(
    config: &ClientConfig,
    socket: &dyn AsyncUdpSocket,
    adapter_mtu: Option<u16>,
) -> Result<u16, TransportError> {
    effective_payload_ceiling_inner(&config.transport().mtu, socket, adapter_mtu)
}

fn effective_server_payload_ceiling(
    config: &ServerConfig,
    socket: &dyn AsyncUdpSocket,
    adapter_mtu: Option<u16>,
) -> Result<u16, TransportError> {
    effective_payload_ceiling_inner(&config.transport().mtu, socket, adapter_mtu)
}

fn effective_payload_ceiling_inner(
    mtu: &crate::config::MtuConfig,
    socket: &dyn AsyncUdpSocket,
    adapter_mtu: Option<u16>,
) -> Result<u16, TransportError> {
    let local = socket.local_addr()?;
    if mtu.pmtu == PmtuMode::Required && socket.may_fragment() {
        return Err(ConfigError::PmtuRequiresNonFragmentingCarrier.into());
    }
    let adapter_mtu = adapter_mtu.or_else(|| {
        socket
            .may_fragment()
            .then(|| mtu.outer_ip_mtu.saturating_sub(28))
    });
    let families = (!socket.may_fragment()).then_some([local.is_ipv4()]);
    let ceiling = match families {
        Some(family) => mtu.static_payload_ceiling(adapter_mtu, family)?,
        None => mtu.static_payload_ceiling(adapter_mtu, [])?,
    };
    if ceiling < mtu.initial_quic_payload || ceiling < mtu.min_quic_payload {
        return Err(ConfigError::PayloadExceedsCarrier {
            payload: mtu.initial_quic_payload.max(mtu.min_quic_payload),
            maximum: ceiling,
        }
        .into());
    }
    Ok(ceiling)
}

fn listen_addr_admits(allowlist: &[SocketAddr], actual: SocketAddr) -> bool {
    allowlist.iter().copied().any(|allowed| {
        allowed.is_ipv4() == actual.is_ipv4()
            && allowed.port() == actual.port()
            && (allowed.ip().is_unspecified() || allowed.ip() == actual.ip())
    })
}

#[cfg(feature = "tls-rustls")]
fn load_roots(path: &Path) -> Result<RootCertStore, TransportError> {
    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(path)? {
        roots.add(certificate).map_err(tls_error)?;
    }
    Ok(roots)
}

#[cfg(feature = "tls-rustls")]
fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    let bytes = read_trusted_file(path, MAX_TLS_FILE_BYTES, TrustedFileMode::SharedReadable)?;
    let certificates = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(tls_error)?;
    if certificates.is_empty() {
        return Err(TransportError::EmptyCertificateFile(path.to_owned()));
    }
    Ok(certificates)
}

#[cfg(feature = "tls-rustls")]
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TransportError> {
    PrivateKeyDer::from_pem_slice(&read_trusted_file(
        path,
        MAX_TLS_FILE_BYTES,
        TrustedFileMode::OwnerOnly,
    )?)
    .map_err(tls_error)
}

#[cfg(feature = "tls-rustls")]
fn tls_error(error: impl std::error::Error + Send + Sync + 'static) -> TransportError {
    TransportError::Tls(Box::new(error))
}

/// Endpoint construction, configuration, security-adapter, and carrier errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Operating-system or adapter I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Endpoint-boundary configuration validation failed.
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[cfg(feature = "tls-rustls")]
    /// TLS material or provider configuration failed.
    #[error("TLS configuration failed: {0}")]
    Tls(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[cfg(feature = "tls-rustls")]
    /// A certificate-chain file contained no certificates.
    #[error("certificate file is empty: {0}")]
    EmptyCertificateFile(PathBuf),
    /// TLS settings were supplied without the `tls-rustls` feature.
    #[error("TLS configuration requires the `tls-rustls` feature")]
    TlsFeatureDisabled,
    /// Custom header protection was combined with TLS.
    #[error("custom QUICP header protection is only available in the no-TLS profile")]
    HeaderProtectionWithTls,
    /// The fixed-peer host carrier was combined with multipath mode.
    #[error("the host-driven carrier supports only single-path mode")]
    UnsupportedMultipathCarrier,
}

#[cfg(all(test, feature = "runtime-tokio"))]
mod tests {
    use std::io::{self, IoSliceMut};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::num::{NonZeroU16, NonZeroUsize};
    #[cfg(any(unix, all(feature = "tls-rustls", unix)))]
    use std::os::unix::fs::PermissionsExt;
    use std::pin::Pin;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::task::{Context, Poll};
    use std::time::Duration;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

    use noq::udp::{RecvMeta, Transmit};
    use noq::{AsyncUdpSocket, PathId, PathStatus, Runtime, UdpSender};
    #[cfg(all(feature = "tls-rustls", unix))]
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        BackupPath, Client, ConnectionBudget, MultipathSocket, Server, TransportError,
        build_client_config, build_client_endpoint_with_socket, build_server_config,
        build_server_endpoint_with_socket, lock_budget,
    };
    #[cfg(unix)]
    use super::{SYN_COOKIE_EPOCH_SECONDS, validate_fake_tcp_syn_data};
    use crate::config::{
        CarrierConfig, ClientConfig, ConfigError, Multipath, MultipathMode, PathCandidate,
        ServerConfig,
    };
    #[cfg(any(not(feature = "tls-rustls"), all(feature = "tls-rustls", unix)))]
    use crate::config::{ClientTls, ServerTls};
    #[cfg(unix)]
    use crate::config::{CongestionControl, SynDataPolicy};
    #[cfg(unix)]
    use crate::faketcp::{FourTuple, SynDataMode};
    use crate::multipath::PathHealth;

    #[cfg(unix)]
    #[test]
    fn raw_faketcp_derives_cookie_from_the_configured_secret() {
        let home = std::env::var_os("HOME").expect("HOME is required for raw tests");
        let directory = tempfile::tempdir_in(home).expect("trusted test directory");
        let secret_path = directory.path().join("carrier-cookie.secret");
        std::fs::write(&secret_path, b"transport test cookie secret").expect("secret");
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
            .expect("secret permissions");
        let carrier =
            CarrierConfig::new(SynDataPolicy::Cookie, secret_path, CongestionControl::Cubic)
                .unwrap();
        let tuple = FourTuple::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 44_443)),
        );
        let transport = crate::config::QuicpTransportConfig::default();
        let paths = super::configure_fake_tcp_paths(&carrier, &transport, &[tuple]).unwrap();
        let secret = carrier.load_cookie_secret().unwrap();
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
            / SYN_COOKIE_EPOCH_SECONDS;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].0, tuple);
        assert_eq!(paths[0].1, carrier.syn_data_mode(&secret, tuple, epoch));
        assert_eq!(paths[0].2, crate::faketcp::DEFAULT_SYN_MSS);
        assert_eq!(paths[0].3, transport.mtu.outer_ip_mtu);
    }

    #[test]
    fn listen_allowlist_wildcards_keep_address_families_separate() {
        assert!(super::listen_addr_admits(
            &[SocketAddr::from(([0, 0, 0, 0], 4433))],
            SocketAddr::from(([127, 0, 0, 1], 4433)),
        ));
        assert!(!super::listen_addr_admits(
            &[SocketAddr::from(([0, 0, 0, 0], 4433))],
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 4433)),
        ));
    }

    #[test]
    fn active_connection_budget_releases_only_after_last_clone() {
        let budget = Arc::new(ConnectionBudget::new(2, 1));
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 4433));
        let other_peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 4434));
        let permit = budget.try_acquire(peer).expect("first connection permit");
        assert!(budget.try_acquire(peer).is_none());
        assert!(budget.try_acquire(other_peer).is_some());
        let clone = Arc::clone(&permit);
        drop(permit);
        assert!(budget.try_acquire(peer).is_none());
        drop(clone);
        assert!(budget.try_acquire(peer).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn raw_faketcp_rejects_disabled_syn_data_without_probe_fallback() {
        let tuple = FourTuple::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 44_443)),
        );
        let error = validate_fake_tcp_syn_data(
            SynDataPolicy::Disabled,
            &[(
                tuple,
                SynDataMode::Disabled,
                crate::faketcp::DEFAULT_SYN_MSS,
                1500,
            )],
        )
        .expect_err("raw carrier must not defer failure until first send");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[derive(Debug)]
    struct FailingSocket {
        inner: Box<dyn AsyncUdpSocket>,
        enabled: Arc<AtomicBool>,
        mode: FailureMode,
    }

    #[derive(Clone, Copy, Debug)]
    enum FailureMode {
        Error,
        Silent,
    }

    impl AsyncUdpSocket for FailingSocket {
        fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
            Box::pin(FailingSender {
                inner: self.inner.create_sender(),
                enabled: Arc::clone(&self.enabled),
                mode: self.mode,
            })
        }

        fn poll_recv(
            &mut self,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            if self.enabled.load(Ordering::Relaxed) {
                match self.mode {
                    FailureMode::Error => {
                        Poll::Ready(Err(io::Error::from(io::ErrorKind::NetworkDown)))
                    }
                    FailureMode::Silent => Poll::Pending,
                }
            } else {
                self.inner.poll_recv(cx, bufs, meta)
            }
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        fn max_receive_segments(&self) -> NonZeroUsize {
            self.inner.max_receive_segments()
        }

        fn may_fragment(&self) -> bool {
            self.inner.may_fragment()
        }
    }

    #[derive(Debug)]
    struct FailingSender {
        inner: Pin<Box<dyn UdpSender>>,
        enabled: Arc<AtomicBool>,
        mode: FailureMode,
    }

    impl UdpSender for FailingSender {
        fn poll_send(
            mut self: Pin<&mut Self>,
            transmit: &Transmit<'_>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            if self.enabled.load(Ordering::Relaxed) {
                match self.mode {
                    FailureMode::Error => {
                        Poll::Ready(Err(io::Error::from(io::ErrorKind::NetworkDown)))
                    }
                    FailureMode::Silent => Poll::Ready(Ok(())),
                }
            } else {
                self.inner.as_mut().poll_send(transmit, cx)
            }
        }

        fn max_transmit_segments(&self) -> NonZeroUsize {
            self.inner.max_transmit_segments()
        }
    }

    async fn wait_for_backup_ready(connection: &super::Connection) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !connection.backup_ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("backup path did not become ready");
    }

    #[cfg(all(feature = "tls-rustls", unix))]
    fn secure_tempdir() -> tempfile::TempDir {
        let home = std::env::var_os("HOME").expect("HOME is required for trusted temporary files");
        tempfile::tempdir_in(home).expect("trusted temporary directory")
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn plaintext_flows_preserve_status_isolation_and_half_close() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let client = ClientConfig {
                tls: None,
                allow_insecure: true,
                multipath: Multipath {
                    mode: MultipathMode::Off,
                    candidates: vec![PathCandidate {
                        name: "primary".to_owned(),
                        local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        server_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
                    }],
                },
                carrier: CarrierConfig::default(),
                transport: crate::config::QuicpTransportConfig::default(),
            };
            let server = ServerConfig {
                listen_addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 4433))],
                tls: None,
                allow_insecure: true,
                carrier: CarrierConfig::default(),
                transport: crate::config::QuicpTransportConfig::default(),
            };
            let mut implicit_plaintext_client = client.clone();
            implicit_plaintext_client.allow_insecure = false;
            assert!(matches!(
                build_client_config(&implicit_plaintext_client),
                Err(TransportError::Config(
                    ConfigError::InsecureProfileRequiresOptIn
                ))
            ));
            let mut implicit_plaintext_server = server.clone();
            implicit_plaintext_server.allow_insecure = false;
            assert!(matches!(
                build_server_config(&implicit_plaintext_server),
                Err(TransportError::Config(
                    ConfigError::InsecureProfileRequiresOptIn
                ))
            ));
            let server_endpoint = noq::Endpoint::server(
                build_server_config(&server).unwrap(),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let client_endpoint =
                noq::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            client_endpoint.set_default_client_config(build_client_config(&client).unwrap());
            let server = Server::from_endpoint(server_endpoint);
            let active_connections = Arc::clone(&server.active_connections);
            let client = Client::from_endpoint(client_endpoint, server_addr, "quicp".to_owned());

            let server_connection =
                async { server.accept().await.unwrap().handshake().await.unwrap() };
            let client_connection = client.connect();
            let (server_connection, client_connection) =
                tokio::join!(server_connection, client_connection);
            let client_connection = client_connection.unwrap();
            assert!(!client_connection.backup_ready());
            assert!(!server_connection.backup_ready());
            assert_eq!(client_connection.path_health(), Some(PathHealth::Ready));
            assert_eq!(server_connection.path_health(), None);
            crate::session::ApplicationProfile::SinglePath
                .admit_connection(client_connection.backend(), true)
                .expect("plaintext single-path admission");
            crate::session::ApplicationProfile::SinglePath
                .admit_connection(server_connection.backend(), true)
                .expect("plaintext server admission");
            let denied = client_connection
                .open_flow(
                    crate::wire::OpenRequest::new(
                        crate::wire::CanonicalHost::parse("denied.example").unwrap(),
                        NonZeroU16::new(443).unwrap(),
                    ),
                    false,
                )
                .await;
            assert!(matches!(
                denied,
                Err(crate::flow::FlowError::Session(
                    crate::session::SessionError::PolicyRejected
                ))
            ));
            assert!(matches!(
                crate::session::ApplicationProfile::Multipath
                    .admit_connection(client_connection.backend(), true),
                Err(crate::session::SessionError::ProfileMismatch)
            ));
            crate::session::ApplicationProfile::admit_negotiated(client_connection.backend(), true)
                .expect("negotiated plaintext profile");
            let blocked_request = crate::wire::OpenRequest::new(
                crate::wire::CanonicalHost::parse("blocked.example").unwrap(),
                NonZeroU16::new(80).unwrap(),
            );
            let blocked_client = {
                let connection = client_connection.clone();
                let request = blocked_request.clone();
                tokio::spawn(async move { connection.open_flow(request, true).await })
            };
            let blocked_pending = server_connection.accept_flow(true).await.unwrap();
            assert_eq!(blocked_pending.request(), &blocked_request);
            assert!(!blocked_client.is_finished());

            let ready_request = crate::wire::OpenRequest::new(
                crate::wire::CanonicalHost::parse("ready.example").unwrap(),
                NonZeroU16::new(443).unwrap(),
            );
            let ready_client = {
                let connection = client_connection.clone();
                let request = ready_request.clone();
                tokio::spawn(async move { connection.open_flow(request, true).await })
            };
            let ready_pending = server_connection.accept_flow(true).await.unwrap();
            assert_eq!(ready_pending.request(), &ready_request);
            let mut server_flow = ready_pending.accept().await.unwrap();
            let mut client_flow = tokio::time::timeout(Duration::from_secs(2), ready_client)
                .await
                .expect("ready flow timed out")
                .unwrap()
                .unwrap();

            client_flow.write_all(b"request").await.unwrap();
            client_flow.shutdown().await.unwrap();
            let mut request = Vec::new();
            tokio::time::timeout(
                Duration::from_secs(2),
                server_flow.read_to_end(&mut request),
            )
            .await
            .expect("request half-close timed out")
            .unwrap();
            assert_eq!(request, b"request");

            server_flow.write_all(b"response").await.unwrap();
            server_flow.shutdown().await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(
                Duration::from_secs(2),
                client_flow.read_to_end(&mut response),
            )
            .await
            .expect("response half-close timed out")
            .unwrap();
            assert_eq!(response, b"response");

            assert!(!blocked_client.is_finished());
            blocked_pending
                .reject(crate::wire::OpenStatus::PolicyDenied)
                .await
                .unwrap();
            let blocked_result = tokio::time::timeout(Duration::from_secs(2), blocked_client)
                .await
                .expect("rejected flow timed out")
                .unwrap();
            assert!(matches!(
                blocked_result,
                Err(crate::flow::FlowError::Rejected(
                    crate::wire::OpenStatus::PolicyDenied
                ))
            ));

            drop(server_connection);
            assert_eq!(lock_budget(&active_connections.state).active, 1);
            drop(server_flow);
            assert_eq!(lock_budget(&active_connections.state).active, 0);
        })
        .await
        .expect("plaintext flow E2E timed out");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn cancelled_pending_write_does_not_consume_the_next_buffer() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let client_config = ClientConfig {
                tls: None,
                allow_insecure: true,
                multipath: Multipath {
                    mode: MultipathMode::Off,
                    candidates: vec![PathCandidate {
                        name: "primary".to_owned(),
                        local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        server_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
                    }],
                },
                carrier: CarrierConfig::default(),
                transport: crate::config::QuicpTransportConfig::default(),
            };
            let server_config = ServerConfig {
                listen_addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 4433))],
                tls: None,
                allow_insecure: true,
                carrier: CarrierConfig::default(),
                transport: crate::config::QuicpTransportConfig::default(),
            };

            let mut backend_server_config = build_server_config(&server_config).unwrap();
            let mut transport = crate::multipath::backend_transport_config(MultipathMode::Off);
            transport.stream_receive_window(noq::VarInt::from_u32(64));
            backend_server_config.transport_config(Arc::new(transport));
            let server_endpoint = noq::Endpoint::server(
                backend_server_config,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let client_endpoint =
                noq::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            client_endpoint.set_default_client_config(build_client_config(&client_config).unwrap());
            let server = Server::from_endpoint(server_endpoint);
            let client = Client::from_endpoint(client_endpoint, server_addr, "quicp".to_owned());

            let server_connection =
                async { server.accept().await.unwrap().handshake().await.unwrap() };
            let client_connection = client.connect();
            let (server_connection, client_connection) =
                tokio::join!(server_connection, client_connection);
            let client_connection = client_connection.unwrap();
            let request = crate::wire::OpenRequest::new(
                crate::wire::CanonicalHost::parse("cancel.example").unwrap(),
                NonZeroU16::new(443).unwrap(),
            );
            let client_flow = client_connection.open_flow(request, true);
            let server_flow = async {
                server_connection
                    .accept_flow(true)
                    .await
                    .unwrap()
                    .accept()
                    .await
                    .unwrap()
            };
            let (client_flow, server_flow) = tokio::join!(client_flow, server_flow);
            let mut client_flow = client_flow.unwrap();
            let mut server_flow = server_flow;

            let chunk = vec![0xa5; 32 * 1024];
            let mut accepted = 0usize;
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let blocked = (0..1024).any(|_| {
                match crate::flow::QuicpFlow::poll_write(
                    Pin::new(&mut client_flow),
                    &mut cx,
                    &chunk,
                ) {
                    Poll::Ready(Ok(written)) => {
                        assert_eq!(written, chunk.len());
                        accepted += written;
                        false
                    }
                    Poll::Ready(Err(error)) => panic!("fill write failed: {error}"),
                    Poll::Pending => true,
                }
            });
            assert!(blocked, "flow-control did not produce a cancellable write");

            let marker = [0x5a];
            let mut received = vec![0; accepted + marker.len()];
            let read = server_flow.read_exact(&mut received);
            let write = async {
                let written = std::future::poll_fn(|cx| {
                    crate::flow::QuicpFlow::poll_write(Pin::new(&mut client_flow), cx, &marker)
                })
                .await
                .unwrap();
                assert_eq!(written, marker.len());
                std::future::poll_fn(|cx| {
                    crate::flow::QuicpFlow::poll_flush(Pin::new(&mut client_flow), cx)
                })
                .await
                .unwrap();
            };
            let (read, ()) = tokio::join!(read, write);
            read.unwrap();
            assert!(received[..accepted].iter().all(|byte| *byte == 0xa5));
            assert_eq!(&received[accepted..], &marker);
        })
        .await
        .expect("cancellation accounting test timed out");
    }

    #[cfg(not(feature = "tls-rustls"))]
    #[test]
    fn rejects_tls_configuration_when_feature_is_disabled() {
        let tls_path = std::path::PathBuf::from("unused.pem");
        let client = ClientConfig {
            tls: Some(ClientTls {
                server_name: "server.example".to_owned(),
                ca_cert: tls_path.clone(),
                client_cert: tls_path.clone(),
                client_key: tls_path.clone(),
            }),
            allow_insecure: false,
            multipath: Multipath {
                mode: MultipathMode::Off,
                candidates: vec![PathCandidate {
                    name: "primary".to_owned(),
                    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    server_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
                }],
            },
            carrier: CarrierConfig::default(),
            transport: crate::config::QuicpTransportConfig::default(),
        };
        let server = ServerConfig {
            listen_addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 4433))],
            tls: Some(ServerTls {
                server_cert: tls_path.clone(),
                server_key: tls_path.clone(),
                client_ca: tls_path,
            }),
            allow_insecure: false,
            carrier: CarrierConfig::default(),
            transport: crate::config::QuicpTransportConfig::default(),
        };

        assert!(matches!(
            build_client_config(&client),
            Err(TransportError::TlsFeatureDisabled)
        ));
        assert!(matches!(
            build_server_config(&server),
            Err(TransportError::TlsFeatureDisabled)
        ));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn multipath_socket_keeps_same_flow_after_primary_io_failure() {
        multipath_socket_keeps_same_flow_after_primary_failure(FailureMode::Error).await;
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn multipath_socket_keeps_same_flow_after_primary_blackhole() {
        multipath_socket_keeps_same_flow_after_primary_failure(FailureMode::Silent).await;
    }

    #[allow(clippy::too_many_lines)]
    async fn multipath_socket_keeps_same_flow_after_primary_failure(mode: FailureMode) {
        let bind_pair = || {
            let primary = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let backup = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            primary.set_nonblocking(true).unwrap();
            backup.set_nonblocking(true).unwrap();
            [primary, backup]
        };
        let [client_primary, client_backup] = bind_pair();
        let [server_primary, server_backup] = bind_pair();
        let client_primary_addr = client_primary.local_addr().unwrap();
        let client_backup_addr = client_backup.local_addr().unwrap();
        let server_primary_addr = server_primary.local_addr().unwrap();
        let server_backup_addr = server_backup.local_addr().unwrap();
        let client = ClientConfig {
            tls: None,
            allow_insecure: true,
            multipath: Multipath {
                mode: MultipathMode::Failover,
                candidates: vec![
                    PathCandidate {
                        name: "primary".to_owned(),
                        local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        server_addr: server_primary_addr,
                    },
                    PathCandidate {
                        name: "backup".to_owned(),
                        local_ip: client_backup_addr.ip(),
                        server_addr: server_backup_addr,
                    },
                ],
            },
            carrier: CarrierConfig::default(),
            transport: crate::config::QuicpTransportConfig::default(),
        };
        let server = ServerConfig {
            listen_addrs: vec![server_primary_addr, server_backup_addr],
            tls: None,
            allow_insecure: true,
            carrier: CarrierConfig::default(),
            transport: crate::config::QuicpTransportConfig::default(),
        };
        let runtime: Arc<dyn Runtime> = Arc::new(noq::TokioRuntime);
        let primary_failed = Arc::new(AtomicBool::new(false));
        let wrap_primary = |socket| -> Box<dyn AsyncUdpSocket> {
            Box::new(FailingSocket {
                inner: runtime.wrap_udp_socket(socket).unwrap(),
                enabled: Arc::clone(&primary_failed),
                mode,
            })
        };
        let client_socket = MultipathSocket::new(
            (wrap_primary(client_primary), server_primary_addr),
            (
                runtime.wrap_udp_socket(client_backup).unwrap(),
                server_backup_addr,
            ),
        )
        .unwrap();
        let server_socket = MultipathSocket::new(
            (wrap_primary(server_primary), client_primary_addr),
            (
                runtime.wrap_udp_socket(server_backup).unwrap(),
                client_backup_addr,
            ),
        )
        .unwrap();
        let client_endpoint = build_client_endpoint_with_socket(
            &client,
            Box::new(client_socket),
            Arc::clone(&runtime),
        )
        .unwrap();
        let server_endpoint = build_server_endpoint_with_socket(
            &server,
            Box::new(server_socket),
            Arc::clone(&runtime),
        )
        .unwrap();
        let client = Client::from_endpoint_with_runtime(
            client_endpoint,
            server_primary_addr,
            "quicp".to_owned(),
            Some(Arc::clone(&runtime)),
            Some(BackupPath {
                remote: server_backup_addr,
                local_ip: client_backup_addr.ip(),
            }),
            None,
            crate::flow::RELAY_BUFFER_BYTES,
            true,
        );

        let server_connection = async {
            server_endpoint
                .accept()
                .await
                .expect("incoming connection")
                .await
                .unwrap()
        };
        let client_connection = client.connect();
        let (server_connection, client_connection) =
            tokio::join!(server_connection, client_connection);
        let client_connection = client_connection.expect("client connection");
        wait_for_backup_ready(&client_connection).await;
        assert_eq!(client_connection.path_health(), Some(PathHealth::Ready));
        let stable_id = client_connection.stable_id();
        let backup = client_connection
            .backend()
            .path(PathId::ZERO.saturating_add(1u32))
            .expect("automatic backup path");
        assert_eq!(backup.status().unwrap(), PathStatus::Backup);

        let server_flow = async {
            crate::flow::accept_flow_backend(
                &server_connection,
                true,
                None,
                crate::flow::RELAY_BUFFER_BYTES,
                true,
            )
            .await
            .unwrap()
            .accept()
            .await
            .unwrap()
        };
        let client_flow = async {
            crate::flow::QuicpFlow::open_backend(
                client_connection.backend(),
                crate::wire::OpenRequest::new(
                    crate::wire::CanonicalHost::parse("example.com").unwrap(),
                    NonZeroU16::new(443).unwrap(),
                ),
                true,
                None,
                crate::flow::RELAY_BUFFER_BYTES,
                true,
            )
            .await
            .unwrap()
        };
        let (mut server_flow, mut client_flow) = tokio::join!(server_flow, client_flow);
        client_flow.write_all(b"before").await.unwrap();
        client_flow.flush().await.unwrap();
        let mut before = [0; 6];
        server_flow.read_exact(&mut before).await.unwrap();
        assert_eq!(&before, b"before");

        let primary = client_connection
            .backend()
            .path(PathId::ZERO)
            .expect("primary path");
        primary
            .set_max_idle_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        server_connection
            .path(PathId::ZERO)
            .expect("primary path")
            .set_max_idle_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let primary_tx_before = primary.stats().udp_tx.bytes;
        let backup_tx_before = backup.stats().udp_tx.bytes;
        primary_failed.store(true, Ordering::Relaxed);
        client_flow.write_all(b"after").await.unwrap();
        client_flow.flush().await.unwrap();
        let mut after = [0; 5];
        tokio::time::timeout(Duration::from_secs(5), server_flow.read_exact(&mut after))
            .await
            .expect("flow did not fail over")
            .unwrap();
        assert_eq!(&after, b"after");
        assert!(primary.stats().udp_tx.bytes > primary_tx_before);
        assert!(primary.status().is_err());
        assert!(backup.stats().udp_tx.bytes > backup_tx_before);
        assert_eq!(client_connection.stable_id(), stable_id);
        assert!(client_connection.backup_ready());
    }

    #[cfg(all(feature = "tls-rustls", unix))]
    #[tokio::test]
    async fn authenticates_mutual_tls_and_both_alpn_profiles() {
        let directory = secure_tempdir();
        let directory = std::fs::canonicalize(directory.path()).unwrap();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(["server.example".to_owned()]).unwrap();
        let cert_path = directory.join("node.pem");
        let key_path = directory.join("node.key");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut client = ClientConfig {
            tls: Some(ClientTls {
                server_name: "server.example".to_owned(),
                ca_cert: cert_path.clone(),
                client_cert: cert_path.clone(),
                client_key: key_path.clone(),
            }),
            allow_insecure: false,
            multipath: Multipath {
                mode: MultipathMode::Off,
                candidates: vec![PathCandidate {
                    name: "primary".to_owned(),
                    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    server_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
                }],
            },
            carrier: CarrierConfig::default(),
            transport: crate::config::QuicpTransportConfig::default(),
        };
        let server = ServerConfig {
            listen_addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 4433))],
            tls: Some(ServerTls {
                server_cert: cert_path.clone(),
                server_key: key_path,
                client_ca: cert_path,
            }),
            allow_insecure: false,
            carrier: CarrierConfig::default(),
            transport: crate::config::QuicpTransportConfig::default(),
        };

        authenticate(&client, &server).await;
        client.multipath.mode = MultipathMode::Failover;
        client.multipath.candidates.push(PathCandidate {
            name: "backup".to_owned(),
            local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            server_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 4434)),
        });
        authenticate(&client, &server).await;
    }

    #[cfg(all(feature = "tls-rustls", unix))]
    async fn authenticate(client: &ClientConfig, server: &ServerConfig) {
        let profile = crate::session::ApplicationProfile::from(client.multipath.mode);
        let client_config = build_client_config(client).unwrap();
        let server_config = build_server_config(server).unwrap();
        let server_endpoint =
            noq::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let client_endpoint =
            noq::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        client_endpoint.set_default_client_config(client_config);

        let server_connection = async {
            server_endpoint
                .accept()
                .await
                .expect("incoming connection")
                .await
                .unwrap()
        };
        let client_connection = async {
            client_endpoint
                .connect(server_addr, &client.tls.as_ref().unwrap().server_name)
                .unwrap()
                .await
                .unwrap()
        };
        let (server_connection, client_connection) =
            tokio::join!(server_connection, client_connection);
        let wrong_profile = match profile {
            crate::session::ApplicationProfile::SinglePath => {
                crate::session::ApplicationProfile::Multipath
            }
            crate::session::ApplicationProfile::Multipath => {
                crate::session::ApplicationProfile::SinglePath
            }
        };
        assert_eq!(
            wrong_profile.admit_connection(&server_connection, true),
            Err(crate::session::SessionError::ProfileMismatch)
        );
        profile.admit_connection(&server_connection, true).unwrap();
        profile.admit_connection(&client_connection, true).unwrap();
    }
}
