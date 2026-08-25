//! Tokio runtime adapter and explicitly supported Unix `FakeTCP` endpoint extensions.
//!
//! This module is the only place that combines the Tokio executor with runtime adapters. Its Linux
//! and macOS raw-socket extensions are target-gated; the protocol and host-carrier API remain in
//! the parent. Windows requires a separate packet-injection adapter and is intentionally not
//! routed through the Unix path.

#[cfg(any(test, unix))]
use std::io::{self, IoSliceMut};
#[cfg(any(test, unix))]
use std::net::{IpAddr, SocketAddr};
#[cfg(any(test, unix))]
use std::num::NonZeroUsize;
#[cfg(any(test, unix))]
use std::pin::Pin;
#[cfg(any(test, unix))]
use std::sync::Arc;
#[cfg(any(test, unix))]
use std::task::{Context, Poll};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(test, unix))]
use noq::udp::{RecvMeta, Transmit};
#[cfg(any(test, unix))]
use noq::{AsyncUdpSocket, UdpSender};

#[cfg(unix)]
use crate::config::{
    CarrierConfig, ClientConfig, ConfigError, MssMode, ServerConfig, SynDataPolicy,
};
#[cfg(unix)]
use crate::congestion::TransportOptions;
#[cfg(unix)]
use crate::faketcp::{CarrierDirection, FakeTcpSocket, FourTuple, SynDataMode};

#[cfg(unix)]
use super::{
    Client, Server, TransportError, ValidatedClientConfig, ValidatedServerConfig,
    build_client_endpoint_with_validated_config, build_server_endpoint_with_validated_config,
    configured_backup_path, listen_addr_admits,
};

#[cfg(unix)]
pub(crate) const SYN_COOKIE_EPOCH_SECONDS: u64 = 60;
#[cfg(any(test, unix))]
#[derive(Debug)]
pub(crate) struct MultipathSocket {
    children: [Box<dyn AsyncUdpSocket>; 2],
    routes: [(IpAddr, SocketAddr); 2],
    next_recv: usize,
}

#[cfg(any(test, unix))]
impl MultipathSocket {
    pub(crate) fn new(
        primary: (Box<dyn AsyncUdpSocket>, SocketAddr),
        backup: (Box<dyn AsyncUdpSocket>, SocketAddr),
    ) -> io::Result<Self> {
        let routes = [
            (primary.0.local_addr()?.ip(), primary.1),
            (backup.0.local_addr()?.ip(), backup.1),
        ];
        if routes[0] == routes[1] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multipath routes must be unique",
            ));
        }
        Ok(Self {
            children: [primary.0, backup.0],
            routes,
            next_recv: 0,
        })
    }
}

#[cfg(any(test, unix))]
impl AsyncUdpSocket for MultipathSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(MultipathSender {
            children: [
                self.children[0].create_sender(),
                self.children[1].create_sender(),
            ],
            routes: self.routes,
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut path_error = None;
        let mut unavailable = 0;
        for offset in 0..2 {
            let index = (self.next_recv + offset) % 2;
            match self.children[index].poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(received)) => {
                    self.next_recv = (index + 1) % 2;
                    return Poll::Ready(Ok(received));
                }
                Poll::Ready(Err(error)) if is_path_unavailable(&error) => {
                    unavailable += 1;
                    path_error.get_or_insert(error);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }
        if unavailable == self.children.len() {
            Poll::Ready(Err(path_error.expect("all paths returned an error")))
        } else {
            Poll::Pending
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.children[0].local_addr()
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.children[0]
            .max_receive_segments()
            .max(self.children[1].max_receive_segments())
    }

    fn may_fragment(&self) -> bool {
        self.children[0].may_fragment() || self.children[1].may_fragment()
    }
}

#[cfg(any(test, unix))]
fn is_path_unavailable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::NetworkUnreachable
    )
}

#[cfg(any(test, unix))]
#[derive(Debug)]
struct MultipathSender {
    children: [Pin<Box<dyn UdpSender>>; 2],
    routes: [(IpAddr, SocketAddr); 2],
}

#[cfg(any(test, unix))]
impl UdpSender for MultipathSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(index) = self.routes.iter().position(|(source, destination)| {
            transmit.destination == *destination
                && transmit.src_ip.is_none_or(|requested| requested == *source)
        }) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "no multipath socket is bound to {:?} -> {}",
                    transmit.src_ip, transmit.destination
                ),
            )));
        };
        self.children[index].as_mut().poll_send(transmit, cx)
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.children[0]
            .max_transmit_segments()
            .min(self.children[1].max_transmit_segments())
    }
}

#[cfg(unix)]
impl Client {
    /// Binds a Unix `FakeTCP` client endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths or socket setup failure.
    #[cfg(unix)]
    pub fn bind_fake_tcp(
        config: &ClientConfig,
        tuples: &[FourTuple],
    ) -> Result<Self, TransportError> {
        Self::bind_fake_tcp_with_options(config, tuples, &TransportOptions::default())
    }

    /// Binds a Unix `FakeTCP` client endpoint with runtime-neutral Rust extension options.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, raw-socket setup failure, or endpoint construction.
    #[cfg(unix)]
    pub fn bind_fake_tcp_with_options(
        config: &ClientConfig,
        tuples: &[FourTuple],
        options: &TransportOptions,
    ) -> Result<Self, TransportError> {
        let endpoint = build_fake_tcp_client_endpoint_with_options(config, tuples, options)?;
        let Some(primary) = tuples.first() else {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "FakeTCP requires a path").into(),
            );
        };
        let server_addr = primary.destination;
        let server_name = config
            .tls
            .as_ref()
            .map_or_else(|| "quicp".to_owned(), |tls| tls.server_name.clone());
        Ok(Self::from_endpoint_with_runtime(
            endpoint,
            server_addr,
            server_name,
            Some(Arc::new(noq::TokioRuntime)),
            configured_backup_path(config),
            Some(*primary),
            config.transport().flow_write_buffer_bytes as usize,
            config.transport().default_nodelay,
        ))
    }
}
#[cfg(unix)]
impl Server {
    /// Binds a Unix `FakeTCP` server endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths or socket setup failure.
    #[cfg(unix)]
    pub fn bind_fake_tcp(
        config: &ServerConfig,
        tuples: &[FourTuple],
    ) -> Result<Self, TransportError> {
        Self::bind_fake_tcp_with_options(config, tuples, &TransportOptions::default())
    }

    /// Binds a Unix `FakeTCP` server endpoint with runtime-neutral Rust extension options.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, raw-socket setup failure, or endpoint construction.
    #[cfg(unix)]
    pub fn bind_fake_tcp_with_options(
        config: &ServerConfig,
        tuples: &[FourTuple],
        options: &TransportOptions,
    ) -> Result<Self, TransportError> {
        build_fake_tcp_server_endpoint_with_options(config, tuples, options)
            .map(|endpoint| Self::from_endpoint_with_config(endpoint, config))
    }
}
/// Builds a client endpoint whose underlay is raw TCP-shaped packets rather than UDP.
///
/// Each path owns independent tuple-bound carrier state. The builder loads the configured
/// owner-only cookie secret and derives the current tuple-bound SYN cookie; callers provide only
/// the path tuples. Backup path lifecycle remains with the caller; [`Client::bind_fake_tcp`] arms
/// configured backups automatically.
///
/// # Errors
///
/// Returns an error for the temporary TLS-backed adapter, raw-socket setup, or the selected
/// runtime adapter.
#[cfg(unix)]
pub fn build_fake_tcp_client_endpoint(
    config: &ClientConfig,
    tuples: &[FourTuple],
) -> Result<noq::Endpoint, TransportError> {
    build_fake_tcp_client_endpoint_with_options(config, tuples, &TransportOptions::default())
}

/// Builds a Unix `FakeTCP` client endpoint with runtime-neutral Rust extension options.
///
/// # Errors
///
/// Returns an error for invalid paths, an unavailable cookie secret, raw-socket setup failure, or
/// endpoint construction.
#[cfg(unix)]
pub fn build_fake_tcp_client_endpoint_with_options(
    config: &ClientConfig,
    tuples: &[FourTuple],
    options: &TransportOptions,
) -> Result<noq::Endpoint, TransportError> {
    let config = ValidatedClientConfig::new(config)?;
    let paths = configure_fake_tcp_paths(&config.carrier, config.transport(), tuples)?;
    if paths.len() != usize::from(config.multipath.mode.path_limit())
        || paths.len() != config.multipath.candidates.len()
        || paths
            .iter()
            .zip(&config.multipath.candidates)
            .any(|((tuple, _, _, _), candidate)| {
                tuple.source.ip() != candidate.local_ip
                    || tuple.destination != candidate.server_addr
            })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FakeTCP paths do not match configured candidates",
        )
        .into());
    }
    let payload_ceiling = config
        .transport()
        .mtu
        .static_payload_ceiling(None, tuples.iter().map(|tuple| tuple.source.is_ipv4()))?;
    let socket = bind_fake_tcp_paths(
        &paths,
        CarrierDirection::ClientToServer,
        config.carrier.packet_socket,
    )?;
    build_client_endpoint_with_validated_config(
        config,
        socket,
        Arc::new(noq::TokioRuntime),
        options,
        Some(payload_ceiling),
    )
}

/// Builds a server endpoint whose underlay is raw TCP-shaped packets rather than UDP.
///
/// Every path source must be admitted by the server's listen-address policy.
///
/// # Errors
///
/// Returns an error for the temporary TLS-backed adapter or raw-socket setup.
#[cfg(unix)]
pub fn build_fake_tcp_server_endpoint(
    config: &ServerConfig,
    tuples: &[FourTuple],
) -> Result<noq::Endpoint, TransportError> {
    build_fake_tcp_server_endpoint_with_options(config, tuples, &TransportOptions::default())
}

/// Builds a Unix `FakeTCP` server endpoint with runtime-neutral Rust extension options.
///
/// # Errors
///
/// Returns an error for invalid paths, an unavailable cookie secret, raw-socket setup failure, or
/// endpoint construction.
#[cfg(unix)]
pub fn build_fake_tcp_server_endpoint_with_options(
    config: &ServerConfig,
    tuples: &[FourTuple],
    options: &TransportOptions,
) -> Result<noq::Endpoint, TransportError> {
    let config = ValidatedServerConfig::new(config)?;
    let paths = configure_fake_tcp_paths(&config.carrier, config.transport(), tuples)?;
    if paths.is_empty()
        || paths.len() > 2
        || paths
            .iter()
            .any(|(tuple, _, _, _)| !listen_addr_admits(&config.listen_addrs, tuple.source))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FakeTCP paths are outside the server listen allowlist",
        )
        .into());
    }
    let payload_ceiling = config
        .transport()
        .mtu
        .static_payload_ceiling(None, tuples.iter().map(|tuple| tuple.source.is_ipv4()))?;
    let socket = bind_fake_tcp_paths(
        &paths,
        CarrierDirection::ServerToClient,
        config.carrier.packet_socket,
    )?;
    build_server_endpoint_with_validated_config(
        config,
        socket,
        Arc::new(noq::TokioRuntime),
        options,
        Some(payload_ceiling),
    )
}

#[cfg(unix)]
fn bind_fake_tcp_paths(
    paths: &[(FourTuple, SynDataMode, u16, u16)],
    direction: CarrierDirection,
    packet_socket: bool,
) -> io::Result<Box<dyn AsyncUdpSocket>> {
    if matches!(paths, [primary, backup]
        if (primary.0.source.ip(), primary.0.destination)
            == (backup.0.source.ip(), backup.0.destination))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FakeTCP paths must have distinct routable tuples",
        ));
    }
    let bind = |(tuple, syn_data, syn_mss, outer_mtu)| {
        FakeTcpSocket::bind(
            tuple,
            direction,
            syn_data,
            syn_mss,
            outer_mtu,
            packet_socket,
        )
    };
    match paths {
        [path] => Ok(Box::new(bind(*path)?)),
        [primary, backup] => {
            let primary_socket: Box<dyn AsyncUdpSocket> = Box::new(bind(*primary)?);
            let backup_socket: Box<dyn AsyncUdpSocket> = Box::new(bind(*backup)?);
            Ok(Box::new(MultipathSocket::new(
                (primary_socket, primary.0.destination),
                (backup_socket, backup.0.destination),
            )?))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FakeTCP requires one or two paths",
        )),
    }
}

#[cfg(all(test, unix))]
pub(crate) fn validate_fake_tcp_syn_data(
    policy: SynDataPolicy,
    paths: &[(FourTuple, SynDataMode, u16, u16)],
) -> io::Result<()> {
    if policy == SynDataPolicy::Cookie
        && paths
            .iter()
            .all(|(_, mode, _, _)| matches!(mode, SynDataMode::Cookie(_)))
    {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "raw FakeTCP requires cookie SYN data until empty-SYN fallback is implemented",
    ))
}

#[cfg(unix)]
pub(crate) fn configure_fake_tcp_paths(
    carrier: &CarrierConfig,
    transport: &crate::config::QuicpTransportConfig,
    tuples: &[FourTuple],
) -> Result<Vec<(FourTuple, SynDataMode, u16, u16)>, TransportError> {
    if carrier.syn_data() != SynDataPolicy::Cookie {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "raw FakeTCP requires cookie SYN data until empty-SYN fallback is implemented",
        )
        .into());
    }
    let secret = carrier.load_cookie_secret()?;
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("system clock is before the Unix epoch: {error}"),
            )
        })?
        .as_secs()
        / SYN_COOKIE_EPOCH_SECONDS;
    Ok(tuples
        .iter()
        .copied()
        .map(|tuple| {
            let safe_mss = transport
                .mtu
                .safe_payload_for_family(tuple.source.is_ipv4())?;
            let syn_mss = match transport.mtu.mss {
                MssMode::Auto => safe_mss,
                MssMode::Fixed(mss) => mss,
            };
            Ok::<_, ConfigError>((
                tuple,
                carrier.syn_data_mode(&secret, tuple, epoch),
                syn_mss,
                transport.mtu.outer_ip_mtu,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?)
}
