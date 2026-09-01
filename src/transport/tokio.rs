//! Tokio runtime adapter and explicitly supported native `FakeTCP` endpoint extensions.
//!
//! This module is the only place that combines the Tokio executor with runtime adapters. Its Linux,
//! macOS, and Windows packet adapters are target-gated; the protocol and host-carrier API remain in
//! the parent.

use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use noq::AsyncUdpSocket;

use crate::config::{CarrierConfig, ClientConfig, ConfigError, MssMode, ServerConfig};
use crate::congestion::TransportOptions;
use crate::faketcp::{CarrierDirection, FakeTcpSocket, FourTuple, SynDataMode};

use super::{
    Client, MultipathSocket, RecoveryMemoryBudget, Server, TransportError, ValidatedClientConfig,
    ValidatedServerConfig, build_client_config_with_options_and_payload, build_client_endpoint,
    build_server_config_with_options_and_payload, build_server_endpoint, configured_backup_path,
    listen_addr_admits,
};

pub(crate) const SYN_COOKIE_EPOCH_SECONDS: u64 = 60;
impl Client {
    /// Binds a native `FakeTCP` client endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths or socket setup failure.
    pub fn bind_fake_tcp(
        config: &ClientConfig,
        tuples: &[FourTuple],
    ) -> Result<Self, TransportError> {
        Self::bind_fake_tcp_with_options(config, tuples, &TransportOptions::default())
    }

    /// Binds a native `FakeTCP` client endpoint with runtime-neutral Rust extension options.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, raw-socket setup failure, or endpoint construction.
    pub fn bind_fake_tcp_with_options(
        config: &ClientConfig,
        tuples: &[FourTuple],
        options: &TransportOptions,
    ) -> Result<Self, TransportError> {
        let (endpoint, payload_ceiling) =
            build_fake_tcp_client_endpoint_with_options(config, tuples, options)?;
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
            None,
            configured_backup_path(config),
            config.transport().flow_write_buffer_bytes as usize,
            config.transport().default_nodelay,
            config.transport().recovery,
            Arc::new(RecoveryMemoryBudget::new(
                config.transport().recovery_memory_budget_bytes,
            )),
            usize::from(payload_ceiling) - crate::wire::REPAIR_DATAGRAM_HEADER_BYTES,
        ))
    }
}
impl Server {
    /// Binds a native `FakeTCP` server endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths or socket setup failure.
    pub fn bind_fake_tcp(
        config: &ServerConfig,
        tuples: &[FourTuple],
    ) -> Result<Self, TransportError> {
        Self::bind_fake_tcp_with_options(config, tuples, &TransportOptions::default())
    }

    /// Binds a native `FakeTCP` server endpoint with runtime-neutral Rust extension options.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, raw-socket setup failure, or endpoint construction.
    pub fn bind_fake_tcp_with_options(
        config: &ServerConfig,
        tuples: &[FourTuple],
        options: &TransportOptions,
    ) -> Result<Self, TransportError> {
        let (endpoint, payload_ceiling) =
            build_fake_tcp_server_endpoint_with_options(config, tuples, options)?;
        Ok(Self::from_endpoint_with_limits(
            endpoint,
            usize::from(config.transport().max_active_connections),
            usize::from(config.transport().max_active_connections_per_peer),
            config.transport().flow_write_buffer_bytes as usize,
            config.transport().default_nodelay,
            Arc::new(noq::TokioRuntime),
            None,
            config.transport().recovery,
            Arc::new(RecoveryMemoryBudget::new(
                config.transport().recovery_memory_budget_bytes,
            )),
            usize::from(payload_ceiling) - crate::wire::REPAIR_DATAGRAM_HEADER_BYTES,
        ))
    }
}
fn build_fake_tcp_client_endpoint_with_options(
    config: &ClientConfig,
    tuples: &[FourTuple],
    options: &TransportOptions,
) -> Result<(noq::Endpoint, u16), TransportError> {
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
    let transport =
        build_client_config_with_options_and_payload(config, options, Some(payload_ceiling))?;
    let socket = bind_fake_tcp_paths(
        &paths,
        CarrierDirection::ClientToServer,
        config.carrier.packet_socket,
    )?;
    build_client_endpoint(
        config,
        transport,
        socket,
        Arc::new(noq::TokioRuntime),
        payload_ceiling,
    )
}

fn build_fake_tcp_server_endpoint_with_options(
    config: &ServerConfig,
    tuples: &[FourTuple],
    options: &TransportOptions,
) -> Result<(noq::Endpoint, u16), TransportError> {
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
    let transport =
        build_server_config_with_options_and_payload(config, options, Some(payload_ceiling))?;
    let socket = bind_fake_tcp_paths(
        &paths,
        CarrierDirection::ServerToClient,
        config.carrier.packet_socket,
    )?;
    build_server_endpoint(
        config,
        transport,
        socket,
        Arc::new(noq::TokioRuntime),
        payload_ceiling,
    )
}

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

pub(crate) fn configure_fake_tcp_paths(
    carrier: &CarrierConfig,
    transport: &crate::config::QuicpTransportConfig,
    tuples: &[FourTuple],
) -> Result<Vec<(FourTuple, SynDataMode, u16, u16)>, TransportError> {
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
                carrier.syn_cookie_mode(&secret, tuple, epoch),
                syn_mss,
                transport.mtu.outer_ip_mtu,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?)
}
