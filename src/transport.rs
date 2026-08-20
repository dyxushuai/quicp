#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
use std::io::{self, IoSliceMut};
#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
use std::net::{IpAddr, SocketAddr};
#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
use std::num::NonZeroUsize;
#[cfg(feature = "tls-rustls")]
use std::path::{Path, PathBuf};
#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
use std::pin::Pin;
use std::sync::Arc;
#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
use std::task::{Context, Poll};

#[cfg(feature = "tls-rustls")]
use noq::crypto::rustls::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig};
#[cfg(feature = "tls-rustls")]
use noq::rustls::pki_types::pem::{Error as PemError, PemObject};
#[cfg(feature = "tls-rustls")]
use noq::rustls::pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(feature = "tls-rustls")]
use noq::rustls::server::{VerifierBuilderError, WebPkiClientVerifier};
#[cfg(feature = "tls-rustls")]
use noq::rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
use noq::udp::{RecvMeta, Transmit};
#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
use noq::{AsyncUdpSocket, UdpSender};
use thiserror::Error;

use crate::config::{ClientConfig, ConfigError, MultipathMode, ServerConfig};
#[cfg(feature = "tls-rustls")]
use crate::config::{TrustedFileMode, read_trusted_file};
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use crate::faketcp::{CarrierDirection, FakeTcpSocket, FourTuple, SynDataMode};
use crate::multipath::backend_transport_config;
use crate::no_security::{NoSecurityClientConfig, NoSecurityServerConfig};
use crate::session::{ApplicationProfile, ResumptionCache, ResumptionPolicy};

#[cfg(feature = "tls-rustls")]
const MAX_TLS_FILE_BYTES: u64 = 1024 * 1024;
const MAX_PENDING_HANDSHAKES: u16 = 128;
const PENDING_HANDSHAKE_BYTES: u32 = 32 * 1024;

/// A client connection that may still be waiting for the full handshake.
pub enum ClientHandshake {
    OneRtt(noq::Connecting),
    ZeroRtt {
        connection: noq::Connection,
        accepted: noq::ZeroRttAccepted,
    },
}

impl ClientHandshake {
    #[must_use]
    pub const fn is_zero_rtt(&self) -> bool {
        matches!(self, Self::ZeroRtt { .. })
    }

    /// Completes a 1-RTT connection or returns a 0-RTT connection immediately.
    ///
    /// The optional future resolves after the handshake and reports whether early data was
    /// accepted. Callers must not treat the 0-RTT connection as authenticated until it resolves.
    ///
    /// # Errors
    ///
    /// Returns the backend connection error when a one-round-trip handshake fails.
    pub async fn finish(
        self,
    ) -> Result<(noq::Connection, Option<noq::ZeroRttAccepted>), noq::ConnectionError> {
        match self {
            Self::OneRtt(connecting) => connecting.await.map(|connection| (connection, None)),
            Self::ZeroRtt {
                connection,
                accepted,
            } => Ok((connection, Some(accepted))),
        }
    }
}

/// Applies the application-owned replay policy before trying `noq` 0-RTT.
pub fn start_client_handshake(
    connecting: noq::Connecting,
    cache: &mut ResumptionCache,
    policy: &ResumptionPolicy,
) -> ClientHandshake {
    if !cache.admit(policy) {
        return ClientHandshake::OneRtt(connecting);
    }
    match connecting.into_0rtt() {
        Ok((connection, accepted)) => ClientHandshake::ZeroRtt {
            connection,
            accepted,
        },
        Err(connecting) => ClientHandshake::OneRtt(connecting),
    }
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
    let profile_token = ApplicationProfile::from(config.multipath.mode).profile_token();
    let mut transport = match config.tls.as_ref() {
        Some(tls) => {
            #[cfg(feature = "tls-rustls")]
            {
                let mut crypto = RustlsClientConfig::builder_with_provider(Arc::new(
                    noq::rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[&noq::rustls::version::TLS13])?
                .with_root_certificates(load_roots(&tls.ca_cert)?)
                .with_client_auth_cert(
                    load_certificates(&tls.client_cert)?,
                    load_private_key(&tls.client_key)?,
                )?;
                crypto.alpn_protocols = vec![profile_token.to_vec()];
                // Server-side early OPEN admission is not wired yet, so advertising 0-RTT would
                // let a peer replay application payload past the bounded OPEN header.
                crypto.enable_early_data = false;
                noq::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?))
            }
            #[cfg(not(feature = "tls-rustls"))]
            {
                let _ = tls;
                return Err(TransportError::TlsFeatureDisabled);
            }
        }
        None => noq::ClientConfig::new(Arc::new(NoSecurityClientConfig::new(profile_token))),
    };
    let transport_config = backend_transport_config(config.multipath.mode);
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
    let mut transport = match config.tls.as_ref() {
        Some(tls) => {
            #[cfg(feature = "tls-rustls")]
            {
                let provider = Arc::new(noq::rustls::crypto::ring::default_provider());
                let client_verifier = WebPkiClientVerifier::builder_with_provider(
                    Arc::new(load_roots(&tls.client_ca)?),
                    Arc::clone(&provider),
                )
                .build()?;
                let mut crypto = noq::rustls::ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&noq::rustls::version::TLS13])?
                    .with_client_cert_verifier(client_verifier)
                    .with_single_cert(
                        load_certificates(&tls.server_cert)?,
                        load_private_key(&tls.server_key)?,
                    )?;
                crypto.alpn_protocols = [
                    ApplicationProfile::SinglePath,
                    ApplicationProfile::Multipath,
                ]
                .into_iter()
                .map(|profile| profile.profile_token().to_vec())
                .collect();
                noq::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?))
            }
            #[cfg(not(feature = "tls-rustls"))]
            {
                let _ = tls;
                return Err(TransportError::TlsFeatureDisabled);
            }
        }
        None => noq::ServerConfig::with_crypto(Arc::new(NoSecurityServerConfig)),
    };
    let transport_config = backend_transport_config(MultipathMode::Failover);
    transport
        .transport_config(Arc::new(transport_config))
        .max_incoming(usize::from(MAX_PENDING_HANDSHAKES))
        .incoming_buffer_size(u64::from(PENDING_HANDSHAKE_BYTES))
        .incoming_buffer_size_total(
            u64::from(MAX_PENDING_HANDSHAKES) * u64::from(PENDING_HANDSHAKE_BYTES),
        );
    Ok(transport)
}

#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
#[derive(Debug)]
struct MultipathSocket {
    children: [Box<dyn AsyncUdpSocket>; 2],
    routes: [(IpAddr, SocketAddr); 2],
    next_recv: usize,
}

#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
impl MultipathSocket {
    fn new(
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

#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
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

#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
fn is_path_unavailable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::NetworkUnreachable
    )
}

#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
#[derive(Debug)]
struct MultipathSender {
    children: [Pin<Box<dyn UdpSender>>; 2],
    routes: [(IpAddr, SocketAddr); 2],
}

#[cfg(any(
    all(test, feature = "runtime-tokio"),
    all(target_os = "linux", feature = "runtime-tokio")
))]
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
    let mut endpoint_config = noq::EndpointConfig::default();
    endpoint_config.grease_quic_bit(config.tls.is_some());
    let endpoint = noq::Endpoint::new_with_abstract_socket(endpoint_config, None, socket, runtime)?;
    endpoint.set_default_client_config(build_client_config(config)?);
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
    let mut endpoint_config = noq::EndpointConfig::default();
    endpoint_config.grease_quic_bit(config.tls.is_some());
    Ok(noq::Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(build_server_config(config)?),
        socket,
        runtime,
    )?)
}

/// Builds a client endpoint whose underlay is raw TCP-shaped packets rather than UDP.
///
/// Each path owns independent tuple-bound carrier state. The caller opens configured backup paths
/// on the established connection.
///
/// # Errors
///
/// Returns an error for the temporary TLS-backed adapter, raw-socket setup, or the selected
/// runtime adapter.
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
pub fn build_fake_tcp_client_endpoint(
    config: &ClientConfig,
    paths: &[(FourTuple, SynDataMode)],
) -> Result<noq::Endpoint, TransportError> {
    if paths.len() != usize::from(config.multipath.mode.path_limit())
        || paths.len() != config.multipath.candidates.len()
        || paths
            .iter()
            .zip(&config.multipath.candidates)
            .any(|((tuple, _), candidate)| {
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
    let socket = bind_fake_tcp_paths(
        paths,
        CarrierDirection::ClientToServer,
        config.carrier.packet_socket,
    )?;
    build_client_endpoint_with_socket(config, socket, Arc::new(noq::TokioRuntime))
}

/// Builds a server endpoint whose underlay is raw TCP-shaped packets rather than UDP.
///
/// Every path source must be admitted by the server's listen-address policy.
///
/// # Errors
///
/// Returns an error for the temporary TLS-backed adapter or raw-socket setup.
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
pub fn build_fake_tcp_server_endpoint(
    config: &ServerConfig,
    paths: &[(FourTuple, SynDataMode)],
) -> Result<noq::Endpoint, TransportError> {
    if paths.is_empty()
        || paths.len() > 2
        || paths
            .iter()
            .any(|(tuple, _)| !config.listen_addrs.contains(&tuple.source))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FakeTCP paths are outside the server listen allowlist",
        )
        .into());
    }
    let socket = bind_fake_tcp_paths(
        paths,
        CarrierDirection::ServerToClient,
        config.carrier.packet_socket,
    )?;
    build_server_endpoint_with_socket(config, socket, Arc::new(noq::TokioRuntime))
}

#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
fn bind_fake_tcp_paths(
    paths: &[(FourTuple, SynDataMode)],
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
    let bind = |(tuple, syn_data)| FakeTcpSocket::bind(tuple, direction, syn_data, packet_socket);
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

#[cfg(feature = "tls-rustls")]
fn load_roots(path: &Path) -> Result<RootCertStore, TransportError> {
    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(path)? {
        roots.add(certificate)?;
    }
    Ok(roots)
}

#[cfg(feature = "tls-rustls")]
fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    let bytes = read_trusted_file(path, MAX_TLS_FILE_BYTES, TrustedFileMode::SharedReadable)?;
    let certificates = CertificateDer::pem_slice_iter(&bytes).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(TransportError::EmptyCertificateFile(path.to_owned()));
    }
    Ok(certificates)
}

#[cfg(feature = "tls-rustls")]
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TransportError> {
    Ok(PrivateKeyDer::from_pem_slice(&read_trusted_file(
        path,
        MAX_TLS_FILE_BYTES,
        TrustedFileMode::OwnerOnly,
    )?)?)
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[cfg(feature = "tls-rustls")]
    #[error(transparent)]
    Pem(#[from] PemError),
    #[cfg(feature = "tls-rustls")]
    #[error(transparent)]
    Tls(#[from] noq::rustls::Error),
    #[cfg(feature = "tls-rustls")]
    #[error(transparent)]
    ClientVerifier(#[from] VerifierBuilderError),
    #[cfg(feature = "tls-rustls")]
    #[error(transparent)]
    BackendCrypto(#[from] NoInitialCipherSuite),
    #[cfg(feature = "tls-rustls")]
    #[error("certificate file is empty: {0}")]
    EmptyCertificateFile(PathBuf),
    #[error("TLS configuration requires the `tls-rustls` feature")]
    TlsFeatureDisabled,
}

#[cfg(all(test, feature = "runtime-tokio"))]
mod tests {
    use std::io::{self, IoSliceMut};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::num::{NonZeroU16, NonZeroUsize};
    #[cfg(all(feature = "tls-rustls", unix))]
    use std::os::unix::fs::PermissionsExt;
    use std::pin::Pin;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::task::{Context, Poll};
    use std::time::Duration;

    use noq::udp::{RecvMeta, Transmit};
    use noq::{AsyncUdpSocket, FourTuple, PathError, PathId, PathStatus, Runtime, UdpSender};
    #[cfg(all(feature = "tls-rustls", unix))]
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(not(feature = "tls-rustls"))]
    use super::TransportError;
    #[cfg(all(feature = "tls-rustls", unix))]
    use super::{ClientHandshake, start_client_handshake};
    use super::{
        MultipathSocket, build_client_config, build_client_endpoint_with_socket,
        build_server_config, build_server_endpoint_with_socket,
    };
    use crate::config::{
        CarrierConfig, ClientConfig, Ipv4Pool, Multipath, MultipathMode, PathCandidate,
        ServerConfig, ZeroRttMode,
    };
    #[cfg(any(not(feature = "tls-rustls"), all(feature = "tls-rustls", unix)))]
    use crate::config::{ClientTls, ServerTls};
    #[cfg(all(feature = "tls-rustls", unix))]
    use crate::session::{ResumptionCache, ResumptionMetadata, ResumptionPolicy};

    #[derive(Debug)]
    struct FailingSocket {
        inner: Box<dyn AsyncUdpSocket>,
        enabled: Arc<AtomicBool>,
    }

    impl AsyncUdpSocket for FailingSocket {
        fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
            Box::pin(FailingSender {
                inner: self.inner.create_sender(),
                enabled: Arc::clone(&self.enabled),
            })
        }

        fn poll_recv(
            &mut self,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            if self.enabled.load(Ordering::Relaxed) {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::NetworkDown)))
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
    }

    impl UdpSender for FailingSender {
        fn poll_send(
            mut self: Pin<&mut Self>,
            transmit: &Transmit<'_>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            if self.enabled.load(Ordering::Relaxed) {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::NetworkDown)))
            } else {
                self.inner.as_mut().poll_send(transmit, cx)
            }
        }

        fn max_transmit_segments(&self) -> NonZeroUsize {
            self.inner.max_transmit_segments()
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn plaintext_flows_preserve_status_isolation_and_half_close() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let directory = tempfile::tempdir().unwrap();
            let client = ClientConfig {
                journal_path: directory.path().join("fakeip.journal"),
                fake_ip_pool: "198.18.0.0/15".parse::<Ipv4Pool>().unwrap(),
                fake_dns_addr: Ipv4Addr::new(198, 18, 0, 1),
                zero_rtt: ZeroRttMode::Off,
                tls: None,
                multipath: Multipath {
                    mode: MultipathMode::Off,
                    candidates: vec![PathCandidate {
                        name: "primary".to_owned(),
                        local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        server_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
                    }],
                },
                carrier: CarrierConfig::default(),
            };
            let server = ServerConfig {
                listen_addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 4433))],
                tls: None,
                carrier: CarrierConfig::default(),
            };
            let server_endpoint = noq::Endpoint::server(
                build_server_config(&server).unwrap(),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let client_endpoint =
                noq::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            client_endpoint.set_default_client_config(build_client_config(&client).unwrap());

            let server_connection =
                async { server_endpoint.accept().await.unwrap().await.unwrap() };
            let client_connection = async {
                client_endpoint
                    .connect(server_addr, "quicp")
                    .unwrap()
                    .await
                    .unwrap()
            };
            let (server_connection, client_connection) =
                tokio::join!(server_connection, client_connection);
            crate::session::ApplicationProfile::SinglePath
                .authenticate_connection(&client_connection, true)
                .expect("plaintext single-path admission");
            crate::session::ApplicationProfile::SinglePath
                .authenticate_connection(&server_connection, true)
                .expect("plaintext server admission");
            assert!(matches!(
                crate::session::ApplicationProfile::Multipath
                    .authenticate_connection(&client_connection, true),
                Err(crate::session::SessionError::ProfileMismatch)
            ));
            crate::session::ApplicationProfile::admit_negotiated(&client_connection, true)
                .expect("negotiated plaintext profile");
            let blocked_request = crate::wire::OpenRequest::new(
                crate::wire::CanonicalHost::parse("blocked.example").unwrap(),
                NonZeroU16::new(80).unwrap(),
            );
            let blocked_client = {
                let connection = client_connection.clone();
                let request = blocked_request.clone();
                tokio::spawn(
                    async move { crate::flow::QuicpFlow::open(&connection, request).await },
                )
            };
            let blocked_pending = crate::flow::accept_flow(&server_connection).await.unwrap();
            assert_eq!(blocked_pending.request(), &blocked_request);
            assert!(!blocked_client.is_finished());

            let ready_request = crate::wire::OpenRequest::new(
                crate::wire::CanonicalHost::parse("ready.example").unwrap(),
                NonZeroU16::new(443).unwrap(),
            );
            let ready_client = {
                let connection = client_connection.clone();
                let request = ready_request.clone();
                tokio::spawn(
                    async move { crate::flow::QuicpFlow::open(&connection, request).await },
                )
            };
            let ready_pending = crate::flow::accept_flow(&server_connection).await.unwrap();
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
        })
        .await
        .expect("plaintext flow E2E timed out");
    }

    #[cfg(not(feature = "tls-rustls"))]
    #[test]
    fn rejects_tls_configuration_when_feature_is_disabled() {
        let tls_path = std::path::PathBuf::from("unused.pem");
        let client = ClientConfig {
            journal_path: std::path::PathBuf::from("unused.journal"),
            fake_ip_pool: "198.18.0.0/15".parse::<Ipv4Pool>().unwrap(),
            fake_dns_addr: Ipv4Addr::new(198, 18, 0, 1),
            zero_rtt: ZeroRttMode::Off,
            tls: Some(ClientTls {
                server_name: "server.example".to_owned(),
                ca_cert: tls_path.clone(),
                client_cert: tls_path.clone(),
                client_key: tls_path.clone(),
            }),
            multipath: Multipath {
                mode: MultipathMode::Off,
                candidates: vec![PathCandidate {
                    name: "primary".to_owned(),
                    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    server_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
                }],
            },
            carrier: CarrierConfig::default(),
        };
        let server = ServerConfig {
            listen_addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 4433))],
            tls: Some(ServerTls {
                server_cert: tls_path.clone(),
                server_key: tls_path.clone(),
                client_ca: tls_path,
            }),
            carrier: CarrierConfig::default(),
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
        let directory = tempfile::tempdir().unwrap();
        let client = ClientConfig {
            journal_path: directory.path().join("fakeip.journal"),
            fake_ip_pool: "198.18.0.0/15".parse::<Ipv4Pool>().unwrap(),
            fake_dns_addr: Ipv4Addr::new(198, 18, 0, 1),
            zero_rtt: ZeroRttMode::Off,
            tls: None,
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
        };
        let server = ServerConfig {
            listen_addrs: vec![server_primary_addr, server_backup_addr],
            tls: None,
            carrier: CarrierConfig::default(),
        };
        let runtime: Arc<dyn Runtime> = Arc::new(noq::TokioRuntime);
        let primary_failed = Arc::new(AtomicBool::new(false));
        let wrap_primary = |socket| -> Box<dyn AsyncUdpSocket> {
            Box::new(FailingSocket {
                inner: runtime.wrap_udp_socket(socket).unwrap(),
                enabled: Arc::clone(&primary_failed),
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
                .connect(server_primary_addr, "quicp")
                .unwrap()
                .await
                .unwrap()
        };
        let (server_connection, client_connection) =
            tokio::join!(server_connection, client_connection);
        let stable_id = client_connection.stable_id();
        let backup = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match client_connection
                    .open_path(
                        FourTuple::new(server_backup_addr, Some(client_backup_addr.ip())),
                        PathStatus::Backup,
                    )
                    .await
                {
                    Ok(path) => break path,
                    Err(PathError::RemoteCidsExhausted) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(error) => panic!("backup path failed: {error}"),
                }
            }
        })
        .await
        .expect("backup path timed out");
        assert_eq!(backup.status().unwrap(), PathStatus::Backup);

        let server_flow = async {
            crate::flow::accept_flow(&server_connection)
                .await
                .unwrap()
                .accept()
                .await
                .unwrap()
        };
        let client_flow = async {
            crate::flow::QuicpFlow::open(
                &client_connection,
                crate::wire::OpenRequest::new(
                    crate::wire::CanonicalHost::parse("example.com").unwrap(),
                    NonZeroU16::new(443).unwrap(),
                ),
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

        let primary = client_connection.path(PathId::ZERO).expect("primary path");
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
    }

    #[cfg(all(feature = "tls-rustls", unix))]
    #[tokio::test]
    async fn authenticates_mutual_tls_and_both_alpn_profiles() {
        let directory = tempfile::tempdir().unwrap();
        let directory = std::fs::canonicalize(directory.path()).unwrap();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(["server.example".to_owned()]).unwrap();
        let cert_path = directory.join("node.pem");
        let key_path = directory.join("node.key");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut client = ClientConfig {
            journal_path: directory.join("fakeip.journal"),
            fake_ip_pool: "198.18.0.0/15".parse::<Ipv4Pool>().unwrap(),
            fake_dns_addr: Ipv4Addr::new(198, 18, 0, 1),
            zero_rtt: ZeroRttMode::SafeOpenOnly,
            tls: Some(ClientTls {
                server_name: "server.example".to_owned(),
                ca_cert: cert_path.clone(),
                client_cert: cert_path.clone(),
                client_key: key_path.clone(),
            }),
            multipath: Multipath {
                mode: MultipathMode::Off,
                candidates: vec![PathCandidate {
                    name: "primary".to_owned(),
                    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    server_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
                }],
            },
            carrier: CarrierConfig::default(),
        };
        let server = ServerConfig {
            listen_addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 4433))],
            tls: Some(ServerTls {
                server_cert: cert_path.clone(),
                server_key: key_path,
                client_ca: cert_path,
            }),
            carrier: CarrierConfig::default(),
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
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn server_rejects_0rtt_until_safe_open_admission_exists() {
        let directory = tempfile::tempdir().unwrap();
        let directory = std::fs::canonicalize(directory.path()).unwrap();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(["server.example".to_owned()]).unwrap();
        let cert_path = directory.join("node.pem");
        let key_path = directory.join("node.key");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let client = ClientConfig {
            journal_path: directory.join("fakeip.journal"),
            fake_ip_pool: "198.18.0.0/15".parse::<Ipv4Pool>().unwrap(),
            fake_dns_addr: Ipv4Addr::new(198, 18, 0, 1),
            zero_rtt: ZeroRttMode::SafeOpenOnly,
            tls: Some(ClientTls {
                server_name: "server.example".to_owned(),
                ca_cert: cert_path.clone(),
                client_cert: cert_path.clone(),
                client_key: key_path.clone(),
            }),
            multipath: Multipath {
                mode: MultipathMode::Off,
                candidates: vec![PathCandidate {
                    name: "primary".to_owned(),
                    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    server_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
                }],
            },
            carrier: CarrierConfig::default(),
        };
        let server = ServerConfig {
            listen_addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 4433))],
            tls: Some(ServerTls {
                server_cert: cert_path.clone(),
                server_key: key_path.clone(),
                client_ca: cert_path,
            }),
            carrier: CarrierConfig::default(),
        };
        let server_endpoint = noq::Endpoint::server(
            build_server_config(&server).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let client_endpoint =
            noq::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        client_endpoint.set_default_client_config(build_client_config(&client).unwrap());

        let first_server = async {
            server_endpoint
                .accept()
                .await
                .expect("first incoming")
                .await
                .unwrap()
        };
        let first_client = async {
            client_endpoint
                .connect(server_addr, &client.tls.as_ref().unwrap().server_name)
                .unwrap()
                .await
                .unwrap()
        };
        let (first_server, first_client) = tokio::join!(first_server, first_client);
        let (mut ticket, _ticket_recv) = first_server.open_bi().await.unwrap();
        ticket.write_all(b"ticket").await.unwrap();
        ticket.finish().unwrap();
        let (_ticket_copy_send, mut ticket_copy) = first_client.accept_bi().await.unwrap();
        assert_eq!(ticket_copy.read_to_end(1024).await.unwrap(), b"ticket");

        let mut cache = ResumptionCache::new();
        cache.insert(ResumptionMetadata::new(
            [7; 32],
            10_000,
            1,
            crate::session::ApplicationProfile::SinglePath,
            crate::session::MAX_OPEN_HEADER,
        ));
        let policy = ResumptionPolicy {
            mode: ZeroRttMode::SafeOpenOnly,
            server_fingerprint: [7; 32],
            now_unix_seconds: 9_999,
            policy_epoch: 1,
            profile: crate::session::ApplicationProfile::SinglePath,
            header_limit: crate::session::MAX_OPEN_HEADER,
        };
        let server_second = tokio::spawn(async move {
            server_endpoint
                .accept()
                .await
                .expect("second incoming")
                .await
                .unwrap()
        });
        let handshake = start_client_handshake(
            client_endpoint
                .connect(server_addr, &client.tls.as_ref().unwrap().server_name)
                .unwrap(),
            &mut cache,
            &policy,
        );
        assert!(matches!(handshake, ClientHandshake::OneRtt(_)));
        let (second_client, accepted) = handshake.finish().await.unwrap();
        let second_server = server_second.await.unwrap();
        assert!(accepted.is_none());
        let (mut request, _request_recv) = second_client.open_bi().await.unwrap();
        request.write_all(b"one-rtt-header").await.unwrap();
        request.finish().unwrap();
        let (_received_send, mut received) = second_server.accept_bi().await.unwrap();
        assert_eq!(received.read_to_end(1024).await.unwrap(), b"one-rtt-header");
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
            wrong_profile.authenticate_connection(&server_connection, true),
            Err(crate::session::SessionError::ProfileMismatch)
        );
        profile
            .authenticate_connection(&server_connection, true)
            .unwrap();
        profile
            .authenticate_connection(&client_connection, true)
            .unwrap();
    }
}
