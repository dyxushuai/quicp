//! Validated endpoint, security, path, and carrier configuration.
//!
//! TOML loading and programmatic constructors share the same validation rules. Invariant-bearing
//! fields stay private so endpoint construction can validate the complete snapshot again.

use std::cmp::min;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::faketcp::{FourTuple, SynDataMode, issue_syn_cookie};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// QUIC's minimum UDP payload size.
pub const MIN_QUIC_PAYLOAD: u16 = 1200;
/// QUIC's maximum UDP payload size.
pub const MAX_QUIC_PAYLOAD: u16 = 65_527;
/// Maximum per-flow buffer allocated by the transport.
pub const MAX_FLOW_BUFFER_BYTES: u32 = 16 * 1024 * 1024;
/// Maximum bytes retained for one pending handshake.
pub const MAX_PENDING_HANDSHAKE_BUFFER_BYTES: u32 = 1024 * 1024;
const DEFAULT_OUTER_IP_MTU: u16 = 1500;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_PMTU_INTERVAL: Duration = Duration::from_secs(600);
const DEFAULT_PMTU_BLACK_HOLE_COOLDOWN: Duration = Duration::from_secs(60);
const MAX_CONFIG_WINDOW: u64 = (1u64 << 62) - 1;

/// Loads one bounded, owner-checked configuration snapshot.
///
/// # Errors
///
/// Returns an error for an unsafe path, file metadata, read failure, or invalid config.
pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let input = read_trusted_file(path, MAX_CONFIG_BYTES, TrustedFileMode::SharedReadable)?;
    let input = String::from_utf8(input)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Config::parse(&input)
}

pub(crate) fn read_trusted_file(
    path: &Path,
    max_bytes: u64,
    mode: TrustedFileMode,
) -> Result<Vec<u8>, ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError::PathNotAbsolute);
    }

    #[cfg(unix)]
    let mut file = secure_open(path)?;
    #[cfg(not(unix))]
    return Err(ConfigError::UnsupportedPlatform);

    #[cfg(unix)]
    {
        let metadata = verify_file(path, &file)?;
        if mode == TrustedFileMode::OwnerOnly && metadata.mode() & 0o077 != 0 {
            return Err(ConfigError::InsecurePermissions {
                path: path.to_owned(),
                mode: metadata.mode() & 0o7777,
            });
        }
        if metadata.len() > max_bytes {
            return Err(ConfigError::FileTooLarge(path.to_owned()));
        }

        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len()).expect("bounded file length fits usize"),
        );
        file.by_ref().take(max_bytes + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max_bytes {
            return Err(ConfigError::FileTooLarge(path.to_owned()));
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrustedFileMode {
    SharedReadable,
    OwnerOnly,
}

#[cfg(unix)]
fn secure_open(path: &Path) -> Result<File, ConfigError> {
    use rustix::fs::{Mode, OFlags};
    use std::path::Component;

    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => names.push(name.to_owned()),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(secure_open_error(rustix::io::Errno::INVAL));
            }
        }
    }
    let file_name = names
        .pop()
        .ok_or_else(|| secure_open_error(rustix::io::Errno::INVAL))?;
    let start = if path.is_absolute() { "/" } else { "." };
    let directory_flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY;
    let mut directory = File::from(
        rustix::fs::open(start, directory_flags, Mode::empty()).map_err(secure_open_error)?,
    );
    let mut directory_path = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    };
    verify_directory(&directory_path, &directory)?;
    for name in names {
        let next = rustix::fs::openat(&directory, &name, directory_flags, Mode::empty())
            .map_err(secure_open_error)?;
        directory = File::from(next);
        directory_path.push(&name);
        verify_directory(&directory_path, &directory)?;
    }

    rustix::fs::openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(secure_open_error)
}

#[cfg(unix)]
fn secure_open_error(error: rustix::io::Errno) -> ConfigError {
    ConfigError::SecureOpen(error.into())
}

#[cfg(unix)]
fn verify_file(path: &Path, file: &File) -> Result<std::fs::Metadata, ConfigError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(ConfigError::NotRegularFile(path.to_owned()));
    }
    verify_owner_and_mode(path, &metadata)?;
    Ok(metadata)
}

#[cfg(unix)]
fn verify_directory(path: &Path, file: &File) -> Result<(), ConfigError> {
    let metadata = file.metadata()?;
    verify_owner_and_mode(path, &metadata)
}

#[cfg(unix)]
fn verify_owner_and_mode(path: &Path, metadata: &std::fs::Metadata) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;

    let owner = metadata.uid();
    let current = rustix::process::geteuid().as_raw();
    if owner != 0 && owner != current {
        return Err(ConfigError::WrongOwner {
            path: path.to_owned(),
            owner,
        });
    }
    let mode = metadata.mode();
    if mode & 0o022 != 0 {
        return Err(ConfigError::InsecurePermissions {
            path: path.to_owned(),
            mode: mode & 0o7777,
        });
    }
    Ok(())
}

/// A validated client or server configuration snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Config {
    /// Client endpoint configuration.
    Client(ClientConfig),
    /// Server endpoint configuration.
    Server(ServerConfig),
}

impl Config {
    /// Parses and validates one immutable configuration snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed TOML or an invalid trust-boundary value.
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(input)
            .map_err(|error: toml::de::Error| ConfigError::Toml(error.to_string()))?;
        raw.validate()
    }

    #[must_use]
    /// Returns the client configuration when this snapshot has the client role.
    pub const fn client(&self) -> Option<&ClientConfig> {
        match self {
            Self::Client(config) => Some(config),
            Self::Server(_) => None,
        }
    }

    #[must_use]
    /// Returns the server configuration when this snapshot has the server role.
    pub const fn server(&self) -> Option<&ServerConfig> {
        match self {
            Self::Server(config) => Some(config),
            Self::Client(_) => None,
        }
    }
}

/// Validated client security, path, and carrier settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    /// Temporary `noq` backend security settings; not part of the no-security QUICP core.
    pub(crate) tls: Option<ClientTls>,
    /// Explicitly permits the unauthenticated no-security profile when TLS is absent.
    pub(crate) allow_insecure: bool,
    pub(crate) multipath: Multipath,
    pub(crate) carrier: CarrierConfig,
    pub(crate) transport: QuicpTransportConfig,
}

/// Validated server security, listen-address, and carrier settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub(crate) listen_addrs: Vec<SocketAddr>,
    /// Temporary `noq` backend security settings; not part of the no-security QUICP core.
    pub(crate) tls: Option<ServerTls>,
    /// Explicitly permits the unauthenticated no-security profile when TLS is absent.
    pub(crate) allow_insecure: bool,
    pub(crate) carrier: CarrierConfig,
    pub(crate) transport: QuicpTransportConfig,
}

impl ClientConfig {
    /// Creates an explicitly unauthenticated client configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the multipath or carrier configuration is invalid.
    pub fn insecure(multipath: Multipath, carrier: CarrierConfig) -> Result<Self, ConfigError> {
        Self::from_parts(None, true, multipath, carrier, None)
    }

    /// Creates a client configuration using the supplied TLS identity and trust material.
    ///
    /// # Errors
    ///
    /// Returns an error when TLS, multipath, or carrier configuration is invalid.
    pub fn with_tls(
        tls: ClientTls,
        multipath: Multipath,
        carrier: CarrierConfig,
    ) -> Result<Self, ConfigError> {
        Self::from_parts(Some(tls), false, multipath, carrier, None)
    }

    fn from_parts(
        tls: Option<ClientTls>,
        allow_insecure: bool,
        multipath: Multipath,
        carrier: CarrierConfig,
        transport: Option<QuicpTransportConfig>,
    ) -> Result<Self, ConfigError> {
        let congestion_control = carrier.congestion_control;
        let config = Self {
            tls,
            allow_insecure,
            multipath,
            carrier,
            transport: transport.unwrap_or_else(|| {
                QuicpTransportConfig::default().with_congestion_control(congestion_control)
            }),
        };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        validate_security_profile(self.tls.is_some(), self.allow_insecure)?;
        if let Some(tls) = &self.tls {
            tls.validate()?;
        }
        validate_multipath(&self.multipath)?;
        self.carrier.validate()?;
        self.transport.validate()
    }

    #[must_use]
    /// Returns the TLS settings, or `None` for the explicitly insecure profile.
    pub const fn tls(&self) -> Option<&ClientTls> {
        self.tls.as_ref()
    }

    #[must_use]
    /// Returns whether the unauthenticated profile was explicitly selected.
    pub const fn allow_insecure(&self) -> bool {
        self.allow_insecure
    }

    #[must_use]
    /// Returns the validated path configuration.
    pub const fn multipath(&self) -> &Multipath {
        &self.multipath
    }

    #[must_use]
    /// Returns the raw-carrier policy.
    pub const fn carrier(&self) -> &CarrierConfig {
        &self.carrier
    }

    #[must_use]
    /// Returns the validated QUICP transport policy.
    pub const fn transport(&self) -> &QuicpTransportConfig {
        &self.transport
    }

    /// Replaces the transport policy and validates the complete client snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy is invalid for the client snapshot.
    pub fn with_transport(mut self, transport: QuicpTransportConfig) -> Result<Self, ConfigError> {
        self.transport = transport;
        self.validate()?;
        Ok(self)
    }
}

impl ServerConfig {
    /// Creates an explicitly unauthenticated server configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the listen allowlist or carrier configuration is invalid.
    pub fn insecure(
        listen_addrs: Vec<SocketAddr>,
        carrier: CarrierConfig,
    ) -> Result<Self, ConfigError> {
        Self::from_parts(listen_addrs, None, true, carrier, None)
    }

    /// Creates a server configuration using the supplied TLS identity and trust material.
    ///
    /// # Errors
    ///
    /// Returns an error when the listen allowlist, TLS, or carrier configuration is invalid.
    pub fn with_tls(
        listen_addrs: Vec<SocketAddr>,
        tls: ServerTls,
        carrier: CarrierConfig,
    ) -> Result<Self, ConfigError> {
        Self::from_parts(listen_addrs, Some(tls), false, carrier, None)
    }

    fn from_parts(
        listen_addrs: Vec<SocketAddr>,
        tls: Option<ServerTls>,
        allow_insecure: bool,
        carrier: CarrierConfig,
        transport: Option<QuicpTransportConfig>,
    ) -> Result<Self, ConfigError> {
        let congestion_control = carrier.congestion_control;
        let config = Self {
            listen_addrs,
            tls,
            allow_insecure,
            carrier,
            transport: transport.unwrap_or_else(|| {
                QuicpTransportConfig::default().with_congestion_control(congestion_control)
            }),
        };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        validate_listen_addrs(&self.listen_addrs)?;
        validate_security_profile(self.tls.is_some(), self.allow_insecure)?;
        if let Some(tls) = &self.tls {
            tls.validate()?;
        }
        self.carrier.validate()?;
        self.transport.validate()
    }

    #[must_use]
    /// Returns the validated server listen-address allowlist.
    pub fn listen_addrs(&self) -> &[SocketAddr] {
        &self.listen_addrs
    }

    #[must_use]
    /// Returns the TLS settings, or `None` for the explicitly insecure profile.
    pub const fn tls(&self) -> Option<&ServerTls> {
        self.tls.as_ref()
    }

    #[must_use]
    /// Returns whether the unauthenticated profile was explicitly selected.
    pub const fn allow_insecure(&self) -> bool {
        self.allow_insecure
    }

    #[must_use]
    /// Returns the raw-carrier policy.
    pub const fn carrier(&self) -> &CarrierConfig {
        &self.carrier
    }

    #[must_use]
    /// Returns the validated QUICP transport policy.
    pub const fn transport(&self) -> &QuicpTransportConfig {
        &self.transport
    }

    /// Replaces the transport policy and validates the complete server snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy is invalid for the server snapshot.
    pub fn with_transport(mut self, transport: QuicpTransportConfig) -> Result<Self, ConfigError> {
        self.transport = transport;
        self.validate()?;
        Ok(self)
    }
}

/// TLS settings for the temporary backend adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientTls {
    pub(crate) server_name: String,
    pub(crate) ca_cert: PathBuf,
    pub(crate) client_cert: PathBuf,
    pub(crate) client_key: PathBuf,
}

impl ClientTls {
    /// Creates validated client TLS settings.
    ///
    /// # Errors
    ///
    /// Returns an error when the server name is empty or any material path is not absolute.
    pub fn new(
        server_name: impl Into<String>,
        ca_cert: impl Into<PathBuf>,
        client_cert: impl Into<PathBuf>,
        client_key: impl Into<PathBuf>,
    ) -> Result<Self, ConfigError> {
        let tls = Self {
            server_name: server_name.into(),
            ca_cert: ca_cert.into(),
            client_cert: client_cert.into(),
            client_key: client_key.into(),
        };
        tls.validate()?;
        Ok(tls)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.server_name.is_empty() {
            return Err(ConfigError::EmptyTlsServerName);
        }
        validate_tls_paths([&self.ca_cert, &self.client_cert, &self.client_key])
    }

    #[must_use]
    /// Returns the server name authenticated by TLS.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    #[must_use]
    /// Returns the trusted certificate-authority file.
    pub fn ca_cert(&self) -> &Path {
        &self.ca_cert
    }

    #[must_use]
    /// Returns the client certificate-chain file.
    pub fn client_cert(&self) -> &Path {
        &self.client_cert
    }

    #[must_use]
    /// Returns the client private-key file.
    pub fn client_key(&self) -> &Path {
        &self.client_key
    }
}

/// Server TLS settings for the temporary backend adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerTls {
    pub(crate) server_cert: PathBuf,
    pub(crate) server_key: PathBuf,
    pub(crate) client_ca: PathBuf,
}

impl ServerTls {
    /// Creates validated server TLS settings.
    ///
    /// # Errors
    ///
    /// Returns an error when any material path is not absolute.
    pub fn new(
        server_cert: impl Into<PathBuf>,
        server_key: impl Into<PathBuf>,
        client_ca: impl Into<PathBuf>,
    ) -> Result<Self, ConfigError> {
        let tls = Self {
            server_cert: server_cert.into(),
            server_key: server_key.into(),
            client_ca: client_ca.into(),
        };
        tls.validate()?;
        Ok(tls)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_tls_paths([&self.server_cert, &self.server_key, &self.client_ca])
    }

    #[must_use]
    /// Returns the server certificate-chain file.
    pub fn server_cert(&self) -> &Path {
        &self.server_cert
    }

    #[must_use]
    /// Returns the server private-key file.
    pub fn server_key(&self) -> &Path {
        &self.server_key
    }

    #[must_use]
    /// Returns the certificate authority used to authenticate clients.
    pub fn client_ca(&self) -> &Path {
        &self.client_ca
    }
}

/// MSS advertisement policy for the TCP-shaped carrier.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum MssMode {
    /// Derive MSS from the configured outer IP MTU and path address family.
    #[default]
    Auto,
    /// Advertise a caller-selected MSS after validating it against the path envelope.
    Fixed(u16),
}

/// QUIC path MTU discovery policy.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PmtuMode {
    /// Let the carrier capability decide whether backend discovery is enabled.
    #[default]
    Auto,
    /// Use the configured static payload and do not probe.
    Disabled,
    /// Require a non-fragmenting carrier so probing is meaningful.
    Required,
}

/// Explicit MTU, MSS, and PMTU units for one QUICP transport policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MtuConfig {
    /// Complete outer IP packet MTU used by raw `FakeTCP`, in bytes.
    #[serde(default = "default_outer_ip_mtu")]
    pub outer_ip_mtu: u16,
    /// Maximum QUIC payload, excluding outer IP and carrier headers, in bytes.
    #[serde(default)]
    pub max_quic_payload: Option<u16>,
    /// Initial QUIC payload used before path discovery, in bytes.
    #[serde(default = "default_quic_payload")]
    pub initial_quic_payload: u16,
    /// Minimum QUIC payload after black-hole recovery, in bytes.
    #[serde(default = "default_quic_payload")]
    pub min_quic_payload: u16,
    /// SYN MSS advertisement policy.
    #[serde(default)]
    pub mss: MssMode,
    /// QUIC path MTU discovery policy.
    #[serde(default)]
    pub pmtu: PmtuMode,
    /// Optional upper bound for discovered QUIC payload, in bytes.
    #[serde(default)]
    pub pmtu_upper_bound: Option<u16>,
    /// Time between PMTU discovery runs.
    #[serde(default = "default_pmtu_interval")]
    pub pmtu_interval: Duration,
    /// Smallest payload change that is worth retaining.
    #[serde(default = "default_pmtu_minimum_change")]
    pub pmtu_minimum_change: u16,
    /// Delay before retrying after a PMTU black-hole event.
    #[serde(default = "default_pmtu_black_hole_cooldown")]
    pub pmtu_black_hole_cooldown: Duration,
}

impl Default for MtuConfig {
    fn default() -> Self {
        Self {
            outer_ip_mtu: DEFAULT_OUTER_IP_MTU,
            max_quic_payload: None,
            initial_quic_payload: MIN_QUIC_PAYLOAD,
            min_quic_payload: MIN_QUIC_PAYLOAD,
            mss: MssMode::Auto,
            pmtu: PmtuMode::Auto,
            pmtu_upper_bound: None,
            pmtu_interval: DEFAULT_PMTU_INTERVAL,
            pmtu_minimum_change: 20,
            pmtu_black_hole_cooldown: DEFAULT_PMTU_BLACK_HOLE_COOLDOWN,
        }
    }
}

impl MtuConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if !(1260..=u16::MAX).contains(&self.outer_ip_mtu) {
            return Err(ConfigError::InvalidOuterMtu(self.outer_ip_mtu));
        }
        validate_payload("minimum QUIC payload", self.min_quic_payload)?;
        validate_payload("initial QUIC payload", self.initial_quic_payload)?;
        if self.min_quic_payload > self.initial_quic_payload {
            return Err(ConfigError::MtuOrdering {
                minimum: self.min_quic_payload,
                initial: self.initial_quic_payload,
                upper: self.pmtu_upper_bound.or(self.max_quic_payload),
            });
        }
        if let Some(maximum) = self.max_quic_payload {
            validate_payload("maximum QUIC payload", maximum)?;
            if self.initial_quic_payload > maximum {
                return Err(ConfigError::MtuOrdering {
                    minimum: self.min_quic_payload,
                    initial: self.initial_quic_payload,
                    upper: Some(maximum),
                });
            }
        }
        if let Some(upper) = self.pmtu_upper_bound {
            validate_payload("PMTU upper bound", upper)?;
            if upper < self.initial_quic_payload
                || self.max_quic_payload.is_some_and(|maximum| upper > maximum)
            {
                return Err(ConfigError::MtuOrdering {
                    minimum: self.min_quic_payload,
                    initial: self.initial_quic_payload,
                    upper: Some(upper),
                });
            }
        }
        if self.pmtu_interval.is_zero() || self.pmtu_black_hole_cooldown.is_zero() {
            return Err(ConfigError::ZeroPmtuDuration);
        }
        if self.pmtu_minimum_change == 0 {
            return Err(ConfigError::ZeroPmtuChange);
        }
        if let MssMode::Fixed(mss) = self.mss
            && (mss == 0 || mss > MAX_QUIC_PAYLOAD)
        {
            return Err(ConfigError::InvalidMss {
                mss,
                maximum: MAX_QUIC_PAYLOAD,
            });
        }
        Ok(())
    }

    pub(crate) fn safe_payload_for_family(&self, ipv4: bool) -> Result<u16, ConfigError> {
        let overhead = if ipv4 { 40 } else { 60 };
        let safe = self
            .outer_ip_mtu
            .checked_sub(overhead)
            .ok_or(ConfigError::InvalidOuterMtu(self.outer_ip_mtu))?;
        let ceiling = self
            .max_quic_payload
            .map_or(MAX_QUIC_PAYLOAD, |configured| {
                min(configured, MAX_QUIC_PAYLOAD)
            });
        let effective = min(safe, ceiling);
        if effective < self.initial_quic_payload || effective < self.min_quic_payload {
            return Err(ConfigError::PayloadExceedsCarrier {
                payload: self.initial_quic_payload.max(self.min_quic_payload),
                maximum: effective,
            });
        }
        if let MssMode::Fixed(mss) = self.mss {
            let mss_maximum = safe;
            if mss > mss_maximum {
                return Err(ConfigError::InvalidMss {
                    mss,
                    maximum: mss_maximum,
                });
            }
        }
        Ok(effective)
    }

    pub(crate) fn static_payload_ceiling(
        &self,
        adapter_mtu: Option<u16>,
        raw_families: impl IntoIterator<Item = bool>,
    ) -> Result<u16, ConfigError> {
        let mut ceiling = self.max_quic_payload.unwrap_or(MAX_QUIC_PAYLOAD);
        if let Some(adapter_mtu) = adapter_mtu {
            ceiling = min(ceiling, adapter_mtu);
        }
        for ipv4 in raw_families {
            ceiling = min(ceiling, self.safe_payload_for_family(ipv4)?);
        }
        if let Some(upper) = self.pmtu_upper_bound {
            ceiling = min(ceiling, upper);
        }
        if ceiling < self.initial_quic_payload || ceiling < self.min_quic_payload {
            return Err(ConfigError::PayloadExceedsCarrier {
                payload: self.initial_quic_payload.max(self.min_quic_payload),
                maximum: ceiling,
            });
        }
        Ok(ceiling)
    }
}

/// Runtime-neutral QUICP transport controls shared by client and server endpoints.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QuicpTransportConfig {
    /// MTU, MSS, and PMTU policy.
    #[serde(default)]
    pub mtu: MtuConfig,
    /// Maximum bytes sent without peer flow-control credit.
    #[serde(default = "default_connection_window")]
    pub connection_send_window: u64,
    /// Maximum bytes accepted across all streams.
    #[serde(default = "default_connection_window")]
    pub connection_receive_window: u64,
    /// Per-stream receive window.
    #[serde(default = "default_stream_window")]
    pub stream_receive_window: u32,
    /// Maximum peer-initiated bidirectional streams.
    #[serde(default = "default_bidi_streams")]
    pub max_concurrent_bidi_streams: u32,
    /// Maximum peer-initiated unidirectional streams.
    #[serde(default)]
    pub max_concurrent_uni_streams: u32,
    /// Connection idle timeout.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: Duration,
    /// Connection keepalive interval.
    #[serde(default = "default_keep_alive_interval")]
    pub keep_alive_interval: Duration,
    /// Per-path idle timeout.
    #[serde(default = "default_path_idle_timeout")]
    pub path_idle_timeout: Duration,
    /// Number of ack-eliciting packets before an ACK is requested.
    #[serde(default = "default_ack_threshold")]
    pub ack_eliciting_threshold: u32,
    /// Maximum ACK delay.
    #[serde(default = "default_ack_delay")]
    pub max_ack_delay: Duration,
    /// Default TCP_NODELAY-like flow behavior.
    #[serde(default = "default_nodelay")]
    pub default_nodelay: bool,
    /// Bounded per-flow write buffer.
    #[serde(default = "default_flow_buffer")]
    pub flow_write_buffer_bytes: u32,
    /// Maximum simultaneous server handshakes.
    #[serde(default = "default_pending_handshakes")]
    pub max_pending_handshakes: u16,
    /// Per-handshake buffered bytes.
    #[serde(default = "default_pending_handshake_buffer")]
    pub pending_handshake_buffer_bytes: u32,
    /// Maximum active server connections.
    #[serde(default = "default_active_connections")]
    pub max_active_connections: u16,
    /// Maximum active connections from one peer.
    #[serde(default = "default_active_connections_per_peer")]
    pub max_active_connections_per_peer: u16,
    /// Built-in congestion controller used by the QUICP transport.
    #[serde(default)]
    pub congestion_control: CongestionControl,
}

impl Default for QuicpTransportConfig {
    fn default() -> Self {
        Self {
            mtu: MtuConfig::default(),
            connection_send_window: 8 * 1024 * 1024,
            connection_receive_window: 8 * 1024 * 1024,
            stream_receive_window: 128 * 1024,
            max_concurrent_bidi_streams: 128,
            max_concurrent_uni_streams: 0,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            keep_alive_interval: DEFAULT_KEEP_ALIVE_INTERVAL,
            path_idle_timeout: DEFAULT_PATH_IDLE_TIMEOUT,
            ack_eliciting_threshold: 10,
            max_ack_delay: Duration::from_millis(1),
            default_nodelay: true,
            flow_write_buffer_bytes: 32 * 1024,
            max_pending_handshakes: 128,
            pending_handshake_buffer_bytes: 32 * 1024,
            max_active_connections: 128,
            max_active_connections_per_peer: 16,
            congestion_control: CongestionControl::Cubic,
        }
    }
}

impl QuicpTransportConfig {
    /// Replaces the MTU and PMTU policy.
    #[must_use]
    pub fn with_mtu(mut self, mtu: MtuConfig) -> Self {
        self.mtu = mtu;
        self
    }

    /// Selects the built-in congestion controller.
    #[must_use]
    pub const fn with_congestion_control(mut self, congestion_control: CongestionControl) -> Self {
        self.congestion_control = congestion_control;
        self
    }

    /// Selects the default TCP_NODELAY-like flow behavior.
    #[must_use]
    pub const fn with_nodelay(mut self, nodelay: bool) -> Self {
        self.default_nodelay = nodelay;
        self
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        self.mtu.validate()?;
        if self.connection_send_window == 0 || self.connection_send_window > MAX_CONFIG_WINDOW {
            return Err(ConfigError::InvalidTransportWindow(
                self.connection_send_window,
            ));
        }
        if self.connection_receive_window == 0 || self.connection_receive_window > MAX_CONFIG_WINDOW
        {
            return Err(ConfigError::InvalidTransportWindow(
                self.connection_receive_window,
            ));
        }
        if self.stream_receive_window == 0 {
            return Err(ConfigError::ZeroTransportValue("stream_receive_window"));
        }
        if self.max_concurrent_bidi_streams == 0 {
            return Err(ConfigError::ZeroTransportValue(
                "max_concurrent_bidi_streams",
            ));
        }
        if self.idle_timeout.is_zero()
            || self.keep_alive_interval.is_zero()
            || self.path_idle_timeout.is_zero()
            || self.max_ack_delay.is_zero()
        {
            return Err(ConfigError::ZeroTransportDuration);
        }
        if self.keep_alive_interval >= self.idle_timeout {
            return Err(ConfigError::KeepAliveNotShorter {
                keep_alive: self.keep_alive_interval,
                idle: self.idle_timeout,
            });
        }
        if self.path_idle_timeout >= self.idle_timeout {
            return Err(ConfigError::PathIdleNotShorter {
                path_idle: self.path_idle_timeout,
                idle: self.idle_timeout,
            });
        }
        if self.idle_timeout.as_millis() > MAX_CONFIG_WINDOW.into() {
            return Err(ConfigError::InvalidIdleTimeout(self.idle_timeout));
        }
        if self.ack_eliciting_threshold == 0 || self.flow_write_buffer_bytes == 0 {
            return Err(ConfigError::ZeroTransportValue("ACK or flow buffer"));
        }
        if self.flow_write_buffer_bytes > MAX_FLOW_BUFFER_BYTES {
            return Err(ConfigError::InvalidTransportBuffer {
                name: "flow_write_buffer_bytes",
                value: self.flow_write_buffer_bytes,
                maximum: MAX_FLOW_BUFFER_BYTES,
            });
        }
        if self.max_pending_handshakes == 0
            || self.pending_handshake_buffer_bytes == 0
            || self.max_active_connections == 0
            || self.max_active_connections_per_peer == 0
        {
            return Err(ConfigError::ZeroTransportValue("resource limit"));
        }
        if self.pending_handshake_buffer_bytes > MAX_PENDING_HANDSHAKE_BUFFER_BYTES {
            return Err(ConfigError::InvalidTransportBuffer {
                name: "pending_handshake_buffer_bytes",
                value: self.pending_handshake_buffer_bytes,
                maximum: MAX_PENDING_HANDSHAKE_BUFFER_BYTES,
            });
        }
        if self.max_active_connections_per_peer > self.max_active_connections {
            return Err(ConfigError::PerPeerLimitExceedsGlobal {
                per_peer: self.max_active_connections_per_peer,
                global: self.max_active_connections,
            });
        }
        u64::from(self.max_pending_handshakes)
            .checked_mul(u64::from(self.pending_handshake_buffer_bytes))
            .ok_or(ConfigError::HandshakeBudgetOverflow)?;
        Ok(())
    }
}

fn validate_payload(name: &'static str, value: u16) -> Result<(), ConfigError> {
    if !(MIN_QUIC_PAYLOAD..=MAX_QUIC_PAYLOAD).contains(&value) {
        return Err(ConfigError::InvalidPayload { name, value });
    }
    Ok(())
}

const fn default_outer_ip_mtu() -> u16 {
    DEFAULT_OUTER_IP_MTU
}

const fn default_quic_payload() -> u16 {
    MIN_QUIC_PAYLOAD
}

const fn default_pmtu_interval() -> Duration {
    DEFAULT_PMTU_INTERVAL
}

const fn default_pmtu_minimum_change() -> u16 {
    20
}

const fn default_pmtu_black_hole_cooldown() -> Duration {
    DEFAULT_PMTU_BLACK_HOLE_COOLDOWN
}

const fn default_connection_window() -> u64 {
    8 * 1024 * 1024
}

const fn default_stream_window() -> u32 {
    128 * 1024
}

const fn default_bidi_streams() -> u32 {
    128
}

const fn default_idle_timeout() -> Duration {
    DEFAULT_IDLE_TIMEOUT
}

const fn default_keep_alive_interval() -> Duration {
    DEFAULT_KEEP_ALIVE_INTERVAL
}

const fn default_path_idle_timeout() -> Duration {
    DEFAULT_PATH_IDLE_TIMEOUT
}

const fn default_ack_threshold() -> u32 {
    10
}

const fn default_ack_delay() -> Duration {
    Duration::from_millis(1)
}

const fn default_nodelay() -> bool {
    true
}

const fn default_flow_buffer() -> u32 {
    32 * 1024
}

const fn default_pending_handshakes() -> u16 {
    128
}

const fn default_pending_handshake_buffer() -> u32 {
    32 * 1024
}

const fn default_active_connections() -> u16 {
    128
}

const fn default_active_connections_per_peer() -> u16 {
    16
}

/// Raw `FakeTCP` carrier policy shared by client and server.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CarrierConfig {
    #[serde(default)]
    pub(crate) syn_data: SynDataPolicy,
    #[serde(default = "default_cookie_secret_file")]
    pub(crate) cookie_secret_file: PathBuf,
    /// Use filtered Linux `AF_PACKET` sockets for both directions instead of IP raw sockets.
    #[serde(default)]
    pub(crate) packet_socket: bool,
    /// Selects the built-in congestion controller used by the QUICP transport.
    #[serde(default)]
    pub(crate) congestion_control: CongestionControl,
}

impl Default for CarrierConfig {
    fn default() -> Self {
        Self {
            syn_data: SynDataPolicy::Cookie,
            cookie_secret_file: default_cookie_secret_file(),
            packet_socket: false,
            congestion_control: CongestionControl::Cubic,
        }
    }
}

impl CarrierConfig {
    /// Creates a validated raw-carrier policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the SYN-cookie secret path is not absolute.
    pub fn new(
        syn_data: SynDataPolicy,
        cookie_secret_file: impl Into<PathBuf>,
        congestion_control: CongestionControl,
    ) -> Result<Self, ConfigError> {
        let config = Self {
            syn_data,
            cookie_secret_file: cookie_secret_file.into(),
            packet_socket: false,
            congestion_control,
        };
        config.validate()?;
        Ok(config)
    }

    /// Selects filtered Linux packet sockets for the raw carrier.
    #[must_use]
    pub const fn with_packet_socket(mut self, packet_socket: bool) -> Self {
        self.packet_socket = packet_socket;
        self
    }

    /// Loads the owner-only SYN-cookie secret.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is unsafe or the file is empty.
    pub fn load_cookie_secret(&self) -> Result<Vec<u8>, ConfigError> {
        let bytes = read_trusted_file(&self.cookie_secret_file, 64, TrustedFileMode::OwnerOnly)?;
        if bytes.is_empty() {
            return Err(ConfigError::CookieSecretEmpty(
                self.cookie_secret_file.clone(),
            ));
        }
        Ok(bytes)
    }

    /// Converts the configured policy into the tuple-bound SYN mode used by one path.
    #[must_use]
    pub fn syn_data_mode(&self, cookie_secret: &[u8], tuple: FourTuple, epoch: u64) -> SynDataMode {
        match self.syn_data {
            SynDataPolicy::Disabled => SynDataMode::Disabled,
            SynDataPolicy::Cookie => {
                SynDataMode::Cookie(issue_syn_cookie(cookie_secret, tuple, epoch))
            }
        }
    }

    #[must_use]
    /// Returns the configured SYN-data policy.
    pub const fn syn_data(&self) -> SynDataPolicy {
        self.syn_data
    }

    #[must_use]
    /// Returns the owner-only carrier-cookie secret path.
    pub fn cookie_secret_file(&self) -> &Path {
        &self.cookie_secret_file
    }

    #[must_use]
    /// Returns whether Linux packet sockets are selected over IP raw sockets.
    pub const fn packet_socket(&self) -> bool {
        self.packet_socket
    }

    #[must_use]
    /// Returns the selected built-in congestion controller.
    pub const fn congestion_control(&self) -> CongestionControl {
        self.congestion_control
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.cookie_secret_file.is_absolute() {
            return Err(ConfigError::CookieSecretPathNotAbsolute(
                self.cookie_secret_file.clone(),
            ));
        }
        Ok(())
    }
}

fn default_cookie_secret_file() -> PathBuf {
    PathBuf::from("/etc/quicp/carrier-cookie.secret")
}

/// Policy for TCP-shaped SYN payloads on the raw carrier.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SynDataPolicy {
    /// Disables SYN data; raw endpoint construction currently rejects this mode.
    Disabled,
    /// Carries a tuple-bound carrier cookie and backend handshake datagram.
    #[default]
    Cookie,
}

/// Built-in congestion-control algorithms for one QUICP connection/path.
///
/// This setting affects transport pacing and congestion windows; it does not change the QUICP
/// wire format or the `FakeTCP` carrier. Custom Rust controllers remain an advanced backend seam and
/// are intentionally not part of the C ABI yet.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum CongestionControl {
    /// CUBIC, the default profile.
    #[default]
    Cubic,
    /// RFC 6582-style New Reno.
    NewReno,
    /// `BBRv3` controller supplied by the vendored QUIC backend.
    Bbr3,
}

/// Validated single-path or primary/backup path selection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Multipath {
    pub(crate) mode: MultipathMode,
    pub(crate) candidates: Vec<PathCandidate>,
}

/// One named local-address to server-address path candidate.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PathCandidate {
    pub(crate) name: String,
    pub(crate) local_ip: IpAddr,
    pub(crate) server_addr: SocketAddr,
}

impl Multipath {
    /// Creates a single-path configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the candidate is invalid.
    pub fn single(primary: PathCandidate) -> Result<Self, ConfigError> {
        let multipath = Self {
            mode: MultipathMode::Off,
            candidates: vec![primary],
        };
        validate_multipath(&multipath)?;
        Ok(multipath)
    }

    /// Creates a failover configuration ordered primary, then backup.
    ///
    /// # Errors
    ///
    /// Returns an error when the candidates duplicate a name or path tuple.
    pub fn failover(primary: PathCandidate, backup: PathCandidate) -> Result<Self, ConfigError> {
        let multipath = Self {
            mode: MultipathMode::Failover,
            candidates: vec![primary, backup],
        };
        validate_multipath(&multipath)?;
        Ok(multipath)
    }

    #[must_use]
    /// Returns the configured path mode.
    pub const fn mode(&self) -> MultipathMode {
        self.mode
    }

    #[must_use]
    /// Returns candidates in primary-then-backup order.
    pub fn candidates(&self) -> &[PathCandidate] {
        &self.candidates
    }
}

impl PathCandidate {
    /// Creates one validated local-to-server path candidate.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty name, unusable address, mixed address family, or zero port.
    pub fn new(
        name: impl Into<String>,
        local_ip: IpAddr,
        server_addr: SocketAddr,
    ) -> Result<Self, ConfigError> {
        let candidate = Self {
            name: name.into(),
            local_ip,
            server_addr,
        };
        validate_path_candidate(&candidate)?;
        Ok(candidate)
    }

    #[must_use]
    /// Returns the diagnostic candidate name.
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    /// Returns the local source IP address.
    pub const fn local_ip(&self) -> IpAddr {
        self.local_ip
    }

    #[must_use]
    /// Returns the remote server socket address.
    pub const fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }
}

/// Supported path-selection modes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MultipathMode {
    /// Use exactly one path.
    Off,
    /// Keep one primary and one backup path.
    Failover,
}

impl MultipathMode {
    #[must_use]
    pub(crate) const fn path_limit(self) -> u8 {
        match self {
            Self::Off => 1,
            Self::Failover => 2,
        }
    }
}

/// Configuration loading and validation errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A trusted-file path was relative.
    #[error("configuration path must be absolute")]
    PathNotAbsolute,
    /// Secure trusted-file loading is unavailable on this platform.
    #[error("configuration loading is supported only on Unix")]
    UnsupportedPlatform,
    /// A trusted-file I/O operation failed.
    #[error("configuration I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(unix)]
    /// Opening a trusted file without following symlinks failed.
    #[error("secure configuration open failed: {0}")]
    SecureOpen(#[source] std::io::Error),
    /// A trusted file exceeded its bounded size.
    #[error("trusted file is too large: {0}")]
    FileTooLarge(PathBuf),
    /// A trusted path did not resolve to a regular file.
    #[error("configuration path is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    /// A trusted file is not owned by the current effective user.
    #[error("configuration path {path} is owned by uid {owner}")]
    WrongOwner {
        /// Rejected file path.
        path: PathBuf,
        /// Observed owner identifier.
        owner: u32,
    },
    /// A trusted file is writable by group or other users.
    #[error("configuration path {path} has unsafe mode {mode:#o}")]
    InsecurePermissions {
        /// Rejected file path.
        path: PathBuf,
        /// Observed Unix permission mode.
        mode: u32,
    },
    /// TOML parsing failed.
    #[error("invalid TOML: {0}")]
    Toml(String),
    /// A path mode was paired with the wrong number of candidates.
    #[error("multipath mode {mode:?} requires {expected} path candidate(s), got {actual}")]
    CandidateCount {
        /// Selected path mode.
        mode: MultipathMode,
        /// Required candidate count.
        expected: usize,
        /// Observed candidate count.
        actual: usize,
    },
    /// Two candidates used the same diagnostic name.
    #[error("duplicate path candidate name {0}")]
    DuplicateCandidateName(String),
    /// Two candidates used the same local/remote tuple.
    #[error("duplicate path candidate tuple {local_ip} -> {server_addr}")]
    DuplicateCandidateTuple {
        /// Duplicate local source address.
        local_ip: IpAddr,
        /// Duplicate remote server address.
        server_addr: SocketAddr,
    },
    /// A candidate mixed IPv4 and IPv6 endpoints.
    #[error("path candidate {name} uses different IP families")]
    AddressFamilyMismatch {
        /// Rejected candidate name.
        name: String,
    },
    /// A candidate used an unspecified, multicast, or otherwise unusable address.
    #[error("path candidate {name} has an unusable address")]
    UnusableCandidateAddress {
        /// Rejected candidate name.
        name: String,
    },
    /// A server configuration supplied no listen addresses.
    #[error("server listen allowlist must not be empty")]
    EmptyListenAllowlist,
    /// A server listen address appeared more than once.
    #[error("duplicate server listen address {0}")]
    DuplicateListenAddress(SocketAddr),
    /// A configured socket address used port zero.
    #[error("port must be nonzero")]
    ZeroPort,
    /// The carrier-cookie secret path was relative.
    #[error("FakeTCP SYN-cookie secret path must be absolute: {0}")]
    CookieSecretPathNotAbsolute(PathBuf),
    /// The carrier-cookie secret file was empty.
    #[error("FakeTCP SYN-cookie secret is empty: {0}")]
    CookieSecretEmpty(PathBuf),
    /// Client TLS settings supplied an empty server name.
    #[error("TLS server name must not be empty")]
    EmptyTlsServerName,
    /// A TLS material path was relative.
    #[error("TLS material path must be absolute: {0}")]
    TlsPathNotAbsolute(PathBuf),
    /// The no-security profile was not explicitly selected.
    #[error("the unauthenticated no-security profile requires allow_insecure = true")]
    InsecureProfileRequiresOptIn,
    /// TLS was combined with the explicit no-security opt-in.
    #[error("TLS configuration cannot be combined with allow_insecure = true")]
    TlsWithInsecureOptIn,
    /// The complete outer IP MTU is outside the supported envelope.
    #[error("outer IP MTU {0} must be between 1260 and 65535 bytes")]
    InvalidOuterMtu(u16),
    /// A QUIC payload is outside the backend's supported bounds.
    #[error("{name} {value} must be between 1200 and 65527 bytes")]
    InvalidPayload {
        /// Configuration field name.
        name: &'static str,
        /// Rejected value.
        value: u16,
    },
    /// MTU payload values are not monotonically ordered.
    #[error(
        "MTU payload ordering is invalid: minimum {minimum}, initial {initial}, upper {upper:?}"
    )]
    MtuOrdering {
        /// Configured minimum payload.
        minimum: u16,
        /// Configured initial payload.
        initial: u16,
        /// Configured upper payload.
        upper: Option<u16>,
    },
    /// The configured payload cannot fit the carrier envelope.
    #[error("QUIC payload {payload} exceeds the carrier maximum {maximum}")]
    PayloadExceedsCarrier {
        /// Requested payload.
        payload: u16,
        /// Derived carrier ceiling.
        maximum: u16,
    },
    /// A fixed MSS is outside the safe carrier envelope.
    #[error("FakeTCP MSS {mss} exceeds the safe maximum {maximum}")]
    InvalidMss {
        /// Rejected MSS.
        mss: u16,
        /// Safe MSS ceiling.
        maximum: u16,
    },
    /// A PMTU timer was zero.
    #[error("PMTU interval and black-hole cooldown must be nonzero")]
    ZeroPmtuDuration,
    /// A PMTU minimum change was zero.
    #[error("PMTU minimum change must be nonzero")]
    ZeroPmtuChange,
    /// A transport window was outside the QUIC variable-integer range.
    #[error("transport window {0} must be between 1 and 2^62-1")]
    InvalidTransportWindow(u64),
    /// A bounded transport buffer exceeded the implementation safety limit.
    #[error("transport buffer {name}={value} exceeds maximum {maximum}")]
    InvalidTransportBuffer {
        /// Configuration field name.
        name: &'static str,
        /// Rejected byte count.
        value: u32,
        /// Maximum supported byte count.
        maximum: u32,
    },
    /// A transport value that must be positive was zero.
    #[error("transport value {0} must be nonzero")]
    ZeroTransportValue(&'static str),
    /// A transport duration that must be positive was zero.
    #[error("transport durations must be nonzero")]
    ZeroTransportDuration,
    /// The connection idle timeout cannot be represented by QUIC's millisecond varint.
    #[error("idle timeout {0:?} exceeds the QUIC varint range")]
    InvalidIdleTimeout(Duration),
    /// Keepalive would not prevent the idle timeout.
    #[error("keepalive interval {keep_alive:?} must be shorter than idle timeout {idle:?}")]
    KeepAliveNotShorter {
        /// Configured keepalive interval.
        keep_alive: Duration,
        /// Configured idle timeout.
        idle: Duration,
    },
    /// A path would expire after the connection has already expired.
    #[error("path idle timeout {path_idle:?} must be shorter than idle timeout {idle:?}")]
    PathIdleNotShorter {
        /// Configured path idle timeout.
        path_idle: Duration,
        /// Configured connection idle timeout.
        idle: Duration,
    },
    /// A per-peer limit exceeded the global active-connection limit.
    #[error("per-peer connection limit {per_peer} exceeds global limit {global}")]
    PerPeerLimitExceedsGlobal {
        /// Per-peer limit.
        per_peer: u16,
        /// Global limit.
        global: u16,
    },
    /// The handshake memory-budget multiplication overflowed.
    #[error("pending handshake memory budget overflowed")]
    HandshakeBudgetOverflow,
    /// PMTU probing was required on a carrier that may fragment.
    #[error("PMTU discovery is required but the selected carrier may fragment")]
    PmtuRequiresNonFragmentingCarrier,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "role", rename_all = "lowercase", deny_unknown_fields)]
enum RawConfig {
    Client {
        #[serde(default)]
        tls: Option<ClientTls>,
        #[serde(default)]
        allow_insecure: bool,
        multipath: Multipath,
        #[serde(default)]
        carrier: CarrierConfig,
        #[serde(default)]
        transport: Option<QuicpTransportConfig>,
    },
    Server {
        listen_addrs: Vec<SocketAddr>,
        #[serde(default)]
        tls: Option<ServerTls>,
        #[serde(default)]
        allow_insecure: bool,
        #[serde(default)]
        carrier: CarrierConfig,
        #[serde(default)]
        transport: Option<QuicpTransportConfig>,
    },
}

impl RawConfig {
    fn validate(self) -> Result<Config, ConfigError> {
        match self {
            Self::Client {
                tls,
                allow_insecure,
                multipath,
                carrier,
                transport,
            } => Ok(Config::Client(ClientConfig::from_parts(
                tls,
                allow_insecure,
                multipath,
                carrier,
                transport,
            )?)),
            Self::Server {
                listen_addrs,
                tls,
                allow_insecure,
                carrier,
                transport,
            } => Ok(Config::Server(ServerConfig::from_parts(
                listen_addrs,
                tls,
                allow_insecure,
                carrier,
                transport,
            )?)),
        }
    }
}

fn validate_tls_paths<'a>(paths: impl IntoIterator<Item = &'a PathBuf>) -> Result<(), ConfigError> {
    for path in paths {
        if !path.is_absolute() {
            return Err(ConfigError::TlsPathNotAbsolute(path.clone()));
        }
    }
    Ok(())
}

fn validate_listen_addrs(listen_addrs: &[SocketAddr]) -> Result<(), ConfigError> {
    if listen_addrs.is_empty() {
        return Err(ConfigError::EmptyListenAllowlist);
    }
    let mut unique = HashSet::new();
    for address in listen_addrs {
        if address.port() == 0 {
            return Err(ConfigError::ZeroPort);
        }
        if !unique.insert(*address) {
            return Err(ConfigError::DuplicateListenAddress(*address));
        }
    }
    Ok(())
}

pub(crate) const fn validate_security_profile(
    tls_configured: bool,
    allow_insecure: bool,
) -> Result<(), ConfigError> {
    match (tls_configured, allow_insecure) {
        (false, false) => Err(ConfigError::InsecureProfileRequiresOptIn),
        (true, true) => Err(ConfigError::TlsWithInsecureOptIn),
        _ => Ok(()),
    }
}

pub(crate) fn validate_multipath(multipath: &Multipath) -> Result<(), ConfigError> {
    let expected = usize::from(multipath.mode.path_limit());
    if multipath.candidates.len() != expected {
        return Err(ConfigError::CandidateCount {
            mode: multipath.mode,
            expected,
            actual: multipath.candidates.len(),
        });
    }

    for candidate in &multipath.candidates {
        validate_path_candidate(candidate)?;
    }
    if let [primary, backup] = multipath.candidates.as_slice() {
        if primary.name == backup.name {
            return Err(ConfigError::DuplicateCandidateName(backup.name.clone()));
        }
        if (primary.local_ip, primary.server_addr) == (backup.local_ip, backup.server_addr) {
            return Err(ConfigError::DuplicateCandidateTuple {
                local_ip: backup.local_ip,
                server_addr: backup.server_addr,
            });
        }
    }
    Ok(())
}

fn validate_path_candidate(candidate: &PathCandidate) -> Result<(), ConfigError> {
    if candidate.local_ip.is_ipv4() != candidate.server_addr.is_ipv4() {
        return Err(ConfigError::AddressFamilyMismatch {
            name: candidate.name.clone(),
        });
    }
    if candidate.name.is_empty()
        || candidate.local_ip.is_unspecified()
        || candidate.local_ip.is_multicast()
        || candidate.server_addr.ip().is_unspecified()
        || candidate.server_addr.ip().is_multicast()
    {
        return Err(ConfigError::UnusableCandidateAddress {
            name: candidate.name.clone(),
        });
    }
    if candidate.server_addr.port() == 0 {
        return Err(ConfigError::ZeroPort);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::{ConfigError, TrustedFileMode, read_trusted_file};

    #[test]
    fn private_material_must_be_owner_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("client.key");
        std::fs::write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        assert!(matches!(
            read_trusted_file(&path, 1024, TrustedFileMode::OwnerOnly),
            Err(ConfigError::InsecurePermissions { .. })
        ));
    }
}
