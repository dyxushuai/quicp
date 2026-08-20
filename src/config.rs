use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

use crate::faketcp::{FourTuple, SynDataMode, issue_syn_cookie};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

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
        verify_parent_directories(path)?;
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

#[cfg(target_os = "linux")]
fn secure_open(path: &Path) -> Result<File, rustix::io::Errno> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};

    rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn secure_open(path: &Path) -> Result<File, rustix::io::Errno> {
    use rustix::fs::{Mode, OFlags};

    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
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
fn verify_parent_directories(path: &Path) -> Result<(), ConfigError> {
    for parent in path.parent().ok_or(ConfigError::MissingParent)?.ancestors() {
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.file_type().is_dir() {
            return Err(ConfigError::UnsafeParent(parent.to_owned()));
        }
        verify_owner_and_mode(parent, &metadata)?;
    }
    Ok(())
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Config {
    Client(ClientConfig),
    Server(ServerConfig),
}

impl Config {
    /// Parses and validates one immutable configuration snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed TOML or an invalid trust-boundary value.
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(input)?;
        raw.validate()
    }

    #[must_use]
    pub const fn client(&self) -> Option<&ClientConfig> {
        match self {
            Self::Client(config) => Some(config),
            Self::Server(_) => None,
        }
    }

    #[must_use]
    pub const fn server(&self) -> Option<&ServerConfig> {
        match self {
            Self::Server(config) => Some(config),
            Self::Client(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    pub journal_path: PathBuf,
    pub fake_ip_pool: Ipv4Pool,
    pub fake_dns_addr: Ipv4Addr,
    pub zero_rtt: ZeroRttMode,
    /// Temporary `noq` backend security settings; not part of the no-security QUICP core.
    pub tls: Option<ClientTls>,
    pub multipath: Multipath,
    pub carrier: CarrierConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub listen_addrs: Vec<SocketAddr>,
    /// Temporary `noq` backend security settings; not part of the no-security QUICP core.
    pub tls: Option<ServerTls>,
    pub carrier: CarrierConfig,
}

/// TLS settings for the temporary backend adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientTls {
    pub server_name: String,
    pub ca_cert: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

/// Server TLS settings for the temporary backend adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerTls {
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_ca: PathBuf,
}

/// Raw `FakeTCP` carrier policy shared by client and server.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CarrierConfig {
    #[serde(default)]
    pub syn_data: SynDataPolicy,
    #[serde(default = "default_cookie_secret_file")]
    pub cookie_secret_file: PathBuf,
    /// Use filtered Linux `AF_PACKET` sockets for both directions instead of IP raw sockets.
    #[serde(default)]
    pub packet_socket: bool,
}

impl Default for CarrierConfig {
    fn default() -> Self {
        Self {
            syn_data: SynDataPolicy::Cookie,
            cookie_secret_file: default_cookie_secret_file(),
            packet_socket: false,
        }
    }
}

impl CarrierConfig {
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

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SynDataPolicy {
    Disabled,
    #[default]
    Cookie,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Multipath {
    pub mode: MultipathMode,
    pub candidates: Vec<PathCandidate>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PathCandidate {
    pub name: String,
    pub local_ip: IpAddr,
    pub server_addr: SocketAddr,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MultipathMode {
    Off,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum ZeroRttMode {
    #[serde(rename = "off")]
    Off,
    #[serde(rename = "safe-open-only")]
    SafeOpenOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Pool {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Pool {
    #[must_use]
    pub fn contains(self, address: Ipv4Addr) -> bool {
        let mask = u32::MAX
            .checked_shl(u32::from(32 - self.prefix_len))
            .unwrap_or(0);
        u32::from(address) & mask == u32::from(self.network)
    }

    #[must_use]
    pub const fn network(self) -> Ipv4Addr {
        self.network
    }

    #[must_use]
    pub fn broadcast(self) -> Ipv4Addr {
        let host_mask = u32::MAX
            .checked_shr(u32::from(self.prefix_len))
            .unwrap_or(0);
        Ipv4Addr::from(u32::from(self.network) | host_mask)
    }

    #[must_use]
    pub fn is_usable(self, address: Ipv4Addr) -> bool {
        self.contains(address) && address != self.network() && address != self.broadcast()
    }
}

impl std::fmt::Display for Ipv4Pool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for Ipv4Pool {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| "IPv4 pool must use CIDR notation".to_owned())?;
        let address = address
            .parse::<Ipv4Addr>()
            .map_err(|error| error.to_string())?;
        let prefix_len = prefix.parse::<u8>().map_err(|error| error.to_string())?;
        if prefix_len > 32 {
            return Err("IPv4 prefix length must be at most 32".to_owned());
        }
        let mask = u32::MAX
            .checked_shl(u32::from(32 - prefix_len))
            .unwrap_or(0);
        let network = Ipv4Addr::from(u32::from(address) & mask);
        if network != address {
            return Err("IPv4 pool contains host bits".to_owned());
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }
}

impl<'de> Deserialize<'de> for Ipv4Pool {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration path must be absolute")]
    PathNotAbsolute,
    #[error("configuration loading is supported only on Unix")]
    UnsupportedPlatform,
    #[error("configuration I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(unix)]
    #[error("secure configuration open failed: {0}")]
    SecureOpen(#[from] rustix::io::Errno),
    #[error("configuration path has no parent directory")]
    MissingParent,
    #[error("trusted file is too large: {0}")]
    FileTooLarge(PathBuf),
    #[error("configuration path is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error("unsafe configuration parent: {0}")]
    UnsafeParent(PathBuf),
    #[error("configuration path {path} is owned by uid {owner}")]
    WrongOwner { path: PathBuf, owner: u32 },
    #[error("configuration path {path} has unsafe mode {mode:#o}")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("multipath mode {mode:?} requires {expected} path candidate(s), got {actual}")]
    CandidateCount {
        mode: MultipathMode,
        expected: usize,
        actual: usize,
    },
    #[error("duplicate path candidate name {0}")]
    DuplicateCandidateName(String),
    #[error("duplicate path candidate tuple {local_ip} -> {server_addr}")]
    DuplicateCandidateTuple {
        local_ip: IpAddr,
        server_addr: SocketAddr,
    },
    #[error("path candidate {name} uses different IP families")]
    AddressFamilyMismatch { name: String },
    #[error("path candidate {name} has an unusable address")]
    UnusableCandidateAddress { name: String },
    #[error("FakeDNS address {address} is outside pool {pool}")]
    FakeDnsOutsidePool { address: Ipv4Addr, pool: Ipv4Pool },
    #[error("FakeDNS address {0} is a network or broadcast address")]
    UnusableFakeDnsAddress(Ipv4Addr),
    #[error("server listen allowlist must not be empty")]
    EmptyListenAllowlist,
    #[error("duplicate server listen address {0}")]
    DuplicateListenAddress(SocketAddr),
    #[error("port must be nonzero")]
    ZeroPort,
    #[error("FakeTCP SYN-cookie secret path must be absolute: {0}")]
    CookieSecretPathNotAbsolute(PathBuf),
    #[error("FakeTCP SYN-cookie secret is empty: {0}")]
    CookieSecretEmpty(PathBuf),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "role", rename_all = "lowercase", deny_unknown_fields)]
enum RawConfig {
    Client {
        journal_path: PathBuf,
        fake_ip_pool: Ipv4Pool,
        fake_dns_addr: Ipv4Addr,
        zero_rtt: ZeroRttMode,
        #[serde(default)]
        tls: Option<ClientTls>,
        multipath: Multipath,
        #[serde(default)]
        carrier: CarrierConfig,
    },
    Server {
        listen_addrs: Vec<SocketAddr>,
        #[serde(default)]
        tls: Option<ServerTls>,
        #[serde(default)]
        carrier: CarrierConfig,
    },
}

impl RawConfig {
    fn validate(self) -> Result<Config, ConfigError> {
        match self {
            Self::Client {
                journal_path,
                fake_ip_pool,
                fake_dns_addr,
                zero_rtt,
                tls,
                multipath,
                carrier,
            } => {
                if !fake_ip_pool.contains(fake_dns_addr) {
                    return Err(ConfigError::FakeDnsOutsidePool {
                        address: fake_dns_addr,
                        pool: fake_ip_pool,
                    });
                }
                if !fake_ip_pool.is_usable(fake_dns_addr) {
                    return Err(ConfigError::UnusableFakeDnsAddress(fake_dns_addr));
                }
                validate_multipath(&multipath)?;
                carrier.validate()?;
                Ok(Config::Client(ClientConfig {
                    journal_path,
                    fake_ip_pool,
                    fake_dns_addr,
                    zero_rtt,
                    tls,
                    multipath,
                    carrier,
                }))
            }
            Self::Server {
                listen_addrs,
                tls,
                carrier,
            } => {
                if listen_addrs.is_empty() {
                    return Err(ConfigError::EmptyListenAllowlist);
                }
                let mut unique = HashSet::new();
                for address in &listen_addrs {
                    if address.port() == 0 {
                        return Err(ConfigError::ZeroPort);
                    }
                    if !unique.insert(*address) {
                        return Err(ConfigError::DuplicateListenAddress(*address));
                    }
                }
                carrier.validate()?;
                Ok(Config::Server(ServerConfig {
                    listen_addrs,
                    tls,
                    carrier,
                }))
            }
        }
    }
}

fn validate_multipath(multipath: &Multipath) -> Result<(), ConfigError> {
    let expected = usize::from(multipath.mode.path_limit());
    if multipath.candidates.len() != expected {
        return Err(ConfigError::CandidateCount {
            mode: multipath.mode,
            expected,
            actual: multipath.candidates.len(),
        });
    }

    let mut names = HashSet::new();
    let mut tuples = HashSet::new();
    for candidate in &multipath.candidates {
        if !names.insert(candidate.name.as_str()) {
            return Err(ConfigError::DuplicateCandidateName(candidate.name.clone()));
        }
        if !tuples.insert((candidate.local_ip, candidate.server_addr)) {
            return Err(ConfigError::DuplicateCandidateTuple {
                local_ip: candidate.local_ip,
                server_addr: candidate.server_addr,
            });
        }
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
