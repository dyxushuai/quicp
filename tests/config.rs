use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use quicp::load_config;
use quicp::{
    CarrierConfig, ClientConfig, ClientTls, Config, ConfigError, CongestionControl, FourTuple,
    MAX_FLOW_BUFFER_BYTES, MssMode, MtuConfig, Multipath, MultipathMode, PathCandidate, PmtuMode,
    QuicpTransportConfig, ServerConfig, ServerTls, SynDataMode, SynDataPolicy,
};

const CLIENT_PREFIX: &str = r#"
role = "client"

[tls]
server_name = "gateway.example.com"
ca_cert = "/etc/quicp/ca.pem"
client_cert = "/etc/quicp/client.pem"
client_key = "/etc/quicp/client.key"

[multipath]
mode = "failover"
"#;

fn secure_tempdir() -> tempfile::TempDir {
    let home = std::env::var_os("HOME").expect("HOME is required for trusted temporary files");
    tempfile::tempdir_in(home).expect("trusted temporary directory")
}

fn candidate(name: &str, local: Ipv4Addr, remote: Ipv4Addr, port: u16) -> PathCandidate {
    PathCandidate::new(name, IpAddr::V4(local), SocketAddr::from((remote, port))).unwrap()
}

#[test]
fn programmatic_configuration_uses_the_same_validation_rules() {
    let primary = candidate(
        "primary",
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 10),
        4433,
    );
    let backup = candidate(
        "backup",
        Ipv4Addr::new(192, 0, 2, 11),
        Ipv4Addr::new(203, 0, 113, 10),
        4433,
    );
    let client = ClientConfig::insecure(
        Multipath::failover(primary.clone(), backup).unwrap(),
        CarrierConfig::default(),
    )
    .unwrap();
    let server = ServerConfig::insecure(
        vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 4433))],
        CarrierConfig::default(),
    )
    .unwrap();

    assert_eq!(client.multipath().candidates().len(), 2);
    assert_eq!(client.multipath().candidates()[0], primary);
    assert_eq!(server.listen_addrs().len(), 1);

    assert!(matches!(
        PathCandidate::new(
            "",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
        ),
        Err(ConfigError::UnusableCandidateAddress { .. })
    ));
    assert!(matches!(
        PathCandidate::new(
            "mixed",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 4433)),
        ),
        Err(ConfigError::AddressFamilyMismatch { .. })
    ));
    assert!(matches!(
        PathCandidate::new(
            "zero-port",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        ),
        Err(ConfigError::ZeroPort)
    ));
    assert!(matches!(
        PathCandidate::new(
            "unspecified",
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
        ),
        Err(ConfigError::UnusableCandidateAddress { .. })
    ));
    assert!(matches!(
        Multipath::failover(primary.clone(), primary),
        Err(ConfigError::DuplicateCandidateName(_))
    ));
    let tuple_duplicate = candidate(
        "different-name",
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 10),
        4433,
    );
    assert!(matches!(
        Multipath::failover(
            candidate(
                "primary",
                Ipv4Addr::new(192, 0, 2, 10),
                Ipv4Addr::new(203, 0, 113, 10),
                4433,
            ),
            tuple_duplicate,
        ),
        Err(ConfigError::DuplicateCandidateTuple { .. })
    ));
    assert!(matches!(
        ServerConfig::insecure(Vec::new(), CarrierConfig::default()),
        Err(ConfigError::EmptyListenAllowlist)
    ));
}

#[test]
fn transport_policy_exposes_explicit_mtu_units_and_validation() {
    let primary = candidate(
        "primary",
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 10),
        4433,
    );
    let client = ClientConfig::insecure(
        Multipath::single(primary).unwrap(),
        CarrierConfig::default(),
    )
    .unwrap();
    assert_eq!(client.transport().mtu.outer_ip_mtu, 1500);
    assert_eq!(client.transport().mtu.mss, MssMode::Auto);

    let policy = QuicpTransportConfig {
        mtu: MtuConfig {
            outer_ip_mtu: 1280,
            pmtu: PmtuMode::Disabled,
            ..MtuConfig::default()
        },
        ..QuicpTransportConfig::default()
    };
    let configured = client.clone().with_transport(policy).unwrap();
    assert_eq!(configured.transport().mtu.outer_ip_mtu, 1280);
    assert_eq!(configured.transport().mtu.pmtu, PmtuMode::Disabled);

    let invalid = QuicpTransportConfig {
        mtu: MtuConfig {
            outer_ip_mtu: 1200,
            ..MtuConfig::default()
        },
        ..QuicpTransportConfig::default()
    };
    assert!(matches!(
        client.with_transport(invalid),
        Err(ConfigError::InvalidOuterMtu(1200))
    ));

    let oversized_flow_buffer = QuicpTransportConfig {
        flow_write_buffer_bytes: MAX_FLOW_BUFFER_BYTES + 1,
        ..QuicpTransportConfig::default()
    };
    assert!(matches!(
        configured.with_transport(oversized_flow_buffer),
        Err(ConfigError::InvalidTransportBuffer {
            name: "flow_write_buffer_bytes",
            ..
        })
    ));
}

#[test]
fn parses_transport_policy_without_backend_types() {
    let config = Config::parse(
        r#"
role = "client"
allow_insecure = true

[multipath]
mode = "off"

[[multipath.candidates]]
name = "primary"
local_ip = "192.0.2.10"
server_addr = "203.0.113.10:4433"

[transport]
idle_timeout = { secs = 30, nanos = 0 }
keep_alive_interval = { secs = 1, nanos = 0 }
path_idle_timeout = { secs = 5, nanos = 0 }

[transport.mtu]
outer_ip_mtu = 1280
pmtu = "disabled"
mss = { fixed = 1200 }
"#,
    )
    .unwrap();
    let client = config.client().unwrap();
    assert_eq!(client.transport().mtu.outer_ip_mtu, 1280);
    assert_eq!(client.transport().mtu.pmtu, PmtuMode::Disabled);
    assert_eq!(client.transport().mtu.mss, MssMode::Fixed(1200));
    assert_eq!(
        client.transport().idle_timeout,
        std::time::Duration::from_secs(30)
    );
}

#[test]
fn tls_and_carrier_programmatic_constructors_validate_paths() {
    let absolute = PathBuf::from("/etc/quicp/material.pem");
    assert!(matches!(
        ClientTls::new("", absolute.clone(), absolute.clone(), absolute.clone(),),
        Err(ConfigError::EmptyTlsServerName)
    ));
    assert!(matches!(
        ServerTls::new("relative.pem", absolute.clone(), absolute.clone()),
        Err(ConfigError::TlsPathNotAbsolute(_))
    ));
    assert!(matches!(
        CarrierConfig::new(
            SynDataPolicy::Cookie,
            "relative.secret",
            CongestionControl::Cubic,
        ),
        Err(ConfigError::CookieSecretPathNotAbsolute(_))
    ));

    let client_tls = ClientTls::new(
        "gateway.example.com",
        absolute.clone(),
        absolute.clone(),
        absolute.clone(),
    )
    .unwrap();
    let server_tls = ServerTls::new(absolute.clone(), absolute.clone(), absolute).unwrap();
    let primary = candidate(
        "primary",
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 10),
        4433,
    );
    let client = ClientConfig::with_tls(
        client_tls,
        Multipath::single(primary).unwrap(),
        CarrierConfig::default(),
    )
    .unwrap();
    let server = ServerConfig::with_tls(
        vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 4433))],
        server_tls,
        CarrierConfig::default(),
    )
    .unwrap();
    assert!(!client.allow_insecure());
    assert!(!server.allow_insecure());
}

#[test]
fn parses_failover_client_with_exactly_two_paths() {
    let input = format!(
        "{CLIENT_PREFIX}{}",
        r#"
[[multipath.candidates]]
name = "wifi"
local_ip = "192.0.2.10"
server_addr = "203.0.113.10:4433"

[[multipath.candidates]]
name = "cellular"
local_ip = "192.0.2.11"
server_addr = "203.0.113.10:4433"
"#
    );

    let config = Config::parse(&input).expect("valid config");
    let client = config.client().expect("client config");

    assert_eq!(client.multipath().mode(), MultipathMode::Failover);
    assert_eq!(client.multipath().candidates().len(), 2);
}

#[test]
fn transport_config_rejects_platform_adapter_fields() {
    let input = r#"
role = "client"
journal_path = "/var/lib/quicp/fakeip.journal"
fake_ip_pool = "198.18.0.0/15"
fake_dns_addr = "198.18.0.1"
allow_insecure = true

[multipath]
mode = "off"
"#;

    assert!(matches!(Config::parse(input), Err(ConfigError::Toml(_))));
}

#[test]
fn transport_config_rejects_obsolete_zero_rtt_switch() {
    let input = r#"
role = "client"
zero_rtt = "safe-open-only"
allow_insecure = true

[multipath]
mode = "off"

[[multipath.candidates]]
name = "primary"
local_ip = "192.0.2.10"
server_addr = "203.0.113.10:4433"
"#;

    assert!(matches!(Config::parse(input), Err(ConfigError::Toml(_))));
}

#[test]
fn rejects_wrong_candidate_count_for_mode() {
    let input = format!(
        "{CLIENT_PREFIX}{}",
        r#"
[[multipath.candidates]]
name = "wifi"
local_ip = "192.0.2.10"
server_addr = "203.0.113.10:4433"
"#
    );

    assert!(matches!(
        Config::parse(&input),
        Err(ConfigError::CandidateCount {
            mode: MultipathMode::Failover,
            expected: 2,
            actual: 1,
        })
    ));
}

#[test]
fn rejects_duplicate_candidate_names_and_tuples() {
    let input = format!(
        "{CLIENT_PREFIX}{}",
        r#"
[[multipath.candidates]]
name = "same"
local_ip = "192.0.2.10"
server_addr = "203.0.113.10:4433"

[[multipath.candidates]]
name = "same"
local_ip = "192.0.2.10"
server_addr = "203.0.113.10:4433"
"#
    );

    assert!(matches!(
        Config::parse(&input),
        Err(ConfigError::DuplicateCandidateName(name)) if name == "same"
    ));
}

#[test]
fn parses_server_listen_allowlist() {
    let input = r#"
role = "server"
listen_addrs = ["0.0.0.0:4433", "[::]:4433"]

[tls]
server_cert = "/etc/quicp/server.pem"
server_key = "/etc/quicp/server.key"
client_ca = "/etc/quicp/client-ca.pem"
"#;

    let config = Config::parse(input).expect("valid server config");
    assert_eq!(
        config.server().expect("server config").listen_addrs().len(),
        2
    );
}

#[test]
fn parses_server_without_tls() {
    let config = Config::parse(
        r#"
role = "server"
listen_addrs = ["127.0.0.1:4433"]
allow_insecure = true

[carrier]
packet_socket = true
congestion_control = "new-reno"
"#,
    )
    .expect("valid plaintext server config");
    let server = config.server().expect("server config");
    assert!(server.tls().is_none());
    assert!(server.carrier().packet_socket());
    assert_eq!(
        server.carrier().congestion_control(),
        CongestionControl::NewReno
    );
}

#[test]
fn carrier_defaults_to_cubic_congestion_control() {
    let config = Config::parse(
        r#"
role = "server"
listen_addrs = ["127.0.0.1:4433"]
allow_insecure = true
"#,
    )
    .expect("valid server config");
    assert_eq!(
        config
            .server()
            .expect("server")
            .carrier()
            .congestion_control(),
        CongestionControl::Cubic
    );
}

#[test]
fn plaintext_config_requires_explicit_insecure_opt_in() {
    assert!(matches!(
        Config::parse(
            r#"
role = "server"
listen_addrs = ["127.0.0.1:4433"]
"#,
        ),
        Err(ConfigError::InsecureProfileRequiresOptIn)
    ));
}

#[test]
fn client_tls_rejects_insecure_opt_in() {
    let input = r#"
role = "client"
allow_insecure = true

[tls]
server_name = "gateway.example.com"
ca_cert = "/etc/quicp/ca.pem"
client_cert = "/etc/quicp/client.pem"
client_key = "/etc/quicp/client.key"

[multipath]
mode = "off"

[[multipath.candidates]]
name = "primary"
local_ip = "192.0.2.10"
server_addr = "203.0.113.10:4433"
"#;

    assert!(matches!(
        Config::parse(input),
        Err(ConfigError::TlsWithInsecureOptIn)
    ));
}

#[test]
fn server_tls_rejects_insecure_opt_in() {
    let input = r#"
role = "server"
listen_addrs = ["127.0.0.1:4433"]
allow_insecure = true

[tls]
server_cert = "/etc/quicp/server.pem"
server_key = "/etc/quicp/server.key"
client_ca = "/etc/quicp/client-ca.pem"
"#;

    assert!(matches!(
        Config::parse(input),
        Err(ConfigError::TlsWithInsecureOptIn)
    ));
}

#[test]
fn loads_an_owner_checked_config_snapshot() {
    let temporary = secure_tempdir();
    let path = std::fs::canonicalize(temporary.path())
        .expect("canonical temporary directory")
        .join("server.toml");
    std::fs::write(
        &path,
        r#"
role = "server"
listen_addrs = ["127.0.0.1:4433"]

[tls]
server_cert = "/etc/quicp/server.pem"
server_key = "/etc/quicp/server.key"
client_ca = "/etc/quicp/client-ca.pem"
"#,
    )
    .expect("config");

    let config = load_config(&path).expect("secure config");
    assert_eq!(config.server().expect("server").listen_addrs().len(), 1);
}

#[cfg(unix)]
#[test]
fn config_loader_rejects_symlinks_and_writable_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let temporary = secure_tempdir();
    let target = temporary.path().join("target.toml");
    let link = temporary.path().join("link.toml");
    std::fs::write(&target, "role = 'server'").expect("target");
    symlink(&target, &link).expect("symlink");
    assert!(matches!(
        load_config(&link),
        Err(ConfigError::SecureOpen(_))
    ));

    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).expect("permissions");
    assert!(matches!(
        load_config(&target),
        Err(ConfigError::InsecurePermissions { .. })
    ));
}

#[cfg(unix)]
#[test]
fn carrier_cookie_secret_is_owner_checked() {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::os::unix::fs::PermissionsExt;

    let temporary = secure_tempdir();
    let directory = std::fs::canonicalize(temporary.path()).expect("canonical temporary directory");
    let secret_path = directory.join("carrier-cookie.secret");
    std::fs::write(&secret_path, b"cookie secret").expect("cookie secret");
    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
        .expect("secret permissions");

    let carrier =
        CarrierConfig::new(SynDataPolicy::Cookie, secret_path, CongestionControl::Cubic).unwrap();
    let secret = carrier.load_cookie_secret().expect("cookie secret");
    let tuple = FourTuple::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 443)),
    );
    assert!(matches!(
        carrier.syn_data_mode(&secret, tuple, 1),
        SynDataMode::Cookie(_)
    ));
    assert_eq!(
        carrier.syn_data_mode(&secret, tuple, 1),
        carrier.syn_data_mode(&secret, tuple.reverse(), 1)
    );
}
