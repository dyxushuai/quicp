use quicp::config::{CarrierConfig, Config, ConfigError, MultipathMode, ZeroRttMode};
use quicp::faketcp::{FourTuple, SynDataMode};
use quicp::load_config;

const CLIENT_PREFIX: &str = r#"
role = "client"
journal_path = "/var/lib/quicp/fakeip.journal"
fake_ip_pool = "198.18.0.0/15"
fake_dns_addr = "198.18.0.1"
zero_rtt = "safe-open-only"

[tls]
server_name = "gateway.example.com"
ca_cert = "/etc/quicp/ca.pem"
client_cert = "/etc/quicp/client.pem"
client_key = "/etc/quicp/client.key"

[multipath]
mode = "failover"
"#;

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

    assert_eq!(client.multipath.mode, MultipathMode::Failover);
    assert_eq!(client.multipath.candidates.len(), 2);
    assert_eq!(client.zero_rtt, ZeroRttMode::SafeOpenOnly);
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
fn rejects_fake_dns_outside_pool() {
    let input = format!(
        "{}{}",
        CLIENT_PREFIX.replace("198.18.0.1", "192.0.2.1"),
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

    assert!(matches!(
        Config::parse(&input),
        Err(ConfigError::FakeDnsOutsidePool { .. })
    ));
}

#[test]
fn rejects_fake_dns_network_address() {
    let input = format!(
        "{}{}",
        CLIENT_PREFIX.replace("198.18.0.1", "198.18.0.0"),
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

    assert!(matches!(
        Config::parse(&input),
        Err(ConfigError::UnusableFakeDnsAddress(address)) if address.to_string() == "198.18.0.0"
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
        config.server().expect("server config").listen_addrs.len(),
        2
    );
}

#[test]
fn parses_server_without_tls() {
    let config = Config::parse(
        r#"
role = "server"
listen_addrs = ["127.0.0.1:4433"]

[carrier]
packet_socket = true
"#,
    )
    .expect("valid plaintext server config");
    let server = config.server().expect("server config");
    assert!(server.tls.is_none());
    assert!(server.carrier.packet_socket);
}

#[test]
fn loads_an_owner_checked_config_snapshot() {
    let temporary = tempfile::tempdir().expect("temporary directory");
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
    assert_eq!(config.server().expect("server").listen_addrs.len(), 1);
}

#[cfg(unix)]
#[test]
fn config_loader_rejects_symlinks_and_writable_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let temporary = tempfile::tempdir().expect("temporary directory");
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

    let temporary = tempfile::tempdir().expect("temporary directory");
    let directory = std::fs::canonicalize(temporary.path()).expect("canonical temporary directory");
    let secret_path = directory.join("carrier-cookie.secret");
    std::fs::write(&secret_path, b"cookie secret").expect("cookie secret");
    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
        .expect("secret permissions");

    let carrier = CarrierConfig {
        cookie_secret_file: secret_path,
        ..CarrierConfig::default()
    };
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
