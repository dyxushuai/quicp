use std::num::NonZeroU16;

use quicp::{
    ApplicationError, CanonicalHost, Config, Connection, ConnectionError, IncomingConnection,
    OpenRequest, PendingFlow, PlatformPacketBridge, PlatformPacketConfig, QuicpFlow, ZeroRttMode,
};
#[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
use quicp::{Client, Server};

#[test]
fn common_library_api_is_available_from_the_crate_root() {
    let request = OpenRequest::new(
        CanonicalHost::parse("www.example.com").unwrap(),
        NonZeroU16::new(443).unwrap(),
    );
    let bridge = PlatformPacketBridge::new(PlatformPacketConfig::default()).unwrap();
    let config = Config::parse(
        r#"
role = "server"
listen_addrs = ["127.0.0.1:4433"]
"#,
    )
    .unwrap();

    assert_eq!(request.port, NonZeroU16::new(443).unwrap());
    assert!(config.server().is_some());
    assert_eq!(bridge.ingress_len(), 0);
    assert_eq!(ZeroRttMode::Off, ZeroRttMode::Off);

    let _flow_type: Option<QuicpFlow> = None;
    let _pending_type: Option<PendingFlow> = None;
    #[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
    let _client_type: Option<Client> = None;
    #[cfg(all(target_os = "linux", feature = "runtime-tokio"))]
    let _server_type: Option<Server> = None;
    let _connection_type: Option<Connection> = None;
    let _incoming_type: Option<IncomingConnection> = None;
    let _error_type: Option<ConnectionError> = None;
    assert_eq!(ApplicationError::FlowAbort.code(), 0x101);
}
