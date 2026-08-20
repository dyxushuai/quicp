use std::num::NonZeroU16;

use quicp::{
    CanonicalHost, Config, OpenRequest, PlatformPacketBridge, PlatformPacketConfig, QuicpFlow,
    ZeroRttMode, accept_flow,
};

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
    std::hint::black_box(accept_flow);
}
