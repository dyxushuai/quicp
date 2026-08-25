use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Instant;

use quicp::{
    ApplicationError, CanonicalHost, CarrierConfig, Client, ClientConfig, Config,
    CongestionControl, CongestionController, CongestionControllerFactory, CongestionMetrics,
    FlowError, HeaderProtectionFactory, HeaderProtectionKeys, HeaderProtectionSide,
    HostDatagramSocket, HostRuntime, Multipath, OpenRequest, PacketSent, PathCandidate,
    PluginRegistry, QueqiaoPlugin, QuicpHeaderProtector, SessionError, TransportOptions,
};
#[cfg(feature = "platform-smoltcp")]
use quicp::{PlatformPacketBridge, PlatformPacketConfig};

#[derive(Debug)]
struct ApiController;

impl CongestionController for ApiController {
    fn on_sent(&mut self, _event: PacketSent) {}

    fn window(&self) -> u64 {
        1_200
    }

    fn metrics(&self) -> CongestionMetrics {
        CongestionMetrics {
            congestion_window: 1_200,
            ..CongestionMetrics::default()
        }
    }

    fn clone_box(&self) -> Box<dyn CongestionController> {
        Box::new(Self)
    }

    fn initial_window(&self) -> u64 {
        1_200
    }
}

#[derive(Debug)]
struct ApiFactory;

impl CongestionControllerFactory for ApiFactory {
    fn build(&self, _now: Instant, _current_mtu: u16) -> Box<dyn CongestionController> {
        Box::new(ApiController)
    }
}

struct ApiHeaderProtector;

impl QuicpHeaderProtector for ApiHeaderProtector {
    fn decrypt(&self, _packet_number_offset: usize, _packet: &mut [u8]) {}

    fn encrypt(&self, _packet_number_offset: usize, _packet: &mut [u8]) {}

    fn sample_size(&self) -> usize {
        0
    }
}

struct ApiHeaderFactory;

impl HeaderProtectionFactory for ApiHeaderFactory {
    fn build(&self, _side: HeaderProtectionSide) -> HeaderProtectionKeys {
        HeaderProtectionKeys::new(Arc::new(ApiHeaderProtector), Arc::new(ApiHeaderProtector))
    }
}

#[test]
fn common_library_api_is_available_from_the_crate_root() {
    let request = OpenRequest::new(
        CanonicalHost::parse("www.example.com").unwrap(),
        NonZeroU16::new(443).unwrap(),
    );
    #[cfg(feature = "platform-smoltcp")]
    let bridge = PlatformPacketBridge::new(PlatformPacketConfig::default()).unwrap();
    let host_socket = HostDatagramSocket::new(
        "127.0.0.1:10000".parse().unwrap(),
        "127.0.0.1:10001".parse().unwrap(),
        1,
        1200,
    )
    .unwrap();
    let _host_runtime = HostRuntime::new();
    let config = Config::parse(
        r#"
role = "server"
listen_addrs = ["127.0.0.1:4433"]
allow_insecure = true
"#,
    )
    .unwrap();

    assert_eq!(request.port, NonZeroU16::new(443).unwrap());
    assert!(config.server().is_some());
    #[cfg(feature = "platform-smoltcp")]
    assert_eq!(bridge.ingress_len(), 0);
    assert_eq!(host_socket.ingress_len(), 0);
    assert_eq!(CongestionControl::default(), CongestionControl::Cubic);
    let _options = TransportOptions::new()
        .with_congestion_controller_factory(Arc::new(ApiFactory))
        .with_header_protection_factory(Arc::new(ApiHeaderFactory));
    let mut plugins = PluginRegistry::new();
    plugins.register(QueqiaoPlugin::default()).unwrap();
    assert_eq!(plugins.len(), 1);
    let _plugin_options = plugins.build_transport_options().unwrap();

    assert_eq!(ApplicationError::FlowAbort.code(), 0x101);
    let flow_error = FlowError::Session(SessionError::PolicyRejected);
    assert!(matches!(
        flow_error,
        FlowError::Session(SessionError::PolicyRejected)
    ));
}

#[test]
fn fixed_peer_host_carrier_rejects_multipath_without_silent_fallback() {
    let primary = PathCandidate::new(
        "primary",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
    )
    .unwrap();
    let backup = PathCandidate::new(
        "backup",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 4434)),
    )
    .unwrap();
    let config = ClientConfig::insecure(
        Multipath::failover(primary, backup).unwrap(),
        CarrierConfig::default(),
    )
    .unwrap();
    let socket = HostDatagramSocket::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 10000)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
        1,
        1200,
    )
    .unwrap();
    let error = Client::from_host_socket(&config, socket, Arc::new(HostRuntime::new()))
        .expect_err("fixed-peer host carrier must not pretend to support failover");
    assert!(matches!(
        error,
        quicp::TransportError::UnsupportedMultipathCarrier
    ));
}
