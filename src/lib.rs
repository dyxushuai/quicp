#![doc = r"
# QUICP

QUICP is a QUIC-based TCP alternative carried in TCP-shaped `FakeTCP` packets. It preserves
independent QUIC flows instead of recreating one reliable TCP byte stream. `FakeTCP` is an
underlay format, not a TCP connection and not a security boundary.

The [normative QUICP/2 protocol specification](https://github.com/dyxushuai/quicp/blob/main/docs/protocol.md)
defines the wire format, recovery rules, and resource limits.

The stable integration path is host-driven and runtime-neutral: the caller owns datagram I/O,
advances [`HostRuntime`], and constructs endpoints through [`Client::from_host_socket`] and
[`Server::from_host_socket`].

```no_run
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use quicp::{
    CarrierConfig, Client, ClientConfig, HostDatagramSocket, HostRuntime, MtuConfig, Multipath,
    PathCandidate, PmtuMode, QuicpTransportConfig, Server, ServerConfig,
};

let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19_000);
let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19_001);
let client_config = ClientConfig::insecure(
    Multipath::single(PathCandidate::new(client_addr.ip(), server_addr)?)?,
    CarrierConfig::default(),
)?
.with_transport(QuicpTransportConfig {
    mtu: MtuConfig {
        outer_ip_mtu: 1280,
        pmtu: PmtuMode::Disabled,
        ..MtuConfig::default()
    },
    ..QuicpTransportConfig::default()
})?;
let server_config = ServerConfig::insecure(vec![server_addr], CarrierConfig::default())?;
let runtime = Arc::new(HostRuntime::new());
let client_io = HostDatagramSocket::new(client_addr, server_addr, 64, 1500)?;
let server_io = HostDatagramSocket::new(server_addr, client_addr, 64, 1500)?;
let client = Client::from_host_socket(
    &client_config,
    client_io,
    Arc::clone(&runtime),
)?;
let server = Server::from_host_socket(&server_config, server_io, runtime)?;

// Drive the runtime and move datagrams in the host event loop before awaiting these futures.
let _connect = client.connect();
let _accept = server.accept();
# Ok::<(), Box<dyn std::error::Error>>(())
```

See `examples/echo.rs` for the complete bounded pump/drive flow. [`config`] owns validated
configuration; [`host_carrier`] and [`HostRuntime`] are the portable host seam; [`flow`] exposes
established application flows.
Optional [`congestion`] and [`header_protection`] interfaces are Rust-only extensions. The
repository README documents features, platform support, security boundaries,
mobile SDKs, and the unpublished documentation workflow.

## Examples

- `cargo run --example echo`: complete runtime-neutral flow and echo exchange.
- `cargo build --example socks5_tunnel --features runtime-tokio`: Linux client/server SOCKS5
  `CONNECT` relay over raw `FakeTCP`; run the binary with the `client` or `server` role.
- `cargo run --example multipath`: same-flow delivery after primary carrier failure.
- `cargo run --example header_protection`: caller-selected QUICP header protection hook.
- `cargo run --example zero_rtt`: replay-safe early OPEN plus initial bytes and ordinary fallback.
- `cargo run --example smoltcp_bridge --features platform-smoltcp`: bounded TUN/smoltcp packet
  ownership seam.
- Apple and Android packet-loop skeletons live under `sdk/apple/Examples` and
  `sdk/android/examples`.

## Security

QUICP without TLS is intentionally unauthenticated and unencrypted, like TCP. Callers must opt in
with [`ClientConfig::insecure`] and [`ServerConfig::insecure`], or select the `tls-rustls` feature
and validated TLS settings. Header protection does not replace authentication or encryption.
Carrier cookies and their secret validate the TCP-shaped underlay exchange; they do not identify
the QUICP peer. Protect that secret as trust material.

Application 0-RTT is available only through the explicit replay-safe API with a server-issued
expiring token, fresh attempt nonce, compatible capabilities, and bounded process-local replay
admission. Ordinary OPEN and writes remain blocked by handshake and policy admission.

## Stable API boundary

Validated configuration is constructed with methods instead of field initialization.

```compile_fail
use quicp::{CarrierConfig, ClientConfig, Multipath, MultipathMode};

let _ = ClientConfig {
    tls: None,
    allow_insecure: true,
    multipath: Multipath { mode: MultipathMode::Off, candidates: vec![] },
    carrier: CarrierConfig::default(),
};
```
"]
#![doc = r"
Backend and packet-detail modules are private in stable builds. The repository-only
benchmarks and tests use the same public facade as downstream integrations.

```compile_fail
use quicp::transport::Client;
```

```compile_fail
use quicp::faketcp::FakeTcpSocket;
```
"]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod config;
pub mod congestion;
mod faketcp;
mod fec;
#[cfg(feature = "ffi-c")]
pub mod ffi;
pub mod flow;
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing;
pub mod header_protection;
pub mod host_carrier;
mod host_runtime;
mod multipath;
pub(crate) mod no_security;
mod packet_ring;
#[cfg(feature = "platform-smoltcp")]
pub mod platform;
mod recovery;
mod session;
#[cfg(feature = "platform-smoltcp")]
pub mod smolstack;
mod transport;
mod wire;

pub use config::{
    CarrierConfig, ClientConfig, ClientTls, Config, ConfigError, CongestionControl,
    MAX_DECODER_WINDOW, MAX_FLOW_BUFFER_BYTES, MAX_PENDING_HANDSHAKE_BUFFER_BYTES,
    MAX_QUIC_PAYLOAD, MAX_RECOVERY_MEMORY_BUDGET_BYTES, MAX_REPAIR_SPAN, MIN_QUIC_PAYLOAD, MssMode,
    MtuConfig, Multipath, MultipathMode, PathCandidate, PmtuMode, QuicpTransportConfig,
    RecoveryConfig, RecoveryMode, ServerConfig, ServerTls, load_config,
};
pub use congestion::{
    AckBatch, CongestionController, CongestionControllerFactory, CongestionEvent,
    CongestionMetrics, PacketAcked, PacketSent, RttSnapshot, TransportOptions,
};
pub use faketcp::{
    BorrowedDecodedDatagram, CarrierDirection, CarrierError, DecodedDatagram, FakeTcpCarrier,
    FourTuple, SynDataMode,
};
pub use flow::{FlowError, PendingFlow, QuicpFlow};
pub use header_protection::{
    HeaderProtectionFactory, HeaderProtectionKeys, HeaderProtectionSide, QuicpHeaderProtector,
};
pub use host_carrier::{HostDatagramError, HostDatagramSocket};
pub use host_runtime::{HostRuntime, HostRuntimeError};
pub use multipath::PathHealth;
#[cfg(feature = "platform-smoltcp")]
pub use platform::{PlatformError, PlatformPacketBridge, PlatformPacketConfig};
pub use recovery::RecoverySnapshot;
pub use session::{ApplicationError, SessionError};
pub use session::{ReplayAdmission, ReplayToken, ReplayTokenError};
pub use transport::{Client, Server};
pub use transport::{Connection, ConnectionError, IncomingConnection, TransportError};
pub use wire::{CanonicalHost, OpenRequest, OpenStatus, WireError};
