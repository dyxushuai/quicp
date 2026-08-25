# QUICP

[![CI](https://github.com/dyxushuai/quicp/actions/workflows/ci.yml/badge.svg)](https://github.com/dyxushuai/quicp/actions/workflows/ci.yml)
![MSRV 1.88](https://img.shields.io/badge/MSRV-1.88%2B-orange.svg)

QUICP is a TCP alternative built on a QUIC transport engine. It carries independent QUICP flows
inside TCP-shaped `FakeTCP` packets, so loss in one flow does not stall unrelated flows behind one
ordered carrier byte stream.

QUICP is not wire-compatible with IETF QUIC. It is a QUICP-specific protocol and library. In the
portable profile, your event loop owns datagram I/O and the runtime-neutral core advances from
explicit I/O and timer events.

The primary deployment target is the Tier 0 wire carrier: real TCP-shaped packets emitted on the
ISP-facing interface. TUN/TAP, Network Extension, and `VpnService` are packet-integration layers;
they do not replace the wire carrier or claim ISP-level FakeTCP camouflage.

## Implement the protocol

Start with the [QUICP/1 protocol specification](docs/protocol.md). It is the normative reference
for the FakeTCP envelope, QUICP datagram boundary, no-TLS handshake, profile tokens, exact
`OPEN`/`STATUS` bytes, multipath failover, and independent-implementation checklist. This README
focuses on using the Rust crate and platform SDKs.

> **Status:** `0.1.0` source release candidate. The crate remains unpublished (`publish = false`)
> because the vendored `noq` patch must be released as a separately reviewable dependency before
> crates.io distribution. `cargo package` intentionally omits path dependencies, so it is not a
> valid QUICP release artifact; publish a repository source archive that retains `vendor/**` and
> the project licenses instead.
> Windows host-driven and packet-bridge builds are supported; the ISP-facing Windows Tier 0
> carrier and native Wintun/TAP adapter remain roadmap work.

## Start here

Rust 1.88 or newer is required. The smallest complete flow example uses the default,
runtime-neutral host API and does not enable TLS:

```sh
cargo run --locked --example echo
```

The example builds validated client/server configuration, opens a QUICP flow, and echoes bytes
through fixed-peer `HostDatagramSocket` queues. For the lower-level handshake-only carrier seam,
run `cargo run --locked --example host_loopback`. To embed QUICP, send each egress datagram
through your underlay, pass received datagrams to `ingress_datagram_from`, and call
`HostRuntime::drive` after I/O or timer readiness.

### Configure the path envelope

Transport policy is runtime-neutral and does not expose `noq` types. The same policy is used by
host carriers and Unix raw `FakeTCP`; raw paths derive MSS from the address family and complete
outer IP MTU.

```rust
use quicp::{MtuConfig, QuicpTransportConfig};

let transport = QuicpTransportConfig {
    mtu: MtuConfig {
        outer_ip_mtu: 1280,
        pmtu: quicp::PmtuMode::Disabled,
        ..MtuConfig::default()
    },
    ..QuicpTransportConfig::default()
};
// base_client_config is a validated ClientConfig.
let client_config = base_client_config.with_transport(transport)?;
```

`outer_ip_mtu` is a complete raw IP packet limit. QUICP payload limits are separate fields, and
`PmtuMode::Required` is rejected on a carrier that may fragment. `with_transport` validates the
whole client or server snapshot before endpoint creation.
TOML duration fields use Serde's `{ secs = ..., nanos = ... }` shape.

## Pick optional capabilities

| You need | Enable | What it provides |
| --- | --- | --- |
| QUICP core and runtime-neutral Rust API | None | Host-driven carrier, connection, flow, and validated configuration |
| Tokio and Unix raw `FakeTCP` | `runtime-tokio` | Tokio adapter and Unix raw-carrier socket |
| Mutual TLS | `tls-rustls` | Optional rustls authentication and encryption |
| smoltcp packet bridge | `platform-smoltcp` | Bounded packet processing for TUN/mobile adapters |
| C packet-bridge ABI | `ffi-c` | Synchronous C ABI; implies `platform-smoltcp` |
| Repository benchmarks | `internal-bench` | Internal benches only; never a backend selector |

The package defaults to an `rlib`; build a native C/Swift/Kotlin archive explicitly with
`cargo rustc --crate-type staticlib --features ffi-c`.

Multipath failover is configured in the Rust API. Each path uses its own `FakeTCP` four-tuple;
the QUICP session and flow state remain above those carrier paths.

The base build always includes the QUICP protocol and backend. Optional features add integrations
and policies; they do not select a different QUICP implementation.

`runtime-tokio` is confined to the Tokio adapter modules. The packet codec, configuration, flow
contract, and host-carrier API remain runtime-neutral; Unix target gates are limited to kernel
socket differences that Cargo features cannot express.

## Supported integrations

| Surface | Linux | macOS | iOS | Android | Windows |
| --- | --- | --- | --- | --- | --- |
| Host-driven Rust API | Yes | Yes | Yes | Yes | Yes |
| Raw `FakeTCP` carrier | Yes, with `CAP_NET_RAW` or equivalent | Probe-only privileged IPv4 raw socket and scoped PF RST rule | No | No | Roadmap: WFP/driver adapter |
| smoltcp packet bridge | Yes | Yes | Yes | Yes | Yes (host-owned packet I/O) |
| C packet-bridge ABI | Yes | Yes | Yes | Yes | Yes |
| Swift/Kotlin wrappers | — | Packet bridge | Packet bridge | Packet bridge | — |

The C, Swift, and Kotlin surfaces intentionally expose packet bridging only. They do not create
QUICP connections, open flows, manage multipath, or bypass Network Extension and `VpnService`
permissions. The core does not own DNS, FakeIP allocation, or TUN setup; adapters can provide
those pieces at their platform boundary.

### Carrier tiers

- **Tier 0 — wire FakeTCP:** the only carrier profile accepted for ISP-level camouflage. It must
  inject and receive TCP-shaped IP packets, preserve the QUICP datagram boundary, suppress only the
  selected tuple's kernel RST, and pass packet-level capture checks. Unix raw IPv4 is implemented;
  Linux `AF_PACKET`/`TPACKET_V2` is an optional fast path. macOS uses the portable IP raw-socket
  fallback and still needs a privileged runtime probe plus a narrowly scoped PF RST rule before
  production admission.
  Windows must use a separately reviewed WFP/driver packet-injection adapter; Winsock raw TCP is
  not an admitted Tier 0 implementation. The host-driven core and packet bridge compile on
  Windows, while a native Wintun/TAP handle adapter remains Tier 1 roadmap work.
- **Tier 1 — TUN/TAP:** a virtual packet source/sink for smoltcp, tests, and transparent adapters.
  It is not a wire carrier unless the complete deployment attaches it to a verified physical packet
  path.
- **Tier 2 — Apple/Android packet bridge:** `NEPacketTunnelFlow` and `VpnService` provide virtual
  IP packets under platform permissions. They can feed QUICP flows or a Tier 0 gateway, but the
  mobile underlay is not advertised as ISP-level FakeTCP without a separately verified raw carrier.

Unsupported tiers fail closed; no adapter silently changes a requested Tier 0 carrier to UDP or an
ordered TCP byte stream.

The mobile SDK minimums are Rust 1.88, iOS 15, macOS 12, Android API 21, and Swift tools 5.7.
Apple uses a generated local XCFramework; Android currently uses source integration through
`cargo-ndk` and CMake rather than a prebuilt AAR. See [the SDK contract](sdk/README.md) for the
ABI ownership rules and the exact artifact status.

## Security and early data

- Without `tls-rustls`, QUICP is intentionally unauthenticated and unencrypted, like TCP. The
  no-TLS profile requires explicit `ClientConfig::insecure` / `ServerConfig::insecure` construction.
- TLS and optional QUICP header protection are caller-selected. Header protection alone does not
  authenticate a peer or encrypt application data.
- `FakeTCP` shapes the carrier. Its cookie and cookie secret protect the carrier handshake, not
  the QUICP peer or application payload.
- SYN data can carry only the backend handshake datagram. QUICP does not admit transport or
  application 0-RTT through TCP Fast Open; OPEN requests, origin dialing, and payload wait for the
  ordinary handshake and policy checks.
- Raw sockets cross an operating-system privilege boundary. Grant only the capability required by
  the process.

## Documentation

- [Run the Rust examples](examples/README.md)
- [Read the protocol and wire boundaries](docs/protocol.md)
- [Configure plugins and extension points](docs/plugin-system.md)
- [Build the Apple and Android packet bridges](sdk/README.md)
- [Run the benchmark commands](benches/README.md)
- [Follow the production acceptance checklist](docs/production-acceptance-checklist.md)
- [Read the change log](CHANGELOG.md)

Generate the API documentation locally with:

```sh
RUSTDOCFLAGS='-D warnings' cargo doc \
  --features runtime-tokio,tls-rustls,platform-smoltcp,ffi-c --no-deps --locked
```

Check the base library without optional adapters:

```sh
cargo check --lib --locked
```

## Verify locally

```sh
cargo fmt --all -- --check
cargo test --all-features --locked
cargo clippy --all-features --all-targets --locked -- -D warnings
```
