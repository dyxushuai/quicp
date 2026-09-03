# QUICP

[![crates.io](https://img.shields.io/crates/v/quicp.svg)](https://crates.io/crates/quicp)
[![docs.rs](https://docs.rs/quicp/badge.svg)](https://docs.rs/quicp)
[![CI](https://github.com/dyxushuai/quicp/actions/workflows/ci.yml/badge.svg)](https://github.com/dyxushuai/quicp/actions/workflows/ci.yml)
[![MSRV 1.88](https://img.shields.io/badge/MSRV-1.88%2B-orange.svg)](https://www.rust-lang.org/tools/install)
[![License](https://img.shields.io/crates/l/quicp.svg)](LICENSE-APACHE)

QUICP is a TCP alternative for lossy, long-RTT, or QoS-constrained paths. It uses a QUIC
transport engine for session control, carries independent QUICP flows as datagrams, and emits a
TCP-shaped `FakeTCP` carrier. Loss in one flow does not block unrelated flows behind one ordered
carrier byte stream. Multipath failover and replay-safe application early data are explicit,
opt-in capabilities.

QUICP is a QUICP-specific protocol, not wire-compatible with IETF QUIC. `FakeTCP` preserves
datagram boundaries; it is not a TCP byte stream or a security boundary. QUICP does not provide a
VPN, DNS resolver, or FakeIP allocator.

> **Carrier boundary:** Tier 0 is the only profile intended for ISP-facing FakeTCP camouflage.
> TUN/TAP, Network Extension, and `VpnService` are packet-integration layers and do not provide
> that guarantee.

## Install

Rust 1.88 or newer is required.

```toml
[dependencies]
quicp = "0.1.1"
```

The base crate is runtime-neutral and does not enable TLS. Add only the capabilities your
integration needs:

```toml
quicp = { version = "0.1.1", features = ["runtime-tokio", "tls-rustls"] }
```

The current release is `0.1.1`. Its backend crates are published as
[`quicp-noq`](https://crates.io/crates/quicp-noq) and
[`quicp-noq-proto`](https://crates.io/crates/quicp-noq-proto); `vendor/**` remains in the source
tree for auditing.

## Read the wire contract

Start with the [QUICP protocol specification](docs/protocol.md). It is the normative reference
for DATAGRAM recovery, logical ACK/replay/FEC, replay-safe early data, the FakeTCP envelope, and
the independent-implementation checklist. This README focuses on using the library and SDKs.

## Start here

The smallest complete flow uses the runtime-neutral host API and no TLS:

```sh
cargo run --locked --example echo
```

The example builds validated client/server configuration, opens a QUICP flow, and echoes bytes
through fixed-peer `HostDatagramSocket` queues. In an embedding application, send each egress
datagram through your underlay, pass received datagrams to `ingress_datagram_from`, and call
`HostRuntime::drive` after I/O or timer readiness.

## Find the right example

| Goal | Example | Run or inspect |
| --- | --- | --- |
| Runtime-neutral echo flow | [`echo.rs`](examples/echo.rs) | `cargo run --locked --example echo` |
| Linux SOCKS5 client/server tunnel | [`socks5_tunnel.rs`](examples/socks5_tunnel.rs) | `cargo build --locked --example socks5_tunnel --features runtime-tokio` |
| Primary/backup flow failover | [`multipath.rs`](examples/multipath.rs) | `cargo run --locked --example multipath` |
| Custom QUICP header protection | [`header_protection.rs`](examples/header_protection.rs) | `cargo run --locked --example header_protection` |
| Replay-safe application 0-RTT | [`zero_rtt.rs`](examples/zero_rtt.rs) | `cargo run --locked --example zero_rtt` |
| smoltcp/TUN packet seam | [`smoltcp_bridge.rs`](examples/smoltcp_bridge.rs) | `cargo run --locked --example smoltcp_bridge --features platform-smoltcp` |
| Apple Network Extension loop | [`QuicpNetworkExtensionPacketTunnelProvider.swift`](sdk/apple/Examples/QuicpNetworkExtensionPacketTunnelProvider.swift) | Host entitlements and an underlay are required |
| Android `VpnService` loop | [`QuicpVpnServiceExample.kt`](sdk/android/examples/io/quicp/QuicpVpnServiceExample.kt) | Android app, TUN permission, and JNI archive are required |

See the [example guide](examples/README.md) for SOCKS5 command lines and the ownership boundary
of each integration. The Apple and Android sources are packet-loop skeletons, not complete VPN
products.

## Configure MTU, MSS, and PMTU

Transport policy is runtime-neutral and does not expose backend types. The same policy is used by
host carriers and native raw `FakeTCP`; raw paths derive MSS from the address family and complete
outer IP MTU.

```rust
use quicp::{MtuConfig, PmtuMode, QuicpTransportConfig};

let transport = QuicpTransportConfig {
    mtu: MtuConfig {
        outer_ip_mtu: 1280,
        pmtu: PmtuMode::Disabled,
        ..MtuConfig::default()
    },
    ..QuicpTransportConfig::default()
};
// base_client_config is a validated ClientConfig.
let client_config = base_client_config.with_transport(transport)?;
```

`outer_ip_mtu` is the complete raw IP packet limit. `MtuConfig` also exposes fixed or automatic
MSS, QUIC payload ceilings, PMTU probing, and black-hole recovery. `PmtuMode::Required` is rejected
on a carrier that may fragment. `with_transport` validates the complete client or server snapshot
before endpoint creation. TOML duration fields use Serde's `{ secs = ..., nanos = ... }` shape.

## Feature flags

Features are additive. Start with the first row, then enable the row that matches your integration;
no feature selects a different QUICP protocol.

| Need | Feature | Provides | Start here |
| --- | --- | --- | --- |
| Core and runtime-neutral Rust API | None | Host-driven carrier, connection, flow, and validated configuration | [`echo.rs`](examples/echo.rs) |
| Tokio integration and native raw carrier | `runtime-tokio` | Tokio I/O/runtime adapter and raw `FakeTCP` on Linux, macOS, and Windows | [`socks5_tunnel.rs`](examples/socks5_tunnel.rs), [Windows guide](docs/windows.md) |
| Mutual TLS | `tls-rustls` | Optional rustls authentication and encryption | [Security and early data](#security-and-early-data) |
| smoltcp packet bridge | `platform-smoltcp` | Bounded packet processing for TUN/mobile adapters | [`smoltcp_bridge.rs`](examples/smoltcp_bridge.rs) |
| C/Swift/Kotlin engine | `ffi-c` | Synchronous connection, flow, timer, and host-DATAGRAM ABI | [SDK contract](sdk/README.md) |

The package defaults to an `rlib`. Build a native archive with:

```sh
cargo rustc --crate-type staticlib --features ffi-c
```

Add `tls-rustls` to that command for mutual TLS. The no-TLS C archive keeps the
`quicp_engine_create_tls` symbol for ABI stability, but the entry point returns
`QUICP_STATUS_INVALID_ARGUMENT` without constructing an engine.

The core API remains runtime-neutral. `runtime-tokio` enables the Tokio adapter; raw `FakeTCP`
remains target-gated to Linux, macOS, and Windows. Enabling Tokio on iOS, Android, or another Unix
target does not compile a raw carrier.

## Multipath and carrier tiers

Multipath failover is configured in the Rust API. Each path has its own `FakeTCP` four-tuple;
QUICP session and flow state remain above those carrier paths.

| Tier | Use | Boundary |
| --- | --- | --- |
| Tier 0 | Wire `FakeTCP` on the ISP-facing interface | The only profile intended for ISP-level camouflage; requires packet injection, tuple filtering, scoped RST suppression, and packet capture evidence |
| Tier 1 | TUN/TAP and smoltcp | Virtual packet integration; not a wire-carrier claim by itself |
| Tier 2 | Apple Network Extension and Android `VpnService` | Platform packet integration; permissions and underlay remain host responsibilities |

### Platform matrix

| Surface | Linux | macOS | iOS | Android | Windows |
| --- | --- | --- | --- | --- | --- |
| Host-driven Rust API | Yes | Yes | Yes | Yes | Yes |
| Raw `FakeTCP` carrier | Yes, `CAP_NET_RAW` or equivalent | Privileged IPv4 raw-socket probe and scoped PF RST rule | No | No | Yes, pinned WinDivert 2.2.2-A x64; Administrator required |
| smoltcp packet bridge | Yes | Yes | Yes | Yes | Yes, host-owned packet I/O |
| C connection/flow engine | Yes | Yes | Yes | Yes | Yes |
| Swift/Kotlin wrappers | — | Engine | Engine | Engine | — |

Tier 0 details and the Windows installation boundary are documented in the [Windows carrier
guide](docs/windows.md). Unix raw support is explicit: Linux and macOS have adapters; unsupported
targets fail closed instead of inheriting another platform's packet semantics. A native Wintun/TAP
handle adapter remains Tier 1 work.

The C, Swift, and Kotlin surfaces drive real QUICP connections and flows over one or two
host-owned underlay paths. They do not bypass Network Extension or `VpnService` permissions and do
not own DNS, FakeIP allocation, TUN setup, or platform socket lifecycle.

The mobile SDK minimums are Rust 1.88, iOS 15, macOS 12, Android API 21, and Swift tools 5.7. See
the [SDK contract](sdk/README.md) for ABI ownership and artifact status.

Unsupported tiers fail closed; no adapter silently changes a requested Tier 0 carrier to UDP or an
ordered TCP byte stream.

## Security and early data

- Without `tls-rustls`, QUICP is intentionally unauthenticated and unencrypted, like TCP. The
  no-TLS profile requires explicit `ClientConfig::insecure` / `ServerConfig::insecure` construction.
- TLS and optional QUICP header protection are caller-selected. Header protection alone does not
  authenticate a peer or encrypt application data.
- `FakeTCP` shapes the carrier. Its cookie and cookie secret protect the carrier handshake, not
  the QUICP peer or application payload.
- `Client::connect_replay_safe` admits bounded initial bytes only with a server-issued expiring
  token, a fresh attempt nonce, compatible capabilities, and process-local replay capacity.
  Transport-level early-data rejection falls back once to ordinary `OPEN`; token or replay
  rejection is fail-closed. The API does not claim cross-restart or cross-connection exactly-once
  effects. With required multipath, delivery may precede backup validation, so a later backup
  failure is delivery-ambiguous.
- Raw sockets cross an operating-system privilege boundary. Grant only the capability required by
  the process and protect carrier secrets as trust material.

## Documentation

- [Protocol and wire boundaries](docs/protocol.md)
- [Run the Rust examples](examples/README.md)
- [Choose the SDK and ABI contract](sdk/README.md)
- [Run the benchmark commands](benches/README.md)
- [Follow the production acceptance checklist](docs/production-acceptance-checklist.md)
- [Read the change log](CHANGELOG.md)

Generate API documentation locally with:

```sh
RUSTDOCFLAGS='-D warnings' cargo doc \
  --features runtime-tokio,tls-rustls,platform-smoltcp,ffi-c --no-deps --locked
```

## Verify locally

```sh
cargo fmt --all -- --check
cargo test --all-features --locked
cargo clippy --all-features --all-targets --locked -- -D warnings
```

QUICP is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
