# Changelog

## [0.1.0] - 2026-08-24

First source release candidate for the QUICP transport core.

### Added

- Runtime-neutral host-driven client, server, connection, flow, and datagram APIs.
- TCP-shaped FakeTCP carrier with independent QUICP datagrams and bounded SYN handshake data.
- Validated transport policy for MTU/MSS/PMTU, flow-control, timers, ACK behavior, and resource
  budgets.
- Optional mutual TLS, custom no-TLS header protection, congestion-control, and plugin seams.
- Optional smoltcp packet bridge and C ABI used by the Apple and Android packet-bridge SDK sources.
- Linux raw-carrier comparison and carrier codec benchmarks.
- Windows Tier 0 WinDivert packet adapter with filtered tuple capture/injection and native bind
  smoke test; the external signed provider remains a deployment prerequisite.

### Release boundary

- This is a source release candidate; `publish = false` remains set because the vendored `noq`
  patch must be released as a separately reviewable dependency source before crates.io distribution.
  `cargo package` omits path dependencies, so release archives must retain `vendor/**`; the `.crate`
  output is not a complete QUICP source artifact.
- The project is dual-licensed under MIT OR Apache-2.0; both license texts are included in the
  source release.
- No IETF QUIC wire interoperability, mobile connection API, VPN implementation, PSK profile, or
  transport/application 0-RTT is claimed. Windows Tier 0 packet admission still requires the
  external signed WinDivert provider and black-box network evidence.
- No-TLS mode is intentionally unauthenticated and unencrypted. TLS or another caller-owned
  authenticated layer is required when confidentiality or peer authentication is needed.

[0.1.0]: https://github.com/dyxushuai/quicp/releases/tag/v0.1.0
