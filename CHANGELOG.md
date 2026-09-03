# Changelog

## [0.1.1] - 2026-09-03

First published QUICP implementation.

### Release changes

- Published the hardened `noq` backend as `quicp-noq` and `quicp-noq-proto` so the crates.io
  package resolves the same bounded-event and multipath fixes as the repository build.
- Preserved the runtime-neutral API, optional TLS, smoltcp bridge, C ABI, and platform carrier
  matrix from the source release candidate.
- The registry already contained an unrelated immutable `quicp 0.1.0`; this implementation is
  therefore released as `quicp 0.1.1`.

## [0.1.0] - 2026-08-24

First source release candidate for the QUICP transport core.

### Added

- Runtime-neutral host-driven client, server, connection, flow, and datagram APIs.
- TCP-shaped FakeTCP carrier with independent QUICP datagrams and bounded SYN handshake data.
- Validated transport policy for MTU/MSS/PMTU, flow-control, timers, ACK behavior, and resource
  budgets.
- QUICP/2 adaptive DATAGRAM recovery with bounded FEC, replay, reliable fallback, and typed policy.
- Optional mutual TLS, custom no-TLS header protection, and congestion-control seams.
- Optional smoltcp packet bridge plus a synchronous C engine used by the Apple and Android SDKs.
- Linux raw-carrier comparison and carrier codec benchmarks.
- Windows Tier 0 WinDivert packet adapter with filtered tuple capture/injection and native bind
  smoke test; the pinned 2.2.2-A x64 distribution and protected installation boundary remain
  deployment prerequisites.

### Source release boundary

- This is the repository source release candidate that preceded the crates.io publication. The
  vendored backend is retained for source auditing; the published `0.1.1` package resolves the
  separately published `quicp-noq` and `quicp-noq-proto` crates.
- The project is dual-licensed under MIT OR Apache-2.0; both license texts are included in the
  source release.
- No IETF QUIC wire interoperability, VPN implementation, or PSK profile is claimed. Replay-safe
  application 0-RTT is process-local and requires explicit token admission. Windows Tier 0 packet
  admission still requires the pinned WinDivert distribution and black-box network evidence.
- No-TLS mode is intentionally unauthenticated and unencrypted. TLS or another caller-owned
  authenticated layer is required when confidentiality or peer authentication is needed.

[0.1.0]: https://github.com/dyxushuai/quicp/releases/tag/v0.1.0
[0.1.1]: https://github.com/dyxushuai/quicp/releases/tag/v0.1.1
