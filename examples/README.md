# QUICP examples

These examples implement the [normative QUICP/2 protocol](../docs/protocol.md).

Use the example that matches the layer you are integrating:

The real ISP-facing carrier example is `socks5_tunnel.rs` on Linux. The host, smoltcp, Apple, and
Android examples exercise packet seams only; they do not claim to emit FakeTCP on a physical ISP
interface.

| Scenario | Entry point | Run or inspect |
| --- | --- | --- |
| Runtime-neutral QUICP echo flow | `echo.rs` | `cargo run --locked --example echo` |
| SOCKS5 client/server tunnel | `socks5_tunnel.rs` | `cargo build --locked --example socks5_tunnel --features runtime-tokio` |
| Primary/backup flow failover | `multipath.rs` | `cargo run --locked --example multipath` |
| Custom QUICP header protection | `header_protection.rs` | `cargo run --locked --example header_protection` |
| Replay-safe application 0-RTT | `zero_rtt.rs` | `cargo run --locked --example zero_rtt` |
| smoltcp/TUN packet seam | `smoltcp_bridge.rs` | `cargo run --locked --example smoltcp_bridge --features platform-smoltcp` |
| iOS/macOS Network Extension | `sdk/apple/Examples/QuicpNetworkExtensionPacketTunnelProvider.swift` | Swift package and host entitlements required |
| Android `VpnService` | `sdk/android/examples/io/quicp/QuicpVpnServiceExample.kt` | Android app, TUN permission, and JNI archive required |

## Important boundaries

- `echo.rs` is the smallest complete flow example: it opens a QUICP flow, sends bytes, and echoes
  them back through the host-owned datagram pump.
- `socks5_tunnel.rs` is a real two-process Linux client/server tunnel. The client accepts
  unauthenticated SOCKS5 `CONNECT` requests with domain names; the server connects each QUICP flow
  to the requested destination. Both processes require `CAP_NET_RAW`, the same owner-only cookie
  secret, and tuple-scoped TCP RST suppression:

  ```text
  target/debug/examples/socks5_tunnel server --listen 198.51.100.10:40001 --client 203.0.113.20:40000 --secret /etc/quicp/carrier-cookie.secret
  target/debug/examples/socks5_tunnel client --local 203.0.113.20:40000 --server 198.51.100.10:40001 --secret /etc/quicp/carrier-cookie.secret
  curl --socks5-hostname 127.0.0.1:1080 http://example.com/
  ```
  The cookie file must be shared by both roles and have owner-only permissions. This is a tunnel
  example, not a VPN, DNS service, or SOCKS5 authentication implementation.
- `multipath.rs` binds two independent host-owned carriers, establishes one flow, marks the primary
  path unavailable, and completes the same flow through the backup.
- `zero_rtt.rs` issues a MAC-protected token on an established connection, reconnects through the
  explicit replay-safe API, and verifies bounded initial bytes are delivered once.
- `smoltcp_bridge.rs` demonstrates the packet ownership seam, not TUN creation. The platform owns
  TUN, FakeIP/DNS policy, underlay routing, permissions, and the event loop.
- The Apple and Android examples are host-underlay integration skeletons. They do not grant raw
  socket access or claim to be complete VPN implementations.

The core does not own DNS, FakeIP allocation, Network Extension/VpnService permissions, or TUN
creation. Those remain platform adapter responsibilities.
