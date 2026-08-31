# Mobile SDK

These thin wrappers drive real QUICP/2 connections and flows over host-owned underlay datagrams.
Calls for one engine must be serialized by the event loop that owns it.
Their wire and recovery behavior follows the [normative protocol specification](../docs/protocol.md).

## Minimum support

| Surface | Minimum | Current artifact | Validation |
| --- | --- | --- | --- |
| Rust core and C ABI | Rust 1.88; C ABI version 3 | Static library plus `include/quicp.h` | Rust MSRV, FFI E2E, and C header CI jobs |
| Apple | iOS 15; macOS 12; Swift tools 5.7 | Local Swift package containing an XCFramework | Apple target builds and `swift test` |
| Android | API 21; NDK r28.2 | Source integration through `cargo-ndk` and CMake | Kotlin compile and JNI build at API 21 |
| Android ABIs | `arm64-v8a` and `x86_64` | Host application chooses the matching archive | ABI builds are explicit |

The minimum versions are part of the SDK contract. A future release may raise them only with a
release-note entry and a new compatibility decision. The Rust crate's `rust-version` remains the
source of truth for the core MSRV.

## ABI contract

`include/quicp.h` is the only cross-language ABI. `QUICP_ABI_VERSION` is independent of the Rust,
Swift, Kotlin, and package versions; change it when a layout or ownership contract changes.

- The host allocates underlay and flow input/output storage.
- Rust never retains a foreign pointer after an ABI call returns.
- One engine has one logical owner; the owner serializes ingress, egress, drive, flow, and close.
- The call is synchronous and nonblocking. No Rust thread, executor, callback, coroutine, future,
  TUN descriptor, or packet arena crosses the boundary.
- Null, unaligned, overflowing, closed, and invalid generation handles are rejected. Rust panics are
  converted to `QUICP_STATUS_PANIC` and never unwind into foreign code.

The payload path is deliberately copy-free at the language boundary. A platform loop may copy
when it reads from a TUN API or writes to a socket; that is an adapter decision, not an ABI
requirement.

The C, Swift, and Kotlin surfaces create one connection, open flows, inspect pending server OPENs
before accepting or rejecting them, expose ordered reads/writes, drive timers, and move DATAGRAMs
over one or two host-owned paths. They do not grant raw-underlay privileges or bypass the platform
VPN admission model.

Security is explicit: omit the SDK security value for the unencrypted profile, or pass mutual-TLS
server name, CA, certificate, and private-key paths. Server engines require an empty server name.
Creation copies every UTF-8 value; no foreign string pointer is retained.

The C, Swift, and Kotlin engines also expose replay admission, token issuance, and replay-safe
initial bytes on an established connection. Issue a token only after an ordinary flow has
negotiated the capabilities bound into it. Token, secret, and initial-data buffers are borrowed
only for the call. Transport handshake 0-RTT still requires a reusable Rust endpoint/session and
is available through Rust's `Client::connect_replay_safe`; the foreign engine does not claim that
a newly created engine can resume a previous transport session.

## Apple

Run `sdk/apple/build-xcframework.sh`, then add `sdk/apple` as a local Swift package.
`QuicpEngine` and `QuicpFlow` borrow Swift buffers directly for each synchronous call.

During development, the package uses a local binary target. A published package should replace
that target with a versioned remote XCFramework and its SwiftPM checksum; generated binaries are
intentionally not committed here.

`apple/Examples/QuicpNetworkExtensionPacketTunnelProvider.swift` is a carrier and ownership
skeleton. It does not provide entitlements, create an underlay socket, or claim that a Network
Extension can inject arbitrary raw TCP packets.

## Android

Build `libquicp.a` with `cargo ndk -t <abi> -P 21 rustc --crate-type staticlib --features ffi-c,tls-rustls`
for each Android ABI. Add `sdk/android/src/main/kotlin` and
`sdk/android/CMakeLists.txt` to the application module, passing the matching archive as
`-DQUICP_RUST_LIB=...` and `-DANDROID_PLATFORM=android-21`. The Kotlin wrapper accepts direct
native-order `ByteBuffer` values with position zero for underlay and flow I/O.

The current source release does not publish a prebuilt AAR or Maven repository. Applications
embed the JNI library through their own Android library module. A future AAR/Maven publication
must have repeatable signing and ABI artifact provenance; adding a packaging scaffold without
those release inputs would be misleading.

The wrappers intentionally do not own a thread, coroutine, callback, TUN descriptor, socket, or
packet arena. Those belong to the platform event loop.

If a host socket or interface reports a permanent failure, call `markPathUnavailable` so a
multipath engine can fail over immediately instead of waiting for idle-path detection.

The Rust-only host-driven carrier is `HostDatagramSocket` plus `HostRuntime`. It is useful for a
custom event loop or an integration test: copy one underlay datagram into
`ingress_datagram_from`, drain one outbound datagram with `poll_egress_datagram_into`, and advance
`HostRuntime::drive`. `Client::from_host_socket` and `Server::from_host_socket` (or their
`_with_options` variants) provide the portable Rust endpoint facade. It is
fixed-peer and supports the same optional TLS profile, but it does not grant iOS or Android raw-underlay privileges; the
Network Extension/VpnService carrier remains a separate platform admission.

The no-TLS host path is unauthenticated and unencrypted, like TCP. Select TLS in Rust when peer
or through the Swift/Kotlin security value when authentication and confidentiality are required;
carrier cookies and their secret are not a peer
identity.

## Platform loop examples

`apple/Examples/QuicpNetworkExtensionPacketTunnelProvider.swift` shows the serialized
`NEPacketTunnelProvider` read/process/write loop. `android/examples/io/quicp/QuicpVpnServiceExample.kt`
shows the matching `VpnService` ownership and direct-buffer layout. Both are intentionally host
integration skeletons: they do not bypass platform permissions, create an underlay socket, or
claim to be a complete VPN.
