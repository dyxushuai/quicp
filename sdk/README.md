# Mobile SDK

These wrappers keep packet payloads in host-owned memory and make one native call per batch.
Calls for one bridge must be serialized by the `NEPacketTunnelProvider` or `VpnService` packet
loop that owns it.

## Minimum support

| Surface | Minimum | Current artifact | Validation |
| --- | --- | --- | --- |
| Rust core and C ABI | Rust 1.88; C ABI version 1 | Static library plus `include/quicp.h` | Rust MSRV and C header CI jobs |
| Apple | iOS 15; macOS 12; Swift tools 5.7 | Local Swift package containing an XCFramework | Apple target builds and `swift test` |
| Android | API 21; NDK r28.2 | Source integration through `cargo-ndk` and CMake | JNI build at API 21 |
| Android ABIs | `arm64-v8a` and `x86_64` | Host application chooses the matching archive | ABI builds are explicit |

The minimum versions are part of the SDK contract. A future release may raise them only with a
release-note entry and a new compatibility decision. The Rust crate's `rust-version` remains the
source of truth for the core MSRV.

## ABI contract

`include/quicp.h` is the only cross-language ABI. `QUICP_ABI_VERSION` is independent of the Rust,
Swift, Kotlin, and package versions; change it when a layout or ownership contract changes.

- The host allocates input/output packet storage and descriptor arrays.
- Rust never retains a foreign pointer after `quicp_bridge_process_batch` returns.
- Input and output ranges, descriptor ranges, the result, and the bridge handle must not overlap.
- One bridge has one logical owner. Ingress and egress packet calls have direction-local guards,
  but lifecycle operations are not concurrent-safe; the owner must serialize all calls, including
  close.
- The call is synchronous and nonblocking. No Rust thread, executor, callback, coroutine, future,
  TUN descriptor, or packet arena crosses the boundary.
- Null, unaligned, overflowing, closed, and overlapping ranges are rejected. Rust panics are
  converted to `QUICP_STATUS_PANIC` and never unwind into foreign code.

The payload path is deliberately copy-free at the language boundary. A platform loop may copy
when it reads from a TUN API or writes to a socket; that is an adapter decision, not an ABI
requirement.

The C, Swift, and Kotlin surfaces are packet bridges, not connection-level QUICP APIs. They do not
create a connection, open a flow, manage multipath, grant raw-underlay privileges, or bypass the
platform VPN admission model.

## Apple

Run `sdk/apple/build-xcframework.sh`, then add `sdk/apple` as a local Swift package.
`QuicpBridge.processBatch` accepts the C descriptor buffers directly and performs no Swift payload
copy or per-packet allocation.

During development, the package uses a local binary target. A published package should replace
that target with a versioned remote XCFramework and its SwiftPM checksum; generated binaries are
intentionally not committed here.

`apple/Examples/QuicpNetworkExtensionPacketTunnelProvider.swift` is a carrier and ownership
skeleton. It does not provide entitlements, create an underlay socket, or claim that a Network
Extension can inject arbitrary raw TCP packets.

## Android

Build `libquicp.a` with `cargo ndk -t <abi> -P 21 rustc --crate-type staticlib --features ffi-c`
for each Android ABI. Add `sdk/android/src/main/kotlin` and
`sdk/android/CMakeLists.txt` to the application module, passing the matching archive as
`-DQUICP_RUST_LIB=...` and `-DANDROID_PLATFORM=android-21`. The Kotlin wrapper accepts direct
native-order `ByteBuffer` arenas with position zero. Input descriptors are `(offset, length)`
pairs; output descriptors are `(offset, capacity, produced_length)` triples of 32-bit integers.

The current source release does not publish a prebuilt AAR or Maven repository. Applications
embed the JNI library through their own Android library module. A future AAR/Maven publication
must have repeatable signing and ABI artifact provenance; adding a packaging scaffold without
those release inputs would be misleading.

The wrappers intentionally do not own a thread, coroutine, callback, TUN descriptor, or packet
arena. Those belong to the platform packet loop.

The Rust-only host-driven carrier is `HostDatagramSocket` plus `HostRuntime`. It is useful for a
custom event loop or an integration test: copy one underlay datagram into
`ingress_datagram_from`, drain one outbound datagram with `poll_egress_datagram_into`, and advance
`HostRuntime::drive`. `Client::from_host_socket` and `Server::from_host_socket` (or their
`_with_options` variants) provide the portable Rust endpoint facade. It is
fixed-peer and no-TLS capable, but it does not grant iOS or Android raw-underlay privileges; the
Network Extension/VpnService carrier remains a separate platform admission.

The no-TLS host path is unauthenticated and unencrypted, like TCP. Select TLS in Rust when peer
authentication and confidentiality are required; carrier cookies and their secret are not a peer
identity.

## Platform loop examples

`apple/Examples/QuicpNetworkExtensionPacketTunnelProvider.swift` shows the serialized
`NEPacketTunnelProvider` read/process/write loop. `android/examples/io/quicp/QuicpVpnServiceExample.kt`
shows the matching `VpnService` ownership and direct-buffer layout. Both are intentionally
carriers-only skeletons: they do not bypass platform permissions, create an underlay socket, or
claim that the packet bridge is a complete VPN.
