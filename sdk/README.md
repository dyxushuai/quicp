# QUICP SDK

Use QUICP from C, Swift, or Kotlin through a thin synchronous wrapper. The host owns underlay
datagrams, buffers, the clock, the event loop, and platform permissions. One engine has one
serialized owner. Wire and recovery behavior follow the [QUICP protocol specification](../docs/protocol.md).

## Choose a target

| Surface | Minimum | Artifact | Start here |
| --- | --- | --- | --- |
| Rust core and C ABI | Rust 1.88; C ABI 3 | Static library and [`include/quicp.h`](../include/quicp.h) | [`ffi-c` build](#build-the-c-archive) |
| Apple | iOS 15; macOS 12; Swift tools 5.7 | Local Swift package with an XCFramework | [Apple setup](#apple) |
| Android | API 21; NDK r28.2 | Source integration through `cargo-ndk` and CMake | [Android setup](#android) |
| Android ABIs | `arm64-v8a`, `x86_64` | The application supplies the matching archive | [Android setup](#android) |

Minimum versions are part of the SDK contract. The Rust crate's `rust-version` is the source of
truth for the core MSRV.

## Build the C archive

From the repository root:

```sh
cargo rustc --crate-type staticlib --features ffi-c
```

Add `tls-rustls` to that command when the engine must use mutual TLS. The C archive is synchronous
and nonblocking; it does not start a Rust thread or executor.

## ABI contract

[`include/quicp.h`](../include/quicp.h) is the only cross-language ABI. `QUICP_ABI_VERSION` is
independent of Rust, Swift, Kotlin, and package versions; change it when a layout or ownership
contract changes.

- The host allocates underlay and flow input/output storage.
- Rust never retains a foreign pointer after an ABI call returns.
- One engine has one logical owner. That owner serializes ingress, egress, drive, flow, and close.
- Calls are synchronous and nonblocking. No Rust thread, executor, callback, coroutine, future,
  TUN descriptor, or packet arena crosses the boundary.
- Null, unaligned, overflowing, closed, and stale-generation handles are rejected. Rust panics
  become `QUICP_STATUS_PANIC` and never unwind into foreign code.

The payload path is copy-free at the language boundary. A platform loop may copy while reading a
TUN API or writing to a socket; that is an adapter choice, not an ABI requirement.

The engine creates connections, opens or accepts flows, exposes ordered reads and writes, drives
timers, and moves DATAGRAMs over one or two host-owned paths. It does not grant raw-underlay
privileges or bypass Network Extension or `VpnService` admission.

## Security and early data

Omit the SDK security value for the no-TLS profile, or provide the mutual-TLS server name, CA,
certificate, and private-key paths. Server engines use an empty server name. Creation copies every
UTF-8 value and retains no foreign string pointer. No-TLS is intentionally unauthenticated and
unencrypted, like TCP; carrier cookies do not identify the QUICP peer.

Replay-safe initial bytes require an established connection to issue a token. The token, secret,
nonce, and initial-data buffers are borrowed for one call. Transport 0-RTT resumption remains a
Rust-only operation through `Client::connect_replay_safe`; a newly created foreign engine cannot
resume an earlier transport session.

## Apple

Build the local XCFramework, then add `sdk/apple` as a local Swift package:

```sh
sh sdk/apple/build-xcframework.sh
```

`QuicpEngine` and `QuicpFlow` borrow Swift buffers for each synchronous call. The development
package uses a local binary target; generated binaries are not committed. A published package
would need a versioned remote XCFramework and a SwiftPM checksum.

[`QuicpNetworkExtensionPacketTunnelProvider.swift`](apple/Examples/QuicpNetworkExtensionPacketTunnelProvider.swift)
shows the serialized `NEPacketTunnelProvider` loop. It does not provide entitlements, create an
underlay socket, or claim arbitrary raw-TCP injection.

## Android

Build one archive per ABI:

```sh
cargo ndk -t <abi> -P 21 rustc \
  --crate-type staticlib --features ffi-c,tls-rustls
```

Add `sdk/android/src/main/kotlin` and [`CMakeLists.txt`](android/CMakeLists.txt) to the application
module. Pass the matching archive as `-DQUICP_RUST_LIB=...` and `-DANDROID_PLATFORM=android-21`.
The Kotlin wrapper accepts direct, native-order `ByteBuffer` values with position zero for underlay
and flow I/O.

This repository does not publish an AAR or Maven repository. Applications embed the JNI library
through their own Android library module. The [`VpnService` example](android/examples/io/quicp/QuicpVpnServiceExample.kt)
shows ownership and direct-buffer layout; it does not create an underlay socket or bypass platform
permissions.

## Host event loop

For a Rust-only integration, use `HostDatagramSocket` with `HostRuntime`. Copy each received
underlay datagram into `ingress_datagram_from`, drain outbound data with
`poll_egress_datagram_into`, and call `HostRuntime::drive` after I/O or timer readiness.
`Client::from_host_socket` and `Server::from_host_socket` provide the fixed-peer facade; the
`_with_options` variants expose the same host-owned execution model.

If a host socket or interface fails permanently, call `markPathUnavailable` so multipath can fail
over immediately instead of waiting for idle-path detection.

The Network Extension and `VpnService` sources are platform-loop examples, not complete VPN
products. DNS, FakeIP allocation, TUN creation, sockets, and packet scheduling remain platform
responsibilities.
