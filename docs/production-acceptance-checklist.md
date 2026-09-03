# QUICP Production Acceptance Checklist

Created: 2026-08-21

This checklist is the release gate for QUICP. A checked item needs reproducible evidence attached to
the release record. An item marked `N/A` must include the reason and the profile in which the
capability is not admitted. “Works in a unit test” is not evidence for a carrier, privilege,
platform, or failure-mode gate.
The release evidence must use the [normative QUICP protocol](protocol.md).

## 1. Release identity and scope

- [ ] Record the release commit, Cargo.lock hash, Rust toolchain, compiler target, and enabled
  features.
- [ ] Name the admitted profile explicitly:
  - [ ] portable host-driven, no-TLS, single path;
  - [ ] Tier 0 Unix FakeTCP raw carrier, no-TLS (Linux `AF_PACKET` optional; macOS IPv4 raw fallback);
  - [ ] Tier 0 Unix FakeTCP raw carrier with optional TLS adapter;
  - [ ] Tier 1/2 packet integration only.
- [ ] Confirm that the release does not claim IETF QUIC wire interoperability, TCP-stream
  compatibility, indistinguishable camouflage, or universal ISP acceptance. Tier 0 claims only the
  packet-level FakeTCP behavior proven by the release evidence.
- [ ] Confirm that TUN, FakeIP, DNS, VPN, Network Extension, and VpnService are optional adapters,
  not required by the transport core.
- [ ] Confirm that no unsupported profile silently falls back to another carrier or security
  profile.

### 1.1 Carrier tier gate

- [ ] Tier 0 is the only profile described as an ISP-facing FakeTCP carrier.
- [ ] Tier 1 TUN/TAP and Tier 2 mobile packet bridges are labeled integration layers and never
  accepted as wire-carrier evidence by themselves.
- [ ] A requested Tier 0 profile fails closed when exact packet injection, tuple filtering, source
  selection, or scoped RST suppression is unavailable.

## 2. Hard no-go gates

Any failure in this section is a release blocker.

### 2.1 Build, feature, and API contract

- [ ] `cargo fmt --all -- --check` passes.
- [ ] The project license is selected, declared in `Cargo.toml`, and included in the source archive;
  the source archive retains `vendor/**`, while the crates.io package resolves the separately
  published `quicp-noq` and `quicp-noq-proto` backend crates.
- [ ] `cargo clippy --all-targets --locked -- -D warnings` passes.
- [ ] `cargo clippy --all-features --all-targets --locked -- -D warnings` passes.
- [ ] `cargo test --locked` passes.
- [ ] `cargo test --all-features --locked` passes.
- [ ] Rust `1.88` minimum-version checks pass for base and all-feature library targets.
- [ ] Native Windows `x86_64-pc-windows-msvc` all-feature checks pass on a Windows runner.
- [ ] The SDK minimum matrix is recorded: iOS 15, macOS 12, Android API 21, and Swift tools 5.7.
- [ ] `cargo check --locked --all-targets` proves the base build has no Tokio executor requirement.
- [ ] Every public type exported from the crate root is constructible, or is gated out on the
  feature/platform where it cannot be constructed.
- [ ] No public API exposes `noq` types, Tokio futures, Rust collections, callbacks, or OS handles
  across the C/Swift/Kotlin boundary.
- [ ] The C header, Rust ABI constants, Swift status enum, and Kotlin status values are identical.
- [ ] ABI version and struct layout are checked by a C compile smoke test and one Swift or Kotlin
  integration test.

### 2.2 Protocol and carrier correctness

- [ ] Every carrier payload contains exactly one QUICP datagram; QUICP is never placed inside an
  ordered FakeTCP byte stream.
- [ ] FakeTCP IPv4/IPv6 checksum, TCP sequence, ACK, SYN, SYN-ACK, and tuple validation tests pass.
- [ ] A changed four-tuple creates an independent carrier state and sequence space.
- [ ] Missing or reordered FakeTCP carrier packets do not block later QUICP packets.
- [ ] Duplicate, stale, malformed, truncated, oversized, and checksum-invalid packets are rejected
  without poisoning an established carrier or QUICP connection.
- [ ] The SYN-data path is bounded, tuple-cookie protected, and never forwards origin application
  bytes before admission.
- [ ] SYN-data loss, cookie rejection, and disabled SYN-data policy have an explicit safe fallback;
  no application payload is resent solely because SYN data was lost.
- [ ] Packet capture confirms the exact intended framing for the selected profile.

### 2.3 Security and admission

- [ ] No-TLS mode is explicitly selected and is documented as unauthenticated transport-only mode.
- [ ] TLS mode rejects missing or mismatched profile tokens/ALPN/transport parameters before flow
  admission.
- [ ] Mutual authentication, certificate identity, expiry, and policy failures fail closed.
- [ ] Custom header protection is tested as header obfuscation only; it is not accepted as a claim of
  payload confidentiality or authenticity.
- [ ] Ordinary OPEN/writes remain blocked by handshake admission; replay-safe 0-RTT requires a
  valid token, fresh nonce, compatible capabilities, bounded initial bytes, and cache capacity.
- [ ] Duplicate, expired, bad-MAC, wrong-epoch, capability-mismatch, and exhausted-cache attempts
  fail before application side effects; fallback produces one local byte sequence.
- [ ] PSK is either implemented and tested as an authenticated profile, or explicitly marked
  `N/A/not admitted`. The current backend exposes no-TLS and optional TLS; do not advertise PSK
  until its adapter exists.
- [ ] Cookie secrets and private material are absolute, regular, non-symlink files with trusted
  parents and owner-only permissions; secrets never appear in logs or inline configuration.

### 2.4 Multipath and failover

- [ ] Single-path mode negotiates and uses exactly one path.
- [ ] Failover mode admits exactly two configured candidates and rejects malformed, duplicate, or
  extra candidates.
- [ ] Each path owns an independent FakeTCP four-tuple, carrier sequence space, packet-number
  space, congestion state, and socket/adapter owner.
- [ ] A backup path is not considered usable until validation and the expected remote path status
  are both observed.
- [ ] A primary path blackhole preserves the same QUICP session ID and flow bytes on the validated
  backup path.
- [ ] A path failure before backup readiness fails closed; it must not silently report successful
  sends into a black hole.
- [ ] Both paths failing closes the connection and releases endpoint waiters.
- [ ] Path-event lag, contradictory status, and late/repeated transitions hit bounded limits and
  fail closed.
- [ ] Dynamic path-ID churn/reopen is `N/A/not admitted`: this profile fixes two configured
  candidates, permits eight path IDs over a connection lifetime, and never auto-reopens a
  discarded path.
- [ ] Capture proves failover uses the backup tuple rather than merely timing out and reopening a
  new session.
- [ ] Do not treat loopback `iptables` or `tc` drops as carrier blackhole evidence when the raw
  socket path bypasses those hooks; use an isolated veth/netns pair or a second host and capture
  on the actual underlay interface.

### 2.5 Resource, concurrency, and lifecycle safety

- [ ] Published packet, stream, connection, path, queue, and batch limits are enforced under load.
- [ ] Queue-full and output-buffer-too-small paths preserve ownership and do not silently dequeue
  or drop data.
- [ ] Backpressure wakes the owning event loop; no pending future depends on an unobserved atomic
  flag change.
- [ ] The smoltcp interface has one owner and short-lived socket borrows; no long-lived borrow
  prevents the owner from polling the interface.
- [ ] SPSC rings have exactly one logical producer and consumer; platform callbacks are serialized
  without exposing a safe bypass to the ring.
- [ ] FFI calls reject null, unaligned, overflowing, stale, closed, and overlapping descriptors.
- [ ] Rust panics are caught at every FFI entry point and never unwind into foreign code.
- [ ] Close is idempotent, clears the caller-owned handle, wakes pending work, and releases all
  runtime/endpoint state.
- [ ] Graceful shutdown, peer close, half-close, reset, task panic, and transport I/O error each
  terminate or drain all associated waiters.

## 3. Required automated evidence

Run these on every release candidate and attach the complete logs.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-features --all-targets --locked -- -D warnings
cargo test --locked
cargo test --features runtime-tokio --locked
cargo test --all-features --locked
cargo test --locked --features platform-smoltcp --test smolstack
cargo run --locked --example smoltcp_bridge --features platform-smoltcp
cargo +1.88.0 check --all-targets --locked
cargo +1.88.0 check --all-features --all-targets --locked
cargo deny check
cargo audit
```

- [ ] `cargo audit` covers the complete committed `Cargo.lock`, including dev-only dependencies
  excluded by the `cargo-deny` runtime graph gate.

### 3.1 Apple SDK

- [ ] On a macOS runner, compile all admitted Apple targets:

```sh
cargo check --locked --features ffi-c --target aarch64-apple-ios
cargo check --locked --features ffi-c --target aarch64-apple-ios-sim
cargo check --locked --features ffi-c --target x86_64-apple-ios
cargo check --locked --features platform-smoltcp --target aarch64-apple-ios
cargo check --locked --features runtime-tokio --target aarch64-apple-ios
cargo check --locked --features runtime-tokio --target aarch64-apple-darwin
sh sdk/apple/build-xcframework.sh
swift test --package-path sdk/apple
```

- [ ] Swift tests cover create, timers, recovery snapshots, flow I/O, close, repeated close,
  invalid status, and caller-buffer ownership.
- [ ] The Network Extension example is documented as an entitlement/carrier skeleton and is not
  accepted as proof of raw-underlay access.

### 3.2 Android SDK

- [ ] With the pinned NDK and `cargo-ndk`, compile every admitted ABI:

```sh
export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk/28.2.13676358"
export ANDROID_NDK_HOME="$ANDROID_NDK_ROOT"
cargo ndk -t arm64-v8a -t x86_64 -P 21 \
  check --locked --features ffi-c
cargo ndk -t arm64-v8a -t x86_64 -P 21 \
  check --locked --features platform-smoltcp
cargo ndk -t arm64-v8a -t x86_64 -P 21 \
  check --locked --features runtime-tokio
cargo ndk -t arm64-v8a -P 21 \
  rustc --locked --features ffi-c,tls-rustls --crate-type staticlib
cmake -S sdk/android -B "$RUNNER_TEMP/quicp-jni" \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-21 \
  -DQUICP_RUST_LIB="$PWD/target/aarch64-linux-android/debug/libquicp.a"
cmake --build "$RUNNER_TEMP/quicp-jni" --parallel
```

- [ ] Build the JNI wrapper with `sdk/android/CMakeLists.txt` for at least arm64-v8a.
- [ ] Kotlin checks cover direct-buffer validation, engine layout, timer/drive, generation handles,
  flow I/O, and close.
- [ ] The VpnService example is documented as a host-underlay skeleton and is not accepted as
  proof of arbitrary raw TCP injection.

### 3.3 Windows host-driven and C engine

The runtime-neutral host API, optional smoltcp bridge, C engine ABI, and WinDivert-backed Tier 0
carrier are supported on Windows. The native carrier requires the pinned WinDivert 2.2.2-A x64
distribution in a protected installation directory and Administrator privileges; it does not
create a Wintun/TAP handle.

- [ ] Run the native Windows host-driven echo and shutdown tests.
- [ ] Run the C engine connection/flow E2E with caller-owned buffers.
- [ ] Stage the test executable, pinned `WinDivert.dll`, and signed `WinDivert64.sys` in a directory
  owned by `SYSTEM`, `Administrators`, or `TrustedInstaller`, with mutation rights limited to those
  principals; invoke the test executable directly with
  `windivert_carrier_binds_a_filtered_tuple --ignored` from an elevated Windows shell.
- [ ] Capture an external-interface packet round trip, including SYN data, tuple filtering, kernel
  RST suppression, loss/reordering, and shutdown cleanup.

Native Wintun/TAP handle ownership is deferred Tier 1 work; it is not part of the QUICP core or
this release gate.

### 3.4 Other non-Linux behavior

- [ ] Non-Linux persistence, FakeIP, raw sockets, and TUN behavior are either implemented with a
  secure native adapter or marked unsupported in the release matrix.

## 4. Required black-box scenarios

These scenarios require packet capture and an isolated host/network. A unit-test pass does not
replace them.

### 4.1 Portable host-driven path

- [ ] Use two `HostDatagramSocket` paths and one `HostRuntime` owner per endpoint.
- [ ] Drive ingress, egress, timers, backpressure, half-close, reset, and shutdown only through
  caller-owned buffers.
- [ ] Verify the same flow survives delayed/reordered datagrams and never blocks unrelated streams.
- [ ] Verify runtime progress is bounded by the configured task budget and cannot starve packet I/O.

### 4.2 Linux FakeTCP raw carrier

- [ ] Run on an isolated Linux host with `CAP_NET_RAW`, fixed CPU/MTU, and packet capture enabled.
- [ ] Apply only tuple-scoped RST suppression and remove it with a shell `trap` after the run.
- [ ] Test SYN, SYN data, ordinary data, FIN/half-close, reset, malformed input, MTU boundary,
  packet loss, duplicate, reorder, and carrier restart.
- [ ] Test both raw-IP and filtered AF_PACKET modes when both are part of the release profile.
- [ ] Verify destination-address/port allowlists and packet-info filters before QUICP parsing.
- [ ] Verify packets for unowned local addresses are dropped without creating a session.
- [ ] Verify no global RST, firewall, route, or neighbor state remains after teardown.

### 4.3 Multipath black-box failover

- [ ] Use two real underlays (or isolated veth/namespace pairs) with distinct FakeTCP tuples.
- [ ] Establish primary and validated backup before sending the failover payload.
- [ ] Drop only primary traffic during an active flow; verify the same session and exact byte stream
  continue on backup.
- [ ] Inject primary send and receive errors separately; verify the healthy path remains usable.
- [ ] When installing external `tc` filters after `CROSS_FLOW_READY`, set
  `QUICP_RAW_BLACKHOLE_DELAY_MS` to a value that exceeds the filter-install latency; record the
  filter counters before removing the temporary qdisc.
- [ ] Repeat with backup unavailable and both paths blackholed. Delayed-event fail-closed behavior
  is covered by the coordinator/monitor matrix; dynamic path churn/reopen is `N/A/not admitted`.
- [ ] Capture both tuples and record the path IDs, statuses, close reason, and failover latency.
- [ ] Confirm the drop mechanism's counters increment on the underlay; a userspace capture that
  only observes `PACKET_OUTGOING` copies is insufficient to prove delivery was prevented.

### 4.4 Security and SYN data

- [ ] No-TLS profile: confirm packet bytes contain no TLS/AEAD overhead and admission is explicitly
  unauthenticated.
- [ ] TLS profile: verify mutual-auth success, wrong identity, expired certificate, profile-token
  mismatch, and downgrade attempts.
- [ ] Confirm only the explicit replay-safe API can send initial application bytes before handshake
  completion and that ordinary OPEN remains blocked.
- [ ] Confirm no-security bearer tokens are not described as peer authentication and replay cache
  scope is documented as process-local.

## 5. Performance and stability gates

Performance numbers are valid only when both protocols use the same topology, payload boundary,
CPU pinning, MTU, connection state, and no-TLS security profile.

- [ ] Run the authoritative Linux raw comparison on the release host:

```sh
cargo bench --locked --bench loopback --features runtime-tokio -- --quiet
QUICP_ONLY=1 QUICP_ENFORCE_CLEAN_PATH=1 \
  cargo bench --locked --bench loopback --features runtime-tokio -- --quiet
```

- [ ] Compare QUICP FakeTCP and ordinary kernel TCP at 64 B, 1,200 B, and 4,096 B application
  payloads, with connection and flow establishment excluded from the timed region.
- [ ] Record p50, p95, p99, Gbps, CPU%, allocations, absolute peak live Rust heap, replay, repair,
  fallback, and drops for six interleaved samples per payload size. Record lifetime RSS separately;
  it is process-wide and is not attributable to either recovery mode.
- [ ] Run the SOCKS5 client and server as separate processes over Tier 0 FakeTCP, pass one real
  CONNECT request through the tunnel, and attach the tuple-scoped RST rule plus cleanup evidence.
- [ ] Reject results that mix raw FakeTCP with TUN/smoltcp, TLS with no-TLS, or in-memory codec
  microbenchmarks with end-to-end TCP.
- [ ] Require no statistically significant regression against the last accepted baseline, or attach
  an approved exception with a measured reason.
- [ ] Run the configured maximum concurrent flows and two-path limit for at least 30 minutes.
- [ ] Verify bounded RSS, no queue growth, no task leak, no unbounded path-event work, and no
  increasing allocator pressure after warm-up. Dynamic path churn is not admitted in this profile.
- [ ] Repeat with loss/reorder and unequal RTT; record recovery latency and flow completion rate.

## 6. Optional transparent TUN/FakeIP integration

This section is required only when the transparent integration is included in the release. It is
not a gate for the portable transport core or the current carrier-only mobile SDK.

- [ ] Install the owner-tagged TUN route in a dedicated table containing no default, unicast, VPN,
  or inherited override route.
- [ ] Install and persist the destination blackhole before removing the live TUN route; verify the
  blackhole survives graceful stop, crash, and restart.
- [ ] Publish FakeDNS only after authentication and every required failover path are ready.
- [ ] Enumerate every non-QUICP link and Manager-level resolver domain, including ifindex 0; reject
  more-specific routing/search domains and competing global `~.` entries.
- [ ] Subscribe to resolver/link changes and fail closed when a competing domain appears at runtime.
- [ ] Verify stale, unknown, exhausted, or corrupted FakeIP mappings cannot reach the underlay.
- [ ] Verify all routes, resolver links, FakeDNS state, and blackholes are removed or intentionally
  retained according to the crash-safety policy during rollback.

## 7. Operational readiness

- [ ] Configuration loading rejects symlinks, writable private files, malformed candidates, unknown
  fields, duplicate tuples, and invalid security/multipath combinations.
- [ ] Endpoint-wide recovery memory tests prove retained decoder sources, repair rows, pre-OPEN
  data, and flow reassembly cannot exceed the configured budget and teardown returns all credit.
- [ ] Logs contain profile, path state, close reason, queue pressure, and counters but never secrets,
  private keys, raw application payloads, or unredacted target data.
- [ ] Health checks distinguish “process alive”, “carrier bound”, “authenticated”, “backup ready”,
  and “able to forward application data”.
- [ ] Metrics expose per-path TX/RX packets, loss, RTT, congestion window, queue depth, failover
  count/latency, rejected packets, and FFI status counts.
- [ ] The privileged raw-socket component has least privilege, a documented startup failure mode,
  and a tested rollback command.
- [ ] A release operator can disable FakeTCP or multipath explicitly without changing the wire or
  security profile silently.
- [ ] Crash recovery leaves no stale socket, route, resolver, RST rule, or lock that blocks restart.
- [ ] License and dependency review covers the vendored `noq`/`noq-proto` backend and all mobile/native
  build artifacts.

For crash or `kill -9` evidence, launch the privileged carrier in a dedicated process group and
signal that group. Killing only a `sudo` wrapper can orphan the root-owned carrier child and makes
the rollback result invalid; verify the exact carrier path is gone before removing temporary RST
rules.

## 8. Evidence record and release decision

Attach the following to the release record:

```text
Release commit:
Cargo.lock hash:
Rust/toolchain:
Target OS/kernel/SDK:
CPU/cores/MTU:
Enabled features/profile:
Configuration hash:
Automated test logs:
Packet captures:
Raw privilege/RST-rule evidence:
Multipath failover evidence:
FFI ABI evidence:
Benchmark raw data:
RSS/CPU/allocator soak data:
Open P1/P2 findings:
Rollback owner and command:
```

Release is **GO** only when:

- every applicable hard gate is checked;
- every black-box carrier and failover scenario has packet-level evidence;
- no open P0/P1 finding remains;
- unsupported profiles and platform limitations are explicitly excluded from the release claim;
- rollback has been exercised on the same deployment class.

Release is **NO-GO** for any security downgrade, silent fallback, unbounded resource growth,
unverified multipath failover, ABI mismatch, stale privileged state, or benchmark result that does
not match the declared topology.
