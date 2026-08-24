# Public API and Documentation Design

Date: 2026-08-24
Status: Awaiting written review

## Goal

Make QUICP straightforward to embed as a cross-platform Rust library while keeping backend,
platform, and protocol internals out of the stable product surface. The crate documentation must
build with warnings denied and provide one obvious path from installation to an established
connection and application flow.

## Non-goals

- Publish the crate to crates.io or docs.rs in this change.
- Stabilize `noq` types or the vendored backend patch.
- Add Windows raw-carrier support.
- Add connection or multipath operations to the C, Swift, or Kotlin SDKs.
- Add a new builder hierarchy or duplicate the existing configuration model.
- Change QUICP wire, FakeTCP, multipath, security, or flow behavior.

## Stable Product Surface

The crate root is the primary API. It re-exports only types needed by applications:

- Endpoint and flow: `Client`, `Server`, `IncomingConnection`, `Connection`, `QuicpFlow`, and
  `PendingFlow`.
- Portable host integration: `HostDatagramSocket`, `HostRuntime`, and their errors.
- Application protocol: `CanonicalHost`, `OpenRequest`, `OpenStatus`, `ApplicationError`, and
  user-facing errors.
- Configuration: client, server, TLS, carrier, multipath, path-candidate, and congestion-control
  configuration types.
- Runtime-neutral extensions: transport options, congestion control, header protection, and the
  bounded plugin registry.
- Multipath observation: `PathHealth` only.

Default builds keep the implementation modules for `session`, `wire`, `transport`, and
`multipath` private. The root re-exports remain available. The `backend-noq` feature explicitly
opens backend-oriented modules and APIs and is documented as unstable.

The stable FakeTCP surface contains the carrier codec and the types needed to operate it:
`FourTuple`, `FakeTcpCarrier`, `SynDataMode`, and `CarrierError`. Packet parser structures, TCP
option structures, backend sockets, and Linux raw I/O remain implementation or platform details.

FakeIP, smoltcp/platform integration, and the C ABI remain optional integration modules. They do
not become prerequisites for a QUICP connection.

## Configuration Usability

The existing configuration types remain the only configuration model. No parallel builder types
are introduced.

Validated constructors are added to existing types:

- `PathCandidate::new` validates names, addresses, address families, and ports.
- `Multipath::single` and `Multipath::failover` encode the exact supported path counts and the
  primary-before-backup ordering.
- `ClientConfig::insecure` and `ClientConfig::with_tls` make the security choice explicit.
- `ServerConfig::insecure` and `ServerConfig::with_tls` make the security choice explicit.
- Existing carrier and TLS types receive the minimum constructors and accessors required after
  their invariant-bearing fields become private.

Endpoint construction validates configuration again at the trust boundary. TOML parsing uses the
same validation functions as programmatic construction. Invalid public states must not require a
raw struct literal to diagnose.

Method names describe ownership and platform behavior:

- `from_host_socket` remains the stable portable constructor.
- `bind_fake_tcp` remains the Linux raw-carrier convenience constructor.
- `_with_options` variants remain only where they add runtime-neutral extension options.
- Backend endpoint builders are available only with `backend-noq`.

## Feature Design

The default feature set becomes empty. The portable host-driven facade therefore has no Tokio,
smoltcp, TLS, or C ABI requirement.

Optional features retain one responsibility each:

- `runtime-tokio`: Tokio and Linux raw FakeTCP integration.
- `tls-rustls`: the optional mutual-TLS security adapter.
- `platform-smoltcp`: packet bridge and smoltcp integration.
- `ffi-c`: the synchronous C packet-bridge ABI; implies `platform-smoltcp`.
- `backend-noq`: unstable backend types and endpoint-building seams.

docs.rs-compatible metadata builds the stable feature set and excludes `backend-noq`. The package
remains `publish = false` because the vendored `noq` patch does not yet have a publishable source.
This limitation is stated in the README instead of presenting a non-functional docs.rs link.

## Documentation

Add a repository `README.md` with:

1. Project positioning and explicit non-goals.
2. A minimal host-driven connection example.
3. Feature and platform support tables.
4. Security-profile and FakeTCP privilege warnings.
5. Links to protocol, examples, SDK integration, and production acceptance documentation.

Add crate-level rustdoc with the same shortest successful path, using intra-doc links rather than
duplicating protocol prose. Every stable module and stable public item receives useful rustdoc.
Error messages remain concise, while error type documentation explains the boundary at which the
errors occur.

The existing examples stay canonical:

- `host_loopback`: portable endpoint and flow lifecycle.
- `header_protection`: Rust extension hook.
- `queqiao_plugin`: plugin registration.
- Apple and Android examples: caller-owned packet-loop integration.

No duplicate quick-start example is added. Documentation references examples that are compiled by
Cargo.

## Documentation and API Lints

The crate denies broken intra-doc links and warns on missing documentation for the stable surface.
Backend-only modules may carry a narrowly scoped missing-docs allowance until that feature is
promoted; the stable root may not.

CI adds a docs.rs-compatible documentation command with warnings denied. Cargo metadata includes
the rust-version, repository, documentation intent, and docs.rs feature selection, but does not
invent a license or enable publication.

## Validation

The implementation is complete when all of the following pass:

```text
cargo fmt --all -- --check
cargo clippy --all-targets --no-default-features --locked -- -D warnings
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --no-default-features --locked
cargo test --all-features --locked
cargo check --no-default-features --features runtime-tokio,platform-smoltcp,ffi-c --locked
cargo doc --no-deps using the docs.rs-compatible stable feature set with warnings denied
```

The public API compile test must construct single-path and failover configurations without struct
literals and must compile the host-driven endpoint path without backend types. Existing examples
must compile under their declared feature requirements.

## Compatibility

This is an intentional pre-1.0 breaking cleanup. Removed backend and packet-detail exports are not
deprecated. The README identifies the stable root-level replacements and the `backend-noq` escape
hatch.
