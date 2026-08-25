# QUICP plugin system

QUICP plugins are Rust-only configuration extensions. A plugin runs once while a
`TransportOptions` value is built; it is not a per-packet callback and it is not part of the C
ABI. This keeps the hot path allocation-free and keeps foreign runtimes in control of packet
memory and scheduling.

```rust
use quicp::{PluginRegistry, QueqiaoPlugin, TransportOptions};

let mut registry = PluginRegistry::new();
registry.register(QueqiaoPlugin::default())?;
let options: TransportOptions = registry.build_transport_options()?;
```

`QueqiaoPlugin` is a small shared-path congestion policy inspired by the public Queqiao design. It
does not implement Queqiao protocol 1, FEC, SOCKS5, enrollment, TLS identity, or wire
interoperability. It shares a bounded congestion window and can treat non-persistent, non-ECN loss
below the configured parts-per-million floor as erasure. Use the built-in TLS profile for
confidentiality and authentication.

Header protection is a separate Rust-only option:

```rust
let options = TransportOptions::new()
    .with_header_protection_factory(std::sync::Arc::new(MyHeaderFactory));
```

It changes only backend QUIC-style header-protection bits in the no-TLS profile. It does not hide
FakeTCP/IP headers, encrypt the QUICP payload, or authenticate a packet. Supplying it with TLS is
rejected; use TLS when the security boundary requires confidentiality and integrity.

The registry is bounded to eight names, rejects duplicates, applies plugins in registration order,
and is deliberately absent from the C/Swift/Kotlin ABI. Native callers should select built-in
profiles through their host configuration and keep callbacks on the Rust side.
