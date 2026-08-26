# ADR 0002: Preserve the configuration extension seam

- Status: Superseded by ADR 0003
- Date: 2026-08-25

## Context

This decision described the QUICP/1 configuration seam. ADR 0003 supersedes it for QUICP/2, where
adaptive recovery becomes core protocol behavior and explicit typed configuration replaces the
generic registry.

The repository currently has one production configuration adapter, `QueqiaoPlugin`, but the
project requires a plugin system as an intentional extension point. The registry is deliberately
not a packet callback and is not part of the C, Swift, or Kotlin packet-bridge ABI.

## Decision

Keep `PluginRegistry` and `QuicpPlugin` as the single Rust-only configuration-plugin seam. Do
not add packet callbacks, a second plugin framework, or a foreign-language plugin ABI. Revisit the
registry's depth only when a second independent production adapter needs behavior that cannot be
expressed through `TransportOptions`.

## Consequences

- Queqiao remains an adapter policy, not a wire-protocol implementation.
- The registry's bounded capacity and registration-order semantics remain explicit.
- A future second adapter must justify additional interface depth before new abstractions are
  introduced.
