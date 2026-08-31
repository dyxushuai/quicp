# ADR 0002: Preserve the configuration extension seam

- Status: Superseded by ADR 0003
- Date: 2026-08-25

## Context

This decision described the QUICP/1 configuration seam. ADR 0003 supersedes it for QUICP/2, where
adaptive recovery becomes core protocol behavior and explicit typed configuration replaces the
generic registry.

At the time of this decision, the repository had one configuration adapter, `QueqiaoPlugin`, and
treated a plugin system as an intentional extension point. The registry was not a packet callback
or part of the C, Swift, or Kotlin packet-bridge ABI.

## Decision

The superseded decision kept `PluginRegistry` and `QuicpPlugin` as the single Rust-only
configuration-plugin seam and deferred further interface depth until a second independent adapter
needed behavior that `TransportOptions` could not express.

## Consequences

- These consequences no longer apply to QUICP/2; ADR 0003 removes the registry and incorporates
  adaptive recovery into the protocol core.
