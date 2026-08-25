# ADR 0001: Explicit carrier platform matrix

- Status: Accepted
- Date: 2026-08-25

## Context

FakeTCP's shared codec and tuple state are portable, but packet injection and receive behavior are
platform-specific. The previous Unix selector treated every non-Linux Unix target as macOS. That
could compile a Darwin raw-socket implementation on an unsupported operating system and hide the
actual capability gap.

Windows adds a separate constraint: ordinary Winsock raw sockets are not a production path for
sending arbitrary TCP data. A Windows Tier 0 carrier therefore needs a packet-injection adapter
based on an explicitly supported filtering/driver mechanism. Wintun/TAP remains a Tier 1 packet
integration and is not advertised as ISP-level FakeTCP camouflage.

## Decision

1. Keep FakeTCP codec, tuple validation, and carrier state platform-neutral.
2. Select Linux and macOS raw adapters explicitly.
3. Select a future Windows Tier 0 adapter explicitly; do not inherit the macOS implementation.
4. Unsupported Unix targets fail closed when the raw Tokio carrier is requested.
5. Keep host-driven core, C packet bridge, and virtual packet integrations separate from Tier 0
   raw-carrier admission.

## Consequences

- A target cannot silently receive a platform implementation with different packet semantics.
- Windows Tier 0 support can be added behind a real, reviewable adapter without changing
  FakeTCP's wire contract; host-driven and packet-bridge integrations do not require that
  adapter.
- Cross-target CI must test the host-driven profile separately from privileged Tier 0 integration.
- The Windows Tier 0 adapter remains roadmap work until driver, signing, privilege, packet capture,
  RST suppression, and rollback evidence exist.
