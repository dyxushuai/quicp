# ADR 0003: Use datagrams for QUICP payloads

- Status: Accepted
- Date: 2026-08-26

## Decision

QUICP exposes a TCP-like ordered flow API, but sends payload data as QUIC DATAGRAMs whenever the
peer supports them. Reliable QUIC streams carry flow admission, control, acknowledgements, and a
reliable fallback. The exact wire format and limits live in the [protocol specification](../protocol.md).

QUICP uses one profile token, `quicp`. There is no compatibility mode or alternate token. Cargo
features select optional dependencies and platform adapters; they do not select a second protocol
or a recovery algorithm.

## Why datagrams

A reliable stream retransmits and reorders every byte in that stream. That is useful for control, but
it makes a lost payload byte hold later bytes in the same stream. A datagram plane lets QUICP recover
loss independently and keep unrelated flows readable while one flow waits for repair or replay.

FEC is a bounded, connection-wide GF(256) sliding window. Source symbols are sent unchanged and
repair symbols cover recent symbols across all validated paths. Logical byte-range ACKs and bounded
replay provide reliability after direct delivery or FEC recovery. A clean path sends no parity.

## Ownership boundaries

The backend owns QUIC packet ACKs, RTT measurement, congestion control, pacing, TLS packet
protection, path validation, and packet scheduling. QUICP owns flow offsets, logical ACKs, replay,
reassembly, FEC, flow ordering, and resource limits.

Each FakeTCP four-tuple has independent carrier sequence state. Carrier sequence numbers are
camouflage metadata; they are never QUICP byte offsets, ACKs, symbol identifiers, or multipath
state. A carrier packet contains exactly one QUICP datagram and never retransmits or orders it.

The host owns packet I/O and the clock. The runtime-neutral API advances bounded work after I/O or
timer readiness. Tokio, smoltcp, raw sockets, Network Extension, `VpnService`, and the C/Swift/Kotlin
wrappers are adapters around that host boundary.

## Flow behavior

Each flow keeps one reliable bidirectional stream for `OPEN`, `STATUS`, `ACK`, `MAX_OFFSET`, `FIN`,
and fallback `STREAM_DATA`. Payload writes may share a source symbol when no-delay is disabled;
no-delay writes are emitted on the next bounded driver turn. Reads expose only the contiguous byte
prefix, even when later bytes arrived first.

Invalid flow offsets, credit, ACKs, or FIN transitions reset that flow. Invalid shared negotiation,
resource abuse, or a failed driver closes the connection. Malformed datagrams are dropped before
they can mutate shared recovery state. Every peer-controlled count, length, range, and limit is
validated before allocation.

## Multipath

Multipath keeps the same QUICP session and flow state while each path uses its own FakeTCP tuple,
carrier sequence space, socket owner, and backend path state. A validated backup can carry repair,
replay, or fallback data after the primary fails. The current policy admits one primary and one
backup; it does not reopen discarded paths automatically.

## Early data and security

FakeTCP SYN data may carry the first backend handshake datagram. Application early data is separate
and requires an explicit replay-safe operation, a server-issued expiring MAC token, a fresh attempt
nonce, compatible capabilities, and bounded process-local replay admission. Ordinary `open_flow`
remains replay-unsafe. Transport-level early-data rejection falls back once to ordinary `OPEN`;
token or replay rejection fails closed.

TLS is optional. The no-TLS profile is intentionally unauthenticated and unencrypted, like TCP.
Header protection, FEC, checksums, and FakeTCP cookies do not authenticate a peer or encrypt an
application payload.

## Extensions

Use typed configuration for recovery, MTU/MSS/PMTU, congestion control, security, and header
protection. Do not add hot-path packet, flow, scheduler, FEC, or foreign-language callbacks: they
would expose ownership and protocol invariants without hiding meaningful complexity.

## Consequences

- QUICP can recover loss without waiting for a reliable-stream retransmission round trip.
- The application and SDK interfaces remain ordered, TCP-like, and runtime-neutral.
- QUICP owns more recovery behavior than a stream-only transport and must enforce its own bounds and
  logical acknowledgements.
- No interoperability with unrelated protocols or unreleased designs is implied.
