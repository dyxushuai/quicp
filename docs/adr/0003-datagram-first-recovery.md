# ADR 0003: Make adaptive datagram recovery the QUICP core

- Status: Accepted
- Date: 2026-08-26
- Supersedes: ADR 0002

## Context

QUICP targets weak, lossy, long-RTT, and QoS-constrained paths while presenting an ordered,
TCP-like flow interface. QUICP/1 maps each application flow directly to a reliable QUIC stream.
That delegates byte acknowledgement, retransmission, ordering, and flow control to the backend,
but it also prevents a higher recovery layer from observing erasures and preserves stream-local
head-of-line blocking.

The existing `QueqiaoPlugin` does not change that data path. It is a one-shot configuration adapter
that installs a shared congestion controller. It does not implement coded datagrams, byte-range
acknowledgements, replay, flow scheduling, or substrate selection. Expanding the public plugin
interface with packet and flow callbacks would expose ownership-sensitive hot-path behavior without
hiding meaningful complexity.

QUICP does not require wire compatibility with Queqiao Protocol 1. It will reuse the architectural
ideas that match QUICP's goals while retaining its own wire contract, FakeTCP carrier, optional
security profiles, multipath backend, runtime-neutral flow interface, and native SDK boundary.

## Decision

### 1. Introduce one breaking QUICP/2 profile

QUICP/2 replaces QUICP/1 rather than negotiating a compatibility mode. One profile token identifies
the application protocol; DATAGRAM, FEC limits, and multipath are negotiated capabilities rather
than separate profile tokens. The current `docs/protocol.md` remains the normative QUICP/1 document
until the implementation and conformance vectors switch together.

QUICP/2 keeps the existing public flow shape:

```text
Connection::open_flow / accept_flow
QuicpFlow::poll_read / poll_write / poll_flush / poll_shutdown / reset
```

Callers do not choose a wire substrate for each write and do not handle FEC or acknowledgement
callbacks.

### 2. Make logical flow reliability a core module

Each connection owns:

- a connection-wide DATAGRAM plane and one reader;
- a shared directional path model;
- a flow table and DATAGRAM demultiplexer;
- one connection-wide sliding-window encoder and decoder per direction; and
- bounded symbol, replay, reassembly, pre-open, and scheduling storage.

Each flow owns:

- its existing bidirectional QUIC stream, repurposed for reliable control and data fallback;
- absolute send and receive byte offsets;
- bounded replay and receive-reassembly state;
- acknowledged ranges and receive credit; and
- OPEN, FIN, RESET, and terminal state.

The reliable stream carries framed `OPEN`, `STATUS`, `ACK`, `MAX_OFFSET`, `FIN`, `RESET`, and
fallback `STREAM_DATA` messages. Selected data normally travels through QUIC DATAGRAM. Keeping a
stream per flow avoids a single connection-wide control-stream head-of-line dependency and reuses
the current flow admission lifecycle.

### 3. Use connection-wide coded DATAGRAMs

QUICP/2 defines source and repair datagrams. A source symbol contains one or more logical flow data
records identified by QUIC stream ID, absolute byte offset, flags, and payload. A repair symbol
names the consecutive source-symbol window it covers. Source, repair, and transmission sequences
are directional and connection-scoped.

Small writes may share a symbol when no-delay is disabled. No-delay writes are emitted without
waiting for aggregation. Large writes are fragmented across consecutive symbols. A receiver emits
whole logical records as soon as they arrive or are recovered; only each flow's contiguous byte
prefix is exposed to its caller.

DATAGRAM is the primary data substrate when adaptive recovery is active. Reliable stream data is a
fallback when DATAGRAM was not negotiated, coding is not worthwhile on the measured path, or the
adaptive policy has abandoned repeated residual recovery.

### 4. Separate packet acknowledgement from logical acknowledgement

Backend QUIC ACKs continue to own packet loss detection, RTT estimation, congestion control, and
pacing. They do not acknowledge recovered logical bytes.

QUICP/2 flow ACKs carry a contiguous byte offset, a bounded set of additional received ranges, and
the maximum permitted receive offset. They acknowledge bytes received directly or reconstructed by
FEC. The sender retains unacknowledged bytes in a bounded replay buffer, reissues residual gaps, and
reclaims storage only after logical acknowledgement.

Repeated data, ACKs, and FINs are idempotent. A retransmission uses a new source-symbol identity but
the original flow byte offset. A FIN carries the final byte offset; EOF is exposed only after every
byte below that offset is contiguous.

### 5. Use sliding-window random linear coding

The coding model follows the systematic GF(256) sliding-window RLC design described by RFC 8681,
with QUICP-specific framing and policy. Source symbols are sent unchanged. Repair symbols are
deterministic linear combinations of recent source symbols. The decoder performs bounded
incremental elimination and may recover symbols out of order.

The QUICP/2 protocol specification will pin the field polynomial, coefficient generation,
identifier arithmetic, padding rules, maximum repair span, decoder width, and conformance vectors.
The initial bounds are a maximum 256-source repair span and a minimum 512-symbol decoder window.

Coding rate and window size are sender policy derived from directional loss, RTT, delivery rate,
burst behavior, and the cost of replay. Tail repair protects the end of a burst. A clean path sends
no parity. FEC reduces recovery latency but does not claim reliability; the byte-range replay layer
handles residual loss.

No public `FecCodec` or recovery trait is introduced. Existing mature Rust block-code crates do not
implement this sliding-window wire model. The implementation is an internal sans-I/O module,
validated by committed vectors and fuzz/property tests. A mature GF(256) arithmetic kernel may be
reused if it preserves the pinned wire result and improves measured performance.

### 6. Keep coding connection-scoped across paths

A coding window spans all active paths in one direction. A repair arriving on one path can recover
a source erased on another path. FakeTCP continues to create independent TCP-shaped sequence state
for each four-tuple; those carrier sequences never become flow acknowledgements or FEC identities.

The initial implementation lets `noq` select a path for DATAGRAM transmission and consumes its
per-path RTT, congestion, and path-health state. QUICP/2 does not initially require a vendored
`send_datagram_on(path_id)` extension. Explicit source/repair path placement is added only if
same-window measurements prove that backend scheduling prevents useful path diversity; that change
does not require a QUICP/2 wire change.

### 7. Admit application 0-RTT explicitly

FakeTCP SYN data may carry a backend handshake datagram and remains distinct from application
early data.

Application 0-RTT requires a server-issued, expiring, MAC-protected resumption token bound to the
QUICP profile and server epoch. An early flow includes the token identity and a fresh attempt nonce.
The server admits it only when the token is valid, the remembered profile is compatible, the
attempt is absent from a bounded replay cache, and the caller explicitly marked the operation as
replay-safe.

Ordinary `open_flow` remains replay-unsafe by default. The transport suppresses duplicate delivery
within one accepted early attempt, but it cannot guarantee cross-connection exactly-once effects.
Only replay-safe application operations may use early data. A multi-instance deployment needs a
shared replay cache before claiming strict anti-replay. The no-security profile can validate a
server-issued token but still provides neither peer identity nor payload authenticity.

### 8. Replace the generic plugin registry with typed seams

`PluginRegistry`, `QuicpPlugin`, `QueqiaoPlugin`, and `MAX_PLUGINS` are removed. Queqiao-inspired
recovery is core protocol behavior, not a plugin.

Runtime choices use explicit configuration:

- a built-in or Rust-only custom congestion-controller factory;
- adaptive or reliable-only recovery configuration; and
- explicit security/header-protection configuration.

No packet, flow-data, scheduler, FEC, or foreign-language callback interface is added. Swift,
Kotlin, and C select built-in profiles through bounded enum/struct configuration and retain the
existing synchronous, caller-buffer-owned packet interface. Cargo features continue to select
optional dependencies and platform adapters, not runtime protocol policy.

### 9. Fail closed at protocol and resource seams

All untrusted counts, offsets, ranges, symbol identifiers, lengths, and negotiated limits are
validated before allocation or decoder mutation. Replay storage, decoder rows, ACK ranges,
fragment groups, pending flow state, and pre-open DATAGRAM storage have hard limits.

- Local pressure applies backpressure instead of dropping reliable flow bytes.
- Invalid per-flow offsets, credit, ACKs, or final offsets reset that flow.
- Invalid shared control state or peer resource-limit violations close the connection.
- Malformed source and repair datagrams are discarded before entering shared FEC state.
- Symbols leaving the decoder unrecovered trigger replay and do not close the connection.

TLS-protected source and repair DATAGRAMs inherit QUIC AEAD authenticity. The no-security profile
remains explicitly unauthenticated; checksums and FEC do not become a security boundary.

## Implementation sequence

1. Publish the QUICP/2 frame grammar, state transitions, limits, and conformance vectors.
2. Implement and fuzz sans-I/O range, reassembly, replay, and sliding-window coding modules.
3. Enable backend DATAGRAM negotiation and add the connection-wide DATAGRAM plane.
4. Replace `QuicpFlow`'s direct stream storage with an internal flow handle while preserving its
   public poll interface.
5. Add framed control, byte-range ACKs, replay, and reliable stream fallback.
6. Add adaptive coding and shared directional path measurement.
7. Integrate multipath, application 0-RTT, FFI/SDK configuration, examples, and metrics.
8. Delete QUICP/1 flow code and the generic plugin registry after QUICP/2 end-to-end tests pass.

The repository does not retain a runtime compatibility switch or dual wire implementation. Each
step must leave the branch buildable, and unrelated carrier/platform adapters remain intact.

## Verification

The release gate covers:

- exact frame and FEC conformance vectors;
- deterministic clean, random-loss, burst-loss, reorder, duplicate, and repair-loss channels;
- single and multiple symbol recovery plus residual replay;
- ACK compression, duplicate ACKs, invalid ranges, flow credit, FIN gaps, and reset races;
- DATAGRAM-before-OPEN handling and every memory bound;
- malformed offset, ESI, repair, and resumption-token fuzzing;
- accepted, rejected, expired, replayed, and profile-mismatched 0-RTT;
- primary-path failure with recovery on a validated backup path;
- runtime-neutral core, Tokio adapter, C ABI, Swift, and Kotlin smoke tests; and
- aligned reliable-only and adaptive benchmarks on the same carrier and workload.

Performance reports include useful goodput, p50/p99 latency, parity overhead, residual replay, CPU,
allocations, and peak memory. A clean path must disable parity and avoid a material regression.

## Consequences

- QUICP owns more transport behavior and testing responsibility than QUICP/1.
- The architecture matches the weak-path goal and can recover data without waiting for a stream
  retransmission round trip.
- Application and SDK interfaces remain TCP-like and runtime-neutral.
- Wire compatibility with QUICP/1 and Queqiao Protocol 1 is intentionally absent.
- The generic plugin registry disappears; explicit typed seams remain where behavior genuinely
  varies.
- The vendored QUIC backend remains responsible for connection establishment, packet protection,
  packet ACKs, congestion/pacing, path validation, and multipath packet scheduling.

## Rejected alternatives

- FEC over reliable QUIC streams duplicates retransmission and cannot remove stream head-of-line
  blocking.
- Coding complete QUIC packets below the backend preserves the current flow implementation but does
  not provide Queqiao-style logical acknowledgement, selective recovery, or cross-flow scheduling.
- A DATAGRAM-only protocol would rebuild reliable control delivery that QUIC streams already
  provide.
- A public hot-path plugin interface would expose packet ownership and protocol invariants while
  the project still has only one recovery implementation.
- A fixed Reed-Solomon block code has mature implementations but adds block-sealing latency and
  cannot adapt parity for symbols already in flight.
