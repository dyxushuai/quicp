# QUICP/2: datagram-first recovery over FakeTCP

Status: normative protocol implemented by this repository.

QUICP/2 is a TCP-like ordered-flow protocol carried by QUIC DATAGRAM and reliable control streams.
It is not wire-compatible with QUICP/1. The exact profile token is `quicp/2`; no alternate
multipath token exists. FakeTCP preserves datagram boundaries and never retransmits or orders data.

The words MUST, MUST NOT, SHOULD, and MAY are normative.

## 1. Integer and frame encoding

All integers use network byte order. `vint` is the canonical QUIC variable integer: the high two
bits select a width of 1, 2, 4, or 8 bytes and the remaining 6, 14, 30, or 62 bits hold the value.
An encoder MUST use the shortest width. A decoder MUST reject non-canonical, truncated, overflowing,
or trailing input before mutating connection or flow state.

Reliable control-stream frames are:

```text
type:u8 | length:vint | payload:length bytes
```

| Type | Name | Payload |
| ---: | --- | --- |
| `0x01` | `CAPABILITIES` | `flags:vint, max_symbol:u16, max_span:u16, decoder_window:u16, max_ack_ranges:u8` |
| `0x02` | `OPEN` | `host_len:u8, canonical_host, port:u16` |
| `0x03` | `STATUS` | `status:u8` |
| `0x04` | `ACK` | `contiguous:vint, range_count:u8, (start:vint, end:vint)*` |
| `0x05` | `MAX_OFFSET` | `maximum:vint` |
| `0x06` | `FIN` | `final_offset:vint` |
| `0x08` | `STREAM_DATA` | `offset:vint, flags:u8, bytes` |
| `0x09` | `EARLY_OPEN` | `token_len:u8, token, nonce:u64, OPEN payload, initial bytes` |

Type `0x07` is reserved and MUST be rejected. Abortive flow termination uses QUIC `RESET_STREAM`
with a QUICP application error code. Unknown frame types, nonzero reserved flags, duplicate
`CAPABILITIES`, or a frame exceeding the negotiated control-frame limit are connection errors.
Invalid flow offsets, credit, ACK, or FIN transitions reset only that flow.

`STATUS` is a closed one-byte set: `0x00` OK, `0x01` general failure, `0x02` policy denied,
`0x03` resolution failure, `0x04` connection refused, `0x05` connection timeout, and `0x06`
capacity exhausted. Other values are flow protocol errors.

## 2. Capabilities and bounds

`CAPABILITIES.flags` uses `0x01` for DATAGRAM, `0x02` for RLC repair, and `0x08` for replay-safe
early data. Multipath is negotiated by QUIC transport parameters and is not repeated here. Other
bits are invalid. Negotiated flags are the intersection of both peers' flags; each numeric limit is
the minimum of the two advertised values. The resulting tuple is fixed for the connection, and a
later incompatible tuple is a connection error. Adaptive mode requires DATAGRAM and RLC;
reliable-only policy omits both and uses `STREAM_DATA`.

| Limit | Protocol bound | Default |
| --- | ---: | ---: |
| source-symbol bytes | `64..=65527` | backend DATAGRAM ceiling minus the 17-byte repair header |
| repair source span | `1..=256` | `64` |
| decoder symbols | `512..=4096` | `512` |
| ACK ranges per frame | `1..=32` | `16` |
| replay bytes per flow | `1..=16 MiB` | `256 KiB` |
| reassembly bytes per flow | `1..=16 MiB` | `256 KiB` |
| recovery bytes per endpoint | `1..=1 GiB` local policy | `64 MiB` |
| pre-OPEN symbols per connection | `0..=256` | `32` |
| work quanta per DATAGRAM | `1..=4096` | `128` |

Ranges are half-open `[start,end)`, strictly increasing, non-overlapping, and above `contiguous`.
All addition is checked in the 62-bit offset space. Declared counts never determine allocation;
storage is preallocated or bounded by validated configuration.
The endpoint-wide recovery budget is local and not negotiated. It accounts retained decoder,
pre-OPEN, and flow-reassembly bytes across every connection created by that endpoint and releases
credit as symbols expire, applications read, or flows close.

## 3. DATAGRAM encoding

A source DATAGRAM is:

```text
0x20 | symbol_id:u32 | record_count:u8 |
  (flow_id:vint | offset:vint | flags:u8 | length:vint | bytes:length)*
```

Source flag `0x01` marks the record carrying the flow final offset. Other bits are invalid. Records
MUST fit completely in one source symbol. A write may be split across symbols; delay-enabled writes
may share a symbol. No-delay writes are emitted on the next bounded driver turn.

A repair DATAGRAM is:

```text
0x21 | repair_id:u32 | first_symbol_id:u32 | span:u16 |
symbol_size:u16 | seed:u32 | coded_bytes:symbol_size
```

`span` is `1..=256`. Source identifiers use wrapping 32-bit serial arithmetic; a repair window MUST
not cross an ambiguity distance of `2^31`. `symbol_size` is the largest encoded source in the
window; shorter sources are zero-padded. Decoded trailing zero padding is removed using each source
record's canonical encoded lengths.

Malformed source or repair DATAGRAMs are dropped and counted before decoder mutation. A valid frame
that exceeds a negotiated shared-resource bound closes the connection.

## 4. Coding arithmetic

Coding uses GF(256), primitive polynomial `x^8 + x^4 + x^3 + x^2 + 1` (`0x11d`) and generator
`0x02`. Addition is XOR. Multiplication and inversion follow polynomial reduction by `0x11d`.

For source ordinal `i` in a repair window, coefficient generation starts from
`x = seed ^ (repair_id * 0x9e3779b9) ^ (symbol_id(first + i) * 0x85ebca6b)`, with multiplication
modulo `2^32`. Mix `x` with `x ^= x >> 16; x *= 0x7feb352d; x ^= x >> 15;
x *= 0x846ca68b; x ^= x >> 16`, again modulo `2^32`, and use its low byte, replacing zero with one.
Repair bytes are the XOR of each
zero-padded source multiplied by its coefficient. Elimination selects the lowest source identifier
as pivot and normalizes the pivot to one. The exact vectors in `tests/vectors/quicp2.txt` are
normative.

The decoder retains at most the negotiated window and row count. Each received DATAGRAM gets the
configured work quanta multiplied by the negotiated symbol-byte ceiling; exhausting that fixed
local budget rejects the repair without state mutation. An underdetermined matrix stays pending;
it never fabricates data.

## 5. Reliability and flow state

Each flow keeps one reliable bidirectional stream. The opener sends `CAPABILITIES`, then `OPEN`; the
peer replies with identical negotiated capabilities and `STATUS`. Payload is not exposed before
`STATUS OK`.

The sender retains accepted bytes until a logical `ACK` covers them. A replay keeps the original
flow offset and uses a new source symbol identifier. The receiver accepts identical overlapping
bytes while retaining only uncovered ranges, rejects contradictory overlap, and exposes only the
contiguous prefix. `FIN` carries the final
offset; EOF is visible only when all lower bytes are contiguous. `MAX_OFFSET` may increase but never
decrease. Residual gaps are selectively replayed, then sent as `STREAM_DATA` after repeated recovery
failure. QUIC packet ACKs continue to own RTT, congestion, pacing, packet loss, and path validation.

Adaptive repair is sender-local policy, not wire negotiation. It emits no repair without new
outbound loss. When loss is observed, the bounded repair budget combines outbound packet loss and
transmission deltas with logical byte delivery, consecutive loss turns, and prior replay cost. The
budget never exceeds the outstanding source count or negotiated repair span. A remaining gap is
replayed once and then moved to reliable `STREAM_DATA`; reliable-only mode skips DATAGRAM entirely.
Snapshots expose loss, maximum current path RTT, queued DATAGRAMs, and retained coding-window bytes
alongside delivery counters without adding callbacks to the hot path.

One directional coding window spans all validated paths. `noq` chooses the packet path. FakeTCP
sequence state remains independent per four-tuple and is never used as a QUICP ACK or symbol ID.

## 6. Replay-safe early data

Ordinary OPEN and writes are not replay-safe. `EARLY_OPEN` is allowed only through the explicit
replay-safe API and contains bounded initial bytes. Its token is a server-issued MAC over profile,
capabilities, server epoch, expiry, and token identity using a secret distinct from the FakeTCP
cookie. The server admits a `(token identity, nonce)` once in a bounded process-local cache and
rejects bad MAC, expiry, capability mismatch, duplicate nonce, or cache exhaustion before invoking
the origin. Transport-level 0-RTT unavailability or rejection falls back once to ordinary 1-RTT
OPEN; token or replay rejection fails closed and does not retry the origin action. QUICP does not
claim cross-process, cross-restart, or cross-connection exactly-once effects. When multipath is
required, an accepted early action can reach the server before post-handshake backup-path
validation; a later client error is therefore delivery-ambiguous.

TLS and no-security implement the same flow contract. No-security is unencrypted and
unauthenticated; a valid bearer token does not authenticate the client. Header protection, FEC,
checksums, and FakeTCP cookies are not authenticity boundaries.

The no-security backend handshake carried by QUIC CRYPTO frames is exactly:

```text
magic:"QPCS" | kind:u8 | profile_len:u8 | params_len:u16 | profile | QUIC transport parameters
```

`kind` is `1` CLIENT_HELLO, `2` SERVER_HELLO, or `3` CLIENT_CONFIRM. `profile_len` is `1..=32`,
`params_len` is network byte order, and the complete message length is `8 + profile_len +
params_len`; trailing bytes are invalid. The state order is CLIENT_HELLO, SERVER_HELLO,
CLIENT_CONFIRM. Every message carries the exact `quicp/2` profile. The TLS profile uses TLS 1.3
with ALPN `quicp/2`; it does not change QUICP/2 flow or DATAGRAM framing.

A replay token is exactly 73 bytes:

```text
version:u8=1 | epoch:u64 | expiry_seconds:u64 | capability_fingerprint:u64 |
identity:16 bytes | tag:32 bytes
```

`tag` is HMAC-SHA-256 over ASCII `quicp/2 replay token`, one zero byte, and the preceding 41-byte
token body. The HMAC key is a dedicated server secret of at least 32 bytes. A server MUST NOT issue
a token before an ordinary flow has completed capability negotiation. The fingerprint binds that
negotiated snapshot; it is not a replacement for capability negotiation.

## 7. Error and resource scope

- malformed DATAGRAMs that cannot enter shared state: drop and count;
- invalid per-flow offset, ACK, credit, or FIN: reset that flow;
- invalid capabilities, duplicate negotiation, or shared-resource abuse: close the connection;
- local replay/egress pressure: return pending, never discard accepted reliable bytes;
- driver failure: close the connection and release all bounded state.

Implementations MUST reject peer-controlled lengths, counts, offsets, ranges, symbols, tokens, and
limits before allocation or state mutation.

## 8. FakeTCP carrier envelope

The Tier 0 carrier emits complete IPv4 or IPv6 packets with IP protocol `6`, valid IP/TCP
checksums, no fragmentation, addresses and ports from one fixed four-tuple, and one complete QUIC
datagram as the TCP payload. The carrier never splits, joins, retransmits, reorders, encrypts, or
length-prefixes the payload.

IPv4 uses a 20-byte `0x45` header, `DF`, fragment offset zero, TTL 64, and a total length matching
the complete packet. IPv6 uses a 40-byte base header, no extension headers, hop limit 64, and a
payload length matching TCP header, options, and payload. Receivers validate address family,
length, protocol, IP checksum where applicable, and TCP pseudo-header checksum before exposing the
payload. Malformed input is dropped without carrier or QUICP state mutation.

The first client packet uses `SYN`; the first server packet uses `SYN|ACK`; later packets use
`ACK|PSH`. The 20-byte TCP base header has window 65535 and urgent pointer zero. SYN options are an
MSS advertisement, SACK permitted, window scale 7, an optional TCP Fast Open option kind 34 with a
tuple-bound 16-byte cookie, and NOP padding to a 32-bit boundary. Ordinary packets have no options.
Unknown well-formed options are ignored.

Each four-tuple owns independent randomized sequence state. SYN consumes one sequence number and
every payload byte consumes one. Ordinary payload therefore advances by its byte length; SYN data
advances by one plus its byte length. Sequence arithmetic wraps as TCP serial arithmetic. These
values are camouflage metadata only and MUST NOT be used as QUIC packet numbers, QUICP symbol IDs,
logical ACKs, replay state, congestion state, or MPTCP DSS mappings.

`outer_ip_mtu` limits the complete raw IP packet. Automatic MSS is `outer_ip_mtu - IP header - TCP
header`, producing 1460 for IPv4 and 1440 for IPv6 at MTU 1500. The QUIC payload ceiling is the
intersection of the configured QUIC payload, adapter MTU, and carrier envelope. A sender rejects an
oversized datagram instead of fragmenting it.

The optional SYN cookie is a truncated HMAC-SHA-256 over the four-tuple and rotating epoch. It is a
stateless carrier-admission value, not peer identity or a QUICP security key. SYN data may carry
the first backend handshake datagram. Replay-safe `EARLY_OPEN` still requires Section 6 admission;
loss or rejection of SYN data MUST NOT cause duplicate application delivery.

## 9. Carrier tiers and platform boundary

- Tier 0 injects and receives real TCP-shaped IP packets on the ISP-facing path and suppresses only
  the selected tuple's kernel RST. It is the only tier that claims ISP-level FakeTCP camouflage.
- Tier 1 supplies complete packets through TUN/TAP and may use smoltcp. It is an integration seam,
  not a verified ISP-facing carrier by itself.
- Tier 2 uses Apple Network Extension or Android `VpnService` packet APIs. Platform permission,
  socket protection, routes, and lifecycle remain host responsibilities.

All tiers preserve complete datagrams. An unsupported tier fails closed; an implementation MUST
NOT silently substitute UDP or an ordered TCP byte stream. DNS, FakeIP allocation, VPN policy,
TUN creation, raw-socket privilege, and mobile entitlements are outside the QUICP protocol.

## 10. Independent implementation checklist

An implementation claiming QUICP/2 interoperability must:

1. select only `quicp/2` and reproduce the committed wire vectors;
2. implement every peer-controlled bound before allocation or state mutation;
3. keep the reliable stream as control/fallback while source data normally uses DATAGRAM;
4. preserve ordered, duplicate-free flow reads under loss, reorder, repair, replay, and fallback;
5. keep FakeTCP state independent for every four-tuple and preserve datagram boundaries;
6. reject replay-safe attempts before application side effects when token admission fails;
7. document whether replay admission is process-local or distributed and never claim exactly once;
8. pass clean, loss, burst, duplicate, malformed, resource-limit, multipath, and early-data tests.
