# Multipath QUIC Backend Research

Status: non-normative research notes. [`../protocol.md`](../protocol.md) is the
canonical QUICP design and wins if the two documents conflict. QUICP is a custom
protocol; this file audits standard Multipath QUIC as a temporary implementation
backend and prior-art reference. Its TLS, ALPN, packet-protection, and draft
interoperability statements do not apply to the no-security QUICP baseline.
Sources were
checked on 2026-08-09. Repository links are pinned to the inspected revision or
release tag.

## Decision

Use a pinned `noq` 1.1.1-based fork only as the temporary backend candidate for
Multipath QUIC semantics, but keep it behind QUICP's host-driven transport
facade (`Client`/`Server` and caller-owned carrier I/O). `noq` is a Rust, async-oriented Quinn
fork, enables `runtime-tokio` by default, advertises Multipath QUIC and 0-RTT,
and exposes an explicit
`Connection::open_path(FourTuple, PathStatus)` API
([release metadata and features](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq/Cargo.toml#L1-L48),
[project scope](https://github.com/n0-computer/noq/blob/noq-v1.1.1/README.md#L9-L59),
[path API](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq/src/connection.rs#L427-L470)).

This is a guarded implementation choice, not a standards claim. The current
specification is `draft-ietf-quic-multipath-21`, published 2026-03-17. As of the
research date it remains an **Active Internet-Draft**, with IESG state **RFC Ed
Queue** and RFC Editor state **In Progress**; it is not yet an RFC
([Datatracker status](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/21/)).
The draft's IANA values are still described as suggested values pending final
allocation, so the eventual RFC must be compared with the pinned implementation
before release
([draft-21 Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-6)).

Released upstream Quinn 0.11.11 cannot provide native multipath. Its connection
has one current path plus an optional previous migration path and exactly the
Initial, Handshake, and 1-RTT packet-number spaces; its supported transport
parameters omit `initial_max_path_id`, and its frame enum omits every multipath
frame
([connection state](https://github.com/quinn-rs/quinn/blob/quinn-0.11.11/quinn-proto/src/connection/mod.rs#L133-L178),
[transport parameters](https://github.com/quinn-rs/quinn/blob/quinn-0.11.11/quinn-proto/src/transport_parameters.rs#L608-L667),
[frames](https://github.com/quinn-rs/quinn/blob/quinn-0.11.11/quinn-proto/src/frame.rs#L139-L167)).
Its open multipath feature request corroborates that source reading
([Quinn issue 224](https://github.com/quinn-rs/quinn/issues/224)).

## Draft-21 transport semantics

| Concern | Normative result |
| --- | --- |
| Negotiation | Each endpoint advertises `initial_max_path_id` transport parameter `0x3e`. If either endpoint omits it, neither may use this extension's frames or mechanisms. A value of zero negotiates the extension but initially permits no path beyond path 0; `MAX_PATH_ID` can raise the limit. The parameter must not be remembered for a later connection. Multipath requires non-zero source and destination connection IDs and a cipher nonce of at least 12 bytes. ([Sections 2 and 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-2)) |
| Path identity | A connection ID binds a packet to exactly one path ID and therefore one packet-number space. Path 0 is the initial path; the same ID is used in both directions; IDs increase monotonically and are never reused. Different path IDs may use the same four-tuple. ([Section 1](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-1)) |
| Path creation | Only the client opens an additional path, after the handshake negotiated multipath and both endpoints issued connection IDs for a common unused path ID. Both sides validate the peer address; the server remains subject to per-path anti-amplification, and each path must support the 1200-byte minimum QUIC packet size. ([Sections 3 and 3.1](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-3)) |
| Address discovery | The extension deliberately does not discover or manage addresses and does not decide when to open or close paths; the application or another mechanism must supply those decisions. ([Sections 1 and 3](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-1)) The separate QUIC Address Discovery draft only reports an endpoint's externally observed address for an existing path and is expired and archived, so it is not a standards-track source of QUICP path candidates ([QAD status and abstract](https://datatracker.ietf.org/doc/draft-ietf-quic-address-discovery/)). |
| Packet numbers and protection | Application-data packet numbers are separate per path ID and each begins at zero. Initial and Handshake retain path 0. For negotiated multipath, the 1-RTT AEAD nonce incorporates the 32-bit path ID and 62-bit packet number, preventing nonce reuse across those spaces. ([Sections 1 and 2.4](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-2.4)) |
| Recovery and congestion control | Loss detection and congestion state are per path; a sender may not exceed that path's congestion window. Independent controllers can be unfair if paths share a bottleneck; coupled congestion control is possible but is not mandated. ([Section 5.3](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-5.3)) |
| Scheduling | No IETF scheduler is specified. Selection is a local endpoint decision among usable paths. Sending one ordered stream over paths with different delays can make delivery wait for the slowest used path. ([Sections 1 and 5.5](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-5.5)) |
| NAT rebinding and migration | CID rotation, NAT rebinding, and RFC 9000 migration within a path retain its path ID and packet-number space. The draft prefers opening a new path and then abandoning the old one for controlled handover, but ordinary migration remains necessary for NAT rebinding and a server preferred address. After a changed four-tuple is validated, congestion and RTT state are reset according to RFC 9000. ([Section 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-5.1), [RFC 9000 Section 9.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-9.4)) |

The multipath frame set is 1-RTT-only: `PATH_ACK` (`0x3e`/`0x3f`),
`PATH_ABANDON` (`0x3e75`), `PATH_STATUS_BACKUP` (`0x3e76`),
`PATH_STATUS_AVAILABLE` (`0x3e77`), `PATH_NEW_CONNECTION_ID` (`0x3e78`),
`PATH_RETIRE_CONNECTION_ID` (`0x3e79`), `MAX_PATH_ID` (`0x3e7a`),
`PATHS_BLOCKED` (`0x3e7b`), and `PATH_CIDS_BLOCKED` (`0x3e7c`)
([draft-21 Sections 4 and 6](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-4)).

## The 0-RTT boundary

Multipath is unknown while early data is sent. Initial, Handshake, and 0-RTT use
the initial path, path ID 0; additional paths and every multipath-specific frame
are available only after both transport parameters are known and the handshake
completes. After negotiation, `PATH_ACK` may acknowledge still-outstanding 0-RTT
packets in path 0's space, while an endpoint must continue accepting ordinary
`ACK` for them
([draft-21 Sections 2, 2.3, and 3](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-2.3)).

Transport negotiation therefore cannot be inferred from a previous session:
`initial_max_path_id` is explicitly excluded from remembered transport
parameters. `noq` 1.1.1 mirrors that rule by clearing
`initial_max_path_id` when restoring ticket parameters and issues the first
per-path connection IDs only after entering `Established`
([ticket restoration](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/mod.rs#L3974-L4007),
[post-handshake enablement](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/mod.rs#L4713-L4729)).

`noq::Connecting::into_0rtt` warns that outgoing early data is replayable and
that incoming 0.5-RTT can precede client authentication. Its
`Connection::authenticated()` future is the point after which incoming reads
are guaranteed not to arise from replay and outgoing streams will not later be
discarded due to 0-RTT rejection
([0-RTT contract](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq/src/connection.rs#L90-L148),
[`authenticated`](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq/src/connection.rs#L744-L769)).
QUICP does not currently admit this backend capability. If a future profile
adds it, no path-1 action may be attempted before the handshake and application
work must remain behind an explicit replay-safe admission gate.

## `noq` 1.1.1 source audit against draft-21

The [`noq-v1.1.1` tag](https://github.com/n0-computer/noq/tree/noq-v1.1.1)
resolves to commit `12a4bf0b42070b570fb8cf90fe315c630b03f56e`. A
direct source comparison finds the draft-21 wire essentials present:

- transport parameter `initial_max_path_id = 0x3e` and all ten draft-21 code
  points for the nine named multipath frame types match the draft
  ([parameter](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/transport_parameters.rs#L725-L733),
  [frames](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/frame.rs#L99-L124));
- multipath is enabled only when both local and remote maximum path IDs exist,
  and receipt with zero-length connection IDs is rejected
  ([negotiation](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/mod.rs#L6610-L6673));
- the Data space maps each `PathId` to its own packet-number space, while each
  four-tuple path state carries its own RTT estimator, congestion controller,
  pacer, validation, MTU, and in-flight accounting
  ([packet spaces](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/spaces.rs#L23-L41),
  [path state](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/paths.rs#L136-L226)); and
- rustls packet protection passes both path ID and packet number to AEAD
  encryption and decryption
  ([packet key](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/crypto/rustls.rs#L634-L656)).

This audit supports prototyping against draft-21; it is not proof of complete
conformance or interoperability. Five release-API limits affect the canonical
design:

- initial `Endpoint::connect_with` accepts only a remote `SocketAddr`, so QUICP's
  concrete wildcard UDP adapter must supply candidate 0's source IP and interface
  whenever the initial transmit has no source
  ([connect API](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq/src/endpoint.rs#L214-L267));
- `max_concurrent_multipath_paths(2)` initially permits only path IDs 0 and 1.
  The proto layer can replenish `MAX_PATH_ID` after discard, but `noq` does not
  expose that method publicly, so the admitted fork must add the narrow wrapper
  ([transport mapping](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/config/transport.rs#L391-L440),
  [proto operation](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/mod.rs#L2798-L2833));
- `open_path(..., Backup)` updates only local scheduler state and does not enqueue
  `PATH_STATUS_BACKUP`, while a peer-created path starts as `Available`. The fork
  must queue the caller's non-default initial status and create peer-opened
  nonzero paths as local `Backup` before scheduler eligibility
  ([open behavior](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/mod.rs#L561-L597),
  [status enqueue behavior](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/mod.rs#L819-L840));
- its endpoint/connection driver originally used unbounded channels. The vendored adapter now
  replaces those paths with bounded 256-entry protocol queues and 8-entry control queues; protocol
  saturation drops datagram work for QUIC retransmission while endpoint lifecycle events are
  retained and retried ([bounded adapter](../../vendor/noq/src/connection.rs)); and
- per-path keepalive and idle timeout default to `None`, so QUICP must explicitly
  configure them to detect forwarding blackholes
  ([transport defaults](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/config/transport.rs#L566-L595)).

In addition, `noq` contains QAD and an
n0-specific NAT-traversal protocol that its source calls a simplified protocol
inspired by the expired individual NAT-traversal draft. Those extensions are
separate from Multipath QUIC and must remain disabled in QUICP
([`noq` extension list](https://github.com/n0-computer/noq/blob/noq-v1.1.1/README.md#L15-L23),
[n0 transport parameter](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/transport_parameters.rs#L725-L733),
[expired draft status](https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/)).

### Scheduler boundary

`noq` implements the draft's `Available`/`Backup` policy: a validated
`Available` path is preferred, and a `Backup` path may carry data only when no
validated `Available` path exists
([path status API](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/paths.rs#L1023-L1041),
[selection rules](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/mod.rs#L1147-L1198)).
Among equally eligible paths, the implementation iterates path IDs in ascending
order and documents that it currently chooses the lowest path not blocked by
congestion
([poll order](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/mod.rs#L1006-L1104),
[scheduler comment](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/mod.rs#L7288-L7299)).
Thus QUICP `failover` maps directly to path 0 `Available` plus path 1 `Backup`.
An aggregate mode would only provide lowest-ID-first capacity spillover, not
round-robin, weighted, latency-aware, or coupled-congestion scheduling. It is
therefore deferred from v1 until measured under heterogeneous RTT, loss, and MTU
([QUICP multipath modes](../protocol.md#6-multipath-over-faketcp)).

## Implementation status

| Implementation | Primary-source result as of 2026-08-09 |
| --- | --- |
| `noq` 1.1.1 | Native Multipath QUIC, Tokio runtime, explicit source-IP/remote `FourTuple`, path status/events/stats, and 0-RTT are present in the released source; this is the preferred Rust candidate. ([README](https://github.com/n0-computer/noq/blob/noq-v1.1.1/README.md#L9-L59), [`open_path`](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq/src/connection.rs#L427-L470)) |
| `iroh-quinn` 0.16.1 / Iroh | The older `iroh-quinn` release advertises Multipath, QAD, and QNT, but current Iroh source uses `noq`; treat `iroh-quinn` as the predecessor rather than a new dependency choice. ([0.16.1 README](https://docs.rs/crate/iroh-quinn/0.16.1/source/README.md), [Iroh `noq` transport source](https://docs.rs/iroh/1.0.3/src/iroh/endpoint/quic.rs.html)) |
| Quinn 0.11.11 | No native Multipath QUIC. `Endpoint::rebind` replaces the endpoint socket for all active connections, which is RFC 9000 migration/rebinding rather than simultaneous paths. ([source proof above](#decision), [`rebind`](https://github.com/quinn-rs/quinn/blob/quinn-0.11.11/quinn/src/endpoint.rs#L239-L263)) |
| quic-go | Its official multipath request remains open with no linked development, so it is not a native-MPQUIC engine on the inspected branch. ([issue 3343](https://github.com/quic-go/quic-go/issues/3343)) |
| quiche | Its official multipath request remains open with no linked development, so it is not a native-MPQUIC engine on the inspected branch. ([issue 2462](https://github.com/cloudflare/quiche/issues/2462)) |
| ngtcp2 | The inspected transport-parameter registry has no `initial_max_path_id`/`0x3e`; it is not a native-MPQUIC engine at that revision. ([pinned registry](https://github.com/ngtcp2/ngtcp2/blob/d7fb3ed0407e1333e4ecbd011fcfd9c16499d5e0/lib/ngtcp2_transport_params.h#L38-L59)) |
| picoquic | The inspected source advertises the evolving Multipath draft and exposes path creation/status APIs, but constants are still labeled draft-20 and the README says standard-version support remains planned. Use it only as an interop candidate after a draft-21/RFC delta check. ([README](https://github.com/private-octopus/picoquic/blob/467cb81bcafc652bae2a1c8824b70f12f470039c/README.md#L9-L34), [draft label](https://github.com/private-octopus/picoquic/blob/467cb81bcafc652bae2a1c8824b70f12f470039c/picoquic/picoquic.h#L255-L260), [path API](https://github.com/private-octopus/picoquic/blob/467cb81bcafc652bae2a1c8824b70f12f470039c/picoquic/picoquic.h#L1053-L1165)) |

## Historical Design A: one deep `run` module, one concrete adapter

This section records the earlier transparent-proxy proposal. It is superseded by the portable
host-driven library boundary; TUN, FakeIP, DNS, and origin dialing now belong only to optional
integration examples.

**Module and Interface.** Preserve exactly the two existing public entry points:

```rust
pub fn load_config(path: &Path) -> Result<Config, ConfigError>;
pub async fn run(config: Config, shutdown: CancellationToken) -> Result<(), RunError>;
```

This is a deep module: a very small Interface hides a substantial
Implementation. Client `Config` carries only the canonical `off` or `failover`
mode and one or two explicit `{ name, local_ip, server_addr }` candidates; server
`Config` carries its destination-address allowlist. Do not expose
`noq::Connection`, `FourTuple`, `PathId`,
`PathStatus`, streams, path events, or a scheduler trait
([canonical Interface and configuration](../protocol.md#8-platform-adapters-and-mobile-ffi)).

**Implementation and Locality.** Inside `run`, one concrete `noq` Adapter owns
the endpoint, the single long-lived backend session, resumption, flow
multiplexing, path-event draining, and bounded path state. Its wildcard Linux
UDP socket pins source-less initial transmits to candidate 0 and filters the
server's received destination addresses before backend parsing. The event drain
starts first; only after authenticated multipath negotiation does the client
call `open_path(FourTuple::new(candidate.server_addr,
Some(candidate.local_ip)), PathStatus::Backup)` for candidate 1. The server validates and responds but
does not initiate the path, matching draft-21 and the `noq` API
([path initiation](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-3),
[`FourTuple`](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/lib.rs#L371-L422),
[path API](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq/src/connection.rs#L427-L470)).

**Seam and Leverage.** The Adapter is crate-private and concrete. There is no
public transport trait, backend selector, connection pool, or QUICP-level
striping layer: a second hypothetical backend would add a shallow Seam without
current Leverage. All path lifecycle, NAT rebinding, packet-number spaces,
congestion state, and scheduler behavior stay local to the transport Adapter;
the flow layer sees only connection availability and streams
([canonical runtime seam](../protocol.md#7-smoltcp-and-runtime-adapters)).

**Wire and failure boundary.** `off` uses the single-path profile. Multipath
modes use the canonical `quicp/1-mp` profile token; the TLS backend encodes that
token as ALPN. Both endpoints require an exact token/transport-state match in
either direction before accepting an application flow.
This does not add an application frame or control stream. A lost path
keeps existing flows only while the same backend session has another usable
path; loss of the connection resets them
([canonical invariants](../protocol.md#6-multipath-over-faketcp)).

## Production admission gates

1. Pin the exact `noq` release/source graph and repeat the draft-21 comparison
   for every dependency update. Before shipping, compare the RFC Editor output
   and final IANA allocations against transport parameter, frame, nonce, and
   error-code handling
   ([draft status](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/21/),
   [draft IANA section](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-6)).
2. Prove two-source-address operation in Linux namespaces: packet-captured path
   0 and path 1 source IP/interface, server destination-address filtering,
   distinct four-tuples, two validated paths, per-path packet numbers starting
   at zero, per-path RTT/congestion statistics, and only one QUIC connection.
   Capture/qlog must show `0x3e`, the expected path frames, and path-aware AEAD.
3. Require interoperability with an independent implementation confirmed to
   match draft-21 or the final RFC. The inspected picoquic revision is not that
   proof while its public constants remain labeled draft-20
   ([picoquic source](https://github.com/private-octopus/picoquic/blob/467cb81bcafc652bae2a1c8824b70f12f470039c/picoquic/picoquic.h#L255-L260)).
4. Test NAT rebinding, address migration, path abandonment/reopen with a new ID,
   one-path blackhole, both-path blackhole, loss, reordering, unequal RTT, and
   unequal MTU. Verify no stream reset, byte replay, or duplicate origin action
   during a surviving-path handover; qlog must show both Backup status frames
   before application packets are scheduled on path 1
   ([draft implementation considerations](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-5)).
5. Test accepted and rejected 0-RTT. Early packets and `ACK`/`PATH_ACK` handling
   must remain on path 0; path 1 must not open before authenticated negotiation;
   either ALPN/transport mismatch must produce no DNS lookup, origin dial, or
   forwarded target byte
   ([draft 0-RTT rules](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-2.3),
   [QUICP replay gate](../protocol.md#5-quicp-security-profiles)).
6. Keep aggregate mode deferred until p99 latency, throughput, reordering
   memory, and fairness measurements show acceptable behavior under heterogeneous
   paths; neither draft-21 nor `noq` 1.1.1 provides a general aggregation scheduler
   ([draft scheduling guidance](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-5.5),
   [`noq` scheduler](https://github.com/n0-computer/noq/blob/noq-v1.1.1/noq-proto/src/connection/mod.rs#L7288-L7299)).
7. Bound maximum paths, simultaneous validation, lifetime path IDs, connection
   IDs, path events, and both internal driver queues. Start event draining before
   path creation; retain the path permit through `Discarded`; gate replacement
   grants by identity and rate, as draft-21 identifies per-path resource exhaustion
   and amplified denial-of-service as additional risks
   ([draft-21 Sections 7.1 and 7.2](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21#section-7.1)).
