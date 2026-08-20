# QUICP Protocol Foundations and Minimal Interface Proposal

Status: non-normative research notes. [`../protocol.md`](../protocol.md) is the
only canonical QUICP wire and runtime design; if this file conflicts with it, the
canonical document wins. QUICP is a custom protocol, not standard QUIC. Sections
that cite QUIC RFCs or `noq` describe prior art or a temporary backend adapter;
they do not define the QUICP wire format or require TLS. Sources were checked on
2026-08-09 and repository links are pinned to the inspected revisions.

## Decision

Build a TCP-compatible proxy, not a new general-purpose transport stack:

```text
local application
  -> kernel TCP -> TUN -> smoltcp TCP termination
  -> at most one active bidirectional QUICP flow per local TCP flow
  -> one QUICP session with one or two validated network paths
  -> gateway -> origin TCP
```

The selected public boundary is one process-shaped `load_config` plus
`run(Config, CancellationToken)` API. FakeDNS and its persistent FakeIP directory
stay inside the client configuration variant. TUN packet pumping, smoltcp
ownership, QUICP session reuse, stream framing, early-open fallback, flow backpressure,
and origin dialing all stay hidden.

This scope replaces TCP only on the client-to-gateway overlay leg. The local
application still sees TCP, and a gateway that talks to an ordinary origin still
uses TCP on the egress leg. Claiming end-to-end removal of TCP head-of-line (HOL)
blocking would therefore be false.

The design deliberately does not copy Tinect's fake-TCP carrier. In Tinect,
"fake TCP" means making datagrams look like TCP packets to middleboxes. In this
design, "Fake IP" means a DNS-created synthetic destination address used to
recover an authority before opening a QUICP flow. They solve different problems.

## Primary-source findings

### Tinect: useful seam, different protocol

The supplied Tinect repository returned `404` without GitHub authentication and
was cloned through the configured user credentials. Its links therefore require
repository access. All source links below are pinned to the inspected commit
`8f38c51f65d138f186fe72da3cf7e5c33b95e62d`.

- Tinect separates its composition/runtime layer, carrier and platform I/O
  boundaries, dataplane, and pure domain modules. This is a useful dependency
  direction to preserve, especially the rule that platform side effects stay at
  the platform boundary ([architecture, lines 3-12 and 31-40](https://github.com/ihciah/tinect/blob/8f38c51f65d138f186fe72da3cf7e5c33b95e62d/docs/architecture.md#L3-L40)).
- `tinect-fake-tcp` wraps one QUIC UDP datagram in a complete IPv4/IPv6 TCP-shaped
  packet. It intentionally does not implement TCP retransmission, congestion
  control, or flow control, so QUIC keeps those semantics
  ([crate README, lines 3-14](https://github.com/ihciah/tinect/blob/8f38c51f65d138f186fe72da3cf7e5c33b95e62d/crates/tinect-fake-tcp/README.md#L3-L14)).
- Tinect keeps that codec free of TUN/raw-socket/firewall side effects and places
  raw packet injection in its platform boundary
  ([architecture, lines 16-24](https://github.com/ihciah/tinect/blob/8f38c51f65d138f186fe72da3cf7e5c33b95e62d/docs/architecture.md#L16-L24)).
- Its high-leverage integration seam is Quinn's `AsyncUdpSocket`: the rest of the
  QUIC carrier sees a datagram socket while the implementation owns fake-TCP
  sessions and raw I/O
  ([adapter declaration, lines 1-18](https://github.com/ihciah/tinect/blob/8f38c51f65d138f186fe72da3cf7e5c33b95e62d/src/carrier/quicp.rs#L1-L18),
  [implementation, lines 421-485](https://github.com/ihciah/tinect/blob/8f38c51f65d138f186fe72da3cf7e5c33b95e62d/src/carrier/quicp.rs#L421-L485)).
- Tinect already composes Quinn with `TokioRuntime`
  ([underlay construction, lines 294-319](https://github.com/ihciah/tinect/blob/8f38c51f65d138f186fe72da3cf7e5c33b95e62d/src/carrier/underlay.rs#L294-L319))
  and pins Quinn with `runtime-tokio`
  ([Cargo dependencies, lines 28-44](https://github.com/ihciah/tinect/blob/8f38c51f65d138f186fe72da3cf7e5c33b95e62d/Cargo.toml#L28-L44)).
- The inspected Tinect revision is Apache-2.0
  ([package metadata](https://github.com/ihciah/tinect/blob/8f38c51f65d138f186fe72da3cf7e5c33b95e62d/Cargo.toml#L1-L6)).
  Reusing source would still require attribution and a dependency/security review;
  the proposed v1 only reuses the architectural idea.

Conclusion: keep Tinect's deep-adapter pattern, but do not claim wire
compatibility and do not use its fake-TCP terminology for Fake IP.

### QUIC prior art: ordering, HOL, and 0-RTT

The following facts describe standard QUIC only. QUICP borrows the useful
isolation goals but defines its own packet, stream, recovery, and early-open
formats; it does not inherit QUIC's TLS requirement.

- QUIC streams are ordered byte sequences and are individually flow controlled
  ([RFC 9000, Section 2](https://www.rfc-editor.org/rfc/rfc9000.html#section-2)).
- A receiver must buffer out-of-order bytes to deliver an ordered stream, and
  frame boundaries are not preserved. Consequently, a lost range still blocks
  later delivery on that same stream
  ([RFC 9000, Section 2.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-2.2)).
- HTTP/3 demonstrates the intended multiplexing model: one request-response pair
  per QUIC stream, with a blocked or lossy stream not preventing progress on
  other streams
  ([RFC 9114, Section 2](https://www.rfc-editor.org/rfc/rfc9114.html#section-2)).
- QUIC 0-RTT requires a previous connection, remembered transport/application
  state, and a TLS session ticket. A server may reject it; after rejection the
  client must reset early streams and their bound application state
  ([RFC 9001, Sections 4.6-4.6.3](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.6)).
- 0-RTT data can be replayed and is unsuitable for instructions with unwanted
  replay effects
  ([RFC 9001, Section 2.1](https://www.rfc-editor.org/rfc/rfc9001.html#section-2.1),
  [Section 9.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-9.2)).
- HTTP/3 binds 0-RTT acceptance to remembered settings compatibility and rejects
  early data when the server cannot prove compatibility
  ([RFC 9114, Section 7.2.8](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8)).
  HTTP/3 also explicitly applies anti-replay rules to early stream contents
  ([RFC 9114, Section 10.9](https://www.rfc-editor.org/rfc/rfc9114.html#section-10.9)).

Therefore, QUICP v1 can remove cross-flow transport HOL by assigning one TCP flow
to one QUICP flow. It cannot remove same-flow HOL while preserving TCP's ordered
byte semantics. Splitting one byte stream over several QUICP flows would merely
move the required reordering and HOL wait into this protocol.

### smoltcp and Tokio integration facts

- smoltcp describes itself as a standalone, event-driven TCP/IP stack
  ([README, lines 9-18](https://github.com/smoltcp-rs/smoltcp/blob/5393f8853a9e0bee86fb9d66f1b864fb2dcbc71d/README.md#L9-L18))
  and lists TCP support for IPv4 and IPv6
  ([README, lines 118-139](https://github.com/smoltcp-rs/smoltcp/blob/5393f8853a9e0bee86fb9d66f1b864fb2dcbc71d/README.md#L118-L139)).
- Its physical seam is `phy::Device`, which yields receive/transmit tokens for
  raw frames
  ([Device API, lines 346-410](https://github.com/smoltcp-rs/smoltcp/blob/5393f8853a9e0bee86fb9d66f1b864fb2dcbc71d/src/phy/mod.rs#L346-L410)).
- `Interface::poll` drives ingress, maintenance, and egress, but can perform an
  unbounded amount of work if ingress never drains. The source provides bounded
  `poll_ingress_single`, `poll_maintenance`, and `poll_egress` operations for an
  event loop that must remain fair
  ([poll API and warning, lines 449-562](https://github.com/smoltcp-rs/smoltcp/blob/5393f8853a9e0bee86fb9d66f1b864fb2dcbc71d/src/iface/interface/mod.rs#L449-L562)).
- `poll_at`/`poll_delay` expose the next soft timer deadline
  ([timer API, lines 574-629](https://github.com/smoltcp-rs/smoltcp/blob/5393f8853a9e0bee86fb9d66f1b864fb2dcbc71d/src/iface/interface/mod.rs#L574-L629)).
- With the `async` feature, a TCP socket can register one receive and one send
  waker. Each is one-shot, can be overwritten, and admits spurious wakes; this is
  a wake seam, not a Tokio executor
  ([TCP waker API, lines 693-725](https://github.com/smoltcp-rs/smoltcp/blob/5393f8853a9e0bee86fb9d66f1b864fb2dcbc71d/src/socket/tcp.rs#L693-L725)).
- Tokio's `AsyncFd` can attach a nonblocking Unix file descriptor to the reactor.
  Its contract requires retrying after readiness and clearing readiness only on
  `WouldBlock`
  ([Tokio `AsyncFd`](https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFd.html)).

If a custom adapter is required, one Tokio task must own `Interface`, `Device`,
and `SocketSet`. It waits on TUN readiness, the smoltcp timer deadline, and
bounded flow commands; it processes a bounded ingress batch, runs egress, then
yields. Per-flow tasks never lock or mutate smoltcp directly. This ownership
locality avoids an `Arc<Mutex<SocketSet>>` hot path and respects the one-waker
contract.

### Existing Tokio/smoltcp adapters

#### `netstack-smoltcp` 0.2.4: prototype-only

The inspected v0.2.4 tag is commit `f29f90b`, dated 2026-07-11
([tag commit](https://github.com/cavivie/netstack-smoltcp/commit/f29f90b841ac508397dbf280787c8de4686d4da4)).
It is the shortest prototype path because its stated purpose is
to turn packets from/to a TUN into TCP streams and UDP packets
([package metadata, lines 1-16](https://github.com/cavivie/netstack-smoltcp/blob/f29f90b841ac508397dbf280787c8de4686d4da4/Cargo.toml#L1-L16)).
Its listener yields a Tokio `AsyncRead`/`AsyncWrite` `TcpStream` together with the
local and remote addresses, exactly the transparent-flow shape this design needs
([listener and stream, lines 374-485](https://github.com/cavivie/netstack-smoltcp/blob/f29f90b841ac508397dbf280787c8de4686d4da4/src/tcp.rs#L374-L485),
[Tokio I/O implementations, lines 485-553](https://github.com/cavivie/netstack-smoltcp/blob/f29f90b841ac508397dbf280787c8de4686d4da4/src/tcp.rs#L485-L553)).

It is not admitted to production as inspected:

- `BoxFuture` erases a future without a `Send` bound, then uses
  `unsafe impl<T: Send> Send`; `T: Send` does not prove that the captured future
  state is safe to move across threads
  ([runner, lines 7-41](https://github.com/cavivie/netstack-smoltcp/blob/f29f90b841ac508397dbf280787c8de4686d4da4/src/runner.rs#L7-L41)).
- The virtual device ingress and TCP socket/accepted-stream paths use unbounded
  channels
  ([device, lines 10-37](https://github.com/cavivie/netstack-smoltcp/blob/f29f90b841ac508397dbf280787c8de4686d4da4/src/device.rs#L10-L37),
  [TCP runner, lines 62-99](https://github.com/cavivie/netstack-smoltcp/blob/f29f90b841ac508397dbf280787c8de4686d4da4/src/tcp.rs#L62-L99),
  [accepted stream queue, lines 374-404](https://github.com/cavivie/netstack-smoltcp/blob/f29f90b841ac508397dbf280787c8de4686d4da4/src/tcp.rs#L374-L404)).
- The listener creates and publishes a flow for a raw SYN before smoltcp reaches
  `Established`; it has no four-tuple SYN-retransmission deduplication and no
  public active-RST operation. Normal retransmissions can therefore create
  duplicate or ghost QUICP flow attempts.

Production admission requires either an upstream release or a reviewed patch
that removes the unsafe `Send` assertion, makes every externally driven queue
bounded, deduplicates SYNs, publishes only established flows, exposes clean EOF
versus active reset, demonstrates backpressure under overload, and passes
Miri/sanitizer, loss/reorder, and sustained-memory tests. Until then, the adapter
may be used only behind the hidden netstack seam in a prototype build.

#### `tokio-smoltcp` 0.6.0: safer base, wrong ingress shape

The 0.6.0 release uses smoltcp 0.13 and exposes Tokio-oriented TCP APIs
([release Cargo metadata and dependencies](https://github.com/spacemeowx2/tokio-smoltcp/blob/e4ea2a4412146b825d94e234db49e477237a11e4/Cargo.toml#L1-L32)).
The inspected source tree has no equivalent unsafe boxed-future `Send`
assertion. However, its public model is conventional explicit `tcp_bind(addr)`
and `tcp_connect(addr)`
([API, lines 148-195](https://github.com/spacemeowx2/tokio-smoltcp/blob/e4ea2a4412146b825d94e234db49e477237a11e4/src/lib.rs#L148-L195));
its listener creates one smoltcp socket listening on the supplied endpoint
([listener, lines 17-70](https://github.com/spacemeowx2/tokio-smoltcp/blob/e4ea2a4412146b825d94e234db49e477237a11e4/src/socket.rs#L17-L70)).
It does not directly expose a transparent listener that accepts SYNs for
arbitrary Fake IP destination addresses and ports.

Conclusion: use `netstack-smoltcp` only to validate the protocol quickly. For a
production implementation, either admit a corrected release of it or add the
smallest transparent-ingress adapter on top of `tokio-smoltcp`/smoltcp. The
public protocol interface does not change either way.

### Temporary backend candidates

This section records why the prototype currently embeds a standard QUIC engine;
it is an implementation choice to be removed from the no-security QUICP core,
not a protocol requirement.

Upstream Quinn established the smallest single-path baseline because Tinect
already exercises its Tokio integration and Quinn directly exposes the required
stream and 0-RTT capabilities:

- Its `runtime-tokio` feature enables Tokio time, runtime, and networking support
  ([Quinn features](https://github.com/quinn-rs/quinn/blob/acfec5f04cd9e3923bc3b5c47b5d7667bee1e5ee/quinn/Cargo.toml#L15-L39)).
- `Connection::open_bi` and `accept_bi` provide the one-flow/one-stream mapping;
  an opened stream is not visible to the peer until data is written, so the
  `OPEN` header must be written immediately
  ([stream API, lines 290-351](https://github.com/quinn-rs/quinn/blob/acfec5f04cd9e3923bc3b5c47b5d7667bee1e5ee/quinn/src/connection.rs#L290-L351)).
- `Connecting::into_0rtt` can make a resumed connection usable before handshake
  completion, but the peer can still reject early streams and the caller must
  detect and retransmit rejected data
  ([0-RTT API, lines 89-134](https://github.com/quinn-rs/quinn/blob/acfec5f04cd9e3923bc3b5c47b5d7667bee1e5ee/quinn/src/connection.rs#L89-L134)).
- The server does not use incoming `Connecting::into_0rtt`, whose documentation
  warns that server 0.5-RTT data can precede client authentication. It awaits
  ordinary `Connecting` completion before accepting streams, so Quinn 0.11's
  public API supplies the authentication gate without relying on an unreleased
  `Connection::authenticated()` method
  ([Quinn 0.11.11 source, lines 107-123 and 199-216](https://github.com/quinn-rs/quinn/blob/quinn-0.11.11/quinn/src/connection.rs#L107-L216)).
- Quinn documents that worst-case receive memory is proportional to concurrent
  streams and the per-stream window, and that a smaller stream window prevents
  one unread stream from monopolizing connection buffers
  ([transport limits, lines 62-115](https://github.com/quinn-rs/quinn/blob/acfec5f04cd9e3923bc3b5c47b5d7667bee1e5ee/quinn-proto/src/config/transport.rs#L62-L115)).

Upstream Quinn still has no released native multipath API
([tracking issue](https://github.com/quinn-rs/quinn/issues/224)). The canonical
one- or two-path baseline is therefore [`noq` 1.1.1](https://crates.io/crates/noq/1.1.1),
a maintained Quinn fork with `runtime-tokio`, draft-21 path state, bounded path
events, per-path statistics, and `open_path(FourTuple, PathStatus)` including an
explicit local source IP for additional paths
([connection API](https://docs.rs/noq/latest/noq/struct.Connection.html),
[transport API](https://docs.rs/noq/latest/noq/struct.TransportConfig.html)). The
same dependency handles single-path and multipath operation. Every production
build uses a pinned fork that bounds its two internal unbounded driver channels;
`failover` also exposes the proto-level path-limit replenishment operation and
fixes initial Backup status propagation. A concrete wildcard
UDP adapter supplies candidate 0's source and filters server destination
addresses. If the core transport passes but multipath-specific admission fails,
ship single-path mode only. Detailed evidence and patch boundaries are in
[`multipath-quic.md`](multipath-quic.md).

## Canonical FakeIP and public boundary decision

An earlier alternative put a reusable FakeIP allocator behind a public callback
and exposed separate `run_client`/`run_server` functions. It was rejected: v1 has
one Linux client, no FakeIP reuse, and no second allocator implementation to
justify that seam.

The canonical module owns FakeDNS, the persistent bidirectional mapping, TUN and
route lifecycle, and smoltcp. It exposes only:

```rust
pub fn load_config(path: &std::path::Path) -> Result<Config, ConfigError>;

pub async fn run(
    config: Config,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), RunError>;
```

`Config` is tagged as client or server. Each established local flow looks up its
destination FakeIP exactly once before opening QUICP and retains the resulting
canonical hostname. A missing or corrupt mapping fails closed. Mappings are
persisted before DNS answers and are never reassigned in v1; leases and reuse
tests therefore do not exist. The gateway still resolves and authorizes every
concrete egress address independently.

## Hidden implementation and adapter locality

| Category | Hidden adapter/seam | Local responsibility |
| --- | --- | --- |
| Fake IP | Internal persisted directory | One lookup per established flow, canonical hostname validation, no v1 reuse |
| Platform I/O | TUN adapter | Create/configure TUN, packet read/write, cleanup; no protocol decisions |
| Local TCP | `netstack-smoltcp` prototype adapter or admitted smoltcp adapter | Turn IP packets into async TCP flows; own all smoltcp state in one locality |
| Async runtime | Tokio | Readiness, timers, bounded channels, task supervision, shutdown |
| QUICP backend | Current `noq` adapter (temporary) | One long-lived session per gateway, bounded driver events, source/destination enforcement, one or two concurrent validated paths, at most one active flow per local flow; TLS is adapter-only |
| Gateway egress | Tokio TCP/DNS adapter | Revalidate ACL, resolve recovered authority, connect with timeout, proxy bytes |
| Wire codec | Private functions | Bounded `OPEN` and status parsing; no general serialization framework |

No internal adapter is exposed as a public trait. Tests can exercise hidden
adapters with smoltcp's in-memory device and an in-process `noq` endpoint. A
second implementation is added only when a real platform or production-admission
need appears.

## Wire protocol v1

Use profile tokens `quicp/1` for the single-path profile and `quicp/1-mp` when
multipath is required. After the selected security/policy gate and before flow
acceptance, both endpoints enforce `quicp/1 => no multipath` and
`quicp/1-mp => multipath`. Both use the same application bytes. A QUICP session
carries no shared application control flow. Every flow attempt opens one
client-initiated bidirectional QUICP flow and writes one bounded `OPEN`; a
rejected early-open attempt may be replaced once, but at most one attempt is
active. Accepted flows then carry raw ordered bytes.

```text
OPEN (client -> gateway, first bytes of flow)
  host_length:u8 = 1..253
  host:bytes[host_length]
  port:u16
  client byte stream begins only after STATUS(ok)

STATUS (gateway -> client, first byte of reverse direction)
  code:u8 = 0(ok) | 1(general) | 2(policy) | 3(resolve)
          | 4(refused) | 5(timeout) | 6(capacity)
  followed by server byte stream only when code = 0
```

The profile token is the version. `host` is a lowercase ASCII, IDNA2008-canonical,
dot-separated DNS name with labels of `1..=63` bytes and no trailing dot. V1 has
no literal-IP target form. Port zero, truncated input, and oversized or
non-canonical names are stream protocol errors and use `FLOW_PROTOCOL = 0x100`
rather than a status. Error details are logged locally rather than sent to an
untrusted peer. No chunk framing follows `OPEN`: the QUICP flow itself supplies
the reliable ordered byte stream, so another reliability or record layer would add
code without leverage.

Ordering and lifecycle invariants:

1. The client writes `OPEN`, waits for `STATUS(ok)`, and only then drains local
   application bytes into QUICP.
2. The gateway parses and authorizes `OPEN` before resolving or dialing.
3. The gateway writes `STATUS(ok)` only after the origin connection succeeds.
4. Neither side delivers reverse-direction payload before `STATUS(ok)`.
5. Local TCP FIN maps to QUICP flow finish; QUICP FIN maps to origin/local TCP
   half-close. A locally detected generic abort performs TCP RST plus both flow
   reset directions. A received `FLOW_PROTOCOL`, `FLOW_ABORT`, or `FLOW_REJECTED`
   code is mirrored unchanged onto the other direction; an unknown code maps to
   `FLOW_PROTOCOL`.
6. QUICP session loss aborts all attached local flows. V1 does not pretend to
   resume byte streams on a new connection because that would require a second
   delivery acknowledgment and replay protocol above QUICP.
7. All queues, socket buffers, flow counts, parsers, and early-data buffers are
   bounded. Backpressure propagates from QUICP to smoltcp by stopping local reads,
   which closes the local TCP receive window instead of dropping bytes.

There is no separate unreliable datagram API in v1. Rebuilding reliable ordered
delivery above an unreliable mode would duplicate the core flow machinery and
create a larger, shallower module.

## HOL statement, without overclaiming

| Scope | Result |
| --- | --- |
| Separate QUICP sessions | No protocol ordering dependency; they can still contend for the same physical bottleneck. |
| Different flows on one QUICP session | No byte-order HOL between flows. Loss on flow A does not require flow B to wait for A's missing offset. |
| One QUICP flow | Ordered delivery remains; a missing range blocks later bytes on that flow. |
| QUICP session resources | Congestion control, session flow control, CPU, and socket buffers are shared. This is shared-resource coupling, not byte-order HOL. |
| Local and origin TCP legs | Each TCP flow retains normal TCP ordering/HOL. |

V1 uses one QUICP session per gateway because it amortizes setup and gives the
one-active-flow-per-local-flow mapping maximum leverage. That session has one
path in `off` mode or two QUICP paths in `failover`; an independent session pool
is deferred.

## Early-open and replay boundary

Early-open is a QUICP feature, not standard QUIC 0-RTT. It is attempted only
when the configured peer/policy admission state is compatible with the selected
`quicp/1` or `quicp/1-mp` profile. A cold session performs the normal bounded
setup. The cached state binds the profile token, header limits, security mode,
and authorization-policy epoch; incompatibility rejects early data.
`safe-open-only` is explicit opt-in and remains off until its admission checks
pass.

The current implementation keeps transport 0-RTT disabled on both peers because
the server admission path cannot yet prove that buffered early bytes contain
exactly one bounded `OPEN` header. The policy and cache remain fail-closed
preparation, not an enabled capability.

When the optional TLS adapter is used, its resumption ticket and peer
fingerprint are inputs to this policy. In the no-security profile, the caller
must provide an equivalent explicit peer admission record. Missing or stale
metadata clears cached state, so an untrusted identity receives no target
hostname in early data.

The replay boundary is exact:

- Replayable: only the bounded `OPEN` header written before the transport's
  authentication gate completes. Application payload stays in smoltcp.
- Allowed before the gate: only bounded transport buffering on path 0. Additional
  multipath paths and path frames are available only after session admission.
  Application code does not accept or parse a flow until the admission step
  completes.
- Forbidden before the gate: external DNS queries, origin TCP connect, origin
  writes, quota/accounting commits, or any other externally visible/non-idempotent
  effect.
- Commit point: only after the server admission step succeeds may the gateway
  accept and parse a flow, resolve, connect, write, and return `STATUS(ok)`.
- Rejection: the client discards the rejected attempt, opens a fresh ordinary
  flow, and retransmits only `OPEN` exactly once, but only after a successful,
  still-open session explicitly rejected early data. Ambiguous outcomes abort.
  At most one attempt is active; accepted flows and application bytes are never
  replayed.
- Capacity: when the server early-header budget is full, stop reading and apply
  backpressure. Never read generic TCP payload before `STATUS(ok)` and never
  switch to an unbounded queue.

This exercises QUICP early-open without performing replayable upstream actions.
Because the gateway waits for admission, it does not accelerate origin
establishment versus an ordinary admitted session. If a future requirement
demands origin connect/write before authentication, it needs an explicit
idempotency contract plus durable, deployment-wide anti-replay; that is outside
v1. After authentication, the server re-checks the resumed client certificate
fingerprint, expiry, allowlist, and policy epoch when TLS/PSK is enabled; the
no-security profile re-checks its configured peer policy. Authorization changes
rotate or flush cached state.

## Errors and failure locality

| Failure | Local behavior | Connection impact |
| --- | --- | --- |
| Missing/expired Fake IP mapping | Local TCP RST; no QUICP flow | None |
| Policy, resolution, connect, or capacity rejection | Gateway status; client aborts local flow | None |
| Malformed/oversized `OPEN` | Reset offending flow and count violation | None |
| Header or status deadline | Abort both flow directions and release all flow permits | None |
| Early-open rejection | Internal one-time ordinary retry of `OPEN` only | None if retry succeeds |
| One multipath path fails | Continue the same flows on another validated path | None while the session survives |
| QUICP security/protocol failure | Abort all attached flows | Close session |
| TUN/smoltcp owner task failure | Return fatal `Platform` error | Client daemon stops and cleans up |
| Origin half-close | Preserve half-close mapping | One flow only |

## Performance and resource invariants

- The end-to-end backpressure chain is origin/QUICP send capacity -> bounded flow
  buffer -> stop reading smoltcp -> local TCP window. The reverse direction is
  symmetric.
- Patched backend flow count, receive windows, path count, path-event queues, and
  capacity-256 internal driver channels are explicit budgets. Worst-case receive
  memory grows with `max_concurrent_bidi_flows * flow_receive_window` and is capped
  again by the session receive window.
- Each validating, active, closing, or not-yet-discarded path holds a named
  reservation for recovery, congestion, MTU, connection-ID, and event state.
- smoltcp socket receive/send buffers, max flows, early-header bytes, DNS and
  connect concurrency, and TUN ingress batches are configuration limits with
  validated ceilings. They are calibration knobs, not extension interfaces.
- The custom smoltcp loop, if needed, uses bounded ingress batches and yields;
  calling `Interface::poll` against an indefinitely nonempty device can starve
  the Tokio executor.
- No unbounded MPSC channel is allowed in the production path. This keeps
  `netstack-smoltcp` 0.2.4 prototype-only and requires the documented `noq`
  driver-channel patch.
- One `OPEN` header and one status byte are the only application-protocol overhead
  per flow. Stream payload has no per-chunk envelope.
- Expect extra copies and CPU versus kernel TCP because TUN, smoltcp, and the
  current backend all touch bytes. Optimize only after profiling; the first
  admission benchmark must
  measure throughput, p99 latency, CPU, allocations, and memory under loss and
  thousands of concurrent flows.

## Trade-offs and deferred work

- Kept: TCP socket compatibility, per-flow ordering, half-close, bounded
  backpressure, cross-flow HOL isolation, safe early-open transport, and
  gateway egress authorization.
- Accepted: same-flow HOL, shared QUICP session fate, possible reordering from
  heterogeneous active paths, userspace netstack copies, and TCP HOL on the
  ordinary origin leg.
- Deferred: transparent flow resumption after QUICP session loss, UDP proxying,
  automatic path discovery, simultaneous capacity aggregation, more than two
  concurrent/retained paths, custom scheduling, connection
  pooling, server-initiated flows, a TCP fallback, and
  Tinect-style fake-TCP underlay. Add one only after a concrete requirement and
  measurement justifies its protocol state.

## Admission checks

1. With loss injected only into flow A's stream data, flow B must continue while
   A waits; A must still deliver bytes in order.
2. Replaying an early `OPEN` must create zero DNS queries, origin connections, or
   writes before the admission gate; early-open rejection must produce one ordinary
   retry and no duplicated origin bytes.
3. FakeIP tests must prove persist-before-answer, stable no-reuse mappings,
   single-writer enforcement, torn-tail recovery, checksum validation, and
   fail-closed missing mappings.
4. Flow/data-queue saturation must close TCP windows or return `busy`; internal
   driver-channel saturation must close the affected connection or endpoint
   fail-closed. Both cases must keep memory flat over a sustained test.
5. Dropping either half must preserve FIN versus RST semantics and release every
   flow/socket/stream budget.
6. `netstack-smoltcp` cannot pass production admission until its unsafe `Send`
   assertion and unbounded channels are removed or replaced by a reviewed release.
7. Optional TLS/PSK verification, profile-token binding, egress ACLs, and
   incompatible-settings early-open rejection are fail-closed integration tests,
   not part of the no-security baseline.
8. A dual-underlay packet-capture test must prove both actual source/interface
   choices and preserve the same session, flow, byte order, and origin
   socket when path 0 fails within the deadline; losing both paths resets the flow.
9. Multipath admission requires server destination filtering, exact profile-token/
   transport matching, bounded path and driver-event behavior, bounded replacement
   grants/path IDs, and path-0-only early-open.
