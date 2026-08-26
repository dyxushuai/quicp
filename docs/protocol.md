# QUICP/1: a custom multiplexed transport over a datagram-preserving FakeTCP carrier

Status: portable core profile (platform carrier adapters are deployment-gated)

This is the normative implementation document for the current `QUICP/1` profile. The repository
README is an integration overview; implementers should start with this document, then use the
reference source map and conformance checklist below. A change to any wire value, profile token,
or state transition requires a new profile token or protocol version.

## 1. Scope

QUICP is a private, QUIC-inspired multiplexed transport. It is not the IETF QUIC wire protocol,
does not promise QUIC interoperability, and does not require TLS. Its baseline carries QUICP
packets through TCP-shaped IP packets so an underlay that treats UDP as a separate, low-priority
class sees a normal-looking TCP flow. The transport core does not require TUN, FakeIP, DNS, or a
VPN; those are optional platform integrations. The carrier is not a TCP stream:

```text
host-owned input -> QUICP packet -> carrier packet

optional transparent integration:
application/TUN -> smoltcp -> QUICP packet -> raw IPv4/IPv6 TCP packet
```

## 0. Carrier tiers and deployment goal

The primary deployment goal is a **Tier 0 wire FakeTCP carrier**: the ISP-facing interface MUST
emit and receive TCP-shaped IP packets carrying QUICP datagrams. Tier 0 is the only profile that may
claim ISP-level FakeTCP camouflage. It requires exact packet injection, tuple filtering, source-path
selection, and narrowly scoped kernel-RST suppression; a platform that cannot prove those properties
MUST reject the profile rather than silently fall back to UDP or an ordered TCP stream.

Tier 1 TUN/TAP and Tier 2 Apple/Android packet bridges are integration layers, not replacements for
the wire carrier. They provide virtual packet ingress/egress for smoltcp, transparent adapters, or a
remote Tier 0 gateway. Their packets are not ISP-visible FakeTCP unless the complete deployment has a
separately verified physical packet path.

The protocol core is shared across tiers; packet I/O, privileges, RST suppression, and batching are
platform-specific. Linux and macOS have explicit Unix raw IPv4 adapters. Windows uses the
WinDivert signed WFP/WDF packet adapter. Linux `AF_PACKET`/`TPACKET_V2` is an optional performance
path, not a different wire protocol; macOS remains probe-only until packet capture and narrowly
scoped RST-suppression evidence is complete. Other targets fail closed instead of inheriting a
different platform implementation.

There is no UDP header inside the TCP packet and no ordered FakeTCP byte stream around QUICP. Every
carrier payload is exactly one QUICP datagram (which may contain coalesced QUIC packets). A missing
carrier sequence number does not block a later datagram; QUICP owns packet numbers, loss recovery,
congestion control, stream ordering, and retransmission. Putting QUICP in a reliable FakeTCP stream
would recreate transport head-of-line blocking and is explicitly forbidden.

The QUICP core defaults to no encryption. An authenticated security adapter may be selected above
the packet engine, but the no-security profile is the performance and protocol baseline. The
current adapter is mutual TLS; PSK is not implemented or admitted. Rust callers may additionally
install a `QuicpHeaderProtection` factory through
`TransportOptions`; this protects only the backend QUICP packet-header bits and leaves the
FakeTCP/IP headers and QUICP payload unchanged. It is not an authenticity boundary. The current
`noq`/rustls integration is a temporary backend adapter and must not be mistaken for the QUICP
wire contract.

This is an evasion-oriented transport experiment, not a claim of indistinguishability or of
guaranteed ISP acceptance. A deployment must test real NATs, middleboxes, reset injection, packet
capture, and the target ISP before enabling it.

## 1.1 Normative language and implementation boundary

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative. A conforming
implementation has three independently testable layers:

| Layer | Contract | Owner of loss and ordering |
| --- | --- | --- |
| QUICP packet engine | QUIC v1 packet grammar, packet-number spaces, flow control, recovery, and streams; the current reference backend is vendored `noq` | QUICP/QUIC engine |
| FakeTCP carrier | One raw IPv4/IPv6 TCP-shaped packet per QUICP datagram; no byte-stream reassembly | QUICP packet engine, not the carrier |
| Flow protocol | Client-initiated bidirectional stream with `OPEN` followed by one-byte `STATUS` | Each independent QUICP stream |

The carrier MUST NOT buffer, reorder, retransmit, or wait for a missing carrier sequence number.
The QUICP packet engine MUST treat each carrier payload as an independent datagram and perform its
own duplicate detection, loss recovery, and stream ordering. An implementation that inserts the
packet engine into a reliable FakeTCP byte stream is not `QUICP/1`.

The reference source map is deliberately small:

- `src/faketcp.rs` defines the portable raw-carrier fields, checksums, flags, options, and
  sequence rules; `src/faketcp/unix.rs` contains the Unix/Tokio socket adapter.
- `src/no_security.rs` defines the no-TLS `QPCS` handshake and plaintext packet-key behavior.
- `src/session.rs` defines profile-token admission and application error codes.
- `src/wire.rs` defines the `OPEN` request and `STATUS` values.
- `src/multipath.rs` defines the bounded primary/backup path policy.

The QUIC packet grammar and transport-parameter varints follow the QUIC v1 base documents
([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) and
[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)) as implemented by `vendor/noq-proto`.
QUICP changes the security handshake, profile admission, carrier, and flow contract; it does not
claim interoperability with a general-purpose QUIC endpoint.

## 1.2 Version and profile selection

The profile token is an exact byte string and is selected before application flows are accepted:

| Token | Security negotiation | Multipath | Application 0-RTT |
| --- | --- | --- | --- |
| `quicp/1` | no-TLS `QPCS` or TLS 1.3 ALPN | disabled | MUST NOT be accepted |
| `quicp/1-mp` | no-TLS `QPCS` or TLS 1.3 ALPN | primary plus one backup | MUST NOT be accepted |

The client selects one token. The server may advertise both in TLS, but it MUST reject a token and
transport-parameter combination that does not match its selected mode. Unknown tokens are a
protocol error; they are not silently downgraded to `quicp/1`.

For no-TLS, the QUICP handshake bytes carried in QUIC CRYPTO frames are:

```text
offset  size  field
0       4     magic = ASCII "QPCS"
4       1     kind: 1 CLIENT_HELLO, 2 SERVER_HELLO, 3 CLIENT_CONFIRM
5       1     profile_token_length, 1..=32
6       2     transport_parameters_length, unsigned big-endian
8       N     profile token bytes
8+N     M     QUIC transport-parameter bytes
```

The message length is exactly `8 + N + M`; trailing bytes are a protocol error. The state machine
is `CLIENT_HELLO -> SERVER_HELLO -> CLIENT_CONFIRM`. A client MUST NOT open a flow before it has
received and validated `SERVER_HELLO`; a server MUST NOT admit a flow before it has validated
`CLIENT_CONFIRM`. The no-TLS profile has no AEAD tag, no payload encryption, and no early-data
keys. A custom header protector, when both peers configure the same one, changes only backend
header bits and is not a standardized interoperability profile.

## 2. FakeTCP packet format

`FakeTcpPacket` emits a complete raw IPv4 or IPv6 packet with:

- TCP protocol number 6, valid IP and TCP checksums, and no fragmentation;
- source/destination addresses and ports from one fixed four-tuple;
- a stable per-path sequence space, ACK/window fields, and TCP flags;
- SYN options for MSS, SACK-permitted, window scale, and an optional TFO-style cookie;
- a payload containing exactly one QUICP datagram.

### 2.1 IP envelope

The reference encoder emits no IP fragmentation and no IPv6 extension headers. All multi-byte
fields are network byte order.

| Field | IPv4 | IPv6 |
| --- | --- | --- |
| Version/header | `0x45` (20-byte header) | version 6 (40-byte header) |
| Total/payload length | IPv4 total length equals the complete packet length | IPv6 payload length equals TCP header plus options plus payload |
| Next protocol | `6` (TCP) | `6` (TCP) |
| Fragmentation | flags `DF`, offset `0` | no extension-header fragmentation |
| Lifetime | TTL `64` | hop limit `64` |
| Address family | source and destination are IPv4 | source and destination are IPv6 |

Receivers MUST verify the IP length, protocol, address family, checksum (IPv4), and TCP checksum
before inspecting QUICP bytes. A malformed packet is dropped without changing carrier or QUICP
state.

### 2.2 TCP-shaped envelope

The 20-byte TCP base header is followed by zero or more options, padded to a 32-bit boundary, and
then the QUICP datagram. The reference values are:

| Field | `SYN` packet | ordinary packet |
| --- | --- | --- |
| source/destination port | fixed four-tuple | same four-tuple |
| sequence | carrier send sequence | carrier send sequence |
| acknowledgment | highest accepted carrier sequence plus consumed length | same monotonic ACK |
| flags | client `SYN`, server `SYN|ACK` | `ACK|PSH` |
| window | `65535` | `65535` |
| urgent pointer | `0` | `0` |
| checksum | TCP pseudo-header checksum | TCP pseudo-header checksum |

`SYN` options are, in order, an MSS advertisement, SACK-permitted, window scale `7`, optional TCP
Fast Open option kind `34` carrying the tuple-bound 16-byte cookie, and NOP padding. The default
outer IP MTU is 1500 bytes, so automatic MSS is 1460 for IPv4 and 1440 for IPv6 (`outer MTU - IP
header - TCP header`). `MtuConfig::mss` may select a validated fixed MSS; the value is a carrier
hint only and never becomes QUICP stream flow control. Ordinary packets have no options in the
reference encoder. A receiver MAY parse additional well-formed TCP options, but MUST ignore
unknown options and MUST preserve the QUICP payload boundary.

`MtuConfig` uses explicit units: `outer_ip_mtu` is the complete raw IP packet limit, while
`initial_quic_payload`, `min_quic_payload`, `max_quic_payload`, and `pmtu_upper_bound` are QUICP
datagram payload limits. Raw FakeTCP intersects the payload limit with the address-family header
overhead and rejects an encoded packet that exceeds `outer_ip_mtu`; it never fragments a datagram.
Host datagram carriers intersect their own adapter MTU. `PmtuMode::Auto` lets the carrier
capability decide whether backend discovery runs, `Disabled` keeps the static ceiling, and
`Required` rejects a carrier that may fragment.

At the largest representable outer MTU (`65535` bytes), the raw payload ceiling is `65495` bytes
for IPv4 and `65475` bytes for IPv6, before any backend-specific maximum. The sender MUST reject a
larger datagram rather than fragment it. The carrier payload is opaque: it is not length-prefixed,
encrypted, or wrapped in UDP.

The first data packet is `SYN` (or server `SYN|ACK`) and may carry a QUICP datagram. Subsequent
packets use `ACK|PSH`. The current carrier does not attempt to implement kernel TCP congestion
control, stream reassembly, or MPTCP DSS. It only supplies TCP-shaped metadata and a per-path
sequence bookkeeping; QUICP remains the authenticated protocol state machine and owns duplicate
detection.

The sender chooses a fresh random initial sequence (mixed with the tuple checksum) for every
carrier state. `noq` may batch up to eight equal-MTU datagrams; the FakeTCP adapter expands those
segments into independent TCP-shaped packets and, on Linux, submits the batch with `sendmmsg`
when there is more than one packet; a single packet uses the bound socket's direct `send` path.
The adapter retains its segment cursor across readiness polls. Sequence state is advanced when a
segment is encoded, and the encoded batch remains owned until the OS accepts every packet. A
changed four-tuple always creates a new carrier state; sequence state is never shared
between paths. Sequence numbers wrap with TCP serial arithmetic; QUICP packet numbers and replay
state remain independent of this carrier counter.

For each direction, the carrier consumes one sequence number for `SYN` and one sequence number per
payload byte for all packets. An ordinary packet therefore advances `seq` by `payload_length`; a
SYN packet advances it by `1 + payload_length`. The receiver returns the monotonic serial-arithmetic
ACK `seq + consumed`. These counters are local to a four-tuple and direction. They MUST NOT be
used as QUICP packet numbers, replay windows, or application acknowledgments.

## 3. Per-datagram payload

The carrier adds no encryption, authentication tag, length prefix, or padding. The payload is the
QUICP datagram itself; optional no-TLS header protection runs inside the backend packet codec and
does not alter this framing:

```text
[QUICP datagram]
```

### 3.1 QUICP datagram boundary

The bytes above are the QUIC backend datagram. A datagram MAY contain one or more coalesced QUIC
packets according to the QUIC v1 packet grammar; the FakeTCP carrier treats the entire datagram as
one opaque payload and never splits or joins it. A receiver MUST pass the complete payload to its
QUIC packet decoder and MUST NOT feed a partial carrier payload into the decoder.

The reference transport profile uses these advertised limits and defaults:

| Parameter | Value |
| --- | ---: |
| QUIC version | `1` |
| maximum QUIC datagram payload | `65527` bytes, then bounded by `MtuConfig` and the carrier MTU |
| connection send/receive window | `8 MiB` |
| stream receive window | `128 KiB` |
| locally initiated bidirectional streams | `128` |
| unidirectional streams | `0` |
| QUIC DATAGRAM send/receive | disabled |
| ack-eliciting threshold | `10` packets |
| maximum ACK delay | `1 ms` |
| connection idle timeout | `60 s` |
| path keep-alive interval | `5 s` |
| path idle timeout | `15 s` |
| per-flow write buffer | `32 KiB` (maximum `16 MiB`) |
| pending-handshake buffer | `32 KiB` (maximum `1 MiB`) |

The default raw-carrier envelope is therefore 1460 bytes of QUICP payload for an IPv4 path and
1440 bytes for an IPv6 path at a 1500-byte outer MTU. Host and smoltcp adapters use their complete
datagram/IP MTU as the adapter limit; they do not apply a fake TCP MSS conversion.

These values are encoded with the standard QUIC transport-parameter varints. An implementation MAY
choose lower local resource budgets, but it MUST advertise the resulting limits and MUST apply
backpressure rather than silently drop stream bytes. It MUST NOT treat a transport parameter as a
FakeTCP sequence number or as an application-flow status.

The no-security profile intentionally has no payload confidentiality or authentication. An
optional security adapter may add those properties above the packet engine. Header protection is
an extensibility hook, not payload encryption or authentication. The carrier still
returns packets immediately when an earlier sequence is absent. It does not reject packets from an
unauthenticated TCP sequence number: QUICP packet numbers own duplicate and replay handling. The
TCP checksum only detects accidental corruption; it is not an authenticity boundary.

`FakeTcpCarrier` also exposes caller-buffer `encode_*_into` methods. The Unix raw sender reuses a
growable batch buffer; the Windows WinDivert sender reuses one packet buffer per sender; Linux
batches up to 10 encoded packets, removing per-packet user-space allocation;
the kernel send remains an ordinary socket copy and is not claimed as zero-copy. Its
`decode_datagram_borrowed` path validates the packet and returns a borrow of the caller's input;
the Linux receiver drains bounded raw packets from the packet ring when `packet_socket = true`
and decodes directly from each mapped frame (or uses `recvmmsg` and one reusable scratch buffer
when the ring is unavailable), coalesces up to four equal-size decoded payloads into one backend
receive segment, and copies only valid QUICP payloads into backend receive buffers.

`crc32c` selects its hardware implementation when available. No handwritten `unsafe` SIMD checksum
path is enabled while the crate forbids unsafe code; a benchmark must prove a remaining
checksum/copy hotspot before adding a platform-specific implementation.

The SYN cookie is an HMAC-SHA-256 truncation bound to the four-tuple and a rotating epoch. It is a
stateless SYN admission check, not a QUICP security key or a replacement for an optional security
adapter.

## 4. SYN data and fallback

SYN data is a TFO-style carrier optimization. It is enabled only with a valid tuple-bound cookie.
The raw adapter places the first backend handshake datagram in the SYN; it does not admit an
application `OPEN` before the QUICP handshake. This removes a separate carrier setup round trip but
is not QUIC or QUICP transport 0-RTT. Origin DNS, dialing, and application bytes remain blocked
until ordinary QUICP admission completes.

Cookie rejection, a middlebox that drops SYN data, or a disabled policy must fall back to an empty
SYN/ordinary first QUICP packet in a future adapter revision. The application must never resend
origin bytes merely because SYN data was lost. The current raw adapter is admitted only with
`syn_data = "cookie"`; `disabled` is retained for packet/carrier tests and for a future explicit
SYN-probe handshake.

The repository includes a Linux-only raw-carrier comparison:

```text
cargo bench --bench loopback --features runtime-tokio,internal-bench -- --quiet
```

The benchmark defaults to `QuicpFlow` no-delay mode. Set `QUICP_NODELAY=false` to measure the
bounded write buffer; the TCP control remains `TCP_NODELAY` enabled in both runs.

It measures a complete no-TLS `QuicpFlow` over `FakeTcpSocket` against one ordinary kernel TCP
stream at the same application payload boundary. Both timers cover client transmission and server
reception after the respective connection and QUICP flow are established. The raw carrier requires
`CAP_NET_RAW`; non-Linux hosts skip this bench rather than report an in-memory codec result.
Each payload runs five interleaved QUICP/TCP samples and reports nearest-rank median, p95, and p99
nanoseconds per payload plus median Gbps. CPU, RSS, allocator, retransmission, and drop counters
remain host-level release evidence and are not fabricated by this process.
The checked-in Linux loopback profile enables `carrier.packet_socket = true`, so the measured
QUICP path uses the filtered AF_PACKET fast path; set it to `false` when comparing the IP-raw
adapter itself.
Linux loopback runs must suppress only the benchmark tuple's kernel-generated TCP RSTs; use a
temporary raw-table rule and remove it immediately after the run:

```sh
sudo iptables -t raw -I OUTPUT -p tcp --sport 40000:40999 --dport 44000:44999 --tcp-flags RST RST -j DROP
sudo iptables -t raw -I OUTPUT -p tcp --sport 44000:44999 --dport 40000:40999 --tcp-flags RST RST -j DROP
trap 'sudo iptables -t raw -D OUTPUT -p tcp --sport 40000:40999 --dport 44000:44999 --tcp-flags RST RST -j DROP; sudo iptables -t raw -D OUTPUT -p tcp --sport 44000:44999 --dport 40000:40999 --tcp-flags RST RST -j DROP' EXIT
cargo bench --bench loopback --features runtime-tokio,internal-bench -- --quiet
```

Do not replace these rules with a global RST drop in a shared host or deployment.
The allocation-only carrier checks are separate and use the same payload sizes:
`cargo bench --bench carrier_encode` and `cargo bench --bench carrier_decode`; their
`*_payload_gbps` columns are codec-only payload rates, not wire throughput.

The raw comparison intentionally excludes TUN, FakeIP, and smoltcp, but includes the selected raw
FakeTCP adapter path (including its packet-ring receive path). The TCP control is part of the same
`loopback` benchmark, so it shares the process, payload boundary, connection state, and timer
definition. TUN/FakeIP remains an optional integration profile and must not be mixed into the raw
protocol comparison.

## 5. QUICP security profiles

Security is optional and outside the QUICP packet engine. The default `none` profile adds no
encryption or authentication, so its packets are suitable for transport-only benchmarking. The
optional `tls` profile uses mutual TLS 1.3 and is the only authenticated profile currently
implemented. PSK is not a selectable profile. Security profile negotiation uses
the QUICP profile token; ALPN is only an adapter encoding when the TLS backend is selected.

The current `noq` integration exposes the no-TLS baseline plus the optional `tls` adapter. The
no-TLS path still uses the backend state machine, but its packet bytes carry no backend encryption:

Omit the `[tls]` table and set `allow_insecure = true` in a client/server config to select this
explicitly unauthenticated profile; adding the table
selects the existing mutual-TLS adapter.

| QUICP profile | Profile token | Multipath transport | Transport 0-RTT |
| --- | --- | --- | --- |
| single path | `quicp/1` | disabled | not admitted |
| failover | `quicp/1-mp` | negotiated, at most two paths | not admitted |

The endpoint rejects a profile-token/transport mismatch before accepting an application flow.
Neither the no-security baseline nor the optional TLS adapter exposes application early data.

### 5.1 Application flow wire format

After connection admission, the client opens one QUIC bidirectional stream per application flow.
Unidirectional streams and QUIC DATAGRAM frames are not part of the `QUICP/1` flow profile. The
stream bytes are:

```text
client -> server: OPEN = host_length:u8 || host:host_length bytes || port:u16be
server -> client: STATUS = status:u8
both directions: application bytes, only after STATUS == 0x00
```

`host` MUST be lowercase ASCII DNS text with at least two labels, no trailing dot, no IP literal,
and each label in `[a-z0-9-]` with a maximum length of 63 bytes. The complete hostname is at most
253 bytes; the one-byte wire length therefore caps an `OPEN` request at 255 host bytes. `port` MUST
be nonzero. The receiver reads exactly one length byte, then exactly `host_length + 2` bytes; any
invalid value is a flow protocol error and MUST reset the stream with application error `0x100`.

The server sends exactly one status byte. It MUST send `0x00` before forwarding or accepting
application bytes. A nonzero status is terminal and the server MUST finish the stream without
exposing application payload. The assigned status values are:

| Byte | Name | Meaning |
| --- | --- | --- |
| `0x00` | `OK` | destination flow is ready |
| `0x01` | `GENERAL_FAILURE` | unspecified destination failure |
| `0x02` | `POLICY_DENIED` | current policy rejected the destination |
| `0x03` | `RESOLUTION_FAILURE` | destination name could not be resolved |
| `0x04` | `CONNECTION_REFUSED` | origin refused the connection |
| `0x05` | `CONNECTION_TIMEOUT` | origin connection timed out |
| `0x06` | `CAPACITY_EXHAUSTED` | a bounded flow or connection limit was reached |

Values `0x07..=0xff` are unknown and MUST be treated as `FLOW_PROTOCOL` rather than mapped to a
success or a retryable status. The stable stream/connection application error codes are QUIC
varints: `0x100` `FLOW_PROTOCOL`, `0x101` `FLOW_ABORT`, `0x102` `FLOW_REJECTED`, `0x103`
`MULTIPATH_REQUIRED`, and `0x104` `MULTIPATH_CHURN`. Unknown peer error codes map to
`FLOW_PROTOCOL` for diagnostics.

For the reference vector `OPEN("www.example.com", 443)`, the bytes are:

```text
0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d 01 bb
```

The corresponding success status is `00`; a policy denial is `02`. These bytes are independent of
TLS, FakeTCP, multipath, and the host language.

## 6. Multipath over FakeTCP

One QUICP session owns one session-ID namespace and may own up to two validated paths. Each QUICP
path maps to an independent FakeTCP four-tuple and independent carrier state:

```text
QUICP session ID: C
  path 0: (local-ip-0, ephemeral-port-0) -> (server-ip-0, port)
  path 1: (local-ip-1, ephemeral-port-1) -> (server-ip-1, port)
```

QUICP path IDs, packet-number spaces, validation, and recovery remain above the carrier. A failed
path does not reset flows while another path in the same QUICP session is usable. The scheduler
uses the backup path for failover, not byte striping. This implementation does not claim to be
MPTCP: it does not emit MPTCP capability/DSS options or ask the kernel to join TCP subflows.

Path admission is bounded: explicit configured candidates only, two concurrent paths, eight path
IDs over a connection lifetime, one validation at a time, bounded event queues, and fail-closed
behavior when path events lag or contradict the expected role/status.
Dynamic path discovery and automatic reopen after `Discarded` are not part of this profile. A
discarded path is not silently replaced; a future replacement adapter must add its own path-ID,
late-event, and churn-rate admission evidence.

The interoperable path roles are fixed:

| Path ID | Role | Required tuple | Failure behavior |
| ---: | --- | --- | --- |
| `0` | primary | first configured four-tuple | keep using while usable; mark degraded on failure |
| `1` | backup | second configured four-tuple | validate before use; carry the same session/flow bytes after primary failure |

The scheduler MUST NOT stripe one ordered flow across paths in this profile. Each path has its own
carrier sequence space, QUIC packet-number space, congestion controller, RTT/loss state, and socket
owner. A path becomes usable only after local validation and the expected remote `Available` status;
late, repeated, or contradictory path events fail the session closed. A changed four-tuple is a
new carrier path, not a continuation of the old carrier state.

## 7. smoltcp and runtime adapters

`smolstack::RingDevice` is an optional IP-medium smoltcp 0.12 device for transparent packet
integrations. TUN/packet tasks exchange complete IP
packets through two bounded lock-free SPSC rings. Packets move into and out of the queue without a
second payload copy; byte and slot budgets reject overflow instead of silently dropping packets.
Each ring has exactly one logical producer and one logical consumer. The platform bridge serializes
concurrent host calls per direction, while the single-owner smoltcp interface is polled by one task
with a bounded packet budget so a busy TUN cannot starve QUICP. A bridge also rejects a second active
smoltcp owner. Parallel host callbacks therefore do not concurrently poll smoltcp or violate the
SPSC storage contract.

The default calibration is 1,500-byte MTU, 32 packets per poll, and 32 KiB per smoltcp TCP socket
direction. The QUIC backend uses a 128 KiB per-stream receive window under an 8 MiB connection
cap; these budgets are separate. It requests an ACK every ten ack-eliciting packets with a 1 ms
maximum delay to reduce carrier packets on high-throughput paths. Any adapter that adds mirror
ring buffers must include them in admission accounting. Segmentation metadata is consumed only
inside the adapter; the FakeTCP wire always contains one QUICP datagram per TCP-shaped packet.

The current native raw adapters implement the temporary backend's `noq::AsyncUdpSocket` with Tokio.
Unix uses `AsyncFd`; Windows uses a WinDivert receive thread and the dynamically loaded network-layer
API.
The default uses an `IPPROTO_TCP` raw IPv4 socket for filtered receive and a separate
`IPPROTO_TCP` raw socket without `IP_HDRINCL` for transmit; Linux supplies the IPv4 header while
the carrier owns the TCP-shaped segment. Setting `carrier.packet_socket = true` switches both
directions to filtered `AF_PACKET` `SOCK_DGRAM` sockets. That opt-in mode resolves the longest
matching IPv4 route and a currently resolved ARP neighbor at bind time; it fails closed when
either is unavailable. The receive socket applies the same tuple filter before the reusable
buffer, avoiding the IP/TCP raw receive path. When the kernel supports `TPACKET_V2`, the receive
side uses a bounded 8 MiB `PACKET_RX_RING` (64 128-KiB frames) to remove the `recvmmsg` syscall
from the hot path; it falls back to `recvmmsg` if ring setup is unavailable. The ring is an
opt-in consequence of `packet_socket = true`, so the default IP-raw path keeps its original
memory profile. It is not the default because it bypasses the IP output/input paths and does not
provide a portable route or neighbor abstraction. Both Unix modes require `CAP_NET_RAW` (or an
equivalent privileged service), and must run with kernel TCP RST generation suppressed for the
selected destination/port. Windows uses the signed WinDivert provider and requires Administrator
privileges; its current adapter is IPv4-only. A typical Unix deployment needs a narrowly scoped
nftables/iptables rule and a rollback rule; never disable TCP RST globally. Other targets have no
admitted raw carrier adapter and must fail closed.

Tokio is an optional crate feature (`runtime-tokio`) and is disabled by default. The repository-only
`internal-bench` feature exposes `transport::build_*_endpoint_with_socket` for raw benchmarks and
tests; those builders accept the sole vendored backend's `noq::Runtime` and `noq::AsyncUdpSocket`.
The stable facade keeps
those types private and uses `HostRuntime`/`HostDatagramSocket` for another runtime or platform
event loop. A packet-only adapter uses `platform::PlatformPacketBridge`
and `smoltstack::poll_bounded`; no second built-in runtime feature is maintained until a
production adapter needs it.

For host-driven runtimes, `HostRuntime` supplies bounded timer/task progress and
`HostDatagramSocket` supplies one fixed-peer, preallocated datagram path. The host copies underlay
datagrams into `ingress_datagram_from` (which checks the observed peer), drains
`poll_egress_datagram_into`, and calls `HostRuntime::drive` after I/O or at `next_timer`. The socket
is a carrier seam, not a mobile FakeTCP implementation: the built-in host facade admits
single-path only; a multipath adapter must provide one independently routed socket per candidate
through the lower-level `from_socket` seam. Network Extension/VpnService adapters still need a
platform-appropriate underlay before they can be admitted. Rust integrations can use
`Client::from_host_socket` or `Server::from_host_socket` (and their
`_with_options` variants); those constructors create no OS socket or executor. The lower-level
`from_socket` and endpoint builders remain backend-adapter seams for custom multipath and raw/TUN
benchmarks and are not the portable facade. A FakeTCP client reports
`Connection::backup_ready() == true` only after its configured backup candidate has completed
validation, the expected peer status has been observed, and remains locally open; a single-path or
server connection reports `false`.
`Connection::path_health()` exposes the client-side bounded path state (`Ready`, `Degraded`, or
`Failed`); server-side connections return `None` until the server retains an explicit path-role
configuration. Path-event lag or contradictory path state closes the client connection rather than
silently continuing with an unreliable view.

The single smoltcp owner uses the short-borrow `smolstack::poll_tcp_read` and
`smolstack::poll_tcp_write` helpers between `Interface` polls. `flow::QuicpFlow` is the QUICP
bidirectional flow; the Tokio-only `flow::relay_bidirectional` adapter can relay Tokio byte streams
without an intermediate application queue. `QuicpFlow` uses bounded read-ahead and a bounded write
buffer; the write-buffer limit is `flow_write_buffer_bytes` (32 KiB by default). Its
TCP_NODELAY-like `nodelay` mode is enabled by default and writes through to the QUICP backend;
disabling it permits batching until `poll_flush` or `poll_shutdown`.

## 8. Platform adapters and mobile FFI

The portable Rust core owns QUICP, `FakeTcpPacket`, `FakeTcpCarrier`, flow policy, and bounded
carrier queues. smoltcp and `platform::PlatformPacketBridge` are optional packet adapters for
transparent integrations. Platform code owns packet ingress/egress, privileges, lifecycle, and
any route/DNS activation. The seam is complete IP packets, not an OS socket handle:

```text
platform packet source -> core.ingress_ip(packet)
platform packet sink   <- core.poll_egress_ip(packet)
```

The `ffi-c` feature exports the current packet-bridge subset as a synchronous, nonblocking C ABI.
It uses an opaque, single-owner pointer and batches ingress and egress to avoid a global handle
registry and per-packet foreign calls. Swift and Kotlin must serialize calls for one bridge on
their own executor. The eventual engine surface adds timer progress only when the engine owns
enough protocol state to make that operation real:

```text
quicp_abi_version() -> version
quicp_bridge_create(out_bridge) -> status
quicp_bridge_process_batch(bridge, inputs, outputs, result) -> status
quicp_bridge_close(inout_bridge) -> status
```

The caller owns all packet descriptors and buffers. One batch may contain at most 64 packets.
Input buffers are borrowed only until the call returns; output buffers are written in place.
`inputs_consumed` and `outputs_written` make partial progress explicit. The bridge never invokes a
foreign callback or blocks. The current bridge still copies accepted ingress into its bounded Rust
packet pool because protocol processing is deferred; the ABI itself does not allocate a foreign
buffer. A future synchronous engine may consume a batch directly, but it must not retain an
unleased caller pointer. A language-specific wrapper may expose Swift `async` or Kotlin coroutines,
but no Rust `Future`, Tokio handle, `Vec`, callback, or platform descriptor crosses the ABI. Rust
panics must not cross the ABI; every call returns an explicit status and progress counts. The C ABI
remains a separate, audited unsafe wrapper; all pointer validation and panic containment stay in
that module.

The internal smoltcp egress queue now uses a fixed-size preallocated packet pool when its MTU and
byte budget admit it, removing the normal per-packet allocation. The safe ingress seam now offers
both owned `Vec<u8>` transfer and borrowed-slice copying into its preallocated pool; the carrier
also has a synchronous borrowed decode path. The FFI adapter still decides whether deferred packet
processing needs a copy or an explicit lease, so this pool must not be described as end-to-end
zero-copy.

The status contract is deliberately small: `OK`, `WOULD_BLOCK`, `BUFFER_TOO_SMALL`,
`INVALID_ARGUMENT`, `NOT_READY`, and `CLOSED`. A batch returns `OK` when it makes progress, even if
the bounded ingress queue accepts only a prefix. `BUFFER_TOO_SMALL` leaves the next egress packet
queued and writes its required length into the first unwritten output descriptor. `WOULD_BLOCK`
means the call made no progress. Close consumes the opaque pointer and clears the caller's owner
variable; a second close through that cleared variable returns `CLOSED`. Structural pointer,
count, and fixed descriptor/bridge/result overlap errors return before touching the caller's result
or output lengths; once those fixed ranges are valid, packet-range and semantic errors clear the
result and output lengths before returning `INVALID_ARGUMENT`.

| Platform integration | Packet source/sink | Example/adapter status |
| --- | --- | --- |
| Linux | TUN plus raw IPv4 socket | optional example/integration |
| macOS | `NEPacketTunnelProvider` packet loop; raw socket only for a privileged probe | optional skeleton |
| iOS | `NEPacketTunnelProvider.packetFlow` | optional skeleton; entitlement required |
| Android | `VpnService` established TUN file descriptor | optional skeleton; no raw-underlay grant |
| Windows | Host-driven core and packet bridge; WinDivert signed WFP/WDF packet injection for Tier 0; Wintun/TAP for Tier 1 | Tier 0 adapter implemented; provider and packet evidence required |

`VpnService` and `NEPacketTunnelProvider` provide the virtual IP packet stream, but they do not
magically grant arbitrary raw TCP injection on the physical underlay. Mobile admission therefore
requires a separately verified carrier adapter or a platform-appropriate fallback. Windows
host-driven and packet-bridge integrations are in the current build matrix. Its Tier 0 carrier
uses the signed WinDivert WFP/WDF packet-injection path rather than assuming `SOCK_RAW` can send
arbitrary TCP packets. A native Wintun/TAP handle adapter remains a separate roadmap item.

## 9. Configuration and trust boundaries

`CarrierConfig` is shared by client and server:

```toml
[carrier]
syn_data = "cookie" # or "disabled" for carrier tests/future SYN-probe mode
cookie_secret_file = "/etc/quicp/carrier-cookie.secret"
congestion_control = "cubic" # "new-reno" or "bbr3" are also available
```

`congestion_control` selects the transport controller for each QUICP connection/path. It changes
local pacing and congestion-window behavior only; it does not change the wire format, FakeTCP
sequence state, or application-flow ordering. The stable public profiles are `cubic`, `new-reno`,
and `bbr3`. Rust callers may override the profile with `TransportOptions::with_congestion_controller_factory`
when using the host-socket or Linux FakeTCP builders. The factory is synchronous and owns only
congestion state; packet recovery, authentication, and carrier sequencing remain owned by QUICP.
The current C ABI does not expose congestion configuration or callbacks; a future native
configuration ABI should select the built-in enum and never accept a foreign callback.

Rust callers may use `TransportOptions::with_header_protection_factory` for the no-TLS profile.
The factory supplies directional header protectors and is intentionally not accepted with the TLS
profile, whose QUIC header protection is bound to its negotiated keys. A custom protector must be
deterministic for both peers and must not be treated as payload confidentiality or authentication;
use TLS or an authenticated packet adapter when those properties are required.

The Rust-only [`PluginRegistry`](plugin-system.md) applies bounded configuration plugins in
registration order. The included `QueqiaoPlugin` is a shared-path congestion policy inspired by
Queqiao's endpoint-pair model; it is not Queqiao protocol interoperability, FEC, SOCKS5, or
enrollment. Its optional erasure floor is measured against the current shared window. The runnable
host, header-protection, and plugin probes live under `examples/`; the
Network Extension and VpnService packet-loop skeletons live under `sdk/*/Examples`.

The cookie secret must be an absolute, regular, non-symlink file with trusted parents and owner-only
permissions. It is never accepted inline in TOML or logged. Unix `FakeTCP` endpoint builders load
this file during construction and derive the tuple-bound SYN cookie for the current 60-second
epoch; callers provide only the path tuples. A missing, unreadable, or disabled cookie policy
fails endpoint construction rather than silently falling back to an unprotected raw profile.
Windows host-driven and native-carrier configurations use a `%PROGRAMDATA%\\quicp` default path;
owner-only cookie/private-file loading verifies the current owner and write-capable ACL entries.
The WinDivert carrier additionally requires the matching signed provider files and Administrator
privileges; see [the Windows carrier guide](windows.md).

The QUICP transport core accepts a caller-provided canonical hostname or socket target and does
not allocate FakeIP or operate a DNS server. A transparent VPN or TUN example may use FakeIP as a
local lookup key, send the canonical hostname inside the admitted QUICP flow, and let the server
authorize the concrete resolved address before dialing it. Unknown or stale FakeIP state, DNS
split-routing drift, failed authentication, route ambiguity, and capacity exhaustion must fail
closed in that optional integration. Its FakeDNS/TUN and system-resolver lifecycle must be
verified separately from the raw carrier.

When an optional transparent integration uses the FakeIP journal, it must open it component by
component and reject symlinked parent directories and final paths; callers must provide a
canonical, link-free journal path. Persistence currently fails closed as unsupported on non-Unix
platforms until a native no-reparse secure-open implementation is available.

## 10. Optional FakeIP/TUN integration safety

FakeIP, FakeDNS, TUN, and route activation are not part of the QUICP transport core. A transparent
VPN or TUN example that composes them creates an independent trust boundary and must:

- install the owner-tagged TUN route in a dedicated routing table that contains no default,
  unicast, VPN, or inherited override route; a destination rule must not be allowed to fall through
  to a normal underlay route;
- keep a durable owner-tagged destination `blackhole` rule across graceful stop, crash, and restart.
  Removing the live TUN route is allowed only after the blackhole is present, so a cached FakeIP
  cannot escape to the underlay while the process is down;
- publish FakeDNS only after QUICP admission and every configured failover path required by the
  profile are ready. If readiness is lost before publication, stop new flows and leave FakeDNS
  inactive;
- configure `systemd-resolved` only on the QUICP link with route-only `~.` and enumerate every
  non-QUICP link and Manager entry (including ifindex 0) before activation. Any more-specific
  routing/search domain, or any parallel global `~.`, is a fail-closed admission error;
- subscribe to link and Manager domain changes at runtime. A VPN, DHCP, or NetworkManager update
  that introduces a competing domain stops new flows and reverts the QUICP resolver state before
  accepting more FakeIP traffic.

The server's wildcard raw socket must apply the configured destination-address/port allowlist and
packet-info filter before QUICP parsing. A packet addressed to an unowned local address is dropped
without exposing a QUICP session or carrier error.

## 11. Interoperability and release gates

This rewrite intentionally makes no wire/API compatibility promise with the previous UDP proxy.
Before production admission, run:

1. unit and property tests for checksums, malformed headers, duplicate and out-of-order delivery,
   SYN-cookie rotation, and direct QUICP payload delivery;
2. Linux raw-socket integration tests with packet capture, RST suppression, NAT rebinding, MTU
   boundaries, loss/reordering, and both path tuples;
3. Windows WinDivert integration tests with signed-driver startup, external-interface packet
   capture, RST suppression, tuple filtering, shutdown cleanup, and both path tuples;
4. QUICP profile tests for no-security operation, the optional TLS adapter, early-open rejection,
   profile-token mismatch, and multipath failover; PSK remains `N/A/not admitted`;
5. memory and CPU benchmarks at the configured flow/path limits, including the checksum and copy
   paths used on the target CPU;
6. license, dependency, capability, and rollback review for the privileged raw-socket service.

Until those gates pass, ship the ordinary UDP adapter or single-path profile as a separate,
explicit deployment choice. Do not silently fall back from a failed FakeTCP admission check to an
unrelated underlay.

## 12. Independent implementation checklist

An implementation written without this repository should be able to complete the following in
order:

1. Encode and decode the IP/TCP envelope, including IPv4/IPv6 and TCP pseudo-header checksums.
2. Round-trip a caller-provided QUIC datagram through one `SYN`/`SYN|ACK` and ordinary `ACK|PSH`
   carrier packet, then verify that a missing carrier sequence does not block a later datagram.
3. Implement QUIC v1 packet parsing and recovery, then the exact no-TLS `QPCS` handshake or the
   TLS 1.3 ALPN profile. Reject early data in both cases.
4. Negotiate one profile token and enforce its multipath state before accepting a stream.
5. Open a client bidirectional stream, exchange the exact `OPEN`/`STATUS` bytes, and keep all
   application bytes behind `STATUS(OK)`.
6. Add path 1 only as a separately validated four-tuple; fail over the same session without
   resetting flow bytes, and reject path churn outside the two-path budget.

The smallest useful interop capture contains one no-TLS single-path handshake, one successful
`OPEN("www.example.com", 443)`, one policy-denied `OPEN`, one malformed status, one reordered
carrier pair, and one primary-to-backup failover. Record raw packets and decoded QUIC/flow events;
throughput or a loopback-only result is not protocol interoperability evidence.

When this checklist cannot be satisfied using the current QUIC backend or security adapter, the
implementation MUST report the unsupported profile instead of silently selecting another token or
wrapping QUICP in a reliable TCP stream.
