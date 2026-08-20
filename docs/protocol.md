# QUICP/1: a custom multiplexed transport over a datagram-preserving FakeTCP carrier

Status: portable core profile (platform carrier adapters are deployment-gated)

## 1. Scope

QUICP is a private, QUIC-inspired multiplexed transport. It is not the IETF QUIC wire protocol,
does not promise QUIC interoperability, and does not require TLS. Its baseline carries QUICP
packets through TCP-shaped IP packets so an underlay that treats UDP as a separate, low-priority
class sees a normal-looking TCP flow. The carrier is not a TCP stream:

```text
application/TUN -> smoltcp -> QUICP packet -> raw IPv4/IPv6 TCP packet
```

There is no UDP header inside the TCP packet and no ordered FakeTCP byte stream around QUICP. Every
QUICP packet is one carrier payload. A missing carrier sequence number does not block a later
packet; QUICP owns packet numbers, loss recovery, congestion control, stream ordering, and
retransmission. Putting QUICP in a reliable FakeTCP stream would recreate transport head-of-line
blocking and is explicitly forbidden.

The QUICP core contains no encryption. TLS, PSK, or another authenticated security adapter may be
selected above the packet engine, but the no-security profile is the performance and protocol
baseline. The current `noq`/rustls integration is a temporary backend adapter and must not be
mistaken for the QUICP wire contract.

This is an evasion-oriented transport experiment, not a claim of indistinguishability or of
guaranteed ISP acceptance. A deployment must test real NATs, middleboxes, reset injection, packet
capture, and the target ISP before enabling it.

## 2. FakeTCP packet format

`FakeTcpPacket` emits a complete raw IPv4 or IPv6 packet with:

- TCP protocol number 6, valid IP and TCP checksums, and no fragmentation;
- source/destination addresses and ports from one fixed four-tuple;
- a stable per-path sequence space, ACK/window fields, and TCP flags;
- SYN options for MSS, SACK-permitted, window scale, and an optional TFO-style cookie;
- a payload containing exactly one QUICP datagram.

The first data packet is `SYN` (or server `SYN|ACK`) and may carry a QUICP packet. Subsequent
packets use `ACK|PSH`. The current carrier does not attempt to implement kernel TCP congestion
control, stream reassembly, or MPTCP DSS. It only supplies TCP-shaped metadata and a per-path
sequence/replay window; QUICP remains the protocol state machine.

The sender chooses a fresh random initial sequence (mixed with the tuple checksum) for every
carrier state. `noq` may batch up to eight equal-MTU datagrams; the FakeTCP adapter expands those
segments into independent TCP-shaped packets and, on Linux, submits the batch with `sendmmsg`
when there is more than one packet; a single packet uses the bound socket's direct `send` path.
The adapter retains its segment cursor across readiness polls. Sequence state is advanced when a
segment is encoded, and the encoded batch remains owned until the OS accepts every packet. A
changed four-tuple always creates a new carrier state; sequence and replay state are never shared
between paths. A path is retired before its 32-bit sequence space can wrap.

## 3. Per-datagram payload

The carrier adds no encryption, authentication tag, length prefix, or padding. The payload is the
QUICP datagram itself:

```text
[QUICP datagram]
```

The no-security profile intentionally has no payload confidentiality or authentication. An
optional security adapter may add those properties above the packet engine. The carrier still
returns packets immediately when an earlier sequence is absent and rejects duplicate or packets
more than the bounded 64-packet/4 MiB replay horizon behind the newest sequence. The TCP checksum
only detects accidental corruption; it is not an authenticity boundary.

`FakeTcpCarrier` also exposes caller-buffer `encode_*_into` methods. The Linux raw sender reuses a
growable batch buffer for up to 10 encoded packets, removing per-packet user-space allocation;
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

SYN data is a TFO-style optimization. It is enabled only with a valid tuple-bound cookie. A first
connection may carry a bounded QUICP control header immediately; this is a replay-sensitive
0-RTT-style feature, not QUIC 0-RTT. Origin DNS, dialing, and arbitrary application bytes remain
blocked until the selected security/policy gate succeeds. In the no-security profile, that gate is
the explicit QUICP peer/policy admission step.

Cookie rejection, a middlebox that drops SYN data, or a disabled policy must fall back to an empty
SYN/ordinary first QUICP packet in a future adapter revision. The application must never resend
origin bytes merely because SYN data was lost. The current raw adapter is admitted only with
`syn_data = "cookie"`; `disabled` is retained for packet/carrier tests and for a future explicit
SYN-probe handshake.

The repository includes a Linux-only raw-carrier comparison:

```text
cargo bench --bench loopback -- --quiet
```

It measures a complete no-TLS `QuicpFlow` over `FakeTcpSocket` against one ordinary kernel TCP
stream at the same application payload boundary. Both timers cover client transmission and server
reception after the respective connection and QUICP flow are established. The raw carrier requires
`CAP_NET_RAW`; non-Linux hosts skip this bench rather than report an in-memory codec result.
The checked-in Linux loopback profile enables `carrier.packet_socket = true`, so the measured
QUICP path uses the filtered AF_PACKET fast path; set it to `false` when comparing the IP-raw
adapter itself.
Linux loopback runs must suppress only the benchmark tuple's kernel-generated TCP RSTs; use a
temporary raw-table rule and remove it immediately after the run:

```sh
sudo iptables -t raw -I OUTPUT -p tcp --sport 40000:40999 --dport 44000:44999 --tcp-flags RST RST -j DROP
sudo iptables -t raw -I OUTPUT -p tcp --sport 44000:44999 --dport 40000:40999 --tcp-flags RST RST -j DROP
trap 'sudo iptables -t raw -D OUTPUT -p tcp --sport 40000:40999 --dport 44000:44999 --tcp-flags RST RST -j DROP; sudo iptables -t raw -D OUTPUT -p tcp --sport 44000:44999 --dport 40000:40999 --tcp-flags RST RST -j DROP' EXIT
cargo bench --bench loopback -- --quiet
```

Do not replace these rules with a global RST drop in a shared host or deployment.
The allocation-only carrier checks are separate and use the same payload sizes:
`cargo bench --bench carrier_encode` and `cargo bench --bench carrier_decode`; their
`*_payload_gbps` columns are codec-only payload rates, not wire throughput.

The raw comparison intentionally excludes TUN, FakeIP, and smoltcp, but includes the selected raw
FakeTCP adapter path (including its packet-ring receive path). The portable `tcp_loopback` benchmark
remains a kernel-TCP lower-bound baseline. A separate TUN benchmark is required for the
transparent-IP path; its result must not be reported as the raw protocol comparison.

The checked-in macOS `utun_loopback` executable exercises a platform/TUN path and is not the
authoritative raw protocol comparison. Its no-TLS profile excludes TLS and AEAD, while an optional
TLS run is a separate security profile.

## 5. QUICP security profiles

Security is optional and outside the QUICP packet engine. The default `none` profile adds no
encryption or authentication, so its packets are suitable for transport-only benchmarking. The
optional `tls` profile may use TLS 1.3 and the optional `psk` profile may use a pre-shared key, but
neither changes the QUICP stream, loss, or multipath semantics. Security profile negotiation uses
the QUICP profile token; ALPN is only an adapter encoding when the TLS backend is selected.

The current `noq` integration exposes the no-TLS baseline plus the optional `tls` adapter. The
no-TLS path still uses the backend state machine, but its packet bytes carry no backend encryption:

Omit the `[tls]` table in a client/server config to select this no-TLS profile; adding the table
selects the existing mutual-TLS adapter.

| QUICP profile | Profile token | Multipath transport | Early open |
| --- | --- | --- | --- |
| single path | `quicp/1` | disabled | `off` or bounded `safe-open-only` |
| failover | `quicp/1-mp` | negotiated, at most two paths | bounded `safe-open-only` |

The endpoint rejects a profile-token/transport mismatch before accepting an application flow. Early
data is never allowed to resolve a target, open an origin connection, mutate durable state, or
forward unbounded TCP bytes. Rejection is retried once only when the selected security/policy gate
remains alive and explicitly reports early-data rejection; ambiguous connection failure is
fail-closed.

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

## 7. smoltcp and runtime adapters

`smolstack::RingDevice` is an IP-medium smoltcp 0.12 device. TUN/packet tasks exchange complete IP
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

The current raw socket adapter implements the temporary backend's `noq::AsyncUdpSocket` on Linux
with Tokio's `AsyncFd`.
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
memory profile. It is not the default because it bypasses the IP
output/input paths and does not provide a portable route or neighbor abstraction. Both modes
require `CAP_NET_RAW` (or an equivalent privileged service), and must run with kernel TCP RST
generation suppressed for the selected destination/port. A typical deployment needs a narrowly
scoped nftables/iptables rule and a rollback rule; never disable TCP RST globally. IPv6 raw I/O
and non-Linux carrier adapters are not admitted by this implementation profile.

Tokio is an optional crate feature (`runtime-tokio` and the default profile). The
`transport::build_*_endpoint_with_socket` builders accept `noq::Runtime` and
`noq::AsyncUdpSocket`, so another runtime or platform event loop can provide the temporary backend
without changing the QUICP core. A runtime-free packet-only build uses `platform::PlatformPacketBridge`
and `smoltstack::poll_bounded`; no second built-in runtime feature is maintained until a
production adapter needs it.

The single smoltcp owner uses the short-borrow `smolstack::poll_tcp_read` and
`smolstack::poll_tcp_write` helpers between `Interface` polls. `flow::QuicpFlow` is the QUICP
bidirectional flow; the Tokio-only `flow::relay_bidirectional` adapter can relay Tokio byte streams
without an intermediate application queue. `QuicpFlow` uses bounded 32 KiB read-ahead and write
batching; `poll_flush` and `poll_shutdown` drain pending writes.

## 8. Platform adapters and mobile FFI

The portable Rust core owns QUICP, `FakeTcpPacket`, `FakeTcpCarrier`, smoltcp, flow policy, and
bounded packet queues. `platform::PlatformPacketBridge` is the safe packet seam. Platform code
owns only packet ingress/egress, privileges, lifecycle, and route/DNS activation. The seam is
complete IP packets, not an OS socket handle:

```text
platform packet source -> core.ingress_ip(packet)
platform packet sink   <- core.poll_egress_ip(packet)
```

The future `boltffi` bridge (or an equivalent C ABI) must not export only async functions. Its base
surface is synchronous and nonblocking, so Swift/Kotlin can attach their own lifecycle and event
loop:

```text
engine_create(config) -> opaque handle
engine_ingress_ip(handle, ptr, len) -> status
engine_poll_egress_ip(handle, out_ptr, capacity, out_len) -> status
engine_tick(handle, monotonic_now_ns) -> status
engine_close(handle)
```

The caller owns all ABI buffers; the engine never invokes a foreign callback, mutates an input
buffer, or blocks. `ingress_ip` borrows its input until the call returns, so a synchronous adapter
may consume it without copying. An adapter that defers processing must copy the bytes into its
bounded queue (or use an explicit retained-buffer lease); it must never retain an unleased caller
pointer. This is an ownership rule, not a ban on internal Rust allocation. A language-specific
wrapper may turn these calls into Swift `async` or Kotlin coroutines, but no Rust `Future`, Tokio
handle, `Vec`, callback, or platform descriptor crosses the ABI. Rust panics must not cross the ABI;
every call returns an explicit status and byte count. The C ABI remains a separate wrapper; unsafe
code is denied by default and allowed only in the audited SPSC storage module.

The internal smoltcp egress queue now uses a fixed-size preallocated packet pool when its MTU and
byte budget admit it, removing the normal per-packet allocation. The safe ingress seam now offers
both owned `Vec<u8>` transfer and borrowed-slice copying into its preallocated pool; the carrier
also has a synchronous borrowed decode path. The FFI adapter still decides whether deferred packet
processing needs a copy or an explicit lease, so this pool must not be described as end-to-end
zero-copy.

The status contract is deliberately small: `OK`, `WOULD_BLOCK`, `BUFFER_TOO_SMALL`,
`INVALID_ARGUMENT`, `NOT_READY`, and `CLOSED`. `ingress_ip` returns `WOULD_BLOCK` without consuming
the caller buffer when the bounded ingress queue is full. `poll_egress_ip` returns
`BUFFER_TOO_SMALL` without dequeuing when `capacity` cannot hold the next complete packet; it
returns `WOULD_BLOCK` when no packet is ready. `tick` never sleeps and rejects a closed handle.

| Platform | Packet source/sink | Carrier adapter status |
| --- | --- | --- |
| Linux | TUN plus raw IPv4 socket | current implementation |
| macOS | `NEPacketTunnelProvider` for product traffic; raw socket only for a privileged probe | planned |
| iOS | `NEPacketTunnelProvider.packetFlow` | planned; Network Extension entitlement required |
| Android | `VpnService` established TUN file descriptor | planned; `VpnService` does not itself grant raw underlay injection |
| Windows | WFP/Wintun or a signed packet adapter | planned; user-mode raw TCP injection is not the production path |

`VpnService` and `NEPacketTunnelProvider` provide the virtual IP packet stream, but they do not
magically grant arbitrary raw TCP injection on the physical underlay. Mobile admission therefore
requires a separately verified carrier adapter or a platform-appropriate fallback. Windows raw
socket behavior is version- and policy-dependent; a production adapter must use the supported WFP
packet modification/reinjection path rather than assume `SOCK_RAW` can send arbitrary TCP packets.

## 9. Configuration and trust boundaries

`CarrierConfig` is shared by client and server:

```toml
[carrier]
syn_data = "cookie" # or "disabled" for carrier tests/future SYN-probe mode
cookie_secret_file = "/etc/quicp/carrier-cookie.secret"
```

The cookie secret must be an absolute, regular, non-symlink file with trusted parents and owner-only
permissions. It is never accepted inline in TOML or logged.

FakeIP remains a local lookup key. The client sends the canonical hostname inside the admitted
QUICP flow and the server authorizes the concrete resolved address before dialing it. Unknown or
stale FakeIP state, DNS split-routing drift, failed authentication, route ambiguity, and capacity
exhaustion fail closed. The FakeDNS/TUN and system resolver lifecycle must be verified separately
from the raw carrier; this module does not claim to provide a complete Linux daemon yet.

## 10. FakeIP/TUN activation safety

The FakeIP route is an independent trust boundary. The Linux activation layer must:

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

1. unit and property tests for checksums, malformed headers, replay, out-of-order delivery,
   SYN-cookie rotation, and direct QUICP payload delivery;
2. Linux raw-socket integration tests with packet capture, RST suppression, NAT rebinding, MTU
   boundaries, loss/reordering, and both path tuples;
3. QUICP profile tests for no-security operation, optional TLS/PSK adapters, early-open rejection,
   profile-token mismatch, and multipath failover;
4. memory and CPU benchmarks at the configured flow/path limits, including the checksum and copy
   paths used on the target CPU;
5. license, dependency, capability, and rollback review for the privileged raw-socket service.

Until those gates pass, ship the ordinary UDP adapter or single-path profile as a separate,
explicit deployment choice. Do not silently fall back from a failed FakeTCP admission check to an
unrelated underlay.
