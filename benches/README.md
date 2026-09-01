# QUICP benchmarks

These binaries are measurement tools, not part of the runtime API.
They compare modes of the [normative QUICP/2 protocol](../docs/protocol.md).

| Benchmark | Purpose | Requirements |
| --- | --- | --- |
| `carrier_encode` | Compare allocating and caller-buffer FakeTCP encoding | None |
| `carrier_decode` | Compare owning and borrowed FakeTCP decoding | None |
| `loopback` | Matched adaptive and reliable-only QUICP over raw FakeTCP, with optional kernel TCP reference | Linux, `runtime-tokio`, raw-socket privilege |

Run codec and baseline measurements with release optimizations:

```sh
cargo bench --bench carrier_encode --locked
cargo bench --bench carrier_decode --locked
```

The authoritative protocol comparison runs adaptive and reliable-only QUICP with the same carrier,
runtime, payloads, byte count, no-delay setting, and no-TLS profile. Kernel TCP is reported only as
a host reference because it does not traverse the FakeTCP carrier:

```sh
cargo bench --bench loopback \
  --features runtime-tokio --locked
```

Set `QUICP_ONLY=1 QUICP_ENFORCE_CLEAN_PATH=1` for the release gate. It fails unless the adaptive
1200-byte and 4096-byte median goodput stays within 5% of reliable-only and emits no repair symbols.
The gate rejects a narrowed payload set or less than the default 32 MiB per sample.

For the deterministic lossy comparison, run the same binary on an isolated Linux host while
`lo` has `tc netem loss random 0.1% seed 42`; always remove that qdisc afterward. Do not apply
`netem` to a shared host. Leave `QUICP_ENFORCE_CLEAN_PATH` unset because the 5% gate is clean-only.

The CSV includes sampled write-to-delivery p50/p95/p99 latency, median useful goodput, process CPU
percentage, allocations per run, median absolute peak live Rust heap, and separate adaptive/reliable
recovery counters. Each heap sample starts before carrier, configuration, and runtime setup; result
storage is preallocated so the matched modes begin with the same harness-owned heap baseline. This
is the process-wide high-water mark of live bytes visible to Rust's global allocator, not RSS,
allocator-reserved memory, or isolated ownership attribution. Repair overhead is reported as whole
parts per million source symbols, rounded up so a nonzero rate remains visible, because the protocol
snapshot does not expose encoded byte totals. Linux process RSS is a single lifetime high-water mark
printed in the footer; it is not attributed to either mode. Each run samples at most 256 payload
deliveries. Six QUICP samples use three adaptive-first and three reliable-first pairs to reduce
frequency and cache-order bias; the optional kernel TCP reference runs afterward so it cannot
perturb the matched QUICP pairs. Allocation counting is part of the benchmark binary, so use an
external profiler when attributing individual calls. `QUICP_PAYLOAD_SIZE`, `QUICP_TOTAL_BYTES`,
and `QUICP_ONLY` narrow the run without changing framing. `QUICP_NODELAY` accepts
`true`/`false` or `1`/`0` and applies the same setting to QUICP and TCP. `QUICP_IP_RAW=1` selects the
Linux IP-raw fallback instead of the default AF_PACKET path. Loopback results are local
characterization only; they are not evidence of ISP acceptance or Internet-path behavior.
