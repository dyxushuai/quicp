# QUICP benchmarks

These binaries are measurement tools, not part of the runtime API.

| Benchmark | Purpose | Requirements |
| --- | --- | --- |
| `carrier_encode` | Compare allocating and caller-buffer FakeTCP encoding | None |
| `carrier_decode` | Compare owning and borrowed FakeTCP decoding | None |
| `loopback` | Complete Linux raw FakeTCP QUICP flow, optionally alongside kernel TCP | Linux, `runtime-tokio`, `internal-bench`, raw-socket privilege |

Run codec and baseline measurements with release optimizations:

```sh
cargo bench --bench carrier_encode --locked
cargo bench --bench carrier_decode --locked
```

The authoritative QUICP comparison is the complete-flow Linux benchmark. It must be run on the
same host, payload size, total byte count, and privilege policy as the TCP baseline:

```sh
cargo bench --bench loopback \
  --features runtime-tokio,internal-bench --locked
```

`QUICP_PAYLOAD_SIZE`, `QUICP_TOTAL_BYTES`, `QUICP_NODELAY`, and `QUICP_ONLY` narrow the run without
changing the benchmark's framing. Loopback results are local characterization only; they are not
evidence of ISP acceptance or Internet-path behavior.
