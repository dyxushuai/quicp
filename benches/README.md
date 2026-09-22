# QUICP benchmarks

These binaries are measurement tools, not part of the runtime API.
They compare modes of the [normative QUICP protocol](../docs/protocol.md).

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

## Continuous benchmarking with Bencher

The `Benchmarks` workflow runs all three binaries on `ubuntu-24.04` with Rust 1.88.0.
Each binary runs three times; loopback keeps its six internally alternating samples,
32 MiB transfers, all three payload sizes, and `QUICP_NODELAY=true`. Only the loopback and
raw-socket regression-test executables receive `CAP_NET_RAW`. The workflow verifies receive
wakeups before measuring, then uploads CSV and BMF JSON artifacts without
access to the Bencher key. Kernel TCP is excluded from CI comparisons.

The `Bencher` workflow runs separately from trusted `main` code, validates all 18 benchmark
series, and uploads the median of the three measurements to [QUICP on Bencher](https://bencher.dev/perf/quicp).
Main runs establish the baseline. PRs, including forks, compare against the baseline at their
base commit and publish a `Benchmark regression` check on the measured head commit. PR branches
are named `pr-<number>` so fork branch names cannot collide with the main baseline. Failed
measurements, incomplete reports, missing credentials, and Bencher errors fail the check.
The upload also requires a complete base-commit report among the latest 255 main reports and
all 72 expected regression boundaries. This prevents Bencher's missing-hash fallback or
insufficient history from silently passing a PR. Rebase older PRs onto a measured main commit.
Bencher also publishes its native `Bencher Report (QUICP)` check. The workflow compacts its PR
comment into a Markdown table containing every threshold comparison, preserving the full report
link and avoiding GitHub's comment length limit. The same table appears in the required check.

The initial percentage threshold is 20% against the last ten baseline reports, with one report
required to start comparison. Increases in codec latency, delivery p50/p95/p99, allocations,
and live Rust heap are regressions; decreases in useful throughput are regressions. Recovery
counters and CPU use are recorded for diagnosis. `latency` is in nanoseconds; custom measure
names state their units (`payload-gbps`, `delivery-p95-ns`, `rust-heap-bytes`, etc.). Allocation
counts are per complete run, including the existing codec iteration counts.

GitHub-hosted runners do not guarantee identical physical hardware. Three-run medians reduce
noise but do not establish a 5% detection guarantee. Tune the `BENCHER_REGRESSION_LIMIT` repository
variable (a decimal fraction, default `0.20`) from observed runner variance. Change the testbed
name when changing runner hardware, Rust version, features, or workload. This historical PR
comparison does not replace the separate 5% adaptive-versus-reliable release gate described above;
`QUICP_ENFORCE_CLEAN_PATH` is intentionally not enabled on shared CI hosts.

Setup and verification:

1. Create the public `quicp` Bencher project and store its project-scoped key as the GitHub
   repository secret `BENCHER_API_KEY`.
2. Merge both workflows into `main`; GitHub only activates `workflow_run` from the default branch.
   The first main push seeds the baseline. To reseed, manually run `Benchmarks` on `main`.
3. Run `Bencher` manually with a completed main `Benchmarks` run ID and `verify_alert=true`.
   It publishes the real measurements, then reduces a copy's throughput by 99% on a separate
   `validation-<run-id>` branch. Verification requires both a failing Bencher exit code and a
   nonzero alert count; authentication or network failures cannot satisfy this check. Synthetic
   results never enter the main baseline.
4. After a real PR check succeeds, require `Benchmark regression` and `Measure benchmarks`
   in the main branch ruleset. A workflow file alone does not prevent merging.

For local conversion and validation (Python standard library only):

```sh
# DIR contains carrier_encode.csv, carrier_decode.csv, and loopback.csv.
python3 -B benches/bencher.py DIR > target/benchmarks.json
python3 -B benches/bencher.py --validate target/benchmarks.json
python3 -B -m unittest discover -s benches -p 'test_*.py'
bencher run --dry-run --project quicp --adapter json --file target/benchmarks.json
```

Keep macOS codec-only measurements on a separate testbed; they cannot seed the Linux loopback
baseline. For a failed upload, rerun `Bencher` with the original measurement run ID while its
artifacts remain available (14 days), rather than manufacturing replacement benchmark data.
