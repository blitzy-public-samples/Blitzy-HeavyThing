<!--
  HeavyThing x86_64 assembly language library and showcase programs
  Copyright (c) 2015 2 Ton Digital
  Homepage: https://2ton.com.au/
  Author: Jeff Marrison <jeff@2ton.com.au>

  This file is part of the HeavyThing library.

  HeavyThing is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License, or
  (at your option) any later version.

  HeavyThing is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along
  with the HeavyThing library. If not, see <http://www.gnu.org/licenses/>.
-->

# HeavyThing Rust Port — Benchmark Report

This report compares the performance of the Rust port to the original HeavyThing x86_64 assembly baseline for three workloads called out in AAP §0.8.5: AES-128-CBC throughput, SHA-256 throughput, and HTTP round-trip latency.

The measurements recorded here satisfy Gate 3 of the Validation Framework. The acceptable performance threshold per AAP §0.8.1 is **within 3× of the assembly baseline**; any regression beyond 3× MUST be documented with a root-cause analysis in the relevant benchmark section below.

## Methodology

- **Benchmark harness**: `criterion` v0.5 with 100-sample warm-up + 100-sample measurement per run
- **Hardware**: _TBD_ at measurement time (CPU model, base clock, core count, RAM capacity, kernel version)
- **Rust build**: `cargo bench --release` with `RUSTFLAGS="-D warnings"` and the pinned toolchain from `rust-toolchain.toml`
- **Assembly baseline**: pre-built static binaries in the `rwasa/`, `examples/sha256/`, and `examples/aes-cbc/` trees (or standalone harnesses if the examples lack dedicated AES/SHA measurements)
- **Baseline persistence**: criterion `--save-baseline assembly` for assembly measurements; subsequent Rust runs use `--baseline assembly` to produce delta tables
- **Sampling discipline**: each measurement is taken after CPU frequency scaling has been fixed to the performance governor (`cpupower frequency-set -g performance`) and with SMT/hyperthread siblings pinned away from the benchmark core via `taskset`
- **Warmup convention**: criterion's default `warm_up_time` is retained at 3 s; each iteration loop runs long enough that the measurement noise floor is dominated by wall-clock jitter rather than cache-cold effects

### Benchmark Source Code Map

The following mapping between benchmark harness files, assembly sources, and Rust crate modules is preserved verbatim so that downstream measurement engineers know exactly which code paths are being exercised. All paths are relative to the repository root.

| Benchmark        | Harness file                                     | Assembly source    | Rust module                                 |
|------------------|--------------------------------------------------|--------------------|---------------------------------------------|
| AES-128-CBC      | `crates/heavything/benches/aes_cbc.rs`           | `aes.inc`          | `crates/heavything/src/crypto/aes.rs`       |
| SHA-256          | `crates/heavything/benches/sha256.rs`            | `sha2.inc`         | `crates/heavything/src/crypto/sha2.rs`      |
| HTTP round-trip  | `crates/heavything/benches/http_roundtrip.rs`    | `webserver.inc`    | `crates/heavything/src/net/http/server.rs`  |

## AES-128-CBC Throughput

**Benchmark description**: Encrypts a 1 MiB plaintext block with AES-128-CBC, iterated; throughput measured in MB/s. Assembly baseline uses the Wei Dai fallback when AES-NI is absent and the AES-NI path when present; Rust uses the `aes` + `cbc` crates from RustCrypto which also dispatch to AES-NI at runtime when available.

Source-file provenance: `aes.inc` in the repository root implements both the AES-NI path (exercised when `CPUID` reports `has_AESNI = 1`) and the Wei Dai public-domain fallback with the timing countermeasures noted in the original comment block. The Rust counterpart lives at `crates/heavything/src/crypto/aes.rs` and is exercised by `crates/heavything/benches/aes_cbc.rs`.

| Variant              | Throughput (MB/s) | Ratio vs. Assembly | Notes  |
|----------------------|-------------------|--------------------|--------|
| Assembly (AES-NI)    | _TBD_             | 1.00× (baseline)   | _TBD_  |
| Assembly (Wei Dai)   | _TBD_             | _TBD_              | _TBD_  |
| Rust (AES-NI)        | _TBD_             | _TBD_              | _TBD_  |
| Rust (software)      | _TBD_             | _TBD_              | _TBD_  |

Raw criterion output (verbatim from `cargo bench --bench aes_cbc`):

```text
_TBD_ — paste verbatim criterion stdout here at measurement time.
Example lines will resemble:
    aes_cbc/encrypt-1MiB      time:   [_TBD_ µs _TBD_ µs _TBD_ µs]
                              thrpt:  [_TBD_ MiB/s _TBD_ MiB/s _TBD_ MiB/s]
                              change: [_TBD_% _TBD_% _TBD_%] (p = _TBD_ < 0.05)
```

<!-- If the Rust/Assembly ratio for any AES-128-CBC variant exceeds 3.00×, document the root cause in this block. Fill in:
     * which variant regressed (Rust AES-NI vs. Assembly AES-NI, or software-vs-software),
     * the hot path identified via `perf record` or `cargo-flamegraph`,
     * the suspected cause (inline-copy overhead, bounds-check elision failure, SIMD intrinsic selection, etc.),
     * any follow-up action (e.g., file an upstream issue, switch to a different crate version, add a micro-optimization in crates/heavything/src/crypto/aes.rs). -->

### Per-Size Breakdown

Criterion group names follow the convention `aes_cbc/<size>` so individual cases are selectable via `cargo bench --bench aes_cbc -- aes_cbc/1KiB` (et al.). Measurements MUST be captured for each mandated input size (1 KiB, 64 KiB, 1 MiB, 16 MiB) before Gate 3 sign-off per AAP §0.3.1.4 and §0.8.5. All rows fold into the aggregate "AES-128-CBC throughput" row of the Threshold Compliance Summary below; individual-size ratios in excess of 3.00× MUST be called out in the regression root-cause block above.

| Input size | Criterion group | Assembly (MB/s) | Rust (MB/s) | Ratio vs. Assembly | Notes |
|------------|-----------------|-----------------|-------------|--------------------|-------|
| 1 KiB      | `aes_cbc/1KiB`  | _TBD_           | _TBD_       | _TBD_              | _TBD_ |
| 64 KiB     | `aes_cbc/64KiB` | _TBD_           | _TBD_       | _TBD_              | _TBD_ |
| 1 MiB      | `aes_cbc/1MiB`  | _TBD_           | _TBD_       | _TBD_              | _TBD_ |
| 16 MiB     | `aes_cbc/16MiB` | _TBD_           | _TBD_       | _TBD_              | _TBD_ |

## SHA-256 Throughput

**Benchmark description**: Hashes a 64 MiB buffer with SHA-256 in a single `digest::Context::update` call; throughput measured in MB/s. Assembly uses SHA-NI when available with a pure-x86_64 fallback; Rust uses `ring::digest::SHA256` which internally dispatches to SHA-NI on supporting CPUs.

Source-file provenance: `sha2.inc` in the repository root implements the SHA-256 compression function in pure x86_64 and is translated in the Rust port to a thin wrapper over `ring::digest` at `crates/heavything/src/crypto/sha2.rs`. The benchmark lives at `crates/heavything/benches/sha256.rs`.

| Variant              | Throughput (MB/s) | Ratio vs. Assembly | Notes  |
|----------------------|-------------------|--------------------|--------|
| Assembly (SHA-NI)    | _TBD_             | 1.00× (baseline)   | _TBD_  |
| Assembly (software)  | _TBD_             | _TBD_              | _TBD_  |
| Rust (SHA-NI)        | _TBD_             | _TBD_              | _TBD_  |
| Rust (software)      | _TBD_             | _TBD_              | _TBD_  |

Raw criterion output (verbatim from `cargo bench --bench sha256`):

```text
_TBD_ — paste verbatim criterion stdout here at measurement time.
Example lines will resemble:
    sha256/hash-64MiB         time:   [_TBD_ ms _TBD_ ms _TBD_ ms]
                              thrpt:  [_TBD_ MiB/s _TBD_ MiB/s _TBD_ MiB/s]
                              change: [_TBD_% _TBD_% _TBD_%] (p = _TBD_ < 0.05)
```

<!-- If the Rust/Assembly ratio for any SHA-256 variant exceeds 3.00×, document the root cause in this block. Fill in:
     * which variant regressed (Rust SHA-NI vs. Assembly SHA-NI, or software-vs-software),
     * whether `ring` selected the expected backend (verify via `cpuid | grep SHA`),
     * the hot path identified via `perf record`,
     * any follow-up action. -->

### Per-Size Breakdown

Criterion group names follow the convention `sha256/<size>` so individual cases are selectable via `cargo bench --bench sha256 -- sha256/1KiB` (et al.). Measurements MUST be captured for each mandated input size (64 B, 1 KiB, 64 KiB, 1 MiB, 16 MiB, 64 MiB) before Gate 3 sign-off per AAP §0.3.1.4 and §0.8.5. All rows fold into the aggregate "SHA-256 throughput" row of the Threshold Compliance Summary below; individual-size ratios in excess of 3.00× MUST be called out in the regression root-cause block above.

| Input size | Criterion group | Assembly (MB/s) | Rust (MB/s) | Ratio vs. Assembly | Notes |
|------------|-----------------|-----------------|-------------|--------------------|-------|
| 64 B       | `sha256/64B`    | _TBD_           | _TBD_       | _TBD_              | _TBD_ |
| 1 KiB      | `sha256/1KiB`   | _TBD_           | _TBD_       | _TBD_              | _TBD_ |
| 64 KiB     | `sha256/64KiB`  | _TBD_           | _TBD_       | _TBD_              | _TBD_ |
| 1 MiB      | `sha256/1MiB`   | _TBD_           | _TBD_       | _TBD_              | _TBD_ |
| 16 MiB     | `sha256/16MiB`  | _TBD_           | _TBD_       | _TBD_              | _TBD_ |
| 64 MiB     | `sha256/64MiB`  | _TBD_           | _TBD_       | _TBD_              | _TBD_ |

## HTTP Round-Trip Latency

**Benchmark description**: Measures 95th-percentile round-trip latency for HTTP/1.1 GET on `/` from localhost client to localhost server. Workload: 1 KiB response body (static file), 100 iterations per sample, keep-alive disabled to isolate connect + request + response + close. Assembly server is `rwasa/rwasa` bound on 127.0.0.1:8443; Rust server is `cargo run --release --bin webserver` with equivalent config.

Source-file provenance: `webserver.inc` in the repository root implements the 8-stage HTTP/1.1 dispatch pipeline with its own epoll-driven IO chain. The Rust counterpart lives at `crates/heavything/src/net/http/server.rs` and is driven by the `tokio` runtime. The benchmark harness lives at `crates/heavything/benches/http_roundtrip.rs`.

| Variant           | p50 (µs) | p95 (µs) | p99 (µs) | Throughput (req/s) | Ratio vs. Assembly |
|-------------------|----------|----------|----------|--------------------|--------------------|
| Assembly (rwasa)  | _TBD_    | _TBD_    | _TBD_    | _TBD_              | 1.00× (baseline)   |
| Rust (webserver)  | _TBD_    | _TBD_    | _TBD_    | _TBD_              | _TBD_              |

Raw criterion output (verbatim from `cargo bench --bench http_roundtrip`):

```text
_TBD_ — paste verbatim criterion stdout here at measurement time.
Example lines will resemble:
    http_roundtrip/GET-1KiB   time:   [_TBD_ µs _TBD_ µs _TBD_ µs]
                              change: [_TBD_% _TBD_% _TBD_%] (p = _TBD_ < 0.05)
```

**Scheduler note**: the Rust baseline uses `tokio`'s multi-thread scheduler by default; the assembly uses a single-threaded epoll loop per worker process. Multi-thread scheduling introduces task-steal overhead that can dominate a fast localhost round-trip; if the p95 ratio diverges beyond expectation, rerun the Rust benchmark with `tokio::runtime::Builder::new_current_thread()` to isolate the scheduler factor from the protocol-handling factor. Both results should be reported.

<!-- If the Rust/Assembly ratio for p95 latency exceeds 3.00×, document the root cause in this block. Candidate causes include:
     * tokio multi-thread scheduler task-hop overhead on localhost round-trip,
     * rustls handshake cost (only relevant if TLS is enabled for this benchmark),
     * allocator differences under short-lived-object pressure,
     * syscall vectoring via `libc::accept4` vs. direct assembly syscall,
     * hash-map overhead for HTTP header parsing vs. hand-written state machine.
     Fill in which cause was confirmed via `perf record` / `strace -c` and any follow-up action. -->

### Per-Concurrency Breakdown

Criterion group names follow the convention `http_rtt/<concurrency>` so individual cases are selectable via `cargo bench --bench http_rtt -- http_rtt/c1` (et al.). Measurements MUST be captured for each mandated concurrency level (c=1, c=4, c=16) before Gate 3 sign-off per AAP §0.3.1.4 and §0.8.5. All rows fold into the aggregate "HTTP RTT p95" row of the Threshold Compliance Summary below; individual-concurrency ratios in excess of 3.00× MUST be called out in the regression root-cause block above.

| Concurrency | Criterion group | Assembly p95 (µs) | Rust p95 (µs) | Ratio vs. Assembly | Notes |
|-------------|-----------------|-------------------|---------------|--------------------|-------|
| c=1         | `http_rtt/c1`   | _TBD_             | _TBD_         | _TBD_              | _TBD_ |
| c=4         | `http_rtt/c4`   | _TBD_             | _TBD_         | _TBD_              | _TBD_ |
| c=16        | `http_rtt/c16`  | _TBD_             | _TBD_         | _TBD_              | _TBD_ |

## Reproducing These Measurements

All commands are executed from the repository root at `/tmp/blitzy/Blitzy-HeavyThing/master_fc613b/`.

```bash
# From the repository root:

# 1. Capture assembly baseline (one-time):
#    Run the pre-built assembly binaries and record their throughput
#    via bespoke harnesses or /usr/bin/time -v. Document in this file.

# 2. Run Rust benchmarks:
cargo bench --workspace -- --save-baseline rust

# 3. Compare against saved assembly baseline (if captured in criterion format):
cargo bench --workspace -- --baseline assembly

# 4. AES-128-CBC standalone:
cargo bench --bench aes_cbc

# 5. SHA-256 standalone:
cargo bench --bench sha256

# 6. HTTP round-trip standalone:
cargo bench --bench http_roundtrip
```

After each run the raw criterion artefacts are written under `target/criterion/`. The HTML reports (one per benchmark) are suitable for archival alongside this Markdown summary.

### Assembly Baseline Capture

The original `.asm`/`.inc` sources do not expose criterion-compatible harnesses. The assembly baseline is therefore captured manually and folded into this document:

```bash
# AES-128-CBC: use the pre-built example (or a dedicated standalone harness).
/usr/bin/time -v ./examples/aes-cbc/aes-cbc-bench  # if available
# otherwise, measure throughput externally:
dd if=/dev/zero bs=1M count=1024 | ./rwasa/rwasa --aes-bench 128 cbc

# SHA-256: the examples/sha256/ tree ships a streaming-hash binary.
/usr/bin/time -v ./examples/sha256/sha256 < /path/to/1GiB-fixture > /dev/null

# HTTP round-trip: run the assembly server in one terminal,
#   ./rwasa/rwasa -cpu 1 -bind 127.0.0.1:8443 -sandbox ./testroot
# and drive it from another:
wrk -t1 -c1 -d30s --latency http://127.0.0.1:8443/
```

Record the observed throughput / latency figures in the tables above under each benchmark's `Assembly (…)` row. Do not invent or extrapolate numbers.

## Behavioral Differences Affecting Benchmark Interpretation

The Rust port preserves externally observable behavior (AAP §0.8.1), but a small number of implementation differences necessarily change how benchmark numbers should be interpreted. These differences are informational — they do NOT invalidate the 3× threshold — but they MUST be understood before drawing conclusions from any single comparison.

- **TLS cipher-suite divergence** (AAP §0.7.2.2): rustls offers ECDHE + AES-GCM (and CHACHA20-Poly1305) for TLS 1.2; the assembly baseline offered classical DHE + AES-CBC-SHA256 for TLS 1.2 and no TLS 1.3 at all. This divergence does **not** affect the AES-128-CBC primitive benchmark (which measures raw block-cipher + CBC mode, independent of any TLS negotiation) but it **does** affect any end-to-end HTTPS measurement, because ECDHE key establishment is much cheaper than classical DHE on the 2048-bit primes that the assembly used. If an HTTPS-terminated HTTP round-trip is later benchmarked, the Rust number will look favourable purely because of the KX change; this should be called out explicitly in any such follow-up measurement.

- **Async runtime overhead**: tokio has non-zero per-task scheduling cost (wake-by-ref, cross-thread queue, mio event loop dispatch); the assembly's hand-rolled epoll loop has minimal dispatch overhead (direct function pointer through the 7-method IO vtable). This difference is expected to be the largest source of latency delta for the HTTP round-trip benchmark, especially on very fast localhost request paths where scheduler cost is a meaningful fraction of the total. Under moderate concurrency the overhead is amortized across many in-flight connections and the delta shrinks.

- **Allocator**: Rust uses the `std` default allocator (typically glibc `malloc` on Linux, delegating to `jemalloc` only when explicitly configured); the assembly uses its own bin allocator with a never-return-to-kernel policy (`heap.inc`). This affects steady-state RSS growth in long-running processes but has very little per-request latency impact because both allocators satisfy small short-lived allocations from thread-local bins in O(1).

- **Compile-time CPU dispatch parity**: both binaries use runtime CPU feature detection (`std::is_x86_feature_detected!` wired through `ring` / `aes` crates for Rust; the `ht$init` CPUID probe setting `has_AESNI` / `has_AVX` / `has_SSE41` for assembly) — neither is compile-time-locked, so the benchmark hardware should exercise the same code paths regardless of which binary is running. If a divergence appears that tracks a specific CPU feature (e.g., the ratio becomes favourable only on SHA-NI-capable hardware), document it so that future comparisons on other hardware can be interpreted correctly.

- **Deflate level**: both the Rust port (via `flate2` with level 6) and the assembly (`zlib_deflate_level = 6`) default to zlib level 6. This parity is not used by the three mandated benchmarks but is noted here for any future compression-related benchmark.

## Threshold Compliance Summary

| Benchmark              | Assembly Baseline | Rust Measurement | Ratio | ≤ 3× Threshold? |
|------------------------|-------------------|------------------|-------|-----------------|
| AES-128-CBC throughput | _TBD_             | _TBD_            | _TBD_ | _TBD_           |
| SHA-256 throughput     | _TBD_             | _TBD_            | _TBD_ | _TBD_           |
| HTTP p95 latency       | _TBD_             | _TBD_            | _TBD_ | _TBD_           |

If any row shows `_No_` under the threshold column, a corresponding root-cause analysis subsection must appear above for that benchmark (inside the commented-out template already reserved under that benchmark's section). Rows marked `_Yes_` indicate compliance with AAP §0.8.1 and require no additional commentary.

Sign-off requirement (Gate 3): after measurements are captured and this document is filled in, record the reviewer initials and the date alongside the table:

- **Measurement engineer**: _TBD_
- **Date**: _TBD_
- **Toolchain**: _TBD_ (output of `rustc --version`)
- **Criterion version**: _TBD_ (output of `cargo bench --version` or from `Cargo.lock`)
- **Hardware**: _TBD_ (output of `lscpu | head -20` plus `free -h | head -2`)

---

_End of benchmark report. This document is a Gate 3 deliverable required by AAP §0.3.1.4; keep it updated whenever the pinned criterion version, the mandated benchmark set, or the 3× threshold itself is revised by a downstream AAP._
