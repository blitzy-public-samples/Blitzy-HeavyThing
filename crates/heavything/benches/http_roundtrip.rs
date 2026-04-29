// ------------------------------------------------------------------------
// HeavyThing Rust translation — epoll-driven HTTP round-trip latency benchmark
// Copyright © 2015 2 Ton Digital, Jeff Marrison <jeff@2ton.com.au>
// Homepage: https://2ton.com.au/
//
// This file is part of the HeavyThing Rust translation.
//
// HeavyThing is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// HeavyThing is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with the HeavyThing library. If not, see <https://www.gnu.org/licenses/>.
// ------------------------------------------------------------------------
//
// http_roundtrip.rs: Criterion benchmark for epoll-driven HTTP/1.1 round-trip
//                    latency.  Source: exercises Rust code that replaces
//                    `epoll.inc` (3,512 lines) + `webserver.inc` (5,670 lines).
//
// The server is a minimal tokio-based HTTP/1.1 responder bound to 127.0.0.1:8443
// that returns a fixed 1 KiB body for any request. Using raw sockets (rather
// than the full `WebServer` dispatch pipeline) isolates the epoll / async I/O
// cost from the HTTP parsing and routing cost, per AAP §0.3.1.2.
//
// Per AAP §0.8.1, the Rust implementation MUST achieve latency within 3× of the
// assembly baseline; any regression beyond that requires root-cause analysis
// captured in BENCHMARK_REPORT.md (handled by a sibling agent — this file
// produces the raw measurements only).
//
// Runs: `cargo bench --bench http_roundtrip -p heavything`
// Baseline save/compare:
//   cargo bench --bench http_roundtrip -p heavything -- --save-baseline rust_v1
//   cargo bench --bench http_roundtrip -p heavything -- --baseline rust_v1
//
// CRITICAL CONSTRAINT (per AAP §0.6.3.3 / §0.8.7): the workspace pins
// `criterion = "0.5"` WITHOUT the `async_tokio` feature. Therefore async
// operations MUST be wrapped via `rt.block_on(async { ... })` inside the
// criterion `.iter()` closure rather than `.iter_async()` or `.to_async(rt)`.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use heavything::net::runtime as ht_runtime;

// ============================================================================
// Module-level constants — bind address, response shape, and benchmark
// concurrency parameter set.
// ============================================================================

/// Bind address for the in-process benchmark server.
///
/// AAP §0.3.1.2 mandates `127.0.0.1:8443` for this benchmark. The port `8443`
/// is conventionally associated with HTTPS, but this benchmark uses plain HTTP
/// (TLS is intentionally out of scope so the measurement isolates the
/// epoll / async-I/O cost from the TLS handshake cost — separate aes_cbc and
/// sha256 benches cover the crypto cost).
const BIND_ADDR: &str = "127.0.0.1:8443";

/// Fixed response body size — 1 KiB per AAP §0.3.1.2.
///
/// Chosen to be small enough that the response fits in a single TCP segment
/// on a default-MTU loopback interface, eliminating segmentation overhead
/// from the per-iteration measurement.
const RESPONSE_BODY_SIZE: usize = 1024;

/// HTTP request issued by every iteration of both benchmarks.
///
/// Minimal valid HTTP/1.1 with `Connection: close` so the server-side handler
/// can `shutdown()` after a single response cycle without keep-alive or
/// pipelining state to manage. The fixed byte string is wrapped in
/// [`black_box`] at the call site to prevent constant-folding.
const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";

/// Concurrency levels for the concurrent-GET benchmark.
///
/// Per AAP §0.5.1.4 the webclient connection-pool default is 4 max
/// connections per host, so the levels are chosen to surface behaviour
/// below, at, and well above that pool size:
///
/// * `1` — establishes the no-contention baseline.
/// * `4` — matches the production webclient pool size.
/// * `16` — stresses the server beyond what the production client typically
///   inflicts (saturation behaviour visible in p95 / p99 percentiles).
const CONCURRENCY_LEVELS: &[usize] = &[1, 4, 16];

// ============================================================================
// Shared fixture — one tokio runtime + one HTTP server for the whole bench
// process (Phase 7 Approach A from the file's agent_prompt).
//
// Why a shared singleton?  Two reasons:
//   (1) Avoid re-binding `127.0.0.1:8443` between the sequential and concurrent
//       benchmark functions — a second `TcpListener::bind` of the same port
//       would panic with "Address already in use" while the first listener
//       is still alive.
//   (2) Match production topology: real heavything binaries (sshtalk, webserver,
//       hnwatch) construct the runtime once in `main()` and serve many
//       requests over its lifetime.  A shared runtime in the bench harness is
//       the closest analogue.
// ============================================================================

/// Shared bench-fixture state initialised exactly once via [`OnceLock`].
struct Fixture {
    /// Multi-threaded tokio runtime built via [`ht_runtime::build`] so the
    /// benchmark exercises the same runtime construction path used by
    /// production binaries (AAP §0.3.1.2 folder description: "MUST bench the
    /// `heavything` public API, NOT the underlying crates directly").
    rt: Runtime,

    /// Resolved server address — equal to `BIND_ADDR` (`127.0.0.1:8443`) once
    /// `local_addr()` succeeds. Stored as [`SocketAddr`] so both benchmark
    /// functions can pass it directly to [`TcpStream::connect`] without
    /// re-parsing.
    server_addr: SocketAddr,

    /// Graceful-shutdown handle for the server accept loop. Stored in a
    /// [`Mutex<Option<...>>`] purely to keep the move-only [`oneshot::Sender`]
    /// alive for the lifetime of the static fixture: dropping the sender
    /// would close the channel and signal the server task to exit, which we
    /// do NOT want during benchmark execution. The mutex is never locked
    /// during normal bench runs — the field is effectively a "keep-alive
    /// guard" for the sender. The leading underscore documents the
    /// fact that the field is intentionally not read at runtime.
    _shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

/// Acquire (or initialise on first call) the process-wide bench fixture.
///
/// The first call constructs:
///   1. A multi-threaded tokio [`Runtime`] via [`ht_runtime::build`].
///   2. A minimal HTTP/1.1 server bound to [`BIND_ADDR`] on that runtime.
///   3. A [`Fixture`] capturing the runtime, the bound address, and the
///      shutdown sender (held alive in a mutex to prevent server task exit).
///
/// All subsequent calls return the same `&'static Fixture`. Initialisation
/// failure (e.g., port 8443 already in use) panics — fail-fast is the
/// preferred behaviour per the agent_prompt: "the benchmark is expected to
/// be run on a host where 8443 is available".
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        // Build the tokio runtime through heavything's public API rather
        // than constructing it directly. This is the call site enumerated in
        // the schema's `internal_imports.members_accessed = ["build"]`.
        let rt = ht_runtime::build().expect("failed to build heavything tokio runtime");

        // Spawn the server on the runtime, capturing the shutdown sender,
        // the resolved bind address, and the server task's JoinHandle. The
        // JoinHandle is dropped (detached) here: tokio detached tasks
        // continue running until completion or runtime shutdown, which is
        // exactly the behaviour the bench needs.
        let (shutdown_tx, server_addr, _server_handle) = rt.block_on(spawn_server());

        Fixture {
            rt,
            server_addr,
            _shutdown_tx: Mutex::new(Some(shutdown_tx)),
        }
    })
}

// ============================================================================
// Server-side helpers — minimal HTTP/1.1 responder that bypasses the full
// `WebServer` 8-stage dispatch pipeline to isolate the epoll / async-I/O
// round-trip cost (AAP §0.3.1.2 folder description).
// ============================================================================

/// Bind the benchmark HTTP server and spawn its accept loop on the current
/// tokio runtime.
///
/// Returns the triple `(shutdown_sender, bound_addr, server_task_handle)`:
/// sending `()` on the shutdown sender drops the loop's
/// [`oneshot::Receiver`] half via [`tokio::select!`], causing the accept
/// loop to break and the task to complete. The [`JoinHandle`] permits the
/// caller to await graceful shutdown if desired (the bench's [`fixture`]
/// initialiser intentionally does not).
///
/// The server is intentionally minimal:
/// * Binds to [`BIND_ADDR`] (`127.0.0.1:8443`); fails fast if the port is
///   already in use.
/// * For each accepted connection, drains request bytes until the
///   `\r\n\r\n` end-of-headers marker, writes the pre-computed fixed
///   response, and shuts the stream down.
/// * Does NOT implement HTTP keep-alive, pipelining, chunked transfer
///   encoding, TLS, gzip / BREACH, file serving, or any other webserver
///   feature — all of which would confound the epoll-latency measurement
///   per the folder description.
async fn spawn_server() -> (oneshot::Sender<()>, SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(BIND_ADDR)
        .await
        .expect("failed to bind benchmark server to 127.0.0.1:8443");
    let addr = listener
        .local_addr()
        .expect("failed to query bound TcpListener local_addr");

    let (tx, mut rx) = oneshot::channel::<()>();

    let handle = tokio::spawn(async move {
        // Pre-compute the response body and full HTTP framing exactly once,
        // outside the accept loop, so that per-connection work is bounded to
        // a clone + write rather than re-formatting headers per request. The
        // formatter overhead would otherwise leak into the measured client
        // latency (the kernel cannot deliver bytes to the client until the
        // server's `write_all` completes).
        let body = vec![b'x'; RESPONSE_BODY_SIZE];
        let response = build_response(&body);

        loop {
            tokio::select! {
                // Shutdown signal wins over a fresh accept — guarantees the
                // task exits promptly when [`fixture`]'s `_shutdown_tx` is
                // eventually dropped at process tear-down.
                _ = &mut rx => break,
                accept = listener.accept() => {
                    let Ok((stream, _peer)) = accept else { continue; };
                    // Per-connection work is dispatched onto a fresh task so
                    // the accept loop is never blocked by a slow client.
                    // Tokio's multi-threaded runtime will run these tasks in
                    // parallel on its worker threads, matching the assembly
                    // baseline's per-fd parallelism.
                    let resp = response.clone();
                    tokio::spawn(handle_connection(stream, resp));
                }
            }
        }
    });

    (tx, addr, handle)
}

/// Build the fixed `HTTP/1.1 200 OK` response with the supplied body.
///
/// Pre-allocated with `128 + body.len()` capacity to fit the fixed header
/// block plus the body in a single allocation (avoids `Vec` re-grow during
/// `extend_from_slice`).
fn build_response(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(128 + body.len());
    v.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
    v.extend_from_slice(b"Server: heavything-bench\r\n");
    v.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
    v.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    v.extend_from_slice(b"Connection: close\r\n");
    v.extend_from_slice(b"\r\n");
    v.extend_from_slice(body);
    v
}

/// Per-connection handler — reads request bytes until end-of-headers, writes
/// the supplied response, then shuts down the stream.
///
/// Header parsing scans for the literal `\r\n\r\n` boundary marker only — no
/// method extraction, no host header validation, no `Content-Length` parse.
/// This is all the HTTP behaviour the benchmark requires; the raw-socket
/// design is the whole point of bypassing the production [`WebServer`]
/// pipeline (which would otherwise add 8-stage dispatch overhead per AAP
/// §0.3.1.2).
///
/// Defensive cap: requests exceeding 16 KiB without an end-of-headers marker
/// are silently dropped (return without writing). This guards against
/// pathological clients but never fires under the bench's own client which
/// sends a fixed ~60-byte request.
async fn handle_connection(mut stream: TcpStream, response: Vec<u8>) {
    let mut scratch = [0u8; 1024];
    let mut seen: Vec<u8> = Vec::with_capacity(512);
    loop {
        let n = match stream.read(&mut scratch).await {
            Ok(0) => return, // Peer closed before sending headers.
            Ok(n) => n,
            Err(_) => return, // I/O error — give up on this connection.
        };
        seen.extend_from_slice(&scratch[..n]);
        if seen.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if seen.len() > 16 * 1024 {
            return; // Defensively cap request header size.
        }
    }

    // Best-effort write + flush + shutdown: any error here means the client
    // disconnected mid-response, which is benign in a benchmark context. The
    // important invariant is that we do not panic — the server task must
    // remain alive across many thousands of iterations.
    let _ = stream.write_all(&response).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

// ============================================================================
// Sequential benchmark — one connection at a time, measures the no-contention
// HTTP round-trip latency (the headline p50 number).
// ============================================================================

/// Measure HTTP round-trip latency for a single in-flight request at a time.
///
/// Each iteration performs the full RTT path:
///   `connect → write request → flush → read response → close`.
///
/// Criterion's reported median (p50) and standard error are the primary
/// outputs consumed by `BENCHMARK_REPORT.md` (Gate 3); raw samples on disk
/// at `target/criterion/http_roundtrip_latency/sequential/` provide the
/// p95 / p99 percentiles.
fn bench_http_sequential(c: &mut Criterion) {
    let fx = fixture();
    let rt = &fx.rt;
    let server_addr = fx.server_addr;

    let mut group = c.benchmark_group("http_roundtrip_latency/sequential");
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    group.bench_function("single_get", |b| {
        b.iter(|| {
            // `rt.block_on` is the REQUIRED synchronous bridge per the file's
            // CRITICAL CONSTRAINT (criterion's `async_tokio` feature is NOT
            // enabled in workspace deps); using `.iter_async()` or
            // `.to_async(rt)` would require a forbidden dependency churn
            // (AAP §0.8.7).
            rt.block_on(async {
                let mut stream = TcpStream::connect(server_addr).await.unwrap();
                stream.write_all(black_box(REQUEST)).await.unwrap();
                stream.flush().await.unwrap();

                // 1536 bytes covers the full ~1100-byte response (1 KiB body
                // plus headers) without re-grow during `read_to_end`.
                let mut buf = Vec::with_capacity(1536);
                stream.read_to_end(&mut buf).await.unwrap();
                black_box(buf);
            });
        });
    });

    group.finish();

    // No teardown: the fixture intentionally outlives every benchmark function
    // and is dropped only at process exit (Phase 7 Approach A — see [`fixture`]
    // documentation above).
}

// ============================================================================
// Concurrent benchmark — multiple in-flight connections per iteration,
// surfaces saturation behaviour at and beyond the production webclient
// connection-pool size (AAP §0.5.1.4: 4 max connections per host).
// ============================================================================

/// Measure HTTP round-trip latency under varying client concurrency.
///
/// For each `N` in [`CONCURRENCY_LEVELS`] (`[1, 4, 16]`), each iteration
/// spawns `N` tokio tasks that simultaneously perform the same
/// `connect → write → read → close` cycle as the sequential benchmark, then
/// awaits all `N` completions before reporting the iteration's wall time.
///
/// Latency at `N=1` should match the sequential benchmark's median to within
/// noise. Latency at `N=4` reflects the typical production load. Latency at
/// `N=16` exposes server-side queueing behaviour visible in the per-iteration
/// p95 / p99 percentiles.
///
/// Sample size is reduced to 50 (vs. 100 for the sequential bench) because
/// each concurrent iteration takes proportionally longer; without this
/// adjustment criterion would target an unreasonable total bench duration.
fn bench_http_concurrent(c: &mut Criterion) {
    let fx = fixture();
    let rt = &fx.rt;
    let server_addr = fx.server_addr;

    let mut group = c.benchmark_group("http_roundtrip_latency/concurrent");
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(50);

    for &concurrency in CONCURRENCY_LEVELS {
        group.bench_with_input(
            BenchmarkId::from_parameter(concurrency),
            &concurrency,
            |b, &concurrency| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(concurrency);
                        for _ in 0..concurrency {
                            // `server_addr` is `Copy` (SocketAddr is Copy on
                            // every supported target), so `async move` here
                            // captures a fresh copy per spawned task — no
                            // shared mutable state across the N concurrent
                            // request tasks.
                            handles.push(tokio::spawn(async move {
                                let mut stream = TcpStream::connect(server_addr).await.unwrap();
                                stream.write_all(REQUEST).await.unwrap();
                                stream.flush().await.unwrap();
                                let mut buf = Vec::with_capacity(1536);
                                stream.read_to_end(&mut buf).await.unwrap();
                                buf
                            }));
                        }
                        // Awaiting each handle gates the iteration on the
                        // slowest of the N concurrent requests — that is the
                        // wall-clock latency criterion ultimately reports.
                        for h in handles {
                            let buf = h.await.unwrap();
                            black_box(buf);
                        }
                    });
                });
            },
        );
    }

    group.finish();

    // No teardown — see [`bench_http_sequential`] / [`fixture`] commentary.
}

// ============================================================================
// Criterion entry-points.
//
// `criterion_group!` aggregates the two benchmark functions into a single
// `benches` group. `criterion_main!` synthesises the `fn main()` entry point
// that `cargo bench --bench http_roundtrip` invokes (the `[[bench]]` entry in
// `crates/heavything/Cargo.toml` sets `harness = false`, deferring to
// criterion's harness instead of the default libtest harness).
// ============================================================================

criterion_group!(benches, bench_http_sequential, bench_http_concurrent);
criterion_main!(benches);
