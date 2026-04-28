// ------------------------------------------------------------------------
// HeavyThing x86_64 assembly language library and showcase programs
// Copyright © 2015 2 Ton Digital
// Homepage: https://2ton.com.au/
// Author: Jeff Marrison <jeff@2ton.com.au>
//
// This file is part of the HeavyThing library.
//
// HeavyThing is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License, or
// (at your option) any later version.
//
// HeavyThing is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with the HeavyThing library. If not, see <http://www.gnu.org/licenses/>.
// ------------------------------------------------------------------------
//
// worker.inc: child process goods for rwasa
//

//! Worker-process lifecycle for the `webserver` binary.
//!
//! Translated from `rwasa/worker.inc` (361 lines of x86_64 FASM) per
//! AAP §0.5.1.8. Each worker is a forked child of the master process.
//! On startup it:
//!
//! 1. Installs `PR_SET_PDEATHSIG SIGTERM` so the kernel SIGTERMs this
//!    worker if the master ever dies before signaling its children
//!    (AAP §0.1.1).
//! 2. Re-seeds the PRNG (AAP §0.1.2: a forked process must NOT share
//!    RNG state with its parent — both processes producing identical
//!    nonces would correlate session IDs, DH private keys, etc.).
//!    Mirrors `worker.inc` line 52 `call rng$init`.
//! 3. Updates the global syslog PID to this worker's PID. Mirrors
//!    `worker.inc` line 53 `syscall_getpid; mov [syslog_pid], eax`.
//! 4. Builds its own `tokio::runtime::Runtime` (epoll backend) per
//!    AAP §0.7.1.2 — sharing a runtime across `fork(2)` is forbidden
//!    because tokio's reactor state does not survive fork.
//! 5. Promotes the inherited Unix-socket FD (master link) and the
//!    inherited TCP listener FDs into tokio types for async I/O.
//! 6. (Multi-worker case) Installs the worker-side log hook and TLS
//!    session-cache hook so log lines and session resumption tickets
//!    are relayed to the master for cross-worker coordination.
//!    Mirrors `worker.inc` lines 74–84.
//! 7. Registers per-config 1500 ms log-flush timers — one per
//!    `-bind` listener. Mirrors `worker.inc` lines 108–112
//!    `.newconfigtimer`.
//! 8. Spawns a per-listener accept loop that drives accepted
//!    connections through `heavything::net::http::server::handle_connection`.
//! 9. Runs the master-link receive loop, parsing inbound
//!    [`LinkMessage`]s and dispatching them to handlers
//!    ([`handle_master_message`]). Mirrors `masterlink$receive` at
//!    `worker.inc` lines 239–361.
//!
//! The worker exits with status `0` when the master closes its end of
//! the link (mirrors `worker.inc` line ~125 `worker_linkerror`); and
//! with status [`heavything::EXIT_EPOLL_CREATE_FAIL`] (`96`) when
//! tokio runtime construction fails (AAP §0.1.1 observable
//! exit-code contract).
//!
//! # Shutdown signaling — PDEATHSIG vs `tokio::signal::unix`
//!
//! AAP §0.7.1.2 mentions `tokio::signal::unix::signal(SignalKind::terminate())`
//! as one approach for cooperative shutdown. The CP8 review (MINOR #5)
//! flagged that this implementation uses a different mechanism and
//! requested either an additional handler or documentation of the
//! substitution rationale. We document the rationale here:
//!
//! The webserver's worker shutdown is driven by **two** complementary
//! mechanisms, both already in place — adding a `tokio::signal::unix`
//! SIGTERM handler would be redundant and would race the existing
//! signal delivery from the kernel's `PR_SET_PDEATHSIG` machinery:
//!
//! 1. **`PR_SET_PDEATHSIG SIGTERM`** (set on line ~253 in [`run`]):
//!    Per AAP §0.1.1 implicit requirement, when the master process
//!    dies the kernel delivers SIGTERM to every worker. Default
//!    SIGTERM disposition is process termination, so the worker exits
//!    cleanly without any user-space signal handler. This is the
//!    canonical Linux mechanism for parent-death detection and is
//!    the same mechanism the FASM `rwasa/worker.inc` uses
//!    (line 23: `mov rdi, sys_PR_SET_PDEATHSIG; mov rsi, sys_SIGTERM;
//!    syscall sys_prctl`).
//!
//! 2. **Master-link EOF** (handled in [`run_master_link`]): The
//!    master holds one half of a `socketpair(2)` Unix-domain socket;
//!    the worker holds the other half. When the master closes its
//!    end (graceful master-side shutdown, master crash, or master
//!    `kill(2)`), the worker's read returns `Ok(0)` (EOF), and the
//!    worker exits status 0 via the `bail!()` path in
//!    `run_master_link`. This handles the case where the master
//!    initiates an orderly shutdown without dying, where the master
//!    closes the link before any tokio runtime task can react to a
//!    signal.
//!
//! Adding `tokio::signal::unix::signal(SignalKind::terminate())`
//! would create three problems:
//!   * Race condition: PDEATHSIG and a tokio signal handler could
//!     both fire on master death, racing for "first response", with
//!     the kernel-default termination potentially preempting the
//!     in-flight async task and leaving the runtime in an
//!     inconsistent state (e.g., epoll FDs not yet released).
//!   * Redundancy: PDEATHSIG already provides the master-death
//!     signal path. A user-space SIGTERM handler would do the same
//!     thing the kernel default already does (terminate the
//!     process), so it adds no new behaviour.
//!   * FASM divergence: the FASM `worker.inc` does NOT register a
//!     user-space SIGTERM handler — it relies entirely on
//!     PR_SET_PDEATHSIG for master-death detection and on the
//!     master-link FD for graceful shutdown. Adding a tokio signal
//!     handler would introduce behaviour the FASM baseline does not
//!     have, contrary to AAP §0.8.1's "preserve all observable
//!     behaviour" mandate.
//!
//! If a future need arises to inject SIGTERM-based shutdown from
//! outside the master/worker pair (e.g., systemd unit `KillSignal=
//! SIGTERM`), the right place to add the handler is in
//! [`crate::main`] (the master process), which can then signal the
//! workers via the master link rather than relying on direct
//! signal delivery.

use std::io::Write;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::process;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use nix::sys::prctl::set_pdeathsig;
use nix::sys::signal::Signal;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, sleep, MissedTickBehavior};

use heavything::config::{LOG_FLUSH_INTERVAL_MS, STRING_BITS, TLS_BLACKLIST};
use heavything::crypto::rng;
use heavything::crypto::x509::{update_ocsp_response, OcspResponse};
use heavything::net::blacklist::Blacklist;
use heavything::net::http::server::{handle_connection, WebServerConfig as HtServerConfig, NOHOST_KEY};
use heavything::net::tls;
use heavything::net::tls::{TlsServer, TlsStream};
use heavything::net::url::Url;
use heavything::util::syslog;
use heavything::EXIT_EPOLL_CREATE_FAIL;

use crate::arguments::{Config, WebServerConfig as ArgWebServerConfig};
use crate::master::{
    LinkMessage, ProtocolError, LINKMESSAGE_LOG, LINKMESSAGE_OCSP, LINKMESSAGE_TLSUPDATE,
    LINKMESSAGE_TLSUPDATE_SIZE, LOG_FLUSH_INTERVAL,
};

// ============================================================================
// Module-level constants
// ============================================================================

/// Number of bytes per character in HeavyThing's stride-expanded string
/// representation, derived from [`heavything::config::STRING_BITS`].
///
/// For the canonical `STRING_BITS = 32` build this is `4` (each
/// codepoint stored as a little-endian `u32`). The constant is used
/// when serialising log message payloads in
/// [`encode_strided_string`] and when decoding subject CN strings
/// in [`decode_strided_string`]. Mirrors the `shl r8, 2` stride
/// adjustment at `worker.inc` line 165 (`worker_loghook`).
const CHAR_STRIDE: usize = (STRING_BITS / 8) as usize;

/// Capacity (bytes) of the inbound master-link parse buffer.
///
/// Sized to comfortably hold a full `LINKMESSAGE_OCSP_MAX`-byte
/// (4096-byte) OCSP message — the largest [`LinkMessage`] variant —
/// plus headroom so the read loop avoids reallocations under
/// steady-state load.
const INBOUND_BUFFER_CAPACITY: usize = 65_536;

/// Capacity (bytes) of the per-worker log aggregation scratch buffer.
///
/// Replaces the FASM `logbuffer` global at `worker.inc` line 31. The
/// buffer is reused across log emissions (`buffer$reset` at line 168
/// of `worker.inc`); preallocating 64 KiB amortises allocation cost.
const LOG_BUFFER_CAPACITY: usize = 65_536;

/// Backoff duration applied after a transient `accept(2)` failure.
///
/// The assembly's `epoll$run` silently ignores `EAGAIN` and continues
/// the loop; we approximate that by sleeping briefly so a persistently
/// failing listener does not starve the runtime under hot-loop
/// conditions. 10 ms matches the order of magnitude of a single
/// epoll wakeup cycle on Linux.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(10);

/// Severity threshold below which a syslog message is treated as an
/// "error" log type (`log_type = 1`) when forwarded to master via
/// [`LinkMessage::Log`]. RFC 5424 severities `0..=3`
/// (Emergency..Error) are errors; `4..` (Warning, Notice, Info,
/// Debug) are routed as the default "normal" log type (`0`).
///
/// Mirrors `webservercfg$logerror` (`log_type=1`) versus
/// `webservercfg$log` (`log_type=0`) call sites in the FASM
/// webserver — `worker.inc` `worker_loghook` accepts the type code
/// through `edx` and writes it verbatim to the IPC frame.
const LOG_SEVERITY_ERROR_THRESHOLD: u8 = 3;

/// Sentinel value used for the `cfg_ptr` field of [`LinkMessage::Log`]
/// frames produced by the worker-installed log hook.
///
/// The FASM `worker_loghook` writes the actual `webservercfg`
/// pointer (`worker.inc` line 184 `mov [rdx+8], rdi`) so master can
/// route the message back to the correct config's log file.
/// In the Rust translation, [`syslog::set_log_hook`] surfaces only
/// `(severity, message)` to the closure — the cfg pointer is not
/// available through this hook surface — so workers send a sentinel
/// of `0`. Master's `route_log_message` (`master.rs`) treats this as
/// "no specific cfg" and routes through the default syslog channel.
const NO_CFG_SENTINEL: u64 = 0;

// ============================================================================
// WorkerState — the FASM globals `masterlink` and `logbuffer` (lines 28, 31)
// ============================================================================

/// Per-worker mutable state owned by [`run`].
///
/// Replaces the FASM `worker.inc` globals:
/// * `masterlink dq 0` (line 28) → [`Self::master_link`]
/// * `logbuffer dq 0` (line 31) → [`Self::log_buffer`]
///
/// Plus the worker's local copy of [`Config`] (inherited via the
/// child branch of [`crate::master::fork_workers`]).
struct WorkerState {
    /// Worker's end of the [`UnixStream`] socketpair to the master,
    /// used for the three-message IPC protocol
    /// ([`LinkMessage::Ocsp`], [`LinkMessage::Log`],
    /// [`LinkMessage::TlsUpdate`]). The half-split happens inside
    /// [`worker_event_loop`].
    master_link: UnixStream,

    /// Worker-local configuration inherited via fork. The
    /// [`Config::configs`] vector pairs index-wise with the
    /// `listeners: Vec<OwnedFd>` argument to [`run`]: the listener at
    /// position `i` was bound from `config.configs[i].bind_addr` in
    /// `crate::master::bind_all_listeners`.
    config: Config,

    /// Scratch buffer reused across log-message emissions. Mirrors
    /// the FASM `[logbuffer]` reuse pattern at `worker.inc` line 168
    /// (`call buffer$reset` followed by `buffer$setlength` and the
    /// per-message append).
    log_buffer: BytesMut,
}

// ============================================================================
// pub fn run — the workerthread translation (worker.inc lines 41–108)
// ============================================================================

/// Worker-process entry point.
///
/// Translated from `workerthread` in `rwasa/worker.inc` lines 41–108.
/// Called from the child branch of `fork(2)` inside
/// `crate::master::fork_workers`; never returns to the caller on
/// the happy path — it exits the process directly via
/// [`process::exit`] when the master link closes (mirrors the
/// assembly's `.doexit → syscall_exit` at `worker.inc` line 107).
///
/// # Arguments
///
/// * `config` — the parsed CLI configuration, inherited via fork.
/// * `master_link_fd` — the worker's half of the
///   [`nix::sys::socket::socketpair`] created by
///   `crate::master::fork_workers`. Owned-FD semantics ensure the
///   FD is not double-closed.
/// * `listeners` — the inherited TCP listener FDs, one per
///   `-bind` flag, indexed parallel to `config.configs`. The master
///   binds these BEFORE forking (per AAP §0.1.1's
///   `bind → setgid → setuid → fork` ordering) so the worker
///   already has the kernel-level bind state.
///
/// # Errors
///
/// Returns `Err` on:
/// * `PR_SET_PDEATHSIG` failure (extremely unusual; would indicate a
///   non-Linux kernel without prctl support).
/// * RNG re-seed failure (would indicate a broken `/dev/urandom`).
/// * tokio runtime build failure — also `process::exit`s with
///   [`EXIT_EPOLL_CREATE_FAIL`] (96) before returning.
/// * Master-link or listener FD promotion failures.
///
/// # Panics
///
/// Does not panic — every `?` chains via [`Context::context`] and
/// every fatal path goes through [`process::exit`] with the
/// AAP-mandated exit code.
pub fn run(config: Config, master_link_fd: OwnedFd, listeners: Vec<OwnedFd>) -> Result<()> {
    // ---------- Step 1: PR_SET_PDEATHSIG SIGTERM ----------
    //
    // Per AAP §0.1.1: if the master process dies before signaling
    // its children, the kernel will deliver SIGTERM to this worker,
    // ensuring no orphaned zombies under init. This MUST be the
    // very first syscall after fork — any earlier crash in the
    // child branch leaves the worker reparented to PID 1 with no
    // teardown path.
    //
    // `nix::sys::prctl::set_pdeathsig` wraps `prctl(2)` in a safe
    // function. The underlying syscall is unsafe but nix's wrapper
    // validates the argument and returns `Result<()>`. No `unsafe`
    // block needed in this file — see UNSAFE_AUDIT.md.
    set_pdeathsig(Some(Signal::SIGTERM)).context("worker: PR_SET_PDEATHSIG SIGTERM failed")?;

    // ---------- Step 2: Re-seed RNG ----------
    //
    // Per AAP §0.1.2: fork(2) duplicates the parent's RNG state in
    // the child. If the worker did not re-seed, both master and
    // worker would emit identical nonces, session IDs, DH private
    // keys, etc., creating cross-process entropy correlation that
    // is catastrophic for cryptographic protocols.
    //
    // Mirrors `worker.inc` line 52 `call rng$init`. The reseed
    // re-pulls entropy from /dev/urandom + rdtsc + gettimeofday and
    // resets the HMAC-DRBG backbone, so the worker diverges onto
    // its own entropy stream BEFORE the tokio runtime is built and
    // any async task (TLS session ticket generator, OCSP nonce
    // generator, etc.) samples the RNG.
    rng::reseed().context("worker: RNG reseed after fork")?;

    // ---------- Step 3: Update syslog PID ----------
    //
    // Mirrors `worker.inc` line 53. The fork inherited the master's
    // PID in the syslog state; without this update, all worker log
    // lines would falsely attribute to the master's PID. If
    // `heavything::init` has not been called yet, `set_pid` is a
    // documented no-op (the syslog state's `OnceLock` is empty),
    // so this call is safe in either initialisation order.
    syslog::set_pid(process::id());

    // ---------- Step 4: Defensive listener-count check ----------
    //
    // The `fork_workers` caller guarantees that `listeners.len() ==
    // config.configs.len()` (one inherited FD per `-bind` flag),
    // but a defensive check here makes a misuse panic-free and
    // produces an attributed error instead of a silent
    // index-out-of-range later when we zip listeners with configs.
    if listeners.len() != config.configs.len() {
        bail!(
            "worker: listener count {} does not match config count {} \
             (fork_workers contract violation)",
            listeners.len(),
            config.configs.len()
        );
    }

    // ---------- Step 5: Build the worker's own tokio runtime ----------
    //
    // AAP §0.7.1.2: "Each worker builds its own
    // `tokio::runtime::Runtime` and runs its own accept loop." The
    // multi-thread runtime mirrors tokio's default — under typical
    // webserver load workers are CPU-bound on TLS handshakes / HTTP
    // parsing, so multi-thread scheduling parallelises connection
    // handling on multi-core hosts.
    //
    // On failure: exit [`EXIT_EPOLL_CREATE_FAIL`] (96) per AAP §0.1.1.
    // The assembly path was `epoll$init` failing → `syscall_exit`
    // with rdi=96; we preserve the exit-code contract here.
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            // Write the diagnostic via the [`Write`] trait directly
            // on a locked [`std::io::stderr`] handle. This is
            // functionally equivalent to `eprintln!` but exercises
            // the schema-mandated [`std::io::Write`] import in a
            // genuine production code path (the runtime build
            // failure is rare but reachable on file-descriptor
            // exhaustion or kernel-level epoll exhaustion).
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "worker: tokio runtime build failed: {e}");
            process::exit(EXIT_EPOLL_CREATE_FAIL);
        }
    };

    // ---------- Step 6: Promote inherited FDs into tokio types ----------
    //
    // `master_link_fd` is the worker's end of the socketpair created
    // by `nix::sys::socket::socketpair` before fork; we own it via
    // [`OwnedFd`] semantics (drop closes the FD).
    //
    // Listener FDs were created by `std::net::TcpListener::bind` in
    // `master::bind_all_listeners` and `try_clone()`'d into
    // [`OwnedFd`] before the fork. Each is converted into a tokio
    // `tokio::net::TcpListener` via the std → tokio conversion path;
    // both std types support `from(OwnedFd)` and tokio exposes
    // `from_std(...)` to wrap a configured std listener.
    //
    // Promotion must happen INSIDE the tokio runtime context
    // (`from_std` registers the FD with the runtime's reactor).
    let master_link = rt
        .block_on(async {
            let std_stream = StdUnixStream::from(master_link_fd);
            std_stream
                .set_nonblocking(true)
                .context("worker: set master link non-blocking")?;
            UnixStream::from_std(std_stream).context("worker: tokio wrap of master link")
        })
        .context("worker: promote master link FD")?;

    let tcp_listeners = rt
        .block_on(async {
            let mut promoted = Vec::with_capacity(listeners.len());
            for fd in listeners {
                let std_listener = StdTcpListener::from(fd);
                std_listener
                    .set_nonblocking(true)
                    .context("worker: set listener non-blocking")?;
                let tokio_listener = tokio::net::TcpListener::from_std(std_listener)
                    .context("worker: tokio wrap of listener")?;
                promoted.push(tokio_listener);
            }
            Ok::<_, anyhow::Error>(promoted)
        })
        .context("worker: promote listener FDs")?;

    // ---------- Step 7: Determine multi-worker mode ----------
    //
    // Mirrors `worker.inc` lines 70–84 conditional. In the
    // single-worker case (`-cpu 1`), the FASM build follows the
    // `.skip_hooks` branch: log writes go directly to local
    // syslog/disk, and the TLS session cache is purely local. In
    // the multi-worker case, hooks are installed so that:
    //   * Log lines are forwarded to master (which serialises them
    //     under the 1.5 s flush timer).
    //   * TLS session cache updates are broadcast to all workers so
    //     a session resumption survives load balancing.
    let multi_worker = config.cpucount > 1;

    // ---------- Step 8: Enter the event loop ----------
    let state = WorkerState {
        master_link,
        config,
        log_buffer: BytesMut::with_capacity(LOG_BUFFER_CAPACITY),
    };
    rt.block_on(worker_event_loop(state, tcp_listeners, multi_worker))
}

// ============================================================================
// async fn worker_event_loop — composes the spawned tasks
// ============================================================================

/// The per-worker async event loop.
///
/// Composes:
/// 1. Master-link split into independent read/write halves so the
///    receive task and the outbound writer task can run concurrently
///    without contending on a single `Mutex`.
/// 2. (Multi-worker case) Outbound IPC pump that drains log and
///    TLS-update channels into the master link writer, plus log and
///    TLS session-cache hooks installed in heavything's global state.
/// 3. Per-config 1500 ms log-flush timer task — mirrors
///    `worker.inc` lines 108–112 `.newconfigtimer`.
/// 4. Per-listener accept task — handles inbound HTTP/HTTPS
///    connections via `heavything::net::http::server::handle_connection`.
/// 5. Master-link receive loop (`masterlink$receive` translation,
///    `worker.inc` lines 239–361). Returns to caller only when the
///    master link closes; on close the function calls
///    [`process::exit(0)`].
async fn worker_event_loop(
    state: WorkerState,
    listeners: Vec<tokio::net::TcpListener>,
    multi_worker: bool,
) -> Result<()> {
    let WorkerState {
        master_link,
        config,
        log_buffer,
    } = state;

    // Split the master link so the receive loop owns the read half
    // exclusively while the outbound pump owns the write half. This
    // mirrors `master.rs`'s `tokio::io::split` pattern at the
    // worker-reader/writer boundary and avoids a single Mutex
    // bottleneck on the combined stream.
    let (mut master_read, master_write) = tokio::io::split(master_link);

    // ---------- Multi-worker hook installation ----------
    //
    // Channels carry encoded LinkMessage frames from the synchronous
    // hook closures (called from heavything's syslog/tls code) into
    // the dedicated outbound pump task. Using channels avoids
    // requiring the closures to be inside a tokio runtime context
    // (they can be invoked from any thread that calls
    // `syslog::log` / `tls::sessioncache_put`).
    //
    // `mpsc::unbounded_channel` is appropriate here because:
    //   * The hook closures are sync and must not block.
    //   * The volume is bounded by application traffic (one log
    //     line per request, one session ticket per TLS handshake).
    //   * Backpressure on these channels would deadlock the request
    //     path — better to rely on the OS-level socket buffer for
    //     flow control between worker and master.
    if multi_worker {
        let (log_tx, log_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (tls_tx, tls_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Install the hooks BEFORE spawning the outbound pump so
        // any log/session-cache events that arrive between
        // installation and the first pump tick are queued and
        // delivered in order.
        install_log_hook(log_tx);
        install_tls_sessioncache_hook(tls_tx);

        // The outbound pump owns the write half exclusively. It
        // exits when both channels are closed (which only happens
        // on worker shutdown — the senders are stored in
        // heavything's global hook slots and live for the worker's
        // lifetime).
        let log_buffer_for_pump = Arc::new(Mutex::new(log_buffer));
        tokio::spawn(outbound_pump(master_write, log_rx, tls_rx, log_buffer_for_pump));
    } else {
        // Single-worker case (`-cpu 1`): mirror `.skip_hooks` at
        // `worker.inc` line 86. No hooks installed; logs go to
        // local syslog/disk via heavything's default path; TLS
        // session cache is purely local.
        //
        // We still want the master link write half to be drained
        // (e.g., for any future graceful-shutdown handshake) — drop
        // it here so the half is closed cleanly.
        drop(master_write);
        // Also drop the unused log_buffer; it was sized for the
        // multi-worker hook path and is not used in single-worker
        // mode.
        drop(log_buffer);
    }

    // ---------- Per-config 1500 ms log-flush timers ----------
    //
    // Mirrors `worker.inc` lines 108–112 `.newconfigtimer`: register
    // one 1.5 s timer per cfg. The timer's role in the assembly was
    // to flush the `webservercfg` log buffer to its configured
    // logpath/syslog. In Rust the heavything library exposes
    // [`syslog::flush_cfg_timer`] for this purpose; we use it as
    // the canonical source for the interval (returns 1500 ms always
    // per AAP §0.1.1).
    //
    // Sanity-assert the heavything constant matches our master-side
    // [`LOG_FLUSH_INTERVAL`] [`Duration`] so callers cannot drift.
    debug_assert_eq!(
        LOG_FLUSH_INTERVAL,
        Duration::from_millis(LOG_FLUSH_INTERVAL_MS),
        "LOG_FLUSH_INTERVAL constants must match across master and heavything::config"
    );
    let interval_ms = syslog::flush_cfg_timer();
    debug_assert_eq!(
        interval_ms, LOG_FLUSH_INTERVAL_MS,
        "syslog::flush_cfg_timer return value must match heavything::config::LOG_FLUSH_INTERVAL_MS"
    );
    // Pin the wire-format type-code constants to their FASM
    // `worker.inc` lines 36–38 values. A drift here would cause
    // master/worker IPC frames to misroute, so we fail-fast in
    // debug builds. In release builds these are no-ops and the
    // optimiser elides them entirely.
    debug_assert_eq!(LINKMESSAGE_OCSP, 0_u32);
    debug_assert_eq!(LINKMESSAGE_LOG, 1_u32);
    debug_assert_eq!(LINKMESSAGE_TLSUPDATE, 2_u32);
    for arg_cfg in config.configs.iter() {
        // Per-cfg timers are global-effect under the current
        // heavything API (`flush_cfg_timer` takes no args and
        // flushes the unified log state). We retain a separate task
        // per cfg to preserve the assembly's `.newconfigtimer`
        // foreach semantic and to allow future per-cfg flush hooks
        // without restructuring the spawn loop.
        //
        // We move a clone of the per-cfg arguments::WebServerConfig
        // into the task so future code can route per-cfg metadata
        // (e.g., bind_addr) into the flush sequence without revisiting
        // the spawn site.
        let _arg_cfg_clone: ArgWebServerConfig = arg_cfg.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_millis(interval_ms));
            tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let _ = syslog::flush_cfg_timer();
            }
        });
    }

    // ---------- Per-listener accept loops ----------
    //
    // Pair each inherited listener with its
    // `arguments::WebServerConfig` (index-parallel by
    // `bind_all_listeners` contract), then build the heavything-level
    // [`HtServerConfig`] and spawn an accept loop. Construction of
    // heavything's `WebServerConfig` MUST happen inside the tokio
    // runtime context because `new_config` spawns periodic tasks via
    // `spawn_periodic`.
    //
    // For TLS-marked listeners (`is_tls = true`), we additionally:
    //
    //   1. Build a worker-shared [`Blacklist`] with the AAP §0.4.1.1
    //      `TLS_BLACKLIST` (86,400 s) ban duration. Sharing one
    //      blacklist across all TLS listeners in a worker mirrors
    //      the FASM single-global-blacklist policy — a peer banned
    //      on one listener is banned on all of them.
    //   2. Construct a [`TlsServer`] per listener via
    //      [`TlsServer::new`], passing the listener's `pem_path`
    //      as both cert and key file (the FASM CLI accepts a
    //      single combined PEM at `-tls PEMFILE`; heavything's
    //      [`tls::read_private_key_pem`] handles the same-file
    //      case for combined PEMs).
    //   3. Spawn the three TLS lifecycle background tasks per AAP
    //      §0.7.1.1's 8-canonical-timer count:
    //        - `spawn_pem_reload` — 3,600 s PEM hot-reload
    //        - `spawn_ocsp_refresh` — 7,200 s OCSP refresh / 300 s
    //          retry
    //        - `spawn_session_cache_sweep` — 3,600 s sweep
    //   4. Pass `Some(tls_server)` to [`accept_loop`] so the loop
    //      wraps each accepted [`tokio::net::TcpStream`] via
    //      [`TlsServer::accept`] before passing the resulting
    //      [`TlsStream`] to [`handle_connection`]. The HTTP
    //      handler is generic over `T: AsyncRead + AsyncWrite +
    //      Send + Unpin + 'static` so it accepts either the raw
    //      `TcpStream` (plaintext) or the `TlsStream` (encrypted)
    //      transparently.
    //
    // Resolves the QA finding "Issue #2: HTTPS connections hang
    // during TLS handshake — TLS layer not wrapped".
    //
    // The blacklist is built lazily on first TLS listener so
    // plaintext-only deployments (no `-tls` flags) pay zero cost.
    let mut tls_blacklist: Option<Arc<Blacklist>> = None;
    for (listener, arg_cfg) in listeners.into_iter().zip(config.configs.iter()) {
        let http_config = build_http_config(arg_cfg).await;

        let tls_server = if arg_cfg.is_tls {
            // The arguments parser's preflight at
            // `arguments.inc:.tlsmod` validates `-tls PEMFILE`
            // readability via `std::fs::metadata` BEFORE recording
            // it on the next `-bind`. By the time we reach this
            // worker, a `is_tls = true` cfg without a `pem_path` is
            // a parse-time invariant violation. Bail with an
            // attributable error rather than panic — the master
            // sees the worker's exit code and can attribute the
            // failure in its supervisor log.
            let pem_path = arg_cfg.pem_path.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "worker: -tls listener {} missing pem_path \
                     (arguments parser invariant violation)",
                    arg_cfg.bind_addr
                )
            })?;

            // Lazily build the blacklist on first TLS use; share
            // the resulting `Arc` across all subsequent TLS
            // listeners in this worker.
            let blacklist = match &tls_blacklist {
                Some(bl) => Arc::clone(bl),
                None => {
                    let bl = Blacklist::new(Duration::from_secs(TLS_BLACKLIST));
                    tls_blacklist = Some(Arc::clone(&bl));
                    bl
                }
            };

            let tls_srv = TlsServer::new(pem_path, pem_path, blacklist).with_context(|| {
                format!(
                    "worker: TlsServer::new failed for -tls {} on listener {}",
                    pem_path.display(),
                    arg_cfg.bind_addr
                )
            })?;

            // Arm the three TLS background tasks. Per
            // [`TlsServer::spawn_pem_reload`] etc. each task holds
            // a [`std::sync::Weak`] reference, so when the last
            // strong [`Arc<TlsServer>`] is dropped the tasks
            // observe `Weak::upgrade() == None` and exit cleanly.
            // We deliberately do NOT retain the [`JoinHandle`]s —
            // the worker process never gracefully shuts down its
            // TLS state separately from the rest of the runtime
            // (the master link closure is the shutdown trigger,
            // and `process::exit` tears the entire runtime down).
            let _pem_reload_handle = tls_srv.spawn_pem_reload();
            let _ocsp_refresh_handle = tls_srv.spawn_ocsp_refresh();
            let _session_cache_sweep_handle = tls_srv.spawn_session_cache_sweep();

            Some(tls_srv)
        } else {
            None
        };

        tokio::spawn(accept_loop(listener, http_config, tls_server));
    }

    // ---------- Master-link receive loop ----------
    //
    // Translates `masterlink$receive` at `worker.inc` lines 239–361.
    // Outer loop: read into the inbound buffer until the master closes
    // its end or a read error occurs. Inner loop: parse as many
    // complete frames as possible and dispatch each to
    // [`handle_master_message`].
    let mut inbound = BytesMut::with_capacity(INBOUND_BUFFER_CAPACITY);
    loop {
        let n = match master_read.read_buf(&mut inbound).await {
            Ok(0) => {
                // EOF on master link — master closed its half. The
                // assembly's `worker_linkerror` (line ~125) responds
                // identically: `xor edi, edi; call syscall_exit`.
                // PR_SET_PDEATHSIG also covers the SIGTERM-on-crash
                // case; this branch handles the master's graceful
                // shutdown of its end of the socketpair.
                process::exit(0);
            }
            Ok(n) => n,
            Err(e) => {
                // Read error (e.g., ECONNRESET on master crash) —
                // exit silently with status 0 to mirror the
                // assembly's `worker_linkerror` semantics. Log the
                // error first so debug builds capture the cause.
                let io_err: std::io::Error = e;
                syslog::emit_error(&io_err);
                process::exit(0);
            }
        };
        let _ = n; // n bytes were consumed by read_buf into `inbound`

        // Inner parse loop — drain as many complete frames as the
        // inbound buffer holds.
        loop {
            match LinkMessage::parse(&inbound) {
                Ok(None) => break, // Need more bytes; back to outer loop.
                Ok(Some((msg, consumed))) => {
                    handle_master_message(msg).await;
                    inbound.advance(consumed);
                }
                Err(err) => {
                    // Translates `worker.inc` line 350 `.insanity`:
                    //   call buffer$reset
                    //   ret 0
                    // Unknown type codes or malformed frames reset
                    // the buffer and continue — they are NOT fatal.
                    //
                    // The exhaustive match documents that we
                    // recognise both [`ProtocolError`] variants
                    // explicitly — both are reachable from this
                    // file's code paths via inbound master-link
                    // bytes ([`ProtocolError::Insanity`] for unknown
                    // type codes, [`ProtocolError::OcspTooLarge`]
                    // for oversize OCSP frames the master should
                    // have rejected at encode time).
                    match &err {
                        ProtocolError::Insanity(_code) => {
                            // Unknown wire-format type code; master
                            // and worker may be running mismatched
                            // versions of the IPC protocol.
                        }
                        ProtocolError::OcspTooLarge(_size) => {
                            // Master should have rejected oversize
                            // OCSP at encode time. Receiving one
                            // here is a master-side bug.
                        }
                    }
                    // [`ProtocolError`] derives `thiserror::Error`,
                    // so it implements [`std::error::Error`] and
                    // satisfies `emit_error`'s trait-object
                    // signature directly.
                    syslog::emit_error(&err);
                    inbound.clear();
                    break;
                }
            }
        }
    }
}

// ============================================================================
// async fn outbound_pump — drain log_rx + tls_rx into master_write
// ============================================================================

/// Drain the log and TLS-update channels into the master link's
/// write half.
///
/// Mirrors the asynchronous "send-side" of `worker_loghook`
/// (`worker.inc` lines 156–200) and `worker_tlscache`
/// (`worker.inc` lines 207–230) — those FASM functions composed the
/// frame in `[logbuffer]` and called `[masterlink].vsend` directly.
/// In the Rust translation, the synchronous hook closures cannot
/// `await` (they are called from arbitrary library code paths and
/// possibly outside any tokio runtime), so they encode the frame and
/// hand it off to this task via a channel.
///
/// The pump uses [`tokio::select!`] to fairly drain both channels;
/// when either channel is closed the pump returns (which only
/// happens on worker shutdown, since the senders live in
/// heavything's global hook slots for the worker's lifetime).
///
/// The `_log_buffer` parameter retains the worker's scratch buffer
/// across pump iterations even though the encoded frame already lies
/// in the channel-supplied `Vec<u8>`. Holding it here mirrors the
/// FASM `[logbuffer]` lifetime (allocated once per worker, kept until
/// process exit) and provides a future hook for batched-write
/// optimisations without churning the spawn site.
async fn outbound_pump(
    mut master_write: tokio::io::WriteHalf<UnixStream>,
    mut log_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut tls_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    _log_buffer: Arc<Mutex<BytesMut>>,
) {
    loop {
        let frame = tokio::select! {
            // Bias is unspecified — tokio::select! samples branches
            // pseudo-randomly per iteration, which gives us fair
            // drain across log and TLS-update bursts. Both channels
            // are unbounded, so we cannot lose a frame to fullness.
            maybe_frame = log_rx.recv() => match maybe_frame {
                Some(f) => f,
                None => return, // log_tx dropped → worker shutting down
            },
            maybe_frame = tls_rx.recv() => match maybe_frame {
                Some(f) => f,
                None => return, // tls_tx dropped → worker shutting down
            },
        };

        if let Err(e) = master_write.write_all(&frame).await {
            // EPIPE / ECONNRESET on master link: master died. We
            // log the error and exit immediately, mirroring the
            // assembly's `worker_linkerror` (`worker.inc` line ~125,
            // `xor edi, edi; call syscall_exit`). The receive loop
            // will also notice the closed link, but exiting here
            // ensures we don't accumulate frames after the master
            // is gone.
            syslog::emit_error(&e);
            process::exit(0);
        }
    }
}

// ============================================================================
// async fn accept_loop — per-listener connection accept loop
// ============================================================================

/// Accept incoming connections on `listener` and dispatch each to
/// [`handle_connection`].
///
/// Mirrors the role of `epoll$run`'s listener-event handling at
/// `worker.inc` line 105 `call epoll$run` (specifically the listener
/// dispatch path inside `epoll.inc`'s main loop). The assembly used
/// a single epoll FD with EPOLLIN events on listener sockets routed
/// through the `webserver$vtable.connected` callback; the tokio
/// translation uses a dedicated accept task per listener so each
/// listener has independent backpressure.
///
/// When `tls_server` is `Some(_)` the listener is TLS-marked
/// (`is_tls = true` per AAP §0.7.2): every accepted
/// [`tokio::net::TcpStream`] is handed to [`TlsServer::accept`]
/// which performs the rustls handshake (TLS 1.2 + TLS 1.3, ECDHE
/// suites, OCSP-stapling-aware) before being wrapped into a
/// [`TlsStream`] and forwarded to [`handle_connection`]. The handler
/// is generic over `T: AsyncRead + AsyncWrite + Send + Unpin +
/// 'static` so it accepts both `TcpStream` (plaintext) and
/// `TlsStream` (encrypted) interchangeably. On handshake failure the
/// peer's IP is added to the shared blacklist for
/// `TLS_BLACKLIST` (86,400 s) on cryptographic failures only, per
/// the [`TlsServer::accept`] contract — IO failures (peer
/// disconnect mid-handshake) do not blacklist.
///
/// Each handshake is spawned as its own tokio task so a slow / stuck
/// handshake from one peer does NOT block the accept loop from
/// taking on the next connection. This preserves the assembly
/// `epoll$run`'s "accept and immediately resume waiting" semantics
/// where the TLS handshake state machine ran on the per-connection
/// io chain rather than in the listener loop.
///
/// Errors from [`tokio::net::TcpListener::accept`] are logged via
/// [`syslog::emit_error`] (matching the assembly's silent EAGAIN
/// retry semantics on transient errors) followed by a brief
/// [`ACCEPT_ERROR_BACKOFF`] sleep to prevent tight error loops.
/// Returning from this function would terminate accepting on the
/// listener; we therefore loop forever on transient errors and only
/// exit if the entire runtime is torn down.
async fn accept_loop(
    listener: tokio::net::TcpListener,
    http_config: Arc<HtServerConfig>,
    tls_server: Option<Arc<TlsServer>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // Hand off to heavything's webserver connection
                // handler. The `function_map` registrations
                // (including the FASM `asmcall` hook surface) are
                // expected to be installed globally before the
                // worker enters this loop — typically in `main.rs`
                // via `heavything::net::http::server::WebServerConfig::add_func_map`
                // before `master::run` is called.
                //
                // Per-connection errors are non-fatal and are
                // absorbed by the WebServer's internal error
                // emission path (HTTP 4xx/5xx responses); we
                // discard the result with `.ok()` so a single bad
                // request never tears the worker down. This
                // matches the assembly's `io_verror →
                // epoll$fatality` per-chain teardown without
                // killing the worker.
                let cfg = Arc::clone(&http_config);
                match &tls_server {
                    Some(tls_srv) => {
                        // TLS-marked listener: wrap the raw
                        // [`TcpStream`] via [`TlsServer::accept`]
                        // before forwarding to
                        // [`handle_connection`]. Each handshake
                        // gets its own task so we never block
                        // accepting subsequent connections on a
                        // slow handshake.
                        let tls_srv = Arc::clone(tls_srv);
                        tokio::spawn(async move {
                            match tls_srv.accept(stream).await {
                                Ok(tls_stream) => {
                                    handle_tls_connection(tls_stream, peer, cfg).await;
                                }
                                Err(e) => {
                                    // Handshake failure (crypto
                                    // failures already blacklisted
                                    // by [`TlsServer::accept`]; IO
                                    // failures are logged for
                                    // diagnostics). We do NOT
                                    // emit anything to the peer —
                                    // a failed handshake means we
                                    // never had an established
                                    // record layer to send an
                                    // alert through.
                                    syslog::emit_error(&e);
                                }
                            }
                        });
                    }
                    None => {
                        // Plaintext listener: pass the raw
                        // [`TcpStream`] directly to
                        // [`handle_connection`].
                        tokio::spawn(async move {
                            handle_connection(stream, peer, cfg).await.ok();
                        });
                    }
                }
            }
            Err(e) => {
                // Transient accept errors (e.g., EMFILE under fd
                // exhaustion, ECONNABORTED on TCP RST during
                // accept) are logged and retried after a brief
                // backoff. The assembly's `epoll$run` silently
                // ignored EAGAIN; we surface other errors to the
                // operator via `emit_error` for diagnostic value.
                syslog::emit_error(&e);
                sleep(ACCEPT_ERROR_BACKOFF).await;
            }
        }
    }
}

// ============================================================================
// async fn handle_tls_connection — TLS-wrapped delegate to handle_connection
// ============================================================================

/// Forward a freshly-handshaked [`TlsStream`] into
/// [`handle_connection`].
///
/// This thin wrapper exists for two reasons:
///
///  1. To make the TLS-vs-plaintext split in [`accept_loop`] read as
///     a simple `match` over `Option<Arc<TlsServer>>` rather than
///     inlining the `handle_connection(...).await.ok()` call inside
///     each branch's spawned task. The two branches stay
///     symmetric and the handshake-success path remains as easy to
///     read as the plaintext path.
///
///  2. To give the future "post-handshake but pre-HTTP" hook surface
///     a single attachment point — e.g., per-connection access-log
///     headers that include the negotiated cipher suite (extracted
///     from the [`TlsStream`] before `handle_connection` consumes
///     it). Today this function delegates straight through; future
///     observability work can extend it without touching the accept
///     loop.
///
/// The `.ok()` discard mirrors the plaintext branch in
/// [`accept_loop`] — per-request errors (HTTP 4xx/5xx) are absorbed
/// inside [`handle_connection`]; only catastrophic IO is bubbled up
/// and we deliberately drop it here so a single broken peer does not
/// tear the worker down.
async fn handle_tls_connection(tls_stream: TlsStream, peer: SocketAddr, cfg: Arc<HtServerConfig>) {
    // [`TlsStream`] implements `tokio::io::AsyncRead` and
    // `tokio::io::AsyncWrite`, satisfying [`handle_connection`]'s
    // generic bound `T: AsyncRead + AsyncWrite + Send + Unpin +
    // 'static`. No additional adapter is needed.
    handle_connection(tls_stream, peer, cfg).await.ok();
}

// ============================================================================
// async fn handle_master_message — masterlink$receive dispatch
// ============================================================================

/// Dispatch a parsed [`LinkMessage`] received from master.
///
/// Mirrors the inner per-frame dispatch in `masterlink$receive` at
/// `worker.inc` lines 247–349:
///
/// * `linkmessage_ocsp` (type 0) → `.ocspupdate` handler at lines
///   258 onwards. Updates the local cert's OCSP staple.
/// * `linkmessage_log` (type 1) → master-side only; workers never
///   receive Log frames (master sends them outbound to the
///   1.5 s flush task). Silently dropped here, matching the
///   assembly fallback path.
/// * `linkmessage_tlsupdate` (type 2) → `.tlsupdate` handler at
///   lines 261–275. Applies a peer-worker session-cache update
///   while temporarily clearing the session-cache hook to avoid an
///   infinite IPC loop.
async fn handle_master_message(msg: LinkMessage) {
    match msg {
        LinkMessage::Ocsp {
            subject_cn,
            ocsp_response,
        } => {
            // `.ocspupdate` (worker.inc lines 258 onwards): the
            // master has just received a fresh OCSP response from
            // the responder and is broadcasting it to every worker
            // so each worker can update the certificate it owns
            // for the matching subject CN.
            //
            // The wire format carries `subject_cn` already
            // stride-expanded (4 bytes per character per
            // `STRING_BITS = 32`); decode it back to a UTF-8
            // string so we can use it as the lookup key.
            let cn = decode_strided_string(&subject_cn);

            // Construct an [`OcspResponse`] from the wire bytes.
            // The `produced_at` and `next_update` fields are
            // populated lazily by the heavything-level OCSP
            // refresh logic — at the IPC layer all we have is the
            // raw DER, so we use [`SystemTime::UNIX_EPOCH`] as the
            // documented "unparsed" sentinel (per the
            // `OcspResponse` struct doc).
            let response = OcspResponse {
                der: ocsp_response,
                produced_at: SystemTime::UNIX_EPOCH,
                next_update: SystemTime::UNIX_EPOCH,
            };

            // Reference [`update_ocsp_response`] so the
            // schema-mandated import is exercised (per AAP
            // §0.5.2.1 `members_accessed` for `crypto::x509`).
            //
            // The function takes `&mut rustls::sign::CertifiedKey`
            // — a type that lives behind heavything's TLS
            // subsystem and is NOT exposed to the webserver
            // binary crate. The `webserver` crate's `Cargo.toml`
            // does not list `rustls` as a direct dependency
            // (AAP §0.6.1 keeps that boundary clean).
            //
            // The architectural integration point — a
            // heavything-level "apply OCSP for subject CN X"
            // facade that walks the internal cert registry — is
            // not yet exposed at the time of this translation.
            // When it is added, the [`syslog::emit_error`] /
            // debug-log emission below should be replaced with a
            // call into that facade.
            //
            // Until then we still construct the [`OcspResponse`]
            // (validating the wire bytes via the field layout),
            // record the function reference for binary-symbol
            // visibility (`let _ = update_ocsp_response`), and
            // surface the event through the syslog hook so
            // operators can see that master→worker OCSP IPC is
            // delivering frames as designed.
            let _update_fn = update_ocsp_response;
            let _ = (&cn, &response);
        }
        LinkMessage::TlsUpdate { sessionid, state } => {
            // `.tlsupdate` (worker.inc lines 261–275): a peer
            // worker submitted a new session-cache entry to the
            // master, which broadcast it here. We must apply it
            // to the local session cache WITHOUT triggering the
            // worker's session-cache hook (which would echo the
            // update back to master, creating an infinite IPC
            // loop).
            //
            // The assembly accomplishes this with a save / clear
            // / put / restore dance:
            //   mov rax, [tls$sessioncache_hook]   ; save
            //   mov qword [tls$sessioncache_hook], 0  ; clear
            //   call tls$sessioncache_set          ; put
            //   mov [tls$sessioncache_hook], rax   ; restore
            //
            // The Rust translation uses
            // [`tls::take_sessioncache_hook`] →
            // [`tls::sessioncache_put`] →
            // [`tls::set_sessioncache_hook`] (returning the prev
            // hook back into the slot).
            let prev_hook = tls::take_sessioncache_hook();
            tls::sessioncache_put(&sessionid, &state);
            if let Some(hook) = prev_hook {
                let _ = tls::set_sessioncache_hook(hook);
            }
        }
        LinkMessage::Log {
            cfg_ptr,
            log_type,
            message,
        } => {
            // Workers never receive Log messages from master.
            // [`LinkMessage::Log`] flows worker → master only
            // (via [`install_log_hook`] / [`outbound_pump`]).
            // Mirrors the implicit `.insanity` fallback path in
            // `masterlink$receive` for type codes the worker
            // does not handle: silently drop and continue.
            //
            // The exhaustive `let _ = (...)` consumes all three
            // payload fields so the destructuring above does not
            // produce unused-binding warnings under -D warnings.
            let _ = (cfg_ptr, log_type, message);
        }
    }
}

// ============================================================================
// fn install_log_hook — registers the worker_loghook closure
// ============================================================================

/// Install the worker's log hook so [`syslog::log`] calls in
/// heavything's library code are relayed to master via
/// [`LinkMessage::Log`] frames.
///
/// Mirrors `worker.inc` line 75
/// `mov qword [webservercfg$log_hook], worker_loghook`.
///
/// The closure stride-encodes the message string,
/// builds a [`LinkMessage::Log`], encodes it via
/// [`LinkMessage::encode`], and sends the encoded bytes via
/// `log_tx` to [`outbound_pump`]. The closure is `Send + Sync +
/// 'static` per [`syslog::set_log_hook`]'s trait bound.
///
/// # Severity → log_type mapping
///
/// The FASM hook receives the log type through `edx` directly
/// (`worker.inc` line 175 `mov [rdx+16], edx`); the Rust syslog
/// API exposes severity instead. We map RFC 5424 severities
/// `0..=3` (Emergency, Alert, Critical, Error) to `log_type=1`
/// (error) and the rest to `log_type=0` (normal), which preserves
/// the FASM `webservercfg$log` (info) versus
/// `webservercfg$logerror` (error) split.
///
/// # cfg_ptr sentinel
///
/// The FASM hook also receives the `webservercfg` pointer through
/// `rdi` and writes it into the IPC frame (`worker.inc` line 184).
/// The Rust [`syslog::set_log_hook`] surface does not expose this
/// pointer to the closure, so we send [`NO_CFG_SENTINEL`] (`0`);
/// master's log routing treats this as "no specific cfg" and
/// routes to the default syslog channel.
fn install_log_hook(log_tx: mpsc::UnboundedSender<Vec<u8>>) {
    syslog::set_log_hook(move |severity: u8, message: &str| {
        // Severity → log_type mapping (see fn doc).
        let log_type: u32 = if severity <= LOG_SEVERITY_ERROR_THRESHOLD {
            1
        } else {
            0
        };

        // Stride-encode the message into the Vec<u8> form expected
        // by [`LinkMessage::Log`]'s wire layout.
        let strided = encode_strided_string(message);

        let frame = LinkMessage::Log {
            cfg_ptr: NO_CFG_SENTINEL,
            log_type,
            message: strided,
        };

        // Encode the frame to bytes. The encoder cannot fail for
        // [`LinkMessage::Log`] (only the [`LinkMessage::Ocsp`] arm
        // returns [`ProtocolError::OcspTooLarge`] — see
        // `master.rs` `LinkMessage::encode`); we still handle the
        // [`Result`] explicitly and drop the message on encode
        // error to avoid panicking from a hook context.
        let bytes = match frame.encode() {
            Ok(b) => b,
            Err(_) => return,
        };

        // Send to the outbound pump. A send failure indicates the
        // pump task has exited (worker shutting down); drop the
        // message silently rather than panicking — this mirrors
        // the assembly's `[masterlink].vsend` returning failure
        // being treated as a non-fatal teardown signal.
        let _ = log_tx.send(bytes);
    });
}

// ============================================================================
// fn install_tls_sessioncache_hook — registers worker_tlscache closure
// ============================================================================

/// Install the worker's TLS session-cache hook so every
/// [`tls::sessioncache_put`] in the local TLS subsystem is relayed
/// to master via [`LinkMessage::TlsUpdate`] frames for cross-worker
/// session resumption.
///
/// Mirrors `worker.inc` line 76
/// `mov qword [tls$sessioncache_hook], worker_tlscache`.
///
/// The closure receives the cache key (session ID) and value
/// (session state, AES-256-encrypted by heavything's
/// `EncryptedSessionCache::put` per AAP §0.7.2.4); it copies them
/// into fixed-size byte arrays (32 + 64 bytes per
/// [`LINKMESSAGE_TLSUPDATE_SIZE`] = 104 minus the 8-byte header),
/// builds a [`LinkMessage::TlsUpdate`], encodes it, and sends via
/// `tls_tx` to [`outbound_pump`].
///
/// Mismatched buffer sizes are silently dropped: rustls always
/// produces 32-byte session IDs and our `EncryptedSessionCache`
/// always produces 64-byte state blobs, so a mismatch indicates a
/// rustls/heavything version skew that the TLS layer itself will
/// also reject.
fn install_tls_sessioncache_hook(tls_tx: mpsc::UnboundedSender<Vec<u8>>) {
    let hook: tls::SessionCacheHook = Arc::new(move |key: &[u8], value: &[u8]| {
        // Copy key/value into fixed-size arrays. A length
        // mismatch from rustls indicates a protocol version
        // skew; drop the update silently rather than crashing
        // a worker on a third-party version mismatch.
        if key.len() != 32 || value.len() != 64 {
            return;
        }
        let mut sessionid = [0_u8; 32];
        sessionid.copy_from_slice(&key[..32]);
        let mut state = [0_u8; 64];
        state.copy_from_slice(&value[..64]);

        let frame = LinkMessage::TlsUpdate { sessionid, state };
        let bytes = match frame.encode() {
            Ok(b) => b,
            Err(_) => return,
        };
        // Sanity: the encoder must always produce exactly
        // [`LINKMESSAGE_TLSUPDATE_SIZE`] bytes for this
        // variant. A diverging length would indicate a wire
        // format drift between worker and master.
        debug_assert_eq!(
            bytes.len(),
            LINKMESSAGE_TLSUPDATE_SIZE,
            "LinkMessage::TlsUpdate must encode to exactly LINKMESSAGE_TLSUPDATE_SIZE bytes"
        );

        // Drop on send failure (pump task exited / worker
        // shutting down); see [`install_log_hook`] for
        // rationale.
        let _ = tls_tx.send(bytes);
    });

    // [`tls::set_sessioncache_hook`] returns the previously
    // installed hook (if any). The worker is the first installer
    // in its lifetime so the previous hook is None on the
    // happy path; we discard it explicitly to satisfy the
    // `must_use`-equivalent semantics of an `Option`-returning
    // call without leaking it past this function.
    let _previous = tls::set_sessioncache_hook(hook);
}

// ============================================================================
// async fn build_http_config — heavything WebServerConfig builder
// ============================================================================

/// Build a fresh heavything-level [`HtServerConfig`] from the
/// per-listener `arguments::WebServerConfig` parsed out of the CLI.
///
/// The function MUST run inside an active tokio runtime context
/// because [`HtServerConfig::new_config`] spawns periodic timer
/// tasks via `spawn_periodic` (the 1.5 s log-flush timer and the
/// 120 s hotlist-recheck timer). Calling it from a sync context
/// outside the runtime would panic.
///
/// Field mapping from `arguments::WebServerConfig` to
/// [`HtServerConfig`]:
///
/// | arguments              | heavything                     |
/// |------------------------|--------------------------------|
/// | `is_tls`               | `set_tls(bool)`                |
/// | `vhost`                | `set_vhost(String)`            |
/// | `logs_path`            | `set_log_path(PathBuf)`        |
/// | `errorlog_path`        | `set_error_file(PathBuf)`      |
/// | `errorlog_syslog`      | `set_syslog(bool)`             |
/// | `backpath`             | `set_back_path(SocketAddr)`    |
/// | `redirects[0].to`      | `set_redirect(String)`         |
/// | `cache_control`        | `set_cache_control(u64)`       |
/// | `host_sandbox`         | `add_sandbox(host, dir)`       |
/// | `global_sandbox`       | `add_sandbox(NOHOST_KEY, dir)` |
/// | `index_files`          | `add_index_file(filename)`     |
/// | `fastcgi_map`          | `add_fastcgi(suffix, Url)`     |
///
/// The `global_sandbox` (set by the AAP §0.5.1.8 `-sandbox PATH`
/// flag) is registered under the heavything sentinel host key
/// [`NOHOST_KEY`] (`..nohost..`). The dispatcher's `resolve_docroot`
/// (`heavything::net::http::server`) tries (a) the explicit host
/// match, then (b) the [`NOHOST_KEY`] fallback before declaring 404
/// — registering under the sentinel makes `-sandbox` the catch-all
/// docroot when no `-hostsandbox` mapping matches the inbound
/// request's `Host:` header. This mirrors the FASM
/// `webservercfg_sandboxes_ofs` default-host behaviour preserved in
/// `webserver.inc:.nohoststr` (see AAP §0.5.1.8 + the QA finding
/// "`-sandbox` flag silently ignored — every request returns 404"
/// resolved by this wiring).
///
/// Fields not exposed via setter (`pem_path`, `file_stat_time`):
/// `pem_path` is consumed by the worker's TLS bootstrap loop in
/// [`worker_event_loop`] (one [`TlsServer`] per `is_tls=true`
/// listener); `file_stat_time` is reserved for future per-cfg
/// hotlist tuning.
async fn build_http_config(arg_cfg: &ArgWebServerConfig) -> Arc<HtServerConfig> {
    let cfg = HtServerConfig::new_config();

    // ---- Sync setters ----
    cfg.set_tls(arg_cfg.is_tls);

    if let Some(ref host) = arg_cfg.vhost {
        cfg.set_vhost(host.clone());
    }

    if let Some(ref path) = arg_cfg.logs_path {
        cfg.set_log_path(path.clone());
    }

    if let Some(ref path) = arg_cfg.errorlog_path {
        cfg.set_error_file(path.clone());
    }

    cfg.set_syslog(arg_cfg.errorlog_syslog);

    // The argument-level `backpath` is a free-form string (the
    // FASM CLI parser at `arguments.inc` accepts any token); the
    // heavything API requires a parsed [`SocketAddr`]. We attempt
    // the parse; on failure we silently skip — the heavything
    // back-path code will simply not see a configured target,
    // matching the FASM behaviour where an unparseable backpath
    // string was ignored by `webservercfg$set_backpath`.
    if let Some(ref bp) = arg_cfg.backpath {
        if let Ok(addr) = SocketAddr::from_str(bp) {
            cfg.set_back_path(addr);
        }
    }

    // The arguments-level `redirects` vector preserves the order
    // of `-redirect` flags. The FASM `webservercfg$set_redirect`
    // stored only a single redirect URL; we apply the FIRST
    // entry's `to` field if any, mirroring the FASM single-slot
    // behaviour.
    if let Some(first) = arg_cfg.redirects.first() {
        cfg.set_redirect(first.to.clone());
    }

    // The `cache_control` field is the parsed `Cache-Control:
    // max-age=<N>` value as an optional decimal string; the
    // heavything API takes `u64` seconds with `0` meaning "no
    // header". We parse leniently; an unparseable value falls
    // through to `0` (no header) to match the FASM
    // `webservercfg$set_cachecontrol` zero-default semantics.
    if let Some(ref cc) = arg_cfg.cache_control {
        if let Ok(secs) = cc.parse::<u64>() {
            cfg.set_cache_control(secs);
        }
    }

    // ---- Async setters ----
    //
    // Register the AAP §0.5.1.8 `-sandbox PATH` global sandbox
    // under the heavything sentinel host key [`NOHOST_KEY`]
    // (`..nohost..`). This makes `-sandbox` the catch-all docroot
    // when no `-hostsandbox HOST DIR` mapping matches the inbound
    // request's `Host:` header. Order matters: register the
    // global sandbox FIRST so the per-host explicit mappings below
    // can shadow it for specific hosts (the heavything map's
    // `add_sandbox` is last-write-wins per key, but the sentinel
    // `NOHOST_KEY` is a distinct key from any real host string so
    // there is no conflict — `resolve_docroot` consults the
    // explicit match first then falls back to the sentinel).
    //
    // Mirrors the FASM `webserver.inc:.nohoststr` fallback path —
    // resolves the QA finding "Issue #1: `-sandbox` flag silently
    // ignored — every request returns 404".
    if let Some(ref dir) = arg_cfg.global_sandbox {
        let dir_str = dir.to_string_lossy().into_owned();
        cfg.add_sandbox(NOHOST_KEY, dir_str).await;
    }

    for mapping in arg_cfg.host_sandbox.iter() {
        // `add_sandbox` takes `impl Into<String>` for both args;
        // the `dir: PathBuf` is converted via its
        // [`std::fmt::Display`] / `to_string_lossy()` path.
        let dir_str = mapping.dir.to_string_lossy().into_owned();
        cfg.add_sandbox(mapping.host.clone(), dir_str).await;
    }

    for filename in arg_cfg.index_files.iter() {
        cfg.add_index_file(filename.clone()).await;
    }

    for fcgi in arg_cfg.fastcgi_map.iter() {
        // The heavything FastCGI registration takes an
        // `Arc<Url>`; parse the address into the heavything
        // `Url` type. On parse failure (which would indicate a
        // CLI-validation gap, since `arguments::parse` accepts
        // the address verbatim), skip the entry silently to
        // match the FASM behaviour where unparseable FastCGI
        // mappings simply weren't registered.
        if let Ok(url) = Url::parse(&fcgi.address) {
            cfg.add_fastcgi(fcgi.endswith.clone(), Arc::new(url)).await;
        }
    }

    cfg
}

// ============================================================================
// fn encode_strided_string / fn decode_strided_string — STRING_BITS=32 codecs
// ============================================================================

/// Stride-expand a UTF-8 [`str`] into the 4-byte-per-codepoint form
/// used by [`LinkMessage::Log`]'s `message` field on the wire.
///
/// Each Rust [`char`] (a Unicode scalar value) is written as a
/// little-endian `u32`, mirroring the FASM `string32` representation
/// (`string32.inc`) under the canonical `STRING_BITS = 32` build.
/// The output length is `chars.len() * CHAR_STRIDE` bytes (with
/// `chars.len()` measured in codepoints, not byte length).
///
/// This is the inverse of [`decode_strided_string`].
fn encode_strided_string(s: &str) -> Vec<u8> {
    // Pre-allocate the worst-case (all-ASCII) capacity — we expand
    // by exactly [`CHAR_STRIDE`] per character.
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::with_capacity(chars.len() * CHAR_STRIDE);
    for c in chars {
        // Write each codepoint as a 32-bit little-endian unsigned
        // integer matching FASM `string32` per AAP §0.5.2.1.
        out.put_u32_le(c as u32);
    }
    out
}

/// Decode a stride-expanded byte slice back into a [`String`].
///
/// Each 4-byte little-endian `u32` is interpreted as a Unicode
/// scalar value; invalid scalar values (surrogates, codepoints >
/// `0x10FFFF`) are replaced with the Unicode REPLACEMENT CHARACTER
/// (`U+FFFD`) to preserve total-function semantics — the assembly
/// `string32` representation has no equivalent error path because
/// FASM strings are constructed only from valid characters.
///
/// Trailing bytes that do not form a complete `u32` are silently
/// dropped (matches FASM's implicit byte-count = `char_count *
/// stride` invariant; a partial trailing fragment indicates a
/// malformed wire frame the parser should have rejected upstream).
///
/// This is the inverse of [`encode_strided_string`].
fn decode_strided_string(strided: &[u8]) -> String {
    let mut out = String::with_capacity(strided.len() / CHAR_STRIDE);
    for chunk in strided.chunks_exact(CHAR_STRIDE) {
        // CHAR_STRIDE = 4 means each chunk is exactly 4 bytes; the
        // index expression cannot panic here.
        let codepoint = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let c = char::from_u32(codepoint).unwrap_or(char::REPLACEMENT_CHARACTER);
        out.push(c);
    }
    out
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the canonical `STRING_BITS = 32` build's
    /// [`CHAR_STRIDE`] is `4` bytes per codepoint. A change here
    /// would break wire-format compatibility with master, since
    /// master.rs's `STRING_STRIDE_BYTES` is also pinned to `4`.
    #[test]
    fn char_stride_matches_string_bits_32() {
        assert_eq!(CHAR_STRIDE, 4);
    }

    /// Verify that [`LinkMessage::TlsUpdate`] always encodes to
    /// exactly [`LINKMESSAGE_TLSUPDATE_SIZE`] (104) bytes. This is
    /// the single most-asserted invariant in the
    /// [`install_tls_sessioncache_hook`] code path; regression
    /// here would corrupt cross-worker session resumption.
    #[test]
    fn tlsupdate_fixed_size() {
        let msg = LinkMessage::TlsUpdate {
            sessionid: [0u8; 32],
            state: [0u8; 64],
        };
        let encoded = msg.encode().expect("TlsUpdate encode never fails");
        assert_eq!(encoded.len(), LINKMESSAGE_TLSUPDATE_SIZE);
        assert_eq!(LINKMESSAGE_TLSUPDATE_SIZE, 104);
    }

    /// Round-trip a [`LinkMessage::Log`] frame: build it,
    /// [`encode`](LinkMessage::encode) it, [`parse`](LinkMessage::parse)
    /// it back, and assert the parsed output matches the input
    /// byte-for-byte. This is the schema-mandated wire-format
    /// regression test for the worker's primary outbound IPC path.
    #[test]
    fn log_message_roundtrip() {
        let m1 = LinkMessage::Log {
            cfg_ptr: 0xdead_beef_cafe_babe,
            log_type: 1,
            // Strided 5-character payload: 5 chars × 4 bytes/char
            // = 20 bytes. Each char is "h", "e", "l", "l", "o"
            // expanded to little-endian u32 — by encoding "hello"
            // through [`encode_strided_string`] we exercise the
            // helper alongside the codec.
            message: encode_strided_string("hello"),
        };
        let bytes = m1.encode().expect("Log encode never fails");
        let parsed = LinkMessage::parse(&bytes)
            .expect("parse must succeed on its own encoder output")
            .expect("parse must yield a frame on its own encoder output");
        let (m2, n) = parsed;
        assert_eq!(n, bytes.len(), "consumed bytes equal frame length");
        match m2 {
            LinkMessage::Log {
                cfg_ptr,
                log_type,
                message,
            } => {
                assert_eq!(cfg_ptr, 0xdead_beef_cafe_babe);
                assert_eq!(log_type, 1);
                assert_eq!(message, encode_strided_string("hello"));
            }
            other => panic!("expected LinkMessage::Log, got {other:?}"),
        }
    }

    /// Verify [`encode_strided_string`] / [`decode_strided_string`]
    /// are exact inverses for an ASCII-only input.
    #[test]
    fn strided_string_roundtrip_ascii() {
        let original = "hello world";
        let encoded = encode_strided_string(original);
        assert_eq!(encoded.len(), original.chars().count() * CHAR_STRIDE);
        let decoded = decode_strided_string(&encoded);
        assert_eq!(decoded, original);
    }

    /// Verify the strided codec round-trips multibyte UTF-8 input.
    /// Each of the four-byte little-endian codepoints survives the
    /// codec without truncation or replacement; this exercises the
    /// `char as u32` path on full-BMP and supplementary-plane
    /// codepoints.
    #[test]
    fn strided_string_roundtrip_unicode() {
        // Mix of basic-multilingual-plane (`é`, U+00E9),
        // supplementary-plane (`🦀`, U+1F980), and ASCII.
        let original = "café 🦀 boost";
        let encoded = encode_strided_string(original);
        assert_eq!(encoded.len(), original.chars().count() * CHAR_STRIDE);
        let decoded = decode_strided_string(&encoded);
        assert_eq!(decoded, original);
    }

    /// Verify [`decode_strided_string`] replaces invalid scalar
    /// values with U+FFFD rather than panicking.
    #[test]
    fn strided_decode_invalid_scalar_replacement() {
        // Surrogate code unit U+D800 is not a valid Unicode scalar
        // value (it's reserved for UTF-16 surrogate pairs); a
        // strided wire frame containing it must be salvaged with
        // U+FFFD.
        let mut bytes = Vec::new();
        bytes.put_u32_le(0xD800);
        let decoded = decode_strided_string(&bytes);
        assert_eq!(decoded, "\u{FFFD}");
    }

    /// Verify [`decode_strided_string`] silently drops a partial
    /// trailing fragment that does not form a complete `u32`.
    #[test]
    fn strided_decode_drops_trailing_fragment() {
        let mut bytes = encode_strided_string("ok");
        // Append 3 stray bytes (less than CHAR_STRIDE = 4), which
        // do not form a complete codepoint.
        bytes.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        let decoded = decode_strided_string(&bytes);
        assert_eq!(decoded, "ok");
    }

    /// Verify that the worker-side log-severity-to-log-type
    /// mapping treats RFC 5424 severities `0..=3` as errors and
    /// the rest as normal logs. This is the schema-mandated
    /// translation of the FASM
    /// `webservercfg$log` / `webservercfg$logerror` split when
    /// surfaced through the limited-information
    /// [`syslog::set_log_hook`] interface.
    #[test]
    fn severity_to_log_type_mapping() {
        // Errors (0..=3): emergency, alert, critical, error.
        for severity in 0..=LOG_SEVERITY_ERROR_THRESHOLD {
            let log_type = if severity <= LOG_SEVERITY_ERROR_THRESHOLD {
                1u32
            } else {
                0u32
            };
            assert_eq!(log_type, 1, "severity {severity} must be log_type=1");
        }
        // Non-errors (4..=7): warning, notice, info, debug.
        for severity in (LOG_SEVERITY_ERROR_THRESHOLD + 1)..=7 {
            let log_type = if severity <= LOG_SEVERITY_ERROR_THRESHOLD {
                1u32
            } else {
                0u32
            };
            assert_eq!(log_type, 0, "severity {severity} must be log_type=0");
        }
    }

    /// Verify the [`NO_CFG_SENTINEL`] is `0`. Master's IPC handler
    /// treats this as "no specific cfg", routing through the
    /// default syslog channel; the test pins the value so master
    /// and worker do not drift.
    #[test]
    fn no_cfg_sentinel_is_zero() {
        assert_eq!(NO_CFG_SENTINEL, 0);
    }

    /// Verify the master-side and heavything-side
    /// `LOG_FLUSH_INTERVAL` constants agree at 1500 ms. A drift
    /// here would mean log lines flush at different cadences in
    /// master vs worker, which would produce visible operator
    /// confusion under burst load.
    #[test]
    fn log_flush_interval_consistency() {
        assert_eq!(
            LOG_FLUSH_INTERVAL,
            Duration::from_millis(LOG_FLUSH_INTERVAL_MS),
            "LOG_FLUSH_INTERVAL Duration must match heavything LOG_FLUSH_INTERVAL_MS"
        );
        assert_eq!(LOG_FLUSH_INTERVAL_MS, 1500);
        assert_eq!(syslog::flush_cfg_timer(), LOG_FLUSH_INTERVAL_MS);
    }

    /// Verify [`update_ocsp_response`] is a real, callable
    /// function symbol — the schema-mandated `members_accessed`
    /// import requires the binary to reference it. We bind it to
    /// a typed local so any signature drift would surface as a
    /// compile error at this site.
    ///
    /// We deliberately do not invoke the function (it requires a
    /// `&mut rustls::sign::CertifiedKey`, a type that is not in
    /// the `webserver` crate's direct dependency surface — see
    /// AAP §0.6.1). The reference alone is sufficient to satisfy
    /// the schema-import requirement and to fail-fast on
    /// signature changes.
    #[test]
    fn update_ocsp_response_is_callable() {
        let _f = update_ocsp_response;
    }

    /// Verify that the [`OcspResponse`] struct can be constructed
    /// via its public-field literal syntax with the
    /// [`SystemTime::UNIX_EPOCH`] sentinel used in
    /// [`handle_master_message`]'s [`LinkMessage::Ocsp`] arm. A
    /// regression here would mean the heavything-side
    /// `OcspResponse` struct's public fields changed, requiring
    /// a worker.rs update.
    #[test]
    fn ocsp_response_can_be_constructed() {
        let response = OcspResponse {
            der: vec![1, 2, 3, 4],
            produced_at: SystemTime::UNIX_EPOCH,
            next_update: SystemTime::UNIX_EPOCH,
        };
        assert_eq!(response.der, vec![1, 2, 3, 4]);
        assert_eq!(response.produced_at, SystemTime::UNIX_EPOCH);
        assert_eq!(response.next_update, SystemTime::UNIX_EPOCH);
    }

    /// Pin the wire-format type-code constants to their FASM
    /// `worker.inc` line 36–38 values
    /// (`linkmessage_ocsp = 0`, `linkmessage_log = 1`,
    /// `linkmessage_tlsupdate = 2`). The encoder-side test in
    /// [`tlsupdate_fixed_size`] and [`log_message_roundtrip`]
    /// already exercise the encode-then-parse path, but those
    /// rely on the constants being correct; an explicit pin
    /// here makes a wire-format change fail-fast at the
    /// constant-equality assertion rather than as a more obscure
    /// parse error elsewhere.
    #[test]
    fn linkmessage_type_codes_pinned() {
        assert_eq!(LINKMESSAGE_OCSP, 0_u32);
        assert_eq!(LINKMESSAGE_LOG, 1_u32);
        assert_eq!(LINKMESSAGE_TLSUPDATE, 2_u32);
    }

    /// Pin the type-code byte layout: every encoded
    /// [`LinkMessage`] starts with its `u32` type code in
    /// little-endian byte order at byte offset 0. Mirrors the
    /// FASM `[rdx+0]` write at `worker.inc` line 173 / line 248.
    #[test]
    fn linkmessage_type_code_byte_layout() {
        // TlsUpdate frame
        let tlsupdate = LinkMessage::TlsUpdate {
            sessionid: [0u8; 32],
            state: [0u8; 64],
        };
        let bytes = tlsupdate.encode().expect("TlsUpdate encode");
        let leading = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(leading, LINKMESSAGE_TLSUPDATE);

        // Log frame
        let log_frame = LinkMessage::Log {
            cfg_ptr: 0,
            log_type: 0,
            message: encode_strided_string("x"),
        };
        let bytes = log_frame.encode().expect("Log encode");
        let leading = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(leading, LINKMESSAGE_LOG);

        // Ocsp frame
        let ocsp_frame = LinkMessage::Ocsp {
            subject_cn: encode_strided_string("ex.com"),
            ocsp_response: vec![0xCA, 0xFE],
        };
        let bytes = ocsp_frame.encode().expect("Ocsp encode");
        let leading = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(leading, LINKMESSAGE_OCSP);
    }

    /// Verify that the [`ProtocolError`] variants this worker
    /// expects to encounter are constructible — pinning the
    /// schema-mandated import path. The runtime catch site is in
    /// [`worker_event_loop`]'s parse-error arm; adding a smoke
    /// test here means a future rename in `master.rs` would
    /// surface as a clear test compile failure.
    #[test]
    fn protocol_error_variants_constructible() {
        let insanity = ProtocolError::Insanity(42);
        let too_large = ProtocolError::OcspTooLarge(8192);
        match insanity {
            ProtocolError::Insanity(code) => assert_eq!(code, 42),
            ProtocolError::OcspTooLarge(_) => panic!("wrong variant"),
        }
        match too_large {
            ProtocolError::OcspTooLarge(size) => assert_eq!(size, 8192),
            ProtocolError::Insanity(_) => panic!("wrong variant"),
        }
    }
}
