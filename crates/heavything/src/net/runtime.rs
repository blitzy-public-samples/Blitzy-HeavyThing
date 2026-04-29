// HeavyThing x86_64 assembly language library — Rust translation.
//
// Rust translation © 2026, licensed under GPL-3.0-or-later.
// Derived from the HeavyThing assembly library:
//   Copyright © 2015–2018 2 Ton Digital, Jeff Marrison <info@2ton.com.au>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Async runtime and event-loop orchestration — Rust port of
//! `epoll.inc` (AAP §0.5.1.4, §0.7.1).
//!
//! # What this module replaces
//!
//! The HeavyThing FASM source contains a 3,512-line hand-rolled `epoll`
//! event loop in `/tmp/blitzy/Blitzy-HeavyThing/master_fc613b/epoll.inc`.
//! That file is responsible for:
//!
//! * Creating the single `epoll_fd` for the process via `epoll_create1(2)`
//! * Enforcing `RLIMIT_NOFILE ≥ 4096` via `getrlimit(2)` / `setrlimit(2)`
//! * Installing `SIGPIPE = SIG_IGN` and `F_SETFD = FD_CLOEXEC` on the epoll fd
//! * Applying listener-socket defaults: `SO_KEEPALIVE=1`, `SO_LINGER=(1,0)`,
//!   `TCP_NODELAY=1`, `O_NONBLOCK`, `SOCK_CLOEXEC`
//! * Dispatching ready events in priority order
//!   (`EPOLLHUP`/`EPOLLERR` > `EPOLLOUT` > `EPOLLIN`-on-listener >
//!   `EPOLLIN`-on-data) per AAP §0.7.1.1
//! * Maintaining the AVL-ordered timer tree that drives the eight
//!   integration-point timers (HTTP idle 30s, log flush 1.5s, PEM
//!   reload 3600s, TLS session cache sweep 3600s, OCSP refresh 7200s,
//!   OCSP retry 300s, file-cache recheck 120s, IP blacklist 86400s)
//! * Accepting connections in multi-accept mode when
//!   `epoll_multiple_accepts = 1` (drain accept queue per wakeup)
//!
//! # What this module does in Rust
//!
//! Per the AAP's key insight (§0.7.1.1), **tokio's internal `mio`
//! layer already provides the `epoll` backend on Linux**, so we do NOT
//! reimplement the event loop by hand. Instead this module exposes a
//! thin orchestrator layer over `tokio::runtime::Runtime` that retains
//! all observable semantics of the assembly baseline:
//!
//! * [`build`] / [`build_current_thread`] / [`run`] — construct tokio
//!   runtimes for the three consumption patterns (binary-crate
//!   `main()`, per-worker runtime after `fork(2)`, synchronous test
//!   harness).
//! * [`check_ulimit`] — the Stage 10 init check called by
//!   `lib.rs::init()`. Returns
//!   [`InitError::UlimitTooLow`](crate::error::InitError::UlimitTooLow)
//!   on failure; the caller maps this to exit code `97`
//!   (`EXIT_ULIMIT_TOO_LOW`) per AAP §0.1.1 and §0.7.1.1.
//! * [`apply_stream_defaults`] — applies the FASM listener-socket
//!   defaults (`SO_KEEPALIVE`, `SO_LINGER`, `TCP_NODELAY`) to an
//!   accepted [`tokio::net::TcpStream`]. Implemented via
//!   [`tokio::net::TcpStream::set_nodelay`] plus a single grouped
//!   `unsafe { libc::setsockopt(…) }` block per AAP §0.7.4.1.
//! * [`timers`] sub-module — eight named [`std::time::Duration`]
//!   constants naming the eight integration-point timers from AAP
//!   §0.7.1.1.
//! * [`TimerAction`] / [`TeardownReason`] — Rust enum encoding of the
//!   FASM timer return-value convention (`0` = re-arm, non-zero =
//!   tear-down) per AAP §0.7.1.1.
//! * [`spawn_periodic`] / [`spawn_periodic_async`] — helpers that turn
//!   a closure returning [`TimerAction`] into a
//!   [`tokio::task::JoinHandle`] driving a [`tokio::time::interval`]
//!   with `MissedTickBehavior::Delay` (matches FASM `timer_reset`
//!   semantics).
//! * [`accept_loop`] — generic per-listener accept loop that spawns
//!   a per-connection task via [`tokio::spawn`], applying the socket
//!   defaults before handing the stream to the handler closure.
//!   Preserves the `epoll_multiple_accepts` behaviour by relying on
//!   tokio's internal accept-batching instead of an explicit drain
//!   loop (per AAP §0.7.1.2 key insight #4).
//! * [`Shutdown`] + [`install_shutdown_signals`] — cooperative
//!   graceful-shutdown primitive driven by `SIGTERM`/`SIGINT` via
//!   [`tokio::signal::unix`].
//!
//! # Event priority preservation
//!
//! The FASM loop dispatches `EPOLLHUP`/`EPOLLERR` (0x18) before
//! `EPOLLOUT` (0x4) before `EPOLLIN`. Tokio (via `mio`) processes
//! ready events in FD registration order, and I/O errors surface
//! through `Poll::Ready(Err)` inside the top-level
//! [`tokio::net::TcpStream`] read/write futures. The
//! [`IoChain`](super::io::IoChain) `on_error` path pre-empts
//! `on_receive` by teardown-before-further-reads semantics (see the
//! rustdoc of [`super::io`]). Combined, this reproduces the assembly
//! priority ordering without manual intervention from this module.
//!
//! # Timer convention mapping
//!
//! The FASM source uses the convention: a timer callback returning `0`
//! in `rax` re-arms the timer (ready for the next tick); a non-zero
//! return value is treated as a `self-destruct` → `.fatality` → chain
//! tear-down. Rust encodes this as:
//!
//! * [`TimerAction::Reset`] — continue firing the timer.
//! * [`TimerAction::Teardown(reason)`](TimerAction::Teardown) — log
//!   the reason via [`syslog::warning`](crate::util::syslog::warning)
//!   and exit the task. The [`TeardownReason`] enum enumerates the
//!   seven well-known timer categories plus a catch-all
//!   [`TeardownReason::Fatality`] for arbitrary causes.
//!
//! # Master-worker architecture boundary
//!
//! This module is **not** the home of the master-worker fork-and-IPC
//! orchestration — that lives in `crates/webserver/src/master.rs` and
//! `crates/webserver/src/worker.rs`. The building blocks used there
//! ([`build`], [`accept_loop`], [`spawn_periodic`]) are provided here;
//! the composition is the consumer's responsibility. The
//! [`super::child`] module provides the socketpair-based IPC helpers.
//!
//! # `unsafe` budget
//!
//! This module contributes **two** `unsafe` blocks to the crate's
//! [`UNSAFE_AUDIT.md`](../../../../UNSAFE_AUDIT.md) tally (AAP
//! §0.7.4.1):
//!
//! 1. [`check_ulimit`] — one block wrapping
//!    [`libc::getrlimit`] / [`libc::setrlimit`] / re-verify
//!    [`libc::getrlimit`].
//! 2. [`apply_stream_defaults`] — one block wrapping two
//!    [`libc::setsockopt`] calls for `SO_LINGER` and `SO_KEEPALIVE`
//!    on the accepted stream's raw fd.
//!
//! Each block carries a dedicated `// SAFETY:` rationale covering:
//! (a) argument-lifetime / POD-validity / fd-liveness preconditions,
//! (b) why no safe wrapper in `std` / `tokio` suffices. The
//! corresponding integration tests live in
//! `crates/heavything/tests/ffi_boundary.rs` as
//! `test_check_ulimit` and `test_stream_defaults_roundtrip` per AAP
//! §0.7.4.4.
//!
//! # Error mapping
//!
//! * `RLIMIT_NOFILE < EPOLL_MINFDS` → [`InitError::UlimitTooLow`]
//!   (caller maps to exit 97).
//! * [`tokio::runtime::Builder::build`] failure → caller maps to
//!   [`InitError::EpollCreateFail`](crate::error::InitError::EpollCreateFail)
//!   (exit 96).
//! * [`accept_loop`] surfaces `std::io::Error` via
//!   [`NetError::Io`](crate::error::NetError::Io) (auto-`#[from]`).
//!
//! [`InitError::UlimitTooLow`]: crate::error::InitError::UlimitTooLow

use std::future::Future;
use std::net::SocketAddr;

// ============================================================================
// `timers` sub-module — the eight canonical integration-point intervals from
// AAP §0.1.1 and §0.7.1.1.
// ============================================================================

/// The eight canonical timer-driven integration points of the FASM
/// baseline, expressed as [`std::time::Duration`] compile-time constants
/// so consumer modules ([`super::http`], [`super::tls`],
/// [`super::ssh`], `super::blacklist`) can reference them by name.
///
/// The numeric values are sourced from [`crate::config`]; the names
/// mirror the AAP §0.1.1 terminology (HTTP idle 30s, log flush 1.5s,
/// PEM reload 3600s, TLS session cache 3600s, OCSP refresh 7200s,
/// OCSP retry 300s, file-cache recheck 120s, IP blacklist 86400s).
///
/// Note: [`crate::config::X509_OCSP_REFRESH`] and
/// [`crate::config::X509_OCSP_RETRY`] are stored in **milliseconds**
/// (per the FASM `ht_defaults.inc` convention); [`OCSP_REFRESH`] and
/// [`OCSP_RETRY`] here are constructed via
/// [`Duration::from_millis`] rather than `from_secs`. The remaining
/// six constants are stored in seconds and use [`Duration::from_secs`].
pub mod timers {
    use super::Duration;
    use crate::config;

    /// HTTP connection idle timeout — 30 seconds.
    ///
    /// Triggers tear-down of an HTTP connection that has received no
    /// bytes for this interval. Mirrors FASM
    /// `ht_defaults.inc:http_idle_timeout_secs`.
    pub const HTTP_IDLE: Duration = Duration::from_secs(config::HTTP_IDLE_TIMEOUT_SECS);

    /// Log flush interval — 1500 milliseconds.
    ///
    /// Fires in the master process to flush buffered log records to
    /// `/dev/log`. Never triggers [`super::TimerAction::Teardown`];
    /// the closure always returns [`super::TimerAction::Reset`].
    pub const LOG_FLUSH: Duration = Duration::from_millis(config::LOG_FLUSH_INTERVAL_MS);

    /// PEM certificate/key hot-reload interval — 3600 seconds (1 hour).
    ///
    /// The closure re-reads the configured PEM bundle and atomically
    /// swaps the `Arc<rustls::ServerConfig>` via `ArcSwap` (AAP
    /// §0.7.2.5). Never triggers [`super::TimerAction::Teardown`].
    pub const PEM_RELOAD: Duration = Duration::from_secs(config::TLS_PEM_REFRESH_INTERVAL);

    /// TLS session cache sweep interval — 3600 seconds (1 hour).
    ///
    /// The closure walks the session cache and evicts entries older
    /// than the TTL (AAP §0.7.2.1). Never triggers
    /// [`super::TimerAction::Teardown`].
    pub const TLS_SESSION_CACHE_SWEEP: Duration = Duration::from_secs(config::TLS_SERVER_SESSIONCACHE);

    /// OCSP stapling refresh interval — 7 200 000 milliseconds (2 hours).
    ///
    /// The closure fetches a fresh OCSP response from the configured
    /// responder and updates the `CertifiedKey` (AAP §0.7.2.1). On
    /// fetch failure the closure returns
    /// [`super::TimerAction::Reset`] and the next tick is scheduled
    /// via [`OCSP_RETRY`] (300 s) instead.
    pub const OCSP_REFRESH: Duration = Duration::from_millis(config::X509_OCSP_REFRESH);

    /// OCSP stapling retry interval — 300 000 milliseconds (5 minutes).
    ///
    /// Used when an [`OCSP_REFRESH`] tick failed. Never triggers
    /// [`super::TimerAction::Teardown`]; the closure re-attempts the
    /// fetch and returns [`super::TimerAction::Reset`] regardless of
    /// the fetch outcome.
    pub const OCSP_RETRY: Duration = Duration::from_millis(config::X509_OCSP_RETRY);

    /// Hot-list file-cache recheck interval — 120 seconds.
    ///
    /// The closure `stat(2)`-s every entry in the webserver's
    /// mmap-backed file cache and invalidates entries whose `mtime`
    /// has changed (AAP §0.7.2 `webserver.inc` file cache).
    pub const HOTLIST_RECHECK: Duration = Duration::from_secs(config::WEBSERVER_HOTLIST_STATFREQ);

    /// IP blacklist sweep interval — 86 400 seconds (24 hours).
    ///
    /// The closure expires blacklist entries whose insertion time +
    /// ban-duration has elapsed (AAP §0.7.2.1 on TLS failures,
    /// `blacklist.inc`).
    pub const BLACKLIST_EXPIRE: Duration = Duration::from_secs(config::TLS_BLACKLIST);
}

// ============================================================================
// TimerAction / TeardownReason — the Rust encoding of the FASM `0 = reset /
// non-zero = teardown` timer return-value convention (AAP §0.7.1.1).
// ============================================================================

/// The return type of a periodic timer closure passed to
/// [`spawn_periodic`] / [`spawn_periodic_async`].
///
/// Encodes the FASM timer convention `0 = reset, non-zero = teardown`
/// (AAP §0.7.1.1) as an explicit two-variant enum: returning
/// [`TimerAction::Reset`] re-arms the timer for the next tick;
/// returning [`TimerAction::Teardown`] logs the reason via
/// [`syslog::warning`](crate::util::syslog::warning) and exits the
/// driving task (which by dropping the
/// [`tokio::task::JoinHandle`] returned by `spawn_periodic*`
/// cascades the tear-down into any [`IoChain`](super::io::IoChain)
/// held by the closure's captures).
#[derive(Debug, Clone)]
pub enum TimerAction {
    /// Continue: the timer fired successfully; re-arm for the next
    /// tick. FASM equivalent: callback returned `0` in `rax`, which
    /// lands in the `.keeprunning` branch of `epoll$iteration`.
    Reset,

    /// Tear down: the timer has decided that the chain it belongs to
    /// is no longer viable. The driving task will log the reason via
    /// [`syslog::warning`](crate::util::syslog::warning) and return;
    /// callers observing the [`tokio::task::JoinHandle`] can treat
    /// task completion as the tear-down signal. FASM equivalent:
    /// callback returned non-zero in `rax`, which lands in the
    /// `.fatality` branch of `epoll$iteration`.
    Teardown(TeardownReason),
}

/// The enumerated causes a timer closure may return in
/// [`TimerAction::Teardown`]. Ordering mirrors the eight canonical
/// integration-point timers from [`timers`] plus a final catch-all
/// [`TeardownReason::Fatality`] for arbitrary causes not captured by
/// the first seven variants.
///
/// The string representation (via [`std::fmt::Debug`]) is the one
/// included in the `syslog$warning` message emitted by
/// [`spawn_periodic`] / [`spawn_periodic_async`] prior to task exit.
#[derive(Debug, Clone)]
pub enum TeardownReason {
    /// HTTP connection idle timeout expired (30s — see [`timers::HTTP_IDLE`]).
    IdleTimeout,

    /// Log flush timer fatality (unusual — log flush timers never
    /// return this in the canonical master-worker model; reserved for
    /// future use).
    LogFlush,

    /// PEM hot-reload failed in a way that invalidates the
    /// `Arc<rustls::ServerConfig>` (e.g., certificate expired with no
    /// new certificate available). Reserved for future use by
    /// `super::tls`.
    PemReload,

    /// TLS session-cache entry expired during the sweep (3600s — see
    /// [`timers::TLS_SESSION_CACHE_SWEEP`]).
    SessionExpire,

    /// OCSP stapling refresh failed past its retry budget and the
    /// stapled response has expired (AAP §0.7.2.1).
    OcspRefresh,

    /// Hot-list file-cache recheck detected a removed sandbox entry
    /// (120s — see [`timers::HOTLIST_RECHECK`]).
    HotlistRecheck,

    /// Blacklist expiry sweep completed its job and the driving task
    /// is shutting down (rare — the sweep loop usually returns
    /// [`TimerAction::Reset`] indefinitely; this variant captures the
    /// one-shot cleanup case).
    BlacklistExpire,

    /// Arbitrary cause with a free-form message. Used for ad-hoc
    /// tear-down decisions not captured by the first seven variants.
    Fatality(String),
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle;

use crate::error::{InitError, NetError};

// ============================================================================
// Runtime construction — `build`, `build_current_thread`, `run`.
// ============================================================================

/// Build a fresh multi-threaded [`tokio::runtime::Runtime`] with
/// [`Builder::enable_all`].
///
/// Used by each binary crate's `main()` (and by each worker process
/// after `fork(2)`) to obtain the async runtime that drives the
/// [`tokio`]-backed `epoll` event loop. The number of worker threads
/// defaults to the number of logical CPUs; the FASM baseline's
/// `-cpu N` CLI flag is honoured upstream by the `webserver` binary
/// constructing the runtime via [`Builder::new_multi_thread`]
/// directly when a specific thread count is requested.
///
/// # Errors
///
/// Returns `Err` if [`Builder::build`] fails — typically because
/// `epoll_create1(2)` itself failed, or the process has hit a kernel
/// limit on threads or open file descriptors. The caller in
/// `lib.rs::init()` converts the error to
/// [`InitError::EpollCreateFail`](crate::error::InitError::EpollCreateFail)
/// which in turn maps to process exit code `96`
/// (`EXIT_EPOLL_CREATE_FAIL`) per AAP §0.1.1 and §0.7.1.1.
///
/// # Example
///
/// ```no_run
/// # use std::process;
/// let rt = match heavything::net::runtime::build() {
///     Ok(rt) => rt,
///     Err(_) => process::exit(heavything::EXIT_EPOLL_CREATE_FAIL),
/// };
/// rt.block_on(async {
///     // … application logic …
/// });
/// ```
pub fn build() -> std::io::Result<Runtime> {
    Builder::new_multi_thread().enable_all().build()
}

/// Build a fresh current-thread [`tokio::runtime::Runtime`] with
/// [`Builder::enable_all`].
///
/// This variant is used by deterministic integration tests that need
/// guaranteed single-threaded execution (so that `fork(2)`-based
/// tests do not copy locked mutexes from spawned worker threads — a
/// post-fork deadlock hazard documented in AAP §0.7.4 and at the top
/// of `crates/heavything/tests/ffi_boundary.rs`). Binary-crate
/// `main()` should prefer [`build`] for production use.
///
/// # Errors
///
/// Same failure modes as [`build`]. The caller is expected to map
/// any error to a fatal exit or test failure as appropriate.
pub fn build_current_thread() -> std::io::Result<Runtime> {
    Builder::new_current_thread().enable_all().build()
}

/// Convenience helper: build a multi-threaded runtime via [`build`]
/// and drive the provided future to completion via
/// [`tokio::runtime::Runtime::block_on`].
///
/// This collapses the common "build + block_on" pattern used by
/// every binary crate's `main()` into a single call.
///
/// # Errors
///
/// Returns the same runtime-construction error as [`build`]. If the
/// runtime is constructed successfully the future's output is
/// returned wrapped in `Ok`. Failures inside the future itself
/// surface via the future's own return type.
///
/// # Example
///
/// ```no_run
/// use heavything::net::runtime;
///
/// fn main() -> std::io::Result<()> {
///     runtime::run(async {
///         // … async application logic …
///     })
/// }
/// ```
pub fn run<F, T>(future: F) -> std::io::Result<T>
where
    F: Future<Output = T>,
{
    let rt = build()?;
    Ok(rt.block_on(future))
}

// ============================================================================
// `check_ulimit` — Stage 10 init check (RLIMIT_NOFILE ≥ EPOLL_MINFDS).
// ============================================================================

/// Verify that the process has at least
/// [`crate::config::EPOLL_MINFDS`] (4096) file descriptors available,
/// attempting to raise the soft limit to the hard limit if below
/// threshold.
///
/// This is **Stage 10 of `heavything::init`** per AAP §0.1.1,
/// §0.7.1.1, and the FASM `epoll$init` pre-check starting at
/// `epoll.inc:1160`. The FASM baseline calls `syscall_getrlimit` with
/// `edi=7` (`RLIMIT_NOFILE`), compares `rlim_cur` against
/// `epoll_minfds`, uses `cmovl` to raise the requested value to at
/// least the minimum, calls `syscall_setrlimit`, and re-reads the
/// limit to verify. Any residual shortfall jumps to
/// `.error_minfds → ht$exit_error 97`, which in the Rust port
/// becomes [`InitError::UlimitTooLow`] mapped by the caller in
/// `lib.rs::init()` to exit code `97` (`EXIT_ULIMIT_TOO_LOW`).
///
/// # Behaviour
///
/// 1. `getrlimit(RLIMIT_NOFILE)` — read current limits.
/// 2. If `rlim_cur ≥ EPOLL_MINFDS`, return `Ok(())` immediately.
/// 3. Raise `rlim_cur` to the observed `rlim_max` and call
///    `setrlimit(RLIMIT_NOFILE)`. Ignore the setrlimit return value:
///    if the process lacks `CAP_SYS_RESOURCE` the call will fail
///    silently and the subsequent re-check will catch the shortfall.
/// 4. `getrlimit(RLIMIT_NOFILE)` again — read the new current limit.
/// 5. If the post-set `rlim_cur ≥ EPOLL_MINFDS`, return `Ok(())`;
///    otherwise return `Err(InitError::UlimitTooLow)`.
///
/// # Errors
///
/// Returns [`InitError::UlimitTooLow`] when either of the two
/// `getrlimit` calls fails (treated as an insufficient-limit
/// condition — the syscall surface is narrow enough that a failure
/// to query `RLIMIT_NOFILE` at all is indistinguishable from a
/// badly-configured environment for the caller's purpose), or when
/// the post-`setrlimit` re-check shows a limit below
/// [`crate::config::EPOLL_MINFDS`].
///
/// # Unsafe rationale
///
/// The function contains one `unsafe` block grouping the three
/// [`libc`] syscalls (`getrlimit` × 2, `setrlimit` × 1). Each
/// invocation is standard POSIX and has a dedicated `// SAFETY:`
/// comment. The [`libc::rlimit`] struct is a plain-old-data type
/// with two `rlim_t` (u64 on Linux x86_64) fields and no niche
/// requirements; zero-initialisation via [`std::mem::zeroed`] is
/// sound as the struct is fully overwritten by the first
/// `getrlimit` call before being read. See
/// [`UNSAFE_AUDIT.md`](../../../../UNSAFE_AUDIT.md) entry
/// `check_ulimit` and the
/// `tests/ffi_boundary.rs::test_check_ulimit` integration test.
pub fn check_ulimit() -> Result<(), InitError> {
    // Cast the u64 config constant to `libc::rlim_t` so the comparison
    // uses the type the kernel actually produces. On Linux x86_64
    // `rlim_t` is `u64` so the cast is a no-op, but writing it this
    // way documents intent and keeps the code portable across libc
    // definitions.
    let min = crate::config::EPOLL_MINFDS as libc::rlim_t;

    // SAFETY:
    //  * `libc::getrlimit` and `libc::setrlimit` are standard POSIX
    //    syscalls. Their C signatures require a valid `resource`
    //    identifier (`libc::RLIMIT_NOFILE`, a `c_int` constant
    //    exposed by libc) and a valid `*mut rlimit` / `*const rlimit`
    //    pointer respectively. We pass pointers to local stack
    //    variables of type `libc::rlimit` which are valid for the
    //    duration of each call.
    //  * `libc::rlimit` is a C struct with two `rlim_t` fields
    //    (`rlim_cur`, `rlim_max`); `rlim_t` is an unsigned integer
    //    with no niche requirements, so `std::mem::zeroed::<rlimit>()`
    //    is a valid initial state and `getrlimit` fully overwrites
    //    both fields before we read them.
    //  * The `setrlimit` return value is intentionally discarded
    //    (`let _ = …`): if the process lacks `CAP_SYS_RESOURCE` the
    //    syscall fails silently and the subsequent second
    //    `getrlimit` call will observe the shortfall, producing a
    //    clean `InitError::UlimitTooLow` rather than a bespoke
    //    error variant.
    unsafe {
        let mut rl: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            return Err(InitError::UlimitTooLow);
        }
        if rl.rlim_cur >= min {
            return Ok(());
        }

        // Try to raise the soft limit up to the hard limit.
        rl.rlim_cur = rl.rlim_max;
        let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &rl);

        let mut rl2: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl2) != 0 {
            return Err(InitError::UlimitTooLow);
        }
        if rl2.rlim_cur >= min {
            Ok(())
        } else {
            Err(InitError::UlimitTooLow)
        }
    }
}

// ============================================================================
// `apply_stream_defaults` — FASM listener-socket defaults
// (SO_KEEPALIVE, SO_LINGER, TCP_NODELAY).
// ============================================================================

/// Apply the FASM listener-socket defaults — `SO_KEEPALIVE=1`,
/// `SO_LINGER=(l_onoff=1, l_linger=0)`, `TCP_NODELAY=1` — to a freshly
/// accepted [`tokio::net::TcpStream`].
///
/// Matches the three `syscall_setsockopt` calls in
/// `epoll.inc:1438–1490` emitted by the FASM listener's accept loop.
/// `TCP_NODELAY` is applied via tokio's safe
/// [`TcpStream::set_nodelay`] wrapper. The remaining two options
/// require a direct [`libc::setsockopt`] call because neither the
/// `std::net` nor `tokio` public surface exposes `SO_LINGER`
/// configuration, and the AAP forbids pulling in `socket2` as it is
/// not in the dependency inventory (§0.6.1, §0.7.2.2).
///
/// The [`crate::config::EPOLL_NODELAY`] and
/// [`crate::config::EPOLL_KEEPALIVE`] flags gate the `TCP_NODELAY`
/// and `SO_KEEPALIVE` calls respectively; [`SO_LINGER`](libc::SO_LINGER)
/// is always applied because the FASM baseline unconditionally sets
/// `(l_onoff=1, l_linger=0)` to force RST-on-close and avoid
/// TIME_WAIT accumulation under sustained load.
///
/// # Errors
///
/// Returns the underlying [`std::io::Error`] if
/// [`TcpStream::set_nodelay`] fails. The two `libc::setsockopt`
/// calls are best-effort (their return values are discarded) to
/// preserve the FASM baseline behaviour from `epoll.inc:1438–1490`
/// which likewise does not check the syscall return values. A
/// pathological setsockopt failure (e.g. on a socket that has
/// already been closed by the peer) manifests as later read/write
/// failures which surface through the
/// [`IoChain`](super::io::IoChain) error path.
///
/// # Unsafe rationale
///
/// The function contains one `unsafe` block grouping the two
/// [`libc::setsockopt`] calls. The fd is obtained via the safe
/// [`std::os::unix::io::AsRawFd::as_raw_fd`] method on the
/// borrowed [`TcpStream`]; the fd remains valid for the duration of
/// the call because `stream` is borrowed by the caller and cannot
/// be dropped during our execution. The `optval` pointers reference
/// local stack values (a [`libc::linger`] struct and a
/// [`libc::c_int`]); the `optlen` arguments are computed via
/// [`std::mem::size_of`] of the respective types so length and
/// pointer match exactly. See
/// [`UNSAFE_AUDIT.md`](../../../../UNSAFE_AUDIT.md) entry
/// `apply_stream_defaults` and the
/// `tests/ffi_boundary.rs::test_stream_defaults_roundtrip`
/// integration test.
pub fn apply_stream_defaults(stream: &TcpStream) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    if crate::config::EPOLL_NODELAY {
        stream.set_nodelay(true)?;
    }

    let fd = stream.as_raw_fd();

    // SAFETY:
    //  * `stream` is borrowed by the caller for the duration of this
    //    function, so its underlying fd (`stream.as_raw_fd()`) is
    //    guaranteed to remain open and refer to the same socket
    //    throughout the two `libc::setsockopt` calls below.
    //  * The first call passes a pointer to a local
    //    [`libc::linger`] value (`ling`) whose lifetime extends to
    //    the end of the unsafe block. `libc::linger` is a POD C
    //    struct with two `c_int` fields (`l_onoff`, `l_linger`); the
    //    kernel reads them as a byte sequence of size
    //    `std::mem::size_of::<libc::linger>()`, which is what we pass
    //    as `optlen`.
    //  * The second call passes a pointer to a local [`libc::c_int`]
    //    value (`one = 1`) whose lifetime extends to the end of the
    //    unsafe block. `optlen` is `sizeof(c_int) = 4`.
    //  * Both calls use [`libc::SOL_SOCKET`] (level 1) and the
    //    option identifiers [`libc::SO_LINGER`] / [`libc::SO_KEEPALIVE`]
    //    exposed as the correct `c_int` constants by the `libc` crate.
    //  * The return values are intentionally discarded (assigned to
    //    `_`): setsockopt failures are observed downstream via
    //    subsequent `read`/`write` errors on the stream, which is
    //    the same best-effort posture as the FASM `epoll.inc`
    //    baseline at lines 1438–1490.
    unsafe {
        let ling = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&ling as *const libc::linger).cast::<libc::c_void>(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        );

        if crate::config::EPOLL_KEEPALIVE {
            let one: libc::c_int = 1;
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                (&one as *const libc::c_int).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    Ok(())
}

// ============================================================================
// `accept_loop` — generic per-listener accept loop.
// ============================================================================

/// Drive an accept loop on `listener`, spawning a per-connection
/// tokio task for each accepted stream.
///
/// The `handler` closure is `Clone + Send + 'static`; a fresh clone
/// is made for each accepted connection and passed into the spawned
/// task along with the [`TcpStream`] and its peer [`SocketAddr`].
/// The handler's returned [`NetError`], if any, is swallowed by the
/// spawned task (individual connection failures must not tear down
/// the entire listener). To observe per-connection errors, the
/// handler itself should capture them (e.g., via syslog) before
/// returning.
///
/// # FASM baseline mapping
///
/// Matches the `.acceptloop` label at `epoll.inc:3381–3470`. The
/// FASM baseline uses `accept4(SOCK_NONBLOCK|SOCK_CLOEXEC)` and,
/// when `epoll_multiple_accepts = 1`, `jmp .acceptloop` to drain the
/// accept queue per wakeup. Tokio internally batches accepts
/// efficiently (it uses the same `accept4` flags via `mio`), so the
/// simple `loop { listener.accept().await }` form is equivalent in
/// observable behaviour (AAP §0.7.1.2 key insight #4). The
/// [`crate::config::EPOLL_MULTIPLE_ACCEPTS`] flag is retained as a
/// configuration constant for parity but is not consulted inside
/// this loop — tokio's internal batching supersedes the explicit
/// drain.
///
/// # Errors
///
/// Returns `Err` only on a fatal [`TcpListener::accept`] failure
/// (e.g. the listener fd has been closed or the process has hit
/// `EMFILE`/`ENFILE`). Transient per-accept errors like `ECONNABORTED`
/// are handled internally by `mio`/`tokio` and do not bubble up.
/// Per-connection handler errors are swallowed as noted above.
pub async fn accept_loop<F, Fut>(listener: TcpListener, handler: F) -> Result<(), NetError>
where
    F: Fn(TcpStream, SocketAddr) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<(), NetError>> + Send + 'static,
{
    // Parity tag: the FASM `epoll_multiple_accepts` flag is preserved
    // in `crate::config::EPOLL_MULTIPLE_ACCEPTS` but not acted on here
    // because tokio already batches accepts internally. Suppress the
    // unused-read warning by touching the constant.
    let _multi: bool = crate::config::EPOLL_MULTIPLE_ACCEPTS;

    loop {
        let (stream, peer) = listener.accept().await?;
        // Apply defaults best-effort — a setsockopt failure does not
        // justify dropping the connection outright; downstream
        // handlers will observe the consequences through their own
        // read/write paths. The set_nodelay call inside
        // `apply_stream_defaults` may return an error which we
        // deliberately ignore here.
        let _ = apply_stream_defaults(&stream);
        let h = handler.clone();
        tokio::spawn(async move {
            let _ = h(stream, peer).await;
        });
    }
}

// ============================================================================
// `spawn_periodic` / `spawn_periodic_async` — periodic timer helpers.
// ============================================================================

/// Spawn a periodic timer that fires `f` every `interval` on the
/// current tokio runtime.
///
/// The closure `f` is invoked on each tick. When `f` returns
/// [`TimerAction::Reset`] the timer continues firing; when `f`
/// returns [`TimerAction::Teardown(reason)`](TimerAction::Teardown)
/// the returned task logs the reason via
/// [`syslog::warning`](crate::util::syslog::warning) using the
/// caller-supplied `reason_label` tag and exits.
///
/// The [`tokio::time::Interval`] used internally has its missed-tick
/// behaviour set to [`tokio::time::MissedTickBehavior::Delay`] which
/// matches the FASM AVL-tree timer semantics: if the event loop is
/// busy when a tick is due, the next tick is scheduled `interval`
/// after the current tick completes, preventing unbounded catch-up
/// bursts.
///
/// # Panics / behaviour under runtime absence
///
/// This function must be called from within a tokio runtime context
/// (either on a runtime's worker thread or inside a `block_on` call).
/// Calling it without an active runtime panics with the standard
/// tokio panic message ("there is no reactor running, …"). Consumers
/// should obtain a runtime via [`build`] or [`build_current_thread`]
/// first.
pub fn spawn_periodic<F>(interval: Duration, reason_label: &'static str, mut f: F) -> JoinHandle<()>
where
    F: FnMut() -> TimerAction + Send + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match f() {
                TimerAction::Reset => continue,
                TimerAction::Teardown(reason) => {
                    crate::util::syslog::warning(&format!("timer teardown: {reason_label} - {reason:?}"));
                    return;
                }
            }
        }
    })
}

/// Spawn a periodic timer driven by an async closure returning a
/// [`Future`] of [`TimerAction`].
///
/// Functionally identical to [`spawn_periodic`] except that `f`
/// returns a `Future` which is awaited on each tick. Used by async
/// timer consumers — e.g. [`super::tls`]'s PEM hot-reload closure
/// reads from disk asynchronously; [`super::dns`]'s cache-sweep
/// closure queries the resolver.
///
/// See [`spawn_periodic`] for the tick-behaviour and syslog
/// conventions.
pub fn spawn_periodic_async<F, Fut>(
    interval: Duration,
    reason_label: &'static str,
    mut f: F,
) -> JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = TimerAction> + Send + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match f().await {
                TimerAction::Reset => continue,
                TimerAction::Teardown(reason) => {
                    crate::util::syslog::warning(&format!("timer teardown: {reason_label} - {reason:?}"));
                    return;
                }
            }
        }
    })
}

// ============================================================================
// `Shutdown` primitive — cooperative graceful shutdown flag.
// ============================================================================

/// Shared state behind a [`Shutdown`] handle. Held inside a
/// [`std::sync::Arc`] so that every cloned [`Shutdown`] observes the
/// same `triggered` flag and wakes on the same [`tokio::sync::Notify`].
struct ShutdownInner {
    /// Atomic boolean: `false` when the application is running,
    /// `true` after the first `trigger()` call. Load/store uses
    /// [`Ordering::Relaxed`] because there is no additional shared
    /// state synchronised alongside the flag; the `Notify` wake-up
    /// carries the happens-before ordering needed for observers.
    triggered: AtomicBool,

    /// Notification primitive used by `wait()` to park awaiting
    /// tasks. `notify_waiters` is called once from `trigger()` to
    /// release every currently-parked task; new observers that call
    /// `wait()` after the trigger will observe `triggered == true`
    /// on their initial load and return immediately.
    notify: tokio::sync::Notify,
}

/// Cooperative graceful-shutdown primitive.
///
/// A [`Shutdown`] carries an internally reference-counted flag that
/// any number of clones can observe. Typical usage:
///
/// 1. The master process constructs a root [`Shutdown`] via
///    [`Shutdown::new`] (or, more commonly, via
///    [`install_shutdown_signals`] which also arranges for
///    `SIGTERM`/`SIGINT` to call [`Shutdown::trigger`] automatically).
/// 2. Long-running tasks (accept loops, periodic timers, per-worker
///    event loops) each hold a [`token`](Shutdown::token)-cloned copy
///    and race `wait()` against their primary I/O future via
///    `tokio::select!`:
///
///    ```no_run
///    # use heavything::net::runtime::{Shutdown, build};
///    # async fn example(listener: tokio::net::TcpListener, shutdown: Shutdown) {
///    loop {
///        tokio::select! {
///            accept = listener.accept() => {
///                // handle accepted connection …
///                let _ = accept;
///            }
///            () = shutdown.wait() => break,
///        }
///    }
///    # }
///    ```
/// 3. On receipt of a terminating signal, the signal handler task
///    installed by [`install_shutdown_signals`] calls
///    [`Shutdown::trigger`] exactly once; every parked `wait()`
///    resolves, every subsequent `wait()` resolves immediately.
///
/// # Clone semantics
///
/// [`Shutdown`] implements [`Clone`] via a cheap [`Arc::clone`] of
/// the inner state; cloning is idiomatic for distributing observers.
/// The [`token`](Shutdown::token) method is provided as a named
/// alternative that makes the "cheap clone, still refers to the
/// same shutdown signal" intent explicit at call sites.
#[derive(Clone)]
pub struct Shutdown {
    inner: Arc<ShutdownInner>,
}

impl Shutdown {
    /// Create a new [`Shutdown`] in the not-triggered state.
    ///
    /// The underlying [`AtomicBool`] starts as `false` and the
    /// [`tokio::sync::Notify`] starts with no parked waiters. Use
    /// [`Shutdown::token`] or `.clone()` to obtain additional
    /// handles that share the same underlying state.
    ///
    /// This constructor does **not** install signal handlers; for
    /// the common case of "shut down on `SIGTERM`/`SIGINT`" call
    /// [`install_shutdown_signals`] instead, which composes
    /// `new()` with a tokio signal task.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ShutdownInner {
                triggered: AtomicBool::new(false),
                notify: tokio::sync::Notify::new(),
            }),
        }
    }

    /// Return a cheap clone of this [`Shutdown`] that observes the
    /// same underlying flag.
    ///
    /// Equivalent to `.clone()` on the [`Shutdown`] value; the
    /// distinct name communicates intent at call sites where a
    /// "child token" is being issued to a spawned task. Every
    /// `.token()` clone is one `Arc` refcount increment; no heap
    /// allocation occurs.
    #[must_use]
    pub fn token(&self) -> Self {
        self.clone()
    }

    /// Request shutdown.
    ///
    /// Sets the internal flag to `true` (if not already set) and
    /// wakes every currently-parked [`wait`](Shutdown::wait) call
    /// via [`tokio::sync::Notify::notify_waiters`]. Subsequent
    /// `wait()` calls observe the `true` flag on their initial load
    /// and return immediately. Calling `trigger()` multiple times is
    /// idempotent — the flag never un-sets.
    pub fn trigger(&self) {
        self.inner.triggered.store(true, Ordering::Relaxed);
        self.inner.notify.notify_waiters();
    }

    /// Resolve when shutdown has been triggered.
    ///
    /// Returns immediately if `trigger()` has already been called.
    /// Otherwise awaits [`tokio::sync::Notify::notified`] and
    /// re-checks the flag after wake-up — the re-check ensures that
    /// any spurious wake-up (should one ever occur) is ignored in
    /// favour of the actual flag state.
    ///
    /// The future returned is cancel-safe: dropping the future
    /// (e.g., by losing a `tokio::select!` race) does not consume
    /// the notification for other waiters.
    pub async fn wait(&self) {
        loop {
            if self.inner.triggered.load(Ordering::Relaxed) {
                return;
            }
            let notified = self.inner.notify.notified();
            // Re-check after creating the `Notified` future but
            // before awaiting it. This handles the race where
            // `trigger()` fires between our initial load and our
            // call to `.notified()` — without the re-check we would
            // park forever (there is no pending notification to
            // receive because `notify_waiters` is edge-triggered).
            if self.inner.triggered.load(Ordering::Relaxed) {
                return;
            }
            notified.await;
            // Final check — the notification is for us, but
            // double-check for clarity and to guarantee the
            // happens-before ordering the caller relies on.
            if self.inner.triggered.load(Ordering::Relaxed) {
                return;
            }
        }
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Shutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shutdown")
            .field("triggered", &self.inner.triggered.load(Ordering::Relaxed))
            .finish()
    }
}

/// Install a tokio task that calls [`Shutdown::trigger`] on the first
/// `SIGTERM` or `SIGINT` received by the process, returning a shared
/// [`Arc<Shutdown>`] for observers.
///
/// # Preconditions
///
/// Must be called from within a tokio runtime context (typically
/// inside a `block_on` call at the top of a binary crate's `main()`).
/// The signal-handler registration uses [`tokio::signal::unix`] which
/// requires the runtime to be alive; calling this function outside
/// a runtime panics with the standard tokio reactor-missing message.
///
/// # Behaviour
///
/// 1. Constructs a fresh [`Shutdown`] via [`Shutdown::new`].
/// 2. Clones it via [`Shutdown::token`] for the spawned signal task.
/// 3. Wraps the remaining clone in [`Arc`] for the caller.
/// 4. Spawns a background task that:
///    - Registers `SIGTERM` via
///      [`tokio::signal::unix::signal`](tokio::signal::unix::signal)
///      with [`tokio::signal::unix::SignalKind::terminate`].
///    - Registers `SIGINT` likewise with
///      [`tokio::signal::unix::SignalKind::interrupt`].
///    - Awaits the first arrival via [`tokio::select`].
///    - Calls [`Shutdown::trigger`] on its cloned handle.
///
/// If either signal registration fails (e.g., because the process
/// has already installed its own handler for that signal), the
/// spawned task exits silently without triggering the shutdown.
/// The caller's returned [`Arc<Shutdown>`] remains valid and can
/// be triggered manually via [`Shutdown::trigger`].
///
/// # Return value
///
/// An [`Arc<Shutdown>`] that every observer task should clone (via
/// `Arc::clone`) or dereference-and-`.token()` to obtain its own
/// observation handle.
#[must_use]
pub fn install_shutdown_signals() -> Arc<Shutdown> {
    let shutdown = Shutdown::new();
    let for_task = shutdown.token();

    tokio::spawn(async move {
        // SIGTERM — the standard "please exit cleanly" signal sent
        // by `systemd`/`supervisord`/`docker stop`.
        let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(sig) => sig,
            Err(_) => return, // best-effort: silent if registration fails
        };
        // SIGINT — the Ctrl-C convention used at an interactive
        // terminal.
        let mut intr = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
            Ok(sig) => sig,
            Err(_) => return,
        };

        tokio::select! {
            _ = term.recv() => for_task.trigger(),
            _ = intr.recv() => for_task.trigger(),
        }
    });

    Arc::new(shutdown)
}

// ============================================================================
// In-file unit tests (#[cfg(test)] mod tests).
//
// These tests exercise the module's public surface in isolation. Cross-module
// integration tests (that cover the unsafe FFI boundaries end-to-end against
// live sockets / live rlimit queries) live in
// `crates/heavything/tests/ffi_boundary.rs` as
// `test_check_ulimit` and `test_stream_defaults_roundtrip` per AAP §0.7.4.4.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    // ------------------------------------------------------------------
    // Runtime builder tests.
    // ------------------------------------------------------------------

    #[test]
    fn test_build_succeeds() {
        // Sanity: the multi-threaded runtime builder must succeed on
        // any Linux host that has a functional `epoll_create1(2)`.
        let rt = build().expect("multi-threaded runtime construction");
        // A trivial `block_on` confirms the runtime is actually
        // driving futures (not just constructed).
        let observed: u32 = rt.block_on(async { 42 });
        assert_eq!(observed, 42);
    }

    #[test]
    fn test_build_current_thread_succeeds() {
        let rt = build_current_thread().expect("current-thread runtime construction");
        let observed: u32 = rt.block_on(async { 7 });
        assert_eq!(observed, 7);
    }

    #[test]
    fn test_run_helper_drives_future() {
        // The `run` helper builds a runtime and drives a future in
        // one call. We use a current-thread runtime inside the test
        // by calling `run` — which internally uses the multi-thread
        // variant — but for a single trivial future this is fine.
        let observed: &str = run(async { "hello" }).expect("runtime");
        assert_eq!(observed, "hello");
    }

    // ------------------------------------------------------------------
    // `check_ulimit` test — in-file companion to the integration test
    // in `tests/ffi_boundary.rs::test_check_ulimit`.
    // ------------------------------------------------------------------

    #[test]
    fn test_check_ulimit_current() {
        // On any typical developer or CI host the default
        // `RLIMIT_NOFILE` is at or above 4096. We accept both
        // outcomes (Ok or UlimitTooLow) to remain stable on hosts
        // configured with unusually low limits (e.g., some
        // sandboxed Docker containers), and we assert that the
        // error variant — when it occurs — is the expected one
        // (matching the `lib.rs::init()` exit-97 mapping).
        match check_ulimit() {
            Ok(()) => {
                // Happy path — sanity-check that the result matches
                // a direct `getrlimit` observation.
                // SAFETY: `getrlimit` is a standard POSIX syscall;
                // see `check_ulimit` for the full safety rationale.
                let observed = unsafe {
                    let mut rl: libc::rlimit = std::mem::zeroed();
                    libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl);
                    rl.rlim_cur
                };
                assert!(
                    observed >= crate::config::EPOLL_MINFDS as libc::rlim_t,
                    "check_ulimit returned Ok but RLIMIT_NOFILE is still \
                     below EPOLL_MINFDS ({observed} < {minfds})",
                    minfds = crate::config::EPOLL_MINFDS,
                );
            }
            Err(crate::error::InitError::UlimitTooLow) => {
                // Low-limit path — acceptable on constrained hosts.
                // No further assertions; the test's job here is to
                // verify we return *the correct* variant, not to
                // demand a specific limit on the test host.
            }
            Err(other) => {
                panic!("unexpected InitError variant from check_ulimit: {other:?}");
            }
        }
    }

    // ------------------------------------------------------------------
    // Timer-action / teardown-reason round-trip tests.
    // ------------------------------------------------------------------

    #[test]
    fn test_timer_action_variants_constructible() {
        // Explicitly construct every public variant to guard against
        // accidental name/path regressions. The `drop(_)` suppresses
        // unused-variant lints without affecting the test intent.
        drop(TimerAction::Reset);
        drop(TimerAction::Teardown(TeardownReason::IdleTimeout));
        drop(TimerAction::Teardown(TeardownReason::LogFlush));
        drop(TimerAction::Teardown(TeardownReason::PemReload));
        drop(TimerAction::Teardown(TeardownReason::SessionExpire));
        drop(TimerAction::Teardown(TeardownReason::OcspRefresh));
        drop(TimerAction::Teardown(TeardownReason::HotlistRecheck));
        drop(TimerAction::Teardown(TeardownReason::BlacklistExpire));
        drop(TimerAction::Teardown(TeardownReason::Fatality(
            "custom cause".to_string(),
        )));
    }

    #[test]
    fn test_timers_constants_match_config() {
        // Each of the eight `timers` constants must be derived from
        // the corresponding `config` constant. We re-derive the
        // expected value here and compare — any future drift is
        // caught immediately.
        assert_eq!(
            timers::HTTP_IDLE,
            Duration::from_secs(crate::config::HTTP_IDLE_TIMEOUT_SECS)
        );
        assert_eq!(
            timers::LOG_FLUSH,
            Duration::from_millis(crate::config::LOG_FLUSH_INTERVAL_MS)
        );
        assert_eq!(
            timers::PEM_RELOAD,
            Duration::from_secs(crate::config::TLS_PEM_REFRESH_INTERVAL)
        );
        assert_eq!(
            timers::TLS_SESSION_CACHE_SWEEP,
            Duration::from_secs(crate::config::TLS_SERVER_SESSIONCACHE)
        );
        assert_eq!(
            timers::OCSP_REFRESH,
            Duration::from_millis(crate::config::X509_OCSP_REFRESH)
        );
        assert_eq!(
            timers::OCSP_RETRY,
            Duration::from_millis(crate::config::X509_OCSP_RETRY)
        );
        assert_eq!(
            timers::HOTLIST_RECHECK,
            Duration::from_secs(crate::config::WEBSERVER_HOTLIST_STATFREQ)
        );
        assert_eq!(
            timers::BLACKLIST_EXPIRE,
            Duration::from_secs(crate::config::TLS_BLACKLIST)
        );
    }

    // ------------------------------------------------------------------
    // Timer helper tests — sync + async variants, Reset + Teardown paths.
    // ------------------------------------------------------------------

    #[test]
    fn test_timer_reset_semantics() {
        // Drive a 1ms periodic timer that returns Reset three times
        // then Teardown. Verify the spawned task completes (meaning
        // it observed the Teardown path) and the invocation count is
        // exactly 4.
        let rt = build_current_thread().expect("rt");
        let count = Arc::new(AtomicUsize::new(0));
        let count_cl = Arc::clone(&count);
        rt.block_on(async move {
            let handle = spawn_periodic(Duration::from_millis(1), "unit-test", move || {
                let c = count_cl.fetch_add(1, Ordering::SeqCst);
                if c < 3 {
                    TimerAction::Reset
                } else {
                    TimerAction::Teardown(TeardownReason::Fatality("unit-test done".into()))
                }
            });
            // Give the timer ample wall-clock room to tick 4×.
            tokio::time::timeout(Duration::from_secs(2), handle)
                .await
                .expect("timer task completed")
                .expect("join");
        });
        let n = count.load(Ordering::SeqCst);
        assert_eq!(
            n, 4,
            "expected exactly 4 invocations (3 Reset + 1 Teardown), got {n}"
        );
    }

    #[test]
    fn test_timer_async_reset_semantics() {
        // Async-variant twin of test_timer_reset_semantics. Verifies
        // spawn_periodic_async honours the same Reset/Teardown
        // convention when the closure returns a Future.
        let rt = build_current_thread().expect("rt");
        let count = Arc::new(AtomicUsize::new(0));
        let count_cl = Arc::clone(&count);
        rt.block_on(async move {
            let handle = spawn_periodic_async(Duration::from_millis(1), "unit-test-async", move || {
                let c = count_cl.clone();
                async move {
                    let n = c.fetch_add(1, Ordering::SeqCst);
                    if n < 2 {
                        TimerAction::Reset
                    } else {
                        TimerAction::Teardown(TeardownReason::IdleTimeout)
                    }
                }
            });
            tokio::time::timeout(Duration::from_secs(2), handle)
                .await
                .expect("timer task completed")
                .expect("join");
        });
        let n = count.load(Ordering::SeqCst);
        assert_eq!(n, 3, "expected exactly 3 invocations, got {n}");
    }

    // ------------------------------------------------------------------
    // Shutdown primitive tests.
    // ------------------------------------------------------------------

    #[test]
    fn test_shutdown_trigger_wakes_waiters() {
        let rt = build_current_thread().expect("rt");
        rt.block_on(async {
            let sd = Shutdown::new();
            let sd2 = sd.token();
            let waiter = tokio::spawn(async move {
                sd2.wait().await;
            });
            // Give the waiter time to park.
            tokio::time::sleep(Duration::from_millis(5)).await;
            sd.trigger();
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("waiter resolved after trigger")
                .expect("join");
        });
    }

    #[test]
    fn test_shutdown_wait_resolves_immediately_when_already_triggered() {
        let rt = build_current_thread().expect("rt");
        rt.block_on(async {
            let sd = Shutdown::new();
            sd.trigger();
            // Must not await a notification — the initial flag load
            // should short-circuit.
            tokio::time::timeout(Duration::from_millis(100), sd.wait())
                .await
                .expect("wait returns immediately after trigger");
        });
    }

    #[test]
    fn test_shutdown_multiple_triggers_idempotent() {
        let rt = build_current_thread().expect("rt");
        rt.block_on(async {
            let sd = Shutdown::new();
            sd.trigger();
            sd.trigger();
            sd.trigger();
            tokio::time::timeout(Duration::from_millis(100), sd.wait())
                .await
                .expect("wait immediately resolves");
        });
    }

    #[test]
    fn test_shutdown_clone_and_token_share_state() {
        let rt = build_current_thread().expect("rt");
        rt.block_on(async {
            let sd = Shutdown::new();
            let cloned = sd.clone();
            let tok = sd.token();
            sd.trigger();
            // Every handle observes the trigger.
            tokio::time::timeout(Duration::from_millis(100), cloned.wait())
                .await
                .expect("clone sees trigger");
            tokio::time::timeout(Duration::from_millis(100), tok.wait())
                .await
                .expect("token sees trigger");
        });
    }

    #[test]
    fn test_shutdown_default_not_triggered() {
        let rt = build_current_thread().expect("rt");
        rt.block_on(async {
            let sd = Shutdown::default();
            // Expect a timeout — wait should still be parked.
            let result = tokio::time::timeout(Duration::from_millis(20), sd.wait()).await;
            assert!(result.is_err(), "default Shutdown should not be triggered");
        });
    }

    #[test]
    fn test_shutdown_debug_format_reflects_state() {
        let sd = Shutdown::new();
        let before = format!("{sd:?}");
        assert!(
            before.contains("triggered: false"),
            "pre-trigger debug output should show flag=false, got: {before}"
        );
        sd.trigger();
        let after = format!("{sd:?}");
        assert!(
            after.contains("triggered: true"),
            "post-trigger debug output should show flag=true, got: {after}"
        );
    }

    // ------------------------------------------------------------------
    // `apply_stream_defaults` test — in-file companion to the
    // integration test in
    // `tests/ffi_boundary.rs::test_stream_defaults_roundtrip`.
    // ------------------------------------------------------------------

    #[test]
    fn test_apply_stream_defaults() {
        // Round-trip: bind a listener on 127.0.0.1, connect from the
        // same process, accept, apply defaults, and read back each
        // option via `libc::getsockopt`. Runs on a current-thread
        // tokio runtime to avoid fork-hazard interactions noted at
        // the top of `tests/ffi_boundary.rs`.
        let rt = build_current_thread().expect("rt");
        rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
            let local_addr = listener.local_addr().expect("local_addr");

            // Accept task runs concurrently with the connect below.
            let accept = tokio::spawn(async move {
                let (stream, _peer) = listener.accept().await.expect("accept");
                apply_stream_defaults(&stream).expect("defaults applied");
                stream
            });

            let _client = TcpStream::connect(local_addr).await.expect("connect loopback");
            let server_stream = accept.await.expect("accept task");

            use std::os::unix::io::AsRawFd;
            let fd = server_stream.as_raw_fd();

            // Verify via getsockopt (inside a fresh unsafe block —
            // this test performs its own syscall audit independent of
            // the production path).

            // SAFETY: fd is valid for the duration of this block
            // because `server_stream` is owned locally and not yet
            // dropped. `libc::getsockopt` accepts POD output buffers
            // of matching length.
            unsafe {
                // TCP_NODELAY (level=IPPROTO_TCP=6, option=1)
                let mut out: libc::c_int = 0;
                let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                let rc = libc::getsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_NODELAY,
                    (&mut out as *mut libc::c_int).cast::<libc::c_void>(),
                    &mut len,
                );
                assert_eq!(rc, 0, "getsockopt TCP_NODELAY rc={rc}");
                assert_ne!(out, 0, "TCP_NODELAY should be enabled");

                // SO_KEEPALIVE
                let mut out: libc::c_int = 0;
                let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                let rc = libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_KEEPALIVE,
                    (&mut out as *mut libc::c_int).cast::<libc::c_void>(),
                    &mut len,
                );
                assert_eq!(rc, 0, "getsockopt SO_KEEPALIVE rc={rc}");
                assert_ne!(out, 0, "SO_KEEPALIVE should be enabled");

                // SO_LINGER
                let mut ling = libc::linger {
                    l_onoff: 0,
                    l_linger: 0,
                };
                let mut len: libc::socklen_t = std::mem::size_of::<libc::linger>() as libc::socklen_t;
                let rc = libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&mut ling as *mut libc::linger).cast::<libc::c_void>(),
                    &mut len,
                );
                assert_eq!(rc, 0, "getsockopt SO_LINGER rc={rc}");
                assert_eq!(ling.l_onoff, 1, "SO_LINGER l_onoff should be 1");
                assert_eq!(ling.l_linger, 0, "SO_LINGER l_linger should be 0");
            }
        });
    }
}
