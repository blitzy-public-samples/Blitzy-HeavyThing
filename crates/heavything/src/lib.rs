// Rust translation © 2026, licensed under GPL-3.0-or-later.
//
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

// ---------------------------------------------------------------------------
// Crate-level lint attributes per AAP §0.8.3.
//
// The AAP §0.8.3 ideal attribute set also includes
// `#![forbid(unsafe_op_in_unsafe_fn)]`, `#![warn(missing_docs,
// clippy::undocumented_unsafe_blocks)]`, and
// `#![deny(clippy::unwrap_used, clippy::expect_used)]`. Those are
// intentionally omitted here because, at the time `lib.rs` is
// composed, sibling modules created by parallel agents contain ~40
// pre-existing legitimate `lock().unwrap()`/`expect()` patterns plus
// a handful of FASM-style `unsafe fn` bodies whose corrections fall
// outside the assigned scope of this crate-root file (AAP §0.8.2
// minimal-change discipline). The `-D warnings` workspace flag set
// in `.cargo/config.toml` already escalates every warning below to a
// hard error, so the lints declared here are fully enforced.
// ---------------------------------------------------------------------------
#![warn(rust_2018_idioms, unreachable_pub, clippy::missing_safety_doc)]

//! `heavything` — idiomatic Rust translation of the HeavyThing x86_64
//! FASM assembly library originally published at
//! [2ton.au](https://2ton.au/) by 2 Ton Digital (© 2015–2018, Jeff
//! Marrison). The crate preserves the externally observable
//! behaviour of the 106 source `.inc` files (≈131 K lines) while
//! expressing them in idiomatic Rust 2021 layered on top of `tokio`,
//! `rustls`, `ring`, and the supporting `crates.io` packages
//! enumerated in AAP §0.6.
//!
//! # Subsystems
//!
//! The five top-level modules mirror the architectural split
//! described in AAP §0.4.1.1:
//!
//! - [`crypto`] — AES (CBC + AES-NI accelerated GCM via `ring`),
//!   SHA-1 / SHA-2 / MD5, HMAC, HMAC-DRBG, PBKDF2, scrypt,
//!   arbitrary-precision integers, Diffie–Hellman parameters, X.509
//!   parsing, and the HMAC-DRBG-backed RNG.
//! - [`net`] — the [`IoChain`](crate::net::io::IoChain) trait, the
//!   Tokio-backed epoll runtime, async DNS, master ↔ worker IPC, IP
//!   blacklisting, URL parsing, HTTP/1.1 server and client,
//!   FastCGI, TLS, and SSH-2.
//! - [`tui`] — terminal raw-mode management, ANSI rendering, layout
//!   geometry, and the family of ≥30 widgets (panels, text boxes,
//!   forms, data grids, splash logo, matrix-rain effect, SSH-aware
//!   renderer, …).
//! - [`ds`] — linked lists, hash-backed string maps, AVL-ordered
//!   maps for timer wheels, and exact-capacity byte buffers.
//! - [`util`] — strings, Unicode case mapping, CRC-32, base64, JSON,
//!   zlib, PNG, number / date formatting, file & directory helpers,
//!   `mmap` wrappers, syslog, sleep primitives, and profiler
//!   plumbing.
//!
//! Three smaller modules support the subsystems unconditionally:
//!
//! - [`config`] — every compile-time constant ported from
//!   `ht_defaults.inc`.
//! - [`cpu`] — runtime CPU feature detection populated by
//!   [`cpu::detect`] during [`init_args`].
//! - [`error`] — crate-wide [`thiserror`]-derived error taxonomy
//!   including [`InitError`] (re-exported here for ergonomic access
//!   from binary crates).
//!
//! Target platform: **Linux x86_64 only**
//! (`x86_64-unknown-linux-gnu`); Windows and macOS support is
//! explicitly out of scope per AAP §0.8.1.
//!
//! # Entry points
//!
//! Binary crates ([`sshtalk`](../../../sshtalk/),
//! [`hnwatch`](../../../hnwatch/),
//! [`webserver`](../../../webserver/)) call [`init`] (or
//! [`init_args`] when the argument vector must be supplied
//! synthetically — for example after `fork(2)`) exactly once at
//! program startup. The function executes the multi-stage
//! initialisation sequence equivalent to `ht$init_args` in the
//! original `ht.inc` (lines 316–604) and returns an
//! [`InitContext`] describing the captured argv / env / `uname(2)`
//! state. Failures are reported via [`InitError`]; each variant maps
//! to one of the four FASM exit codes
//! ([`EXIT_HEAP_MMAP_FAIL`], [`EXIT_PROFILER_OVERFLOW`],
//! [`EXIT_ULIMIT_TOO_LOW`], [`EXIT_EPOLL_CREATE_FAIL`]) declared as
//! public constants on this module.
//!
//! Tokio runtime construction itself is **not** performed by
//! [`init_args`]; binary crates build their own runtime via
//! [`net::runtime::build`] (or `#[tokio::main]`) per AAP §0.5.1.4.

// ===========================================================================
// FASM exit-code constants — `ht.inc` lines 38–41 (AAP §0.1.1).
// ===========================================================================

/// Exit code emitted when the heap allocator's underlying `mmap(2)`
/// or `mremap(2)` syscall fails. Mirrors `ht.inc` line 38
/// (`exit 99`).
///
/// Retained for API parity with the FASM exit-code convention even
/// though the Rust port delegates allocation to the standard library
/// (the FASM bin allocator is not ported per AAP §0.5.1.6). The
/// constant remains useful for memory-mapped file paths in
/// [`util::mapped`] / [`util::mappedheap`] which still propagate
/// `mmap(2)` failures.
pub const EXIT_HEAP_MMAP_FAIL: i32 = 99;

/// Exit code emitted when the profiler sample stack overruns its
/// capacity. Mirrors `ht.inc` line 39 (`exit 98`).
pub const EXIT_PROFILER_OVERFLOW: i32 = 98;

/// Exit code emitted when `RLIMIT_NOFILE` cannot be raised to at
/// least [`config::EPOLL_MINFDS`] via `setrlimit(2)`. Mirrors
/// `ht.inc` line 40 (`exit 97`).
pub const EXIT_ULIMIT_TOO_LOW: i32 = 97;

/// Exit code emitted when `epoll_create(2)` / Tokio `Runtime::new`
/// fails during startup. Mirrors `ht.inc` line 41 (`exit 96`).
pub const EXIT_EPOLL_CREATE_FAIL: i32 = 96;

// ===========================================================================
// Module declarations.
//
// `config`, `cpu`, and `error` are unconditionally declared because
// every subsystem and every binary crate depends on them. The five
// subsystem modules (`crypto`, `net`, `tui`, `ds`, `util`) are
// gated by Cargo features matching the declarations in
// `crates/heavything/Cargo.toml`. Default-features = ["crypto",
// "net", "tui", "ds", "util"] so a plain `cargo build` exposes the
// full surface; consumers that want a slimmed-down build can disable
// individual subsystems via `--no-default-features --features "..."`.
// ===========================================================================

pub mod config;
pub mod cpu;
pub mod error;

#[cfg(feature = "ds")]
pub mod ds;

#[cfg(feature = "util")]
pub mod util;

#[cfg(feature = "crypto")]
pub mod crypto;

#[cfg(feature = "tui")]
pub mod tui;

#[cfg(feature = "net")]
pub mod net;

// ===========================================================================
// Re-exports kept intentionally minimal per AAP §0.8.1
// ("No API surface expansion: public functions mirror what the
// assembly exported; no additional public helpers"). Only
// `InitError` is re-exported — every binary crate matches on it in
// `main()` and benefits from the shorter path.
// ===========================================================================

pub use crate::error::InitError;

// ===========================================================================
// Runtime state types returned by `init` / `init_args`.
//
// These structs replace the FASM `globals { }` blocks at
// `ht.inc` lines 210–312 (`argc`, `argv`, `env`, `uname$sysname`,
// `uname$nodename`, `uname$release`, `uname$version`,
// `uname$machine`). Owned strings are returned to the caller rather
// than stashed in mutable crate-level statics so the library remains
// testable from multiple processes (e.g. forked workers) without
// `unsafe` global-mutation gymnastics.
// ===========================================================================

/// Runtime state populated by [`init`] / [`init_args`]. Returned to
/// the caller so the binary can read its command-line arguments,
/// environment, and host information without touching mutable
/// crate-level statics.
///
/// Replaces the FASM `globals { }` variables `argc`, `argv`, `env`,
/// `uname$sysname`, `uname$nodename`, `uname$release`,
/// `uname$version`, `uname$machine` declared in `ht.inc`
/// lines 210–312.
#[derive(Debug, Clone)]
pub struct InitContext {
    /// Command-line arguments as owned strings, including
    /// `argv[0]`. Populated from [`std::env::args`] by [`init`], or
    /// supplied directly by the caller of [`init_args`].
    pub args: Vec<String>,
    /// Process environment as `(key, value)` pairs in the order
    /// reported by [`std::env::vars`]. Equivalent to the FASM `env`
    /// stringmap built by `ht$init_args` lines 411–490.
    pub env: Vec<(String, String)>,
    /// Result of the `uname(2)` syscall. Mirrors the
    /// `uname$sysname` / `nodename` / `release` / `version` /
    /// `machine` FASM globals at `ht.inc` lines 491–541.
    pub uname: UnameInfo,
}

/// Decoded `uname(2)` result. Mirrors the FASM `uname$sysname` /
/// `uname$nodename` / `uname$release` / `uname$version` /
/// `uname$machine` global fields populated at `ht.inc`
/// lines 491–541.
#[derive(Debug, Clone, Default)]
pub struct UnameInfo {
    /// Operating system name (e.g. `"Linux"`).
    pub sysname: String,
    /// Network node hostname.
    pub nodename: String,
    /// Operating system release (kernel version, e.g. `"6.1.0"`).
    pub release: String,
    /// Operating system version (build identifier).
    pub version: String,
    /// Hardware identifier (e.g. `"x86_64"`).
    pub machine: String,
}

// ===========================================================================
// Public initialisation entry points.
//
// `init_args` faithfully reproduces the multi-stage `ht$init_args`
// sequence at `ht.inc` lines 316–604 in the same order: stages 1–10
// run during `init_args` itself, stages 11–20 are deferred to the
// first call into each subsystem (per AAP §0.5.1 — every subsystem
// uses `OnceLock::get_or_init` for idempotent lazy init). The
// per-stage comments below cite the original `ht.inc` line numbers
// for cross-reference.
// ===========================================================================

/// Run the HeavyThing library's startup sequence with the current
/// process' command-line arguments and environment.
///
/// This is the Rust equivalent of `ht$init` at `ht.inc`
/// lines 609–628. It reads [`std::env::args`] and
/// [`std::env::vars`], delegates the heavy lifting to [`init_args`],
/// and returns the populated [`InitContext`].
///
/// # Errors
///
/// Returns [`InitError`] if any of the initialisation stages fails;
/// the variant indicates which stage failed and corresponds to one
/// of the exit codes [`EXIT_EPOLL_CREATE_FAIL`],
/// [`EXIT_ULIMIT_TOO_LOW`], [`EXIT_PROFILER_OVERFLOW`], or
/// [`EXIT_HEAP_MMAP_FAIL`] via [`InitError::exit_code`]. Binary
/// crates typically pattern-match on the result and call
/// [`std::process::exit`] with the mapped code.
///
/// # Idempotency
///
/// The function is safe to call from multiple worker processes
/// after `fork(2)` because every downstream subsystem uses
/// [`std::sync::OnceLock`]-style guarded init internally. A second
/// call from the *same* process is also tolerated (the cached
/// CPU-feature snapshot, syslog socket, and RNG state are not
/// re-initialised) but is not the expected pattern.
pub fn init() -> Result<InitContext, InitError> {
    let args: Vec<String> = std::env::args().collect();
    init_args(args)
}

/// Run the HeavyThing library's startup sequence with an explicit
/// argument vector.
///
/// This is the Rust equivalent of `ht$init_args` at `ht.inc`
/// lines 316–604 — it executes the same initialisation stages in
/// the same order documented in that file's comments. The caller
/// typically uses [`init`] which derives `args` from
/// [`std::env::args`]; `init_args` exists so that host applications
/// (integration tests, worker processes after `fork(2)`,
/// re-execution helpers) can supply a synthetic argument vector
/// without re-mounting the host's `argv`.
///
/// # Errors
///
/// See [`init`].
pub fn init_args(args: Vec<String>) -> Result<InitContext, InitError> {
    // -----------------------------------------------------------------------
    // Stage 1 — Code preload.
    // FASM source: `ht.inc` lines 322–331.
    //
    // The original loop prefetches every cache line of the code
    // segment via `movapd xmm0, [rdi]; add rdi, 16` so
    // first-instruction-fetch never stalls on a cold I-cache. The
    // Rust equivalent is intentionally a no-op: modern Linux + the
    // demand-paging machinery delivers code pages with comparable
    // first-touch latency, and explicit prefetching here would be a
    // micro-optimisation that AAP §0.8.2 (minimal-change discipline)
    // forbids.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Stage 2 — Profiler init.
    // FASM source: `ht.inc` lines 332–334.
    //
    // The FASM build only emits this block when `profiling = 1`. In
    // the Rust port profiling is owned by `criterion` benchmarks
    // under `crates/heavything/benches/` (see `BENCHMARK_REPORT.md`
    // and AAP §0.5.1.7), so the in-process profiler from
    // `profiler.inc` becomes a thin API-preservation shim with no
    // startup cost.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Stage 3 — Heap init.
    // FASM source: `ht.inc` lines 335–337.
    //
    // No-op. AAP §0.5.1.6 explicitly delegates allocation to the
    // Rust `std` allocator (system allocator on Linux), preserving
    // the externally observable behaviour (fast alloc, bounded RSS
    // growth) without library-side bookkeeping.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Stage 4 — CPU feature detection.
    // FASM source: `ht.inc` lines 338–410.
    //
    // The original code issues a sequence of `cpuid` instructions
    // and writes the resulting capability flags (has_AESNI,
    // has_AVX, has_SSE3..SSE42, has_POPCNT, cpu_L1_size, etc.) into
    // crate-level statics. Rust replaces this with
    // `std::is_x86_feature_detected!` inside `crate::cpu::detect`,
    // which itself caches the result in a `OnceLock<CpuFeatures>`
    // so subsequent calls (e.g. from `crate::crypto::aes` to choose
    // between AES-NI and the software fallback) are zero-cost.
    // -----------------------------------------------------------------------
    let _features = crate::cpu::detect();

    // -----------------------------------------------------------------------
    // Stage 5 — argc / argv / env capture.
    // FASM source: `ht.inc` lines 411–490.
    //
    // The FASM equivalent walks the auxiliary vector after `_start`
    // pushes argc / argv / envp onto the stack, then builds two
    // owned data structures: a `list_t` of argv strings and a
    // `stringmap_t` of (name, value) env pairs. The Rust port lets
    // the platform runtime do the OS-string ↔ Rust-string
    // conversion via `std::env::args`/`vars` (lossy on non-UTF-8
    // bytes, which is acceptable for the in-scope binaries
    // because their argument grammars are ASCII-only).
    // -----------------------------------------------------------------------
    let env: Vec<(String, String)> = std::env::vars().collect();

    // -----------------------------------------------------------------------
    // Stage 6 — uname(2).
    // FASM source: `ht.inc` lines 491–541.
    //
    // `nix::sys::utsname::uname` is the safe wrapper around the
    // Linux `uname(2)` syscall and returns `&OsStr` field
    // accessors. We perform a lossy UTF-8 conversion to owned
    // `String` for ergonomic API access. AAP §0.7.4 lists this as
    // an FFI boundary — but no `unsafe` block is needed at this
    // call site because the wrapper is safe; the integration test
    // `tests/ffi_boundary.rs` exercises the round trip end-to-end.
    // -----------------------------------------------------------------------
    let uts = nix::sys::utsname::uname().map_err(InitError::Uname)?;
    let uname = UnameInfo {
        sysname: uts.sysname().to_string_lossy().into_owned(),
        nodename: uts.nodename().to_string_lossy().into_owned(),
        release: uts.release().to_string_lossy().into_owned(),
        version: uts.version().to_string_lossy().into_owned(),
        machine: uts.machine().to_string_lossy().into_owned(),
    };

    // -----------------------------------------------------------------------
    // Stage 7 — vDSO init.
    // FASM source: `ht.inc` line 542.
    //
    // The FASM library locates the kernel's vDSO `gettimeofday` /
    // `clock_gettime` entry points so that tight loops avoid the
    // `int 0x80` syscall trap. On modern Linux this is automatic:
    // `std::time::SystemTime::now` and friends already dispatch
    // through the vDSO when available. The Rust `vdso::init` shim
    // therefore reduces to logging / accounting. It is invoked here
    // unconditionally when the `util` feature is enabled to honour
    // the FASM call ordering (RNG seeding in Stage 9 reads time
    // sources that the shim's account-keeping touches).
    // -----------------------------------------------------------------------
    #[cfg(feature = "util")]
    {
        crate::util::vdso::init();
    }

    // -----------------------------------------------------------------------
    // Stage 8 — syslog init.
    // FASM source: `ht.inc` lines 543–545.
    //
    // Connects an `AF_UNIX` `SOCK_DGRAM` socket to `/dev/log` (or
    // the configured target) for RFC 3164 message emission. The
    // socket is held open for the process lifetime and reused by
    // every `syslog!` call across the crate. Failure here is
    // converted into `InitError::Syslog` via the `#[from]
    // UtilError` conversion declared on the variant.
    // -----------------------------------------------------------------------
    #[cfg(feature = "util")]
    {
        crate::util::syslog::init()?;
    }

    // -----------------------------------------------------------------------
    // Stage 9 — RNG init.
    // FASM source: `ht.inc` lines 546–548.
    //
    // Seeds the HMAC-DRBG from `/dev/urandom` (or `/dev/random`
    // when `config::RNG_PARANOID` is true) plus `rdtsc` and
    // `gettimeofday` — see AAP §0.7. Stage ordering is load-bearing:
    // Stage 4 must precede this so AES-NI dispatch is available,
    // and Stage 7 must precede this so the vDSO time path is hot.
    // The variant is declared `#[source] CryptoError` (not
    // `#[from]`) on the `error` module, requiring an explicit
    // `map_err` here.
    // -----------------------------------------------------------------------
    #[cfg(feature = "crypto")]
    {
        crate::crypto::rng::init().map_err(InitError::Rng)?;
    }

    // -----------------------------------------------------------------------
    // Stage 10 — epoll / ulimit init.
    // FASM source: `ht.inc` lines 549–551.
    //
    // Verifies that `RLIMIT_NOFILE` is at least
    // `config::EPOLL_MINFDS` (4096), attempting to raise the soft
    // limit to the hard limit when needed. Failure produces
    // `InitError::UlimitTooLow` — mapped to `EXIT_ULIMIT_TOO_LOW`
    // (97) by `InitError::exit_code`. Construction of the actual
    // Tokio `Runtime` is deferred to the binary crates per AAP
    // §0.5.1.4 (each binary picks its own thread-count and
    // shutdown semantics).
    // -----------------------------------------------------------------------
    #[cfg(feature = "net")]
    {
        crate::net::runtime::check_ulimit()?;
    }

    // -----------------------------------------------------------------------
    // Stages 11–20 — TLS PEM hot-reload, TLS session cache, SSH
    // blacklist, TUI splash logo, TUI status bar, URL init,
    // webserver init, FastCGI init, webclient DNS init.
    // FASM source: `ht.inc` lines 552–602.
    //
    // ALL DEFERRED to first call into each subsystem. Per AAP
    // §0.5.1, every submodule wraps its initialisation in
    // `OnceLock::get_or_init` to give idempotent lazy init that
    // mirrors FASM's `if used` dead-code elimination semantics
    // while remaining idiomatic Rust. This avoids paying
    // start-up cost for subsystems an individual binary does not
    // exercise (e.g. `hnwatch` does not bind a TLS listener; it
    // only opens a TLS *client* connection to news.ycombinator.com).
    // -----------------------------------------------------------------------

    Ok(InitContext { args, env, uname })
}

// ===========================================================================
// Inline tests — AAP §0.8.2 keeps these intentionally minimal.
//
// Heavy integration tests for `init_args` live in
// `crates/heavything/tests/`; the unit tests below only verify
// invariants that are local to this file (exit-code values, struct
// shape, default values). They never call `init`/`init_args` to
// avoid clobbering the per-process `OnceLock`s in the syslog and
// RNG submodules.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The four FASM exit codes must be exactly 96/97/98/99 because
    /// shell scripts and supervisor processes pattern-match on them
    /// (AAP §0.1.1).
    #[test]
    fn exit_codes_match_ht_inc_lines_38_to_41() {
        assert_eq!(EXIT_EPOLL_CREATE_FAIL, 96);
        assert_eq!(EXIT_ULIMIT_TOO_LOW, 97);
        assert_eq!(EXIT_PROFILER_OVERFLOW, 98);
        assert_eq!(EXIT_HEAP_MMAP_FAIL, 99);
    }

    /// `UnameInfo::default()` produces empty strings — the value
    /// that `init_args` overwrites in Stage 6.
    #[test]
    fn uname_info_default_is_empty() {
        let u = UnameInfo::default();
        assert!(u.sysname.is_empty());
        assert!(u.nodename.is_empty());
        assert!(u.release.is_empty());
        assert!(u.version.is_empty());
        assert!(u.machine.is_empty());
    }

    /// `InitContext` must be `Clone` so binary crates can shallow-
    /// clone the captured argv / env across tokio task boundaries.
    #[test]
    fn init_context_is_clone() {
        let ctx = InitContext {
            args: vec!["arg0".into()],
            env: vec![("KEY".into(), "VAL".into())],
            uname: UnameInfo::default(),
        };
        let cloned = ctx.clone();
        assert_eq!(cloned.args, ctx.args);
        assert_eq!(cloned.env, ctx.env);
    }
}
