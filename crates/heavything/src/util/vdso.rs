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

//! vDSO fast time access. API-preservation stub — Rust's `std::time`
//! already uses vDSO on Linux automatically. Port of `vdso.inc`.
//!
//! # Historical Context (FASM original)
//!
//! The original `vdso.inc` (~200 lines) parses `/proc/self/auxv` looking
//! for the `AT_SYSINFO_EHDR` (0x21) auxiliary-vector entry, then walks
//! the ELF64 program-header table in the kernel-mapped vDSO page to
//! resolve the addresses of `__vdso_gettimeofday` and
//! `__vdso_clock_gettime`. Those symbols are then invoked directly from
//! `hmac_drbg.inc` / `rng.inc` seeding, `epoll.inc` timer math, and the
//! `profiler.inc` `rdtsc` complement to provide microsecond-accurate
//! wall-clock time without the syscall-trap overhead of a plain
//! `gettimeofday(2)` call.
//!
//! # Rust Strategy (per AAP §0.5.1.7)
//!
//! This module is an **API-preservation thin wrapper**. On Linux,
//! Rust's `std::time::SystemTime::now()` and `std::time::Instant::now()`
//! internally call `clock_gettime(2)` through `libc`, which libc
//! resolves against the vDSO on process startup. We therefore get the
//! vDSO acceleration for free — the hand-rolled ELF-walking logic in
//! the FASM original becomes unnecessary and would merely duplicate
//! what `libc` already does.
//!
//! The public API here mirrors the shape the FASM callers expect:
//! integer nanosecond / microsecond / millisecond counters rather than
//! `Duration` values (AAP §0.5.1.7 "preserves FASM's integer-based
//! timing API").
//!
//! # Monotonic vs. Wall-Clock
//!
//! Two families of functions are exposed:
//!
//! * [`now_ns`], [`now_us`], [`now_ms`] — **monotonic** counters
//!   measured from process start via [`Instant`]. Immune to system
//!   clock jumps (NTP adjustments, `settimeofday`, DST). Use these for
//!   microbenchmarks, timeouts, and rate limiting. Backed by
//!   `CLOCK_MONOTONIC` via the vDSO.
//!
//! * [`wall_unix_ns`], [`wall_unix_us`], [`wall_unix_secs`] —
//!   **wall-clock** Unix-epoch timestamps via [`SystemTime`]. Subject
//!   to NTP / manual adjustments. Use these only for timestamp
//!   recordkeeping (HTTP `Date` headers, syslog timestamps,
//!   certificate validity windows). Backed by `CLOCK_REALTIME` via
//!   the vDSO.
//!
//! # Consumers
//!
//! * `lib.rs` Stage 7 — calls [`init`] to warm the `OnceLock`
//!   capturing the process-start [`Instant`]. The call site is
//!   `let _ = crate::util::vdso::init();` — hence the unit return
//!   type of [`init`] is LOAD-BEARING.
//! * `util::profiler` — ad-hoc timing measurements.
//! * `net::http::server` — indirectly via `util::date` for
//!   HTTP `Date:` header emission.
//!
//! # Example
//!
//! ```
//! use heavything::util::vdso;
//!
//! vdso::init(); // optional; auto-initialized on first `now_*` call
//!
//! let t0 = vdso::now_ns();
//! // ... work ...
//! let t1 = vdso::now_ns();
//! let elapsed_ns = t1.saturating_sub(t0);
//! assert!(elapsed_ns < u64::MAX);
//!
//! let unix_secs = vdso::wall_unix_secs();
//! assert!(unix_secs > 1_577_836_800); // after 2020-01-01
//! ```

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Process-start [`Instant`] used as the reference point for
/// [`now_ns`], [`now_us`], and [`now_ms`].
///
/// Lazy-initialized on first call via [`OnceLock::get_or_init`], or
/// explicitly by [`init`]. Once populated, all subsequent reads are a
/// single atomic load with `Acquire` ordering — essentially free.
///
/// The choice of [`OnceLock`] (stable since Rust 1.70) over
/// `once_cell::sync::OnceCell` satisfies AAP §0.8.3's "uses
/// `std::sync::OnceLock` (NOT `once_cell::sync::OnceCell`)" rule;
/// it keeps this module dependency-free beyond the standard library.
static PROCESS_START: OnceLock<Instant> = OnceLock::new();

/// Initialize the vDSO helpers by capturing the process-start
/// [`Instant`] reference point.
///
/// **Infallible — returns `()`.** This signature is LOAD-BEARING
/// because it matches the `lib.rs` Stage 7 call site:
///
/// ```text
/// #[cfg(feature = "util")]
/// { let _ = crate::util::vdso::init(); }
/// ```
///
/// On Linux, Rust's `std::time` already resolves vDSO symbols at
/// process start without any application action, so this function
/// performs no syscalls and only seeds the [`OnceLock`] reference
/// point for monotonic time queries.
///
/// This function is idempotent — calling it multiple times is a
/// no-op after the first invocation. It is safe to call from any
/// thread, at any time during program execution.
///
/// If [`init`] is never called explicitly, the [`OnceLock`] is
/// seeded lazily on the first [`now_ns`] / [`now_us`] / [`now_ms`]
/// call, so wrappers around these functions also work correctly
/// without a prior init.
pub fn init() {
    // We intentionally discard the returned `&Instant`; the side
    // effect of seeding `PROCESS_START` is the whole point.
    let _ = PROCESS_START.get_or_init(Instant::now);
}

/// Return the number of nanoseconds since process start.
///
/// Monotonic — immune to wall-clock adjustments (NTP slew, DST
/// transitions, manual `settimeofday`). Backed by
/// `CLOCK_MONOTONIC` via the Linux vDSO
/// (`__vdso_clock_gettime(CLOCK_MONOTONIC, ...)`).
///
/// On first call this lazily seeds [`PROCESS_START`], so the first
/// return value is always `0` (or a tiny nanosecond delta on
/// sufficiently fast hardware). Subsequent calls are non-decreasing.
///
/// # Overflow Behavior
///
/// [`std::time::Duration::as_nanos`] returns `u128` to accommodate
/// durations longer than `u64::MAX` nanoseconds (~584 years).
/// Because `u64::MAX` nanoseconds is ~584 years, a live process will
/// never realistically overflow the `u64` return value. The cast is
/// therefore safe for any plausible process uptime; for theoretical
/// completeness, values exceeding `u64::MAX` are truncated via the
/// `as u64` cast — this cannot occur in practice.
///
/// # Returns
///
/// Nanoseconds elapsed since the first call to either [`init`] or
/// any `now_*` function — whichever was first.
pub fn now_ns() -> u64 {
    let start = PROCESS_START.get_or_init(Instant::now);
    let elapsed = start.elapsed();
    // u128 → u64 truncation is safe for any realistic process uptime
    // (u64::MAX nanoseconds ≈ 584 years). See the overflow note above.
    elapsed.as_nanos() as u64
}

/// Return the number of microseconds since process start.
///
/// Monotonic wrapper around [`now_ns`] — see that function for
/// semantics. This is a pure integer division of the nanosecond
/// counter and imposes no additional syscall or clock-query cost
/// beyond [`now_ns`].
pub fn now_us() -> u64 {
    now_ns() / 1_000
}

/// Return the number of milliseconds since process start.
///
/// Monotonic wrapper around [`now_ns`] — see that function for
/// semantics. This is a pure integer division of the nanosecond
/// counter and imposes no additional syscall or clock-query cost
/// beyond [`now_ns`].
pub fn now_ms() -> u64 {
    now_ns() / 1_000_000
}

/// Return the current wall-clock time in Unix nanoseconds
/// (nanoseconds since 1970-01-01 00:00:00 UTC).
///
/// Wraps [`SystemTime::now`] and computes the duration since
/// [`UNIX_EPOCH`], which internally uses the vDSO
/// `__vdso_clock_gettime(CLOCK_REALTIME, ...)` on Linux.
///
/// # Clock Adjustments
///
/// Unlike [`now_ns`], this value **is** affected by wall-clock
/// adjustments (NTP, `adjtime`, `settimeofday`). Monotonicity is
/// NOT guaranteed across successive calls. Use [`now_ns`] for
/// timing measurements.
///
/// # Edge Case: Pre-Epoch Clocks
///
/// If the system clock is set to a time before 1970-01-01 UTC
/// (which indicates a seriously misconfigured or virgin embedded
/// system), [`SystemTime::duration_since`] returns `Err`. In that
/// case this function returns `0` rather than panicking — callers
/// should treat `0` as a sentinel indicating either epoch-exact
/// time or clock misconfiguration.
pub fn wall_unix_ns() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as u64,
        // Clock before 1970-01-01 — return 0 sentinel (see doc).
        Err(_) => 0,
    }
}

/// Return the current wall-clock time in Unix microseconds.
///
/// Wraps [`SystemTime::now`]. See [`wall_unix_ns`] for clock
/// adjustment and edge-case semantics.
///
/// This is computed from [`wall_unix_ns`] via a single integer
/// division, so the underlying clock source and precision trade-off
/// match [`wall_unix_ns`] exactly.
pub fn wall_unix_us() -> u64 {
    wall_unix_ns() / 1_000
}

/// Return the current wall-clock time in Unix seconds (seconds
/// since 1970-01-01 00:00:00 UTC).
///
/// Wraps [`SystemTime::now`] directly for full `u64` seconds range
/// (rather than deriving from the nanosecond counter, which would
/// truncate at year 2554 due to `u64` nanosecond overflow).
///
/// # Clock Adjustments
///
/// Affected by wall-clock adjustments — see [`wall_unix_ns`].
///
/// # Edge Case: Pre-Epoch Clocks
///
/// Returns `0` if the system clock is before 1970-01-01 UTC (see
/// [`wall_unix_ns`] for the same sentinel convention).
pub fn wall_unix_secs() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// Unit tests — exercise every public function and verify the documented
// invariants (idempotency, monotonicity, unit consistency, epoch sanity).
// Live under `#[cfg(test)]` so they contribute zero bytes to release builds.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// [`init`] must be safely callable multiple times without panic
    /// or error. The first call seeds `PROCESS_START`; subsequent
    /// calls are no-ops because `OnceLock::get_or_init` returns the
    /// existing value.
    #[test]
    fn init_is_idempotent() {
        init();
        init();
        init();
        // If we reached here without panicking, idempotency holds.
    }

    /// [`init`] must return `()` — this is the LOAD-BEARING contract
    /// with `lib.rs` Stage 7's `let _ = crate::util::vdso::init();`
    /// call site. If this test fails to compile, the `init()` return
    /// type has changed and lib.rs's Stage 7 code will no longer
    /// compile either.
    #[test]
    #[allow(clippy::let_unit_value, clippy::unit_cmp)]
    fn init_returns_unit() {
        let r: () = init();
        assert_eq!(r, ());
    }

    /// [`now_ns`] must be monotonically non-decreasing across
    /// successive calls. This is the single most important
    /// invariant for using the counter in timeouts, profiling, and
    /// rate limiting — a time-going-backward bug at this layer
    /// would cascade into every higher-level timer.
    #[test]
    fn now_ns_monotonic() {
        init();
        let a = now_ns();
        let b = now_ns();
        assert!(b >= a, "now_ns must be monotonic: {a} -> {b}");
    }

    /// [`now_us`] and [`now_ms`] must agree with [`now_ns`] modulo
    /// integer division, within a tolerance for test-execution drift
    /// between the three calls. The tolerance is generous (10 ms
    /// between `us` and `ns`, 10 ms between `ms` and `us`) to keep
    /// the test stable on loaded CI runners.
    #[test]
    fn now_units_consistent() {
        let ns = now_ns();
        let us = now_us();
        let ms = now_ms();
        // `us` should be within 10 ms (10_000 µs) of `ns/1000`.
        assert!(
            (ns / 1_000).abs_diff(us) < 10_000,
            "us/ns mismatch: ns={ns} ns/1000={} us={us}",
            ns / 1_000
        );
        // `ms` should be within 10 ms of `us/1000`.
        assert!(
            (us / 1_000).abs_diff(ms) < 10,
            "ms/us mismatch: us={us} us/1000={} ms={ms}",
            us / 1_000
        );
    }

    /// [`wall_unix_secs`] must return a value that is reasonable for
    /// the present era. The lower bound (`1_577_836_800`) is
    /// 2020-01-01 00:00:00 UTC — older than the refactor itself, so
    /// any machine running this test must have a clock past it. The
    /// upper bound (`4_102_444_800`) is 2100-01-01 00:00:00 UTC —
    /// well within `u64` range and comfortably ahead of present day.
    /// Sanity bounds catch the common misconfigurations of
    /// unconfigured RTC (epoch = 0 or epoch = 1970-*) and
    /// absurdly-advanced clocks (cosmic-ray bit flips, filesystem
    /// corruption writing epoch values).
    #[test]
    fn wall_unix_sane() {
        let secs = wall_unix_secs();
        assert!(secs > 1_577_836_800, "wall time before 2020: secs={secs}");
        assert!(secs < 4_102_444_800, "wall time after 2100: secs={secs}");
    }

    /// Additional sanity: the three wall-clock flavors (`secs`,
    /// `us`, `ns`) must agree on the second boundary. Because they
    /// read the clock at slightly different moments, we allow a
    /// 2-second drift — generous for a CI box.
    #[test]
    fn wall_units_consistent() {
        let secs = wall_unix_secs();
        let us = wall_unix_us();
        let ns = wall_unix_ns();
        assert!(
            (us / 1_000_000).abs_diff(secs) < 2,
            "wall us/secs mismatch: us={us} us/1e6={} secs={secs}",
            us / 1_000_000
        );
        assert!(
            (ns / 1_000_000_000).abs_diff(secs) < 2,
            "wall ns/secs mismatch: ns={ns} ns/1e9={} secs={secs}",
            ns / 1_000_000_000
        );
    }
}
