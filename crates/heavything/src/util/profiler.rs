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

//! Profiler API-preservation stub — port of `profiler.inc`.
//!
//! The original FASM `profiler.inc` (1,315 lines) implements an
//! automatic per-function callgraph profiler driven by the `prolog`
//! macro expanded at every function entry. When the compile-time
//! flag `profiling = 1` is set, each function entry/exit is stamped
//! with `rdtsc` and the results are accumulated into per-function
//! call counts and cycle totals. When `calltracing = 1` the entries
//! are additionally emitted to `stderr`.
//!
//! Per AAP §0.5.1.7 the Rust port is a **thin API-preservation
//! wrapper**: actual profiling is delegated to `cargo bench` +
//! `criterion` (see `crates/heavything/benches/*.rs` for the
//! benchmark harnesses). **CPC records omitted per AAP §0.5.1.7.**
//!
//! The public functions [`init`], [`shutdown`], [`enter`], [`exit`],
//! and [`is_enabled`] are deliberately no-ops. They exist solely so
//! that translated FASM-style prologue/epilogue call sites compile
//! unchanged; the Rust compiler fully elides them in release builds.
//!
//! [`Timer`] is a small developer convenience not present in the
//! FASM original — a scoped ad-hoc timing helper that prints only in
//! debug builds and is guaranteed to compile away to nothing when
//! `debug_assertions` is disabled.
//!
//! # Example
//!
//! ```
//! use heavything::util::profiler;
//!
//! // Lifecycle hooks are infallible no-ops:
//! profiler::init();
//! profiler::enter("my_function");
//! profiler::exit("my_function");
//! profiler::shutdown();
//!
//! // `is_enabled` is a `const fn` returning `false` so the compiler
//! // can eliminate any gated code path entirely.
//! const _: bool = profiler::is_enabled();
//! ```

use std::time::Instant;

// ============================================================================
// Public no-op lifecycle hooks.
// ============================================================================

/// Initialize the profiler subsystem.
///
/// **Infallible no-op.** In the Rust port, runtime profiling is
/// delegated entirely to `cargo bench` + `criterion`. This function
/// exists only for source-level API compatibility with translated
/// modules that may call it; the compiler will elide every call site
/// in release builds.
#[inline]
pub fn init() {
    // Intentionally empty — profiling lives in `cargo bench`.
}

/// Finalize the profiler and emit any recorded statistics.
///
/// **No-op in the Rust port.** The FASM `profiler.inc` uses this to
/// flush the accumulated per-function cycle totals to `stderr`; in
/// Rust the equivalent output is produced by `criterion` directly
/// under `target/criterion/`.
#[inline]
pub fn shutdown() {
    // Intentionally empty — criterion writes its own reports.
}

/// Record a function entry event.
///
/// **No-op in the Rust port** — function-level instrumentation is
/// not emitted. The parameter is accepted solely so that translated
/// modules preserving FASM-style `prolog name` call sites compile;
/// the optimizer removes both the call and the argument.
///
/// # Parameters
///
/// * `_function_name` — a `'static` label (unused).
#[inline]
pub fn enter(_function_name: &'static str) {
    // Intentionally empty — Rust's profiler is criterion.
}

/// Record a function exit event.
///
/// **No-op in the Rust port.** Paired with [`enter`] for symmetry
/// with the FASM `prolog`/`epilog` pattern; the optimizer removes
/// every call site.
///
/// # Parameters
///
/// * `_function_name` — a `'static` label (unused).
#[inline]
pub fn exit(_function_name: &'static str) {
    // Intentionally empty.
}

/// Return `true` if runtime profiling is enabled.
///
/// **Always returns `false`** in the Rust port. Declared `const fn`
/// so callers writing `if profiler::is_enabled() { … }` will have
/// the gated block entirely removed by dead-code elimination.
#[inline]
#[must_use]
pub const fn is_enabled() -> bool {
    false
}

// ============================================================================
// Timer — lightweight scoped ad-hoc timing helper.
// ============================================================================

/// Lightweight scoped timer for ad-hoc debugging measurements.
///
/// Not part of the original FASM API; provided as a Rust convenience
/// for developers wanting a one-line stopwatch without a full
/// `criterion` harness. The underlying clock is
/// [`std::time::Instant`], which on Linux x86_64 is vDSO-accelerated
/// (`CLOCK_MONOTONIC`) and therefore has no syscall cost.
///
/// In **debug builds** ([`cfg(debug_assertions)`]),
/// [`Timer::finish`] prints the elapsed duration to `stderr`.
/// In **release builds** the entire struct is elided — the name
/// field is bound-and-discarded, the `Instant` is dropped, and no
/// output is produced.
///
/// # Consumption Semantics
///
/// [`Timer::finish`] takes `self` by value, so the timer can only
/// be finished once. This prevents double-report bugs at compile
/// time (the borrow checker rejects any subsequent use).
///
/// # Example
///
/// ```no_run
/// use heavything::util::profiler::Timer;
///
/// let t = Timer::start("my_operation");
/// // … do work …
/// t.finish(); // prints to stderr in debug builds; no-op in release
/// ```
///
/// To peek at the elapsed time without consuming the timer, use
/// [`Timer::elapsed_ns`]:
///
/// ```no_run
/// use heavything::util::profiler::Timer;
///
/// let t = Timer::start("streaming_op");
/// // … first chunk of work …
/// let _first_ns = t.elapsed_ns();
/// // … second chunk of work …
/// t.finish();
/// ```
#[derive(Debug)]
pub struct Timer {
    /// Human-readable label used by [`Timer::finish`] in debug
    /// builds; dropped without being read in release builds.
    name: &'static str,

    /// Monotonic timestamp captured at [`Timer::start`].
    start: Instant,
}

impl Timer {
    /// Start a new timer, capturing the current monotonic instant.
    ///
    /// # Parameters
    ///
    /// * `name` — a `'static` label printed by [`finish`](Self::finish)
    ///   in debug builds.
    #[inline]
    #[must_use]
    pub fn start(name: &'static str) -> Self {
        Self {
            name,
            start: Instant::now(),
        }
    }

    /// Finish the timer, consuming it.
    ///
    /// In debug builds (`cfg(debug_assertions)` enabled) the elapsed
    /// duration is formatted as `[profiler] <name>: <duration>` and
    /// written to `stderr`. In release builds the call is fully
    /// elided — the compiler may remove the entire construction.
    ///
    /// Consuming `self` prevents accidental double-reporting; a
    /// subsequent attempt to use the timer will fail to compile.
    #[inline]
    pub fn finish(self) {
        #[cfg(debug_assertions)]
        {
            let elapsed = self.start.elapsed();
            eprintln!("[profiler] {}: {:?}", self.name, elapsed);
        }
        #[cfg(not(debug_assertions))]
        {
            // Explicitly bind-and-discard so the field is read in
            // release builds; silences `dead_code` under
            // `-D warnings`.
            let _ = self.name;
        }
    }

    /// Return the elapsed nanoseconds since [`start`](Self::start)
    /// without consuming the timer.
    ///
    /// The result is clamped to [`u64::MAX`] in the unlikely event
    /// the elapsed duration exceeds ≈584 years of nanoseconds; no
    /// panic is possible.
    #[inline]
    #[must_use]
    pub fn elapsed_ns(&self) -> u64 {
        let nanos = self.start.elapsed().as_nanos();
        // `as_nanos()` returns `u128`; truncate to `u64`. The
        // saturation is defensive — a `u64` nanosecond counter
        // wraps after ~584 years so this branch is effectively
        // unreachable in any realistic program.
        if nanos > u128::from(u64::MAX) {
            u64::MAX
        } else {
            nanos as u64
        }
    }
}

// ============================================================================
// Tests.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn init_is_noop() {
        // Must be callable any number of times without side effects.
        init();
        init();
        init();
    }

    #[test]
    fn shutdown_is_noop() {
        // Must be callable without prior `init` and repeatable.
        shutdown();
        shutdown();
    }

    #[test]
    fn enter_exit_noop() {
        // Paired enter/exit must accept arbitrary `'static` labels.
        enter("test_function");
        exit("test_function");
        enter("another::function");
        exit("another::function");
    }

    #[test]
    fn is_enabled_is_false() {
        assert!(!is_enabled(), "profiler stub must always be disabled");
    }

    #[test]
    fn is_enabled_is_const() {
        // Exercise the `const fn` property in a const context.
        const ENABLED: bool = is_enabled();
        // `ENABLED` is a compile-time constant evaluated above — the
        // assertion below is the runtime witness that the const-eval agreed
        // with the feature-gated default. `#[allow]` silences clippy's
        // complaint that the assertion's value is statically known, which is
        // exactly the point of this regression test.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(!ENABLED);
        }
    }

    #[test]
    fn timer_basic_elapsed() {
        let t = Timer::start("test_basic");
        thread::sleep(Duration::from_millis(1));
        let ns = t.elapsed_ns();
        // Sleeping 1ms ≈ 1_000_000 ns, with generous tolerance.
        assert!(ns > 0, "elapsed_ns must be strictly positive after sleep");
        t.finish();
    }

    #[test]
    fn timer_elapsed_monotonic() {
        let t = Timer::start("test_monotonic");
        let first = t.elapsed_ns();
        // Busy-loop a little to ensure the clock advances.
        for _ in 0..10_000 {
            std::hint::black_box(0u64);
        }
        let second = t.elapsed_ns();
        assert!(second >= first, "Instant must be monotonic");
        t.finish();
    }

    #[test]
    fn timer_finish_consumes_self() {
        // The fact that this test compiles demonstrates that
        // `finish` takes ownership; there is no way to observe a
        // double-finish at runtime because it would fail to compile.
        let t = Timer::start("test_consume");
        t.finish();
        // `t` is moved — any use here would fail to compile.
    }

    #[test]
    fn timer_zero_elapsed_before_work() {
        // Immediately after `start`, `elapsed_ns` should be small
        // (likely single-digit nanoseconds on modern hardware).
        let t = Timer::start("test_zero");
        let ns = t.elapsed_ns();
        // Upper bound: 1 second is absurdly generous even on a
        // pathologically loaded CI runner.
        assert!(ns < 1_000_000_000, "fresh timer should read < 1s, got {ns}");
        t.finish();
    }

    #[test]
    fn timer_is_debug() {
        // Ensures the `Debug` derive is present; useful for
        // developer ergonomics.
        let t = Timer::start("debuggable");
        let s = format!("{t:?}");
        assert!(
            s.contains("Timer"),
            "expected Debug output to mention Timer, got: {s}"
        );
        t.finish();
    }
}
