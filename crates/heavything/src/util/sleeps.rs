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

//! Sleep helpers. Port of `sleeps.inc` — provides blocking and async variants.
//!
//! # Historical Context (FASM original)
//!
//! The original `sleeps.inc` (56 lines) defines three FASM macros that
//! inline the `nanosleep(2)` syscall directly into the caller:
//!
//! * `sleep tt` — block for `tt` whole seconds
//! * `usleep tt` — block for `tt` microseconds
//!   (`tv_nsec = tt * 1000`)
//! * `nanosleep tt` — block for `tt` nanoseconds
//!
//! All three allocate a 16-byte `struct timespec` on the red zone, fill
//! it in with `tv_sec` / `tv_nsec`, load `rdi = &ts`, `rsi = NULL`
//! (no remainder out-param), `eax = syscall_nanosleep`, and `syscall`.
//!
//! # Rust Strategy (per AAP §0.5.1.7)
//!
//! * **Blocking variants** — [`sleep_seconds`], [`sleep_millis`],
//!   [`sleep_micros`], [`sleep_nanos`], [`sleep`] — delegate to
//!   [`std::thread::sleep`]. On Linux `std::thread::sleep` issues a
//!   `clock_nanosleep(2)` (glibc) or `nanosleep(2)` syscall, matching
//!   the FASM macros byte-for-byte at the syscall level. Behavioural
//!   parity with the assembly baseline is preserved.
//!
//! * **Async variants** — [`sleep_seconds_async`],
//!   [`sleep_millis_async`], [`sleep_micros_async`], [`sleep_async`]
//!   — delegate to [`tokio::time::sleep`] which yields to the Tokio
//!   scheduler without blocking the executor thread. **These are the
//!   only correct sleep primitive inside an async task**; using
//!   `std::thread::sleep` inside an `async fn` blocks the entire
//!   worker thread (and all other tasks scheduled on it) and is a
//!   runtime bug.
//!
//! # Two Flavours, One Module
//!
//! Both sync and async variants coexist because `heavything` contains
//! both synchronous code paths (`init()` stages executed before the
//! Tokio runtime is entered — AAP §0.5.1.2) and asynchronous code
//! paths (everything running on the Tokio runtime after startup). A
//! caller must pick the variant that matches its execution context.
//!
//! # No Busy-Spin
//!
//! No busy-wait variant is provided. The Linux kernel scheduler is
//! able to wake a sleeping thread at microsecond granularity through
//! `CLOCK_MONOTONIC`, and ring down to 1-nanosecond precision on
//! modern hardware. If sub-microsecond precision is required, the
//! caller should be measuring cycle counts with `rdtsc` rather than
//! wall-clock sleeping.
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//! use heavything::util::sleeps;
//!
//! // Blocking — safe in synchronous code, forbidden inside `async fn`.
//! sleeps::sleep_millis(10);
//! sleeps::sleep(Duration::from_micros(500));
//!
//! # async fn ex() {
//! // Async — yields to the Tokio scheduler.
//! sleeps::sleep_millis_async(10).await;
//! sleeps::sleep_async(Duration::from_micros(500)).await;
//! # }
//! ```

use std::time::Duration;

// ============================================================================
// Blocking sleep helpers — for synchronous (non-async) call sites.
//
// These functions block the calling OS thread. They must NOT be called
// from inside an `async fn` body on a multi-threaded Tokio runtime, as
// doing so stalls the executor's worker thread and starves every other
// task scheduled on it. Use the `_async` counterparts in async contexts.
// ============================================================================

/// Block the current thread for `seconds` whole seconds.
///
/// Matches the FASM `sleep tt` macro from `sleeps.inc` line 24. Delegates
/// to [`std::thread::sleep`] which issues a `nanosleep(2)` / `clock_nanosleep(2)`
/// syscall on Linux, preserving syscall-level parity with the assembly
/// baseline.
///
/// A value of `0` returns (almost) immediately after a single scheduler
/// round-trip.
///
/// # Example
///
/// ```no_run
/// use heavything::util::sleeps;
/// sleeps::sleep_seconds(1);  // block for one second
/// ```
#[inline]
pub fn sleep_seconds(seconds: u64) {
    std::thread::sleep(Duration::from_secs(seconds));
}

/// Block the current thread for `millis` milliseconds.
///
/// Rust convenience built on top of the same `nanosleep(2)` primitive
/// the FASM macros wrap; kept in the sleeps API because millisecond
/// granularity is the most common call-site unit in translated code
/// (timer polling, backoff loops, etc.).
///
/// # Example
///
/// ```no_run
/// use heavything::util::sleeps;
/// sleeps::sleep_millis(250);  // quarter-second pause
/// ```
#[inline]
pub fn sleep_millis(millis: u64) {
    std::thread::sleep(Duration::from_millis(millis));
}

/// Block the current thread for `micros` microseconds.
///
/// Matches the FASM `usleep tt` macro from `sleeps.inc` line 35. The
/// assembly source computes `tv_nsec = tt * 1000`; the Rust port uses
/// [`Duration::from_micros`] which performs the same multiplication
/// internally.
///
/// # Example
///
/// ```no_run
/// use heavything::util::sleeps;
/// sleeps::sleep_micros(500);  // half-millisecond pause
/// ```
#[inline]
pub fn sleep_micros(micros: u64) {
    std::thread::sleep(Duration::from_micros(micros));
}

/// Block the current thread for `nanos` nanoseconds.
///
/// Matches the FASM `nanosleep tt` macro from `sleeps.inc` line 46 —
/// the most direct of the three wrappers. The kernel rounds the actual
/// sleep duration up to the resolution of the system timer (typically
/// 1 nanosecond on modern hardware), so for sub-microsecond intervals
/// the real sleep time may overshoot the requested value.
///
/// # Example
///
/// ```no_run
/// use heavything::util::sleeps;
/// sleeps::sleep_nanos(100_000);  // 100 microseconds in ns units
/// ```
#[inline]
pub fn sleep_nanos(nanos: u64) {
    std::thread::sleep(Duration::from_nanos(nanos));
}

/// Block the current thread for a specific [`Duration`].
///
/// Accepts any [`Duration`] value for maximum flexibility (e.g. sums,
/// arithmetic results, configuration values loaded at runtime). Thin
/// forwarder to [`std::thread::sleep`].
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
/// use heavything::util::sleeps;
/// sleeps::sleep(Duration::from_millis(50) + Duration::from_micros(250));
/// ```
#[inline]
pub fn sleep(duration: Duration) {
    std::thread::sleep(duration);
}

// ============================================================================
// Async sleep helpers — for code running on the Tokio runtime.
//
// These await on [`tokio::time::sleep`] which registers a timer with the
// runtime's timer wheel and yields back to the scheduler. They do not
// hold the executor thread and are therefore safe to call from within
// any `async fn` on the `heavything` tokio runtime.
// ============================================================================

/// Asynchronously sleep for `seconds` whole seconds.
///
/// Yields to the Tokio scheduler so other tasks on the same worker
/// thread can make progress during the wait. Equivalent to calling
/// [`sleep_seconds`] from a synchronous context, but non-blocking with
/// respect to the executor.
///
/// # Example
///
/// ```
/// # async fn ex() {
/// use heavything::util::sleeps;
/// sleeps::sleep_seconds_async(0).await;  // yields once
/// # }
/// ```
#[inline]
pub async fn sleep_seconds_async(seconds: u64) {
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

/// Asynchronously sleep for `millis` milliseconds.
///
/// Non-blocking counterpart of [`sleep_millis`]. The most commonly
/// used async-timing primitive in the `heavything` net stack (HTTP
/// polling, TLS handshake timeouts, SSH keepalives).
///
/// # Example
///
/// ```
/// # async fn ex() {
/// use heavything::util::sleeps;
/// sleeps::sleep_millis_async(5).await;
/// # }
/// ```
#[inline]
pub async fn sleep_millis_async(millis: u64) {
    tokio::time::sleep(Duration::from_millis(millis)).await;
}

/// Asynchronously sleep for `micros` microseconds.
///
/// Non-blocking counterpart of [`sleep_micros`]. Tokio's timer wheel
/// resolution is typically 1 ms on Linux; for sub-millisecond waits
/// the actual yield duration may round up to the next tick.
///
/// # Example
///
/// ```
/// # async fn ex() {
/// use heavything::util::sleeps;
/// sleeps::sleep_micros_async(500).await;
/// # }
/// ```
#[inline]
pub async fn sleep_micros_async(micros: u64) {
    tokio::time::sleep(Duration::from_micros(micros)).await;
}

/// Asynchronously sleep for a specific [`Duration`].
///
/// Non-blocking counterpart of [`sleep`]. Accepts any [`Duration`]
/// value, enabling callers to pass arithmetic results, config values,
/// or backoff computations without unit conversions.
///
/// # Example
///
/// ```
/// # async fn ex() {
/// use std::time::Duration;
/// use heavything::util::sleeps;
/// sleeps::sleep_async(Duration::from_millis(10)).await;
/// # }
/// ```
#[inline]
pub async fn sleep_async(duration: Duration) {
    tokio::time::sleep(duration).await;
}

// ============================================================================
// Tests
// ============================================================================
//
// Tests use generous timing slack because scheduler latency under CI
// load can delay wake-ups well beyond the nominal sleep duration.
// Lower bounds verify the sleep actually happened; upper bounds are
// loose enough to tolerate common CI jitter (seen up to ~300ms on
// heavily loaded VMs) without false failures.

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// A 10ms blocking sleep must elapse at least 10ms (lower bound)
    /// and finish within 500ms (upper bound — generous CI slack).
    #[test]
    fn sleep_millis_reasonable() {
        let start = Instant::now();
        sleep_millis(10);
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(10),
            "slept {}ms, expected >= 10ms",
            elapsed.as_millis()
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "slept {}ms, expected < 500ms",
            elapsed.as_millis()
        );
    }

    /// A zero-duration sleep must return promptly (within 100ms even
    /// on very loaded CI hardware — one scheduler round-trip).
    #[test]
    fn sleep_zero_returns_immediately() {
        let start = Instant::now();
        sleep_millis(0);
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "sleep_millis(0) took {}ms, expected < 100ms",
            start.elapsed().as_millis()
        );
    }

    /// Passing a [`Duration`] directly works end-to-end.
    #[test]
    fn sleep_duration_works() {
        let start = Instant::now();
        sleep(Duration::from_millis(5));
        assert!(
            start.elapsed() >= Duration::from_millis(5),
            "sleep(5ms) elapsed only {}ms",
            start.elapsed().as_millis()
        );
    }

    /// Microsecond blocking sleep completes and consumes measurable
    /// time (at least 100µs for a 500µs request under CI slack).
    #[test]
    fn sleep_micros_works() {
        let start = Instant::now();
        sleep_micros(500);
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_micros(100),
            "sleep_micros(500) elapsed only {}µs, expected >= 100µs",
            elapsed.as_micros()
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "sleep_micros(500) took {}ms, expected < 500ms",
            elapsed.as_millis()
        );
    }

    /// `sleep_seconds(0)` is equivalent to a one-round-trip yield.
    #[test]
    fn sleep_seconds_zero_returns_quickly() {
        let start = Instant::now();
        sleep_seconds(0);
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "sleep_seconds(0) took {}ms, expected < 100ms",
            start.elapsed().as_millis()
        );
    }

    /// `sleep_nanos` completes and does not panic for a small value.
    #[test]
    fn sleep_nanos_works() {
        let start = Instant::now();
        sleep_nanos(1_000_000); // 1 ms
        assert!(
            start.elapsed() >= Duration::from_nanos(100_000),
            "sleep_nanos(1ms) elapsed only {}ns",
            start.elapsed().as_nanos()
        );
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "sleep_nanos(1ms) took {}ms, expected < 500ms",
            start.elapsed().as_millis()
        );
    }

    /// Async sleep completes, elapses at least the requested duration,
    /// and finishes within CI-tolerant slack. Uses `#[tokio::test]`
    /// which spins up a single-threaded runtime per test.
    #[tokio::test]
    async fn sleep_async_works() {
        let start = Instant::now();
        sleep_millis_async(10).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(10),
            "async slept {}ms, expected >= 10ms",
            elapsed.as_millis()
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "async slept {}ms, expected < 500ms",
            elapsed.as_millis()
        );
    }

    /// Async [`sleep_async`] taking a [`Duration`] also works.
    #[tokio::test]
    async fn sleep_async_duration_works() {
        let start = Instant::now();
        sleep_async(Duration::from_millis(5)).await;
        assert!(
            start.elapsed() >= Duration::from_millis(5),
            "sleep_async(5ms) elapsed only {}ms",
            start.elapsed().as_millis()
        );
    }

    /// Async seconds variant with zero completes promptly.
    #[tokio::test]
    async fn sleep_seconds_async_zero_returns_quickly() {
        let start = Instant::now();
        sleep_seconds_async(0).await;
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "sleep_seconds_async(0) took {}ms, expected < 100ms",
            start.elapsed().as_millis()
        );
    }

    /// Async microsecond variant completes for a small value.
    #[tokio::test]
    async fn sleep_micros_async_works() {
        let start = Instant::now();
        sleep_micros_async(500).await;
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "sleep_micros_async(500µs) took {}ms, expected < 500ms",
            start.elapsed().as_millis()
        );
    }
}
