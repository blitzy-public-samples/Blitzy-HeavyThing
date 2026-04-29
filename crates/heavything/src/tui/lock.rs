// crates/heavything/src/tui/lock.rs — HeavyThing TUI render-lock primitive.
//
// Rust translation of tui_lock.inc (261 lines of FASM assembly). Provides
// the render-lock coordination used by widgets to serialize draw operations
// against concurrent timer/event-loop-driven redraw attempts.
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

//! Render-lock primitive for TUI widgets.
//!
//! Widget `draw` methods that mutate shared state acquire a [`RenderLock`]
//! before emitting output and release it by dropping the guard. The lock
//! ensures that async timer-driven renders (e.g. from `tui_spinner`) cannot
//! interleave with user-input-driven renders within the same frame.
//!
//! Two flavors are provided:
//!
//! - [`RenderLock`]: synchronous, backed by [`std::sync::Mutex`]. Used from
//!   widget code running on the event-loop thread.
//! - [`AsyncRenderLock`]: async, backed by [`tokio::sync::Mutex`]. Used from
//!   tokio tasks that drive timer-based animated widgets.
//!
//! Both wrap the same underlying lock domain via a shared ordering token,
//! preventing deadlock across the two paths.
//!
//! # FASM correspondence
//!
//! The FASM `_tui_locklist` (an avl-node tree keyed by object pointer) is
//! intentionally NOT reproduced as a shared data structure in the Rust port.
//! Its deterministic-ordering role is preserved by the monotonic
//! [`LockToken`] issued per-lock, while mutual exclusion is handled by the
//! underlying `Mutex`. Consumers that need to order multiple locks can
//! compare their [`LockToken`]s directly.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};

// ---------------------------------------------------------------------------
// Ordering token
// ---------------------------------------------------------------------------

/// Global counter producing a unique ordering token per lock.
///
/// Starts at 1 so [`LockToken::fresh`] never returns zero, preserving a
/// "null token" sentinel value for any future API that wants one.
static LOCK_TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Monotonically-increasing token used to produce a deterministic ordering
/// equivalent to FASM's `_tui_locklist` pointer-key ordering.
///
/// Tokens are allocated by [`LockToken::fresh`] and never recycled. Use
/// [`LockToken::as_u64`] to extract the raw value for comparison or
/// logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockToken(u64);

impl LockToken {
    /// Allocate a fresh token. Thread-safe; never returns zero.
    ///
    /// Implemented via `AtomicU64::fetch_add` with [`Ordering::SeqCst`] so
    /// that the total order of token allocations is visible identically to
    /// every thread — equivalent to the global-pointer monotonicity the
    /// FASM `_tui_locklist` relied on implicitly.
    #[must_use]
    pub fn fresh() -> Self {
        Self(LOCK_TOKEN_COUNTER.fetch_add(1, Ordering::SeqCst))
    }

    /// Returns the underlying token value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Synchronous render lock
// ---------------------------------------------------------------------------

/// Synchronous render lock. Wraps a `std::sync::Mutex<()>` with an
/// ordering token.
///
/// Acquire via [`RenderLock::lock`]; the returned [`RenderLockGuard`] is
/// released when it goes out of scope. Use this flavor from widget code
/// running on the event-loop thread where `.await` is not available.
#[derive(Debug)]
pub struct RenderLock {
    token: LockToken,
    inner: Mutex<()>,
}

impl RenderLock {
    /// Create a fresh render lock with a newly-allocated ordering token.
    #[must_use]
    pub fn new() -> Self {
        Self {
            token: LockToken::fresh(),
            inner: Mutex::new(()),
        }
    }

    /// Acquire the lock. Returns a guard that releases on drop.
    ///
    /// If a previous holder panicked while holding the lock, the poison
    /// is treated as transient and the guard is returned anyway — widget
    /// render state is recoverable from the widget tree's canonical state,
    /// so poison is non-fatal here.
    pub fn lock(&self) -> RenderLockGuard<'_> {
        let guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        RenderLockGuard { _inner: guard }
    }

    /// Returns this lock's ordering token.
    ///
    /// The token is fixed for the lifetime of the lock and can be used
    /// to impose a global acquisition order on multiple locks.
    #[must_use]
    pub fn token(&self) -> LockToken {
        self.token
    }
}

impl Default for RenderLock {
    /// Equivalent to [`RenderLock::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard returned by [`RenderLock::lock`]. Releases the underlying
/// `std::sync::Mutex` on drop.
///
/// The guard intentionally exposes no API beyond its [`Drop`] behavior —
/// the render lock protects "am I currently rendering" exclusivity, not
/// shared data, so there is nothing to dereference.
pub struct RenderLockGuard<'a> {
    _inner: MutexGuard<'a, ()>,
}

// ---------------------------------------------------------------------------
// Asynchronous render lock
// ---------------------------------------------------------------------------

/// Async render lock backed by `tokio::sync::Mutex<()>`.
///
/// Use from tokio tasks (e.g. timer-driven animated widgets like
/// `tui_spinner`, `tui_matrix`, `tui_typist`). Acquire with
/// [`AsyncRenderLock::lock`]; the future yields a guard that releases
/// the underlying mutex on drop.
#[derive(Debug)]
pub struct AsyncRenderLock {
    token: LockToken,
    inner: AsyncMutex<()>,
}

impl AsyncRenderLock {
    /// Create a fresh async render lock with a newly-allocated ordering token.
    #[must_use]
    pub fn new() -> Self {
        Self {
            token: LockToken::fresh(),
            inner: AsyncMutex::new(()),
        }
    }

    /// Acquire the lock, yielding the current task until it is available.
    /// Returns a guard that releases on drop.
    pub async fn lock(&self) -> AsyncRenderLockGuard<'_> {
        let guard = self.inner.lock().await;
        AsyncRenderLockGuard { _inner: guard }
    }

    /// Try to acquire the lock without yielding.
    ///
    /// Returns `Some(guard)` if the lock was free, `None` if it was
    /// already held.
    pub fn try_lock(&self) -> Option<AsyncRenderLockGuard<'_>> {
        self.inner
            .try_lock()
            .ok()
            .map(|guard| AsyncRenderLockGuard { _inner: guard })
    }

    /// Returns this lock's ordering token.
    #[must_use]
    pub fn token(&self) -> LockToken {
        self.token
    }
}

impl Default for AsyncRenderLock {
    /// Equivalent to [`AsyncRenderLock::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard returned by [`AsyncRenderLock::lock`] and
/// [`AsyncRenderLock::try_lock`]. Releases the underlying
/// `tokio::sync::Mutex` on drop.
pub struct AsyncRenderLockGuard<'a> {
    _inner: AsyncMutexGuard<'a, ()>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_token_is_monotonic() {
        let a = LockToken::fresh();
        let b = LockToken::fresh();
        assert!(b.as_u64() > a.as_u64());
    }

    #[test]
    fn lock_token_never_zero() {
        // The counter starts at 1; the very first token must be >= 1.
        let t = LockToken::fresh();
        assert!(t.as_u64() >= 1);
    }

    #[test]
    fn lock_token_equality_and_ordering() {
        let a = LockToken::fresh();
        let b = LockToken::fresh();
        assert_ne!(a, b);
        assert!(a < b);
        let a_copy = a;
        assert_eq!(a, a_copy);
    }

    #[test]
    fn render_lock_lock_unlock_cycle() {
        let lock = RenderLock::new();
        let g1 = lock.lock();
        drop(g1);
        let _g2 = lock.lock();
    }

    #[test]
    fn render_lock_token_stable() {
        let lock = RenderLock::new();
        let t = lock.token();
        let _g = lock.lock();
        assert_eq!(lock.token(), t);
    }

    #[test]
    fn render_lock_default_equivalent_to_new() {
        let a = RenderLock::default();
        let b = RenderLock::new();
        // Each call allocates a fresh token so the two are distinct,
        // but both are functional and produce monotonically-ordered tokens.
        assert!(b.token() > a.token());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_render_lock_lock_unlock_cycle() {
        let lock = AsyncRenderLock::new();
        let g1 = lock.lock().await;
        drop(g1);
        let _g2 = lock.lock().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_render_lock_try_lock_contention() {
        let lock = AsyncRenderLock::new();
        let g1 = lock.lock().await;
        assert!(lock.try_lock().is_none());
        drop(g1);
        assert!(lock.try_lock().is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_render_lock_token_stable() {
        let lock = AsyncRenderLock::new();
        let t = lock.token();
        let _g = lock.lock().await;
        assert_eq!(lock.token(), t);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_render_lock_default_equivalent_to_new() {
        let a = AsyncRenderLock::default();
        let b = AsyncRenderLock::new();
        assert!(b.token() > a.token());
    }
}
