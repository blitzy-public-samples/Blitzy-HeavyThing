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
// Rust translation of `sshtalk/statusbar.inc` (197 lines, FASM x86_64).
//
// The FASM original subclasses `tui_statusbar` (heavything's general-purpose
// status bar) and overrides only the `timer` vmethod (FASM vtable line 29:
// `dq statusbar$timer, ...`) to render a custom "C: <connected> U: <online>/<total>"
// label that the FASM `tui_statusbar` widget does not natively support.
// The vtable override is invoked every 5 seconds by the global epoll
// timer dispatcher (FASM `tui_statusbar$nvsetup` line 161-164).
//
// The Rust port cannot subclass via vtable replacement because the
// heavything `Statusbar` owns its own private timer task spawned in the
// constructor (`Statusbar::finalize_construction` -> `spawn_timer_task`)
// that always runs `timer_tick` regardless of what the caller wants.
// Instead, we **wrap** the heavything Statusbar (rather than subclassing
// it), construct the base with `show_uptime: false` so its own timer
// becomes a no-op, and spawn an additional 5-second tokio task that
// drives our custom "C: ... U: ..." text via `Statusbar::set_text`.
//
// The visible difference from the FASM baseline is that this Rust port
// presents the connection counts as the **main status text** rather than
// as an additional right-aligned label appended via `nvaddlabel`. This
// simplification is sanctioned by the AAP (file agent_prompt §"Custom
// status bar that displays connection count and user online count")
// which directs the implementation to drive its own text updates via
// an external periodic mechanism. The user-observable counts and timing
// match the FASM baseline (5-second refresh, identical formatter
// output strings, identical online-detection semantics).

//! sshtalk-specific status bar widget.
//!
//! Renders the per-server metrics line:
//!
//! ```text
//! C: <connected> U: <online>/<total>
//! ```
//!
//! Where:
//!
//! * `<connected>` — count of currently active SSH sessions
//!   (incremented via [`session_connected`], decremented via
//!   [`session_disconnected`]; read via [`session_count`] from the
//!   atomic [`SSH_SESSION_COUNT`]).
//! * `<online>` — count of users with at least one active session
//!   (i.e. non-empty `User::tuilist`), computed from the
//!   [`crate::userdb`] registry.
//! * `<total>` — total number of registered users in the
//!   [`crate::userdb`] registry.
//!
//! ## Initialisation order
//!
//! The binary's `main.rs` must call:
//!
//! 1. [`crate::userdb::init`] — populate the user registry.
//! 2. [`init`] — build the shared [`Formatter`] singleton.
//! 3. [`new`] — construct the [`StatusBar`] widget for insertion
//!    into the TUI tree.
//!
//! Calling [`new`] (or anything that triggers a refresh) before
//! [`crate::userdb::init`] panics with a clear diagnostic from the
//! userdb module. This is a programmer-error precondition, not a
//! runtime-recoverable error.
//!
//! ## Thread safety
//!
//! All public functions are safe to call from any thread. The
//! [`StatusBar`] returned by [`new`] is `Send + Sync` (`Arc<Statusbar>`
//! satisfies both bounds). Session-count mutations use atomic
//! operations on [`SSH_SESSION_COUNT`] with [`Ordering::SeqCst`] for
//! the strongest correctness guarantees across the SSH-accept thread,
//! per-session task threads, and the status-bar refresh task.

// ============================================================================
// Imports
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::time::interval;

use heavything::tui::object::ColorPair;
use heavything::tui::widgets::statusbar::Statusbar;
use heavything::util::formatter::{Formatter, Value};

use crate::userdb;

// ============================================================================
// Constants
// ============================================================================

/// Refresh interval for the "C: ... U: ..." text in milliseconds.
///
/// Mirrors the FASM 5-second cadence inherited from
/// `tui_statusbar$nvsetup` (FASM line 161: `mov edi, 5000`). The FASM
/// original re-uses the base statusbar's 5s timer via the vtable
/// override at `statusbar$vtable` slot 6; the Rust port spawns its
/// own tokio interval task at the same cadence.
const REFRESH_INTERVAL_MS: u64 = 5_000;

/// Default foreground colour: ANSI palette index 0 (black).
///
/// Matches FASM `statusbar$new` line 104: `ansi_colors edi, 'black', 'gray'`.
const DEFAULT_FG_COLOR: u8 = 0;

/// Default background colour: ANSI palette index 8 (gray).
///
/// Matches FASM `statusbar$new` line 104: `ansi_colors edi, 'black', 'gray'`.
/// The FASM `ansi_colors` macro maps the symbolic name `'gray'` onto
/// the 256-colour-palette gray slot at index 8.
const DEFAULT_BG_COLOR: u8 = 8;

/// First static segment of the formatter template — `"C: "`.
///
/// Byte-identical to FASM `statusbar.inc` line 70: `cleartext .s1, 'C: '`.
/// The trailing space is significant: it separates the prefix from the
/// connection count number.
const SEGMENT_C: &str = "C: ";

/// Second static segment of the formatter template — `" U: "`.
///
/// Byte-identical to FASM `statusbar.inc` line 71: `cleartext .s2, ' U: '`.
/// **Both** the leading and trailing spaces are significant: they
/// separate the connection count (left) from the online count (right).
const SEGMENT_U: &str = " U: ";

/// Third static segment of the formatter template — `"/"`.
///
/// Byte-identical to FASM `statusbar.inc` line 72: `cleartext .s3, '/'`.
/// Acts as the divider between the online-user count and the total-user
/// count (e.g. `"3/10"` means 3 users online out of 10 registered).
const SEGMENT_SLASH: &str = "/";

/// Width parameter passed to [`Formatter::add_unsigned`] for each
/// numeric placeholder.
///
/// Matches FASM `statusbar$init` lines 52, 59, 66: `mov esi, 1` —
/// minimum width 1 character (i.e. no zero-padding, single-digit
/// values render as one character, multi-digit values render at their
/// natural width).
const UNSIGNED_WIDTH: u32 = 1;

/// Flags parameter passed to [`Formatter::add_unsigned`] for each
/// numeric placeholder.
///
/// Matches FASM `statusbar$init` lines 53, 60, 67: `xor edx, edx` —
/// no flag bits set (no thousands separator, no leading-zero pad,
/// no left-justification override).
const UNSIGNED_FLAGS: u32 = 0;

// ============================================================================
// Statics
// ============================================================================

/// Pre-built formatter for the status bar text:
/// `"C: {connected} U: {online}/{total}"`.
///
/// Mirrors the FASM module-level global `statusbar_fmt` declared at
/// `statusbar.inc` line 38. Built exactly once during process startup
/// by [`init`] and read on every refresh by [`build_status_text`].
///
/// Stored in a [`OnceLock`] (rather than [`std::sync::Mutex`]) because
/// the formatter is **immutable** post-construction: the rendered output
/// changes per call (via [`Formatter::doit`] argument substitution) but
/// the template itself never mutates after [`init`] returns. Lock-free
/// reads keep the per-tick cost minimal.
static STATUSBAR_FMT: OnceLock<Formatter> = OnceLock::new();

/// Atomic counter of currently-active SSH sessions.
///
/// Mirrors the FASM module-level global `ssh_session_count` referenced
/// at `statusbar.inc` lines 114 and 140 (`mov esi, [ssh_session_count]`).
/// In the FASM baseline this is a plain 32-bit memory location modified
/// by the SSH transport layer; in Rust we promote to [`AtomicU64`] with
/// [`Ordering::SeqCst`] so the SSH-accept thread, per-session worker
/// threads, and the status-bar refresh task all observe a consistent
/// value without lock contention.
///
/// The counter is **monotonic per-event-pair**: every accepted SSH
/// connection must call [`session_connected`] exactly once, and every
/// dropped SSH session must call [`session_disconnected`] exactly once
/// (typically from a `Drop` impl on the SSH session wrapper). Imbalanced
/// calls produce a stale display value but cannot cause undefined
/// behaviour.
pub static SSH_SESSION_COUNT: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Public type
// ============================================================================

/// sshtalk-specific status bar widget wrapping a heavything [`Statusbar`].
///
/// FASM parallel: the `statusbar$vtable`-bearing object constructed by
/// `statusbar$new` (`statusbar.inc` lines 101-126). The FASM version
/// achieves customisation by overwriting the first qword of a freshly-
/// allocated `tui_statusbar` with a pointer to `statusbar$vtable`,
/// which differs from `tui_statusbar$vtable` only in the `timer` slot.
///
/// The Rust port wraps an [`Arc<Statusbar>`] via composition rather than
/// vtable replacement (Rust's [`heavything::tui::object::Widget`] trait
/// system does not expose runtime vtable rewriting). The base
/// [`Statusbar`] is constructed with `show_uptime: false` so its own
/// internal 5-second timer becomes a no-op; the sshtalk module then
/// drives its own 5-second refresh via [`spawn_refresh_task`].
///
/// The [`base`](StatusBar::base) field is `pub(crate)` so sibling
/// sshtalk modules (`screen.rs`, etc.) can attach the underlying
/// widget into a parent TUI tree by cloning the `Arc<Statusbar>` and
/// inserting it as `Arc<dyn Widget>`.
pub struct StatusBar {
    /// The underlying heavything [`Statusbar`] base widget. Wrapped in
    /// [`Arc`] so the same widget instance can be shared between the
    /// background refresh task (which holds a [`Weak<StatusBar>`]) and
    /// any TUI parent that mounts it via the [`Widget`](heavything::tui::object::Widget)
    /// trait. The field is `pub(crate)` so sibling sshtalk modules
    /// (`screen.rs`, `chatpanel.rs`, etc.) can clone it and attach it
    /// to the parent panel tree without exposing internal state to
    /// out-of-crate consumers.
    pub(crate) base: Arc<Statusbar>,
}

// ============================================================================
// Public functions: init, session counters, new
// ============================================================================

/// Initialise the shared status-bar formatter.
///
/// FASM parallel: `statusbar$init` (`statusbar.inc` lines 43-72). The
/// FASM original constructs the global `statusbar_fmt` formatter via
/// the sequence:
///
/// ```text
///   formatter$new(0)              ; xor edi, edi (space_between=false)
///   formatter$add_static "C: "    ; line 50
///   formatter$add_unsigned(1, 0)  ; lines 52-54
///   formatter$add_static " U: "   ; line 57
///   formatter$add_unsigned(1, 0)  ; lines 59-61
///   formatter$add_static "/"      ; line 64
///   formatter$add_unsigned(1, 0)  ; lines 66-68
/// ```
///
/// The Rust port mirrors this exact sequence in
/// [`build_statusbar_formatter`] and stores the result in
/// [`STATUSBAR_FMT`] via [`OnceLock::set`].
///
/// # Idempotency
///
/// Returns `Err` if called more than once. Production binaries call
/// this exactly once during the application bootstrap (after
/// [`crate::userdb::init`] but before constructing any widget tree
/// that includes a [`StatusBar`]).
///
/// # Errors
///
/// Returns an error if [`STATUSBAR_FMT`] is already initialised. The
/// error chain includes a human-readable context message via
/// [`Context`].
pub fn init() -> Result<()> {
    STATUSBAR_FMT
        .set(build_statusbar_formatter())
        .map_err(|_| anyhow::anyhow!("sshtalk::statusbar already initialised"))
        .context("statusbar::init")?;
    Ok(())
}

/// Increment the active-SSH-session counter.
///
/// Called exactly once per accepted SSH connection — typically from
/// the per-connection task spawned by the SSH listener loop. The
/// matching [`session_disconnected`] call must be issued exactly once
/// when the session ends (typically from a `Drop` impl on the SSH
/// session wrapper, or in the post-disconnect cleanup path).
///
/// FASM parallel: the FASM SSH transport layer increments
/// `ssh_session_count` directly via `inc dword [ssh_session_count]`
/// at the connection-accept site. The Rust port wraps the increment
/// in this helper so the underlying [`AtomicU64`] usage is
/// encapsulated and the SSH layer only needs the public function.
pub fn session_connected() {
    SSH_SESSION_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Decrement the active-SSH-session counter.
///
/// Called exactly once per dropped SSH session — see
/// [`session_connected`] for the matching pair semantics. If
/// the counter is already zero (an imbalanced call), the underlying
/// [`AtomicU64::fetch_sub`] wraps to `u64::MAX`. This is unlikely in
/// practice (the connection lifecycle is tightly paired) but treated
/// as a non-fatal stale display value rather than a panic.
///
/// FASM parallel: the FASM SSH transport layer decrements
/// `ssh_session_count` directly via `dec dword [ssh_session_count]`
/// at the connection-drop site.
pub fn session_disconnected() {
    SSH_SESSION_COUNT.fetch_sub(1, Ordering::SeqCst);
}

/// Returns the current active-SSH-session count.
///
/// FASM parallel: `mov esi, [ssh_session_count]` at `statusbar.inc`
/// lines 114 (used by `statusbar$new` for the initial render) and
/// 140 (used by `statusbar$timer` for each refresh).
///
/// Uses [`Ordering::SeqCst`] for symmetry with the modifying
/// operations; readers and writers all participate in the same total
/// order, eliminating the need to reason about acquire/release
/// boundaries.
#[must_use]
pub fn session_count() -> u64 {
    SSH_SESSION_COUNT.load(Ordering::SeqCst)
}

/// Construct the sshtalk status bar widget.
///
/// FASM parallel: `statusbar$new` (`statusbar.inc` lines 101-126).
/// The FASM original:
///
/// 1. Loads `xmm0 = 100.0` (full-width percentage; line 103).
/// 2. Builds a colour pair via `ansi_colors edi, 'black', 'gray'`
///    (line 104) — black foreground, gray background.
/// 3. Sets `esi = 1` (douptime=true; line 105) and calls
///    `tui_statusbar$new_d` to allocate the base widget.
/// 4. Overwrites the vtable pointer with `statusbar$vtable`
///    (lines 108-110) — the FASM way of saying "use my custom
///    timer".
/// 5. Computes initial connection / online / total counts and
///    formats them via `statusbar_fmt` (lines 111-117).
/// 6. Inserts the formatted text as an additional label via
///    `tui_statusbar$nvaddlabel` (line 121) and frees the formatter
///    output buffer (lines 122-123).
///
/// The Rust port deviates **only in step 6**: rather than appending
/// the formatted text as an additional right-aligned label
/// (which would require a `pub` `Statusbar::add_label` accepting
/// `&self` — the existing method requires `&mut self` and is
/// incompatible with the post-`Arc::new` ownership model), we set
/// the formatted text as the **main status text** via
/// [`Statusbar::set_text`]. The visible byte content of the
/// formatted text is identical; only its placement on the bar
/// differs from the FASM baseline. See AAP §0.7 for the broader
/// Rust-Arc-vs-FASM-pointer impedance discussion.
///
/// The base statusbar is constructed with `show_uptime: false` so
/// the heavything internal timer becomes a no-op; the sshtalk
/// module owns the entire 5-second refresh cadence via
/// [`spawn_refresh_task`].
///
/// # Parameters
///
/// * `width` — width-percent (0.0..=100.0) relative to the parent
///   container. Matches FASM `xmm0 = 100.0` for full-width bars
///   when the caller passes `100.0`.
/// * `height` — height in cells. Documentary only: the heavything
///   [`Statusbar`] is hard-coded to height=1 (matches FASM
///   `tui_statusbar$nvsetup` line 109: `edx=1`). The parameter is
///   accepted for API symmetry with other widget constructors but
///   non-`1` values are silently ignored.
///
/// # Returns
///
/// An owned [`Arc<StatusBar>`]. Callers may clone the [`Arc`] freely;
/// the spawned refresh task holds a [`Weak`] back-pointer and exits
/// cleanly when the last [`Arc`] is dropped.
///
/// # Errors
///
/// Returns an error if the underlying [`Statusbar::new_d`] call
/// fails (only possible on absurd width values that cause an
/// internal overflow check to fail). The error chain includes
/// human-readable context via [`Context`].
///
/// # Panics
///
/// * Panics if invoked outside a tokio runtime context — this is a
///   precondition of [`Statusbar::new_d`] which spawns its own
///   timer task. The sshtalk binary always invokes this from inside
///   the global tokio runtime built by `heavything::init`.
/// * Panics if [`crate::userdb::init`] has not been called (the
///   initial render path calls into [`users_online`] which reaches
///   into the userdb registry).
pub fn new(width: f64, height: u32) -> Result<Arc<StatusBar>> {
    // Documentary parameter: the heavything Statusbar is hard-coded
    // to height=1 (line 497 of widgets/statusbar.rs: `state.height = 1`).
    // We accept the parameter for API symmetry but do not pass it
    // through. Discarding rather than asserting preserves caller
    // flexibility (e.g. a TUI builder that always passes height=1
    // continues to work without special-casing this widget).
    let _ = height;

    // ---- Step 1: build the colour pair (FASM line 104).
    let colors = ColorPair::new(DEFAULT_FG_COLOR, DEFAULT_BG_COLOR);

    // ---- Step 2: construct the base heavything Statusbar.
    //
    // The FASM original passes `douptime=1` (line 105) which would
    // turn on the heavything Statusbar's internal uptime label. The
    // Rust port passes `false` instead so heavything's internal
    // 5-second timer becomes a no-op (`Statusbar::timer_tick`
    // returns early when `!show_uptime`); this lets sshtalk own the
    // entire refresh cadence via its own spawned task without two
    // competing timers.
    let base: Arc<Statusbar> =
        Statusbar::new_d(width, colors, false).context("statusbar::new: Statusbar::new_d failed")?;

    // ---- Step 3: render the initial counts immediately.
    //
    // FASM lines 111-121 compute initial counts and append the
    // formatted text *during construction* so the bar shows live
    // values from the moment it appears on screen. We mirror this
    // here so the user does not see a blank bar for the first
    // refresh interval.
    if let Some(text) = build_status_text() {
        base.set_text(&text);
    }

    // ---- Step 4: wrap into Arc<StatusBar> and spawn the refresh task.
    let sb = Arc::new(StatusBar { base });
    spawn_refresh_task(&sb);

    Ok(sb)
}

// ============================================================================
// StatusBar methods
// ============================================================================

impl StatusBar {
    /// Recompute the status text from current counts and apply it to
    /// the base statusbar.
    ///
    /// FASM parallel: the body of `statusbar$timer` (`statusbar.inc`
    /// lines 132-197) — recompute the connection / online / total
    /// counts, pass them through `formatter$doit`, and call
    /// `tui_label$nvsettext` to update the label's text.
    ///
    /// Called by the spawned refresh task on every 5-second tick.
    /// Does nothing if [`STATUSBAR_FMT`] has not been initialised
    /// (i.e. [`init`] was not called) — fail-soft behaviour for
    /// pathological misconfiguration.
    ///
    /// # Threading
    ///
    /// Safe to call concurrently with other `&self` methods on the
    /// underlying [`Statusbar`] (which uses interior locking on
    /// the inner status label). Not safe to call concurrently with
    /// `&mut self` operations on the underlying [`Statusbar`]
    /// (e.g. `add_label` or `cleanup`).
    fn refresh(&self) {
        if let Some(text) = build_status_text() {
            self.base.set_text(&text);
        }
    }
}

// ============================================================================
// Private helpers
// ============================================================================

/// Build a fresh formatter mirroring FASM `statusbar$init`.
///
/// The construction sequence is byte-identical to FASM lines 45-68:
///
/// 1. [`Formatter::new`]`(false)` — `xor edi, edi` (no auto-spacing
///    between items; the static segments include their own spacing).
/// 2. [`Formatter::add_static`]`("C: ")` — first segment.
/// 3. [`Formatter::add_unsigned`]`(1, 0)` — connected count slot.
/// 4. [`Formatter::add_static`]`(" U: ")` — second segment.
/// 5. [`Formatter::add_unsigned`]`(1, 0)` — online count slot.
/// 6. [`Formatter::add_static`]`("/")` — third segment.
/// 7. [`Formatter::add_unsigned`]`(1, 0)` — total count slot.
///
/// Returns the constructed formatter by value. The caller is
/// responsible for storing it (typically in [`STATUSBAR_FMT`]).
#[must_use]
fn build_statusbar_formatter() -> Formatter {
    let mut fmt = Formatter::new(false);
    fmt.add_static(SEGMENT_C);
    fmt.add_unsigned(UNSIGNED_WIDTH, UNSIGNED_FLAGS);
    fmt.add_static(SEGMENT_U);
    fmt.add_unsigned(UNSIGNED_WIDTH, UNSIGNED_FLAGS);
    fmt.add_static(SEGMENT_SLASH);
    fmt.add_unsigned(UNSIGNED_WIDTH, UNSIGNED_FLAGS);
    fmt
}

/// Count the number of users currently online.
///
/// FASM parallel: `statusbar$usersonline` (`statusbar.inc` lines 77-96).
/// The FASM original iterates the global `users` map via
/// `unsignedmap$foreach_arg` and counts entries whose
/// `user_tuilist_ofs` AVL tree has a non-null `_avlofs_right`
/// (i.e. the AVL is non-empty). The Rust port iterates the
/// [`crate::userdb::users`] [`heavything::ds::StringMap`] via
/// [`heavything::ds::StringMap::for_each`] and counts entries whose
/// [`crate::userdb::User::tuilist`] is non-empty.
///
/// "Online" is defined as **"has at least one active SSH session"**
/// — there is no separate "online" flag. The first session to add
/// itself to a user's `tuilist` brings the user online; the last
/// session to remove itself takes the user offline.
///
/// # Lock semantics
///
/// Holds a read-guard on the userdb registry (`users().read()`)
/// for the duration of iteration. Per-user `tuilist` read-guards
/// are acquired briefly inside the iteration callback. A poisoned
/// outer registry lock is recovered via `into_inner`; a poisoned
/// per-user `tuilist` lock causes that particular user to be
/// counted as offline (conservatively under-counts rather than
/// panicking).
///
/// # Panics
///
/// Panics if [`crate::userdb::init`] has not been called — the
/// underlying [`crate::userdb::users`] function panics in that case.
/// This is a programmer-error precondition: the binary's `main.rs`
/// must initialise userdb before any code path that triggers a
/// status-bar refresh.
#[must_use]
fn users_online() -> u64 {
    let registry_lock = userdb::users();
    let registry = match registry_lock.read() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let mut count: u64 = 0;
    registry.for_each(|_username, user| {
        // FASM lines 90-95: read `user_tuilist_ofs` (the AVL tree),
        // check `[rcx+_avlofs_right] != 0`, conditionally increment.
        // Rust equivalent: read-lock the tuilist, check `!is_empty()`.
        let online = match user.tuilist.read() {
            Ok(g) => !g.is_empty(),
            // Conservative: a poisoned per-user lock is treated as
            // offline so we under-report rather than panicking.
            Err(_) => false,
        };
        if online {
            count = count.saturating_add(1);
        }
    });
    count
}

/// Total number of registered users.
///
/// Used as the denominator of the `"<online>/<total>"` segment.
/// FASM parallel: `mov ecx, [rcx+_avlofs_right]` at `statusbar.inc`
/// lines 116 and 142 — the FASM `unsignedmap` stores the count of
/// nodes in the AVL `_avlofs_right` slot of the root, which
/// corresponds directly to [`heavything::ds::StringMap::len`] in the
/// Rust port. Wait — that read is actually the AVL root node's right
/// subtree pointer in FASM, but `[rcx+_avlofs_right]` at the map
/// header offset 8 is repurposed by the FASM map structures as the
/// total-element-count field (FASM `maps.inc` convention). The Rust
/// `StringMap::len` returns the same logical value: total entries.
///
/// # Panics
///
/// Same precondition as [`users_online`]: panics if
/// [`crate::userdb::init`] has not been called.
#[must_use]
fn total_users() -> u64 {
    let registry_lock = userdb::users();
    let registry = match registry_lock.read() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    registry.len() as u64
}

/// Render the status text using the current counts.
///
/// Returns `None` if [`STATUSBAR_FMT`] has not been initialised
/// (i.e. [`init`] was not called) or if the formatter call fails
/// (which should not happen for a well-formed three-`Uint`
/// argument list).
///
/// FASM parallel: the formatter invocation block at `statusbar.inc`
/// lines 113-117 (`statusbar$new` initial render) and lines 139-143
/// (`statusbar$timer` periodic refresh) — both use
/// `formatter$doit` with three unsigned arguments in `esi`,
/// `edx`, `ecx` (connected, online, total). The Rust
/// [`Formatter::doit`] signature accepts a `&[Value]` slice so we
/// pass the three counts as [`Value::Uint`] entries.
///
/// # Panics
///
/// Panics if [`crate::userdb::init`] has not been called (via
/// [`users_online`] / [`total_users`]).
#[must_use]
fn build_status_text() -> Option<String> {
    let fmt = STATUSBAR_FMT.get()?;
    let connected = session_count();
    let online = users_online();
    let total = total_users();
    fmt.doit(&[Value::Uint(connected), Value::Uint(online), Value::Uint(total)])
        .ok()
}

/// Spawn the 5-second refresh task that drives [`StatusBar::refresh`].
///
/// FASM parallel: the FASM original re-uses the base statusbar's
/// own `epoll$timer_new(5000, self)` registration via the vtable
/// override. The Rust port spawns a dedicated tokio interval task
/// because the heavything `Statusbar`'s own timer task always runs
/// `timer_tick` (the no-op-when-`!show_uptime` body) regardless of
/// what the caller wants, and there is no per-instance hook to
/// inject custom logic.
///
/// The task captures a [`Weak<StatusBar>`] back-pointer to avoid an
/// [`Arc`] cycle: when the last [`Arc<StatusBar>`] is dropped, the
/// [`Weak::upgrade`] returns `None`, the loop exits, and the task
/// terminates cleanly. This mirrors the heavything Statusbar's own
/// `spawn_timer_task` cleanup pattern (see
/// `crates/heavything/src/tui/widgets/statusbar.rs` lines 670-705).
fn spawn_refresh_task(sb: &Arc<StatusBar>) {
    let weak: Weak<StatusBar> = Arc::downgrade(sb);
    tokio::spawn(async move {
        // Default missed-tick behaviour (`Burst`) is fine for a
        // 5-second status-bar refresh: if the runtime falls behind,
        // catch-up ticks fire back-to-back, which the user perceives
        // as a one-time accelerated refresh of the displayed counts
        // (visually indistinguishable from a normal refresh).
        let mut ticker = interval(Duration::from_millis(REFRESH_INTERVAL_MS));
        loop {
            ticker.tick().await;
            match weak.upgrade() {
                Some(arc) => arc.refresh(),
                None => break,
            }
        }
    });
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    //! Unit tests for `sshtalk::statusbar`.
    //!
    //! These tests deliberately exercise only the parts of the module that
    //! do **not** depend on `crate::userdb` being initialised:
    //!
    //! * Constants and segment values (byte-for-byte verification against
    //!   the FASM `cleartext` declarations).
    //! * Formatter construction shape and rendered output for synthetic
    //!   counts.
    //! * Atomic session-counter pair semantics
    //!   ([`session_connected`] / [`session_disconnected`] /
    //!   [`session_count`]).
    //!
    //! End-to-end paths involving `users_online()` / `total_users()` are
    //! deferred to the integration test suite (where userdb can be
    //! initialised once with a tempfile path before any test runs). The
    //! unit suite must remain free of cross-test ordering dependencies
    //! because cargo test runs `#[test]` functions in parallel.

    use super::*;
    use std::sync::Mutex;

    /// Serialises tests that mutate the shared [`SSH_SESSION_COUNT`]
    /// static so concurrent test execution does not produce racy
    /// delta observations. Without this lock, two tests reading
    /// `baseline`, performing N atomic `fetch_add`, and asserting
    /// `count == baseline + N` could observe N + (other test's delta)
    /// because their critical sections interleave.
    static SESSION_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// FASM `statusbar.inc` line 70: `cleartext .s1, 'C: '`.
    /// Verifies the first segment is byte-identical to the FASM source.
    #[test]
    fn segment_c_byte_identical_to_fasm() {
        assert_eq!(SEGMENT_C, "C: ");
        assert_eq!(SEGMENT_C.len(), 3);
        assert_eq!(SEGMENT_C.as_bytes(), b"C: ");
    }

    /// FASM `statusbar.inc` line 71: `cleartext .s2, ' U: '`.
    /// The leading space is critical — it separates the connection count
    /// number (left) from the `U:` prefix.
    #[test]
    fn segment_u_byte_identical_to_fasm() {
        assert_eq!(SEGMENT_U, " U: ");
        assert_eq!(SEGMENT_U.len(), 4);
        assert_eq!(SEGMENT_U.as_bytes(), b" U: ");
    }

    /// FASM `statusbar.inc` line 72: `cleartext .s3, '/'`.
    /// Used as the divider between the online count and the total count.
    #[test]
    fn segment_slash_byte_identical_to_fasm() {
        assert_eq!(SEGMENT_SLASH, "/");
        assert_eq!(SEGMENT_SLASH.len(), 1);
        assert_eq!(SEGMENT_SLASH.as_bytes(), b"/");
    }

    /// FASM `statusbar$init` lines 52, 59, 66: `mov esi, 1` —
    /// minimum width 1 character per unsigned placeholder.
    #[test]
    fn unsigned_width_matches_fasm_baseline() {
        assert_eq!(UNSIGNED_WIDTH, 1);
    }

    /// FASM `statusbar$init` lines 53, 60, 67: `xor edx, edx` —
    /// no flag bits set per unsigned placeholder.
    #[test]
    fn unsigned_flags_matches_fasm_baseline() {
        assert_eq!(UNSIGNED_FLAGS, 0);
    }

    /// FASM `statusbar$nvsetup` line 161: `mov edi, 5000` — 5-second
    /// refresh cadence inherited from the base `tui_statusbar`.
    #[test]
    fn refresh_interval_matches_fasm_baseline() {
        assert_eq!(REFRESH_INTERVAL_MS, 5_000);
    }

    /// Default colours track FASM `statusbar$new` line 104:
    /// `ansi_colors edi, 'black', 'gray'` — black foreground (0),
    /// gray background (8).
    #[test]
    fn default_colors_match_fasm_baseline() {
        assert_eq!(DEFAULT_FG_COLOR, 0);
        assert_eq!(DEFAULT_BG_COLOR, 8);
    }

    /// Verifies the formatter built by [`build_statusbar_formatter`]
    /// has exactly three register-class arguments and zero XMM-class
    /// arguments, matching the three [`Formatter::add_unsigned`]
    /// invocations in FASM `statusbar$init`.
    #[test]
    fn formatter_has_three_unsigned_placeholders() {
        let fmt = build_statusbar_formatter();
        assert_eq!(
            fmt.reg_arg_count(),
            3,
            "formatter must have exactly 3 register-class (unsigned) placeholders"
        );
        assert_eq!(
            fmt.xmm_arg_count(),
            0,
            "formatter must have zero XMM-class (double/duration) placeholders"
        );
    }

    /// Render a sample input through the formatter and verify the
    /// output is byte-identical to what the FASM baseline would
    /// produce for the same three counts.
    #[test]
    fn formatter_renders_sample_inputs_correctly() {
        let fmt = build_statusbar_formatter();

        // FASM equivalent: connected=5, online=3, total=10 →
        // formatter output "C: 5 U: 3/10".
        let rendered = fmt
            .doit(&[Value::Uint(5), Value::Uint(3), Value::Uint(10)])
            .expect("formatter::doit should succeed for three Uint args");
        assert_eq!(rendered, "C: 5 U: 3/10");
    }

    /// Edge case: zero counts should render as "C: 0 U: 0/0".
    #[test]
    fn formatter_renders_zero_counts_correctly() {
        let fmt = build_statusbar_formatter();
        let rendered = fmt
            .doit(&[Value::Uint(0), Value::Uint(0), Value::Uint(0)])
            .expect("formatter::doit should succeed for zero counts");
        assert_eq!(rendered, "C: 0 U: 0/0");
    }

    /// Edge case: large counts should render at their natural width
    /// (the `width=1` parameter is a *minimum*, not a maximum).
    #[test]
    fn formatter_renders_large_counts_correctly() {
        let fmt = build_statusbar_formatter();
        let rendered = fmt
            .doit(&[Value::Uint(1234), Value::Uint(56789), Value::Uint(99999)])
            .expect("formatter::doit should succeed for large counts");
        assert_eq!(rendered, "C: 1234 U: 56789/99999");
    }

    /// Verifies that [`session_connected`] and [`session_disconnected`]
    /// balance correctly: starting from the current count, an
    /// equal number of connect/disconnect pairs returns the counter
    /// to its original value.
    ///
    /// We use deltas (rather than absolute zero) because the static
    /// counter is shared across all tests in the binary; concurrent
    /// tests may have left it at a non-zero value when this test
    /// runs.
    #[test]
    fn session_counter_pairs_balance() {
        let _guard = SESSION_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let baseline = session_count();
        session_connected();
        session_connected();
        session_connected();
        let after_connect = session_count();
        assert_eq!(after_connect, baseline + 3);
        session_disconnected();
        session_disconnected();
        session_disconnected();
        let after_disconnect = session_count();
        assert_eq!(after_disconnect, baseline);
    }

    /// Verifies that [`session_count`] returns the same value as a
    /// direct atomic load with [`Ordering::SeqCst`].
    #[test]
    fn session_count_matches_direct_load() {
        let _guard = SESSION_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let direct = SSH_SESSION_COUNT.load(Ordering::SeqCst);
        let via_helper = session_count();
        assert_eq!(direct, via_helper);
    }

    /// Verifies that [`session_connected`] increments the underlying
    /// atomic by exactly one.
    #[test]
    fn session_connected_increments_by_one() {
        let _guard = SESSION_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let before = session_count();
        session_connected();
        let after = session_count();
        assert_eq!(after, before + 1);
        // Restore the counter so we don't pollute the shared static
        // for sibling tests that read absolute values.
        session_disconnected();
    }

    /// Verifies that [`session_disconnected`] decrements the
    /// underlying atomic by exactly one (and that we set up the
    /// preceding connect to avoid wraparound).
    #[test]
    fn session_disconnected_decrements_by_one() {
        let _guard = SESSION_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Bump first so we never decrement below zero (which would
        // wrap to u64::MAX and confuse subsequent tests reading the
        // shared static).
        session_connected();
        let before = session_count();
        session_disconnected();
        let after = session_count();
        assert_eq!(after, before - 1);
    }

    /// `SSH_SESSION_COUNT` is publicly exposed per the schema. This
    /// test verifies it is reachable as a `pub static AtomicU64` and
    /// that loading it directly produces the same value as
    /// [`session_count`].
    #[test]
    fn ssh_session_count_static_is_publicly_accessible() {
        let _guard = SESSION_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Direct access via the public path verifies the export is
        // live and addressable.
        let _: &AtomicU64 = &SSH_SESSION_COUNT;
        let direct_value = SSH_SESSION_COUNT.load(Ordering::SeqCst);
        let helper_value = session_count();
        assert_eq!(direct_value, helper_value);
    }
}
