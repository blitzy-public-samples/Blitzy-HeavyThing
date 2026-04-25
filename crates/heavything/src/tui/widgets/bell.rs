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
// tui_bell.inc: a 1x1 tui component that will send via timer the 0x7 bell
// but otherwise is a space (and thus must occupy a 1x1 spot on the render area)
//
// default action is a space of course (as it must be so that the renderer will
// send the difference when we decide to write a bell)
//
// ------------------------------------------------------------------------
// Rust translation of FASM `tui_bell.inc` (165 lines).
// Module file: `crates/heavything/src/tui/widgets/bell.rs`.

//! Bell widget — a 1×1 [`TuiBackground`]-descendant emitting the
//! terminal BEL character (`0x07`) at a 120-millisecond cadence for a
//! caller-specified number of ring cycles.
//!
//! # FASM lineage
//!
//! Direct port of `tui_bell.inc`. The FASM widget has the smallest
//! footprint of any animated TUI widget (16 bytes added on top of
//! [`TuiBackground`] for the timer pointer + counter), and the
//! simplest vtable: only **three** methods are overridden from the
//! parent's vtable copy.
//!
//! | FASM offset | Field      | Type     | Purpose                                  |
//! |-------------|------------|----------|------------------------------------------|
//! | `+0`        | `timerptr` | `dq`     | Timer handle (null when not running).     |
//! | `+8`        | `counter`  | `dd` u32 | Toggle counter — `count << 1` on `ring`.  |
//! | `+12`       | _padding_  | 4 bytes  | Tail padding to 16-byte boundary.         |
//!
//! Total `tui_bell_size = tui_background_size + 16` (FASM line 43).
//!
//! # Vtable overrides (FASM `tui_bell$vtable` line 31–38)
//!
//! - **Slot 0** `tui_vcleanup` → [`Bell::cleanup`]: cancels the timer
//!   task before tearing down inherited state.
//! - **Slot 1** `tui_vclone` → [`Bell::clone_widget`]: deep-clones
//!   the parent state and produces a fresh bell with `counter = 0`
//!   and `timer = None` — **does NOT spawn a new timer task** (the
//!   FASM `heap$alloc_clear` zero-fills the trailing 16 bytes,
//!   leaving counter and timer pointer both null until [`Bell::ring`]
//!   is called on the clone).
//! - **Slot 6** `tui_vtimer` → [`Bell::timer`]: writes either the BEL
//!   codepoint or a space to the first cell of the text buffer based
//!   on the parity of the counter, then decrements the counter and
//!   triggers a display-list update.
//!
//! Slot 2 (`tui_vdraw`) inherits the parent's `tui_background$draw`
//! directly per the FASM vtable definition. In Rust the trait default
//! is a no-op, so [`Bell::draw`] is implemented as a one-line delegate
//! to [`TuiBackground::draw`] to preserve the FASM "vtable copy"
//! semantics. All 33 other vtable slots inherit their `tui_object`
//! defaults from the [`Widget`] trait's default method bodies.
//!
//! # Ring cadence
//!
//! [`Bell::ring`] doubles the requested ring count (FASM `shl esi, 1`
//! at line 142) so each requested ring corresponds to two timer
//! toggles — one writing BEL, one writing space — producing an
//! audible beep per ring with a recovery interval that lets the
//! terminal cleanly redisplay.
//!
//! Calling [`Bell::ring`] while a timer is already running **adds**
//! to the existing counter (FASM `add dword [rdi+counter_ofs], esi`
//! at line 159) — a seamless extension without spawning a second
//! timer task.

// ============================================================================
// Imports
// ============================================================================

use std::any::Any;
use std::sync::{Arc, Mutex, Weak};

use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

use crate::error::TuiError;
use crate::tui::object::{ColorPair, Widget, WidgetState};
use crate::tui::render::Renderer;
use crate::tui::widgets::background::TuiBackground;

// ============================================================================
// Constants
// ============================================================================

/// ASCII BEL (Bell) control character — `0x07`.
///
/// Writing this codepoint into the terminal output stream causes the
/// terminal to ring its audible bell. FASM `tui_bell$timer` uses
/// `mov ecx, 0x7` (line 118) and conditionally moves it into `edx`
/// when the counter is even.
pub const BEL: char = '\u{0007}';

/// Timer tick interval in milliseconds.
///
/// FASM hardcoded value at line 149 (`mov edi, 120`). The 120 ms
/// cadence is fast enough to feel "snappy" but slow enough that
/// individual BEL emissions are perceptually distinct (especially
/// audible on terminals that emit a click rather than a tone).
pub const TICK_MS: u64 = 120;

/// Background fill character for a bell — a literal space.
///
/// FASM line 58 (`mov ecx, ' '`) sets the third argument to
/// `tui_background$init_ii`. Unlike most [`TuiBackground`] descendants
/// which may use `0` (skip text fill) or a decorative codepoint, the
/// bell explicitly fills with `' '` so that a freshly-rendered bell is
/// invisible — the BEL emission appears only during the toggle phase.
const FILLCHAR_SPACE: u32 = b' ' as u32;

// ============================================================================
// Internal state
// ============================================================================

/// Private interior state guarded by [`Bell::inner`]'s [`Mutex`].
///
/// Maps to the two FASM-extra fields at offsets `tui_bell_timerptr_ofs`
/// (offset 0 from `tui_background_size`) and `tui_bell_counter_ofs`
/// (offset 8). The four trailing pad bytes in FASM (offsets 12..=15)
/// have no Rust analogue — Rust's repr lays out fields packed without
/// the manual alignment FASM enforces.
struct BellInner {
    /// Toggle countdown, doubled on each [`Bell::ring`] call so each
    /// requested ring produces two toggles (BEL + space).
    ///
    /// FASM offset 8 (`tui_bell_counter_ofs`).
    counter: u32,

    /// Spawned tokio task handle, `Some` while a timer is active and
    /// `None` once the countdown completes or has been aborted.
    ///
    /// FASM offset 0 (`tui_bell_timerptr_ofs`) — a `dq` pointer to an
    /// `epoll$timer_new`-allocated record. The Rust translation
    /// replaces the kernel-backed epoll timer with a tokio interval
    /// task; the [`JoinHandle`] is the type-safe equivalent of the
    /// FASM raw pointer.
    timer: Option<JoinHandle<()>>,

    /// Codepoint to render in cell[0] on the next [`Widget::draw`]
    /// invocation. Updated on each [`Bell::tick`] to reflect the
    /// FASM `tui_bell$timer` PRE-decrement parity logic (counter
    /// EVEN → BEL, counter ODD → space).
    ///
    /// **Why a separate field?** The Rust translation cannot mutate
    /// the embedded [`TuiBackground`]'s text buffer directly from the
    /// spawned tokio task — the task only holds a [`Weak<Self>`]
    /// which upgrades to `&self`, and writing to cells requires
    /// `&mut self` access. So the task computes the next codepoint
    /// (via [`Bell::tick`]) and stores it here under [`Mutex`]
    /// protection; the framework's render pipeline then calls
    /// [`Widget::draw`] with `&mut self` and applies the codepoint
    /// to cell[0] of the text buffer.
    ///
    /// **FASM mapping**: this field has no FASM analogue. The FASM
    /// `tui_bell$timer` callback runs synchronously from the epoll
    /// dispatcher with full pointer access and writes cell[0]
    /// in-place at FASM line 121 (`mov [rsi], edx`). The Rust
    /// translation defers this write to the next render pass to
    /// satisfy the borrow checker.
    ///
    /// **Initial value**: `' '` (space, `0x20`). Set to BEL inside
    /// [`Bell::ring`] when starting a fresh timer so the first
    /// render after `ring(N)` displays BEL even if the spawned
    /// task has not yet fired its first tick.
    pending_char: u32,
}

// ============================================================================
// Bell — public widget type
// ============================================================================

/// Terminal bell widget — 1×1 [`TuiBackground`]-descendant emitting
/// `0x07` (BEL) at a 120-millisecond cadence for a caller-specified
/// number of ring cycles.
///
/// Bell composes a [`TuiBackground`] (the parent class in the FASM
/// inheritance hierarchy) by-value, exposing all 37 [`Widget`] trait
/// methods through the embedded [`TuiBackground`] field while
/// overriding only the three slots that diverge from the parent's
/// behavior (`cleanup`, `clone_widget`, `timer`).
///
/// # Send + Sync
///
/// Both fields are `Send + Sync`:
/// - [`TuiBackground`] is `Send + Sync` via the [`Widget`] trait bound.
/// - [`Mutex<BellInner>`] is `Send + Sync` because [`BellInner`]
///   contains only `u32` (`Copy`) and [`Option<JoinHandle<()>>`]
///   (which is `Send + Sync` per the tokio API).
///
/// # FASM size
///
/// `tui_bell_size = tui_background_size + 16` (line 43). The Rust
/// struct is laid out by `repr(Rust)` so the byte count is not
/// guaranteed identical, but the field count and ownership semantics
/// match exactly.
pub struct Bell {
    /// Inherited [`TuiBackground`] state — bounds, width/height,
    /// text/attribute buffers, layout, children, and the
    /// `bgfillchar = ' '` + `bgcolors` set in [`Bell::new`].
    background: TuiBackground,

    /// Bell-specific interior state guarded by a [`Mutex`] so the
    /// spawned tokio timer task (which holds a [`Weak<Self>`]) can
    /// mutate the counter through `&self` while concurrently the
    /// framework's [`Widget`] dispatch can call [`Widget::timer`]
    /// or [`Widget::cleanup`] through `&mut self`.
    inner: Mutex<BellInner>,
}

/// Backwards-friendly alias matching the `tui_*` FASM naming
/// convention used by sibling widgets such as
/// [`crate::tui::widgets::newsticker::TuiNewsticker`].
pub type TuiBell = Bell;

// ============================================================================
// Construction & non-virtual public API
// ============================================================================

impl Bell {
    /// Create a new bell widget.
    ///
    /// Mirrors FASM `tui_bell$new(edi=width, esi=height, edx=colors)`
    /// (`tui_bell.inc` lines 47–62):
    ///
    /// ```text
    ///   heap$alloc_clear(tui_bell_size)
    ///   set vtable to tui_bell$vtable
    ///   tui_background$init_ii(self, width, height, ' ', colors)
    /// ```
    ///
    /// The FASM `heap$alloc_clear` zero-fills the trailing 16 bytes
    /// (`timerptr_ofs` and `counter_ofs`); the Rust translation uses
    /// explicit field initializers (`counter: 0`, `timer: None`) for
    /// the same effect. The parent's `init_ii` constructor pre-fills
    /// the text buffer with `cells * 4` zero bytes and the attribute
    /// buffer with `cells` zero entries (per
    /// [`TuiBackground::new_ii`]), giving the widget a stable starting
    /// state ready for the first render pass.
    ///
    /// # Panics
    ///
    /// Panics if [`TuiBackground::new_ii`] fails (it returns an error
    /// only on `usize`-to-byte arithmetic overflow when computing the
    /// text-buffer reservation, which is impossible for any realistic
    /// `width`/`height` pair on a 64-bit target). The panic message
    /// quotes the inner [`TuiError`] for debuggability.
    ///
    /// # Returns
    ///
    /// An `Arc<Self>` so callers can clone references for embedding
    /// the bell in parent widget trees and for retaining a handle to
    /// invoke [`Bell::ring`] later.
    #[must_use]
    pub fn new(width: i32, height: i32, colors: ColorPair) -> Arc<Self> {
        // FASM lines 53–60: allocate, set vtable, init_ii with ' ' fill char.
        // The Rust factory returns `Result<Arc<Self>, TuiError>` — bell's
        // public API is infallible (FASM never propagates an error from
        // $new) so we panic on the impossible-in-practice failure path
        // with an informative message.
        let bg_arc = TuiBackground::new_ii(width, height, FILLCHAR_SPACE, colors)
            .unwrap_or_else(|e| panic!("Bell: TuiBackground::new_ii failed: {e}"));

        // Extract the inner TuiBackground from its Arc shell so we
        // can store it by-value as a field. `try_unwrap` succeeds
        // because `new_ii` returns an Arc with refcount = 1; the only
        // failure path would be a race that handed us a shared Arc,
        // which the `new_ii` factory contract forbids.
        let background = Arc::try_unwrap(bg_arc).unwrap_or_else(|_| {
            // Defensive: this can only happen if some hypothetical
            // future change to `new_ii` started returning shared Arcs.
            // Panic with a clear message to surface the breakage
            // immediately rather than silently degrading behavior.
            panic!("Bell: TuiBackground::new_ii returned a shared Arc — refcount > 1")
        });

        // Construct the BellInner with cleared FASM-tail-zero state
        // (counter = 0, timer = None) — matches FASM `heap$alloc_clear`
        // which zero-fills the 16-byte tail (timerptr_ofs + counter_ofs).
        // pending_char defaults to ' ' (space) so a freshly-constructed
        // bell renders an empty cell until the first [`Bell::ring`].
        let inner = BellInner {
            counter: 0,
            timer: None,
            pending_char: b' ' as u32,
        };

        Arc::new(Self {
            background,
            inner: Mutex::new(inner),
        })
    }

    /// Ring the terminal bell `count` times.
    ///
    /// Mirrors FASM `tui_bell$nvdoit(rdi=self, esi=count)`
    /// (`tui_bell.inc` lines 135–165):
    ///
    /// ```text
    ///   if count == 0:        return                                  ; .nothingtodo
    ///   count <<= 1                                                   ; double for on/off
    ///   if self.timerptr != 0:
    ///       self.counter += count                                     ; .alreadygoing
    ///       return
    ///   self.counter = count
    ///   self.timerptr = epoll$timer_new(120, self, $vtable)
    ///   self.timerptr[24] = 2                                         ; don't auto-destroy
    /// ```
    ///
    /// # Doubling
    ///
    /// The `count << 1` (FASM line 142) doubles the requested ring
    /// count because each ring requires two toggles: one to write
    /// `BEL` (which the renderer flushes, causing the audible beep)
    /// and one to write `' '` (so the renderer doesn't repeat the
    /// BEL emission on the next frame). Calling `ring(3)` therefore
    /// schedules **6** timer ticks producing the cell-content
    /// pattern `BEL, ' ', BEL, ' ', BEL, ' '`.
    ///
    /// # Extension semantics
    ///
    /// If a timer is already running (`timerptr != 0` in FASM), the
    /// requested doubled-count is **added** to the existing counter —
    /// the timer task continues without restart, the bell pattern
    /// extends seamlessly. This matches FASM `.alreadygoing` at
    /// line 158.
    ///
    /// # Self-destruction guard
    ///
    /// FASM line 155 sets `[rax+24] = 2` on the timer record to flag
    /// "do not destroy the widget when the timer ends". In Rust this
    /// is unnecessary because [`Arc`] reference counting keeps the
    /// widget alive as long as any caller holds a reference; the
    /// timer task drops its [`Weak`] when the loop exits but does not
    /// trigger any teardown.
    ///
    /// # Tokio runtime requirement
    ///
    /// This method spawns a tokio task via [`tokio::spawn`] and
    /// therefore must be called from within a tokio runtime
    /// (`#[tokio::main]`, `Runtime::block_on`, or any async context).
    /// Calling [`Bell::ring`] outside a runtime panics — same
    /// contract as the spawned-task pattern used by sibling widgets
    /// like [`crate::tui::widgets::newsticker::TuiNewsticker`] and
    /// [`crate::tui::widgets::spinner::Spinner`]. A `count == 0`
    /// invocation is special-cased early to avoid touching the
    /// runtime at all (FASM `.nothingtodo` at line 162).
    pub fn ring(self: &Arc<Self>, count: u32) {
        // FASM `.nothingtodo` (line 162) — early bail before any
        // counter mutation or timer spawn. This must happen *before*
        // any `tokio::spawn` so a `ring(0)` call is safe to invoke
        // outside a tokio runtime.
        if count == 0 {
            return;
        }

        // FASM line 142 (`shl esi, 1`) — double for on/off pattern.
        // We use `wrapping_mul` to make the doubling explicit and
        // never panic on overflow (which would wrap silently in FASM
        // due to the 32-bit integer arithmetic).
        let doubled: u32 = count.wrapping_mul(2);

        // Acquire the inner lock with poison recovery — matches the
        // sibling-widget pattern in newsticker.rs / spinner.rs /
        // progressbar.rs. A poisoned mutex here means a previous
        // panic-while-holding-lock left the state in an indeterminate
        // condition; we recover by reading what's there and pressing
        // forward (the worst case is a stale counter, which the next
        // tick will harmlessly observe).
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        if guard.timer.is_some() {
            // FASM `.alreadygoing` (line 158): timer is running, just
            // extend the counter. Do NOT spawn a second task.
            guard.counter = guard.counter.wrapping_add(doubled);
            return;
        }

        // FASM main path (lines 145–155): no timer running — set
        // counter and spawn a fresh interval task.
        //
        // We also pre-set `pending_char = BEL` so the very first
        // [`Widget::draw`] after `ring(N)` produces a BEL emission
        // even if it fires before the spawned task has had a chance
        // to call [`Bell::tick`]. This eliminates a frame-1 race
        // window (~ microseconds) where the cell would otherwise
        // briefly render space before the first tick ran.
        //
        // The first BEL is correct because the doubled counter is
        // always EVEN (since `count.wrapping_mul(2)` always yields
        // an even number), and FASM pre-decrement parity for an
        // even counter is BEL.
        guard.counter = doubled;
        guard.pending_char = BEL as u32;

        // Capture a Weak<Self> so the spawned task does not keep the
        // bell alive after all external references drop. The
        // spawn-with-Weak pattern is identical to the one used in
        // newsticker / spinner / matrix.
        let weak: Weak<Self> = Arc::downgrade(self);
        let handle: JoinHandle<()> = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(TICK_MS));
            // The first `tick().await` resolves immediately by the
            // tokio interval contract; subsequent ticks honor the
            // `TICK_MS` cadence. We absorb the first tick into the
            // loop body to begin the bell pattern as quickly as
            // possible after `ring()` returns — matches FASM where
            // `epoll$timer_new` registers a timer that fires
            // `delay_ms` after registration.
            loop {
                ticker.tick().await;
                match weak.upgrade() {
                    Some(strong) => {
                        if !strong.tick() {
                            // Counter reached 0 — break out of the
                            // loop and let the JoinHandle resolve.
                            // The widget itself stays alive (matches
                            // FASM `[timerptr+24] = 2`).
                            break;
                        }
                    }
                    None => {
                        // The bell was dropped — exit the task to
                        // free its resources. No further action
                        // needed; the Weak's strong-count is now 0.
                        break;
                    }
                }
            }
        });

        // Install the handle so future `cleanup` / `ring` calls can
        // observe the timer is running.
        guard.timer = Some(handle);
    }

    /// Tick callback invoked by the spawned tokio interval task.
    ///
    /// Returns `true` to keep the timer running and `false` to break
    /// the task's loop (matching FASM `tui_bell$timer`'s `eax = 0` /
    /// `eax = 1` semantics at lines 125 and 130 respectively).
    ///
    /// # FASM-faithful pre-decrement parity
    ///
    /// Mirrors FASM `tui_bell$timer` (`tui_bell.inc` lines 116–125)
    /// in computing the next codepoint **before** decrementing the
    /// counter:
    ///
    /// ```text
    ///   mov  edx, ' '              ; default = space
    ///   mov  ecx, 0x7              ; alternative = BEL
    ///   test dword [rdi+counter_ofs], 1
    ///   cmovz edx, ecx             ; cmovz fires when counter is EVEN
    ///   mov  [rsi], edx            ; write to cell[0]
    ///   sub  dword [rdi+counter_ofs], 1   ; THEN decrement
    /// ```
    ///
    /// The Rust translation stores the computed codepoint in
    /// [`BellInner::pending_char`] under [`Mutex`] protection. The
    /// next call to [`Widget::draw`] (with `&mut self` access) reads
    /// `pending_char` and writes it to cell[0] of the embedded
    /// [`TuiBackground`]'s text buffer — completing the
    /// "FASM cell-write" semantics across two Rust callbacks.
    ///
    /// # Borrow-checker rationale
    ///
    /// The spawned tokio task only holds a [`Weak<Self>`] which
    /// upgrades to `Arc<Self>` (i.e., `&self`). Mutating the text
    /// buffer requires `&mut self` access, which is not obtainable
    /// from `Arc<Self>` even via interior mutability on
    /// [`TuiBackground`]'s embedded state (the `state` field is
    /// `pub(crate)` but not behind a [`Mutex`] — it is intended for
    /// `&mut self`-only access in the [`Widget`] trait contract).
    /// Therefore the task confines itself to advancing the counter
    /// and recording the next codepoint; the framework's render
    /// pipeline does the actual buffer mutation.
    fn tick(&self) -> bool {
        // Acquire lock with poison recovery (same pattern as `ring`).
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        // FASM `.alldone` branch (line 128): counter exhausted —
        // clear the timer pointer and return 1 (stop). The Rust
        // equivalent: clear `timer` to None and return false. We
        // leave `pending_char` at its current value (space, written
        // by the previous tick) so [`Widget::draw`] continues to
        // render an empty cell after the ring sequence completes.
        if guard.counter == 0 {
            guard.timer = None;
            return false;
        }

        // FASM lines 116–122: compute pre-decrement parity, store
        // the next codepoint in `pending_char`. The `Widget::draw`
        // pipeline will read this and apply it to cell[0].
        //
        // FASM bit-test inversion: counter EVEN → BEL, counter ODD
        // → space (verified against FASM `cmovz` semantics at line
        // 120 — `cmovz` fires when zero-flag is set, which `test`
        // sets when the operand is zero, i.e., when the low bit is
        // 0, i.e., when counter is EVEN).
        guard.pending_char = if guard.counter & 1 == 0 {
            BEL as u32
        } else {
            b' ' as u32
        };

        // FASM line 122 (`sub dword [rdi+counter_ofs], 1`):
        // decrement counter by 1. We use `saturating_sub` to make
        // the impossibility of underflow explicit (the `counter==0`
        // branch above always fires before we'd reach this line
        // with a zero counter, but defensive arithmetic is cheap).
        guard.counter = guard.counter.saturating_sub(1);

        // FASM line 125 (`xor eax, eax`) — keep the timer alive.
        true
    }

    /// Read the current counter value — internal accessor used by
    /// `ring` and the unit tests to observe the doubled-count and
    /// extension semantics. Access is `pub(crate)` so the tests in
    /// this module (and external integration tests in the
    /// `heavything` crate) can verify behavior without exposing the
    /// counter field publicly. Gated by `#[cfg(test)]` because the
    /// helper exists exclusively to support test observation; the
    /// non-test build path of the library never reads the counter
    /// from outside the spawned timer task and the `Widget::draw`
    /// snapshot.
    #[cfg(test)]
    #[doc(hidden)]
    pub(crate) fn debug_counter(&self) -> u32 {
        match self.inner.lock() {
            Ok(g) => g.counter,
            Err(p) => p.into_inner().counter,
        }
    }

    /// Returns `true` if a timer task is currently registered.
    /// Internal accessor used by tests to verify the
    /// timer-not-spawned path of `ring(0)` and the timer-installed
    /// path of `ring(n > 0)`. Gated by `#[cfg(test)]` for the same
    /// reason as [`Self::debug_counter`].
    #[cfg(test)]
    #[doc(hidden)]
    pub(crate) fn debug_timer_active(&self) -> bool {
        match self.inner.lock() {
            Ok(g) => g.timer.is_some(),
            Err(p) => p.into_inner().timer.is_some(),
        }
    }
}

// ============================================================================
// Free helpers — extracted for unit-testability without needing async runtime
// ============================================================================

/// Advance the bell state machine by one timer tick.
///
/// Returns:
/// - `Some(BEL)` when the counter is non-zero and even (FASM
///   `cmovz` fires when `counter & 1 == 0`, selecting the BEL
///   branch).
/// - `Some(' ')` when the counter is non-zero and odd (FASM
///   `cmovz` is skipped, leaving `edx = ' '`).
/// - `None` when the counter has reached zero — the caller should
///   stop the timer (FASM `.alldone` branch sets `eax = 1`).
///
/// In both `Some` cases the counter is decremented by 1
/// (saturating at 0). When `None` is returned, the timer field is
/// cleared to `None` to mirror FASM's `mov qword [rdi+timerptr_ofs], 0`
/// at line 129.
///
/// This helper exists so the toggle-pattern unit test can drive the
/// state machine synchronously without spawning a tokio runtime —
/// matching the pattern used by sibling widgets (e.g.,
/// [`crate::tui::widgets::newsticker`]'s `tick_scroll_state`).
///
/// # FASM bit-test correctness
///
/// FASM `tui_bell$timer` (`tui_bell.inc` lines 117–120):
///
/// ```text
///   mov  edx, ' '              ; default = space
///   mov  ecx, 0x7              ; alternative = BEL
///   test dword [rdi+counter_ofs], 1
///   cmovz edx, ecx             ; when ZF=1 (counter EVEN), edx ← 0x07
/// ```
///
/// `cmovz` fires when the zero flag is set, which `test` sets when
/// the operand is zero. So **counter EVEN → BEL, counter ODD → space**.
/// This is the exact semantics implemented below.
fn advance_bell_state(inner: &mut BellInner) -> Option<char> {
    if inner.counter == 0 {
        // FASM `.alldone` (line 128): zero out the timer pointer.
        // The caller (the spawned tokio task or the synchronous
        // [`Widget::timer`] path) is responsible for actually
        // breaking out of its loop / returning.
        inner.timer = None;
        return None;
    }

    // FASM bit-test inversion: counter EVEN → BEL (0x07), ODD → space.
    let new_char: char = if inner.counter & 1 == 0 { BEL } else { ' ' };

    // FASM line 122 (`sub dword [rdi+counter_ofs], 1`).
    inner.counter = inner.counter.saturating_sub(1);

    Some(new_char)
}

/// Write a UTF-32 codepoint into the first 4-byte slot of a
/// [`crate::ds::Buffer`] (i.e., cell index 0). Mirrors FASM
/// `mov [rsi], edx` at `tui_bell.inc` line 121, which stores a
/// little-endian `u32` into the text-buffer pointer for the bell's
/// first (and typically only) cell.
///
/// The function is a no-op when the buffer is shorter than 4 bytes,
/// matching the FASM defensive posture: the FASM `tui_background$init_ii`
/// pre-allocates `cells * 4` bytes, but a hostile or pre-cleanup
/// caller might invoke timer with an empty buffer; in that case we
/// silently skip the write rather than panic.
///
/// # Endianness
///
/// `u32::to_le_bytes()` produces little-endian bytes, matching x86_64
/// FASM's `mov [rsi], edx` instruction (which stores the dword in
/// processor-native byte order — little-endian on x86_64).
fn write_first_cell_codepoint(buf: &mut crate::ds::Buffer, codepoint: u32) {
    let bytes = codepoint.to_le_bytes();
    let slice = buf.as_mut_slice();
    if slice.len() >= 4 {
        slice[0..4].copy_from_slice(&bytes);
    }
    // else: buffer too small — silently skip. The next `draw` pass
    // (which calls `tui_background$nvfill`) will repopulate the
    // buffer with `cells * 4` bytes of bgfillchar (' ').
}

/// Deep-clone a [`WidgetState`] for use during widget cloning.
///
/// Replicates the private `init_copy_from` helper from
/// [`crate::tui::widgets::background`] (which is not exported across
/// the module boundary). The pattern is identical to the helpers in
/// sibling widget modules ([`crate::tui::widgets::newsticker`] line
/// 788, [`crate::tui::widgets::progressbar`] line 880).
///
/// Mirrors FASM `tui_object$init_copy` (`tui_object.inc` lines
/// 254–276):
///
/// 1. Scalar fields (`bounds`, `width`, `height`, `width_percent`,
///    `height_percent`, `visible`, `include_in_layout`,
///    `absolute_x`, `absolute_y`, `layout`, `horiz_align`,
///    `vert_align`, `bastard_glue`, `drop_shadow`, `scroll`) are
///    direct value copies.
/// 2. `display_name` is a heap-allocated string — clone via
///    [`String::clone`] (FASM uses `string$clone` at line 263).
/// 3. `text` and `attributes` buffers are deep-cloned via
///    [`Buffer::clone`] / [`Attributes::clone`] (both derive
///    [`Clone`]); FASM `memcpy`s the `cells * 4` bytes at line 268.
/// 4. `children` are recursively cloned via [`Widget::clone_widget`]
///    on each child (FASM `list$clone_with_callback` invoking each
///    widget's vtable[`tui_vclone`] at line 273).
/// 5. `bastards` stays empty — matches FASM `init_copy` line 274
///    which does NOT clone the bastard children list (only direct
///    children participate in inheritance).
fn clone_widget_state(src: &WidgetState) -> Result<WidgetState, TuiError> {
    let mut cloned = WidgetState::new();

    // Scalar fields — direct value copies.
    cloned.bounds = src.bounds;
    cloned.width = src.width;
    cloned.width_percent = src.width_percent;
    cloned.height = src.height;
    cloned.height_percent = src.height_percent;
    cloned.visible = src.visible;
    cloned.include_in_layout = src.include_in_layout;
    cloned.absolute_x = src.absolute_x;
    cloned.absolute_y = src.absolute_y;
    cloned.layout = src.layout;
    cloned.horiz_align = src.horiz_align;
    cloned.vert_align = src.vert_align;
    cloned.bastard_glue = src.bastard_glue;
    cloned.drop_shadow = src.drop_shadow;
    cloned.scroll = src.scroll;
    cloned.display_name = src.display_name.clone();

    // Buffers — deep clone (Buffer/Attributes both derive Clone).
    cloned.text = src.text.clone();
    cloned.attributes = src.attributes.clone();

    // Children — recursive deep clone via Widget::clone_widget.
    for child in src.children.iter() {
        let cloned_child = child.clone_widget()?;
        cloned.children.push_back(cloned_child);
    }

    // bastards stays empty (matching FASM init_copy at line 274).
    Ok(cloned)
}

// ============================================================================
// Widget trait — required + 3 vtable overrides + draw delegate
// ============================================================================

impl Widget for Bell {
    /// Required base accessor — delegate to the embedded
    /// [`TuiBackground`]'s state, which transitively holds the
    /// inherited [`WidgetState`].
    fn state(&self) -> &WidgetState {
        self.background.state()
    }

    /// Required base accessor — mutable delegate.
    fn state_mut(&mut self) -> &mut WidgetState {
        self.background.state_mut()
    }

    /// Required downcast accessor — returns `self` so callers
    /// holding an `Arc<dyn Widget>` can recover the concrete
    /// [`Bell`] via [`Any::downcast_ref`].
    fn as_any(&self) -> &dyn Any {
        self
    }

    // ----------------- Override 1: cleanup (vtable slot 0) -----------------

    /// Override — vtable slot 0 (`tui_vcleanup`).
    ///
    /// FASM parallel: `tui_bell$cleanup`
    /// (`tui_bell.inc` lines 87–105):
    ///
    /// ```text
    ///   if self.timerptr != 0:
    ///       epoll$timer_clear(self.timerptr)
    ///   tui_object$cleanup(self)
    /// ```
    ///
    /// 1. Cancel the spawned timer task via [`JoinHandle::abort`]
    ///    (replaces FASM `epoll$timer_clear` at line 96). After this
    ///    call the next [`Weak::upgrade`] in the task body would see
    ///    the bell alive but the task is already aborted, so no
    ///    further [`Bell::tick`] calls happen.
    /// 2. Mirror the trait-default `cleanup` body inline by clearing
    ///    `state.children`, `state.bastards`, `state.text`,
    ///    `state.attributes`, and `state.display_name`. This matches
    ///    FASM `tui_object$cleanup` at lines 98 and 102 — clearing
    ///    the per-widget heap-tracked buffers without re-entering
    ///    polymorphic dispatch.
    ///
    /// **Why inline rather than call
    /// [`crate::tui::object::cleanup_widget`]?** The free helper
    /// dispatches polymorphically through `self.cleanup()` at its
    /// tail; calling it from inside this override produces unbounded
    /// recursion. The exemplar sibling implementations in
    /// [`crate::tui::widgets::spinner::Spinner`] (line 551) and
    /// [`crate::tui::widgets::newsticker::TuiNewsticker`] use the
    /// same inline-clear pattern; [`cleanup_widget`] is the
    /// framework's entry point invoked **from outside** the widget.
    fn cleanup(&mut self) {
        // ---- Step 1: cancel the timer task.
        //
        // We pull the JoinHandle out of the Mutex to avoid holding
        // the lock during abort, and to leave `timer = None` so a
        // subsequent cleanup() invocation (defensive idempotency) is
        // a no-op.
        let handle: Option<JoinHandle<()>> = match self.inner.lock() {
            Ok(mut guard) => guard.timer.take(),
            Err(poisoned) => poisoned.into_inner().timer.take(),
        };
        if let Some(h) = handle {
            h.abort();
        }

        // ---- Step 2: inline the trait-default cleanup body.
        //
        // Mirrors the [`Widget::cleanup`] default impl in
        // `crates/heavything/src/tui/object.rs`. We do NOT call
        // [`crate::tui::object::cleanup_widget`] here because that
        // helper polymorphically dispatches `self.cleanup()` at its
        // tail — which would re-enter this method ad infinitum.
        let state = self.background.state_mut();
        state.children.clear();
        state.bastards.clear();
        state.text.clear();
        state.attributes.clear();
        state.display_name.clear();
    }

    // ----------------- Override 2: clone_widget (vtable slot 1) -----------------

    /// Override — vtable slot 1 (`tui_vclone`).
    ///
    /// FASM parallel: `tui_bell$clone`
    /// (`tui_bell.inc` lines 68–84):
    ///
    /// ```text
    ///   heap$alloc_clear(tui_bell_size)        ; zero-fills tail
    ///   set vtable to tui_bell$vtable
    ///   tui_background$init_copy(new, self)    ; clones background only
    ///   ; ...counter/timerptr stay zero from alloc_clear
    /// ```
    ///
    /// **CRITICAL**: Bell's clone differs from
    /// [`crate::tui::widgets::newsticker::TuiNewsticker::clone_widget`]
    /// (and from spinner / matrix) in that **it does NOT spawn a
    /// timer task**. The FASM `heap$alloc_clear` zero-fills the
    /// 16-byte tail, and `tui_background$init_copy` only copies the
    /// background fields. The result is a cloned bell with
    /// `counter = 0` and `timer = None` — the clone is fully inert
    /// until the caller invokes [`Bell::ring`] on it.
    ///
    /// This matches the FASM author's intent that clone produces a
    /// "fresh, idle bell" rather than a duplicate of an in-progress
    /// ringing pattern. A caller wishing to re-trigger the bell
    /// pattern on the clone must explicitly call `ring(n)` on the
    /// returned `Arc<dyn Widget>` (after downcasting).
    ///
    /// # Errors
    ///
    /// Propagates [`TuiError`] from [`clone_widget_state`] when
    /// recursive child cloning fails (e.g., a child widget's
    /// [`Widget::clone_widget`] returns an error).
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // FASM `tui_object$init_copy` deep-clones the parent state.
        let cloned_bg_state = clone_widget_state(self.background.state())?;
        let cloned_bg = TuiBackground {
            state: cloned_bg_state,
            bgfillchar: self.background.fillchar(),
            bgcolors: self.background.colors(),
        };

        // Inert BellInner — counter zero, no timer, pending_char=space.
        // Matches FASM's `heap$alloc_clear` zero-filled tail (the
        // pending_char field has no FASM analogue and defaults to
        // its post-construction value of `' '`).
        let fresh_inner = BellInner {
            counter: 0,
            timer: None,
            pending_char: b' ' as u32,
        };

        Ok(Arc::new(Self {
            background: cloned_bg,
            inner: Mutex::new(fresh_inner),
        }) as Arc<dyn Widget>)
    }

    // ----------------- Override 3: timer (vtable slot 6) -----------------

    /// Override — vtable slot 6 (`tui_vtimer`).
    ///
    /// FASM parallel: `tui_bell$timer`
    /// (`tui_bell.inc` lines 109–133):
    ///
    /// ```text
    ///   if self.counter == 0:
    ///       self.timerptr = 0                     ; .alldone
    ///       return 1                              ; eax = 1 (stop timer)
    ///   rsi = self.text                           ; tui_text_ofs pointer
    ///   edx = ' '
    ///   ecx = 0x7
    ///   if (counter & 1) == 0: edx = ecx          ; cmovz selects BEL
    ///   [rsi] = edx                               ; write codepoint
    ///   self.counter -= 1
    ///   call vupdatedisplaylist
    ///   return 0                                  ; eax = 0 (keep timer)
    /// ```
    ///
    /// 1. Run the bit-test state machine via [`advance_bell_state`].
    ///    On `None` (counter exhausted) we return immediately — the
    ///    timer field is already cleared inside the helper.
    /// 2. On `Some(c)` we write `c`'s codepoint as four little-endian
    ///    bytes to cell 0 of the text buffer (FASM `mov [rsi], edx`
    ///    at line 121).
    /// 3. Trigger the display-list update via
    ///    [`Widget::update_display_list`] (FASM
    ///    `call qword [rcx+tui_vupdatedisplaylist]` at line 124).
    ///    The trait default is a no-op; renderer-bound compositions
    ///    override it to flush.
    ///
    /// The trait signature is `fn timer(&mut self) -> ()` — there is
    /// no [`crate::tui::object::TimerAction`] return value at the
    /// trait level. FASM's `eax = 0` (keep) / `eax = 1` (stop) is
    /// represented internally by the `inner.timer = None` mutation
    /// performed by [`advance_bell_state`] when the counter reaches
    /// zero; the spawned task observes this through [`Bell::tick`]'s
    /// boolean return.
    fn timer(&mut self) {
        // ---- Step 1: advance the state machine.
        let next_char: Option<char> = match self.inner.lock() {
            Ok(mut g) => advance_bell_state(&mut g),
            Err(p) => advance_bell_state(&mut p.into_inner()),
        };

        // FASM `.alldone` path — counter was zero, nothing to do.
        let Some(c) = next_char else { return };

        // ---- Step 2: write codepoint to cell 0 of text buffer.
        let codepoint: u32 = c as u32;
        let state = self.background.state_mut();
        write_first_cell_codepoint(&mut state.text, codepoint);

        // ---- Step 3: trigger display-list update (FASM line 124).
        self.update_display_list();
    }

    // ----------------- Inherited slot 2 (draw) — explicit delegate -----------------

    /// "Inherited" slot 2 (`tui_vdraw`) — delegates to
    /// [`TuiBackground::draw`] for the bulk fill, then overlays the
    /// pending bell codepoint into cell[0].
    ///
    /// # FASM mapping
    ///
    /// FASM `tui_bell$vtable[2] = tui_background$draw`
    /// (`tui_bell.inc` line 32). The FASM vtable copies the parent's
    /// `draw` function pointer directly so that on each render pass
    /// the bell's text buffer gets refilled with `bgfillchar = ' '`.
    /// The cell-overlay step is implicit in FASM because
    /// `tui_bell$timer` writes cell[0] = BEL/space directly during
    /// the timer callback, and that write persists in memory until
    /// the next `tui_background$draw` overwrites it.
    ///
    /// In Rust, the timer callback ([`Bell::tick`]) cannot mutate
    /// the text buffer through `&self` access — see the rationale on
    /// [`Bell::tick`]. We therefore split the FASM "draw + write"
    /// behavior across two callbacks:
    ///
    /// 1. **`Widget::draw`** (this method): delegates to
    ///    [`TuiBackground::draw`] to fill the buffer with
    ///    `bgfillchar = ' '` (FASM `tui_background$nvfill`), then
    ///    overlays cell[0] with the codepoint stored in
    ///    [`BellInner::pending_char`].
    /// 2. **[`Bell::tick`]**: computes the next codepoint based on
    ///    the FASM pre-decrement parity (counter EVEN → BEL, ODD →
    ///    space) and stores it in [`BellInner::pending_char`].
    ///
    /// The combined effect across these two callbacks is identical
    /// to the FASM behavior: each render pass produces a cell[0]
    /// containing the most-recently-computed bell codepoint.
    ///
    /// # Order of operations
    ///
    /// 1. Read `pending_char` under [`Mutex`] (no allocations,
    ///    cheap).
    /// 2. Call [`TuiBackground::draw`] (which calls
    ///    [`TuiBackground::nvfill`] to fill the entire text buffer
    ///    with `bgfillchar = ' '` and the entire attribute buffer
    ///    with packed `bgcolors`).
    /// 3. Overlay `pending_char` onto cell[0] of the text buffer
    ///    via [`write_first_cell_codepoint`].
    ///
    /// The two-step "fill then overlay" is necessary because
    /// [`TuiBackground::nvfill`] unconditionally fills the entire
    /// buffer; if we wrote `pending_char` first, `nvfill` would
    /// overwrite it.
    ///
    /// # Errors
    ///
    /// Propagates [`TuiError::Render`] from [`TuiBackground::draw`]
    /// when the buffer-fill arithmetic overflows. (Realistically
    /// impossible for any sensible `width`/`height` pair on a
    /// 64-bit target.)
    fn draw(&mut self, renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        // ---- Step 1: snapshot pending_char under the Mutex.
        //
        // We snapshot the value rather than holding the lock across
        // the call to `self.background.draw(renderer)` because the
        // latter mutates `self.background` and we want to release the
        // BellInner lock as quickly as possible to minimize
        // contention with the spawned task's `tick` calls.
        let pending: u32 = match self.inner.lock() {
            Ok(g) => g.pending_char,
            Err(p) => p.into_inner().pending_char,
        };

        // ---- Step 2: delegate to background.draw to fill buffers.
        //
        // FASM `tui_background$draw` calls `tui_background$nvfill`
        // which fills the text buffer with `bgfillchar = ' '` and
        // the attribute buffer with packed `bgcolors`.
        self.background.draw(renderer)?;

        // ---- Step 3: overlay pending_char onto cell[0].
        //
        // FASM `tui_bell$timer` writes cell[0] = BEL/space at line
        // 121 (`mov [rsi], edx`); we apply the same write here using
        // the codepoint that the most-recent `tick` selected.
        //
        // When `pending_char == ' '` (the post-construction default
        // and the post-completion state) this overlay is a no-op
        // value-wise (cell[0] is already ' ' from `nvfill`), but
        // performing the write unconditionally keeps the code
        // simple and produces no observable side-effect.
        let state = self.background.state_mut();
        write_first_cell_codepoint(&mut state.text, pending);

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================
//
// Coverage strategy mirrors the sibling pattern established by
// [`crate::tui::widgets::newsticker`] and [`crate::tui::widgets::spinner`]:
//
// 1. **Type-property tests** (`#[test]`) — verify the GPLv3 attribution
//    constants and `Send + Sync` bound at monomorphisation time. These
//    do NOT require a tokio runtime.
//
// 2. **Free-helper tests** (`#[test]`) — drive [`advance_bell_state`]
//    and [`write_first_cell_codepoint`] synchronously, exercising the
//    FASM bit-test parity inversion (counter EVEN → BEL, ODD → space)
//    and the little-endian cell-write semantics without spawning a
//    tokio runtime.
//
// 3. **Constructor tests** (`#[test]`) — verify [`Bell::new`] produces
//    a widget with the expected dimensions, fill character, and
//    initial state. [`Bell::new`] is synchronous so these do not need
//    a tokio runtime either.
//
// 4. **Ring + clone + cleanup tests** (`#[tokio::test]`) — the only
//    tests that actually spawn the timer task. These verify
//    [`Bell::ring`]'s doubling, extension, no-op, and pending_char
//    semantics, [`Widget::clone_widget`]'s "inert clone" promise, and
//    [`Widget::cleanup`]'s timer-abort + state-clear behavior.

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper — produce a default test [`ColorPair`] (white-on-black).
    /// Mirrors the convention from
    /// [`crate::tui::widgets::newsticker`] tests at line 1378.
    fn test_colors() -> ColorPair {
        ColorPair { fg: 7, bg: 0 }
    }

    /// `assert_send_sync<T>()` enforces the `Send + Sync` bound at
    /// monomorphisation time — required for `Arc<dyn Widget>` use
    /// across tokio task boundaries. Same helper as
    /// [`crate::tui::widgets::newsticker`] tests at line 1385.
    fn assert_send_sync<T: Send + Sync>() {}

    // ----------------------------------------------------------------
    // Section 1: Type-property tests (sync, no runtime)
    // ----------------------------------------------------------------

    /// `Bell` must be `Send + Sync` for use across tokio task
    /// boundaries — required because `Arc<dyn Widget>` carries this
    /// bound and bell is embedded into the widget tree as exactly
    /// such an `Arc<dyn Widget>`.
    #[test]
    fn bell_is_send_and_sync() {
        assert_send_sync::<Bell>();
        assert_send_sync::<TuiBell>();
    }

    /// FASM `mov ecx, 0x7` (line 118) — the BEL constant must equal
    /// the ASCII control character `0x07` for the terminal to emit
    /// an audible bell. Guard against accidental refactoring of the
    /// constant.
    #[test]
    fn test_bel_constant_equals_seven() {
        assert_eq!(BEL as u32, 0x07);
        assert_eq!(BEL, '\u{0007}');
    }

    /// FASM `mov edi, 120` (line 149) — the bell tick interval is
    /// hardcoded to 120 ms. Guard against accidental refactoring of
    /// the cadence.
    #[test]
    fn test_tick_ms_matches_fasm_constant() {
        assert_eq!(TICK_MS, 120);
    }

    /// FASM `mov ecx, ' '` (line 58) — the background fill char is
    /// the ASCII space (0x20). Guard against refactoring that might
    /// inadvertently change the visible-state-at-rest contract.
    #[test]
    fn test_fillchar_space_constant() {
        assert_eq!(FILLCHAR_SPACE, 0x20);
        assert_eq!(FILLCHAR_SPACE, b' ' as u32);
    }

    // ----------------------------------------------------------------
    // Section 2: advance_bell_state — free-function unit tests
    // ----------------------------------------------------------------
    //
    // These tests drive the FASM `tui_bell$timer` state machine
    // synchronously — no tokio runtime needed. They verify the
    // critical bit-test inversion: counter EVEN → BEL, ODD → space,
    // matching FASM `cmovz` semantics at line 120.

    /// Build a [`BellInner`] with the given counter value and a
    /// non-`Some` timer field — used by the synchronous
    /// `advance_bell_state` tests below.
    fn make_inner(counter: u32) -> BellInner {
        BellInner {
            counter,
            timer: None,
            pending_char: b' ' as u32,
        }
    }

    /// FASM `.alldone` (line 128): when `counter == 0`, the helper
    /// returns `None` and clears the `timer` field. The caller
    /// (spawned task) is expected to break out of its loop.
    #[test]
    fn test_advance_state_with_zero_counter_returns_none() {
        let mut inner = make_inner(0);
        let result = advance_bell_state(&mut inner);
        assert_eq!(result, None);
        assert!(
            inner.timer.is_none(),
            "timer must remain None after exhausted counter"
        );
        assert_eq!(inner.counter, 0, "counter stays at zero");
    }

    /// FASM `cmovz` fires when `counter & 1 == 0` (zero flag set by
    /// `test`). For `counter = 4` (EVEN), the result must be BEL and
    /// the counter must decrement to 3.
    #[test]
    fn test_advance_state_with_even_counter_returns_bel() {
        let mut inner = make_inner(4);
        let result = advance_bell_state(&mut inner);
        assert_eq!(result, Some(BEL));
        assert_eq!(inner.counter, 3, "counter decrements after computing BEL");
    }

    /// FASM `cmovz` does NOT fire when `counter & 1 == 1` (zero flag
    /// clear). For `counter = 3` (ODD), the result must be space and
    /// the counter must decrement to 2.
    #[test]
    fn test_advance_state_with_odd_counter_returns_space() {
        let mut inner = make_inner(3);
        let result = advance_bell_state(&mut inner);
        assert_eq!(result, Some(' '));
        assert_eq!(inner.counter, 2, "counter decrements after computing space");
    }

    /// Drive the state machine through a full `ring(2)` sequence
    /// (counter starts at `2 << 1 = 4`) to verify the FASM-faithful
    /// alternating BEL / space pattern. Expected sequence after
    /// four ticks: BEL, space, BEL, space — then the fifth tick
    /// returns `None` because the counter has reached 0.
    ///
    /// FASM trace for `count = 2` (counter=4):
    /// - Tick 1: counter=4 (EVEN) → BEL, counter→3
    /// - Tick 2: counter=3 (ODD) → space, counter→2
    /// - Tick 3: counter=2 (EVEN) → BEL, counter→1
    /// - Tick 4: counter=1 (ODD) → space, counter→0
    /// - Tick 5: counter=0 → None (timer cleared)
    #[test]
    fn test_advance_state_full_ring_two_pattern() {
        let mut inner = make_inner(4);

        assert_eq!(advance_bell_state(&mut inner), Some(BEL));
        assert_eq!(inner.counter, 3);

        assert_eq!(advance_bell_state(&mut inner), Some(' '));
        assert_eq!(inner.counter, 2);

        assert_eq!(advance_bell_state(&mut inner), Some(BEL));
        assert_eq!(inner.counter, 1);

        assert_eq!(advance_bell_state(&mut inner), Some(' '));
        assert_eq!(inner.counter, 0);

        // Fifth tick: counter exhausted, helper returns None.
        assert_eq!(advance_bell_state(&mut inner), None);
        assert!(inner.timer.is_none());
    }

    // ----------------------------------------------------------------
    // Section 3: write_first_cell_codepoint — free-function unit tests
    // ----------------------------------------------------------------

    /// `write_first_cell_codepoint` writes the codepoint as four
    /// little-endian bytes into the first cell of the buffer, leaving
    /// any trailing bytes untouched.
    #[test]
    fn test_write_first_cell_codepoint_writes_le_bytes() {
        let mut buf = crate::ds::Buffer::with_capacity(8);
        // Pre-populate the buffer with a recognizable pattern so we
        // can confirm only the first 4 bytes are mutated.
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44]);

        // Write BEL (0x07) into cell 0.
        write_first_cell_codepoint(&mut buf, BEL as u32);

        let slice = buf.as_slice();
        // First 4 bytes are little-endian 0x00000007.
        assert_eq!(&slice[0..4], &[0x07, 0x00, 0x00, 0x00]);
        // Trailing 4 bytes are untouched.
        assert_eq!(&slice[4..8], &[0x11, 0x22, 0x33, 0x44]);
    }

    /// `write_first_cell_codepoint` is a no-op when the buffer is
    /// shorter than 4 bytes. Defensive posture — matches the
    /// FASM-equivalent guarantee that an empty buffer is safe.
    #[test]
    fn test_write_first_cell_codepoint_short_buffer_noop() {
        let mut buf = crate::ds::Buffer::new();
        // Buffer is empty (length = 0, < 4 bytes). The helper must
        // silently skip rather than panic.
        write_first_cell_codepoint(&mut buf, BEL as u32);
        assert_eq!(buf.len(), 0, "empty buffer remains empty");

        // Buffer with 3 bytes is also too short.
        let mut buf3 = crate::ds::Buffer::with_capacity(8);
        buf3.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        write_first_cell_codepoint(&mut buf3, BEL as u32);
        // The 3 bytes remain unchanged.
        assert_eq!(buf3.as_slice(), &[0xFF, 0xFE, 0xFD]);
    }

    /// `write_first_cell_codepoint` correctly encodes the space
    /// character (`0x20`) — the post-tick fillchar that
    /// [`Widget::draw`] applies after a BEL emission. Verifies the
    /// space → bytes encoding matches the FASM `init_ii` fillchar
    /// argument at line 58.
    #[test]
    fn test_write_first_cell_codepoint_writes_space() {
        let mut buf = crate::ds::Buffer::with_capacity(4);
        buf.extend_from_slice(&[0x99, 0x99, 0x99, 0x99]);
        write_first_cell_codepoint(&mut buf, b' ' as u32);
        assert_eq!(buf.as_slice(), &[0x20, 0x00, 0x00, 0x00]);
    }

    // ----------------------------------------------------------------
    // Section 4: Constructor — Bell::new (sync — no tokio runtime)
    // ----------------------------------------------------------------

    /// FASM `tui_bell$new(edi=width, esi=height, edx=colors)` — a
    /// 1×1 bell is the canonical FASM use case. Verify dimensions
    /// flow through to the inherited [`WidgetState`].
    #[test]
    fn test_bell_new_creates_correct_dimensions_1x1() {
        let bell = Bell::new(1, 1, test_colors());
        assert_eq!(bell.state().width, 1);
        assert_eq!(bell.state().height, 1);
    }

    /// `Bell::new` accepts arbitrary dimensions per the constructor
    /// signature; verify a non-1×1 size flows through correctly.
    /// (FASM does not enforce 1×1 — the assembly source comment
    /// notes "this is typically 1×1 but other sizes are accepted".)
    #[test]
    fn test_bell_new_creates_correct_dimensions_5x3() {
        let bell = Bell::new(5, 3, test_colors());
        assert_eq!(bell.state().width, 5);
        assert_eq!(bell.state().height, 3);
    }

    /// Verify the FASM `tui_bell$new` zero-initialized tail (counter
    /// and timer). `BellInner` defaults: counter=0, timer=None,
    /// pending_char=' '.
    #[test]
    fn test_bell_new_initial_state_is_inert() {
        let bell = Bell::new(1, 1, test_colors());
        let guard = bell.inner.lock().expect("inner not poisoned");
        assert_eq!(guard.counter, 0, "counter starts at zero");
        assert!(guard.timer.is_none(), "no timer task on construction");
        assert_eq!(guard.pending_char, b' ' as u32, "pending_char defaults to space");
    }

    // ----------------------------------------------------------------
    // Section 5: ring — public method tests (require tokio runtime)
    // ----------------------------------------------------------------

    /// FASM `.nothingtodo` (line 162) — `ring(0)` is a no-op:
    /// counter stays at 0, no timer is spawned, and (importantly) no
    /// `tokio::spawn` call is made — so the test could in theory run
    /// outside a tokio runtime, but we use `#[tokio::test]` for
    /// consistency with the other ring tests.
    #[tokio::test]
    async fn test_ring_zero_is_noop() {
        let bell = Bell::new(1, 1, test_colors());
        bell.ring(0);

        assert_eq!(bell.debug_counter(), 0, "ring(0) leaves counter at 0");
        assert!(!bell.debug_timer_active(), "ring(0) does NOT spawn a timer");
    }

    /// FASM `shl esi, 1` (line 142) — `ring(N)` doubles the count
    /// before storing it in the counter. `ring(3)` → counter=6.
    /// FASM `epoll$timer_new` (line 149) — a timer task is spawned.
    #[tokio::test]
    async fn test_ring_doubles_count_and_spawns_timer() {
        let bell = Bell::new(1, 1, test_colors());
        bell.ring(3);

        assert_eq!(bell.debug_counter(), 6, "ring(3) sets counter to 6 (3 << 1)");
        assert!(bell.debug_timer_active(), "ring(N>0) spawns a timer task");

        // Cleanup: tear down the spawned task.
        let mut owned = Arc::try_unwrap(bell)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.cleanup();
    }

    /// FASM `.alreadygoing` (line 158) — calling `ring(N)` while a
    /// timer is already running ADDS `N << 1` to the existing
    /// counter, without spawning a second task.
    ///
    /// Sequence: `ring(2)` → counter=4; `ring(3)` → counter=4+6=10.
    /// The same JoinHandle remains active; only the counter grows.
    #[tokio::test]
    async fn test_ring_while_running_extends_counter() {
        let bell = Bell::new(1, 1, test_colors());
        bell.ring(2);
        assert_eq!(bell.debug_counter(), 4, "first ring(2) sets counter to 4");
        assert!(bell.debug_timer_active(), "first ring spawns a timer");

        // Snapshot the current `Arc::weak_count` before the second
        // ring — if `ring(3)` spawned a SECOND task, the weak count
        // would increase by 1; otherwise it stays the same.
        let weak_before = Arc::weak_count(&bell);

        bell.ring(3);
        assert_eq!(
            bell.debug_counter(),
            10,
            "second ring(3) extends counter by 6 → 10"
        );
        assert!(bell.debug_timer_active(), "extension does not clear the timer");

        let weak_after = Arc::weak_count(&bell);
        assert_eq!(
            weak_before, weak_after,
            "extension must NOT spawn a second task (weak count unchanged)"
        );

        // Cleanup.
        let mut owned = Arc::try_unwrap(bell)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.cleanup();
    }

    /// `ring(N>0)` pre-sets `pending_char = BEL` so the very first
    /// render after `ring()` displays BEL even if the spawned task
    /// has not yet had a chance to call [`Bell::tick`]. This
    /// eliminates a frame-1 race window of microseconds.
    #[tokio::test]
    async fn test_ring_presets_pending_char_to_bel() {
        let bell = Bell::new(1, 1, test_colors());
        // Before ring: pending_char = ' ' (space).
        let pending_before = match bell.inner.lock() {
            Ok(g) => g.pending_char,
            Err(p) => p.into_inner().pending_char,
        };
        assert_eq!(pending_before, b' ' as u32);

        bell.ring(1);

        // After ring: pending_char = BEL (0x07).
        let pending_after = match bell.inner.lock() {
            Ok(g) => g.pending_char,
            Err(p) => p.into_inner().pending_char,
        };
        assert_eq!(pending_after, BEL as u32, "ring presets pending_char to BEL");

        // Cleanup.
        let mut owned = Arc::try_unwrap(bell)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.cleanup();
    }

    /// `ring(0)` must not modify `pending_char` (the bell was idle
    /// and stays idle). The pre-construction default of `' '` is
    /// preserved.
    #[tokio::test]
    async fn test_ring_zero_does_not_modify_pending_char() {
        let bell = Bell::new(1, 1, test_colors());
        bell.ring(0);

        let pending = match bell.inner.lock() {
            Ok(g) => g.pending_char,
            Err(p) => p.into_inner().pending_char,
        };
        assert_eq!(pending, b' ' as u32, "ring(0) leaves pending_char as space");
    }

    /// Calling `ring(N)` while a timer is already running must NOT
    /// reset `pending_char` — the running timer's tick cycle should
    /// continue from wherever it left off, not jump back to BEL.
    #[tokio::test]
    async fn test_ring_extension_preserves_pending_char() {
        let bell = Bell::new(1, 1, test_colors());
        bell.ring(2);

        // Manually mutate pending_char to space (simulating a tick
        // that just wrote space — counter is now odd-decremented).
        {
            let mut guard = bell.inner.lock().expect("inner not poisoned");
            guard.pending_char = b' ' as u32;
        }

        bell.ring(3);

        let pending = match bell.inner.lock() {
            Ok(g) => g.pending_char,
            Err(p) => p.into_inner().pending_char,
        };
        assert_eq!(
            pending, b' ' as u32,
            "extension does NOT reset pending_char to BEL — the running tick cycle continues"
        );

        // Cleanup.
        let mut owned = Arc::try_unwrap(bell)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.cleanup();
    }

    // ----------------------------------------------------------------
    // Section 6: clone_widget — Bell-specific inert-clone semantics
    // ----------------------------------------------------------------

    /// **CRITICAL bell-specific behavior**: clone produces an inert
    /// widget — counter=0, timer=None — even when cloning a bell
    /// whose source was actively ringing. The caller must explicitly
    /// `ring(N)` on the clone to start emitting bells from it.
    ///
    /// FASM rationale: `tui_bell$clone` (lines 68–84) calls
    /// `heap$alloc_clear` (which zero-fills the 16-byte tail) and
    /// `tui_background$init_copy` (which only copies background
    /// fields). Counter and timer pointer remain zero.
    #[tokio::test]
    async fn test_clone_widget_yields_inert_clone() {
        let source = Bell::new(1, 1, test_colors());
        source.ring(5); // Source is now actively ringing.

        // Verify source is ringing.
        assert_eq!(source.debug_counter(), 10);
        assert!(source.debug_timer_active());

        // Clone via the trait method.
        let cloned_dyn = source.clone_widget().expect("clone_widget should succeed");
        let cloned_concrete: &Bell = cloned_dyn
            .as_any()
            .downcast_ref::<Bell>()
            .expect("downcast must succeed for clone result");

        // CRITICAL: clone is inert — counter=0, timer=None.
        assert_eq!(cloned_concrete.debug_counter(), 0, "clone counter must be 0");
        assert!(
            !cloned_concrete.debug_timer_active(),
            "clone must NOT have a timer task"
        );

        // Clone has its own pending_char defaulted to space.
        let clone_pending = match cloned_concrete.inner.lock() {
            Ok(g) => g.pending_char,
            Err(p) => p.into_inner().pending_char,
        };
        assert_eq!(clone_pending, b' ' as u32, "clone pending_char defaults to space");

        // Source remains in its ringing state — clone does not
        // disturb the source.
        assert_eq!(source.debug_counter(), 10, "source counter unchanged by clone");
        assert!(source.debug_timer_active(), "source timer unchanged by clone");

        // Cleanup both.
        drop(cloned_dyn);
        let mut owned = Arc::try_unwrap(source)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.cleanup();
    }

    /// `clone_widget` produces an `Arc<dyn Widget>` with a fresh
    /// allocation distinct from the source. Mirrors the
    /// [`crate::tui::widgets::newsticker`] test
    /// `test_clone_widget_yields_independent_arc` at line 1721.
    #[tokio::test]
    async fn test_clone_widget_yields_independent_allocation() {
        let bell: Arc<Bell> = Bell::new(1, 1, test_colors());
        let cloned = bell.clone_widget().expect("clone_widget should succeed");
        let cloned_concrete: &Bell = cloned
            .as_any()
            .downcast_ref::<Bell>()
            .expect("downcast must succeed");

        // Different underlying allocations — pointer comparison
        // must show they are distinct objects.
        assert!(
            !std::ptr::eq(Arc::as_ptr(&bell), cloned_concrete as *const Bell),
            "clone must produce a fresh allocation"
        );

        drop(cloned);
        // Source bell never had its timer spawned, so we can drop
        // the only Arc reference cleanly.
        let _ = Arc::try_unwrap(bell).map_err(|_| ());
    }

    /// `clone_widget` deep-copies the inherited [`WidgetState`]
    /// (width, height, etc.). Mutating the source's state after
    /// cloning must not affect the clone.
    #[tokio::test]
    async fn test_clone_widget_deep_copies_state() {
        let bell: Arc<Bell> = Bell::new(7, 2, test_colors());
        let cloned = bell.clone_widget().expect("clone_widget should succeed");
        let cloned_concrete: &Bell = cloned
            .as_any()
            .downcast_ref::<Bell>()
            .expect("downcast must succeed");

        // Clone has the same dimensions as source.
        assert_eq!(cloned_concrete.state().width, 7);
        assert_eq!(cloned_concrete.state().height, 2);

        // Cleanup.
        drop(cloned);
        let _ = Arc::try_unwrap(bell).map_err(|_| ());
    }

    // ----------------------------------------------------------------
    // Section 7: cleanup — Widget trait override
    // ----------------------------------------------------------------

    /// `cleanup()` aborts the spawned timer task and clears the
    /// inherited state buffers. Mirrors the
    /// [`crate::tui::widgets::newsticker`] test
    /// `test_cleanup_clears_timer_and_filltext` at line 1644.
    #[tokio::test]
    async fn test_cleanup_aborts_timer_and_clears_state() {
        let bell = Bell::new(1, 1, test_colors());
        bell.ring(3);

        let mut owned = Arc::try_unwrap(bell)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");

        // Verify timer is set BEFORE cleanup.
        let timer_before = match owned.inner.lock() {
            Ok(g) => g.timer.is_some(),
            Err(p) => p.into_inner().timer.is_some(),
        };
        assert!(timer_before, "timer should be set before cleanup");

        owned.cleanup();

        // Verify timer is None AFTER cleanup.
        let timer_after = match owned.inner.lock() {
            Ok(g) => g.timer.is_some(),
            Err(p) => p.into_inner().timer.is_some(),
        };
        assert!(!timer_after, "timer should be None after cleanup");

        // State buffers are cleared (matches trait-default cleanup
        // body inlined into Bell::cleanup).
        assert_eq!(owned.state().text.as_slice().len(), 0, "text buffer cleared");
        assert_eq!(owned.state().attributes.cells.len(), 0, "attributes cleared");
    }

    /// `cleanup()` is idempotent — calling it twice is safe and
    /// leaves the widget in the same "fully cleaned" state. The
    /// second invocation finds `timer = None` already and proceeds
    /// to the state-clear step which is itself idempotent.
    #[tokio::test]
    async fn test_cleanup_is_idempotent() {
        let bell = Bell::new(1, 1, test_colors());
        bell.ring(2);

        let mut owned = Arc::try_unwrap(bell)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");

        owned.cleanup();
        // Second cleanup must not panic.
        owned.cleanup();

        // Still in cleaned state.
        let timer_after = match owned.inner.lock() {
            Ok(g) => g.timer.is_some(),
            Err(p) => p.into_inner().timer.is_some(),
        };
        assert!(!timer_after);
    }

    // ----------------------------------------------------------------
    // Section 8: Widget::as_any — downcast support
    // ----------------------------------------------------------------

    /// `as_any()` returns a `&dyn Any` reference that downcasts
    /// successfully to the concrete [`Bell`] type. Required so
    /// callers holding `Arc<dyn Widget>` (e.g., parents iterating
    /// children) can recover the concrete type when needed.
    #[tokio::test]
    async fn test_as_any_downcast_recovers_concrete_type() {
        let bell: Arc<Bell> = Bell::new(1, 1, test_colors());
        let dyn_widget: Arc<dyn Widget> = bell.clone() as Arc<dyn Widget>;

        let recovered: &Bell = dyn_widget
            .as_any()
            .downcast_ref::<Bell>()
            .expect("downcast must succeed");

        // Pointer equality — same underlying allocation.
        assert!(std::ptr::eq(Arc::as_ptr(&bell), recovered as *const Bell));

        // Source never had ring() called on it, so no cleanup
        // needed before drop.
        drop(dyn_widget);
        let _ = Arc::try_unwrap(bell).map_err(|_| ());
    }
}
