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
// tui_newsticker: a "ticker tape" style component, nothing terribly fancy.
// Ported from tui_newsticker.inc (316 lines of FASM assembly).
//
// Rust translation © 2026, licensed under GPL-3.0-or-later. Derived from
// the HeavyThing assembly library (© 2015–2018 2 Ton Digital, Jeff
// Marrison <info@2ton.com.au>).

//! Newsticker widget — a height-1 [`TuiBackground`] descendant that
//! scrolls a text string right-to-left across its cells at a 200 ms
//! cadence (5 fps).
//!
//! ## FASM Parallel: `tui_newsticker.inc` (316 lines)
//!
//! Per the FASM `tui_newsticker$vtable` declaration
//! (`tui_newsticker.inc` lines 28–35), the newsticker overrides
//! exactly **four** of the 37 vmethods:
//!
//! - [`Widget::cleanup`]      (slot 0) → `tui_newsticker$cleanup`
//! - [`Widget::clone_widget`] (slot 1) → `tui_newsticker$clone`
//! - [`Widget::draw`]         (slot 2) → `tui_newsticker$draw`
//! - [`Widget::timer`]        (slot 6) → `tui_newsticker$timer`
//!
//! The other 33 methods inherit the [`Widget`] trait defaults — this
//! matches the FASM vtable's pass-through `tui_object$*` entries for
//! every non-overridden slot.
//!
//! ## Scroll state machine
//!
//! The widget keeps a three-state `scrollpos: i32`:
//!
//! - `-1` — initial / just-reset sentinel. The next [`Widget::draw`]
//!   sets `scrollpos = width - 1` to start the text re-entering from
//!   the right edge.
//! - `width-1 → 0` — scrolling phase. Each timer tick decrements
//!   `scrollpos` by one until it reaches 0.
//! - `0` — at the left edge. Subsequent timer ticks then advance
//!   `textpos` (the read-cursor into the source text) so the leading
//!   characters scroll off and the trailing characters appear at the
//!   right edge of the widget.
//!
//! When `textpos` reaches the end of the source string, [`Widget::draw`]
//! resets both fields back to `scrollpos = -1, textpos = 0` so the
//! next cycle re-enters from the right.
//!
//! ## Tick cadence
//!
//! [`TICK_MS`] holds the FASM-hardcoded 200 ms period
//! (`tui_newsticker_speed = 200`, line 46). The Rust translation drives
//! the cadence with [`tokio::time::interval`] capturing a [`Weak<Self>`]
//! back-reference — the spawned task exits cleanly when the last
//! [`Arc`] reference is dropped, exactly matching the FASM
//! `epoll$timer_clear` semantics in `cleanup`.
//!
//! ## Owned text
//!
//! The constructor and [`set_text`](TuiNewsticker::set_text) deep-copy
//! the input string (FASM `string$copy`); this guarantees the widget
//! retains a valid backing store even after the caller drops their
//! source string. [`append_text`](TuiNewsticker::append_text) preserves
//! the existing scroll position so a live news feed can keep growing
//! the text without visual glitches.
//!
//! Translation of FASM `tui_newsticker.inc`. Per AAP §0.5.1.5 this is a
//! 1-to-1 module-to-module port; the FASM vtable becomes a Rust trait
//! impl, the AVL-tree-backed epoll timer becomes a tokio interval task,
//! and the `string$copy`/`string$concat` calls become Rust `String`
//! ops (which deep-copy by default).

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

/// Newsticker tick rate in milliseconds.
///
/// FASM parallel: `tui_newsticker_speed = 200` (`tui_newsticker.inc`
/// line 46). 200 ms gives 5 frames-per-second scrolling — fast enough
/// to look smooth on mid-90s era VT100 hardware (which the FASM
/// library originally targeted) but slow enough to remain readable
/// across the full width of a typical 80-column terminal.
///
/// Modifying this constant at the source-code level is allowed — the
/// upper limit before perception degrades is roughly 50 ms (20 fps);
/// the lower limit before scrolling becomes unwatchable is roughly
/// 1000 ms (1 fps). Tests guard the FASM-equivalent value against
/// accidental refactors.
const TICK_MS: u64 = 200;

/// Sentinel value stored in [`NewstickerInner::scrollpos`] to indicate
/// "the widget is in its just-reset state; the next [`Widget::draw`]
/// must set scrollpos to (width - 1) so the text re-enters from the
/// right edge".
///
/// FASM parallel: the literal `-1` (as a 32-bit signed dword) at
/// `tui_newsticker.inc` lines 81, 119, 147, 225, 287. The FASM uses
/// the same sentinel; we name it for clarity.
const SCROLLPOS_RESET_SENTINEL: i32 = -1;

// ============================================================================
// NewstickerInner — interior-mutable extra-state struct.
// ============================================================================

/// Mutable, interior-state fields of [`TuiNewsticker`] guarded by
/// [`TuiNewsticker::inner`]'s [`Mutex`].
///
/// FASM offsets (relative to `tui_background_size`, see
/// `tui_newsticker.inc` lines 37–42):
///
/// | FASM offset                       | FASM type | Rust field   |
/// |-----------------------------------|-----------|--------------|
/// | `tui_newsticker_filltext_ofs   +0`| `dq`      | `filltext`   |
/// | `tui_newsticker_textpos_ofs    +8`| `dd`      | `textpos`    |
/// | `tui_newsticker_scrollpos_ofs +12`| `dd`      | `scrollpos`  |
/// | `tui_newsticker_timerptr_ofs  +16`| `dq`      | `timer`      |
///
/// `tui_newsticker_size = tui_background_size + 24` (FASM line 42).
/// The Rust translation does not preserve the literal byte layout —
/// the trait dispatch table replaces the `dq vtable` field in the
/// FASM struct, and [`Mutex<NewstickerInner>`] supplies interior
/// mutability for the four "extra" fields that the FASM stored in
/// the trailing 24 bytes.
struct NewstickerInner {
    /// Owned copy of the ticker text content.
    ///
    /// FASM offset: `tui_newsticker_filltext_ofs = tui_background_size
    /// + 0` (line 37). The FASM stores a pointer to a heap-allocated
    /// FASM string (a `dq` length prefix + UTF-32 codepoint payload).
    /// In Rust we use the standard library [`String`] which is UTF-8
    /// encoded. The character iteration in [`Widget::draw`] uses
    /// [`str::chars`] which yields decoded codepoints — semantically
    /// equivalent to the FASM-era UTF-32 cell-by-cell traversal at
    /// `tui_newsticker$draw` lines 203–207.
    ///
    /// **Why owned?** The constructor MUST deep-copy the caller's
    /// `&str` so the caller is free to drop their string immediately
    /// after construction. FASM `string$copy` at line 60 / 97 has
    /// the same semantic.
    filltext: String,

    /// Read-cursor index into [`Self::filltext`] (in characters, NOT
    /// bytes — see character-vs-byte note below).
    ///
    /// FASM offset: `tui_newsticker_textpos_ofs = tui_background_size
    /// + 8` (line 38). Stored as `u32` to match the FASM `dd` width.
    ///
    /// **Character semantics**: `textpos` counts characters consumed
    /// from the source text, not bytes. The FASM ran on UTF-32 storage
    /// so codepoint-index and array-index were equivalent; for Rust's
    /// UTF-8 `String` we use [`String::chars`] iteration which yields
    /// one [`char`] per codepoint, matching the FASM cell-by-cell
    /// scrolling unit.
    textpos: u32,

    /// Scroll offset within the widget's display row.
    ///
    /// FASM offset: `tui_newsticker_scrollpos_ofs = tui_background_size
    /// + 12` (line 39). Stored as `i32` to preserve the FASM signed
    /// `dd` semantics (the FASM uses `-1` as a sentinel value for
    ///   "just reset").
    ///
    /// State diagram (FASM `tui_newsticker$timer` lines 248–270):
    ///
    /// ```text
    ///   scrollpos == -1   — reset; next draw sets scrollpos = width-1
    ///   scrollpos == 0    — at left edge; next tick advances textpos
    ///   scrollpos >  0    — scrolling; next tick decrements scrollpos
    ///   scrollpos == width-1  — text just re-entered from right edge
    /// ```
    scrollpos: i32,

    /// Handle to the spawned tokio task driving the 200 ms tick loop.
    ///
    /// FASM offset: `tui_newsticker_timerptr_ofs = tui_background_size
    /// + 16` (line 40). The FASM stored a raw pointer to the AVL-node
    /// entry inside the global epoll timer tree; the Rust port stores
    /// a [`JoinHandle`] which provides equivalent
    /// `cancel`-on-drop / `abort`-on-cleanup semantics via
    /// [`JoinHandle::abort`].
    ///
    /// `None` when the widget has been cleaned up via
    /// [`Widget::cleanup`] (FASM `tui_newsticker$cleanup` calls
    /// `epoll$timer_clear` at line 162). `Some(handle)` while the
    /// widget is alive and animating.
    timer: Option<JoinHandle<()>>,
}

// ============================================================================
// TuiNewsticker — public widget type.
// ============================================================================

/// Scrolling ticker-tape widget — one cell tall, configurable width,
/// with a configurable text string scrolling right-to-left across the
/// row at a 200 ms cadence.
///
/// FASM parallel: `tui_newsticker` (`tui_newsticker.inc`, 316 lines).
///
/// ## Layout
///
/// The widget's height is fixed at 1 cell. Width is configurable per
/// constructor variant:
///
/// - [`new_i`](Self::new_i) — explicit integer cell width
/// - [`new_d`](Self::new_d) — percentage of parent width
///
/// ## Construction
///
/// Both constructors return `Result<Arc<Self>, TuiError>` —
/// [`Arc<Self>`] for shared ownership across the widget tree and the
/// spawned tokio timer task; [`Result`] for parity with the parent
/// [`TuiBackground`] constructor signatures.
///
/// ## Thread safety
///
/// `TuiNewsticker` is `Send + Sync` via the bound on the parent
/// [`Widget`] trait. The [`WidgetState`] sub-fields follow the
/// established [`crate::tui::widgets::background::TuiBackground`]
/// pattern (held inline through the embedded
/// [`background`](Self::background) field); concurrent draw access is
/// serialised externally via [`crate::tui::lock`]. The
/// [`Mutex<NewstickerInner>`] field guards the interior-mutable
/// scroll state and the timer handle that the spawned tokio task
/// needs to mutate via `&self`.
///
/// ## Vmethod overrides (vs. [`Widget`] trait defaults)
///
/// | FASM vtable slot | [`Widget`] trait method  | Override?         |
/// |------------------|--------------------------|-------------------|
/// | 0 cleanup        | [`Widget::cleanup`]      | YES               |
/// | 1 clone          | [`Widget::clone_widget`] | YES               |
/// | 2 draw           | [`Widget::draw`]         | YES               |
/// | 6 timer          | [`Widget::timer`]        | YES               |
/// | All other 33     | various                  | inherit defaults  |
pub struct TuiNewsticker {
    /// Embedded [`TuiBackground`] — supplies dimensions
    /// (`width`, `height = 1`), the fill character (`b' '`), the
    /// background color pair, and the inherited [`WidgetState`]
    /// accessed via [`Widget::state`] / [`Widget::state_mut`].
    ///
    /// We hold this by value (not `Arc`-wrapped) so that
    /// [`TuiNewsticker`] owns and can mutate the underlying state
    /// directly during [`Widget::draw`]. The `Arc` returned by
    /// [`TuiBackground::new_ii`] / [`TuiBackground::new_di`] is
    /// unwrapped via [`Arc::try_unwrap`] inside our constructors —
    /// this always succeeds because the factories return a fresh
    /// `Arc` with strong-count 1.
    background: TuiBackground,

    /// Interior-mutable extra-state — `filltext`, `textpos`,
    /// `scrollpos`, and the running timer's [`JoinHandle`]. Guarded
    /// by [`std::sync::Mutex`] (NOT [`tokio::sync::Mutex`]) because
    /// the critical sections are short synchronous memory updates
    /// with no `await` points, matching the established widget-
    /// mutation pattern in
    /// [`crate::tui::widgets::spinner`] and
    /// [`crate::tui::widgets::progressbar`].
    inner: Mutex<NewstickerInner>,
}

/// Friendly type alias matching the abridged Rust naming convention.
///
/// `Newsticker` and [`TuiNewsticker`] are the same concrete type; the
/// alias exists so callers preferring the `Tui`-stripped form can
/// import this directly without an extra wrapper layer.
pub type Newsticker = TuiNewsticker;

// ============================================================================
// Constructors — `tui_newsticker$new_i` / `tui_newsticker$new_d` equivalents
// ============================================================================

impl TuiNewsticker {
    /// Default fill character — ASCII space (`0x20`).
    ///
    /// Both FASM constructors pass `' '` to `tui_background$init_ii`
    /// at line 70 / `tui_background$init_di` at line 108 so that
    /// [`TuiBackground::nvfill`] paints the row with spaces before
    /// [`Widget::draw`] overlays the scrolled text characters on top.
    const FILLCHAR_SPACE: u32 = b' ' as u32;

    /// FASM `tui_newsticker$new_i(edi=width, rsi=filltext, edx=colors)`.
    ///
    /// Construct a newsticker with explicit integer cell width.
    ///
    /// # Arguments
    ///
    /// - `width` — Number of columns the ticker occupies. Treated as
    ///   `i32` to match FASM signed-dword semantics (negative widths
    ///   degenerate to a no-op widget — `Widget::draw` bails when
    ///   `width <= 0`, mirroring FASM `.nothingtodo` at line 175).
    /// - `filltext` — Source text to scroll. Deep-copied into a
    ///   [`String`] (FASM `string$copy` at line 60); the caller may
    ///   drop the source `&str` immediately after the call returns.
    /// - `colors` — Foreground/background color pair applied to every
    ///   cell of the row (FASM `edx` parameter forwarded to
    ///   `tui_background$init_ii` at line 73).
    ///
    /// # Returns
    ///
    /// An owning [`Arc<Self>`] with the timer task already spawned.
    /// The returned `Arc` has strong-count 1; cloning is the usual
    /// way to register the widget under a parent.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when the parent
    /// [`TuiBackground::new_ii`] fails (typically a `width * height`
    /// arithmetic overflow when computing buffer sizes — impossible
    /// for any realistic terminal width).
    ///
    /// # FASM parallel
    ///
    /// `tui_newsticker$new_i` (`tui_newsticker.inc` lines 51–83):
    ///
    /// ```text
    ///   sub  rsp, 24                      ; spill area for args
    ///   call string$copy                  ; deep-copy filltext
    ///   call heap$alloc_clear             ; allocate zero-filled struct
    ///   set vtable to tui_newsticker$vtable
    ///   set filltext_ofs = copy result
    ///   call tui_background$init_ii(self, width, 1, ' ', colors)
    ///   call epoll$timer_new(200, self)   ; fire 200 ms timer
    ///   set timerptr_ofs = timer handle
    ///   set scrollpos_ofs = -1            ; reset sentinel
    /// ```
    pub fn new_i(width: i32, filltext: &str, colors: ColorPair) -> Result<Arc<Self>, TuiError> {
        let bg_arc = TuiBackground::new_ii(width, 1, Self::FILLCHAR_SPACE, colors)?;
        Self::wrap_background(bg_arc, filltext)
    }

    /// FASM `tui_newsticker$new_d(xmm0=width_percent, rdi=filltext, esi=colors)`.
    ///
    /// Construct a newsticker with percentage-based width.
    ///
    /// # Arguments
    ///
    /// - `width_percent` — Fraction of the parent's content area
    ///   width (e.g. `0.5` = 50%). Forwarded to the parent
    ///   [`TuiBackground::new_di`] which stores it for the layout
    ///   pass to resolve. The FASM accepted this as an `xmm0` SSE
    ///   double-precision register at line 88.
    /// - `filltext` — Source text to scroll. Deep-copied (see
    ///   [`new_i`](Self::new_i)).
    /// - `colors` — Foreground/background color pair (FASM `esi`
    ///   parameter at line 88).
    ///
    /// # Returns
    ///
    /// See [`new_i`](Self::new_i).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when the parent
    /// [`TuiBackground::new_di`] fails (in practice infallible for
    /// percentage-based dimensions, since buffer allocation defers
    /// until layout resolves the absolute width).
    ///
    /// # FASM parallel
    ///
    /// `tui_newsticker$new_d` (`tui_newsticker.inc` lines 87–121):
    ///
    /// ```text
    ///   movq rax, xmm0                    ; spill width_percent
    ///   call string$copy                  ; deep-copy filltext
    ///   call heap$alloc_clear             ; allocate zero-filled struct
    ///   set vtable to tui_newsticker$vtable
    ///   set filltext_ofs = copy result
    ///   call tui_background$init_di(self, width_percent, 1, ' ', colors)
    ///   call epoll$timer_new(200, self)
    ///   set timerptr_ofs = timer handle
    ///   set scrollpos_ofs = -1
    /// ```
    pub fn new_d(width_percent: f64, filltext: &str, colors: ColorPair) -> Result<Arc<Self>, TuiError> {
        let bg_arc = TuiBackground::new_di(width_percent, 1, Self::FILLCHAR_SPACE, colors)?;
        Self::wrap_background(bg_arc, filltext)
    }

    /// Internal constructor helper — extract the freshly-built
    /// [`TuiBackground`] from its `Arc` shell, deep-copy the filltext
    /// into the [`NewstickerInner`], spawn the 200 ms timer task, and
    /// re-wrap the composite in a new `Arc<Self>`.
    ///
    /// # Algorithm
    ///
    /// 1. [`Arc::try_unwrap`] the freshly-built [`TuiBackground`] —
    ///    this always succeeds because each `TuiBackground::new_*`
    ///    factory returns an `Arc` with strong-count exactly 1 (no
    ///    clones have escaped the call stack yet). The `Err` arm
    ///    returns a [`TuiError::Render`] for completeness even though
    ///    it is statically unreachable on this code path.
    /// 2. Build the [`NewstickerInner`] with `filltext = filltext.to_string()`
    ///    (deep copy), `textpos = 0`, `scrollpos = SCROLLPOS_RESET_SENTINEL`,
    ///    `timer = None`. The timer slot is filled in below.
    /// 3. Wrap the composite struct in [`Arc::new`] so we can hand
    ///    the spawned tokio task a [`Weak<Self>`] back-reference.
    /// 4. Spawn the tokio interval task — the task captures the
    ///    [`Weak<Self>`] and on each tick attempts to upgrade it; on
    ///    success it calls [`TuiNewsticker::tick`] which advances
    ///    the scroll state under the inner [`Mutex`]. On failure
    ///    (last `Arc` reference dropped) the task exits cleanly.
    /// 5. Re-acquire the inner [`Mutex`] and install the
    ///    [`JoinHandle`] into the `timer` slot.
    ///
    /// # FASM parallel
    ///
    /// This helper combines the post-`init_*` tail of both FASM
    /// constructors (`tui_newsticker.inc` lines 74–81 for `$new_i`
    /// and lines 112–119 for `$new_d`):
    ///
    /// ```text
    ///   call epoll$timer_new(200, self)   ; spawn periodic timer
    ///   set timerptr_ofs = timer handle
    ///   set scrollpos_ofs = -1            ; mark "needs reset on draw"
    /// ```
    fn wrap_background(bg_arc: Arc<TuiBackground>, filltext: &str) -> Result<Arc<Self>, TuiError> {
        let background = Arc::try_unwrap(bg_arc).map_err(|_| {
            TuiError::Render(std::io::Error::other(
                "TuiNewsticker: TuiBackground Arc had unexpected outstanding references",
            ))
        })?;

        let inner = NewstickerInner {
            // FASM string$copy at line 60 / 97 — deep-copy the source.
            // Rust `.to_string()` on a `&str` performs the same byte-
            // level deep-copy into a freshly heap-allocated `String`.
            filltext: filltext.to_string(),
            // Initial textpos = 0 (FASM heap$alloc_clear zero-fills
            // the entire newsticker_size allocation, lines 63 / 100).
            textpos: 0,
            // FASM `mov dword [rax+tui_newsticker_scrollpos_ofs], -1`
            // at lines 81 / 119 — sentinel for "next draw must set
            // scrollpos to width-1".
            scrollpos: SCROLLPOS_RESET_SENTINEL,
            // Filled in below.
            timer: None,
        };

        let arc: Arc<Self> = Arc::new(Self {
            background,
            inner: Mutex::new(inner),
        });

        // Spawn the periodic ticker — replaces FASM
        // `epoll$timer_new(tui_newsticker_speed, self)` at lines
        // 75–77 / 113–115. The Weak<Self> back-reference lets the
        // task exit cleanly when the last Arc reference is dropped
        // (matching FASM `epoll$timer_clear` semantics in cleanup).
        let weak: Weak<Self> = Arc::downgrade(&arc);
        let handle: JoinHandle<()> = tokio::spawn(async move {
            // tokio::time::interval starts firing immediately; the
            // first tick().await returns instantly. We let that first
            // tick advance the scroll state from the SCROLLPOS_RESET_SENTINEL
            // initial value so the first visible frame shows text at
            // scrollpos = width - 1 (i.e. starting to enter from the
            // right edge). Subsequent ticks fire at TICK_MS intervals.
            let mut ticker = interval(Duration::from_millis(TICK_MS));
            loop {
                ticker.tick().await;
                match weak.upgrade() {
                    Some(strong) => strong.tick(),
                    // Last strong reference dropped — exit cleanly.
                    None => break,
                }
            }
        });

        // Install the JoinHandle into the inner Mutex. The match-on-
        // Result fallback covers the theoretical poisoned case; we
        // treat it as recoverable because no invariant can have been
        // violated yet (Mutex was just created; no awaits happened
        // between Arc::new and this lock acquisition).
        match arc.inner.lock() {
            Ok(mut guard) => {
                guard.timer = Some(handle);
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.timer = Some(handle);
            }
        }

        Ok(arc)
    }

    /// Advance the scroll state by one tick under the inner [`Mutex`].
    ///
    /// Called by the spawned tokio timer task on each tick. The
    /// surrounding task holds a [`Weak<Self>`] which it upgrades to
    /// an [`Arc<Self>`] before invoking this method — therefore
    /// `tick` takes `&self` (not `&mut self`) and uses the inner
    /// [`Mutex`] for interior mutability.
    ///
    /// **Important**: this method does NOT touch the text/attribute
    /// buffers in [`WidgetState`]. The scroll-rendering happens when
    /// the framework's render pass next calls [`Widget::draw`]
    /// (which has unique `&mut self` access). This separation
    /// matches the [`crate::tui::widgets::spinner::Spinner::tick`]
    /// pattern and avoids needing interior mutability on the entire
    /// [`WidgetState`] (which would conflict with [`Widget::state`]'s
    /// `&WidgetState` return type).
    ///
    /// FASM parallel: `tui_newsticker$timer`
    /// (`tui_newsticker.inc` lines 248–270):
    ///
    /// ```text
    ///   if scrollpos > 0:  scrollpos -= 1
    ///   if scrollpos == 0: textpos += 1
    ///   if scrollpos < 0:  no-op (let next draw handle the reset)
    /// ```
    ///
    /// The FASM unconditionally calls `vdraw` after each branch; in
    /// the Rust port the spawned task does NOT trigger an immediate
    /// re-draw because the framework's render pipeline is responsible
    /// for re-drawing after timer events. This avoids re-entering
    /// [`Widget::draw`] from inside the spawned task (which would
    /// require obtaining a `&mut self` borrow from the `Arc<Self>`,
    /// which is not always achievable when the arc is shared with
    /// the widget tree).
    fn tick(&self) {
        match self.inner.lock() {
            Ok(mut guard) => {
                tick_scroll_state(&mut guard);
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                tick_scroll_state(&mut guard);
            }
        }
    }
}

// ============================================================================
// Non-virtual public API — set_text / append_text
// ============================================================================

impl TuiNewsticker {
    /// Replace the ticker text and reset the scroll position.
    ///
    /// FASM parallel: `tui_newsticker$nvsettext`
    /// (`tui_newsticker.inc` lines 274–293):
    ///
    /// ```text
    ///   heap$free(self.filltext)         ; release old buffer
    ///   self.filltext = string$copy(new) ; deep-copy new string
    ///   self.scrollpos = -1              ; reset to "start from right"
    ///   self.textpos = 0                 ; rewind read cursor
    ///   call vdraw                       ; immediate redraw
    /// ```
    ///
    /// The Rust translation uses standard [`String`] assignment for
    /// the deep-copy + free sequence (the [`Drop`] impl on the old
    /// `String` releases its backing allocation; `to_string()` on the
    /// new `&str` allocates a fresh buffer).
    ///
    /// Unlike FASM's `vdraw` call at line 291, the Rust port does
    /// NOT invoke an immediate redraw from within `set_text` — the
    /// framework's render pipeline owns redraw scheduling. Callers
    /// that need an immediate visual update should follow this with
    /// a render-pass invocation through the framework's lock layer.
    ///
    /// # Argument
    ///
    /// - `new_text` — Replacement source text. Deep-copied into the
    ///   widget; the caller may drop their `&str` immediately after.
    pub fn set_text(&self, new_text: &str) {
        match self.inner.lock() {
            Ok(mut guard) => {
                set_text_in_inner(&mut guard, new_text);
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                set_text_in_inner(&mut guard, new_text);
            }
        }
    }

    /// Append text to the ticker without resetting the scroll position.
    ///
    /// FASM parallel: `tui_newsticker$nvappendtext`
    /// (`tui_newsticker.inc` lines 297–313):
    ///
    /// ```text
    ///   new = string$concat(self.filltext, appended)
    ///   heap$free(self.filltext)
    ///   self.filltext = new
    ///   call vdraw
    /// ```
    ///
    /// Note that the FASM version, like this Rust translation, does
    /// **not** reset `scrollpos` or `textpos` — the existing scroll
    /// continues mid-stream while the source text grows. This is the
    /// canonical pattern for live news feeds: new headlines arrive
    /// at the end of the source string and naturally appear at the
    /// right edge of the widget some time later as the existing
    /// content scrolls past.
    ///
    /// **Caveat**: if `textpos` previously equalled the old
    /// filltext length (i.e. the ticker had just finished scrolling
    /// the entire string and the next draw would have reset state),
    /// appending now defers the reset because the new
    /// `filltext.len()` exceeds the now-stale `textpos`. The next
    /// [`Widget::draw`] will continue scrolling from the appended
    /// portion, which is the FASM-original behaviour and what live
    /// feed callers want.
    ///
    /// # Argument
    ///
    /// - `appended` — Text to append. The widget's `filltext` field
    ///   becomes `format!("{}{}", old_filltext, appended)` — the
    ///   original text followed by the new text without a separator.
    pub fn append_text(&self, appended: &str) {
        match self.inner.lock() {
            Ok(mut guard) => {
                append_text_in_inner(&mut guard, appended);
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                append_text_in_inner(&mut guard, appended);
            }
        }
    }

    /// Read the current scrollpos under lock — used internally and by
    /// tests to assert FASM-equivalent state-machine behaviour.
    #[cfg(test)]
    fn current_scrollpos(&self) -> i32 {
        match self.inner.lock() {
            Ok(g) => g.scrollpos,
            Err(p) => p.into_inner().scrollpos,
        }
    }

    /// Read the current textpos under lock — used internally and by
    /// tests.
    #[cfg(test)]
    fn current_textpos(&self) -> u32 {
        match self.inner.lock() {
            Ok(g) => g.textpos,
            Err(p) => p.into_inner().textpos,
        }
    }

    /// Read a clone of the current filltext under lock — used by
    /// tests for content verification.
    #[cfg(test)]
    fn current_filltext(&self) -> String {
        match self.inner.lock() {
            Ok(g) => g.filltext.clone(),
            Err(p) => p.into_inner().filltext.clone(),
        }
    }
}

// ============================================================================
// Free helpers — pure functions operating on a locked NewstickerInner
// ============================================================================

/// Advance the scroll state by one tick.
///
/// Pulled out into a free function so [`TuiNewsticker::tick`] and
/// [`Widget::timer`] can share the implementation without duplicating
/// the lock-acquisition match-arm pair.
///
/// FASM parallel: the body of `tui_newsticker$timer`
/// (`tui_newsticker.inc` lines 248–270), excluding the unconditional
/// `call vdraw` tail (which the Rust port handles externally — see
/// [`TuiNewsticker::tick`] doc-comment).
fn tick_scroll_state(inner: &mut NewstickerInner) {
    if inner.scrollpos > 0 {
        // FASM `.decscrollpos` branch (line 258):
        //   sub dword [rdi+tui_newsticker_scrollpos_ofs], 1
        inner.scrollpos -= 1;
    } else if inner.scrollpos == 0 {
        // FASM `.inctextpos` branch (line 265):
        //   add dword [rdi+tui_newsticker_textpos_ofs], 1
        // We use saturating_add to defend against the (effectively
        // impossible) overflow case where textpos reaches u32::MAX
        // — in practice textpos is bounded by filltext.chars().count()
        // which is bounded by the source string length, which never
        // approaches u32::MAX in any realistic ticker use-case.
        inner.textpos = inner.textpos.saturating_add(1);
    }
    // scrollpos < 0 (the SCROLLPOS_RESET_SENTINEL case): no-op. The
    // next Widget::draw observes the sentinel and sets scrollpos to
    // (width - 1) so the text re-enters from the right edge.
}

/// Replace the filltext and reset scroll state.
///
/// Pulled out into a free function so both [`TuiNewsticker::set_text`]
/// and the [`Widget::cleanup`] / [`Widget::clone_widget`] paths could
/// reuse it if needed (currently only `set_text` calls it, but the
/// extraction keeps the lock-acquisition pattern uniform).
fn set_text_in_inner(inner: &mut NewstickerInner, new_text: &str) {
    // FASM `heap$free(old) + string$copy(new)` at lines 281–286.
    // In Rust, replacing the String field is a deep-copy + drop in
    // one assignment.
    inner.filltext = new_text.to_string();
    // FASM `mov dword [rbx+tui_newsticker_scrollpos_ofs], -1` at
    // line 287 — sentinel for "next draw starts from right edge".
    inner.scrollpos = SCROLLPOS_RESET_SENTINEL;
    // FASM `mov dword [rbx+tui_newsticker_textpos_ofs], 0` at line
    // 288 — rewind read cursor.
    inner.textpos = 0;
}

/// Append to the filltext WITHOUT resetting scroll state.
///
/// FASM parallel: the body of `tui_newsticker$nvappendtext`
/// (`tui_newsticker.inc` lines 300–311), excluding the unconditional
/// `call vdraw` tail.
fn append_text_in_inner(inner: &mut NewstickerInner, appended: &str) {
    // FASM `string$concat(old, new)` at line 305 produces a fresh
    // buffer holding `old + new`. In Rust we use String::push_str
    // which extends the existing allocation in place when capacity
    // permits, or grows the allocation if needed. The result is
    // semantically identical: filltext now holds the concatenation.
    inner.filltext.push_str(appended);
    // Note: scrollpos and textpos are intentionally NOT reset —
    // FASM nvappendtext likewise leaves them untouched at lines
    // 300–311. This is the live-feed pattern: new content appears
    // at the right edge as the existing content scrolls past.
}

/// Deep-clone a [`WidgetState`] including children (via
/// [`Widget::clone_widget`]), preserving the FASM
/// `tui_object$init_copy` semantics that
/// [`crate::tui::widgets::background::TuiBackground`] uses internally.
///
/// Replicated locally because the equivalent helper in
/// `widgets::background` is private to that module — this duplicates
/// ~30 lines of straight-line state cloning logic but keeps
/// `newsticker.rs` self-contained without modifying `background.rs`.
/// The same pattern is used by
/// [`crate::tui::widgets::progressbar`].
///
/// # Algorithm
///
/// The logic mirrors FASM `tui_object$init_copy` /
/// `tui_background$init_copy` (`tui_object.inc` lines 235–333,
/// `tui_background.inc` lines 56–75):
///
/// 1. All scalar fields are bitwise-copied (`bounds`, `width`,
///    `width_percent`, `height`, `height_percent`, `visible`,
///    `include_in_layout`, `absolute_x`, `absolute_y`, `layout`,
///    `horiz_align`, `vert_align`, `bastard_glue`, `drop_shadow`,
///    `scroll`).
/// 2. `display_name` is deep-copied (FASM `string$copy`; Rust
///    `String::clone`).
/// 3. `text` and `attributes` are deep-cloned (the underlying
///    `Vec<u8>` / `Vec<u32>` are duplicated by [`Buffer`] /
///    [`crate::tui::object::Attributes`]'s [`Clone`] impl).
/// 4. `children` is recursively deep-cloned via each child's own
///    [`Widget::clone_widget`] vmethod.
/// 5. `bastards` is intentionally **not** cloned — it is reset to
///    [`WidgetState::new`]'s empty list, matching FASM
///    `tui_object.inc` line 274 which explicitly creates a new empty
///    bastards list during `init_copy`.
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
// Widget trait implementation — overrides cleanup, clone_widget, draw, timer.
// ============================================================================

impl Widget for TuiNewsticker {
    /// Required base accessor — returns a shared reference to the
    /// inherited [`WidgetState`] via the embedded [`TuiBackground`].
    fn state(&self) -> &WidgetState {
        self.background.state()
    }

    /// Required base accessor — returns a mutable reference to the
    /// inherited [`WidgetState`] via the embedded [`TuiBackground`].
    fn state_mut(&mut self) -> &mut WidgetState {
        self.background.state_mut()
    }

    /// Required downcasting accessor — returns `self` as a `&dyn Any`
    /// so callers holding an `Arc<dyn Widget>` can recover the concrete
    /// `TuiNewsticker` type via [`Any::downcast_ref`].
    fn as_any(&self) -> &dyn Any {
        self
    }

    // ----------------- Override 1: cleanup (vtable slot 0) -----------------

    /// Override — vtable slot 0 (`tui_vcleanup`).
    ///
    /// FASM parallel: `tui_newsticker$cleanup`
    /// (`tui_newsticker.inc` lines 152–166):
    ///
    /// ```text
    ///   heap$free(self.filltext)        ; release filltext buffer
    ///   epoll$timer_clear(self.timer)   ; cancel periodic ticker
    ///   tui_object$cleanup(self)        ; clear children/bastards/text/...
    /// ```
    ///
    /// 1. Cancel the spawned tokio timer task via
    ///    [`JoinHandle::abort`] (replaces FASM
    ///    `epoll$timer_clear` at line 162). After this call any
    ///    subsequent [`Weak::upgrade`] in the spawned task body
    ///    returns `None` (because `cleanup` is called after the
    ///    last strong reference is about to be dropped) so the task
    ///    exits on its next tick — but `abort` short-circuits the
    ///    wait by cancelling the task immediately.
    /// 2. Clear the [`String`] held in `filltext` so the
    ///    backing allocation is released (FASM `heap$free` at line
    ///    160; Rust replaces the `String` with an empty one which
    ///    drops the old allocation immediately).
    /// 3. Inline the trait-default cleanup body — clear `state.children`,
    ///    `state.bastards`, `state.text`, `state.attributes`, and
    ///    `state.display_name`. This matches the FASM `tui_object$cleanup`
    ///    body at line 164.
    ///
    /// **Why inline rather than call [`crate::tui::object::cleanup_widget`]?**
    /// The free helper [`crate::tui::object::cleanup_widget`]
    /// dispatches polymorphically through `self.cleanup()` at its
    /// tail; calling it from inside an override produces unbounded
    /// recursion. The exemplar sibling implementations in
    /// [`crate::tui::widgets::spinner`] and
    /// [`crate::tui::widgets::progressbar`] use the same inline-clear
    /// pattern; [`crate::tui::object::cleanup_widget`] is the
    /// framework's entry point invoked **from outside** the widget
    /// (when a parent destroys this child) — not from inside an
    /// override.
    fn cleanup(&mut self) {
        // ---- Step 1: cancel the timer task and release filltext.
        //
        // We pull both fields out of the Mutex to avoid holding the
        // lock during abort (which is non-blocking but still good
        // hygiene), and to leave timer = None / filltext = "" so a
        // subsequent cleanup() invocation (defensive idempotency)
        // is a no-op.
        let handle: Option<JoinHandle<()>> = match self.inner.lock() {
            Ok(mut guard) => {
                // FASM heap$free(filltext) at line 160 — release the
                // string buffer. Rust: replacing with an empty
                // String drops the old allocation immediately.
                guard.filltext.clear();
                guard.filltext.shrink_to_fit();
                guard.timer.take()
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.filltext.clear();
                guard.filltext.shrink_to_fit();
                guard.timer.take()
            }
        };
        if let Some(h) = handle {
            // FASM epoll$timer_clear at line 162 — cancel the timer.
            h.abort();
        }

        // ---- Step 2: inline the trait-default cleanup body.
        //
        // Mirrors the [`Widget::cleanup`] default impl in
        // `crates/heavything/src/tui/object.rs`. We do NOT call
        // [`cleanup_widget`] here because that helper polymorphically
        // dispatches `self.cleanup()` at its tail — which would
        // re-enter this method ad infinitum. The spinner / progressbar
        // widgets use the same inline pattern.
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
    /// FASM parallel: `tui_newsticker$clone`
    /// (`tui_newsticker.inc` lines 125–148):
    ///
    /// ```text
    ///   heap$alloc_clear(tui_newsticker_size)    ; fresh allocation
    ///   tui_background$init_copy(new, src)       ; deep-copy base state
    ///   new.filltext = string$copy(src.filltext) ; deep-copy text
    ///   new.timer = epoll$timer_new(200, new)    ; fresh timer
    ///   new.scrollpos = -1                       ; reset to right edge
    ///   ; (textpos defaults to 0 from heap$alloc_clear)
    /// ```
    ///
    /// The Rust translation:
    ///
    /// 1. Deep-clone the embedded [`TuiBackground`]'s [`WidgetState`]
    ///    using the locally-replicated [`clone_widget_state`] helper
    ///    (since `init_copy_from` is private to the
    ///    `widgets::background` module).
    /// 2. Build a fresh [`TuiBackground`] from the cloned state plus
    ///    the source's `bgfillchar` and `bgcolors`.
    /// 3. Snapshot the source's `filltext` under the inner lock and
    ///    deep-copy it into the new [`NewstickerInner`].
    /// 4. Wrap the composite in [`Arc::new`] and spawn a fresh 200 ms
    ///    timer task with a [`Weak<Self>`] back-reference.
    /// 5. Install the [`JoinHandle`] into the new widget's inner slot.
    ///
    /// FASM-equivalent fields preserved:
    /// - `filltext` — deep-copied via `String::clone`
    /// - `scrollpos` — reset to [`SCROLLPOS_RESET_SENTINEL`] (`-1`)
    /// - `textpos` — reset to `0`
    /// - `timer` — freshly spawned at 200 ms cadence
    ///
    /// FASM-equivalent fields NOT cloned (matching `tui_object$init_copy`):
    /// - `bastards` (left empty in the clone — see FASM line 274)
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when the [`clone_widget_state`]
    /// helper fails (e.g. a child's `clone_widget` propagates an
    /// error).
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // ---- Step 1: deep-clone the base state.
        let cloned_bg_state = clone_widget_state(self.background.state())?;
        let cloned_bg = TuiBackground {
            state: cloned_bg_state,
            bgfillchar: self.background.fillchar(),
            bgcolors: self.background.colors(),
        };

        // ---- Step 2: snapshot filltext under the inner lock.
        let filltext_clone = match self.inner.lock() {
            Ok(g) => g.filltext.clone(),
            Err(p) => p.into_inner().filltext.clone(),
        };

        // ---- Step 3: build the new NewstickerInner with reset state.
        //
        // FASM `tui_newsticker$clone` zeros the heap$alloc_clear
        // result then sets scrollpos = -1 (line 147), implicitly
        // leaving textpos = 0 from the zero-fill. We replicate this
        // exactly: textpos = 0, scrollpos = SCROLLPOS_RESET_SENTINEL,
        // timer = None (filled in below).
        let cloned_inner = NewstickerInner {
            filltext: filltext_clone,
            textpos: 0,
            scrollpos: SCROLLPOS_RESET_SENTINEL,
            timer: None,
        };

        // ---- Step 4: assemble the new Arc<Self>.
        let new_arc: Arc<Self> = Arc::new(Self {
            background: cloned_bg,
            inner: Mutex::new(cloned_inner),
        });

        // ---- Step 5: spawn a fresh timer task for the clone.
        //
        // FASM `epoll$timer_new(tui_newsticker_speed, new)` at lines
        // 142–143. The new widget gets its own Weak<Self> back-
        // reference and its own JoinHandle.
        let weak: Weak<Self> = Arc::downgrade(&new_arc);
        let handle: JoinHandle<()> = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(TICK_MS));
            loop {
                ticker.tick().await;
                match weak.upgrade() {
                    Some(strong) => strong.tick(),
                    None => break,
                }
            }
        });

        match new_arc.inner.lock() {
            Ok(mut guard) => guard.timer = Some(handle),
            Err(poisoned) => poisoned.into_inner().timer = Some(handle),
        }

        // ---- Step 6: upcast to Arc<dyn Widget> for the trait return type.
        Ok(new_arc as Arc<dyn Widget>)
    }

    // ----------------- Override 3: draw (vtable slot 2) -----------------

    /// Override — vtable slot 2 (`tui_vdraw`).
    ///
    /// FASM parallel: `tui_newsticker$draw`
    /// (`tui_newsticker.inc` lines 170–242):
    ///
    /// ```text
    ///   if width == 0 || height == 0:        ; .nothingtodo
    ///       return
    ///   call tui_background$nvfill           ; paint base row
    ///   if filltext.length == 0:             ; .nofilltext
    ///       call vupdatedisplaylist
    ///       return
    ///   if scrollpos == -1:
    ///       scrollpos = width - 1
    ///   ; main scroll loop
    ///   x = scrollpos
    ///   text_buf = self.text + x*4           ; first cell to write
    ///   while x < width:
    ///       if textpos >= filltext.length:
    ///           x += 1; text_buf += 4         ; advance past end
    ///           textpos += 1                  ; (FASM advances both)
    ///           continue
    ///       text_buf[0] = filltext[textpos]   ; write codepoint
    ///       x += 1; text_buf += 4
    ///       textpos += 1
    ///   if textpos >= filltext.length:
    ///       scrollpos = -1                    ; reset for next cycle
    ///       textpos = 0
    ///   call vupdatedisplaylist
    /// ```
    ///
    /// **Loop body subtlety**: the FASM scroll loop enters `.loop`
    /// at line 198. On each iteration it tests `eax >= ecx`
    /// (i.e. `x >= width+1` because line 191 increments `ecx` by 1)
    /// to terminate, and tests `edx >= [rdi]` (i.e. `textpos >=
    /// filltext.length`) to choose the `.loopnext_nocopy` branch.
    /// The `.loopnext_nocopy` branch advances `eax`, `edx`, and
    /// `rsi` by one cell **without writing** — this is how trailing
    /// cells beyond the end of the source text get the background
    /// fill character preserved (the prior `nvfill` already painted
    /// them). The Rust translation collapses both branches into a
    /// `while` loop with an explicit "no source char available"
    /// short-circuit that just advances the cursor.
    ///
    /// **End-of-cycle reset**: after the loop, FASM tests
    /// `textpos >= [rdi]` (filltext length) at line 222. If true,
    /// it resets `scrollpos = -1, textpos = 0` (lines 225–226) so
    /// the next timer tick starts a fresh right-to-left scroll.
    /// The Rust translation preserves this exactly.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when the parent
    /// [`TuiBackground::nvfill`] fails (typically `width * height`
    /// arithmetic overflow — impossible for a height-1 widget at
    /// any realistic terminal width).
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        // ---- Step 1: bail-out conditions matching FASM .nothingtodo.
        //
        // FASM lines 175–178:
        //   cmp dword [rdi+tui_width_ofs], 0
        //   je .nothingtodo
        //   cmp dword [rdi+tui_height_ofs], 0
        //   je .nothingtodo
        //
        // The FASM uses unsigned compares; we use Rust's signed i32
        // and treat negative as zero (defensive — should not happen
        // since both constructors guarantee height = 1 and width
        // came from a positive-only constructor).
        let width = self.background.state().width;
        let height = self.background.state().height;
        if width <= 0 || height <= 0 {
            return Ok(());
        }

        // ---- Step 2: paint the background row.
        //
        // FASM `call tui_background$nvfill` at line 181 — fills the
        // text buffer with the fill char (`b' '`) and the attribute
        // buffer with the packed background colors. This MUST happen
        // BEFORE writing the scrolled-text cells because cells beyond
        // the live scroll window need to retain the background fill.
        self.background.nvfill()?;

        // ---- Step 3: handle empty filltext.
        //
        // FASM lines 182–184:
        //   mov rdi, [rbx+tui_newsticker_filltext_ofs]
        //   cmp qword [rdi], 0           ; first qword is FASM string length
        //   je .nofilltext
        //
        // .nofilltext (line 233) just dispatches vupdatedisplaylist
        // and returns. We collect the chars now under lock so we can
        // release the lock before iterating.
        let (chars, scrollpos_was_sentinel) = {
            let guard = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if guard.filltext.is_empty() {
                // FASM .nofilltext — nothing to scroll. Drop the
                // lock and dispatch the display-list update.
                drop(guard);
                self.update_display_list();
                return Ok(());
            }
            // Materialize the char vector while we hold the lock so
            // the source is consistent with the textpos snapshot
            // even if a concurrent set_text races us. (The lock is
            // not strictly required for char enumeration but the
            // snapshot atomicity matters for the scroll-state read.)
            let chars: Vec<char> = guard.filltext.chars().collect();
            let was_sentinel = guard.scrollpos == SCROLLPOS_RESET_SENTINEL;
            (chars, was_sentinel)
        };

        // chars cannot be empty — we already early-returned on
        // filltext.is_empty(). But chars().count() can theoretically
        // differ from filltext.len() for non-ASCII UTF-8. Use
        // chars.len() as the loop bound throughout this function.
        let chars_len: u32 = u32::try_from(chars.len()).unwrap_or(u32::MAX);

        // ---- Step 4: resolve scrollpos sentinel.
        //
        // FASM lines 185–190:
        //   mov eax, [rbx+tui_newsticker_scrollpos_ofs]
        //   mov ecx, [rbx+tui_width_ofs]
        //   sub ecx, 1
        //   cmp eax, -1
        //   cmove eax, ecx              ; if scrollpos == -1, eax = width-1
        //   mov [rbx+tui_newsticker_scrollpos_ofs], eax
        //
        // We update scrollpos under lock then snapshot the resulting
        // values (scrollpos and textpos) for the loop body.
        let (scrollpos, textpos_start) = {
            let mut guard = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if scrollpos_was_sentinel {
                guard.scrollpos = width.saturating_sub(1);
            }
            (guard.scrollpos, guard.textpos)
        };

        // ---- Step 5: scroll loop.
        //
        // FASM `.loop` at line 198 — copy chars from filltext starting
        // at the column `scrollpos` of the text buffer. Advance both
        // the buffer cursor (`eax` in FASM = our `buf_x`) and the
        // text cursor (`edx` in FASM = our `text_pos`) until either:
        //   - buf_x reaches width, OR
        //   - text_pos reaches filltext.length.
        //
        // We start `buf_x` at scrollpos.max(0) because scrollpos can
        // technically be negative in pathological cases (e.g.
        // width=0 was just handled, but defensive against
        // arithmetic underflow when sub_saturating evaluates to 0
        // for width=0 — although that case is already filtered).
        let start_col = scrollpos.max(0) as usize;
        let width_usize = width.max(0) as usize;
        let mut buf_x: usize = start_col;
        let mut text_pos: u32 = textpos_start;

        // Snapshot the text buffer and attribute buffer as mutable
        // slices via the embedded TuiBackground. We need the text
        // buffer to write the codepoint dwords (4 bytes each),
        // matching FASM `mov [rsi], r8d` at line 208.
        //
        // The buffer was just populated by nvfill() above, so it
        // holds (width * height * 4) bytes = (width * 4) bytes for
        // our height-1 widget. The first scrollpos.max(0) cells
        // remain untouched (they keep the background fill); we
        // overlay starting at column scrollpos.
        let text_buf = self.background.state_mut().text.as_mut_slice();

        while buf_x < width_usize {
            if text_pos >= chars_len {
                // FASM `.loopnext_nocopy` branch — past end of source;
                // the FASM advances both `eax` (buf_x) and `edx`
                // (textpos) but does NOT write. Advancing textpos
                // here is required so the FASM-equivalent
                // post-loop test `if textpos >= filltext.length`
                // observes the same value the FASM would.
                buf_x += 1;
                text_pos = text_pos.saturating_add(1);
                continue;
            }
            // FASM `.loop` body lines 203–212 — write the codepoint
            // dword from filltext[textpos*4 + 8] (skipping the FASM
            // length prefix) into text_buf[buf_x*4]. In Rust the
            // chars vec is already decoded codepoints; we convert
            // each `char` to its `u32` codepoint and write 4 bytes
            // little-endian into the byte buffer.
            //
            // SAFETY: text_pos < chars_len is guaranteed by the
            // immediately preceding branch; the cast from u32 to
            // usize is sound because chars_len was derived from
            // chars.len() which is a usize.
            let ch: char = chars[text_pos as usize];
            let codepoint: u32 = ch as u32;
            let cell_byte_offset = buf_x.saturating_mul(4);

            // Defensive bound check — text_buf was sized by nvfill
            // to hold exactly (width * 4) bytes; cell_byte_offset
            // + 4 must not exceed that. If for any reason
            // (e.g. a pathological width) the buffer is shorter,
            // we abort the loop early to avoid a panic.
            if cell_byte_offset + 4 > text_buf.len() {
                break;
            }
            // Write the codepoint as 4 little-endian bytes — matches
            // FASM `mov [rsi], r8d` at line 208 on x86_64 where
            // dword stores are natively little-endian.
            text_buf[cell_byte_offset..cell_byte_offset + 4].copy_from_slice(&codepoint.to_le_bytes());

            buf_x += 1;
            text_pos = text_pos.saturating_add(1);
        }

        // ---- Step 6: end-of-cycle reset detection.
        //
        // FASM lines 220–226:
        //   .loopdone:
        //     mov edx, [rbx+tui_newsticker_textpos_ofs]   ; re-read textpos from STRUCT
        //     cmp edx, [rdi]            ; rdi = filltext, [rdi] = length
        //     jb .nofilltext            ; if textpos < length, no reset
        //     mov dword [rbx+tui_newsticker_scrollpos_ofs], -1
        //     mov dword [rbx+tui_newsticker_textpos_ofs], 0
        //
        // **Critical FASM subtlety**: at `.loopdone`, the FASM
        // **re-reads** textpos from the struct (line 223:
        // `mov edx, [rbx+tui_newsticker_textpos_ofs]`). The local
        // `edx` register (which the loop body advanced) is
        // discarded. The reset check therefore uses the
        // pre-loop textpos value — meaning the struct's textpos
        // is only modified by the [`Widget::timer`] path, never
        // by the draw path. The local `text_pos` variable in the
        // loop above is purely an iterator into filltext characters
        // for the current draw frame; it does not persist across
        // draw calls.
        //
        // The reset fires only when timer ticks have already
        // pushed the struct's textpos past chars_len — i.e. when
        // the entire source text has fully scrolled off the left
        // edge of the widget.
        {
            let mut guard = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if guard.textpos >= chars_len {
                // Reset the scroll cycle. FASM lines 225–226.
                guard.scrollpos = SCROLLPOS_RESET_SENTINEL;
                guard.textpos = 0;
            }
            // else: textpos in struct < chars_len → no reset.
            // We do NOT write the advanced local text_pos back
            // because FASM doesn't either — only the timer
            // advances the struct's textpos field.
        }

        // ---- Step 7: dispatch the display-list update.
        //
        // FASM `call qword [rsi+tui_vupdatedisplaylist]` at line 229
        // / 236 — the polymorphic dispatch goes through the trait
        // method here. The trait default is a no-op; renderer-bound
        // compositions override `update_display_list` to flush the
        // populated buffers downstream.
        self.update_display_list();

        Ok(())
    }

    // ----------------- Override 4: timer (vtable slot 6) -----------------

    /// Override — vtable slot 6 (`tui_vtimer`).
    ///
    /// FASM parallel: `tui_newsticker$timer`
    /// (`tui_newsticker.inc` lines 245–270):
    ///
    /// ```text
    ///   if scrollpos > 0:
    ///       scrollpos -= 1
    ///   else if scrollpos == 0:
    ///       textpos += 1
    ///   ; (else scrollpos < 0 → no-op, draw will handle)
    ///   call vdraw                  ; immediate redraw
    ///   eax = 0                     ; return 0 = keep timer alive
    /// ```
    ///
    /// In the Rust translation this method is invoked by the
    /// framework's external timer dispatcher (when present); the
    /// counter advancement is the same as [`TuiNewsticker::tick`]
    /// (which the spawned tokio task uses), so we delegate.
    ///
    /// However the trait signature for [`Widget::timer`] is
    /// `fn timer(&mut self) -> ()` — there is no `TimerAction`
    /// return value at the trait level (the
    /// [`crate::tui::object::TimerAction`] enum exists for future
    /// framework use but is not part of the trait signature).
    /// Returning `()` is equivalent to FASM's `eax = 0` (keep timer
    /// alive) for every invocation; the newsticker has no condition
    /// under which it wishes to terminate the timer, matching the
    /// FASM `xor eax, eax` at lines 255 / 262 / 269.
    ///
    /// **Note on redraw**: the FASM original calls `vdraw` at lines
    /// 254 / 261 / 268 immediately after advancing the scroll state.
    /// The Rust translation does NOT redraw via [`Widget::draw`]
    /// from inside this method because that would require a
    /// [`Renderer`] argument the trait does not provide here. The
    /// framework dispatcher is expected to schedule a draw pass
    /// after the timer fires. In typical operation, ticks come from
    /// the spawned tokio task (which calls
    /// [`TuiNewsticker::tick`] without redrawing — see the doc-
    /// comment on `tick` for rationale); this trait method is the
    /// path used when an external dispatcher prefers to drive ticks
    /// synchronously instead of via the spawned task.
    fn timer(&mut self) {
        // Use the same atomic-equivalent scroll-state advance as
        // the tokio-driven path. Calling `tick` keeps the two code
        // paths byte-for-byte equivalent and ensures the
        // newsticker's apparent scroll rate is unchanged whether
        // the framework drives ticks externally or relies on the
        // spawned tokio task.
        self.tick();
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper — produce a default test [`ColorPair`] (white-on-black).
    fn test_colors() -> ColorPair {
        ColorPair { fg: 7, bg: 0 }
    }

    /// `assert_send_sync<T>()` enforces the `Send + Sync` bound at
    /// monomorphisation time — required for `Arc<dyn Widget>` use
    /// across tokio task boundaries.
    fn assert_send_sync<T: Send + Sync>() {}

    // ----------------------------------------------------------------
    // Type-property tests
    // ----------------------------------------------------------------

    #[test]
    fn tui_newsticker_is_send_and_sync() {
        // Required for the Widget: Send + Sync 'static contract that
        // makes Arc<dyn Widget> usable across tokio task boundaries.
        assert_send_sync::<TuiNewsticker>();
    }

    /// FASM `tui_newsticker_speed = 200` — guard against accidental
    /// refactoring of the tick cadence.
    #[test]
    fn test_tick_ms_matches_fasm_constant() {
        assert_eq!(TICK_MS, 200);
    }

    // ----------------------------------------------------------------
    // tick_scroll_state — pure free-function tests
    // ----------------------------------------------------------------

    /// `tick_scroll_state` with `scrollpos > 0` decrements scrollpos
    /// without touching textpos. Mirrors FASM `.decscrollpos`.
    #[test]
    fn test_tick_state_decrements_when_positive() {
        let mut inner = NewstickerInner {
            filltext: String::from("hello"),
            textpos: 3,
            scrollpos: 5,
            timer: None,
        };
        tick_scroll_state(&mut inner);
        assert_eq!(inner.scrollpos, 4);
        assert_eq!(inner.textpos, 3);
    }

    /// `tick_scroll_state` with `scrollpos == 0` increments textpos
    /// and leaves scrollpos at 0. Mirrors FASM `.inctextpos`.
    #[test]
    fn test_tick_state_increments_textpos_at_zero() {
        let mut inner = NewstickerInner {
            filltext: String::from("hello"),
            textpos: 3,
            scrollpos: 0,
            timer: None,
        };
        tick_scroll_state(&mut inner);
        assert_eq!(inner.scrollpos, 0);
        assert_eq!(inner.textpos, 4);
    }

    /// `tick_scroll_state` with negative `scrollpos` (the sentinel)
    /// is a no-op; the next draw will resolve the sentinel to
    /// `width - 1`.
    #[test]
    fn test_tick_state_noop_when_sentinel() {
        let mut inner = NewstickerInner {
            filltext: String::from("hello"),
            textpos: 3,
            scrollpos: SCROLLPOS_RESET_SENTINEL,
            timer: None,
        };
        tick_scroll_state(&mut inner);
        assert_eq!(inner.scrollpos, SCROLLPOS_RESET_SENTINEL);
        assert_eq!(inner.textpos, 3);
    }

    /// `tick_scroll_state` saturates textpos at u32::MAX rather than
    /// overflowing — defensive even though the bound is unreachable
    /// in any realistic ticker use-case.
    #[test]
    fn test_tick_state_saturates_textpos_at_max() {
        let mut inner = NewstickerInner {
            filltext: String::from("hello"),
            textpos: u32::MAX,
            scrollpos: 0,
            timer: None,
        };
        tick_scroll_state(&mut inner);
        assert_eq!(inner.textpos, u32::MAX);
    }

    // ----------------------------------------------------------------
    // set_text_in_inner / append_text_in_inner — pure free-function tests
    // ----------------------------------------------------------------

    /// `set_text_in_inner` replaces filltext and resets BOTH
    /// scrollpos AND textpos. Mirrors FASM `tui_newsticker$nvsettext`.
    #[test]
    fn test_set_text_resets_scroll_and_textpos() {
        let mut inner = NewstickerInner {
            filltext: String::from("old text"),
            textpos: 5,
            scrollpos: 10,
            timer: None,
        };
        set_text_in_inner(&mut inner, "new text");
        assert_eq!(inner.filltext, "new text");
        assert_eq!(inner.scrollpos, SCROLLPOS_RESET_SENTINEL);
        assert_eq!(inner.textpos, 0);
    }

    /// `append_text_in_inner` extends filltext but does NOT reset
    /// scroll state. Mirrors FASM `tui_newsticker$nvappendtext`.
    #[test]
    fn test_append_text_preserves_scroll_state() {
        let mut inner = NewstickerInner {
            filltext: String::from("hello "),
            textpos: 5,
            scrollpos: 10,
            timer: None,
        };
        append_text_in_inner(&mut inner, "world");
        assert_eq!(inner.filltext, "hello world");
        assert_eq!(inner.scrollpos, 10);
        assert_eq!(inner.textpos, 5);
    }

    /// `append_text_in_inner` with empty `appended` is a no-op for
    /// the filltext content (and a no-op for scroll state per the
    /// preserve-scroll contract).
    #[test]
    fn test_append_text_empty_is_noop_for_text() {
        let mut inner = NewstickerInner {
            filltext: String::from("unchanged"),
            textpos: 3,
            scrollpos: 7,
            timer: None,
        };
        append_text_in_inner(&mut inner, "");
        assert_eq!(inner.filltext, "unchanged");
        assert_eq!(inner.scrollpos, 7);
        assert_eq!(inner.textpos, 3);
    }

    // ----------------------------------------------------------------
    // Constructor tests — new_i / new_d
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_new_i_sets_height_to_one() {
        let nt = TuiNewsticker::new_i(20, "hello", test_colors())
            .expect("new_i should succeed for positive width");
        // Height MUST be 1 — both constructors force height = 1.
        assert_eq!(nt.state().height, 1);
        assert_eq!(nt.state().width, 20);
        assert_eq!(nt.state().width_percent, None);
        // Cleanup the spawned timer.
        Arc::try_unwrap(nt).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_new_i_initial_state() {
        let nt = TuiNewsticker::new_i(40, "foo", test_colors()).expect("new_i should succeed");
        // FASM heap$alloc_clear zeros all extra fields; new_i then
        // sets scrollpos = -1.
        assert_eq!(nt.current_scrollpos(), SCROLLPOS_RESET_SENTINEL);
        assert_eq!(nt.current_textpos(), 0);
        // filltext is the deep-copy of the input.
        assert_eq!(nt.current_filltext(), "foo");
        Arc::try_unwrap(nt).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_new_d_sets_height_to_one_and_uses_percent() {
        let nt = TuiNewsticker::new_d(0.5, "hello", test_colors()).expect("new_d should succeed");
        // Height = 1, width is 0 sentinel for percent-based
        // (matches TuiBackground::new_di).
        assert_eq!(nt.state().height, 1);
        assert_eq!(nt.state().width_percent, Some(0.5));
        assert_eq!(nt.state().height_percent, None);
        Arc::try_unwrap(nt).map(|mut owned| owned.cleanup()).ok();
    }

    /// FASM defaults preserved: visible=true, include_in_layout=true,
    /// absolute_x=-1, absolute_y=-1 (the "not yet positioned"
    /// sentinel from WidgetState::new). These come from the
    /// inherited [`TuiBackground`] state.
    #[tokio::test]
    async fn test_new_i_inherits_widget_state_defaults() {
        let nt = TuiNewsticker::new_i(20, "test", test_colors()).expect("new_i should succeed");
        assert!(nt.state().visible);
        assert!(nt.state().include_in_layout);
        assert_eq!(nt.state().absolute_x, -1);
        assert_eq!(nt.state().absolute_y, -1);
        Arc::try_unwrap(nt).map(|mut owned| owned.cleanup()).ok();
    }

    /// new_i with negative width still constructs (the parent
    /// [`TuiBackground::new_ii`] doesn't reject negative widths)
    /// but the resulting widget's draw is a no-op (.nothingtodo).
    #[tokio::test]
    async fn test_new_i_accepts_zero_width_widget_is_noop() {
        let nt =
            TuiNewsticker::new_i(0, "hello", test_colors()).expect("new_i with width=0 still constructs");
        assert_eq!(nt.state().width, 0);
        // Draw is a no-op for width=0 (FASM .nothingtodo).
        Arc::try_unwrap(nt).map(|mut owned| owned.cleanup()).ok();
    }

    /// The constructor must deep-copy the filltext so the caller can
    /// drop their `&str` source immediately. We verify by passing
    /// an owned String, then dropping it, then querying the widget.
    #[tokio::test]
    async fn test_new_i_owns_filltext_independent_of_caller() {
        let source = String::from("ephemeral");
        let nt = TuiNewsticker::new_i(20, &source, test_colors()).expect("new_i should succeed");
        drop(source);
        // The widget retains its own deep-copy.
        assert_eq!(nt.current_filltext(), "ephemeral");
        Arc::try_unwrap(nt).map(|mut owned| owned.cleanup()).ok();
    }

    // ----------------------------------------------------------------
    // set_text / append_text — public API tests
    // ----------------------------------------------------------------

    /// `set_text` resets scrollpos and textpos AND replaces filltext.
    #[tokio::test]
    async fn test_set_text_replaces_and_resets() {
        let nt = TuiNewsticker::new_i(20, "alpha", test_colors()).expect("new_i should succeed");
        // Mutate scrollpos and textpos directly (bypass timer race).
        {
            let mut guard = nt.inner.lock().expect("lock");
            guard.scrollpos = 5;
            guard.textpos = 3;
        }
        nt.set_text("beta");
        assert_eq!(nt.current_filltext(), "beta");
        assert_eq!(nt.current_scrollpos(), SCROLLPOS_RESET_SENTINEL);
        assert_eq!(nt.current_textpos(), 0);
        Arc::try_unwrap(nt).map(|mut owned| owned.cleanup()).ok();
    }

    /// `append_text` does NOT reset scrollpos or textpos.
    #[tokio::test]
    async fn test_append_text_preserves_scroll() {
        let nt = TuiNewsticker::new_i(20, "alpha", test_colors()).expect("new_i should succeed");
        {
            let mut guard = nt.inner.lock().expect("lock");
            guard.scrollpos = 5;
            guard.textpos = 3;
        }
        nt.append_text(" beta");
        assert_eq!(nt.current_filltext(), "alpha beta");
        assert_eq!(nt.current_scrollpos(), 5);
        assert_eq!(nt.current_textpos(), 3);
        Arc::try_unwrap(nt).map(|mut owned| owned.cleanup()).ok();
    }

    // ----------------------------------------------------------------
    // Widget trait — cleanup, clone_widget, draw, timer
    // ----------------------------------------------------------------

    /// `cleanup` aborts the timer task and clears the filltext.
    #[tokio::test]
    async fn test_cleanup_clears_timer_and_filltext() {
        let nt = TuiNewsticker::new_i(20, "ticker", test_colors()).expect("new_i should succeed");
        let mut owned = Arc::try_unwrap(nt)
            .map_err(|_| ())
            .expect("test holds the only reference");

        // Verify timer is set BEFORE cleanup.
        let timer_before = match owned.inner.lock() {
            Ok(g) => g.timer.is_some(),
            Err(p) => p.into_inner().timer.is_some(),
        };
        assert!(timer_before);

        owned.cleanup();

        // Verify timer is None and filltext is empty AFTER cleanup.
        let (timer_after, filltext_after) = match owned.inner.lock() {
            Ok(g) => (g.timer.is_some(), g.filltext.clone()),
            Err(p) => {
                let g = p.into_inner();
                (g.timer.is_some(), g.filltext.clone())
            }
        };
        assert!(!timer_after, "timer should be None after cleanup");
        assert_eq!(filltext_after, "", "filltext should be cleared");

        // State buffers should also be cleared (text/attributes/...).
        assert_eq!(owned.state().text.as_slice().len(), 0);
        assert_eq!(owned.state().attributes.cells.len(), 0);
    }

    /// `clone_widget` deep-copies filltext, spawns a fresh timer,
    /// and resets scrollpos to -1 and textpos to 0. The clone has
    /// its own independent inner state.
    #[tokio::test]
    async fn test_clone_widget_deep_copies_and_resets() {
        let nt = TuiNewsticker::new_i(20, "source", test_colors()).expect("new_i should succeed");

        // Mutate source state to verify clone-isolation.
        {
            let mut guard = nt.inner.lock().expect("lock");
            guard.scrollpos = 7;
            guard.textpos = 4;
        }

        // Clone via the trait method.
        let cloned_dyn = nt.clone_widget().expect("clone_widget should succeed");
        let cloned_concrete: &TuiNewsticker = cloned_dyn
            .as_any()
            .downcast_ref::<TuiNewsticker>()
            .expect("downcast must succeed for clone result");

        // Clone has its own filltext (deep copy).
        assert_eq!(cloned_concrete.current_filltext(), "source");
        // Clone resets scroll state.
        assert_eq!(cloned_concrete.current_scrollpos(), SCROLLPOS_RESET_SENTINEL);
        assert_eq!(cloned_concrete.current_textpos(), 0);

        // Clone has its own fresh timer.
        let clone_timer_present = match cloned_concrete.inner.lock() {
            Ok(g) => g.timer.is_some(),
            Err(p) => p.into_inner().timer.is_some(),
        };
        assert!(clone_timer_present, "clone should have its own fresh timer");

        // Source state is not mutated by the clone.
        assert_eq!(nt.current_scrollpos(), 7);
        assert_eq!(nt.current_textpos(), 4);

        // Cleanup both.
        drop(cloned_dyn);
        Arc::try_unwrap(nt).map(|mut owned| owned.cleanup()).ok();
    }

    /// `clone_widget` produces an `Arc<dyn Widget>` with a fresh
    /// allocation distinct from the source.
    #[tokio::test]
    async fn test_clone_widget_yields_independent_arc() {
        let nt: Arc<TuiNewsticker> =
            TuiNewsticker::new_i(20, "test", test_colors()).expect("new_i should succeed");

        let cloned = nt.clone_widget().expect("clone_widget should succeed");
        let cloned_concrete: &TuiNewsticker = cloned
            .as_any()
            .downcast_ref::<TuiNewsticker>()
            .expect("downcast must succeed");

        // Different underlying allocations — Arc::as_ptr disagrees.
        assert!(!std::ptr::eq(
            Arc::as_ptr(&nt),
            cloned_concrete as *const TuiNewsticker
        ));

        drop(cloned);
        Arc::try_unwrap(nt).map(|mut owned| owned.cleanup()).ok();
    }

    /// `draw` with width=0 is a no-op and does not panic.
    #[tokio::test]
    async fn test_draw_width_zero_is_noop() {
        let nt = TuiNewsticker::new_i(0, "hello", test_colors()).expect("new_i should succeed");
        let mut owned = Arc::try_unwrap(nt)
            .map_err(|_| ())
            .expect("test holds the only reference");

        let mut renderer = NullRenderer::default();
        let result = owned.draw(&mut renderer);
        assert!(result.is_ok());
        owned.cleanup();
    }

    /// `draw` with empty filltext fills the background and returns
    /// without writing any scrolled-text characters.
    #[tokio::test]
    async fn test_draw_empty_filltext_only_fills_background() {
        let nt = TuiNewsticker::new_i(10, "", test_colors()).expect("new_i should succeed");
        let mut owned = Arc::try_unwrap(nt)
            .map_err(|_| ())
            .expect("test holds the only reference");

        let mut renderer = NullRenderer::default();
        owned.draw(&mut renderer).expect("draw should succeed");

        // Buffer is filled with the fill character (b' ' = 0x20).
        let text = owned.state().text.as_slice();
        // 10 cells × 4 bytes = 40 bytes.
        assert_eq!(text.len(), 40);
        // Each cell holds the fill char (0x20) as a u32 little-endian.
        for chunk in text.chunks_exact(4) {
            assert_eq!(chunk, &[0x20, 0x00, 0x00, 0x00]);
        }
        owned.cleanup();
    }

    /// `draw` resolves the SCROLLPOS_RESET_SENTINEL (`-1`) on first
    /// call by setting scrollpos to (width - 1).
    #[tokio::test]
    async fn test_draw_resolves_sentinel_to_width_minus_one() {
        let nt = TuiNewsticker::new_i(10, "abc", test_colors()).expect("new_i should succeed");
        let mut owned = Arc::try_unwrap(nt)
            .map_err(|_| ())
            .expect("test holds the only reference");

        // Verify sentinel is set after construction.
        assert_eq!(owned.current_scrollpos(), SCROLLPOS_RESET_SENTINEL);

        let mut renderer = NullRenderer::default();
        owned.draw(&mut renderer).expect("draw should succeed");

        // After draw, scrollpos should be resolved to width - 1 = 9.
        assert_eq!(owned.current_scrollpos(), 9);

        owned.cleanup();
    }

    /// `draw` writes the filltext characters into the text buffer
    /// starting at column scrollpos.
    #[tokio::test]
    async fn test_draw_writes_chars_at_scrollpos() {
        let nt = TuiNewsticker::new_i(10, "ab", test_colors()).expect("new_i should succeed");
        let mut owned = Arc::try_unwrap(nt)
            .map_err(|_| ())
            .expect("test holds the only reference");

        // Force a known scrollpos for deterministic placement.
        {
            let mut guard = owned.inner.lock().expect("lock");
            guard.scrollpos = 3;
            guard.textpos = 0;
        }

        let mut renderer = NullRenderer::default();
        owned.draw(&mut renderer).expect("draw should succeed");

        // text buffer = 10 cells × 4 bytes = 40 bytes.
        let text = owned.state().text.as_slice();
        assert_eq!(text.len(), 40);

        // Cell 0..3 should hold fill char (0x20).
        for chunk in text[..12].chunks_exact(4) {
            assert_eq!(chunk, &[0x20, 0, 0, 0]);
        }
        // Cell 3 should hold 'a' (0x61).
        assert_eq!(&text[12..16], &[0x61, 0, 0, 0]);
        // Cell 4 should hold 'b' (0x62).
        assert_eq!(&text[16..20], &[0x62, 0, 0, 0]);
        // Cells 5..10 should hold fill char.
        for chunk in text[20..40].chunks_exact(4) {
            assert_eq!(chunk, &[0x20, 0, 0, 0]);
        }

        owned.cleanup();
    }

    /// `draw` resets scrollpos to -1 and textpos to 0 when textpos
    /// (in the struct) is already >= chars_len at the start of the
    /// draw. Mirrors FASM lines 220–226 — the reset check uses the
    /// re-read struct textpos, not the loop's advanced local copy.
    #[tokio::test]
    async fn test_draw_resets_when_struct_textpos_at_or_past_end() {
        let nt = TuiNewsticker::new_i(10, "ab", test_colors()).expect("new_i should succeed");
        let mut owned = Arc::try_unwrap(nt)
            .map_err(|_| ())
            .expect("test holds the only reference");

        // Force textpos already at chars_len (= 2). This is the
        // post-condition the timer eventually reaches by repeatedly
        // incrementing textpos at scrollpos == 0.
        {
            let mut guard = owned.inner.lock().expect("lock");
            guard.scrollpos = 0;
            guard.textpos = 2;
        }

        let mut renderer = NullRenderer::default();
        owned.draw(&mut renderer).expect("draw should succeed");

        // After draw observes textpos >= chars_len, both fields
        // reset for the next cycle.
        assert_eq!(owned.current_scrollpos(), SCROLLPOS_RESET_SENTINEL);
        assert_eq!(owned.current_textpos(), 0);

        owned.cleanup();
    }

    /// `draw` does NOT reset when textpos in the struct is still
    /// less than chars_len, even if the loop's local cursor advances
    /// past it. The struct's textpos is only modified by the timer.
    #[tokio::test]
    async fn test_draw_does_not_advance_struct_textpos() {
        let nt = TuiNewsticker::new_i(10, "ab", test_colors()).expect("new_i should succeed");
        let mut owned = Arc::try_unwrap(nt)
            .map_err(|_| ())
            .expect("test holds the only reference");

        // Force scrollpos to a known value; textpos starts at 0.
        {
            let mut guard = owned.inner.lock().expect("lock");
            guard.scrollpos = 5;
            guard.textpos = 0;
        }

        let mut renderer = NullRenderer::default();
        owned.draw(&mut renderer).expect("draw should succeed");

        // Draw should NOT advance struct's textpos (FASM semantics:
        // textpos is only mutated by the timer, never by draw).
        assert_eq!(owned.current_textpos(), 0);
        // scrollpos was not the sentinel and not at end-of-cycle,
        // so it stays at 5.
        assert_eq!(owned.current_scrollpos(), 5);

        owned.cleanup();
    }

    /// `Widget::timer` advances scroll state via the same path as
    /// `tick` — verifies the scrollpos > 0 branch decrements.
    #[tokio::test]
    async fn test_widget_timer_decrements_scrollpos() {
        let nt = TuiNewsticker::new_i(20, "test", test_colors()).expect("new_i should succeed");
        let mut owned = Arc::try_unwrap(nt)
            .map_err(|_| ())
            .expect("test holds the only reference");

        // Set scrollpos > 0 manually.
        {
            let mut guard = owned.inner.lock().expect("lock");
            guard.scrollpos = 5;
            guard.textpos = 0;
        }

        Widget::timer(&mut owned);
        assert_eq!(owned.current_scrollpos(), 4);
        assert_eq!(owned.current_textpos(), 0);

        owned.cleanup();
    }

    /// `Widget::timer` increments textpos when scrollpos == 0.
    #[tokio::test]
    async fn test_widget_timer_increments_textpos_at_zero() {
        let nt = TuiNewsticker::new_i(20, "test", test_colors()).expect("new_i should succeed");
        let mut owned = Arc::try_unwrap(nt)
            .map_err(|_| ())
            .expect("test holds the only reference");

        {
            let mut guard = owned.inner.lock().expect("lock");
            guard.scrollpos = 0;
            guard.textpos = 0;
        }

        Widget::timer(&mut owned);
        assert_eq!(owned.current_scrollpos(), 0);
        assert_eq!(owned.current_textpos(), 1);

        owned.cleanup();
    }

    /// `Widget::timer` is a no-op when scrollpos is the sentinel.
    #[tokio::test]
    async fn test_widget_timer_noop_when_sentinel() {
        let nt = TuiNewsticker::new_i(20, "test", test_colors()).expect("new_i should succeed");
        let mut owned = Arc::try_unwrap(nt)
            .map_err(|_| ())
            .expect("test holds the only reference");

        // Default state is sentinel.
        assert_eq!(owned.current_scrollpos(), SCROLLPOS_RESET_SENTINEL);

        Widget::timer(&mut owned);
        assert_eq!(owned.current_scrollpos(), SCROLLPOS_RESET_SENTINEL);
        assert_eq!(owned.current_textpos(), 0);

        owned.cleanup();
    }

    /// Full tick cycle: starting from sentinel, repeatedly tick the
    /// widget; observe scrollpos descend from width-1 down to 0,
    /// then textpos increment, and finally the cycle reset.
    ///
    /// Verifies the FASM `tui_newsticker$timer` state machine
    /// (lines 245–270) drives correctly through all four phases
    /// (sentinel → entering → at-edge → cycle-end).
    ///
    /// Per FASM semantics confirmed via reconnaissance: the
    /// **timer** is the only mutator of struct textpos; **draw**
    /// only mutates struct scrollpos (sentinel resolution + cycle
    /// reset).
    #[tokio::test]
    async fn test_full_scroll_cycle_via_widget_timer() {
        // Use width=4 with filltext "ab" so the cycle is observable
        // in a reasonable number of ticks.
        let nt = TuiNewsticker::new_i(4, "ab", test_colors()).expect("new_i should succeed");
        let mut owned = Arc::try_unwrap(nt)
            .map_err(|_| ())
            .expect("test holds the only reference");

        let mut renderer = NullRenderer::default();

        // Phase 1: draw resolves sentinel to width-1 = 3.
        // Draw does NOT advance struct textpos (FASM: only timer
        // advances textpos in struct).
        owned.draw(&mut renderer).expect("draw");
        assert_eq!(owned.current_scrollpos(), 3);
        assert_eq!(owned.current_textpos(), 0);

        // Phase 2: timer ticks decrement scrollpos from 3 down to 0.
        Widget::timer(&mut owned);
        assert_eq!(owned.current_scrollpos(), 2);
        Widget::timer(&mut owned);
        assert_eq!(owned.current_scrollpos(), 1);
        Widget::timer(&mut owned);
        assert_eq!(owned.current_scrollpos(), 0);
        // textpos still 0 — only decrements happened.
        assert_eq!(owned.current_textpos(), 0);

        // Phase 3: timer ticks at scrollpos==0 increment struct
        // textpos. After 2 ticks, textpos = 2 = chars_len.
        Widget::timer(&mut owned);
        assert_eq!(owned.current_scrollpos(), 0);
        assert_eq!(owned.current_textpos(), 1);
        Widget::timer(&mut owned);
        assert_eq!(owned.current_scrollpos(), 0);
        assert_eq!(owned.current_textpos(), 2);

        // Phase 4: draw observes textpos >= chars_len and resets
        // both fields for the next cycle.
        owned.draw(&mut renderer).expect("draw");
        assert_eq!(owned.current_scrollpos(), SCROLLPOS_RESET_SENTINEL);
        assert_eq!(owned.current_textpos(), 0);

        owned.cleanup();
    }

    /// Downcast from `Arc<dyn Widget>` recovers the concrete type.
    #[tokio::test]
    async fn test_as_any_downcast_recovers_concrete_type() {
        let nt: Arc<TuiNewsticker> =
            TuiNewsticker::new_i(10, "test", test_colors()).expect("new_i should succeed");
        let dyn_handle: Arc<dyn Widget> = nt.clone() as Arc<dyn Widget>;
        let concrete = dyn_handle
            .as_any()
            .downcast_ref::<TuiNewsticker>()
            .expect("downcast must succeed");
        assert!(std::ptr::eq(Arc::as_ptr(&nt), concrete as *const TuiNewsticker));
        drop(dyn_handle);
        Arc::try_unwrap(nt).map(|mut owned| owned.cleanup()).ok();
    }

    /// Validate that the framework's external `cleanup_widget`
    /// entry point works correctly (no infinite recursion). This
    /// is the canonical "parent destroys child" cleanup path.
    #[tokio::test]
    async fn test_cleanup_widget_external_entry_point() {
        use crate::tui::object::cleanup_widget;
        let nt = TuiNewsticker::new_i(20, "ticker", test_colors()).expect("new_i should succeed");
        let mut owned = Arc::try_unwrap(nt)
            .map_err(|_| ())
            .expect("test holds the only reference");

        // Verify timer is set BEFORE cleanup_widget.
        let timer_before = match owned.inner.lock() {
            Ok(g) => g.timer.is_some(),
            Err(p) => p.into_inner().timer.is_some(),
        };
        assert!(timer_before);

        // Drive cleanup through the framework's external entry point.
        // This MUST terminate (no infinite recursion).
        cleanup_widget(&mut owned);

        // Verify the override fired exactly once: timer slot is None,
        // filltext is empty, state buffers cleared.
        let timer_after = match owned.inner.lock() {
            Ok(g) => g.timer.is_some(),
            Err(p) => p.into_inner().timer.is_some(),
        };
        assert!(!timer_after);
        assert_eq!(owned.state().text.as_slice().len(), 0);
        assert_eq!(owned.state().attributes.cells.len(), 0);
    }

    /// Test helper — pure no-op renderer for `Widget::draw` tests.
    /// `draw` does not actually invoke any [`Renderer`] methods (it
    /// only mutates internal state buffers and dispatches the
    /// display-list update via the trait default), so the methods
    /// here can return trivial defaults.
    #[derive(Default)]
    struct NullRenderer {
        state: crate::tui::render::RenderState,
    }

    impl Renderer for NullRenderer {
        fn ansi_output(&mut self, _bytes: &[u8]) -> Result<(), TuiError> {
            Ok(())
        }
        fn flush(&mut self) -> Result<(), TuiError> {
            Ok(())
        }
        fn state(&self) -> &crate::tui::render::RenderState {
            &self.state
        }
        fn state_mut(&mut self) -> &mut crate::tui::render::RenderState {
            &mut self.state
        }
    }
}
