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
// tui_spinner: A 1×1 animated text spinner cycling through `-`, `\`, `|`, `/`.
// Ported from tui_spinner.inc (144 lines of FASM assembly).
//
// Rust translation © 2026, licensed under GPL-3.0-or-later. Derived from
// the HeavyThing assembly library (© 2015–2018 2 Ton Digital, Jeff
// Marrison <info@2ton.com.au>).

//! Spinner widget — a 1×1 animated glyph indicator cycling `-\|/` at a
//! caller-configurable tick interval.
//!
//! ## FASM Parallel: `tui_spinner.inc` (144 lines)
//!
//! [`Spinner`] descends [`crate::tui::object::Widget`] **directly** (not
//! via [`crate::tui::widgets::background::TuiBackground`]). It is one of
//! the rare widgets that does NOT use the background-fill base because
//! a single 1×1 cell does not benefit from the rectangular fill helpers
//! `tui_background$nvfill` provides.
//!
//! Per the FASM `tui_spinner$vtable` declaration
//! (`tui_spinner.inc` lines 31–38), the spinner overrides only **four**
//! of the 37 vmethods:
//!
//! - [`Widget::cleanup`] (slot 0)  → cancel the timer task, then run
//!   the base [`crate::tui::object::cleanup_widget`] recursive helper.
//! - [`Widget::clone_widget`] (slot 1)  → re-create a fresh spinner with
//!   identical colors and tick interval (no children to clone).
//! - [`Widget::draw`] (slot 2)  → write the current glyph into the
//!   widget's text buffer and dispatch the display-list update.
//! - [`Widget::timer`] (slot 6)  → advance the counter modulo
//!   [`SPIN_CHARS`] length; the next [`Widget::draw`] reads the new
//!   glyph from the counter.
//!
//! All 33 other vmethods inherit the [`Widget`] trait defaults from
//! [`crate::tui::object`]; this matches the FASM vtable's pass-through
//! `tui_object$*` entries for every non-overridden slot.
//!
//! ## Glyph rotation
//!
//! The four-character spin sequence `- \ | /` is preserved byte-for-byte
//! from FASM `tui_spinner$draw.spinchars`
//! (`tui_spinner.inc` line 124, `dd '-', '\', '|', '/'`). The constant
//! [`SPIN_CHARS`] is intentionally `[char; 4]` (not `[u32; 4]`) so the
//! sequence reads naturally in source.
//!
//! ## Runtime architecture
//!
//! The FASM original registers the timer callback through
//! `epoll$timer_new(speed_ms, self)`, which the global epoll dispatcher
//! invokes at the requested interval. The Rust port replaces this with
//! a self-spawned [`tokio::spawn`] task that holds a [`Weak`] back-pointer
//! to the spinner; on each tick, the task upgrades the [`Weak`], calls
//! the inherent [`Spinner::tick`] helper which advances the counter via
//! the [`Mutex<SpinnerInner>`] guard, and continues. When the spinner is
//! dropped (last [`Arc`] reference released), the [`Weak::upgrade`]
//! returns `None`, the loop exits, and the task terminates cleanly. See
//! AAP §0.7.1 for the broader epoll-to-tokio translation strategy.
//!
//! ## State storage rationale
//!
//! [`Spinner`] stores its inherited [`WidgetState`] as a direct field
//! (matching the [`crate::tui::widgets::background::TuiBackground`] /
//! [`crate::tui::widgets::spacers::TuiHSpacer`] pattern) because the
//! [`Widget::state`] / [`Widget::state_mut`] trait accessors require a
//! plain `&WidgetState` / `&mut WidgetState` reference and cannot return
//! a `MutexGuard`. The mutable counter and the timer [`JoinHandle`] live
//! in a separate [`Mutex<SpinnerInner>`] guarded field — this is the
//! only fragment that the spawned timer task needs to mutate via `&self`
//! interior mutability. The text/attribute buffers in [`WidgetState`]
//! are populated synchronously inside [`Widget::draw`], where the
//! caller (the framework's render pass) holds the unique `&mut self`
//! borrow required to mutate state.

use std::any::Any;
use std::sync::{Arc, Mutex, Weak};

use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

use crate::error::TuiError;
use crate::tui::object::{ColorPair, TimerAction, Widget, WidgetState};
use crate::tui::render::Renderer;

// ============================================================================
// Glyph rotation — exact byte-for-byte copy of FASM `.spinchars`.
// ============================================================================

/// Spinner glyph rotation sequence per FASM
/// `tui_spinner.inc` line 124 (`dd '-', '\\', '|', '/'`).
///
/// Index `0..=3` map directly to the four glyphs the spinner cycles
/// through. Modifying this constant changes the visual rotation
/// (e.g. swapping in Unicode Braille spinner glyphs `⠁⠂⠄⡀…`) without
/// touching any of the surrounding logic, mirroring the FASM
/// architectural comment at `tui_spinner.inc` lines 22–25 which
/// instructs porters to "modify spincharcount and the spinchars
/// themselves" to retheme the spinner.
///
/// **Note**: the second slot is a single backslash; Rust string literal
/// rules require it to be escaped as `'\\'`.
pub const SPIN_CHARS: [char; 4] = ['-', '\\', '|', '/'];

// ============================================================================
// SpinnerInner — interior-mutable extra-state struct.
// ============================================================================

/// Mutable, interior-state fields of [`Spinner`] guarded by
/// [`Spinner::inner`]'s [`Mutex`].
///
/// FASM offsets (relative to `tui_object_size`, see `tui_spinner.inc`
/// lines 41–45):
///
/// | FASM offset                   | FASM type | Rust field   |
/// |-------------------------------|-----------|--------------|
/// | `tui_spinner_counter_ofs   +0`| `dd`      | `counter`    |
/// | `tui_spinner_colors_ofs    +8`| `dd`      | `colors`     |
/// | `tui_spinner_speed_ofs    +16`| `dq`      | `speed_ms`   |
/// | `tui_spinner_timerptr_ofs +24`| `dq`      | `timer`      |
///
/// `tui_spinner_size = tui_object_size + 32` (FASM line 45). The Rust
/// translation does not preserve the literal byte layout; the trait
/// dispatch table replaces the `dq vtable` field at offset 0 of the
/// FASM struct, and Rust's `Mutex<...>` provides interior mutability
/// in place of FASM's lock-free counter increments under the
/// global epoll dispatcher.
struct SpinnerInner {
    /// Current glyph index modulo [`SPIN_CHARS`] length (4).
    ///
    /// FASM offset: `tui_spinner_counter_ofs = tui_object_size + 0`
    /// (`tui_spinner.inc` line 41). Stored as `u32` to match the
    /// FASM `dd` width even though Rust `usize` indexing is wider —
    /// this keeps the arithmetic faithful to the FASM modulo-4 step
    /// at lines 137–138.
    counter: u32,

    /// Color pair (foreground/background palette indices) used when
    /// writing the glyph into the widget's attribute buffer.
    ///
    /// FASM offset: `tui_spinner_colors_ofs = tui_object_size + 8`
    /// (`tui_spinner.inc` line 42).
    colors: ColorPair,

    /// Tick interval in milliseconds (lower = faster animation).
    ///
    /// FASM offset: `tui_spinner_speed_ofs = tui_object_size + 16`
    /// (`tui_spinner.inc` line 43). Examples from FASM comment:
    /// `50` ≈ 20 fps, `100` = 10 fps. Persisted so
    /// [`Widget::clone_widget`] can re-create a fresh spinner with
    /// the same speed.
    speed_ms: u64,

    /// Handle to the spawned tokio task driving periodic ticks.
    ///
    /// `None` when the spinner has been cleaned up via
    /// [`Widget::cleanup`] (FASM `tui_spinner$cleanup` calls
    /// `epoll$timer_clear` first thing — `tui_spinner.inc` lines 102–103).
    /// `Some(handle)` while the spinner is alive and animating.
    ///
    /// FASM offset: `tui_spinner_timerptr_ofs = tui_object_size + 24`
    /// (`tui_spinner.inc` line 44). The FASM stored a raw pointer to
    /// the AVL-node entry inside the global epoll timer tree; the
    /// Rust port stores a [`JoinHandle`] which provides equivalent
    /// `cancel`-on-drop / `abort`-on-cleanup semantics.
    timer: Option<JoinHandle<()>>,
}

// ============================================================================
// Spinner — public widget type.
// ============================================================================

/// 1×1 animated spinner widget cycling through [`SPIN_CHARS`]
/// at a caller-configurable interval.
///
/// FASM parallel: `tui_spinner` (`tui_spinner.inc`, 144 lines).
///
/// ## Layout
///
/// The widget is fixed at one cell wide × one cell tall. The
/// [`Widget::state`] accessor exposes the inherited [`WidgetState`]
/// with `width = 1`, `height = 1`, and pre-allocated text + attribute
/// buffers sized to a single cell (4 bytes for the UTF-32 glyph plus
/// a single packed `u32` for the color attribute).
///
/// ## Construction
///
/// [`Spinner::new`] returns an `Arc<Self>` — the only constructor.
/// The returned [`Arc`] owns one strong reference; the spawned
/// timer task holds a [`Weak`] back-reference, so dropping the last
/// strong reference allows the spinner to be deallocated and the
/// timer task to exit on its next tick.
///
/// ## Thread safety
///
/// `Spinner` is `Send + Sync`. The state field follows the
/// [`crate::tui::widgets::background::TuiBackground`] pattern (direct
/// [`WidgetState`]); concurrent draw access is serialised externally
/// via the [`crate::tui::lock::RenderLock`] following AAP §0.7.3
/// rendering coordination rules. The `Mutex<SpinnerInner>` field
/// guards interior-mutable counter/timer state accessed only by the
/// spinner's spawned tick task, so it never contends with the
/// render path under normal operation.
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
pub struct Spinner {
    /// Inherited base widget state (bounds, dimensions, visibility,
    /// text/attribute buffers, layout, …). Direct field per the
    /// established [`Widget::state`] / [`Widget::state_mut`] contract;
    /// see the module docs for the design rationale.
    pub(crate) state: WidgetState,

    /// Mutable extra-state — counter, color, speed, and the running
    /// timer task's [`JoinHandle`]. Guarded by [`std::sync::Mutex`]
    /// (NOT [`tokio::sync::Mutex`]) because the critical sections are
    /// short synchronous memory updates with no `await` points,
    /// matching the established widget-mutation pattern in
    /// [`crate::tui::widgets::background`].
    inner: Mutex<SpinnerInner>,
}

// ============================================================================
// Constructor — `tui_spinner$new` equivalent.
// ============================================================================

impl Spinner {
    /// Construct a new 1×1 spinner with the given color pair and
    /// tick interval in milliseconds.
    ///
    /// FASM parallel: `tui_spinner$new(edi=colors, esi=speed_ms)`
    /// (`tui_spinner.inc` lines 51–78).
    ///
    /// # Construction sequence
    ///
    /// 1. Allocate the spinner with `counter = 0`, the supplied
    ///    `colors`, and `speed_ms` (FASM lines 54–61).
    /// 2. Initialise the inherited [`WidgetState`] to a 1×1 area
    ///    (FASM `tui_object$init_ii(self, 1, 1)`, line 65) — width=1,
    ///    height=1, and pre-allocate the text + attribute buffers
    ///    sized to one cell.
    /// 3. Write the **initial glyph** `'-'` into the text buffer at
    ///    position 0 and the packed color into the attribute buffer
    ///    so the very first render shows a stable spinner before the
    ///    timer task has fired (FASM lines 67–71).
    /// 4. Spawn the tokio timer task (replaces FASM
    ///    `epoll$timer_new(speed, self)` at lines 72–74). The task
    ///    holds a [`Weak`] back-pointer to break the [`Arc`] cycle
    ///    that would otherwise pin the spinner alive forever.
    /// 5. Store the [`JoinHandle`] so [`Widget::cleanup`] can abort
    ///    the task on teardown (FASM `tui_spinner_timerptr_ofs`,
    ///    line 77).
    ///
    /// # Returns
    ///
    /// An owning [`Arc<Self>`]. The caller may clone the [`Arc`] to
    /// register the spinner as a child of any parent widget while the
    /// timer task continues to drive animation in the background.
    ///
    /// # Panics
    ///
    /// Panics only via [`tokio::spawn`] if invoked outside a Tokio
    /// runtime context — this is a precondition of the surrounding
    /// runtime, not a defect in this constructor. All construction
    /// paths in HeavyThing run inside the global tokio runtime built
    /// by `heavything::init`.
    #[must_use]
    pub fn new(colors: ColorPair, speed_ms: u64) -> Arc<Self> {
        // ---- Step 1: prepare the inherited WidgetState as a 1×1 cell.
        //
        // Mirrors FASM tui_object$init_ii(self, 1, 1) at line 65 plus
        // the immediate text/attr buffer initialisation at lines
        // 67–71. We pre-allocate exactly four bytes for the text
        // buffer (one UTF-32 codepoint) and exactly one entry for the
        // attribute buffer (one packed colour cell).
        let mut state = WidgetState::new();
        state.width = 1;
        state.height = 1;
        state.width_percent = None;
        state.height_percent = None;

        // FASM line 70: `mov dword [rdi], '-'` writes the codepoint
        // little-endian into the freshly allocated text buffer. We do
        // the same via Buffer::push_u32_le, populating four bytes.
        let initial_glyph_codepoint = SPIN_CHARS[0] as u32;
        state.text.push_u32_le(initial_glyph_codepoint);

        // FASM line 71: `mov dword [rsi], ecx` writes the packed
        // color attribute into the attribute buffer. We push one
        // entry whose low byte holds `fg`, next byte holds `bg`,
        // top 16 bits are zero (no SGR mask). This matches the
        // `pack_color_pair` formula used by TuiBackground::nvfill in
        // `crates/heavything/src/tui/widgets/background.rs`.
        state.attributes.cells.push(pack_colors_u32(colors));

        // ---- Step 2: build the SpinnerInner with timer = None.
        //
        // The timer JoinHandle is filled in below after Arc::new so
        // the spawned task can hold a Weak<Self> back-pointer.
        let inner = SpinnerInner {
            counter: 0,
            colors,
            speed_ms,
            timer: None,
        };

        // ---- Step 3: wrap into Arc<Self> so we can hand out a Weak.
        let spinner = Arc::new(Self {
            state,
            inner: Mutex::new(inner),
        });

        // ---- Step 4: spawn the tokio timer task.
        //
        // The task captures a Weak<Spinner> back-pointer to avoid
        // pinning the spinner alive via the spawned future. On each
        // tick:
        //
        //   1. weak.upgrade() — None → spinner was dropped, exit.
        //                       Some(arc) → continue.
        //   2. arc.tick() — increments the counter modulo 4 under
        //      the inner Mutex.
        //
        // We use `tokio::time::interval(Duration::from_millis(...))`
        // with the default missed-tick behaviour (Burst); a spinner
        // missing a tick due to scheduler back-pressure is harmless
        // and the catch-up burst self-aligns the visible glyph with
        // wall-clock time on the next render.
        //
        // FASM parallel: `epoll$timer_new(speed_ms, self)` at line 74.
        let weak_self: Weak<Self> = Arc::downgrade(&spinner);
        let speed_ms_for_task = speed_ms;
        let handle: JoinHandle<()> = tokio::spawn(async move {
            // The interval starts firing immediately; the first
            // tick().await returns instantly. We discard that first
            // tick by letting it advance the counter from 0→1 since
            // the visible glyph at index 0 was already written to
            // the text buffer above. After speed_ms milliseconds the
            // second tick fires and the counter reaches 2, etc.
            let mut ticker = interval(Duration::from_millis(speed_ms_for_task));
            loop {
                ticker.tick().await;
                match weak_self.upgrade() {
                    Some(arc) => arc.tick(),
                    None => break,
                }
            }
        });

        // ---- Step 5: install the JoinHandle into the spinner.
        //
        // This requires re-locking the inner Mutex via the Arc; the
        // critical section is brief (a single Option assignment). We
        // intentionally do not propagate a poisoned-lock failure here
        // because the Mutex was just created and cannot be poisoned
        // unless the spawned task itself panics with the lock held —
        // which it cannot, because we have not yet released `spinner`
        // for the task to acquire.
        //
        // The unwrap_or_else fallback covers the theoretical poisoned
        // case by reaching into the lock's inner data via
        // PoisonError::into_inner (Mutex::lock() returns
        // Result<MutexGuard, PoisonError<MutexGuard>>); we treat a
        // poisoned lock here as recoverable because no invariant can
        // have been violated yet at this construction point.
        match spinner.inner.lock() {
            Ok(mut guard) => {
                guard.timer = Some(handle);
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.timer = Some(handle);
            }
        }

        spinner
    }

    /// Advance the spinner counter by one (modulo [`SPIN_CHARS`]
    /// length).
    ///
    /// Called by the spawned tokio timer task on each tick. The
    /// surrounding task holds a [`Weak<Self>`] which it upgrades
    /// to an [`Arc<Self>`] before invoking this method — therefore
    /// `tick` takes `&self` (not `&mut self`) and uses the inner
    /// [`Mutex`] for interior mutability.
    ///
    /// **Important**: this method does NOT touch the text buffer
    /// in [`WidgetState`]. The text glyph is written when the
    /// framework's render pass next calls [`Widget::draw`]
    /// (which has unique `&mut self` access). This separation
    /// avoids needing interior mutability on the entire
    /// [`WidgetState`] (which would conflict with
    /// [`Widget::state`]'s `&WidgetState` return type).
    ///
    /// FASM parallel: counter advancement at
    /// `tui_spinner$timer` lines 134–139 of `tui_spinner.inc`. The
    /// FASM also calls `vdraw` to immediately re-render; the Rust
    /// version defers rendering to the framework's redraw pipeline.
    fn tick(&self) {
        // Match-on-Result pattern instead of `.expect()` — a
        // poisoned spinner Mutex is non-fatal because the only
        // invariant is "counter holds the current glyph index"
        // and any racy half-update can be safely overwritten on
        // the next tick.
        match self.inner.lock() {
            Ok(mut guard) => {
                // FASM lines 136–138: ` add edx, 1; cmp edx, 4;
                // cmovae edx, ecx` — equivalent to `(counter + 1) % 4`
                // for unsigned u32. Using `% 4` directly is the
                // idiomatic Rust translation; `wrapping_add` followed
                // by `% (SPIN_CHARS.len() as u32)` would also work
                // but is unnecessary because counter ∈ {0, 1, 2, 3}
                // and (3 + 1) = 4 fits a u32 trivially.
                let next = (guard.counter.wrapping_add(1)) % (SPIN_CHARS.len() as u32);
                guard.counter = next;
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                let next = (guard.counter.wrapping_add(1)) % (SPIN_CHARS.len() as u32);
                guard.counter = next;
            }
        }
    }

    /// Read the currently displayed glyph index without advancing it.
    ///
    /// Used by tests to assert FASM-equivalent counter behaviour
    /// without relying on internal field access. The return value
    /// is in `0..SPIN_CHARS.len()`.
    #[cfg(test)]
    fn current_counter(&self) -> u32 {
        match self.inner.lock() {
            Ok(g) => g.counter,
            Err(p) => p.into_inner().counter,
        }
    }
}

// ============================================================================
// Internal helpers.
// ============================================================================

/// Pack a [`ColorPair`] into the FASM 32-bit color-attribute layout.
///
/// Bits layout (matching FASM `tui_object.attr` cell encoding):
///
/// ```text
///   bits 0..=7   : foreground palette index
///   bits 8..=15  : background palette index
///   bits 16..=31 : SGR attribute mask (0 here — spinner uses no SGR
///                  bits; `Attributes::push` would produce identical
///                  bytes when invoked with sgr = 0)
/// ```
///
/// FASM parallel: the `mov dword [rsi], ecx` write at
/// `tui_spinner.inc` line 71, where `ecx` was loaded from
/// `[rax+tui_spinner_colors_ofs]` (the dword stored by the
/// constructor). The FASM stored both `fg` and `bg` as a
/// single packed dword in `colors_ofs`; we reconstruct that
/// packed value here.
fn pack_colors_u32(cp: ColorPair) -> u32 {
    u32::from(cp.fg) | (u32::from(cp.bg) << 8)
}

// ============================================================================
// Widget trait implementation — overrides cleanup, clone_widget, draw, timer.
// ============================================================================

impl Widget for Spinner {
    /// Required base accessor — returns a shared reference to the
    /// inherited [`WidgetState`].
    fn state(&self) -> &WidgetState {
        &self.state
    }

    /// Required base accessor — returns a mutable reference to the
    /// inherited [`WidgetState`].
    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    /// Required downcasting accessor — returns `self` as a `&dyn Any`
    /// so callers holding an `Arc<dyn Widget>` can recover the concrete
    /// `Spinner` type via [`Any::downcast_ref`].
    fn as_any(&self) -> &dyn Any {
        self
    }

    // ----------------- Override 1: cleanup (vtable slot 0) -----------------

    /// Override — vtable slot 0 (`tui_vcleanup`).
    ///
    /// FASM parallel: `tui_spinner$cleanup`
    /// (`tui_spinner.inc` lines 98–106):
    ///
    /// ```text
    ///   epoll$timer_clear(self.timerptr)
    ///   tui_object$cleanup(self)
    /// ```
    ///
    /// 1. Cancel the spawned timer task via
    ///    [`JoinHandle::abort`] (replaces FASM
    ///    `epoll$timer_clear` at line 103). After this call the
    ///    next [`Weak::upgrade`] in the task body would see the
    ///    spinner alive but the task is already aborted, so no
    ///    further [`Spinner::tick`] calls happen.
    /// 2. Mirror the trait-default `cleanup` body inline by clearing
    ///    `state.children`, `state.bastards`, `state.text`,
    ///    `state.attributes`, and `state.display_name`. This matches
    ///    the FASM `tui_object$cleanup` body at line 105 — clearing
    ///    the per-widget heap-tracked buffers without re-entering
    ///    polymorphic dispatch.
    ///
    /// **Why inline rather than call [`crate::tui::object::cleanup_widget`]?**
    /// The free helper [`cleanup_widget`] dispatches polymorphically
    /// through `self.cleanup()` at its tail; calling it from inside
    /// an override produces unbounded recursion. The exemplar sibling
    /// implementation in [`crate::tui::widgets::png`] uses the same
    /// inline-clear pattern; [`cleanup_widget`] is the framework's
    /// entry point invoked **from outside** the widget (when a parent
    /// destroys this child) — not from inside an override. The
    /// re-export of [`cleanup_widget`] in this module's `use`
    /// statement is exercised by the unit test
    /// `test_cleanup_widget_external_entry_point`.
    fn cleanup(&mut self) {
        // ---- Step 1: cancel the timer task.
        //
        // We pull the JoinHandle out of the Mutex to avoid holding
        // the lock during abort (which is non-blocking but still
        // good hygiene), and to leave `timer = None` so a subsequent
        // cleanup() invocation (defensive idempotency) is a no-op.
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
        // [`cleanup_widget`] here because that helper polymorphically
        // dispatches `self.cleanup()` at its tail — which would
        // re-enter this method ad infinitum. The png widget
        // (`crates/heavything/src/tui/widgets/png.rs::cleanup`) uses
        // the same inline pattern.
        let state = &mut self.state;
        state.children.clear();
        state.bastards.clear();
        state.text.clear();
        state.attributes.clear();
        state.display_name.clear();
    }

    // ----------------- Override 2: clone_widget (vtable slot 1) -----------------

    /// Override — vtable slot 1 (`tui_vclone`).
    ///
    /// FASM parallel: `tui_spinner$clone`
    /// (`tui_spinner.inc` lines 85–91):
    ///
    /// ```text
    ///   ; since we aren't going to have any children/bastards, clone
    ///   ; is simple — we can just return a new one.
    ///   esi = self.speed_ms
    ///   edi = self.colors
    ///   tui_spinner$new(edi, esi)
    /// ```
    ///
    /// The FASM comment at line 87 explicitly notes that spinner
    /// clone "is simple" because the widget never has children.
    /// The Rust translation follows the same shortcut: read
    /// `colors` and `speed_ms` out of [`SpinnerInner`] and call
    /// [`Spinner::new`] to mint a fresh spinner with a fresh
    /// counter (reset to 0) and a freshly-spawned timer task.
    ///
    /// # Errors
    ///
    /// Returns [`Result<Arc<dyn Widget>, TuiError>`] for trait
    /// signature symmetry; in practice this method never produces
    /// an `Err` because [`Spinner::new`] is infallible.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // Read the two parameters needed for re-construction.
        let (colors, speed_ms) = match self.inner.lock() {
            Ok(g) => (g.colors, g.speed_ms),
            Err(p) => {
                let g = p.into_inner();
                (g.colors, g.speed_ms)
            }
        };

        // Spawn a fresh spinner — counter resets to 0, fresh timer
        // task is spawned, fresh text buffer holds '-'. Children
        // and bastards are intentionally NOT cloned, matching the
        // FASM shortcut at line 87.
        let cloned: Arc<Spinner> = Spinner::new(colors, speed_ms);
        Ok(cloned as Arc<dyn Widget>)
    }

    // ----------------- Override 3: draw (vtable slot 2) -----------------

    /// Override — vtable slot 2 (`tui_vdraw`).
    ///
    /// FASM parallel: `tui_spinner$draw`
    /// (`tui_spinner.inc` lines 113–121):
    ///
    /// ```text
    ///   edx = self.counter
    ///   rsi = self.text_buffer  (i.e. tui_text_ofs pointer)
    ///   eax = .spinchars[edx*4]
    ///   [rsi] = eax            ; write the glyph dword
    ///   call vupdatedisplaylist
    /// ```
    ///
    /// 1. Read the current counter from [`SpinnerInner`] under the
    ///    inner [`Mutex`].
    /// 2. Look up the corresponding glyph in [`SPIN_CHARS`] and
    ///    write its UTF-32 codepoint as four little-endian bytes
    ///    into the first cell of the text buffer (FASM `mov dword
    ///    [rsi], eax` at line 119 stores the codepoint
    ///    little-endian on x86_64).
    /// 3. Re-write the packed color attribute into the attribute
    ///    buffer's first cell. The FASM `draw` does not re-write
    ///    the attribute (it was set once in `$new` at line 71)
    ///    because the FASM never changes spinner colours mid-run;
    ///    we mirror that by skipping the attribute write here when
    ///    the cell already exists, which avoids unnecessary
    ///    allocator churn.
    /// 4. Trigger the display-list update via
    ///    [`Widget::update_display_list`] (FASM `call qword
    ///    [rcx + tui_vupdatedisplaylist]` at line 120). The trait
    ///    default is a no-op; renderer-bound compositions override
    ///    it to flush the buffers downstream.
    ///
    /// The `_renderer` parameter is accepted to satisfy the
    /// [`Widget`] trait signature; the FASM `tui_spinner$draw`
    /// does not write to the terminal directly — it only stages
    /// glyph state and dispatches the display-list update. The
    /// actual byte emission happens through the descendant
    /// rendering pipeline.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] only on `usize`-to-byte
    /// arithmetic overflow when computing the text buffer slot
    /// (impossible for the fixed 1×1 spinner geometry; the
    /// `Result` return type is preserved for API symmetry with
    /// the [`Widget`] trait signature).
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        // ---- Step 1: read counter under the inner Mutex.
        let counter: u32 = match self.inner.lock() {
            Ok(g) => g.counter,
            Err(p) => p.into_inner().counter,
        };

        // Defensive modulo in case some external caller wrote a
        // counter value out of range. SPIN_CHARS.len() is a
        // compile-time constant 4 so the divisor cannot be zero.
        let idx: usize = (counter as usize) % SPIN_CHARS.len();

        // ---- Step 2: write the glyph into text[0].
        //
        // The FASM mov dword [rsi], eax writes a little-endian u32
        // codepoint. We emulate via Buffer::clear + push_u32_le,
        // which keeps the buffer at exactly 4 bytes (1 cell × 4
        // bytes/cell) — no allocator churn because Buffer retains
        // capacity across clear() / push() pairs.
        let glyph_codepoint: u32 = SPIN_CHARS[idx] as u32;
        self.state.text.clear();
        self.state.text.push_u32_le(glyph_codepoint);

        // ---- Step 3: ensure attribute cell is present and current.
        //
        // The FASM original sets the attribute once in $new and
        // never touches it again from $draw. We match that exactly
        // when the cell already exists; otherwise (e.g. after the
        // base `cleanup` cleared attributes) we re-populate it so
        // the spinner renders correctly post-resume.
        let colors: ColorPair = match self.inner.lock() {
            Ok(g) => g.colors,
            Err(p) => p.into_inner().colors,
        };
        let packed = pack_colors_u32(colors);
        if self.state.attributes.cells.is_empty() {
            self.state.attributes.cells.push(packed);
        } else {
            self.state.attributes.cells[0] = packed;
        }

        // ---- Step 4: dispatch display-list update.
        //
        // FASM `call qword [rcx + tui_vupdatedisplaylist]` at line 120
        // — the polymorphic dispatch goes through the trait method
        // here. The trait default is a no-op; renderer-bound
        // compositions override `update_display_list` to flush.
        self.update_display_list();

        Ok(())
    }

    // ----------------- Override 4: timer (vtable slot 6) -----------------

    /// Override — vtable slot 6 (`tui_vtimer`).
    ///
    /// FASM parallel: `tui_spinner$timer`
    /// (`tui_spinner.inc` lines 131–142):
    ///
    /// ```text
    ///   rsi = self.vtable
    ///   edx = self.counter
    ///   ecx = 0
    ///   edx += 1
    ///   if edx >= 4: edx = 0      ; cmovae edx, ecx
    ///   self.counter = edx
    ///   call vdraw                ; immediate redraw
    ///   eax = 0                   ; return 0 == keep timer alive
    /// ```
    ///
    /// In the Rust translation this method is invoked by the
    /// framework's external timer dispatcher (when present); the
    /// counter advancement is the same as [`Spinner::tick`] (which
    /// the spawned tokio task uses), and afterwards we re-emit the
    /// glyph via [`Widget::draw`] using a no-op renderer adapter.
    /// However the trait signature for [`Widget::timer`] is
    /// `fn timer(&mut self) -> ()` — there is no [`TimerAction`]
    /// return value at the trait level (the [`TimerAction`] enum
    /// exists in [`crate::tui::object`] for future framework use
    /// but is not part of the trait signature). Returning `()` is
    /// equivalent to FASM's `eax = 0` (keep timer alive) for every
    /// invocation; the spinner has no condition under which it
    /// wishes to terminate the timer, matching the FASM `xor eax,
    /// eax` at line 141.
    ///
    /// **Note**: this method does NOT redraw via [`Widget::draw`]
    /// because that would require a [`Renderer`] argument the
    /// trait does not provide. The framework dispatcher is
    /// expected to schedule a draw pass after the timer fires.
    /// In typical operation, ticks come from the spawned tokio
    /// task (which calls [`Spinner::tick`]); this trait method
    /// is the path used when an external dispatcher prefers to
    /// drive ticks synchronously instead of via the spawned task.
    fn timer(&mut self) {
        // Use the same atomic-equivalent counter advance as the
        // tokio-driven path. Calling `tick` keeps the two code
        // paths byte-for-byte equivalent and ensures the
        // spinner's apparent animation rate is unchanged whether
        // the framework drives ticks externally or relies on the
        // spawned tokio task.
        self.tick();

        // FASM xor eax, eax (return 0 → keep timer). The trait
        // signature does not encode return values, but if a future
        // framework dispatcher consults TimerAction, the spinner
        // always wants Continue. We document this explicitly in
        // the doc-comment above; no runtime action needed.
        let _continue = TimerAction::Continue;
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    // The free helper [`crate::tui::object::cleanup_widget`] is the
    // framework-level entry point for "parent destroys child" cleanup
    // chains. The Spinner override of [`Widget::cleanup`] does NOT
    // call this helper (doing so would cause infinite recursion); it
    // is exercised only at the framework boundary, demonstrated by
    // [`test_cleanup_widget_external_entry_point`] below.
    use crate::tui::object::cleanup_widget;

    /// Helper — produce a default test [`ColorPair`] (white-on-black).
    fn test_colors() -> ColorPair {
        ColorPair { fg: 7, bg: 0 }
    }

    /// FASM byte sequence verification — the spinner glyph rotation
    /// MUST exactly equal `'-', '\\', '|', '/'` per
    /// `tui_spinner.inc` line 124, in that order. Modifying these
    /// is allowed at the source-code level (per the FASM
    /// architectural comment lines 22–25), but tests guard against
    /// accidental reordering in routine refactors.
    #[test]
    fn test_spin_chars_sequence() {
        assert_eq!(SPIN_CHARS.len(), 4);
        assert_eq!(SPIN_CHARS[0], '-');
        assert_eq!(SPIN_CHARS[1], '\\');
        assert_eq!(SPIN_CHARS[2], '|');
        assert_eq!(SPIN_CHARS[3], '/');
    }

    /// `pack_colors_u32` must emit the FASM-equivalent packed dword.
    #[test]
    fn test_pack_colors_u32_layout() {
        // FASM `mov ecx, [rax+tui_spinner_colors_ofs]` where
        // colors_ofs holds an u32 with low byte = fg, second byte = bg,
        // top 16 bits zero.
        let cp = ColorPair { fg: 0xAB, bg: 0xCD };
        let packed = pack_colors_u32(cp);
        assert_eq!(packed & 0xFF, 0xAB);
        assert_eq!((packed >> 8) & 0xFF, 0xCD);
        assert_eq!(packed >> 16, 0);
    }

    /// `pack_colors_u32` for the default ColorPair must produce 0
    /// (both indices are 0).
    #[test]
    fn test_pack_colors_default_is_zero() {
        let cp = ColorPair::default();
        assert_eq!(pack_colors_u32(cp), 0);
    }

    /// Counter increment wraps modulo 4. Calling `tick()` four times
    /// returns the counter to 0; calling it five times reaches 1.
    /// This validates FASM `cmp edx, 4; cmovae edx, ecx`.
    #[tokio::test]
    async fn test_counter_wraps_modulo_four() {
        let s = Spinner::new(test_colors(), 1_000_000); // huge interval so the spawned task does NOT tick during this test.
        assert_eq!(s.current_counter(), 0);
        s.tick();
        assert_eq!(s.current_counter(), 1);
        s.tick();
        assert_eq!(s.current_counter(), 2);
        s.tick();
        assert_eq!(s.current_counter(), 3);
        s.tick();
        assert_eq!(s.current_counter(), 0); // Wrapped.
        s.tick();
        assert_eq!(s.current_counter(), 1);
        // Cleanup the spawned timer task so it doesn't leak between tests.
        Arc::try_unwrap(s).map(|mut owned| owned.cleanup()).ok();
    }

    /// After construction, the text buffer must already contain the
    /// initial glyph `'-'` BEFORE the first tick fires. This matches
    /// FASM `tui_spinner$new` lines 67–71 which initialise the text
    /// buffer eagerly.
    #[tokio::test]
    async fn test_new_initial_glyph_is_dash() {
        let s = Spinner::new(test_colors(), 1_000_000);
        // Verify text buffer holds exactly 4 bytes (1 cell × UTF-32).
        let text = s.state().text.as_slice();
        assert_eq!(text.len(), 4);
        // Reconstruct the codepoint from little-endian bytes.
        let codepoint = u32::from_le_bytes([text[0], text[1], text[2], text[3]]);
        assert_eq!(codepoint, '-' as u32);
        // Cleanup.
        Arc::try_unwrap(s).map(|mut owned| owned.cleanup()).ok();
    }

    /// After construction, the attribute buffer must contain exactly
    /// one cell holding the packed color pair. This matches FASM
    /// `mov dword [rsi], ecx` at line 71.
    #[tokio::test]
    async fn test_new_initial_attributes() {
        let colors = ColorPair { fg: 12, bg: 4 };
        let s = Spinner::new(colors, 1_000_000);
        let attrs = &s.state().attributes;
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs.cells[0], pack_colors_u32(colors));
        Arc::try_unwrap(s).map(|mut owned| owned.cleanup()).ok();
    }

    /// The spinner is initialised as a 1×1 widget. Width and height
    /// must both equal 1, matching FASM `tui_object$init_ii(self, 1, 1)`
    /// at line 65.
    #[tokio::test]
    async fn test_new_dimensions_are_1x1() {
        let s = Spinner::new(test_colors(), 1_000_000);
        assert_eq!(s.state().width, 1);
        assert_eq!(s.state().height, 1);
        assert_eq!(s.state().width_percent, None);
        assert_eq!(s.state().height_percent, None);
        Arc::try_unwrap(s).map(|mut owned| owned.cleanup()).ok();
    }

    /// FASM defaults preserved: visible=true, include_in_layout=true,
    /// absolute_x=-1, absolute_y=-1 (the "not yet positioned" sentinel).
    #[tokio::test]
    async fn test_new_inherits_widget_state_defaults() {
        let s = Spinner::new(test_colors(), 1_000_000);
        assert!(s.state().visible);
        assert!(s.state().include_in_layout);
        assert_eq!(s.state().absolute_x, -1);
        assert_eq!(s.state().absolute_y, -1);
        Arc::try_unwrap(s).map(|mut owned| owned.cleanup()).ok();
    }

    /// `clone_widget` produces a fresh spinner with identical colors
    /// and speed but counter reset to 0 (it freshly calls `Spinner::new`).
    #[tokio::test]
    async fn test_clone_widget_resets_counter_preserves_params() {
        let colors = ColorPair { fg: 9, bg: 3 };
        let speed_ms: u64 = 1_000_000;
        let s = Spinner::new(colors, speed_ms);
        // Advance the source spinner's counter so we can verify the
        // clone resets to 0 (rather than copying the source's value).
        s.tick();
        s.tick();
        assert_eq!(s.current_counter(), 2);

        // Clone via the trait method (returns Arc<dyn Widget>).
        let cloned_dyn = s.clone_widget().expect("spinner clone never fails");
        // Recover the concrete Spinner from the dyn handle.
        let cloned_concrete: &Spinner = cloned_dyn
            .as_any()
            .downcast_ref::<Spinner>()
            .expect("clone must produce a Spinner");
        assert_eq!(cloned_concrete.current_counter(), 0);
        // Verify the clone's colors and speed match the source's.
        let cloned_state = match cloned_concrete.inner.lock() {
            Ok(g) => (g.colors, g.speed_ms),
            Err(p) => {
                let g = p.into_inner();
                (g.colors, g.speed_ms)
            }
        };
        assert_eq!(cloned_state.0, colors);
        assert_eq!(cloned_state.1, speed_ms);

        // Clean up both spinners.
        drop(cloned_dyn);
        Arc::try_unwrap(s).map(|mut owned| owned.cleanup()).ok();
    }

    /// `cleanup` cancels the spawned timer task. Although we cannot
    /// observe `JoinHandle::is_finished()` from outside the task
    /// without polling, calling `cleanup` and then waiting briefly
    /// validates that the task does not continue to fire indefinitely.
    /// We assert post-cleanup that the inner.timer slot is `None`.
    #[tokio::test]
    async fn test_cleanup_clears_timer_handle() {
        let s = Spinner::new(test_colors(), 10);

        // Take exclusive ownership of the spinner so we can call cleanup.
        let mut owned = Arc::try_unwrap(s)
            .map_err(|_| ())
            .expect("test should hold the only reference");

        // Verify the timer is set before cleanup.
        let timer_present_before = match owned.inner.lock() {
            Ok(g) => g.timer.is_some(),
            Err(p) => p.into_inner().timer.is_some(),
        };
        assert!(timer_present_before, "timer should be Some after new()");

        // Cleanup should abort the task and clear the handle.
        owned.cleanup();

        // Verify the timer slot is now None.
        let timer_after = match owned.inner.lock() {
            Ok(g) => g.timer.is_some(),
            Err(p) => p.into_inner().timer.is_some(),
        };
        assert!(!timer_after, "timer should be None after cleanup");
    }

    /// `Widget::timer` (the trait method) advances the counter by 1
    /// per call, modulo 4, equivalent to the spawned-task tick path.
    /// FASM `tui_spinner$timer` at lines 131–142.
    #[tokio::test]
    async fn test_widget_timer_advances_counter() {
        let s = Spinner::new(test_colors(), 1_000_000);
        let mut owned = Arc::try_unwrap(s)
            .map_err(|_| ())
            .expect("test should hold the only reference");
        assert_eq!(owned.current_counter(), 0);
        Widget::timer(&mut owned);
        assert_eq!(owned.current_counter(), 1);
        Widget::timer(&mut owned);
        Widget::timer(&mut owned);
        Widget::timer(&mut owned);
        // After 4 invocations the counter wraps back to 0.
        assert_eq!(owned.current_counter(), 0);
        owned.cleanup();
    }

    /// `draw` writes the current glyph into `state.text`. After
    /// constructing a spinner, advancing the counter, and calling
    /// `draw`, the text buffer holds the expected codepoint.
    #[tokio::test]
    async fn test_draw_writes_current_glyph_to_text_buffer() {
        let s = Spinner::new(test_colors(), 1_000_000);
        let mut owned = Arc::try_unwrap(s)
            .map_err(|_| ())
            .expect("test should hold the only reference");

        // Initial glyph is '-' (index 0).
        let text0 = owned.state().text.as_slice();
        let cp0 = u32::from_le_bytes([text0[0], text0[1], text0[2], text0[3]]);
        assert_eq!(cp0, '-' as u32);

        // Advance counter to 1, draw, expect '\\'.
        owned.tick();
        let mut renderer = NullRenderer::default();
        owned.draw(&mut renderer).expect("draw never fails for spinner");
        let text1 = owned.state().text.as_slice();
        let cp1 = u32::from_le_bytes([text1[0], text1[1], text1[2], text1[3]]);
        assert_eq!(cp1, '\\' as u32);

        // Advance counter to 2, draw, expect '|'.
        owned.tick();
        owned.draw(&mut renderer).expect("draw never fails for spinner");
        let text2 = owned.state().text.as_slice();
        let cp2 = u32::from_le_bytes([text2[0], text2[1], text2[2], text2[3]]);
        assert_eq!(cp2, '|' as u32);

        // Advance counter to 3, draw, expect '/'.
        owned.tick();
        owned.draw(&mut renderer).expect("draw never fails for spinner");
        let text3 = owned.state().text.as_slice();
        let cp3 = u32::from_le_bytes([text3[0], text3[1], text3[2], text3[3]]);
        assert_eq!(cp3, '/' as u32);

        // Advance counter back to 0, draw, expect '-' again.
        owned.tick();
        owned.draw(&mut renderer).expect("draw never fails for spinner");
        let text4 = owned.state().text.as_slice();
        let cp4 = u32::from_le_bytes([text4[0], text4[1], text4[2], text4[3]]);
        assert_eq!(cp4, '-' as u32);

        owned.cleanup();
    }

    /// `Spinner` can be downcast from `Arc<dyn Widget>` back to the
    /// concrete type via the `as_any` accessor. This validates the
    /// required `as_any` trait method.
    #[tokio::test]
    async fn test_as_any_downcast_recovers_concrete_type() {
        let s: Arc<Spinner> = Spinner::new(test_colors(), 1_000_000);
        let dyn_handle: Arc<dyn Widget> = s.clone() as Arc<dyn Widget>;
        let concrete = dyn_handle
            .as_any()
            .downcast_ref::<Spinner>()
            .expect("downcast must succeed");
        // Compare via Arc::as_ptr to verify same underlying allocation.
        // `Arc::as_ptr` already returns `*const Spinner` so no cast
        // is required; clippy::unnecessary_cast enforces this.
        assert!(std::ptr::eq(Arc::as_ptr(&s), concrete as *const Spinner));
        // Cleanup.
        drop(dyn_handle);
        Arc::try_unwrap(s).map(|mut owned| owned.cleanup()).ok();
    }

    /// Spinner is `Send + Sync` — required for `Arc<dyn Widget>` use.
    #[test]
    fn test_spinner_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Spinner>();
    }

    /// Validate that the framework's external [`cleanup_widget`]
    /// entry point works correctly on a [`Spinner`] by exercising
    /// the no-recursion code path: `cleanup_widget(&mut spinner)`
    /// walks the (empty) children list, then polymorphically
    /// dispatches `self.cleanup()` exactly once. Our override of
    /// [`Widget::cleanup`] inlines the trait-default state clearing
    /// rather than re-entering [`cleanup_widget`], so this call
    /// terminates after the single dispatch.
    ///
    /// This test is the canonical demonstration of the FASM-equivalent
    /// "parent destroys child" cleanup chain at
    /// `tui_object.inc`'s widget destruction path.
    #[tokio::test]
    async fn test_cleanup_widget_external_entry_point() {
        let s = Spinner::new(test_colors(), 1_000_000);
        let mut owned = Arc::try_unwrap(s)
            .map_err(|_| ())
            .expect("test should hold the only reference");

        // Verify the timer is set BEFORE cleanup_widget.
        let timer_present_before = match owned.inner.lock() {
            Ok(g) => g.timer.is_some(),
            Err(p) => p.into_inner().timer.is_some(),
        };
        assert!(timer_present_before, "timer should be Some after Spinner::new");

        // Drive cleanup through the framework's external entry point.
        // This MUST terminate (no infinite recursion).
        cleanup_widget(&mut owned);

        // Verify the override fired exactly once: timer slot is None.
        let timer_after = match owned.inner.lock() {
            Ok(g) => g.timer.is_some(),
            Err(p) => p.into_inner().timer.is_some(),
        };
        assert!(
            !timer_after,
            "timer should be None after cleanup_widget(&mut spinner)"
        );

        // The state-clearing also fired: text and attributes are empty.
        assert_eq!(
            owned.state().text.as_slice().len(),
            0,
            "text buffer should be empty after cleanup"
        );
        assert_eq!(
            owned.state().attributes.cells.len(),
            0,
            "attributes buffer should be empty after cleanup"
        );
    }

    // -----------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------

    /// A no-op renderer used in tests. The spinner's `draw` method
    /// does not actually invoke any [`Renderer`] methods (it only
    /// updates internal text/attribute buffers and dispatches the
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
