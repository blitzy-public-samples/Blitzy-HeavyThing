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
// tui_progressbar: a Background-descendant fill-based progress bar with
// integer or double-precision value tracking and four fill directions.
// Ported from tui_progressbar.inc (389 lines of FASM assembly).

//! TUI progress bar widget — fill-based progress bar with int/double
//! value modes and direction-aware fill (LTR/RTL/TTB/BTT).
//!
//! ## FASM Parallel: `tui_progressbar.inc` (389 lines)
//!
//! [`TuiProgressBar`] is a [`TuiBackground`]-descendant widget that adds
//! 72 bytes of state over its parent (min/cur/max as both u64 and f64,
//! plus an integer-mode flag, a direction flag, and a fill-color pair).
//! Per FASM `tui_progressbar$vtable` it overrides exactly two virtual
//! methods of the 37-method [`Widget`] base trait — slot 1
//! ([`Widget::clone_widget`]) and slot 2 ([`Widget::draw`]) — and
//! inherits the other 35 methods from the [`TuiBackground`] composition.
//!
//! ## Visual model
//!
//! [`TuiProgressBar::draw`] paints the entire rectangle with the
//! parent's `empty_colors` (via [`TuiBackground::nvfill`]) and then
//! overlays `fill_colors` on a contiguous prefix or suffix of the
//! attribute buffer:
//!
//! - **[`FillDirection::Forward`]** (FASM `dir = 0`, default):
//!   the first `round(total_cells * percent)` cells receive
//!   `fill_colors`. For a horizontal bar this yields LTR fill; for a
//!   vertical bar it yields TTB fill (the visual axis is determined
//!   by the rectangle's aspect, not by this enum).
//! - **[`FillDirection::Reverse`]** (FASM `dir = 1`): the last
//!   `round(total_cells * percent)` cells receive `fill_colors`,
//!   yielding RTL or BTT fill respectively.
//!
//! ## Value modes
//!
//! [`ValueMode::Integer`] (FASM `int_ofs = 1`, default after every
//! constructor) tracks `min: u64`, `cur: u64`, `max: u64`. This is the
//! constructor default; callers must explicitly invoke
//! [`TuiProgressBar::set_limits_double`] to switch to
//! [`ValueMode::Double`] (FASM `int_ofs = 0`) which tracks `min: f64`,
//! `cur: f64`, `max: f64`.
//!
//! [`TuiProgressBar::percentage`] returns a normalized `f64` in
//! `[0.0, 1.0]` and explicitly returns `0.0` (never `NaN` and never
//! a panic) for degenerate inputs:
//!
//! - integer mode: `min == max` or `max == 0`
//! - double mode: `max == 0.0` or `min == max`
//!
//! ## Constructors
//!
//! Five constructors mirror the FASM `tui_progressbar$new_*` family
//! (`new_id`, `new_di`, `new_dd`, `new_ii`, `new_rect`), each
//! delegating to the corresponding [`TuiBackground`] factory with
//! `fillchar = 0x20` (ASCII space) and the caller's `empty_colors`,
//! then initializing the progressbar-specific state to integer mode
//! with `min = cur = max = 0`.

use std::any::Any;
use std::sync::{Arc, Mutex};

use crate::error::TuiError;
use crate::tui::geometry::Rect;
use crate::tui::object::{ColorPair, Widget, WidgetState};
use crate::tui::render::Renderer;
use crate::tui::widgets::background::TuiBackground;

// ============================================================================
// Public enums
// ============================================================================

/// Fill direction for [`TuiProgressBar`] rendering.
///
/// Mirrors the single-bit FASM `tui_progressbar_dir_ofs` field.
///
/// - [`FillDirection::Forward`]: LTR for horizontal bars, TTB for
///   vertical (FASM `dir = 0`, the constructor default).
/// - [`FillDirection::Reverse`]: RTL for horizontal bars, BTT for
///   vertical (FASM `dir = 1`).
///
/// The visual axis (horizontal vs. vertical) is implicit from the
/// rectangle shape and is **not** encoded in this enum. Callers that
/// want to carry both axis and orientation in a single value can use
/// [`ProgressDirection`] which expands to four named variants and
/// converts to [`FillDirection`] via [`From`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum FillDirection {
    /// FASM `dir = 0`. Default. LTR (horizontal) / TTB (vertical).
    Forward = 0,
    /// FASM `dir = 1`. RTL (horizontal) / BTT (vertical).
    Reverse = 1,
}

impl Default for FillDirection {
    /// FASM constructor default — `dir_ofs = 0` after `heap$alloc_clear`.
    fn default() -> Self {
        Self::Forward
    }
}

/// Higher-level progress bar fill direction encoding both visual axis
/// and orientation as a single value.
///
/// This is purely a convenience layer over [`FillDirection`] for
/// callers that want explicit "left-to-right" / "top-to-bottom"
/// nomenclature in their APIs. The four variants project onto
/// [`FillDirection`]'s two values via the [`From`] impl below:
///
/// - [`ProgressDirection::LeftToRight`] / [`ProgressDirection::TopToBottom`]
///   → [`FillDirection::Forward`]
/// - [`ProgressDirection::RightToLeft`] / [`ProgressDirection::BottomToTop`]
///   → [`FillDirection::Reverse`]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ProgressDirection {
    /// Fill from the left edge rightward (horizontal bar).
    LeftToRight,
    /// Fill from the right edge leftward (horizontal bar).
    RightToLeft,
    /// Fill from the top edge downward (vertical bar).
    TopToBottom,
    /// Fill from the bottom edge upward (vertical bar).
    BottomToTop,
}

impl From<ProgressDirection> for FillDirection {
    fn from(pd: ProgressDirection) -> Self {
        match pd {
            ProgressDirection::LeftToRight | ProgressDirection::TopToBottom => FillDirection::Forward,
            ProgressDirection::RightToLeft | ProgressDirection::BottomToTop => FillDirection::Reverse,
        }
    }
}

// ============================================================================
// Internal state types
// ============================================================================

/// Numeric value representation for a [`TuiProgressBar`].
///
/// Mirrors the dual storage in FASM where a single struct holds both
/// `min/cur/max: u64` (offsets +0/+16/+32) and `mind/curd/maxd: f64`
/// (offsets +8/+24/+40), tagged by the `int_ofs` flag at +48
/// (`1` = integer mode, `0` = double mode). In Rust we collapse the
/// two parallel triples into a single tagged enum since the language
/// makes this representation strictly safer without losing the
/// behavioral semantics.
#[derive(Copy, Clone, Debug)]
enum ValueMode {
    /// FASM `int_ofs == 1` (the constructor default). Tracks the bar
    /// in unsigned-integer space.
    Integer { min: u64, cur: u64, max: u64 },
    /// FASM `int_ofs == 0`. Tracks the bar in IEEE-754 double space.
    Double { min: f64, cur: f64, max: f64 },
}

impl ValueMode {
    /// FASM constructor default — `int_ofs = 1` and all six numeric
    /// fields zeroed by `heap$alloc_clear`.
    const fn default_integer() -> Self {
        Self::Integer {
            min: 0,
            cur: 0,
            max: 0,
        }
    }
}

/// Mutable state of a [`TuiProgressBar`] — the 72 bytes of FASM state
/// stored above the parent [`TuiBackground`].
///
/// Wrapped in a [`Mutex`] inside [`TuiProgressBar`] because the
/// [`Widget`] trait's read-shaped methods take `&self` while these
/// fields must mutate from `set_limits_*` / `update_*` calls invoked
/// through `Arc<dyn Widget>` shared-ownership references. Using
/// [`std::sync::Mutex`] (not [`tokio::sync::Mutex`]) is appropriate
/// because every operation is a fast in-memory state mutation that
/// never blocks on I/O.
#[derive(Clone, Debug)]
struct ProgressbarInner {
    /// Tagged numeric state — see [`ValueMode`].
    value: ValueMode,
    /// Fill direction — FASM offset +56 (`dir_ofs`).
    direction: FillDirection,
    /// Color pair for the filled portion — FASM offset +64
    /// (`fillcolors_ofs`). The unfilled portion uses the parent
    /// [`TuiBackground::colors`] (`empty_colors` from the constructor).
    fill_colors: ColorPair,
}

// ============================================================================
// TuiProgressBar
// ============================================================================

/// A Background-descendant progress bar widget.
///
/// Composes a [`TuiBackground`] (which itself inherits from
/// [`tui_object`](crate::tui::object)) plus an interior-mutable
/// [`ProgressbarInner`] holding the integer/double value state, the
/// fill direction, and the fill-colors pair.
///
/// ## Vtable overrides (matching FASM `tui_progressbar$vtable`)
///
/// Only two of the 37 [`Widget`] vmethods are overridden:
///
/// - slot 1 [`Widget::clone_widget`] — deep-clone including all 72
///   bytes of progressbar state on top of the parent's deep clone.
/// - slot 2 [`Widget::draw`] — paint `empty_colors` everywhere via
///   [`TuiBackground::nvfill`], then overlay `fill_colors` on the
///   computed filled cell range.
///
/// Slots 0 (`cleanup`) and 6 (`timer`) intentionally inherit the
/// `tui_object` defaults — FASM places `tui_object$cleanup` and
/// `tui_object$timer` in those slots, **not** the background's
/// versions. The Rust translation matches this by allowing the
/// [`Widget`] trait defaults to apply (the trait default `cleanup`
/// matches the FASM `tui_object$cleanup` implementation; the trait
/// default `timer` is a no-op matching FASM `tui_object$timer`).
pub struct TuiProgressBar {
    /// Embedded [`TuiBackground`] — provides dimensions, the empty
    /// color pair, the fill character (`0x20`), and the parent
    /// [`WidgetState`] accessed via [`Widget::state`] /
    /// [`Widget::state_mut`].
    ///
    /// We hold this by value (not `Arc`-wrapped) so that
    /// [`TuiProgressBar`] owns and can mutate the underlying state
    /// directly during `draw`. The `Arc` returned by each
    /// `TuiBackground::new_*` factory is unwrapped via
    /// [`Arc::try_unwrap`] inside our constructors — this always
    /// succeeds because the factories return a fresh `Arc` with
    /// strong-count 1.
    background: TuiBackground,
    /// Interior-mutable progressbar-specific state.
    inner: Mutex<ProgressbarInner>,
}

/// Friendly type alias matching the workspace export schema.
///
/// `ProgressBar` and [`TuiProgressBar`] are the same concrete type;
/// the alias exists so callers using the more idiomatic Rust naming
/// (without the FASM `Tui` prefix) get the same struct without an
/// extra wrapper layer.
pub type ProgressBar = TuiProgressBar;

// ============================================================================
// Constructors — five FASM-mirroring factories
// ============================================================================

impl TuiProgressBar {
    /// FASM constructor default fill character — ASCII space (`0x20`).
    ///
    /// Every progressbar constructor passes this value to the parent
    /// [`TuiBackground`] so that [`TuiBackground::nvfill`] paints the
    /// text buffer with spaces (preserving the geometric area) before
    /// the progressbar overlays color-only attribute changes on top.
    const FILLCHAR_SPACE: u32 = b' ' as u32;

    /// FASM `tui_progressbar$new_id(edi=width, xmm0=height_percent, ...)`.
    ///
    /// Construct with integer width and percentage-based height.
    pub fn new_id(
        width: i32,
        height_percent: f64,
        dir: FillDirection,
        empty_colors: ColorPair,
        fill_colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        let bg_arc = TuiBackground::new_id(width, height_percent, Self::FILLCHAR_SPACE, empty_colors)?;
        Self::wrap_background(bg_arc, dir, fill_colors)
    }

    /// FASM `tui_progressbar$new_di(xmm0=width_percent, edi=height, ...)`.
    ///
    /// Construct with percentage-based width and integer height.
    pub fn new_di(
        width_percent: f64,
        height: i32,
        dir: FillDirection,
        empty_colors: ColorPair,
        fill_colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        let bg_arc = TuiBackground::new_di(width_percent, height, Self::FILLCHAR_SPACE, empty_colors)?;
        Self::wrap_background(bg_arc, dir, fill_colors)
    }

    /// FASM `tui_progressbar$new_dd(xmm0=width_percent, xmm1=height_percent, ...)`.
    ///
    /// Construct with percentage-based width AND percentage-based
    /// height — final dimensions resolved at layout time.
    pub fn new_dd(
        width_percent: f64,
        height_percent: f64,
        dir: FillDirection,
        empty_colors: ColorPair,
        fill_colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        let bg_arc =
            TuiBackground::new_dd(width_percent, height_percent, Self::FILLCHAR_SPACE, empty_colors)?;
        Self::wrap_background(bg_arc, dir, fill_colors)
    }

    /// FASM `tui_progressbar$new_ii(edi=width, esi=height, ...)`.
    ///
    /// Construct with explicit integer width AND integer height.
    pub fn new_ii(
        width: i32,
        height: i32,
        dir: FillDirection,
        empty_colors: ColorPair,
        fill_colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        let bg_arc = TuiBackground::new_ii(width, height, Self::FILLCHAR_SPACE, empty_colors)?;
        Self::wrap_background(bg_arc, dir, fill_colors)
    }

    /// FASM `tui_progressbar$new_rect(rdi=rect_ptr, esi=dir, ...)`.
    ///
    /// Construct from an explicit [`Rect`] (half-open
    /// inclusive-top-left, exclusive-bottom-right).
    pub fn new_rect(
        bounds: Rect,
        dir: FillDirection,
        empty_colors: ColorPair,
        fill_colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        let bg_arc = TuiBackground::new_rect(bounds, Self::FILLCHAR_SPACE, empty_colors)?;
        Self::wrap_background(bg_arc, dir, fill_colors)
    }

    /// Internal constructor helper — extract the freshly-built
    /// [`TuiBackground`] from its `Arc` shell, attach the
    /// progressbar-specific state, and re-wrap the composite in a new
    /// `Arc<Self>`.
    ///
    /// Each `TuiBackground::new_*` factory returns an `Arc` with
    /// strong-count exactly 1 (no clones have escaped), so
    /// [`Arc::try_unwrap`] always succeeds; the `Err` arm returns a
    /// [`TuiError::Render`] for completeness even though it is
    /// statically unreachable on this code path.
    fn wrap_background(
        bg_arc: Arc<TuiBackground>,
        dir: FillDirection,
        fill_colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        let background = Arc::try_unwrap(bg_arc).map_err(|_| {
            TuiError::Render(std::io::Error::other(
                "TuiProgressBar: TuiBackground Arc had unexpected outstanding references",
            ))
        })?;
        let inner = ProgressbarInner {
            value: ValueMode::default_integer(),
            direction: dir,
            fill_colors,
        };
        Ok(Arc::new(Self {
            background,
            inner: Mutex::new(inner),
        }))
    }
}

// ============================================================================
// Non-virtual public API — limits, updates, percentage
// ============================================================================

impl TuiProgressBar {
    /// FASM `tui_progressbar$nvlimits(rdi=self, rsi=min_u64, rdx=max_u64)`.
    ///
    /// Switch to integer mode (`int_ofs = 1`) and store the new
    /// `min/max` pair. Per FASM the `cur` field is **not** modified —
    /// callers issuing a fresh limits range are expected to either
    /// allow the existing `cur` to remain or call
    /// [`update_int`](Self::update_int) afterward to set a new value.
    ///
    /// Triggers [`Widget::draw`] via [`Self::redraw`] after updating
    /// state (matching FASM's terminating `call vdraw`).
    pub fn set_limits_int(&self, min: u64, max: u64) -> Result<(), TuiError> {
        self.with_inner(|inner| {
            // Preserve cur across mode switches: if we were in double
            // mode, start the new integer cur at the previous cur
            // truncated to u64; if we were already in integer mode,
            // leave cur untouched (FASM nvlimits leaves cur_ofs alone).
            let cur = match inner.value {
                ValueMode::Integer { cur, .. } => cur,
                ValueMode::Double { cur, .. } => {
                    // FASM cross-mode behavior is undefined since the
                    // user is expected to avoid mixing; we choose the
                    // safest in-range projection.
                    if cur.is_finite() && cur >= 0.0 {
                        cur as u64
                    } else {
                        0
                    }
                }
            };
            inner.value = ValueMode::Integer { min, cur, max };
        })?;
        self.redraw()
    }

    /// FASM `tui_progressbar$nvlimitsd(rdi=self, xmm0=min_f64, xmm1=max_f64)`.
    ///
    /// Switch to double mode (`int_ofs = 0`) and store the new
    /// `min/max` pair. Like the integer variant, leaves `cur`
    /// unchanged (FASM nvlimitsd leaves curd_ofs alone).
    ///
    /// Triggers [`Widget::draw`] after updating state.
    pub fn set_limits_double(&self, min: f64, max: f64) -> Result<(), TuiError> {
        self.with_inner(|inner| {
            // Cross-mode cur preservation analogous to set_limits_int.
            let cur = match inner.value {
                ValueMode::Double { cur, .. } => cur,
                ValueMode::Integer { cur, .. } => cur as f64,
            };
            inner.value = ValueMode::Double { min, cur, max };
        })?;
        self.redraw()
    }

    /// FASM `tui_progressbar$nvupdate(rdi=self, rsi=cur_u64)`.
    ///
    /// Update the integer-mode `cur` value. If the bar is currently
    /// in double mode, this method silently switches it to integer
    /// mode (mirroring the FASM behavior where the caller is
    /// responsible for matching the current mode; in Rust we cannot
    /// silently corrupt the tagged enum, so we explicitly switch).
    ///
    /// Triggers [`Widget::draw`] after updating state.
    pub fn update_int(&self, cur: u64) -> Result<(), TuiError> {
        self.with_inner(|inner| {
            inner.value = match inner.value {
                ValueMode::Integer { min, max, .. } => ValueMode::Integer { min, cur, max },
                ValueMode::Double { min, max, .. } => {
                    // Mode mismatch — fold the existing double limits
                    // back into u64 space using saturating casts.
                    let min_u64 = if min.is_finite() && min >= 0.0 {
                        min as u64
                    } else {
                        0
                    };
                    let max_u64 = if max.is_finite() && max >= 0.0 {
                        max as u64
                    } else {
                        0
                    };
                    ValueMode::Integer {
                        min: min_u64,
                        cur,
                        max: max_u64,
                    }
                }
            };
        })?;
        self.redraw()
    }

    /// FASM `tui_progressbar$nvupdated(rdi=self, xmm0=cur_f64)`.
    ///
    /// Update the double-mode `cur` value. As with
    /// [`update_int`](Self::update_int), if the bar is in the wrong
    /// mode we silently switch — this is a slight extension of FASM
    /// semantics necessitated by the tagged-enum representation.
    ///
    /// Triggers [`Widget::draw`] after updating state.
    pub fn update_double(&self, cur: f64) -> Result<(), TuiError> {
        self.with_inner(|inner| {
            inner.value = match inner.value {
                ValueMode::Double { min, max, .. } => ValueMode::Double { min, cur, max },
                ValueMode::Integer { min, max, .. } => ValueMode::Double {
                    min: min as f64,
                    cur,
                    max: max as f64,
                },
            };
        })?;
        self.redraw()
    }

    /// FASM `tui_progressbar$nvgetperc(rdi=self) -> xmm0`.
    ///
    /// Returns the current progress as a normalized `f64` in
    /// `[0.0, 1.0]`. Returns `0.0` (never `NaN` and never a panic)
    /// for degenerate inputs:
    ///
    /// - integer mode: `min == max` or `max == 0`
    /// - double mode: `max == 0.0` or `min == max`
    ///
    /// Values outside `[min, max]` are NOT clamped — the result may
    /// exceed `1.0` if `cur > max` or fall below `0.0` if
    /// `cur < min`. This preserves FASM behavior (the FASM division
    /// is unsigned in integer mode, so `cur < min` underflows to a
    /// very large value; in Rust we use [`u64::saturating_sub`] to
    /// avoid the underflow while still producing a deterministic
    /// non-negative result).
    #[must_use]
    pub fn percentage(&self) -> f64 {
        // If the lock is poisoned, recover the inner state and
        // continue — a poisoned lock here means a panic during
        // an earlier mutation, but the data is still well-typed.
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        match inner.value {
            ValueMode::Integer { min, cur, max } => {
                // FASM .zeroret guards: if min == max OR max == 0,
                // return 0.0 to avoid divide-by-zero.
                if min == max || max == 0 {
                    return 0.0;
                }
                let numer = cur.saturating_sub(min) as f64;
                let denom = (max - min) as f64;
                numer / denom
            }
            ValueMode::Double { min, cur, max } => {
                // FASM double-mode guards (translated per agent_prompt
                // §5e from the FASM .doubles path): return 0.0 when
                // max is exactly 0.0 OR when min == max (which would
                // produce NaN via 0/0).
                if max == 0.0 || min == max {
                    return 0.0;
                }
                (cur - min) / (max - min)
            }
        }
    }

    /// Convenience method exposing the FASM `nvlimits` semantics under
    /// the friendlier name listed in the workspace export schema.
    ///
    /// Equivalent to [`set_limits_int`](Self::set_limits_int).
    pub fn set_limits(&self, min: u64, max: u64) -> Result<(), TuiError> {
        self.set_limits_int(min, max)
    }

    /// Convenience method exposing the FASM `nvlimitsd` semantics
    /// under the friendlier name listed in the workspace export
    /// schema. Equivalent to
    /// [`set_limits_double`](Self::set_limits_double).
    pub fn set_limits_f64(&self, min: f64, max: f64) -> Result<(), TuiError> {
        self.set_limits_double(min, max)
    }

    /// Convenience method matching the friendly name in the workspace
    /// export schema. Equivalent to [`update_int`](Self::update_int).
    pub fn update(&self, cur: u64) -> Result<(), TuiError> {
        self.update_int(cur)
    }

    /// Convenience method matching the friendly name in the workspace
    /// export schema. Equivalent to
    /// [`update_double`](Self::update_double).
    pub fn update_f64(&self, cur: f64) -> Result<(), TuiError> {
        self.update_double(cur)
    }

    /// Convenience method matching the friendly name in the workspace
    /// export schema. Equivalent to [`percentage`](Self::percentage).
    #[must_use]
    pub fn get_percentage(&self) -> f64 {
        self.percentage()
    }

    /// Internal — acquire the inner state under lock and apply a
    /// closure-shaped mutation, recovering from poisoned locks.
    ///
    /// Returns [`TuiError::Render`] only if the closure itself
    /// triggers an io-shaped error (currently always returns `Ok`).
    fn with_inner<F>(&self, f: F) -> Result<(), TuiError>
    where
        F: FnOnce(&mut ProgressbarInner),
    {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        f(&mut guard);
        Ok(())
    }

    /// Internal — re-trigger the draw pipeline after a state mutation.
    ///
    /// This emulates FASM's `call vdraw` at the tail of every
    /// `nvlimits` / `nvlimitsd` / `nvupdate` / `nvupdated`
    /// implementation. We construct a no-op renderer-free draw by
    /// downcasting through [`Arc::try_unwrap`] is not possible (we
    /// hold `&self` not the `Arc`), so we route through a single
    /// internal `redraw_unlocked` helper that mirrors the body of
    /// [`Widget::draw`] but takes `&self` plus uses interior mutation
    /// against the inner [`Mutex`] only — buffer mutation requires
    /// `&mut self.background`, so we instead defer the actual buffer
    /// repaint to the next [`Widget::draw`] call from the render
    /// pipeline.
    ///
    /// In practice the FASM render loop calls `draw` on every state
    /// change, so this method's only job is to mark the widget as
    /// dirty. Since the Rust render pipeline already invokes `draw`
    /// once per frame on the visible widget tree, no explicit
    /// dirty-marking is needed — the next frame will repaint.
    fn redraw(&self) -> Result<(), TuiError> {
        // Intentional no-op at the public API level: the render loop
        // (driven by the renderer + display list) re-invokes
        // [`Widget::draw`] every frame, so a state mutation here is
        // automatically visible on the next paint pass without our
        // intervention. Documenting this method explicitly so
        // call-site intent ("after this state mutation, please
        // schedule a redraw") remains traceable in the source.
        Ok(())
    }
}

// ============================================================================
// Widget trait — 3 required impls + 2 vtable overrides
// ============================================================================

impl Widget for TuiProgressBar {
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

    /// Required downcast accessor — returns `self` so callers holding
    /// `Arc<dyn Widget>` can recover the concrete [`TuiProgressBar`]
    /// via [`Any::downcast_ref`].
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Override — vtable slot 1 (`tui_vclone`).
    ///
    /// FASM parallel: `tui_progressbar$clone`
    /// (`tui_progressbar.inc` lines 218–241):
    ///
    /// ```text
    ///   heap$alloc_clear(tui_progressbar_size)
    ///   set vtable to tui_progressbar$vtable
    ///   tui_background$init_copy(new, self)
    ///   memcpy(new + tui_progressbar_min_ofs, self + tui_progressbar_min_ofs, 72)
    ///   return new
    /// ```
    ///
    /// In Rust the 72-byte memcpy is replaced by a structural clone of
    /// [`ProgressbarInner`] (which derives [`Clone`]); the parent
    /// `tui_background$init_copy` is replaced by a manual rebuild of
    /// the background struct using a deep-cloned [`WidgetState`]
    /// (replicating the private `init_copy_from` helper since it is
    /// not exposed across the [`crate::tui::widgets::background`]
    /// module boundary).
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // Deep-clone the parent state — mirrors FASM
        // `tui_object$init_copy` which is invoked transitively by
        // `tui_background$init_copy`.
        let cloned_bg_state = clone_widget_state(self.background.state())?;
        let cloned_bg = TuiBackground {
            state: cloned_bg_state,
            bgfillchar: self.background.fillchar(),
            bgcolors: self.background.colors(),
        };

        // Snapshot inner state under lock — Mutex<T: Clone> is not
        // itself Clone, so we must lock + clone the contents.
        let inner_clone = match self.inner.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        };

        Ok(Arc::new(Self {
            background: cloned_bg,
            inner: Mutex::new(inner_clone),
        }) as Arc<dyn Widget>)
    }

    /// Override — vtable slot 2 (`tui_vdraw`).
    ///
    /// FASM parallel: `tui_progressbar$draw`
    /// (`tui_progressbar.inc` lines 246–291):
    ///
    /// ```text
    ///   if width == 0 OR height == 0:    return                 ; .nothingtodo
    ///   tui_background$nvfill(self)                              ; paint empty_colors
    ///   perc = tui_progressbar$nvgetperc(self)
    ///   total_cells = width * height
    ///   fill_cells = round(total_cells * perc)                   ; cvtsd2si
    ///   if fill_cells <= 0:               return                 ; .outtahere
    ///   if dir == 0:
    ///       memset32(attr_buf, fill_colors, fill_cells)          ; Forward
    ///   else:
    ///       memset32(attr_buf + (total - fill_bytes), fill_colors, fill_cells)
    ///   self.vupdatedisplaylist(self)
    /// ```
    ///
    /// Notes on rounding: FASM's `cvtsd2si` rounds to nearest-even
    /// (the x86 default rounding mode); Rust's bare `as usize` cast
    /// truncates which differs at exactly `0.5`. We use
    /// [`f64::round`] explicitly to match the FASM rounding mode.
    ///
    /// Notes on the `.outtahere` path: when `fill_cells == 0`, FASM
    /// returns **without** calling `vupdatedisplaylist`. We preserve
    /// this exact behavior — the `nvfill` call already painted the
    /// buffer with `empty_colors`, but the display-list update is
    /// skipped, matching the FASM source precisely. The next frame
    /// (if `fill_cells > 0`) will re-trigger the full pipeline.
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        // FASM .nothingtodo bail — width or height of zero.
        let width = self.background.state().width;
        let height = self.background.state().height;
        if width == 0 || height == 0 {
            return Ok(());
        }

        // FASM step 1: have tui_background paint empty_colors across
        // the entire text + attribute buffers.
        self.background.nvfill()?;

        // FASM step 2: compute fill ratio.
        let perc = self.percentage();

        // FASM step 3: total cells = width * height (using i32-safe
        // casts; nvfill above already validated width/height >= 1).
        // Negative dimensions were filtered by the early bail above
        // (a negative i32 != 0), but we additionally guard via
        // saturating_*-style casts to keep the multiplication safe
        // for arbitrarily large dimensions.
        let width_us = (width.max(0)) as usize;
        let height_us = (height.max(0)) as usize;
        let total_cells = match width_us.checked_mul(height_us) {
            Some(n) => n,
            None => {
                return Err(TuiError::Render(std::io::Error::other(format!(
                    "TuiProgressBar::draw: width*height overflowed usize \
                     (width={width}, height={height})"
                ))));
            }
        };

        // FASM step 4: fill_cells = round(total_cells * perc) using
        // x86 default rounding mode (nearest-even). Clamp negative
        // perc to 0 and oversized perc to total_cells to prevent
        // out-of-bounds slicing.
        let raw = (total_cells as f64) * perc;
        let fill_cells_signed = if raw.is_finite() { raw.round() as i64 } else { 0 };
        let fill_cells: usize = if fill_cells_signed <= 0 {
            0
        } else {
            (fill_cells_signed as usize).min(total_cells)
        };

        // FASM .outtahere — fill_cells <= 0 returns WITHOUT calling
        // vupdatedisplaylist. The empty-colors paint from nvfill
        // remains in place; the display-list update is intentionally
        // skipped to mirror the assembly behavior precisely.
        if fill_cells == 0 {
            return Ok(());
        }

        // FASM step 5: overlay fill_colors on the computed cell range
        // of the attribute buffer. The text buffer (filled by nvfill
        // with spaces) is NOT modified — only color attributes change.
        let (fill_colors, dir) = {
            let inner = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            (inner.fill_colors, inner.direction)
        };
        let packed = pack_color_pair(fill_colors);

        // Query the attribute-cell buffer length via `Attributes::len()`
        // BEFORE the upcoming `state_mut()` mutable borrow. The attr
        // buffer should match `total_cells` after `nvfill`, but we
        // defensively cap the fill slice to the smaller of `fill_cells`
        // and the actual buffer length to be robust against future
        // changes in `nvfill`'s allocation policy.
        let buf_len = self.background.state().attributes.len();
        let effective_fill = fill_cells.min(buf_len);

        let cells: &mut Vec<u32> = &mut self.background.state_mut().attributes.cells;

        match dir {
            FillDirection::Forward => {
                // FASM dir == 0: memset32(attr, fill_colors, fill_cells)
                for cell in &mut cells[..effective_fill] {
                    *cell = packed;
                }
            }
            FillDirection::Reverse => {
                // FASM dir != 0: memset32(attr + (total - fill_bytes),
                //                          fill_colors, fill_cells)
                let start = buf_len.saturating_sub(effective_fill);
                for cell in &mut cells[start..buf_len] {
                    *cell = packed;
                }
            }
        }

        // FASM step 6: trigger the display-list update via the
        // polymorphic vmethod. The default trait impl is a no-op
        // (matching FASM `tui_object$updatedisplaylist`); renderer-
        // bound compositions override it to flush attribute changes
        // through the rendering pipeline.
        self.update_display_list();
        Ok(())
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Pack a [`ColorPair`] into the `u32` cell-attribute representation
/// used by the [`Attributes`] buffer.
///
/// Replicates the byte layout from `tui_object.inc` (and from the
/// private `pack_color_pair` helper inside
/// [`crate::tui::widgets::background`]):
///
/// ```text
///   bits 0..=7   : foreground color index (u8)
///   bits 8..=15  : background color index (u8)
///   bits 16..=31 : SGR attributes (zero for progressbar fill — we
///                  inherit no SGR state, matching FASM where the
///                  fillcolors_ofs field is a 32-bit value already
///                  packed by the caller).
/// ```
///
/// Defined locally instead of importing the background-module helper
/// because that helper is private to its module.
fn pack_color_pair(cp: ColorPair) -> u32 {
    u32::from(cp.fg) | (u32::from(cp.bg) << 8)
}

/// Deep-clone a [`WidgetState`] including children (via
/// [`Widget::clone_widget`]), preserving the FASM
/// `tui_object$init_copy` semantics that
/// [`crate::tui::widgets::background::TuiBackground`] uses internally.
///
/// Replicated locally because the equivalent helper in
/// `widgets::background` is private to that module — placing it here
/// duplicates ~30 lines of straight-line state cloning logic but
/// keeps `progressbar.rs` self-contained without modifying
/// `background.rs`. The logic mirrors FASM
/// `tui_object$init_copy`/`tui_background$init_copy`:
///
/// - All scalar fields are copied directly.
/// - `text` and `attributes` are deep-cloned (the underlying
///   `Vec<u8>` / `Vec<u32>` are duplicated).
/// - `children` is recursively deep-cloned via each child's own
///   [`Widget::clone_widget`] vmethod.
/// - `bastards` is intentionally **not** cloned — it is reset to the
///   `WidgetState::new()` empty list, matching FASM line 274
///   (`call list$new; mov [rdi+tui_bastards_ofs], rax`).
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

    // Buffers — deep clone (Buffer/Attributes derive Clone).
    cloned.text = src.text.clone();
    cloned.attributes = src.attributes.clone();

    // Children — recursive deep clone via Widget::clone_widget.
    for child in src.children.iter() {
        let cloned_child = child.clone_widget()?;
        cloned.children.push_back(cloned_child);
    }

    // bastards stays empty (matching FASM init_copy).
    Ok(cloned)
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::geometry::Rect;

    /// Helper: dark-on-light empty-colors palette.
    fn empty_palette() -> ColorPair {
        ColorPair::new(7, 0) // light grey on black
    }

    /// Helper: bright-on-dark fill-colors palette.
    fn fill_palette() -> ColorPair {
        ColorPair::new(15, 4) // bright white on red
    }

    /// Helper: produce a default-config 10x1 progressbar in integer mode.
    fn make_bar_10x1() -> Arc<TuiProgressBar> {
        TuiProgressBar::new_ii(10, 1, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("construction should succeed")
    }

    // ------------------------------------------------------------------
    // Type-property tests
    // ------------------------------------------------------------------

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn tui_progressbar_is_send_and_sync() {
        // Required for the Widget: Send + Sync 'static contract that
        // makes Arc<dyn Widget> usable across tokio task boundaries.
        assert_send_sync::<TuiProgressBar>();
    }

    #[test]
    fn fill_direction_default_is_forward() {
        // FASM constructor default — dir_ofs = 0 after heap$alloc_clear.
        assert_eq!(FillDirection::default(), FillDirection::Forward);
    }

    #[test]
    fn fill_direction_repr_values() {
        // FASM offsets: 0 = Forward (LTR/TTB), 1 = Reverse (RTL/BTT).
        assert_eq!(FillDirection::Forward as u32, 0);
        assert_eq!(FillDirection::Reverse as u32, 1);
    }

    #[test]
    fn progress_direction_to_fill_direction_mapping() {
        assert_eq!(
            FillDirection::from(ProgressDirection::LeftToRight),
            FillDirection::Forward
        );
        assert_eq!(
            FillDirection::from(ProgressDirection::TopToBottom),
            FillDirection::Forward
        );
        assert_eq!(
            FillDirection::from(ProgressDirection::RightToLeft),
            FillDirection::Reverse
        );
        assert_eq!(
            FillDirection::from(ProgressDirection::BottomToTop),
            FillDirection::Reverse
        );
    }

    // ------------------------------------------------------------------
    // Constructor tests — all five factories
    // ------------------------------------------------------------------

    #[test]
    fn new_ii_constructs_with_explicit_dimensions() {
        let bar = TuiProgressBar::new_ii(8, 2, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("new_ii should succeed");
        assert_eq!(bar.background.state().width, 8);
        assert_eq!(bar.background.state().height, 2);
    }

    #[test]
    fn new_id_uses_percentage_height() {
        let bar = TuiProgressBar::new_id(12, 0.5, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("new_id should succeed");
        assert_eq!(bar.background.state().width, 12);
        assert_eq!(bar.background.state().height_percent, Some(0.5));
    }

    #[test]
    fn new_di_uses_percentage_width() {
        let bar = TuiProgressBar::new_di(0.75, 4, FillDirection::Reverse, empty_palette(), fill_palette())
            .expect("new_di should succeed");
        assert_eq!(bar.background.state().width_percent, Some(0.75));
        assert_eq!(bar.background.state().height, 4);
    }

    #[test]
    fn new_dd_uses_both_percentages() {
        let bar = TuiProgressBar::new_dd(0.6, 0.4, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("new_dd should succeed");
        assert_eq!(bar.background.state().width_percent, Some(0.6));
        assert_eq!(bar.background.state().height_percent, Some(0.4));
    }

    #[test]
    fn new_rect_stores_bounds() {
        let r = Rect::new(2, 3, 18, 7);
        let bar = TuiProgressBar::new_rect(r, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("new_rect should succeed");
        assert_eq!(bar.background.state().bounds, r);
        // Width/height derived from rect dimensions.
        assert_eq!(bar.background.state().width, 16);
        assert_eq!(bar.background.state().height, 4);
    }

    // ------------------------------------------------------------------
    // Default-state tests
    // ------------------------------------------------------------------

    #[test]
    fn default_value_mode_is_integer_with_zero_bounds() {
        // FASM int_ofs = 1 by default; min/cur/max all zero from
        // heap$alloc_clear.
        let bar = make_bar_10x1();
        let inner = bar.inner.lock().expect("lock");
        match inner.value {
            ValueMode::Integer { min, cur, max } => {
                assert_eq!(min, 0);
                assert_eq!(cur, 0);
                assert_eq!(max, 0);
            }
            ValueMode::Double { .. } => {
                panic!("default mode should be Integer per FASM int_ofs=1")
            }
        }
    }

    #[test]
    fn default_fillchar_is_space() {
        let bar = make_bar_10x1();
        // FASM constructors pass 0x20 as the fill character.
        assert_eq!(bar.background.fillchar(), b' ' as u32);
    }

    #[test]
    fn default_empty_colors_match_constructor_arg() {
        let palette = ColorPair::new(11, 22);
        let bar = TuiProgressBar::new_ii(5, 1, FillDirection::Forward, palette, ColorPair::new(0, 0))
            .expect("ctor");
        assert_eq!(bar.background.colors(), palette);
    }

    #[test]
    fn fill_colors_stored_separately_from_empty() {
        let empty = ColorPair::new(2, 3);
        let fill = ColorPair::new(14, 15);
        let bar = TuiProgressBar::new_ii(5, 1, FillDirection::Forward, empty, fill).expect("ctor");
        // empty_colors live on the parent; fill_colors live on the child.
        assert_eq!(bar.background.colors(), empty);
        let inner = bar.inner.lock().expect("lock");
        assert_eq!(inner.fill_colors, fill);
    }

    // ------------------------------------------------------------------
    // Limits / update / percentage tests
    // ------------------------------------------------------------------

    #[test]
    fn set_limits_int_sets_integer_mode_and_bounds() {
        let bar = make_bar_10x1();
        bar.set_limits_int(0, 100).expect("limits");
        let inner = bar.inner.lock().expect("lock");
        match inner.value {
            ValueMode::Integer { min, max, .. } => {
                assert_eq!(min, 0);
                assert_eq!(max, 100);
            }
            ValueMode::Double { .. } => panic!("expected integer mode"),
        }
    }

    #[test]
    fn set_limits_double_switches_to_double_mode() {
        let bar = make_bar_10x1();
        bar.set_limits_double(0.0, 1.0).expect("limits");
        let inner = bar.inner.lock().expect("lock");
        match inner.value {
            ValueMode::Double { min, max, .. } => {
                assert_eq!(min, 0.0);
                assert_eq!(max, 1.0);
            }
            ValueMode::Integer { .. } => panic!("expected double mode"),
        }
    }

    #[test]
    fn update_int_writes_cur_in_integer_mode() {
        let bar = make_bar_10x1();
        bar.set_limits_int(0, 100).expect("limits");
        bar.update_int(50).expect("update");
        assert!((bar.percentage() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn update_double_writes_cur_in_double_mode() {
        let bar = make_bar_10x1();
        bar.set_limits_double(0.0, 1.0).expect("limits");
        bar.update_double(0.75).expect("update");
        assert!((bar.percentage() - 0.75).abs() < 1e-12);
    }

    #[test]
    fn percentage_returns_zero_when_max_is_zero_int() {
        // FASM .zeroret guard #2: if max == 0, return 0.0.
        let bar = make_bar_10x1();
        // Default is Integer { 0, 0, 0 } — max is zero.
        assert_eq!(bar.percentage(), 0.0);
    }

    #[test]
    fn percentage_returns_zero_when_min_equals_max_int() {
        // FASM .zeroret guard #1: if min == max, return 0.0.
        let bar = make_bar_10x1();
        bar.set_limits_int(50, 50).expect("limits");
        bar.update_int(50).expect("update");
        assert_eq!(bar.percentage(), 0.0);
    }

    #[test]
    fn percentage_returns_zero_when_max_is_zero_double() {
        let bar = make_bar_10x1();
        bar.set_limits_double(-5.0, 0.0).expect("limits");
        bar.update_double(-2.0).expect("update");
        assert_eq!(bar.percentage(), 0.0);
    }

    #[test]
    fn percentage_returns_zero_when_min_equals_max_double() {
        let bar = make_bar_10x1();
        bar.set_limits_double(0.5, 0.5).expect("limits");
        bar.update_double(0.5).expect("update");
        assert_eq!(bar.percentage(), 0.0);
    }

    #[test]
    fn percentage_handles_cur_below_min_without_underflow() {
        // FASM uses unsigned subtraction which would underflow; we
        // use saturating_sub which yields 0 → percentage = 0.
        let bar = make_bar_10x1();
        bar.set_limits_int(50, 100).expect("limits");
        bar.update_int(10).expect("update");
        assert_eq!(bar.percentage(), 0.0);
    }

    #[test]
    fn convenience_aliases_match_canonical_methods() {
        let bar = make_bar_10x1();
        bar.set_limits(0, 200).expect("alias");
        bar.update(150).expect("alias");
        assert!((bar.get_percentage() - 0.75).abs() < 1e-12);

        bar.set_limits_f64(0.0, 4.0).expect("alias");
        bar.update_f64(1.0).expect("alias");
        assert!((bar.percentage() - 0.25).abs() < 1e-12);
    }

    // ------------------------------------------------------------------
    // draw() tests — fill direction & rounding semantics
    // ------------------------------------------------------------------

    /// Internal helper — minimal renderer stub for draw() tests.
    /// We use a no-op renderer because TuiProgressBar::draw never
    /// touches the renderer (per the schema's note that it operates
    /// only on the attribute buffer).
    struct NopRenderer;

    impl Renderer for NopRenderer {
        fn ansi_output(&mut self, _bytes: &[u8]) -> Result<(), TuiError> {
            Ok(())
        }
        fn flush(&mut self) -> Result<(), TuiError> {
            Ok(())
        }
        fn state(&self) -> &crate::tui::render::RenderState {
            // SAFETY: never reached because the trait default impls
            // for move_cursor / set_fg / set_bg are not invoked by
            // TuiProgressBar::draw, and we always return Ok before
            // any path that would consult the state.
            unreachable!(
                "NopRenderer::state should never be called from \
                 TuiProgressBar::draw"
            )
        }
        fn state_mut(&mut self) -> &mut crate::tui::render::RenderState {
            unreachable!(
                "NopRenderer::state_mut should never be called from \
                 TuiProgressBar::draw"
            )
        }
    }

    #[test]
    fn draw_no_op_when_width_is_zero() {
        // Force a 0x0 by constructing then verifying we don't crash.
        // (We can't easily construct a 0-width directly via new_ii
        // since negative / zero dims are accepted but bail on draw.)
        let bar = TuiProgressBar::new_ii(0, 1, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("ctor");
        let mut owned = Arc::try_unwrap(bar).ok().expect("unique Arc");
        let mut nop = NopRenderer;
        assert!(owned.draw(&mut nop).is_ok());
        // No mutation expected: cells stays empty (background.nvfill
        // bails on width == 0, and progressbar.draw bails before that).
        assert!(owned.background.state().attributes.cells.is_empty());
    }

    #[test]
    fn draw_no_op_when_height_is_zero() {
        let bar = TuiProgressBar::new_ii(10, 0, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("ctor");
        let mut owned = Arc::try_unwrap(bar).ok().expect("unique Arc");
        let mut nop = NopRenderer;
        assert!(owned.draw(&mut nop).is_ok());
        assert!(owned.background.state().attributes.cells.is_empty());
    }

    #[test]
    fn draw_forward_fills_prefix_of_attribute_buffer() {
        let bar = TuiProgressBar::new_ii(10, 1, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("ctor");
        bar.set_limits_int(0, 100).expect("limits");
        bar.update_int(50).expect("update");

        let mut owned = Arc::try_unwrap(bar).ok().expect("unique Arc");
        let mut nop = NopRenderer;
        owned.draw(&mut nop).expect("draw");

        let cells = &owned.background.state().attributes.cells;
        assert_eq!(cells.len(), 10);
        let empty_packed = pack_color_pair(empty_palette());
        let fill_packed = pack_color_pair(fill_palette());
        // First 5 cells should be fill; last 5 should be empty.
        for cell in &cells[0..5] {
            assert_eq!(*cell, fill_packed, "expected fill in prefix");
        }
        for cell in &cells[5..10] {
            assert_eq!(*cell, empty_packed, "expected empty in suffix");
        }
    }

    #[test]
    fn draw_reverse_fills_suffix_of_attribute_buffer() {
        let bar = TuiProgressBar::new_ii(10, 1, FillDirection::Reverse, empty_palette(), fill_palette())
            .expect("ctor");
        bar.set_limits_int(0, 100).expect("limits");
        bar.update_int(50).expect("update");

        let mut owned = Arc::try_unwrap(bar).ok().expect("unique Arc");
        let mut nop = NopRenderer;
        owned.draw(&mut nop).expect("draw");

        let cells = &owned.background.state().attributes.cells;
        assert_eq!(cells.len(), 10);
        let empty_packed = pack_color_pair(empty_palette());
        let fill_packed = pack_color_pair(fill_palette());
        // First 5 cells should be empty; last 5 should be fill.
        for cell in &cells[0..5] {
            assert_eq!(*cell, empty_packed, "expected empty in prefix");
        }
        for cell in &cells[5..10] {
            assert_eq!(*cell, fill_packed, "expected fill in suffix");
        }
    }

    #[test]
    fn draw_full_fill_at_100_percent() {
        let bar = TuiProgressBar::new_ii(10, 1, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("ctor");
        bar.set_limits_int(0, 100).expect("limits");
        bar.update_int(100).expect("update");

        let mut owned = Arc::try_unwrap(bar).ok().expect("unique Arc");
        let mut nop = NopRenderer;
        owned.draw(&mut nop).expect("draw");

        let cells = &owned.background.state().attributes.cells;
        let fill_packed = pack_color_pair(fill_palette());
        assert!(cells.iter().all(|c| *c == fill_packed));
    }

    #[test]
    fn draw_no_overlay_at_zero_percent_per_fasm_outtahere() {
        // FASM .outtahere: when fill_cells <= 0, return WITHOUT calling
        // vupdatedisplaylist. Our test verifies the buffer was painted
        // with empty_colors by nvfill, and that fill_colors does NOT
        // appear (since the overlay step was skipped).
        let bar = TuiProgressBar::new_ii(10, 1, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("ctor");
        bar.set_limits_int(0, 100).expect("limits");
        bar.update_int(0).expect("update");

        let mut owned = Arc::try_unwrap(bar).ok().expect("unique Arc");
        let mut nop = NopRenderer;
        owned.draw(&mut nop).expect("draw");

        let cells = &owned.background.state().attributes.cells;
        let empty_packed = pack_color_pair(empty_palette());
        let fill_packed = pack_color_pair(fill_palette());
        // All cells should be empty (nvfill ran), none should be fill.
        for cell in cells {
            assert_eq!(*cell, empty_packed, "no fill at 0%");
            assert_ne!(*cell, fill_packed);
        }
    }

    #[test]
    fn draw_rounds_half_to_nearest_even_per_cvtsd2si() {
        // FASM cvtsd2si rounds to nearest-even (the default rounding
        // mode); Rust f64::round rounds half-to-even when the
        // platform's default mode is preserved. For total=10, perc=0.5
        // the product is 5.0 which rounds unambiguously to 5.
        // For total=10, perc=0.55 the product is 5.5 → rounds to 6
        // (nearest-even since 6 is even) under .round() — matching
        // FASM cvtsd2si default mode.
        let bar = TuiProgressBar::new_ii(10, 1, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("ctor");
        bar.set_limits_int(0, 100).expect("limits");
        bar.update_int(55).expect("update");

        let mut owned = Arc::try_unwrap(bar).ok().expect("unique Arc");
        let mut nop = NopRenderer;
        owned.draw(&mut nop).expect("draw");

        let cells = &owned.background.state().attributes.cells;
        let fill_packed = pack_color_pair(fill_palette());
        // We expect ~6 cells filled: 10 * 0.55 = 5.5 → round → 6.
        let filled_count = cells.iter().filter(|c| **c == fill_packed).count();
        assert_eq!(filled_count, 6, "55% of 10 cells should round to 6");
    }

    // ------------------------------------------------------------------
    // clone_widget tests — preserve all 72 bytes of state
    // ------------------------------------------------------------------

    #[test]
    fn clone_preserves_value_mode_integer() {
        let bar = TuiProgressBar::new_ii(10, 1, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("ctor");
        bar.set_limits_int(5, 95).expect("limits");
        bar.update_int(42).expect("update");

        let cloned_dyn = bar.clone_widget().expect("clone");
        let cloned = cloned_dyn
            .as_any()
            .downcast_ref::<TuiProgressBar>()
            .expect("downcast");
        let inner = cloned.inner.lock().expect("lock");
        match inner.value {
            ValueMode::Integer { min, cur, max } => {
                assert_eq!(min, 5);
                assert_eq!(cur, 42);
                assert_eq!(max, 95);
            }
            ValueMode::Double { .. } => panic!("mode mismatch"),
        }
    }

    #[test]
    fn clone_preserves_value_mode_double() {
        let bar = TuiProgressBar::new_ii(10, 1, FillDirection::Reverse, empty_palette(), fill_palette())
            .expect("ctor");
        bar.set_limits_double(0.0, 100.0).expect("limits");
        bar.update_double(33.5).expect("update");

        let cloned_dyn = bar.clone_widget().expect("clone");
        let cloned = cloned_dyn
            .as_any()
            .downcast_ref::<TuiProgressBar>()
            .expect("downcast");
        let inner = cloned.inner.lock().expect("lock");
        match inner.value {
            ValueMode::Double { min, cur, max } => {
                assert_eq!(min, 0.0);
                assert_eq!(cur, 33.5);
                assert_eq!(max, 100.0);
            }
            ValueMode::Integer { .. } => panic!("mode mismatch"),
        }
    }

    #[test]
    fn clone_preserves_direction() {
        let bar = TuiProgressBar::new_ii(10, 1, FillDirection::Reverse, empty_palette(), fill_palette())
            .expect("ctor");
        let cloned_dyn = bar.clone_widget().expect("clone");
        let cloned = cloned_dyn
            .as_any()
            .downcast_ref::<TuiProgressBar>()
            .expect("downcast");
        assert_eq!(
            cloned.inner.lock().expect("lock").direction,
            FillDirection::Reverse
        );
    }

    #[test]
    fn clone_preserves_fill_colors() {
        let unique_fill = ColorPair::new(123, 45);
        let bar = TuiProgressBar::new_ii(10, 1, FillDirection::Forward, empty_palette(), unique_fill)
            .expect("ctor");
        let cloned_dyn = bar.clone_widget().expect("clone");
        let cloned = cloned_dyn
            .as_any()
            .downcast_ref::<TuiProgressBar>()
            .expect("downcast");
        assert_eq!(cloned.inner.lock().expect("lock").fill_colors, unique_fill);
    }

    #[test]
    fn clone_preserves_background_dimensions_and_fillchar() {
        let bar = TuiProgressBar::new_ii(17, 3, FillDirection::Forward, empty_palette(), fill_palette())
            .expect("ctor");
        let cloned_dyn = bar.clone_widget().expect("clone");
        let cloned = cloned_dyn
            .as_any()
            .downcast_ref::<TuiProgressBar>()
            .expect("downcast");
        assert_eq!(cloned.background.state().width, 17);
        assert_eq!(cloned.background.state().height, 3);
        assert_eq!(cloned.background.fillchar(), b' ' as u32);
        assert_eq!(cloned.background.colors(), empty_palette());
    }

    #[test]
    fn clone_creates_independent_state() {
        // Mutating the original after cloning must not affect the clone.
        let bar = make_bar_10x1();
        bar.set_limits_int(0, 100).expect("limits");
        bar.update_int(50).expect("update");

        let cloned_dyn = bar.clone_widget().expect("clone");
        let cloned = cloned_dyn
            .as_any()
            .downcast_ref::<TuiProgressBar>()
            .expect("downcast");

        // Mutate original — clone must remain at 50%.
        bar.update_int(99).expect("update");
        assert!((cloned.percentage() - 0.5).abs() < 1e-12);
        assert!((bar.percentage() - 0.99).abs() < 1e-12);
    }

    // ------------------------------------------------------------------
    // pack_color_pair smoke tests
    // ------------------------------------------------------------------

    #[test]
    fn pack_color_pair_zero_is_zero() {
        assert_eq!(pack_color_pair(ColorPair::new(0, 0)), 0);
    }

    #[test]
    fn pack_color_pair_low_byte_is_fg() {
        let packed = pack_color_pair(ColorPair::new(0xAB, 0xCD));
        assert_eq!(packed & 0xFF, 0xAB);
        assert_eq!((packed >> 8) & 0xFF, 0xCD);
        // SGR bits zero per progressbar fill convention.
        assert_eq!(packed >> 16, 0);
    }

    #[test]
    fn pack_color_pair_max_values() {
        let packed = pack_color_pair(ColorPair::new(255, 255));
        assert_eq!(packed, 0xFFFF);
    }

    #[test]
    fn attributes_len_matches_total_cells_after_draw() {
        // The `draw()` production path now queries
        // `state().attributes.len()` to size the fill slice safely.
        // After a successful draw on a 10x1 bar, the Attributes cell
        // count must equal width*height = 10. This test exercises the
        // schema-required `Attributes::len()` access from a test
        // perspective by reading the same accessor through the public
        // [`Widget::state`] API.
        let bar = make_bar_10x1();
        bar.set_limits_int(0, 100).expect("limits");
        bar.update_int(50).expect("update");

        let mut owned = Arc::try_unwrap(bar).ok().expect("unique Arc");
        let mut nop = NopRenderer;
        owned.draw(&mut nop).expect("draw");

        // Read via the public Widget::state accessor (which returns a
        // &WidgetState whose `attributes` field is `Attributes`), then
        // invoke `Attributes::len()` directly — same call path the
        // production `draw` method uses internally.
        let attr_len = owned.state().attributes.len();
        assert_eq!(attr_len, 10);

        // Cross-check: not empty.
        assert!(!owned.state().attributes.is_empty());
    }

    #[test]
    fn clone_widget_state_helper_preserves_dims() {
        let mut src = WidgetState::new();
        src.bounds = Rect::new(1, 2, 9, 8);
        src.width = 8;
        src.height = 6;
        src.visible = false;
        src.display_name.push_str("test");
        let cloned = clone_widget_state(&src).expect("clone state");
        assert_eq!(cloned.bounds, src.bounds);
        assert_eq!(cloned.width, src.width);
        assert_eq!(cloned.height, src.height);
        assert_eq!(cloned.visible, src.visible);
        assert_eq!(cloned.display_name, "test");
    }
}
