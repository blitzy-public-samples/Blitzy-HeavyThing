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
// tui_lines: VLine and HLine — thin constructors producing TuiBackground
// widgets pre-filled with Unicode box-drawing characters.
// Ported from tui_lines.inc (112 lines of FASM assembly).
//
// Rust translation © 2026, licensed under GPL-3.0-or-later. Derived from
// the HeavyThing assembly library (© 2015–2018 2 Ton Digital, Jeff
// Marrison <info@2ton.com.au>).

//! TUI line widgets — thin factories producing [`TuiBackground`] pre-filled
//! with Unicode vertical (`│`) or horizontal (`─`) box-drawing characters.
//!
//! ## FASM Parallel: `tui_lines.inc` (112 lines)
//!
//! Per FASM, `tui_vline` and `tui_hline` have **NO dedicated vtable** and
//! **NO struct extension** — they reuse `tui_background$vtable` and
//! `tui_background_size` unchanged. Only the fill character and one of
//! the two axis dimensions are fixed by the line constructor; the
//! cross-axis dimension comes from the caller:
//!
//! - VLine: fillchar `0x2502` (`│` BOX DRAWINGS LIGHT VERTICAL),
//!   width fixed at 1 cell.
//! - HLine: fillchar `0x2500` (`─` BOX DRAWINGS LIGHT HORIZONTAL),
//!   height fixed at 1 cell.
//!
//! The four FASM constructors map 1:1 to the four Rust factory functions:
//!
//! | FASM symbol            | Rust factory                           |
//! |------------------------|----------------------------------------|
//! | `tui_vline$new_i`      | [`TuiVLine::new_i`]                    |
//! | `tui_vline$new_d`      | [`TuiVLine::new_d`]                    |
//! | `tui_hline$new_i`      | [`TuiHLine::new_i`]                    |
//! | `tui_hline$new_d`      | [`TuiHLine::new_d`]                    |
//!
//! Each calls the corresponding [`TuiBackground::new_ii`] /
//! [`TuiBackground::new_id`] / [`TuiBackground::new_di`] with the
//! appropriate fillchar and 1-cell line-axis dimension.
//!
//! ## Rust Port Strategy
//!
//! Lines are pure factories — they introduce no new state, no overridden
//! behavior, and no new vtable. We expose them as associated functions on
//! dedicated zero-sized marker types ([`TuiVLine`], [`TuiHLine`]) that
//! return `Arc<TuiBackground>`. This preserves the FASM API shape — four
//! distinct constructor symbols grouped into two namespaces — while
//! avoiding unnecessary type proliferation. Callers receive a fully
//! functional [`TuiBackground`] with all 37 [`Widget`] vmethods inherited
//! from the base class.
//!
//! ## Rendering Note
//!
//! The Unicode codepoints `0x2500` and `0x2502` are stored verbatim in
//! the widget's text buffer. When the terminal is in `acs_linechars = 1`
//! mode (the FASM default), the [`crate::tui::ansi`] / [`crate::tui::render`]
//! pipeline translates them at emit time to VT100 ACS line characters
//! (`q` = horizontal, `x` = vertical) so they render correctly even on
//! terminals that lack Unicode box-drawing glyphs. This translation is a
//! property of the renderer, not of the widget — both Unicode and ACS
//! paths produce visually identical output.
//!
//! ## Usage
//!
//! Lines are typically embedded as decorative siblings inside panels,
//! forms, status bars, and other composite widgets:
//!
//! ```ignore
//! use std::sync::Arc;
//! use heavything::tui::object::{ColorPair, Widget};
//! use heavything::tui::widgets::lines::{TuiHLine, TuiVLine};
//!
//! let colors = ColorPair::new(7, 0);
//! let separator: Arc<dyn Widget> = TuiHLine::new_d(100.0, colors)?;
//! let column_divider: Arc<dyn Widget> = TuiVLine::new_i(20, colors)?;
//! # Ok::<(), heavything::error::TuiError>(())
//! ```

use std::sync::Arc;

use crate::error::TuiError;
use crate::tui::object::ColorPair;
use crate::tui::widgets::background::TuiBackground;

// ============================================================================
// Unicode fill-character constants
// ============================================================================

/// BOX DRAWINGS LIGHT VERTICAL — `U+2502` (`│`).
///
/// Used as the fill character for every [`TuiVLine`] constructor.
/// FASM parallel: literal `0x2502` in `ecx` at `tui_lines.inc` line 40
/// (`new_i`) and `edx` at line 63 (`new_d`).
///
/// When the terminal is in `acs_linechars = 1` mode, the renderer
/// translates this codepoint to VT100 ACS character `x` (0x78) at emit
/// time — see [`crate::tui::ansi`] for the translation table.
pub const VLINE_CHAR: u32 = 0x2502;

/// BOX DRAWINGS LIGHT HORIZONTAL — `U+2500` (`─`).
///
/// Used as the fill character for every [`TuiHLine`] constructor.
/// FASM parallel: literal `0x2500` in `ecx` at `tui_lines.inc` line 84
/// (`new_i`) and `edx` at line 107 (`new_d`).
///
/// When the terminal is in `acs_linechars = 1` mode, the renderer
/// translates this codepoint to VT100 ACS character `q` (0x71) at emit
/// time — see [`crate::tui::ansi`] for the translation table.
pub const HLINE_CHAR: u32 = 0x2500;

// ============================================================================
// TuiVLine — Vertical line factory
// ============================================================================

/// Vertical-line widget factory.
///
/// Zero-sized marker type whose associated functions construct a
/// [`TuiBackground`] pre-filled with [`VLINE_CHAR`] (`│`) and a fixed
/// width of 1 cell. The caller supplies only the height dimension (as
/// either an integer cell count or a percentage of the parent's content
/// area) and the foreground/background [`ColorPair`].
///
/// FASM parallel: `tui_vline$new_i` and `tui_vline$new_d`
/// (`tui_lines.inc` lines 26–68). Per FASM, `tui_vline` has **no
/// dedicated vtable** — every constructed widget reuses
/// `tui_background$vtable` directly, so all 37 [`crate::tui::object::Widget`]
/// vmethods come from the [`TuiBackground`] / `tui_object` defaults
/// without further override.
///
/// # Example
///
/// ```ignore
/// use heavything::tui::object::ColorPair;
/// use heavything::tui::widgets::lines::TuiVLine;
///
/// // 10-cell-tall vertical separator with white-on-black coloring.
/// let separator = TuiVLine::new_i(10, ColorPair::new(7, 0))?;
/// # Ok::<(), heavything::error::TuiError>(())
/// ```
pub struct TuiVLine;

impl TuiVLine {
    /// Construct a vertical line with a fixed integer height and a
    /// width of exactly 1 cell.
    ///
    /// FASM parallel: `tui_vline$new_i(esi=height, edx=colors)`
    /// (`tui_lines.inc` lines 26–45). The FASM body allocates a fresh
    /// `tui_background_size` heap slot, installs `tui_background$vtable`,
    /// and dispatches to `tui_background$init_ii(self, width=1,
    /// height, fillchar=0x2502, colors)`. The Rust translation collapses
    /// the heap allocation and vtable installation into the
    /// [`TuiBackground::new_ii`] call (which does both internally via
    /// [`Arc::new`] and the [`Widget`](crate::tui::object::Widget) trait
    /// impl on [`TuiBackground`]).
    ///
    /// # Parameters
    ///
    /// - `height` — line height in cells (passed verbatim to
    ///   [`TuiBackground::new_ii`]). Negative or zero values are
    ///   accepted by the underlying constructor; layout simply skips
    ///   buffer allocation in that case (matching FASM `init_ii` at
    ///   `tui_object.inc` lines 494–548).
    /// - `colors` — foreground/background [`ColorPair`]. Stored at
    ///   FASM offset `tui_bgcolors_ofs = tui_object_size + 8` and
    ///   applied to the entire line on every render.
    ///
    /// # Returns
    ///
    /// `Ok(Arc<TuiBackground>)` ready for embedding as
    /// `Arc<dyn Widget>` in any parent's children list.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] only if the underlying
    /// [`TuiBackground::new_ii`] fails to allocate the text/attribute
    /// buffers (typically arithmetic overflow on extreme dimensions);
    /// in normal operating conditions this constructor is infallible.
    pub fn new_i(height: i32, colors: ColorPair) -> Result<Arc<TuiBackground>, TuiError> {
        TuiBackground::new_ii(1, height, VLINE_CHAR, colors)
    }

    /// Construct a vertical line with a percentage-of-parent height and
    /// a width of exactly 1 cell.
    ///
    /// FASM parallel: `tui_vline$new_d(xmm0=heightperc, edi=colors)`
    /// (`tui_lines.inc` lines 47–68). The FASM body allocates a fresh
    /// `tui_background_size` heap slot, installs `tui_background$vtable`,
    /// and dispatches to `tui_background$init_id(self, width=1,
    /// heightperc, fillchar=0x2502, colors)` — note that the percentage
    /// is passed in `xmm0` to match the SystemV ABI convention for
    /// floating-point arguments.
    ///
    /// # Parameters
    ///
    /// - `height_perc` — line height as a percentage of the parent's
    ///   content height (typical range `0.0..=100.0`; values outside
    ///   the range are accepted but parent layout will clamp on render).
    /// - `colors` — foreground/background [`ColorPair`].
    ///
    /// # Returns
    ///
    /// `Ok(Arc<TuiBackground>)` whose absolute height will be resolved
    /// to `parent.height × height_perc / 100` on the next layout pass.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] for API symmetry; this constructor
    /// is infallible in practice (no buffer allocation occurs because
    /// the absolute height is unknown until layout — matching FASM
    /// `tui_object$init_id` at `tui_object.inc` lines 400–427).
    pub fn new_d(height_perc: f64, colors: ColorPair) -> Result<Arc<TuiBackground>, TuiError> {
        TuiBackground::new_id(1, height_perc, VLINE_CHAR, colors)
    }
}

// ============================================================================
// TuiHLine — Horizontal line factory
// ============================================================================

/// Horizontal-line widget factory.
///
/// Zero-sized marker type whose associated functions construct a
/// [`TuiBackground`] pre-filled with [`HLINE_CHAR`] (`─`) and a fixed
/// height of 1 cell. The caller supplies only the width dimension (as
/// either an integer cell count or a percentage of the parent's content
/// area) and the foreground/background [`ColorPair`].
///
/// FASM parallel: `tui_hline$new_i` and `tui_hline$new_d`
/// (`tui_lines.inc` lines 70–112). Per FASM, `tui_hline` has **no
/// dedicated vtable** — every constructed widget reuses
/// `tui_background$vtable` directly, so all 37
/// [`crate::tui::object::Widget`] vmethods come from the
/// [`TuiBackground`] / `tui_object` defaults without further override.
///
/// # Example
///
/// ```ignore
/// use heavything::tui::object::ColorPair;
/// use heavything::tui::widgets::lines::TuiHLine;
///
/// // Full-width horizontal separator with white-on-black coloring.
/// let separator = TuiHLine::new_d(100.0, ColorPair::new(7, 0))?;
/// # Ok::<(), heavything::error::TuiError>(())
/// ```
pub struct TuiHLine;

impl TuiHLine {
    /// Construct a horizontal line with a fixed integer width and a
    /// height of exactly 1 cell.
    ///
    /// FASM parallel: `tui_hline$new_i(esi=width, edx=colors)`
    /// (`tui_lines.inc` lines 70–89). The FASM body allocates a fresh
    /// `tui_background_size` heap slot, installs `tui_background$vtable`,
    /// and dispatches to `tui_background$init_ii(self, width,
    /// height=1, fillchar=0x2500, colors)`. The Rust translation
    /// collapses the heap allocation and vtable installation into the
    /// [`TuiBackground::new_ii`] call.
    ///
    /// # Parameters
    ///
    /// - `width` — line width in cells (passed verbatim to
    ///   [`TuiBackground::new_ii`]). Negative or zero values are
    ///   accepted by the underlying constructor; layout simply skips
    ///   buffer allocation in that case.
    /// - `colors` — foreground/background [`ColorPair`].
    ///
    /// # Returns
    ///
    /// `Ok(Arc<TuiBackground>)` ready for embedding as
    /// `Arc<dyn Widget>` in any parent's children list.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] only if the underlying
    /// [`TuiBackground::new_ii`] fails to allocate the text/attribute
    /// buffers (typically arithmetic overflow on extreme dimensions);
    /// in normal operating conditions this constructor is infallible.
    pub fn new_i(width: i32, colors: ColorPair) -> Result<Arc<TuiBackground>, TuiError> {
        TuiBackground::new_ii(width, 1, HLINE_CHAR, colors)
    }

    /// Construct a horizontal line with a percentage-of-parent width
    /// and a height of exactly 1 cell.
    ///
    /// FASM parallel: `tui_hline$new_d(xmm0=widthperc, edi=colors)`
    /// (`tui_lines.inc` lines 91–112). The FASM body allocates a fresh
    /// `tui_background_size` heap slot, installs `tui_background$vtable`,
    /// and dispatches to `tui_background$init_di(self, widthperc,
    /// height=1, fillchar=0x2500, colors)` — the percentage rides
    /// in `xmm0` per SystemV ABI for floating-point arguments.
    ///
    /// # Parameters
    ///
    /// - `width_perc` — line width as a percentage of the parent's
    ///   content width (typical range `0.0..=100.0`).
    /// - `colors` — foreground/background [`ColorPair`].
    ///
    /// # Returns
    ///
    /// `Ok(Arc<TuiBackground>)` whose absolute width will be resolved
    /// to `parent.width × width_perc / 100` on the next layout pass.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] for API symmetry; this constructor
    /// is infallible in practice (no buffer allocation occurs because
    /// the absolute width is unknown until layout — matching FASM
    /// `tui_object$init_di` at `tui_object.inc` lines 429–459).
    pub fn new_d(width_perc: f64, colors: ColorPair) -> Result<Arc<TuiBackground>, TuiError> {
        TuiBackground::new_di(width_perc, 1, HLINE_CHAR, colors)
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    // Bring the `Widget` trait into scope so the `.state()` method on
    // `Arc<TuiBackground>` resolves to the trait method that returns the
    // shared `WidgetState` reference. The trait is only needed in tests
    // because lines.rs does not implement Widget directly — its
    // factories return `Arc<TuiBackground>` whose Widget impl lives in
    // the `background` submodule.
    use crate::tui::object::Widget;

    /// Sanity-check that the FASM literal codepoints are preserved
    /// verbatim. Any change here would silently break ACS-linechar
    /// fallback rendering on terminals that lack Unicode glyphs.
    #[test]
    fn vline_and_hline_chars_match_fasm_literals() {
        assert_eq!(
            VLINE_CHAR, 0x2502,
            "VLINE_CHAR must match FASM tui_lines.inc line 40"
        );
        assert_eq!(
            HLINE_CHAR, 0x2500,
            "HLINE_CHAR must match FASM tui_lines.inc line 84"
        );
    }

    /// `TuiVLine::new_i` must produce a 1-cell-wide widget at the
    /// caller-supplied integer height. FASM `tui_vline$new_i` passes
    /// `esi=1, edx=height` to `tui_background$init_ii`.
    #[test]
    fn vline_new_i_has_width_one_and_caller_supplied_height() {
        let colors = ColorPair { fg: 7, bg: 0 };
        let vline = TuiVLine::new_i(10, colors).expect("TuiVLine::new_i must succeed for valid input");
        let state = vline.state();
        assert_eq!(state.width, 1, "VLine width must be fixed at 1 cell");
        assert_eq!(state.height, 10, "VLine height must equal caller-supplied value");
        assert_eq!(state.width_percent, None, "integer width has no percentage");
        assert_eq!(state.height_percent, None, "integer height has no percentage");
    }

    /// `TuiVLine::new_d` must produce a 1-cell-wide widget with the
    /// caller-supplied percentage height. FASM `tui_vline$new_d` passes
    /// `esi=1` and the f64 percentage to `tui_background$init_id`.
    #[test]
    fn vline_new_d_has_width_one_and_caller_supplied_height_percent() {
        let colors = ColorPair { fg: 7, bg: 0 };
        let vline = TuiVLine::new_d(50.0, colors).expect("TuiVLine::new_d must succeed for valid input");
        let state = vline.state();
        assert_eq!(state.width, 1, "VLine width must be fixed at 1 cell");
        assert_eq!(state.width_percent, None, "integer width has no percentage");
        assert_eq!(
            state.height_percent,
            Some(50.0),
            "VLine height_percent must equal caller-supplied value"
        );
    }

    /// `TuiHLine::new_i` must produce a 1-cell-tall widget at the
    /// caller-supplied integer width. FASM `tui_hline$new_i` passes
    /// `esi=width, edx=1` to `tui_background$init_ii`.
    #[test]
    fn hline_new_i_has_height_one_and_caller_supplied_width() {
        let colors = ColorPair { fg: 7, bg: 0 };
        let hline = TuiHLine::new_i(20, colors).expect("TuiHLine::new_i must succeed for valid input");
        let state = hline.state();
        assert_eq!(state.width, 20, "HLine width must equal caller-supplied value");
        assert_eq!(state.height, 1, "HLine height must be fixed at 1 cell");
        assert_eq!(state.width_percent, None, "integer width has no percentage");
        assert_eq!(state.height_percent, None, "integer height has no percentage");
    }

    /// `TuiHLine::new_d` must produce a 1-cell-tall widget with the
    /// caller-supplied percentage width. FASM `tui_hline$new_d` passes
    /// the f64 percentage and `esi=1` to `tui_background$init_di`.
    #[test]
    fn hline_new_d_has_height_one_and_caller_supplied_width_percent() {
        let colors = ColorPair { fg: 7, bg: 0 };
        let hline = TuiHLine::new_d(100.0, colors).expect("TuiHLine::new_d must succeed for valid input");
        let state = hline.state();
        assert_eq!(
            state.width_percent,
            Some(100.0),
            "HLine width_percent must equal caller-supplied value"
        );
        assert_eq!(state.height, 1, "HLine height must be fixed at 1 cell");
        assert_eq!(state.height_percent, None, "integer height has no percentage");
    }

    /// Both line types must preserve the caller-supplied [`ColorPair`]
    /// fields byte-for-byte; the FASM `tui_bgcolors_ofs` slot stores
    /// the colors verbatim and the renderer reads them directly.
    #[test]
    fn lines_preserve_colors_verbatim() {
        let colors = ColorPair { fg: 0x42, bg: 0xA7 };

        let vline_i = TuiVLine::new_i(5, colors).expect("vline new_i");
        assert_eq!(vline_i.bgcolors.fg, 0x42);
        assert_eq!(vline_i.bgcolors.bg, 0xA7);
        assert_eq!(vline_i.bgfillchar, VLINE_CHAR);

        let vline_d = TuiVLine::new_d(25.0, colors).expect("vline new_d");
        assert_eq!(vline_d.bgcolors.fg, 0x42);
        assert_eq!(vline_d.bgcolors.bg, 0xA7);
        assert_eq!(vline_d.bgfillchar, VLINE_CHAR);

        let hline_i = TuiHLine::new_i(8, colors).expect("hline new_i");
        assert_eq!(hline_i.bgcolors.fg, 0x42);
        assert_eq!(hline_i.bgcolors.bg, 0xA7);
        assert_eq!(hline_i.bgfillchar, HLINE_CHAR);

        let hline_d = TuiHLine::new_d(75.0, colors).expect("hline new_d");
        assert_eq!(hline_d.bgcolors.fg, 0x42);
        assert_eq!(hline_d.bgcolors.bg, 0xA7);
        assert_eq!(hline_d.bgfillchar, HLINE_CHAR);
    }

    /// Verify the returned `Arc<TuiBackground>` coerces to
    /// `Arc<dyn Widget>` — the canonical way in which line widgets are
    /// embedded in parent widget trees. This test catches accidental
    /// regressions where `TuiBackground` stops implementing `Widget`
    /// or the `Send + Sync` bound is violated.
    #[test]
    fn lines_coerce_to_arc_dyn_widget() {
        let colors = ColorPair::default();
        let vline: Arc<TuiBackground> = TuiVLine::new_i(3, colors).expect("vline");
        let hline: Arc<TuiBackground> = TuiHLine::new_i(7, colors).expect("hline");

        // Coerce to Arc<dyn Widget> — proves Widget is implemented and
        // the trait object is constructible. If TuiBackground stops
        // satisfying `Widget: Send + Sync`, this line fails to compile.
        let _vline_dyn: Arc<dyn Widget> = vline;
        let _hline_dyn: Arc<dyn Widget> = hline;
    }
}
