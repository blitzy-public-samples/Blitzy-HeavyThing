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
// tui_background: The foundational TUI widget — a solid-color rectangle with
// an optional fill character. Base class for ~12 other widget types.
// Ported from tui_background.inc (263 lines of FASM assembly).

//! TUI background widget — solid-color rectangle with optional fill character.
//!
//! ## FASM Parallel: `tui_background.inc` (263 lines)
//!
//! [`TuiBackground`] is the foundational TUI widget. It inherits from
//! [`tui_object`](crate::tui::object) (all 37 vmethods available via
//! [`Widget`] default impls), and overrides only:
//!
//! - [`Widget::clone_widget`] (vtable slot 1) — deep-copy self including
//!   fillchar + colors and recursively clone the children list.
//! - [`Widget::draw`] (vtable slot 2) — fill the text/attr buffers via
//!   [`TuiBackground::nvfill`] then trigger
//!   [`Widget::update_display_list`].
//!
//! All 35 other vmethods use the trait defaults from
//! [`crate::tui::object::Widget`], matching the FASM `tui_background$vtable`
//! at `tui_background.inc` lines 26–39 which delegates every non-overridden
//! slot to the corresponding `tui_object$*` function.
//!
//! ## Struct Layout (FASM offsets)
//! ```text
//! tui_bgfillchar_ofs = tui_object_size      ; +0  (dd — u32 Unicode codepoint)
//! tui_bgcolors_ofs   = tui_object_size + 8  ; +8  (dd — packed ColorPair)
//! tui_background_size = tui_object_size + 16
//! ```
//!
//! The Rust translation collapses both `dd` fields into ordinary struct
//! fields (`bgfillchar: u32`, `bgcolors: ColorPair`) embedded after the
//! [`WidgetState`] base. Exact byte-level layout matches FASM only in
//! semantics, not in raw memory layout (Rust's struct repr is opaque
//! unless `#[repr(C)]` is used; we do not need binary compatibility with
//! FASM-emitted memory).
//!
//! ## Fill Character Semantics
//!
//! - `fillchar == 0`: do **not** fill the text buffer (leave prior content
//!   intact); only update the attributes buffer with `colors`.
//! - `fillchar != 0`: fill **both** the text buffer (with fillchar) and
//!   the attributes buffer (with colors).
//!
//! This distinction is load-bearing for descendants. Widgets such as
//! [`TuiButton`](crate::tui::widgets::button) (when ported) store their
//! label in the text buffer first, then set fillchar=0 so subsequent
//! redraws do not overwrite the label content.
//!
//! ## Descendants
//!
//! TuiBackground is the direct base class for these widget types
//! (per AAP §0.5.1.5):
//!
//! `lines`, `bell`, `newsticker`, `splash`, `panel`, `button`,
//! `progressbar`, `typist`, `label`, `simpleauth`, `form`, `text`.

use std::any::Any;
use std::sync::Arc;

use crate::ds::Buffer;
use crate::error::TuiError;
use crate::tui::geometry::Rect;
use crate::tui::object::{Attributes, ColorPair, Widget, WidgetState};
use crate::tui::render::Renderer;

// ============================================================================
// TuiBackground — primary type
// ============================================================================

/// Foundational TUI widget — a solid-color rectangle with an optional
/// fill character.
///
/// FASM parallel: `tui_background` (`tui_background.inc`, 263 lines).
///
/// ## Fields (matching FASM offsets)
///
/// - `state`: inherited [`WidgetState`] from `tui_object` (bounds, width,
///   height, text/attr buffers, children, bastards, layout, alignment,
///   etc.).
/// - `bgfillchar`: Unicode codepoint to fill the text buffer with.
///   `0` = skip text fill (only update attributes). Matches FASM
///   `tui_bgfillchar_ofs = tui_object_size + 0`.
/// - `bgcolors`: packed fg/bg [`ColorPair`] applied to the entire
///   rectangle. Matches FASM `tui_bgcolors_ofs = tui_object_size + 8`.
///
/// ## Construction
///
/// Five constructors mirror FASM's five `tui_background$init_*` variants:
///
/// - [`new_rect`](Self::new_rect) — explicit [`Rect`] bounds.
/// - [`new_ii`](Self::new_ii) — integer width × integer height.
/// - [`new_id`](Self::new_id) — integer width × percentage height.
/// - [`new_di`](Self::new_di) — percentage width × integer height.
/// - [`new_dd`](Self::new_dd) — percentage width × percentage height.
///
/// All five return `Result<Arc<Self>, TuiError>` so the widget can be
/// embedded as `Arc<dyn Widget>` in any parent's children list while
/// preserving the `Send + Sync` bound on the [`Widget`] trait.
///
/// ## Thread safety
///
/// `TuiBackground` is `Send + Sync` because all its fields are
/// `Send + Sync` ([`WidgetState`] inherits the bound from its
/// `Arc<dyn Widget>` children list; `u32` and [`ColorPair`] are `Copy`).
pub struct TuiBackground {
    /// Inherited state from `tui_object` — bounds, width/height,
    /// text/attr buffers, layout, children list, etc.
    pub(crate) state: WidgetState,

    /// Unicode codepoint to fill the text buffer with on
    /// [`nvfill`](Self::nvfill). `0` = skip text fill (attributes only).
    ///
    /// FASM offset: `tui_bgfillchar_ofs = tui_object_size + 0`
    /// (`tui_background.inc` line 42).
    pub bgfillchar: u32,

    /// Color pair (fg/bg) applied to the entire rectangle on
    /// [`nvfill`](Self::nvfill). Always applied regardless of
    /// `bgfillchar` value.
    ///
    /// FASM offset: `tui_bgcolors_ofs = tui_object_size + 8`
    /// (`tui_background.inc` line 43).
    pub bgcolors: ColorPair,
}

// ============================================================================
// Construction — five FASM init_* variants
// ============================================================================

impl TuiBackground {
    /// Constructor from explicit [`Rect`] bounds.
    ///
    /// Computes `width = bounds.width()` and `height = bounds.height()`
    /// from the half-open rectangle. When both width and height are
    /// positive, the text and attributes buffers are pre-allocated and
    /// zero-filled — matching FASM `tui_object$init_rect`
    /// (`tui_object.inc` lines 336–397) which does the equivalent
    /// `heap$alloc(cells * 4)` + `memset32(buf, 0, bytes)` for both
    /// buffers.
    ///
    /// FASM parallel: `tui_background$init_rect`
    /// (`tui_background.inc` lines 78–97):
    ///
    /// ```text
    ///   tui_object$init_rect(self, &Rect)
    ///   self.bgfillchar = fillchar
    ///   self.bgcolors   = colors
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] only if buffer allocation fails
    /// (typically OOM); in practice this constructor is infallible
    /// under normal operating conditions but the [`Result`] return
    /// type is preserved for API symmetry with [`Widget::clone_widget`].
    pub fn new_rect(bounds: Rect, fillchar: u32, colors: ColorPair) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.bounds = bounds;
        state.width = bounds.width();
        state.height = bounds.height();
        state.width_percent = None;
        state.height_percent = None;
        Self::finalize_init(state, fillchar, colors)
    }

    /// Constructor — integer width and integer height.
    ///
    /// When both `width` and `height` are positive, the text and
    /// attributes buffers are pre-allocated and zero-filled (matching
    /// FASM `tui_object$init_ii`, `tui_object.inc` lines 494–548).
    ///
    /// FASM parallel: `tui_background$init_ii`
    /// (`tui_background.inc` lines 165–183):
    ///
    /// ```text
    ///   tui_object$init_ii(self, width, height)
    ///   self.bgfillchar = fillchar
    ///   self.bgcolors   = colors
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] only if buffer allocation fails.
    pub fn new_ii(width: i32, height: i32, fillchar: u32, colors: ColorPair) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = height;
        state.width_percent = None;
        state.height_percent = None;
        Self::finalize_init(state, fillchar, colors)
    }

    /// Constructor — integer width, percentage height.
    ///
    /// Buffers are **not** pre-allocated because the absolute height is
    /// unknown until layout resolves the parent's content area; the
    /// layout pass allocates the buffers when it computes the final
    /// dimensions (matching FASM `tui_object$init_id` at
    /// `tui_object.inc` lines 400–427 which does not allocate buffers).
    ///
    /// FASM parallel: `tui_background$init_id`
    /// (`tui_background.inc` lines 99–118).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] for API symmetry; this constructor
    /// is infallible in practice.
    pub fn new_id(
        width: i32,
        height_perc: f64,
        fillchar: u32,
        colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = 0;
        state.width_percent = None;
        state.height_percent = Some(height_perc);
        Self::finalize_init(state, fillchar, colors)
    }

    /// Constructor — percentage width, integer height.
    ///
    /// Buffers are **not** pre-allocated (matching FASM
    /// `tui_object$init_di` at `tui_object.inc` lines 429–459).
    ///
    /// FASM parallel: `tui_background$init_di`
    /// (`tui_background.inc` lines 121–140).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] for API symmetry; this constructor
    /// is infallible in practice.
    pub fn new_di(
        width_perc: f64,
        height: i32,
        fillchar: u32,
        colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = 0;
        state.height = height;
        state.width_percent = Some(width_perc);
        state.height_percent = None;
        Self::finalize_init(state, fillchar, colors)
    }

    /// Constructor — percentage width and percentage height.
    ///
    /// Buffers are **not** pre-allocated (matching FASM
    /// `tui_object$init_dd` at `tui_object.inc` lines 461–492).
    ///
    /// FASM parallel: `tui_background$init_dd`
    /// (`tui_background.inc` lines 143–162).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] for API symmetry; this constructor
    /// is infallible in practice.
    pub fn new_dd(
        width_perc: f64,
        height_perc: f64,
        fillchar: u32,
        colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = 0;
        state.height = 0;
        state.width_percent = Some(width_perc);
        state.height_percent = Some(height_perc);
        Self::finalize_init(state, fillchar, colors)
    }

    /// Internal helper: shared post-init setup for all five
    /// constructors.
    ///
    /// Pre-allocates and zero-fills the text and attributes buffers
    /// when both `state.width > 0` and `state.height > 0`, matching the
    /// FASM `tui_object$init_rect` / `init_ii` allocation path. For
    /// constructors with percentage-based dimensions the buffers stay
    /// empty because the layout pass owns their sizing.
    ///
    /// `WidgetState::new()` already sets `visible = true`,
    /// `include_in_layout = true`, `absolute_x = -1`,
    /// `absolute_y = -1`, so this helper does **not** re-set those
    /// fields — doing so would mask FASM's "not-yet-positioned"
    /// sentinel semantics for `absolute_x/y`.
    fn finalize_init(
        mut state: WidgetState,
        fillchar: u32,
        colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        // Pre-allocate buffers when dimensions are concretely known.
        // FASM init_rect / init_ii zero-fills both buffers via memset32
        // with esi=0 (zero value); we mirror this with `vec![0; bytes]`.
        if state.width > 0 && state.height > 0 {
            let cells = (state.width as usize)
                .checked_mul(state.height as usize)
                .ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(format!(
                        "TuiBackground: width*height overflowed usize \
                         (width={}, height={})",
                        state.width, state.height
                    )))
                })?;
            let bytes = cells.checked_mul(4).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(format!(
                    "TuiBackground: cells*4 overflowed usize (cells={cells})"
                )))
            })?;
            // Reserve and append `bytes` zero bytes to the text buffer.
            state.text.reserve_exact(bytes);
            for _ in 0..bytes {
                state.text.push(0);
            }
            // Resize attributes to `cells` zero entries.
            state.attributes.cells.resize(cells, 0);
        }

        Ok(Arc::new(Self {
            state,
            bgfillchar: fillchar,
            bgcolors: colors,
        }))
    }
}

// ============================================================================
// Clone helper — backs Widget::clone_widget (vtable slot 1)
// ============================================================================

impl TuiBackground {
    /// Deep-clone helper used by [`Widget::clone_widget`].
    ///
    /// Performs the FASM `tui_background$init_copy` algorithm
    /// (`tui_background.inc` lines 56–75):
    ///
    /// 1. `tui_object$init_copy(dst, src)` — copies all base fields,
    ///    fresh-allocates text/attr buffers (if width/height > 0) and
    ///    deep-copies their contents, deep-clones every child via the
    ///    child's own `vclone` vmethod, leaves bastards empty.
    /// 2. Copy `bgfillchar` (32-bit dword) and `bgcolors` (32-bit dword)
    ///    from src to dst.
    ///
    /// FASM behavior preserved exactly:
    /// - **Children are deeply cloned** (each via `clone_widget`).
    /// - **Bastards are NOT cloned** (left empty in the copy) — see
    ///   `tui_object.inc` line 274 where init_copy resets bastards to a
    ///   fresh empty list.
    /// - **Text/attr buffer contents are duplicated** (memcpy in FASM,
    ///   `Buffer::clone` / `Vec::clone` in Rust).
    /// - `absolute_x` / `absolute_y` are copied verbatim (FASM memcpy
    ///   covers them; the layout pass will re-resolve on next layout
    ///   pass if needed).
    /// - `display_name` is deep-copied (FASM `string$copy`; Rust
    ///   `String::clone`).
    fn init_copy_from(src: &Self) -> Result<Self, TuiError> {
        let cloned_state = Self::clone_widget_state(&src.state)?;
        Ok(Self {
            state: cloned_state,
            bgfillchar: src.bgfillchar,
            bgcolors: src.bgcolors,
        })
    }

    /// Deep-clone a [`WidgetState`] following FASM
    /// `tui_object$init_copy` (`tui_object.inc` lines 235–333) semantics.
    ///
    /// - All scalar fields are bitwise-copied.
    /// - `display_name` is deep-copied.
    /// - `text` and `attributes` are deep-copied (preserving cell-level
    ///   contents) — this matches FASM's `heap$alloc` + `memcpy`
    ///   sequence at `tui_object.inc` lines 286–303.
    /// - `children` are deep-cloned by invoking each child's
    ///   `clone_widget` vmethod (FASM `list$foreach` with `.childrencopy`
    ///   callback at lines 308–331).
    /// - `bastards` are intentionally **not** cloned — the cloned
    ///   state's bastards list is freshly empty, matching FASM line 274
    ///   (`call list$new; mov [rdi+tui_bastards_ofs], rax`).
    fn clone_widget_state(src: &WidgetState) -> Result<WidgetState, TuiError> {
        let mut cloned = WidgetState::new();

        // Scalar fields — direct copies.
        cloned.bounds = src.bounds;
        cloned.width = src.width;
        cloned.width_percent = src.width_percent;
        cloned.height = src.height;
        cloned.height_percent = src.height_percent;
        cloned.visible = src.visible;
        cloned.include_in_layout = src.include_in_layout;
        // FASM init_copy memcpys absolute_x/y as part of the full
        // tui_object_size memcpy; we preserve that here. The layout
        // pass will re-resolve these on next pass if the parent moves.
        cloned.absolute_x = src.absolute_x;
        cloned.absolute_y = src.absolute_y;
        cloned.layout = src.layout;
        cloned.horiz_align = src.horiz_align;
        cloned.vert_align = src.vert_align;
        cloned.bastard_glue = src.bastard_glue;
        cloned.drop_shadow = src.drop_shadow;
        cloned.scroll = src.scroll;
        cloned.display_name = src.display_name.clone();

        // Text / attributes — deep-copy contents (matching FASM memcpy).
        // `Buffer` and `Attributes` both derive `Clone`, so `.clone()` is
        // a deep copy of the backing `Vec<u8>` / `Vec<u32>`.
        cloned.text = src.text.clone();
        cloned.attributes = src.attributes.clone();

        // Children — deep-clone via each child's `clone_widget`.
        // Bastards remain empty (matching FASM init_copy).
        for child in src.children.iter() {
            let cloned_child = child.clone_widget()?;
            cloned.children.push_back(cloned_child);
        }

        Ok(cloned)
    }
}

// ============================================================================
// nvfill — non-virtual fill helper
// ============================================================================

impl TuiBackground {
    /// Fill the text buffer with [`bgfillchar`](Self::bgfillchar) (when
    /// non-zero) and the attributes buffer with
    /// [`bgcolors`](Self::bgcolors).
    ///
    /// Does **not** trigger a display refresh — callers that want a
    /// full draw cycle invoke [`Widget::draw`] which composes
    /// `nvfill` + [`Widget::update_display_list`].
    ///
    /// FASM parallel: `tui_background$nvfill`
    /// (`tui_background.inc` lines 220–263).
    ///
    /// ## Bail-out conditions (matching FASM `.nothingtodo` / `.bailout`)
    ///
    /// - `width <= 0` or `height <= 0`: returns `Ok(())` with no buffer
    ///   modifications (FASM `.nothingtodo`).
    /// - `text` buffer is empty: returns `Ok(())` (FASM `.bailout`,
    ///   triggered by `mov rdi, [tui_text_ofs]; test rdi, rdi; jz`).
    ///   This handles the case where layout has not yet allocated the
    ///   buffers (e.g. percentage-based constructors before first
    ///   layout).
    ///
    /// ## Fill rules
    ///
    /// - When `bgfillchar != 0`: fill the first `cells * 4` bytes of
    ///   the text buffer with the codepoint's little-endian bytes
    ///   repeated per 4-byte cell.
    /// - When `bgfillchar == 0`: skip text fill (FASM `.attronly`).
    /// - **Always** fill the first `cells` u32s of the attributes
    ///   buffer with the packed [`bgcolors`](Self::bgcolors) value.
    ///
    /// ## Why public to the crate
    ///
    /// Other widgets (e.g. `TuiNewsticker`, `TuiProgressBar` once
    /// ported) call `nvfill` directly to establish a clean background
    /// before drawing their specialized content on top — mirroring the
    /// FASM convention where `tui_background$nvfill` is a published
    /// helper symbol.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] only on arithmetic overflow when
    /// computing `cells * 4` (impossible for any realistic terminal
    /// dimensions).
    pub(crate) fn nvfill(&mut self) -> Result<(), TuiError> {
        let width = self.state.width;
        let height = self.state.height;

        // FASM .nothingtodo — bail when either dimension is zero (or
        // negative, which the FASM unsigned compares cannot represent
        // but Rust's signed i32 can; we treat negative as zero).
        if width <= 0 || height <= 0 {
            return Ok(());
        }

        // FASM .bailout — bail when the text buffer is null (in Rust:
        // empty, since `Buffer::default()` is a zero-length `Vec<u8>`).
        if self.state.text.is_empty() {
            return Ok(());
        }

        // Compute cell count, checking for arithmetic overflow.
        let cells = (width as usize).checked_mul(height as usize).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(format!(
                "TuiBackground::nvfill: width*height overflowed usize \
                     (width={width}, height={height})"
            )))
        })?;

        // Fill the text buffer iff fillchar != 0 (FASM .attronly skip).
        if self.bgfillchar != 0 {
            fill_u32_buffer(&mut self.state.text, self.bgfillchar, cells)?;
        }

        // ALWAYS fill the attributes buffer (FASM falls through from
        // .attronly into the attr memset32 unconditionally).
        let packed = pack_color_pair(self.bgcolors);
        fill_u32_attributes(&mut self.state.attributes, packed, cells)?;

        Ok(())
    }
}

// ============================================================================
// Public setters / getters
// ============================================================================

impl TuiBackground {
    /// Set the fill character.
    ///
    /// Pass `0` to disable text fill — useful for descendants such as
    /// `TuiButton` / `TuiLabel` that store their text content in the
    /// text buffer and do not want subsequent
    /// [`nvfill`](Self::nvfill) calls to overwrite it.
    pub fn set_fillchar(&mut self, fillchar: u32) {
        self.bgfillchar = fillchar;
    }

    /// Set the color pair (fg/bg).
    ///
    /// Applied to the entire rectangle on the next
    /// [`nvfill`](Self::nvfill) / [`Widget::draw`] invocation.
    pub fn set_colors(&mut self, colors: ColorPair) {
        self.bgcolors = colors;
    }

    /// Get the current fill character (`0` = text fill disabled).
    #[must_use]
    pub fn fillchar(&self) -> u32 {
        self.bgfillchar
    }

    /// Get the current color pair.
    #[must_use]
    pub fn colors(&self) -> ColorPair {
        self.bgcolors
    }
}

// ============================================================================
// Widget trait implementation — overrides ONLY clone_widget + draw
// ============================================================================

impl Widget for TuiBackground {
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
    /// `TuiBackground` via [`Any::downcast_ref`].
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Override — vtable slot 1 (`tui_vclone`).
    ///
    /// FASM parallel: `tui_background$clone`
    /// (`tui_background.inc` lines 186–203):
    ///
    /// ```text
    ///   heap$alloc(tui_background_size)
    ///   set vtable to tui_background$vtable
    ///   tui_background$init_copy(new, self)
    ///   return new
    /// ```
    ///
    /// In Rust the vtable concept is replaced by trait dispatch on
    /// `dyn Widget`. Allocation is implicit via [`Arc::new`]; the
    /// initialization step ([`init_copy_from`](Self::init_copy_from))
    /// performs the FASM `tui_object$init_copy` deep-clone of the base
    /// state plus copying the two `bg*` fields.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        let cloned = Self::init_copy_from(self)?;
        Ok(Arc::new(cloned) as Arc<dyn Widget>)
    }

    /// Override — vtable slot 2 (`tui_vdraw`).
    ///
    /// FASM parallel: `tui_background$draw`
    /// (`tui_background.inc` lines 206–217):
    ///
    /// ```text
    ///   tui_background$nvfill(self)
    ///   self.vtable.updatedisplaylist(self)
    /// ```
    ///
    /// 1. Populate this widget's text and attribute buffers via
    ///    [`nvfill`](Self::nvfill).
    /// 2. Trigger the display-list update via the `Widget` vmethod
    ///    [`Widget::update_display_list`] (vtable slot 4) — the default
    ///    implementation is a no-op, but renderer-aware compositions
    ///    override it to flush the buffers to a target surface.
    ///
    /// The `_renderer` parameter is accepted to satisfy the
    /// [`Widget`] trait signature; the actual flush happens through
    /// `update_display_list` rather than direct renderer calls because
    /// FASM's `tui_background$draw` invokes the polymorphic
    /// `vupdatedisplaylist` rather than emitting bytes directly. This
    /// matches the FASM convention where `draw` is composition-only:
    /// it touches state buffers and dispatches the display update; it
    /// does not write to the terminal itself.
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        self.nvfill()?;
        // Vtable slot 4 — the default is a no-op (matching FASM
        // tui_object$updatedisplaylist when no override is in place);
        // descendant widgets and renderer-bound compositions override
        // update_display_list to push the populated buffers through
        // the rendering pipeline.
        self.update_display_list();
        Ok(())
    }
}

// ============================================================================
// Internal helpers — buffer fill primitives
// ============================================================================

/// Fill the first `count` 4-byte cells of `buf` with the little-endian
/// bytes of `value`, growing or truncating the buffer to exactly
/// `count * 4` bytes.
///
/// FASM parallel: `memset32(rdi=buf, esi=value, rdx=count)` from
/// `memfuncs.inc`. The FASM helper writes `count` 32-bit dwords; this
/// function preserves that semantic by writing `count` u32s in
/// little-endian byte order (matching `x86_64` native byte order).
///
/// # Behavior contract
///
/// - On entry, `buf` may have any current length (including zero or
///   more than `count * 4`).
/// - On return, the first `count * 4` bytes of `buf` contain `count`
///   copies of `value`'s little-endian bytes.
/// - Any bytes beyond `count * 4` are removed (truncated).
///
/// # Errors
///
/// Returns [`TuiError::Render`] on arithmetic overflow computing
/// `count * 4`.
fn fill_u32_buffer(buf: &mut Buffer, value: u32, count: usize) -> Result<(), TuiError> {
    let bytes = count.checked_mul(4).ok_or_else(|| {
        TuiError::Render(std::io::Error::other(format!(
            "fill_u32_buffer: count*4 overflowed usize (count={count})"
        )))
    })?;

    // Ensure the buffer has at least `bytes` bytes of capacity.
    if buf.len() < bytes {
        buf.reserve(bytes - buf.len());
        // Append zero bytes up to `bytes` length so the slice exists.
        for _ in buf.len()..bytes {
            buf.push(0);
        }
    }

    // Truncate any tail beyond `bytes` so the buffer length matches
    // exactly what nvfill expects (FASM caller works on a fixed-size
    // allocation, so we mirror that). `Buffer::truncate(n)` removes
    // `n` bytes from the END (FASM-style API), so to shrink the
    // buffer down to `bytes` total length we pass the count of
    // bytes-to-remove (`buf.len() - bytes`).
    if buf.len() > bytes {
        let to_remove = buf.len() - bytes;
        buf.truncate(to_remove).map_err(|e| {
            TuiError::Render(std::io::Error::other(format!(
                "fill_u32_buffer: truncate failed: {e:?}"
            )))
        })?;
    }

    // Write `count` little-endian u32s into the first `bytes` bytes.
    // We use the mutable slice view so we don't disturb capacity.
    let value_le = value.to_le_bytes();
    let slice = buf.as_mut_slice();
    debug_assert!(
        slice.len() >= bytes,
        "fill_u32_buffer: slice unexpectedly shorter than bytes"
    );
    for chunk in slice.chunks_exact_mut(4).take(count) {
        chunk.copy_from_slice(&value_le);
    }

    Ok(())
}

/// Fill the first `count` u32 cells of `attr` with `value`, growing
/// or truncating the underlying [`Vec<u32>`] to length `count`.
///
/// FASM parallel: `memset32(rdi=attr_buf, esi=value, rdx=count)` from
/// `memfuncs.inc`. Unlike the text buffer (byte-addressable),
/// [`Attributes`] stores cells as a `Vec<u32>` directly, so we operate
/// on the typed slice via [`Vec::resize`] + iteration.
fn fill_u32_attributes(attr: &mut Attributes, value: u32, count: usize) -> Result<(), TuiError> {
    if attr.cells.len() < count {
        attr.cells.resize(count, 0);
    } else if attr.cells.len() > count {
        attr.cells.truncate(count);
    }
    for cell in attr.cells.iter_mut() {
        *cell = value;
    }
    Ok(())
}

/// Pack a [`ColorPair`] into a `u32` matching the FASM 32-bit color
/// attribute format.
///
/// FASM byte layout (matching `tui_object.inc` `Attributes::push`):
///
/// ```text
///   bits 0..=7   : foreground color index (u8)
///   bits 8..=15  : background color index (u8)
///   bits 16..=31 : SGR attribute bits (u16, defaulted to 0 here)
/// ```
///
/// `nvfill` always uses SGR=0 because [`TuiBackground`] does not carry
/// SGR state (descendants like `TuiText` do, and they perform their
/// own packing in their specialized draw paths). This matches FASM
/// `tui_background$nvfill` which uses `mov eax, [tui_bgcolors_ofs]`
/// where `tui_bgcolors_ofs` was written in `init_*` from `ecx` (which
/// the assembly callers set to `(bg << 8) | fg`).
fn pack_color_pair(cp: ColorPair) -> u32 {
    u32::from(cp.fg) | (u32::from(cp.bg) << 8)
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::geometry::{Point, Rect};

    /// Helper — produce a default test [`ColorPair`] (white-on-black).
    fn test_colors() -> ColorPair {
        ColorPair { fg: 7, bg: 0 }
    }

    // ----------------------------------------------------------------
    // Constructor tests
    // ----------------------------------------------------------------

    #[test]
    fn new_rect_stores_dimensions_from_bounds() {
        let bounds = Rect::from_origin_size(Point::ZERO, 10, 5);
        let bg = TuiBackground::new_rect(bounds, b' ' as u32, test_colors()).expect("new_rect must succeed");
        assert_eq!(bg.state().width, 10);
        assert_eq!(bg.state().height, 5);
        assert_eq!(bg.bgfillchar, b' ' as u32);
        assert_eq!(bg.bgcolors, test_colors());
    }

    #[test]
    fn new_rect_preserves_bounds_field() {
        let bounds = Rect::from_origin_size(Point::ZERO, 12, 7);
        let bg = TuiBackground::new_rect(bounds, 0, test_colors()).expect("new_rect must succeed");
        assert_eq!(bg.state().bounds, bounds);
        assert_eq!(bg.state().width_percent, None);
        assert_eq!(bg.state().height_percent, None);
    }

    #[test]
    fn new_ii_stores_fillchar_and_colors() {
        let bg = TuiBackground::new_ii(20, 3, 0x2588, test_colors()).expect("new_ii must succeed");
        assert_eq!(bg.state().width, 20);
        assert_eq!(bg.state().height, 3);
        assert_eq!(bg.bgfillchar, 0x2588);
        assert_eq!(bg.colors(), test_colors());
        assert_eq!(bg.state().width_percent, None);
        assert_eq!(bg.state().height_percent, None);
    }

    #[test]
    fn new_id_uses_percentage_height() {
        let bg = TuiBackground::new_id(10, 50.0, 0, test_colors()).expect("new_id must succeed");
        assert_eq!(bg.state().width, 10);
        assert_eq!(bg.state().height, 0);
        assert_eq!(bg.state().width_percent, None);
        assert_eq!(bg.state().height_percent, Some(50.0));
        assert_eq!(bg.bgfillchar, 0);
    }

    #[test]
    fn new_di_uses_percentage_width() {
        let bg = TuiBackground::new_di(100.0, 5, b'.' as u32, test_colors()).expect("new_di must succeed");
        assert_eq!(bg.state().width, 0);
        assert_eq!(bg.state().height, 5);
        assert_eq!(bg.state().width_percent, Some(100.0));
        assert_eq!(bg.state().height_percent, None);
        assert_eq!(bg.bgfillchar, b'.' as u32);
    }

    #[test]
    fn new_dd_uses_both_percentages() {
        let bg = TuiBackground::new_dd(50.0, 75.0, 0, test_colors()).expect("new_dd must succeed");
        assert_eq!(bg.state().width, 0);
        assert_eq!(bg.state().height, 0);
        assert_eq!(bg.state().width_percent, Some(50.0));
        assert_eq!(bg.state().height_percent, Some(75.0));
    }

    // ----------------------------------------------------------------
    // Default-flag tests (FASM "not yet positioned" sentinels)
    // ----------------------------------------------------------------

    #[test]
    fn constructed_widget_is_visible_and_in_layout() {
        let bg = TuiBackground::new_ii(5, 5, 0, test_colors()).unwrap();
        assert!(bg.state().visible);
        assert!(bg.state().include_in_layout);
    }

    #[test]
    fn constructed_widget_has_unpositioned_absolute_coords() {
        // FASM sentinel: -1 means "not yet positioned by layout".
        let bg = TuiBackground::new_ii(5, 5, 0, test_colors()).unwrap();
        assert_eq!(bg.state().absolute_x, -1);
        assert_eq!(bg.state().absolute_y, -1);
    }

    // ----------------------------------------------------------------
    // Buffer pre-allocation tests
    // ----------------------------------------------------------------

    #[test]
    fn new_ii_preallocates_buffers_when_dimensions_known() {
        let bg = TuiBackground::new_ii(4, 3, b' ' as u32, test_colors()).unwrap();
        // FASM init_ii allocs `cells * 4 = 4 * 3 * 4 = 48` text bytes
        // and `cells = 12` attribute u32s.
        assert_eq!(bg.state().text.len(), 48);
        assert_eq!(bg.state().attributes.cells.len(), 12);
    }

    #[test]
    fn new_id_does_not_preallocate_buffers() {
        // Percentage-based — buffers deferred to layout pass.
        let bg = TuiBackground::new_id(10, 50.0, 0, test_colors()).unwrap();
        assert!(bg.state().text.is_empty());
        assert!(bg.state().attributes.cells.is_empty());
    }

    #[test]
    fn new_dd_does_not_preallocate_buffers() {
        let bg = TuiBackground::new_dd(50.0, 50.0, 0, test_colors()).unwrap();
        assert!(bg.state().text.is_empty());
        assert!(bg.state().attributes.cells.is_empty());
    }

    // ----------------------------------------------------------------
    // Setter / getter tests
    // ----------------------------------------------------------------

    #[test]
    fn setters_mutate_fields_and_getters_observe_them() {
        let bg_arc = TuiBackground::new_ii(5, 5, 0, test_colors()).unwrap();
        let mut bg = Arc::try_unwrap(bg_arc)
            .ok()
            .expect("Arc must be unique in this test");
        assert_eq!(bg.fillchar(), 0);
        assert_eq!(bg.colors(), test_colors());

        bg.set_fillchar(b'#' as u32);
        bg.set_colors(ColorPair { fg: 1, bg: 2 });
        assert_eq!(bg.fillchar(), b'#' as u32);
        assert_eq!(bg.colors(), ColorPair { fg: 1, bg: 2 });
    }

    // ----------------------------------------------------------------
    // pack_color_pair byte-layout tests
    // ----------------------------------------------------------------

    #[test]
    fn pack_color_pair_layout_low_byte_is_fg() {
        let cp = ColorPair { fg: 0x42, bg: 0xA7 };
        let packed = pack_color_pair(cp);
        assert_eq!(packed & 0xFF, 0x42, "fg must be in low byte");
        assert_eq!((packed >> 8) & 0xFF, 0xA7, "bg must be in second byte");
        // SGR bits (high u16) are zero for nvfill.
        assert_eq!(packed >> 16, 0, "SGR bits must be zero");
    }

    #[test]
    fn pack_color_pair_zero_is_zero() {
        let cp = ColorPair { fg: 0, bg: 0 };
        assert_eq!(pack_color_pair(cp), 0);
    }

    #[test]
    fn pack_color_pair_max_values() {
        let cp = ColorPair { fg: 0xFF, bg: 0xFF };
        let packed = pack_color_pair(cp);
        assert_eq!(packed, 0x0000_FFFF);
    }

    // ----------------------------------------------------------------
    // nvfill behavioral tests
    // ----------------------------------------------------------------

    #[test]
    fn nvfill_writes_fillchar_to_text_buffer_when_nonzero() {
        let bg_arc = TuiBackground::new_ii(2, 2, 0x2588, test_colors()).unwrap();
        let mut bg = Arc::try_unwrap(bg_arc).ok().expect("unique Arc");
        bg.nvfill().expect("nvfill must succeed");

        // Expect 4 cells × 4 bytes = 16 bytes, each cell = 0x00002588 LE.
        let slice = bg.state().text.as_slice();
        assert_eq!(slice.len(), 16);
        for chunk in slice.chunks_exact(4) {
            assert_eq!(chunk, &[0x88, 0x25, 0x00, 0x00]);
        }
    }

    #[test]
    fn nvfill_skips_text_buffer_when_fillchar_is_zero() {
        let bg_arc = TuiBackground::new_ii(2, 2, 0, test_colors()).unwrap();
        let mut bg = Arc::try_unwrap(bg_arc).ok().expect("unique Arc");

        // Pre-poison the text buffer with non-zero bytes.
        for byte in bg.state.text.as_mut_slice() {
            *byte = 0xAA;
        }

        bg.nvfill().expect("nvfill must succeed");

        // Text buffer must be UNCHANGED (still 0xAA) because fillchar=0.
        for byte in bg.state().text.as_slice() {
            assert_eq!(*byte, 0xAA, "text byte must be unchanged when fillchar=0");
        }
    }

    #[test]
    fn nvfill_always_writes_attributes() {
        let colors = ColorPair { fg: 0x12, bg: 0x34 };
        let bg_arc = TuiBackground::new_ii(2, 2, 0, colors).unwrap();
        let mut bg = Arc::try_unwrap(bg_arc).ok().expect("unique Arc");
        bg.nvfill().expect("nvfill must succeed");

        let expected = pack_color_pair(colors);
        assert_eq!(bg.state().attributes.cells.len(), 4);
        for cell in bg.state().attributes.cells.iter() {
            assert_eq!(*cell, expected);
        }
    }

    #[test]
    fn nvfill_bails_when_width_is_zero() {
        // Use a percentage constructor so width stays 0.
        let bg_arc = TuiBackground::new_di(50.0, 5, 0x42, test_colors()).unwrap();
        let mut bg = Arc::try_unwrap(bg_arc).ok().expect("unique Arc");
        bg.nvfill().expect("nvfill must succeed");

        // Both buffers must remain empty.
        assert!(bg.state().text.is_empty());
        assert!(bg.state().attributes.cells.is_empty());
    }

    #[test]
    fn nvfill_bails_when_height_is_zero() {
        let bg_arc = TuiBackground::new_id(5, 50.0, 0x42, test_colors()).unwrap();
        let mut bg = Arc::try_unwrap(bg_arc).ok().expect("unique Arc");
        bg.nvfill().expect("nvfill must succeed");

        assert!(bg.state().text.is_empty());
        assert!(bg.state().attributes.cells.is_empty());
    }

    #[test]
    fn nvfill_bails_when_text_buffer_is_empty() {
        // Construct with non-zero dims but force the text buffer empty
        // afterwards (simulating a pre-layout state).
        let bg_arc = TuiBackground::new_ii(3, 3, 0x42, test_colors()).unwrap();
        let mut bg = Arc::try_unwrap(bg_arc).ok().expect("unique Arc");
        bg.state.text.clear();
        // Force attributes empty too (just a defensive setup).
        bg.state.attributes.cells.clear();

        bg.nvfill().expect("nvfill must succeed");

        // Both buffers must remain empty (FASM .bailout path).
        assert!(bg.state().text.is_empty());
        assert!(bg.state().attributes.cells.is_empty());
    }

    #[test]
    fn nvfill_overwrites_prior_text_content() {
        let bg_arc = TuiBackground::new_ii(2, 1, b'X' as u32, test_colors()).unwrap();
        let mut bg = Arc::try_unwrap(bg_arc).ok().expect("unique Arc");
        // Pre-fill with 'Y'.
        for byte in bg.state.text.as_mut_slice() {
            *byte = b'Y';
        }
        bg.nvfill().expect("nvfill must succeed");

        // After nvfill, every cell's low byte should be 'X'.
        for chunk in bg.state().text.as_slice().chunks_exact(4) {
            assert_eq!(chunk[0], b'X');
        }
    }

    // ----------------------------------------------------------------
    // Widget trait tests
    // ----------------------------------------------------------------

    #[test]
    fn state_returns_reference_to_widget_state() {
        let bg = TuiBackground::new_ii(7, 4, 0, test_colors()).unwrap();
        let s: &WidgetState = bg.state();
        assert_eq!(s.width, 7);
        assert_eq!(s.height, 4);
    }

    #[test]
    fn state_mut_allows_mutation() {
        let bg_arc = TuiBackground::new_ii(7, 4, 0, test_colors()).unwrap();
        let mut bg = Arc::try_unwrap(bg_arc).ok().expect("unique Arc");
        bg.state_mut().width = 99;
        assert_eq!(bg.state().width, 99);
    }

    #[test]
    fn as_any_supports_downcasting() {
        let bg_arc = TuiBackground::new_ii(2, 2, 0, test_colors()).unwrap();
        let widget: Arc<dyn Widget> = bg_arc.clone();
        // Downcast back through `as_any`.
        let any_ref = widget.as_any();
        let downcast = any_ref.downcast_ref::<TuiBackground>();
        assert!(downcast.is_some(), "as_any must support downcasting");
        assert_eq!(downcast.unwrap().bgfillchar, 0);
    }

    #[test]
    fn clone_widget_produces_distinct_arc_with_equal_fields() {
        let original_arc = TuiBackground::new_ii(3, 2, 0xAB, test_colors()).unwrap();
        let cloned_arc: Arc<dyn Widget> = original_arc.clone_widget().expect("clone_widget must succeed");

        // The cloned widget must downcast back to TuiBackground.
        let cloned = cloned_arc
            .as_any()
            .downcast_ref::<TuiBackground>()
            .expect("clone must remain a TuiBackground");

        assert_eq!(cloned.bgfillchar, 0xAB);
        assert_eq!(cloned.bgcolors, test_colors());
        assert_eq!(cloned.state().width, 3);
        assert_eq!(cloned.state().height, 2);
    }

    #[test]
    fn clone_widget_deep_copies_text_and_attributes() {
        let original_arc = TuiBackground::new_ii(2, 2, b' ' as u32, test_colors()).unwrap();
        let mut original = Arc::try_unwrap(original_arc).ok().expect("unique Arc");
        // Populate text with distinctive bytes.
        for (i, byte) in original.state.text.as_mut_slice().iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        // Populate attributes with distinctive values.
        for (i, cell) in original.state.attributes.cells.iter_mut().enumerate() {
            *cell = 0x1000 + i as u32;
        }

        let cloned_arc = original.clone_widget().expect("clone must succeed");
        let cloned = cloned_arc
            .as_any()
            .downcast_ref::<TuiBackground>()
            .expect("downcast must succeed");

        // Verify the cloned buffers contain the same bytes/cells.
        assert_eq!(cloned.state().text.as_slice(), original.state().text.as_slice());
        assert_eq!(cloned.state().attributes.cells, original.state().attributes.cells);
    }

    #[test]
    fn clone_widget_does_not_share_underlying_buffer() {
        // Mutating the original after clone must not affect the clone.
        let original_arc = TuiBackground::new_ii(2, 2, b'A' as u32, test_colors()).unwrap();
        let mut original = Arc::try_unwrap(original_arc).ok().expect("unique Arc");
        // Initial fill so both buffers have content.
        original.nvfill().unwrap();

        let cloned_arc = original.clone_widget().expect("clone must succeed");

        // Mutate the original.
        for byte in original.state.text.as_mut_slice() {
            *byte = 0xFF;
        }

        let cloned = cloned_arc
            .as_any()
            .downcast_ref::<TuiBackground>()
            .expect("downcast must succeed");

        // Cloned buffer must still hold 'A' bytes (unchanged).
        let first_byte = cloned.state().text.as_slice()[0];
        assert_eq!(first_byte, b'A', "clone must not share buffer with original");
    }

    // ----------------------------------------------------------------
    // fill_u32_buffer / fill_u32_attributes helper tests
    // ----------------------------------------------------------------

    #[test]
    fn fill_u32_buffer_writes_le_bytes_per_cell() {
        let mut buf = Buffer::new();
        fill_u32_buffer(&mut buf, 0xDEAD_BEEF, 3).expect("fill must succeed");
        assert_eq!(buf.len(), 12);
        assert_eq!(
            buf.as_slice(),
            &[0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE]
        );
    }

    #[test]
    fn fill_u32_buffer_zero_count_yields_empty_buffer() {
        let mut buf = Buffer::new();
        buf.push(0xAA); // pre-existing content
        fill_u32_buffer(&mut buf, 0x12345678, 0).expect("fill must succeed");
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn fill_u32_attributes_writes_value_to_each_cell() {
        let mut attr = Attributes { cells: Vec::new() };
        fill_u32_attributes(&mut attr, 0xCAFE_BABE, 4).expect("fill must succeed");
        assert_eq!(attr.cells.len(), 4);
        for cell in &attr.cells {
            assert_eq!(*cell, 0xCAFE_BABE);
        }
    }

    #[test]
    fn fill_u32_attributes_truncates_excess_cells() {
        let mut attr = Attributes {
            cells: vec![0xFFFF_FFFF; 10],
        };
        fill_u32_attributes(&mut attr, 0x0000_0042, 3).expect("fill must succeed");
        assert_eq!(attr.cells.len(), 3);
        for cell in &attr.cells {
            assert_eq!(*cell, 0x0000_0042);
        }
    }

    // ----------------------------------------------------------------
    // Send + Sync compile-time check
    // ----------------------------------------------------------------

    #[test]
    fn tui_background_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TuiBackground>();
        // Also confirm Arc<dyn Widget> erasure works.
        let bg = TuiBackground::new_ii(1, 1, 0, test_colors()).unwrap();
        let _: Arc<dyn Widget> = bg;
    }
}
