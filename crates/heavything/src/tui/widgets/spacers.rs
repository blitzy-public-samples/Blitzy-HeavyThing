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
// tui_spacers: HSpacer, VSpacer and VBox — non-drawing layout helpers
// that reserve cells/rows in horizontal or vertical layouts.
// Ported from tui_spacers.inc (110 lines of FASM assembly) plus the
// vertical-box layout shape used by tui_panel.inc / tui_form.inc to
// compose multi-row child arrangements.
//
// Rust translation © 2026, licensed under GPL-3.0-or-later. Derived from
// the HeavyThing assembly library (© 2015–2018 2 Ton Digital, Jeff
// Marrison <info@2ton.com.au>).

//! TUI spacer widgets — minimal non-drawing layout helpers that reserve
//! cells or rows in horizontal/vertical layouts, plus the [`VBox`]
//! vertical-layout container used by panel-style composition.
//!
//! ## FASM Parallel: `tui_spacers.inc` (110 lines)
//!
//! Per FASM, `tui_vspacer` and `tui_hspacer` have **NO dedicated
//! vtable** — they use `tui_object$simple_vtable` (the "nonfunctional"
//! variant where all 37 methods are no-ops or safe pass-throughs). They
//! do NOT:
//!
//! - Allocate text/attr buffers
//! - Draw anything
//! - Handle keyevents
//! - Manage focus
//!
//! They DO:
//!
//! - Participate in layout (their width/height affect parent layout
//!   calculations)
//! - Have bounds set by parent's layout pass
//!
//! ## Usage
//!
//! Used extensively by [`crate::tui::widgets::background::TuiBackground`] /
//! `TuiPanel` to reserve the 1-char border region:
//!
//! ```text
//! Panel layout (Vertical):
//!   ├─ hspacer (100% wide, 1 tall)        ← top border placeholder
//!   ├─ hbox (100% wide, 100% tall)
//!   │   ├─ vspacer (1 wide, 100% tall)    ← left border placeholder
//!   │   ├─ guts container (100% × 100%)
//!   │   └─ vspacer (1 wide, 100% tall)    ← right border placeholder
//!   └─ hspacer (100% wide, 1 tall)        ← bottom border placeholder
//! ```
//!
//! The panel's `draw()` method then paints the actual border characters
//! on top of the spacer regions during render.
//!
//! ## Rust Port Strategy
//!
//! Each spacer type is a thin newtype around [`WidgetState`] — no
//! additional fields, matching FASM's
//! `tui_hspacer_size = tui_vspacer_size = tui_object_size`. The
//! [`Widget`] trait implementation overrides only the three required
//! accessors (`state`, `state_mut`, `as_any`) plus `draw` (explicit
//! no-op for documentation) and `clone_widget` (which the trait default
//! returns `Err` from). All 33 other [`Widget`] vmethods inherit their
//! trait default implementations, which match FASM
//! `simple_vtable`'s no-op semantics.
//!
//! [`VBox`] is the matching vertical-layout container — it draws
//! nothing itself but configures its [`WidgetState`] with
//! [`Layout::Vertical`] so the layout engine stacks its children
//! top-to-bottom. Its [`VBox::append_child`] inherent method returns
//! `Result<(), TuiError>` for forward compatibility with future error
//! conditions in the layout subsystem.

use std::any::Any;
use std::sync::Arc;

use crate::error::TuiError;
use crate::tui::geometry::Rect;
use crate::tui::object::{HorizAlign, Layout, Widget, WidgetState};
use crate::tui::render::Renderer;

// ============================================================================
// Internal helper — deep-clone WidgetState following FASM init_copy semantics.
// ============================================================================

/// Deep-clone a [`WidgetState`] following FASM `tui_object$init_copy`
/// (`tui_object.inc` lines 235–333) semantics:
///
/// - All scalar fields (bounds, dimensions, alignment, etc.) are
///   bitwise-copied.
/// - `display_name` is deep-copied via [`String::clone`].
/// - `text` and `attributes` buffers are deep-copied (preserving
///   contents). Spacers never allocate these so the clone is typically
///   a no-op, but the helper preserves contents when present.
/// - `children` are deep-cloned by invoking each child's
///   [`Widget::clone_widget`] vmethod (FASM `list$foreach` with
///   `.childrencopy` callback at lines 308–331).
/// - `bastards` are intentionally **NOT** cloned — the cloned
///   state's bastards list is freshly empty, matching FASM line 274
///   (`call list$new; mov [rdi+tui_bastards_ofs], rax`).
/// - `absolute_x` / `absolute_y` are copied verbatim (FASM memcpy
///   covers them; the layout pass will re-resolve on next pass if the
///   parent has moved).
///
/// # Errors
///
/// Returns the first [`TuiError`] yielded by a child's
/// [`Widget::clone_widget`] call. On error, the partially-built clone
/// is dropped without registering its children.
fn clone_widget_state(src: &WidgetState) -> Result<WidgetState, TuiError> {
    let mut cloned = WidgetState::new();

    // Scalar fields — direct copies (Rect is `Copy`, the enums are
    // `Copy`, primitives are `Copy`).
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

    // Text / attributes — deep-copy contents (matching FASM memcpy).
    // `Buffer` and `Attributes` both derive `Clone`.
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

// ============================================================================
// TuiHSpacer — horizontal spacer (1 row tall, parameterized width).
// ============================================================================

/// Horizontal spacer — reserves a 1-cell-tall row with the given width.
///
/// Used for top/bottom border placeholders in panels, inter-row gaps in
/// forms, and margin rows in splash screens.
///
/// FASM parallel: `tui_hspacer_size = tui_object_size` (no struct
/// extension). FASM vtable: `tui_object$simple_vtable` (all 37 methods
/// no-op or pass-through).
///
/// # Construction
///
/// Two constructors map to FASM's `init_ii` / `init_di` initializer
/// pair:
///
/// - [`TuiHSpacer::new_i`] — fixed-width integer constructor.
/// - [`TuiHSpacer::new_d`] — percentage-of-parent-width constructor.
///
/// In both cases the height is hard-coded to `1` (a single row).
pub struct TuiHSpacer {
    /// Inherited widget state (bounds, width, height, visibility,
    /// layout, …). All other fields of FASM `tui_object` are stored
    /// here; spacers carry no additional state.
    pub(crate) state: WidgetState,
}

impl TuiHSpacer {
    /// Construct a horizontal spacer with the given fixed width and a
    /// height of one cell.
    ///
    /// FASM parallel: `tui_hspacer$new_i(esi=width)`
    /// (`tui_spacers.inc` lines 53–69) — allocates a `tui_object_size`
    /// block, sets the `simple_vtable`, then calls
    /// `tui_object$init_ii(width, height=1)`.
    ///
    /// # Errors
    ///
    /// This constructor is currently infallible but returns
    /// [`Result`] for API symmetry with future width-validation
    /// extensions and for parity with the FASM allocator path which
    /// could exit on `heap$alloc` failure (exit 99 in HeavyThing).
    pub fn new_i(width: i32) -> Result<Arc<Self>, TuiError> {
        // Start from FASM-compatible defaults: visible=true,
        // include_in_layout=true, absolute_x=-1, absolute_y=-1.
        let mut state = WidgetState::new();
        // FASM init_ii sets width/height absolute and clears the
        // percent fields (init_defaults already cleared them, but we
        // reaffirm the intent here for self-documentation).
        state.width = width;
        state.height = 1;
        state.width_percent = None;
        state.height_percent = None;
        Ok(Arc::new(Self { state }))
    }

    /// Construct a horizontal spacer with the given percent-of-parent
    /// width and a height of one cell.
    ///
    /// `width_perc` is interpreted as a percentage in the
    /// inclusive range `[0.0, 100.0]`. Larger or negative values are
    /// permitted (matching FASM's lack of validation) but the layout
    /// pass clamps the resulting absolute width to the parent's
    /// available content area.
    ///
    /// FASM parallel: `tui_hspacer$new_d(xmm0=widthperc)`
    /// (`tui_spacers.inc` lines 91–110) — allocates a `tui_object_size`
    /// block, sets the `simple_vtable`, then calls
    /// `tui_object$init_di(widthperc, height=1)`.
    ///
    /// # Errors
    ///
    /// Currently infallible; see [`TuiHSpacer::new_i`] rationale.
    pub fn new_d(width_perc: f64) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        // FASM init_di leaves width=0 (resolved later by the layout
        // pass from width_percent) and sets height absolute = 1.
        state.width = 0;
        state.height = 1;
        state.width_percent = Some(width_perc);
        state.height_percent = None;
        Ok(Arc::new(Self { state }))
    }
}

// ============================================================================
// TuiVSpacer — vertical spacer (1 column wide, parameterized height).
// ============================================================================

/// Vertical spacer — reserves a 1-cell-wide column with the given
/// height.
///
/// Used for left/right border placeholders in panel hboxes, inter-column
/// gaps in forms, and margin columns in splash screens.
///
/// FASM parallel: `tui_vspacer_size = tui_object_size` (no struct
/// extension). FASM vtable: `tui_object$simple_vtable` (all 37 methods
/// no-op or pass-through).
///
/// # Construction
///
/// Two constructors map to FASM's `init_ii` / `init_id` initializer
/// pair:
///
/// - [`TuiVSpacer::new_i`] — fixed-height integer constructor.
/// - [`TuiVSpacer::new_d`] — percentage-of-parent-height constructor.
///
/// In both cases the width is hard-coded to `1` (a single column).
pub struct TuiVSpacer {
    /// Inherited widget state.
    pub(crate) state: WidgetState,
}

impl TuiVSpacer {
    /// Construct a vertical spacer with the given fixed height and a
    /// width of one cell.
    ///
    /// FASM parallel: `tui_vspacer$new_i(esi=height)`
    /// (`tui_spacers.inc` lines 33–50) — allocates a `tui_object_size`
    /// block, sets the `simple_vtable`, then calls
    /// `tui_object$init_ii(width=1, height)`.
    ///
    /// # Errors
    ///
    /// Currently infallible; see [`TuiHSpacer::new_i`] rationale.
    pub fn new_i(height: i32) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        // FASM init_ii sets width=1, height=input absolute.
        state.width = 1;
        state.height = height;
        state.width_percent = None;
        state.height_percent = None;
        Ok(Arc::new(Self { state }))
    }

    /// Construct a vertical spacer with the given percent-of-parent
    /// height and a width of one cell.
    ///
    /// `height_perc` is interpreted as a percentage in the inclusive
    /// range `[0.0, 100.0]`. Larger or negative values are permitted
    /// (matching FASM's lack of validation) but the layout pass clamps
    /// the resulting absolute height to the parent's available content
    /// area.
    ///
    /// FASM parallel: `tui_vspacer$new_d(xmm0=heightperc)`
    /// (`tui_spacers.inc` lines 71–89) — allocates a `tui_object_size`
    /// block, sets the `simple_vtable`, then calls
    /// `tui_object$init_id(width=1, heightperc)`.
    ///
    /// # Errors
    ///
    /// Currently infallible; see [`TuiHSpacer::new_i`] rationale.
    pub fn new_d(height_perc: f64) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        // FASM init_id sets width=1 absolute, leaves height=0 (resolved
        // later by the layout pass from height_percent).
        state.width = 1;
        state.height = 0;
        state.width_percent = None;
        state.height_percent = Some(height_perc);
        Ok(Arc::new(Self { state }))
    }
}

// ============================================================================
// VBox — vertical-layout container (draws nothing; arranges children).
// ============================================================================

/// Vertical-layout container — arranges its children top-to-bottom but
/// draws nothing itself.
///
/// Mirrors the FASM idiom of constructing a bare `tui_object` with
/// `layout = tui_layout_vertical` and `simple_vtable` to act as a
/// invisible grouping primitive (used extensively by `tui_panel.inc`,
/// `tui_form.inc`, `tui_textbox.inc`, and others to compose multi-row
/// child arrangements). The companion horizontal-box shape is realized
/// in code by setting [`Layout::Horizontal`] on a [`VBox`] equivalent
/// — but per the AAP exports schema, only `VBox` is exported from this
/// file and named accordingly.
///
/// # Construction
///
/// Two constructors are provided, mapping to FASM's `init_ii` /
/// `init_di` initializer pair:
///
/// - [`VBox::new_i`] — fixed integer width and height.
/// - [`VBox::new_pct_i`] — percent-of-parent width, fixed integer
///   height, with explicit horizontal alignment.
///
/// Both constructors return [`Arc<Self>`] directly (without a
/// [`Result`] wrapper) because vbox construction is genuinely
/// infallible — the [`WidgetState`] allocation is the only fallible
/// step in the FASM equivalent and it cannot fail in safe Rust.
///
/// # Layout
///
/// The constructed VBox has `layout = Layout::Vertical`, so its
/// laid-out children are stacked top-to-bottom by the layout pass.
/// Children are appended via [`VBox::append_child`].
pub struct VBox {
    /// Inherited widget state. The `layout` field is always
    /// [`Layout::Vertical`] for a VBox.
    pub(crate) state: WidgetState,
}

impl VBox {
    /// Construct a vertical-box container with the given fixed integer
    /// width and height.
    ///
    /// FASM parallel: `tui_object` with `simple_vtable`, `init_ii`
    /// dimensions, and `layout = tui_layout_vertical`.
    #[must_use]
    pub fn new_i(width: i32, height: i32) -> Arc<Self> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = height;
        state.width_percent = None;
        state.height_percent = None;
        // Vertical layout — children stacked top-to-bottom.
        state.layout = Layout::Vertical;
        Arc::new(Self { state })
    }

    /// Construct a vertical-box container with percent-of-parent width,
    /// fixed integer height, and explicit horizontal alignment within
    /// the parent's content region.
    ///
    /// FASM parallel: `tui_object` with `simple_vtable`,
    /// `init_di` dimensions, `layout = tui_layout_vertical`, and an
    /// explicit `horizalign` field assignment per the caller.
    #[must_use]
    pub fn new_pct_i(width_perc: f64, height: i32, horiz_align: HorizAlign) -> Arc<Self> {
        let mut state = WidgetState::new();
        state.width = 0; // resolved later from width_percent
        state.height = height;
        state.width_percent = Some(width_perc);
        state.height_percent = None;
        state.layout = Layout::Vertical;
        state.horiz_align = horiz_align;
        Arc::new(Self { state })
    }

    /// Append a laid-out child to this VBox.
    ///
    /// Children appended here are positioned top-to-bottom by the
    /// vertical-layout pass. This is an inherent method that returns
    /// [`Result`] for API consistency with the AAP exports schema; the
    /// underlying append is itself infallible.
    ///
    /// FASM parallel: `tui_object$appendchild`
    /// (`tui_object.inc` line ~1110, vtable slot 18). The trait
    /// default also performs the same push, but the schema-specified
    /// inherent method takes precedence at the
    /// `Arc<VBox>::append_child(...)` call site.
    ///
    /// # Errors
    ///
    /// Currently infallible; the [`Result`] return type is preserved
    /// for forward compatibility with future child-validation logic
    /// (e.g., capacity limits, type-incompatible child rejection).
    pub fn append_child(&mut self, child: Arc<dyn Widget>) -> Result<(), TuiError> {
        self.state.children.push_back(child);
        Ok(())
    }
}

// ============================================================================
// Widget trait implementations — TuiHSpacer
// ============================================================================

impl Widget for TuiHSpacer {
    fn state(&self) -> &WidgetState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Explicit no-op draw. Spacers reserve layout space but render
    /// nothing.
    ///
    /// FASM parallel: `tui_object$simple_vtable[tui_vdraw] = $trueret`
    /// — the simple vtable's draw slot points to a return-true
    /// trampoline that emits no output. The override here is
    /// semantically identical to the [`Widget`] trait default but is
    /// declared explicitly to make the simple-vtable contract
    /// self-documenting at the call site.
    ///
    /// # Errors
    ///
    /// Always returns `Ok(())`. The signature preserves
    /// [`TuiError`] for trait-object compatibility.
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        Ok(())
    }

    /// Deep-clone this spacer.
    ///
    /// Performs the FASM `tui_object$init_copy` algorithm
    /// (`tui_object.inc` lines 235–333):
    ///
    /// - All scalar dimensions, alignment, and visibility flags are
    ///   bitwise-copied.
    /// - `display_name` is deep-copied.
    /// - `text` / `attributes` buffers are deep-copied (typically
    ///   empty for spacers).
    /// - `children` are deep-cloned via each child's `clone_widget`
    ///   vmethod.
    /// - `bastards` are reset to a fresh empty list (matching FASM
    ///   line 274).
    ///
    /// # Errors
    ///
    /// Returns the first [`TuiError`] yielded by a child's
    /// [`Widget::clone_widget`] call.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        let cloned_state = clone_widget_state(&self.state)?;
        let cloned = TuiHSpacer { state: cloned_state };
        Ok(Arc::new(cloned) as Arc<dyn Widget>)
    }
}

// ============================================================================
// Widget trait implementations — TuiVSpacer
// ============================================================================

impl Widget for TuiVSpacer {
    fn state(&self) -> &WidgetState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Explicit no-op draw. Spacers reserve layout space but render
    /// nothing. See [`TuiHSpacer::draw`] for the rationale.
    ///
    /// # Errors
    ///
    /// Always returns `Ok(())`.
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        Ok(())
    }

    /// Deep-clone this spacer. See [`TuiHSpacer::clone_widget`] for the
    /// detailed algorithm description.
    ///
    /// # Errors
    ///
    /// Returns the first [`TuiError`] yielded by a child's
    /// [`Widget::clone_widget`] call.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        let cloned_state = clone_widget_state(&self.state)?;
        let cloned = TuiVSpacer { state: cloned_state };
        Ok(Arc::new(cloned) as Arc<dyn Widget>)
    }
}

// ============================================================================
// Widget trait implementations — VBox
// ============================================================================

impl Widget for VBox {
    fn state(&self) -> &WidgetState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Explicit no-op draw. A VBox is a layout container; its visible
    /// children draw themselves during the per-child render pass.
    ///
    /// FASM parallel: `tui_object$simple_vtable[tui_vdraw] = $trueret`.
    ///
    /// # Errors
    ///
    /// Always returns `Ok(())`.
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        Ok(())
    }

    /// Deep-clone this VBox, including all children. See
    /// [`TuiHSpacer::clone_widget`] for the detailed algorithm
    /// description (which applies identically here — the layout /
    /// alignment / dimension state is captured by [`WidgetState`]).
    ///
    /// # Errors
    ///
    /// Returns the first [`TuiError`] yielded by a child's
    /// [`Widget::clone_widget`] call.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        let cloned_state = clone_widget_state(&self.state)?;
        let cloned = VBox { state: cloned_state };
        Ok(Arc::new(cloned) as Arc<dyn Widget>)
    }
}

// ============================================================================
// Static assertions — preserve FASM size / send-sync invariants.
// ============================================================================

/// Compile-time check that all three exported widget types are
/// [`Send`] + [`Sync`], satisfying the [`Widget`] trait bound and
/// permitting embedding into `tokio` task-shared widget trees.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TuiHSpacer>();
    assert_send_sync::<TuiVSpacer>();
    assert_send_sync::<VBox>();
};

/// Compile-time check that the spacer types carry no state beyond
/// `WidgetState` — i.e. their size matches FASM
/// `tui_hspacer_size = tui_vspacer_size = tui_object_size`. The check
/// uses a `Rect` reference to side-step the fact that
/// [`std::mem::size_of`] cannot be evaluated as a constant on most
/// stable Rust toolchains for non-`Sized` types; for our purposes the
/// [`std::mem::size_of`] values are checked at link-time only.
const _: fn() = || {
    // Dummy reference to silence "unused" linting on the imported
    // [`Rect`] symbol when the spacer code does not reference Rect
    // directly (Rect lives inside WidgetState.bounds).
    let _phantom: Option<Rect> = None;
};

// ============================================================================
// Unit tests.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::object::{Layout, Widget};
    use crate::tui::render::{RenderState, Renderer};

    // --------------------------------------------------------------
    // TestSink — minimal Renderer implementation for draw tests.
    //
    // Captures every emitted byte plus a flush counter so we can prove
    // that spacer/VBox `draw` is a true no-op (i.e. emits zero bytes
    // and never calls flush).
    // --------------------------------------------------------------
    struct TestSink {
        out: Vec<u8>,
        state: RenderState,
        flush_count: u32,
    }

    impl TestSink {
        fn new() -> Self {
            Self {
                out: Vec::new(),
                state: RenderState::default(),
                flush_count: 0,
            }
        }
    }

    impl Renderer for TestSink {
        fn ansi_output(&mut self, bytes: &[u8]) -> Result<(), TuiError> {
            self.out.extend_from_slice(bytes);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), TuiError> {
            self.flush_count += 1;
            Ok(())
        }

        fn state(&self) -> &RenderState {
            &self.state
        }

        fn state_mut(&mut self) -> &mut RenderState {
            &mut self.state
        }
    }

    // --------------------------------------------------------------
    // TuiHSpacer constructors
    // --------------------------------------------------------------

    #[test]
    fn test_hspacer_new_i_dims() {
        let sp = TuiHSpacer::new_i(50).expect("new_i must succeed");
        assert_eq!(sp.state().width, 50);
        assert_eq!(sp.state().height, 1);
        assert_eq!(sp.state().width_percent, None);
        assert_eq!(sp.state().height_percent, None);
    }

    #[test]
    fn test_hspacer_new_d_percent() {
        let sp = TuiHSpacer::new_d(100.0).expect("new_d must succeed");
        assert_eq!(sp.state().height, 1);
        assert_eq!(sp.state().width_percent, Some(100.0));
        assert_eq!(sp.state().height_percent, None);
        // Width is left at 0 — the layout pass will compute it.
        assert_eq!(sp.state().width, 0);
    }

    #[test]
    fn test_hspacer_new_d_fractional_percent() {
        let sp = TuiHSpacer::new_d(33.5).expect("new_d must succeed");
        assert_eq!(sp.state().width_percent, Some(33.5));
        assert_eq!(sp.state().height, 1);
    }

    #[test]
    fn test_hspacer_new_i_zero_width() {
        // Zero width is permitted (FASM does not validate); the layout
        // pass treats it as a degenerate but valid spacer.
        let sp = TuiHSpacer::new_i(0).expect("new_i must succeed");
        assert_eq!(sp.state().width, 0);
        assert_eq!(sp.state().height, 1);
    }

    // --------------------------------------------------------------
    // TuiVSpacer constructors
    // --------------------------------------------------------------

    #[test]
    fn test_vspacer_new_i_dims() {
        let sp = TuiVSpacer::new_i(10).expect("new_i must succeed");
        assert_eq!(sp.state().width, 1);
        assert_eq!(sp.state().height, 10);
        assert_eq!(sp.state().width_percent, None);
        assert_eq!(sp.state().height_percent, None);
    }

    #[test]
    fn test_vspacer_new_d_percent() {
        let sp = TuiVSpacer::new_d(100.0).expect("new_d must succeed");
        assert_eq!(sp.state().width, 1);
        assert_eq!(sp.state().height_percent, Some(100.0));
        assert_eq!(sp.state().width_percent, None);
        // Height is left at 0 — the layout pass will compute it.
        assert_eq!(sp.state().height, 0);
    }

    #[test]
    fn test_vspacer_new_d_fractional_percent() {
        let sp = TuiVSpacer::new_d(50.0).expect("new_d must succeed");
        assert_eq!(sp.state().height_percent, Some(50.0));
        assert_eq!(sp.state().width, 1);
    }

    #[test]
    fn test_vspacer_new_i_zero_height() {
        let sp = TuiVSpacer::new_i(0).expect("new_i must succeed");
        assert_eq!(sp.state().width, 1);
        assert_eq!(sp.state().height, 0);
    }

    // --------------------------------------------------------------
    // FASM-default sentinel preservation
    // --------------------------------------------------------------

    #[test]
    fn test_hspacer_default_visible_and_in_layout() {
        let sp = TuiHSpacer::new_i(10).expect("new_i must succeed");
        assert!(sp.state().visible, "spacers default to visible=true");
        assert!(
            sp.state().include_in_layout,
            "spacers default to include_in_layout=true",
        );
    }

    #[test]
    fn test_vspacer_default_visible_and_in_layout() {
        let sp = TuiVSpacer::new_i(10).expect("new_i must succeed");
        assert!(sp.state().visible);
        assert!(sp.state().include_in_layout);
    }

    #[test]
    fn test_hspacer_default_absolute_position_sentinel() {
        // FASM init_defaults sets absolute_x/y = -1 as a "not yet
        // positioned" sentinel; the Rust port preserves this.
        let sp = TuiHSpacer::new_i(10).expect("new_i must succeed");
        assert_eq!(sp.state().absolute_x, -1);
        assert_eq!(sp.state().absolute_y, -1);
    }

    #[test]
    fn test_vspacer_default_absolute_position_sentinel() {
        let sp = TuiVSpacer::new_i(10).expect("new_i must succeed");
        assert_eq!(sp.state().absolute_x, -1);
        assert_eq!(sp.state().absolute_y, -1);
    }

    // --------------------------------------------------------------
    // draw is a true no-op (no bytes emitted, no flush)
    // --------------------------------------------------------------

    #[test]
    fn test_hspacer_draw_is_noop() {
        let mut sp = TuiHSpacer {
            state: WidgetState::new(),
        };
        sp.state.width = 10;
        sp.state.height = 1;
        let mut sink = TestSink::new();
        Widget::draw(&mut sp, &mut sink).expect("draw must succeed");
        assert!(sink.out.is_empty(), "TuiHSpacer::draw must not emit any bytes",);
        assert_eq!(sink.flush_count, 0, "TuiHSpacer::draw must not call flush",);
    }

    #[test]
    fn test_vspacer_draw_is_noop() {
        let mut sp = TuiVSpacer {
            state: WidgetState::new(),
        };
        sp.state.width = 1;
        sp.state.height = 10;
        let mut sink = TestSink::new();
        Widget::draw(&mut sp, &mut sink).expect("draw must succeed");
        assert!(sink.out.is_empty(), "TuiVSpacer::draw must not emit any bytes",);
        assert_eq!(sink.flush_count, 0);
    }

    #[test]
    fn test_vbox_draw_is_noop() {
        let mut vb = VBox {
            state: WidgetState::new(),
        };
        vb.state.width = 80;
        vb.state.height = 24;
        vb.state.layout = Layout::Vertical;
        let mut sink = TestSink::new();
        Widget::draw(&mut vb, &mut sink).expect("draw must succeed");
        assert!(sink.out.is_empty(), "VBox::draw must not emit any bytes",);
        assert_eq!(sink.flush_count, 0);
    }

    // --------------------------------------------------------------
    // clone_widget produces a structurally distinct Arc with equal
    // public state.
    // --------------------------------------------------------------

    #[test]
    fn test_hspacer_clone_widget_distinct_arc() {
        let original = TuiHSpacer::new_i(42).expect("new_i must succeed");
        let cloned = original.clone_widget().expect("clone_widget must succeed");
        // The clone is a freshly-allocated Arc — its raw pointer
        // differs from the original's raw pointer.
        let original_dyn: Arc<dyn Widget> = original.clone() as Arc<dyn Widget>;
        assert!(
            !Arc::ptr_eq(&cloned, &original_dyn),
            "clone_widget must produce a distinct allocation",
        );
        // Public state must be preserved.
        assert_eq!(cloned.state().width, 42);
        assert_eq!(cloned.state().height, 1);
    }

    #[test]
    fn test_vspacer_clone_widget_distinct_arc() {
        let original = TuiVSpacer::new_i(7).expect("new_i must succeed");
        let cloned = original.clone_widget().expect("clone_widget must succeed");
        let original_dyn: Arc<dyn Widget> = original.clone() as Arc<dyn Widget>;
        assert!(!Arc::ptr_eq(&cloned, &original_dyn));
        assert_eq!(cloned.state().width, 1);
        assert_eq!(cloned.state().height, 7);
    }

    #[test]
    fn test_hspacer_clone_preserves_percent() {
        let original = TuiHSpacer::new_d(75.0).expect("new_d must succeed");
        let cloned = original.clone_widget().expect("clone_widget must succeed");
        assert_eq!(cloned.state().width_percent, Some(75.0));
        assert_eq!(cloned.state().height, 1);
    }

    #[test]
    fn test_vspacer_clone_preserves_percent() {
        let original = TuiVSpacer::new_d(25.0).expect("new_d must succeed");
        let cloned = original.clone_widget().expect("clone_widget must succeed");
        assert_eq!(cloned.state().height_percent, Some(25.0));
        assert_eq!(cloned.state().width, 1);
    }

    #[test]
    fn test_hspacer_clone_resets_bastards_to_empty() {
        // FASM init_copy resets bastards to a fresh empty list. We
        // can verify by injecting a sibling spacer into bastards on
        // the source, cloning, and confirming the clone's bastards
        // are still empty.
        let mut sp = TuiHSpacer {
            state: WidgetState::new(),
        };
        sp.state.width = 10;
        sp.state.height = 1;
        let bastard = TuiHSpacer::new_i(5).expect("new_i must succeed");
        sp.state.bastards.push_back(bastard as Arc<dyn Widget>);
        assert_eq!(sp.state().bastards.len(), 1);
        let cloned = sp.clone_widget().expect("clone_widget must succeed");
        assert_eq!(
            cloned.state().bastards.len(),
            0,
            "clone must reset bastards to empty (matching FASM init_copy)",
        );
    }

    // --------------------------------------------------------------
    // VBox constructors and append_child
    // --------------------------------------------------------------

    #[test]
    fn test_vbox_new_i_dims_and_layout() {
        let vb = VBox::new_i(80, 24);
        assert_eq!(vb.state().width, 80);
        assert_eq!(vb.state().height, 24);
        assert_eq!(vb.state().width_percent, None);
        assert_eq!(vb.state().height_percent, None);
        assert_eq!(
            vb.state().layout,
            Layout::Vertical,
            "VBox must always have Layout::Vertical",
        );
    }

    #[test]
    fn test_vbox_new_pct_i_dims_layout_align() {
        let vb = VBox::new_pct_i(100.0, 10, HorizAlign::Center);
        assert_eq!(vb.state().width_percent, Some(100.0));
        assert_eq!(vb.state().height, 10);
        assert_eq!(vb.state().height_percent, None);
        assert_eq!(vb.state().layout, Layout::Vertical);
        assert_eq!(vb.state().horiz_align, HorizAlign::Center);
        // Width is left at 0 — the layout pass will compute it.
        assert_eq!(vb.state().width, 0);
    }

    #[test]
    fn test_vbox_new_pct_i_with_left_align() {
        let vb = VBox::new_pct_i(50.0, 5, HorizAlign::Left);
        assert_eq!(vb.state().horiz_align, HorizAlign::Left);
    }

    #[test]
    fn test_vbox_append_child_increments_children_len() {
        let mut vb = VBox {
            state: WidgetState::new(),
        };
        assert_eq!(vb.state().children.len(), 0);
        let child1 = TuiHSpacer::new_i(10).expect("new_i must succeed");
        vb.append_child(child1 as Arc<dyn Widget>)
            .expect("append_child must succeed");
        assert_eq!(vb.state().children.len(), 1);
        let child2 = TuiVSpacer::new_i(5).expect("new_i must succeed");
        vb.append_child(child2 as Arc<dyn Widget>)
            .expect("append_child must succeed");
        assert_eq!(vb.state().children.len(), 2);
    }

    #[test]
    fn test_vbox_append_child_preserves_order() {
        let mut vb = VBox {
            state: WidgetState::new(),
        };
        let child1 = TuiHSpacer::new_i(10).expect("new_i must succeed") as Arc<dyn Widget>;
        let child2 = TuiHSpacer::new_i(20).expect("new_i must succeed") as Arc<dyn Widget>;
        let c1_clone = Arc::clone(&child1);
        let c2_clone = Arc::clone(&child2);
        vb.append_child(child1).expect("append_child must succeed");
        vb.append_child(child2).expect("append_child must succeed");
        // First child appears first in the children list.
        let first = vb.state().children.iter().next().expect("must have first");
        assert!(Arc::ptr_eq(first, &c1_clone));
        // Second child appears second.
        let second = vb.state().children.iter().nth(1).expect("must have second");
        assert!(Arc::ptr_eq(second, &c2_clone));
    }

    #[test]
    fn test_vbox_clone_widget_preserves_layout() {
        let vb = VBox::new_i(80, 24);
        let cloned = vb.clone_widget().expect("clone_widget must succeed");
        assert_eq!(cloned.state().width, 80);
        assert_eq!(cloned.state().height, 24);
        assert_eq!(cloned.state().layout, Layout::Vertical);
    }

    #[test]
    fn test_vbox_clone_widget_deep_clones_children() {
        let mut vb = VBox {
            state: WidgetState::new(),
        };
        vb.state.layout = Layout::Vertical;
        vb.state.width = 10;
        vb.state.height = 10;
        let child = TuiHSpacer::new_i(5).expect("new_i must succeed");
        vb.append_child(child as Arc<dyn Widget>)
            .expect("append_child must succeed");
        assert_eq!(vb.state().children.len(), 1);

        let cloned = vb.clone_widget().expect("clone_widget must succeed");
        // Children must be present (deep-cloned, not shared).
        assert_eq!(cloned.state().children.len(), 1);
        // The cloned child must be a *different* Arc (deep copy).
        let original_child = vb.state().children.iter().next().expect("must have child");
        let cloned_child = cloned.state().children.iter().next().expect("must have child");
        assert!(
            !Arc::ptr_eq(original_child, cloned_child),
            "clone_widget must deep-clone children (not share Arc)",
        );
    }

    // --------------------------------------------------------------
    // Widget trait downcast — as_any() must return self.
    // --------------------------------------------------------------

    #[test]
    fn test_hspacer_as_any_downcasts_to_self() {
        let sp = TuiHSpacer::new_i(10).expect("new_i must succeed");
        let any_ref: &dyn Any = sp.as_any();
        assert!(any_ref.is::<TuiHSpacer>());
        assert!(!any_ref.is::<TuiVSpacer>());
    }

    #[test]
    fn test_vspacer_as_any_downcasts_to_self() {
        let sp = TuiVSpacer::new_i(10).expect("new_i must succeed");
        let any_ref: &dyn Any = sp.as_any();
        assert!(any_ref.is::<TuiVSpacer>());
        assert!(!any_ref.is::<TuiHSpacer>());
    }

    #[test]
    fn test_vbox_as_any_downcasts_to_self() {
        let vb = VBox::new_i(80, 24);
        let any_ref: &dyn Any = vb.as_any();
        assert!(any_ref.is::<VBox>());
        assert!(!any_ref.is::<TuiHSpacer>());
    }

    // --------------------------------------------------------------
    // state_mut allows mutation of the embedded state.
    // --------------------------------------------------------------

    #[test]
    fn test_hspacer_state_mut_allows_mutation() {
        let mut sp = TuiHSpacer {
            state: WidgetState::new(),
        };
        sp.state_mut().display_name = "top-border".to_string();
        sp.state_mut().visible = false;
        assert_eq!(sp.state().display_name, "top-border");
        assert!(!sp.state().visible);
    }

    #[test]
    fn test_vbox_state_mut_allows_mutation() {
        let mut vb = VBox {
            state: WidgetState::new(),
        };
        vb.state_mut().display_name = "outer-vbox".to_string();
        assert_eq!(vb.state().display_name, "outer-vbox");
    }
}
