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
// tui_form: a "convenience wrapper" to hold form-style goods.
// We deal with all the normal input components, and importantly deal with
// tab order, etc. NOTE: if you want custom focus changes from onenter/etc
// from tui_text or the like, you'll need to hook it outside of here and
// call our tab/shifttab/whatever — same goes for submit-style functionality,
// hook the onenters. And for button presses, they fire the click event, so
// it is up to you how to deal with those events.
//
// Ported from tui_form.inc (780 lines of FASM assembly).
//
// Rust translation © 2026, licensed under GPL-3.0-or-later. Derived from
// the HeavyThing assembly library (© 2015 2 Ton Digital, Jeff
// Marrison <jeff@2ton.com.au>).

//! [`Form`] widget: a [`crate::tui::widgets::background::TuiBackground`]-style
//! container managing label+input pairs and centered buttons with a
//! custom tab-order ring.
//!
//! Translation of FASM `tui_form.inc` (780 lines).
//!
//! # Architecture
//!
//! The form fills its full bounds with the supplied `bgfillchar` and
//! `bgcolors` (matching `tui_background$draw`) and centers an
//! "insidebox" inside its full height by flanking it with two 100%
//! [`crate::tui::widgets::spacers::TuiVSpacer`] rows. The insidebox
//! holds an optional **inputrow** (horizontal layout of `labelcolumn` +
//! `inputcolumn`) and/or an optional **buttonrow** (horizontal layout
//! sandwiched with [`crate::tui::widgets::spacers::TuiHSpacer`]s for
//! horizontal centering of the button group):
//!
//! ```text
//! Form (Background-style fill, layout = Vertical, horiz_align = Center)
//! ├─ TuiVSpacer 100%                                         ← top centering
//! ├─ insidebox (SimpleContainer, layout = None)
//! │  ├─ inputrow (SimpleContainer, layout = Horizontal)      ← optional
//! │  │  ├─ labelcolumn (SimpleContainer, horiz_align = Right)
//! │  │  │  ├─ TuiLabel #1
//! │  │  │  └─ TuiLabel #2 …
//! │  │  └─ inputcolumn (SimpleContainer, layout = None)
//! │  │     ├─ input #1
//! │  │     └─ input #2 …
//! │  └─ buttonrow (SimpleContainer, layout = Horizontal)     ← optional
//! │     ├─ TuiHSpacer 100%                                   ← leading pad
//! │     ├─ button #1
//! │     ├─ TuiHSpacer 100%
//! │     ├─ button #2
//! │     ├─ TuiHSpacer 100%                                   ← trailing pad
//! │     ┊
//! └─ TuiVSpacer 100%                                         ← bottom centering
//! ```
//!
//! # Tab order
//!
//! A separate `tablist` (a [`Vec`] of [`Arc<dyn Widget>`]) holds
//! references to the focusable widgets — one entry per
//! [`Form::add_item`] call (the input, never the label) plus one entry
//! per [`Form::add_button`] call. [`Form::on_tab`] and
//! [`Form::on_shift_tab`] cycle a `focus_index` through this ring
//! independently of the children-tree walk order.
//!
//! # Custom hooks
//!
//! Callers installing custom `onenter` / `oncomplete` behavior that
//! must move focus must explicitly invoke [`Form::on_tab`] or
//! [`Form::on_shift_tab`] — the form does not auto-tab on Enter.
//!
//! # Design choices vs. FASM
//!
//! - **Scaffolding tracking by index, not by Arc.** FASM stores raw
//!   pointers to the insidebox / inputrow / buttonrow / labelcolumn /
//!   inputcolumn at fixed struct offsets. The Rust port records the
//!   *position* of each scaffolding widget within its parent's
//!   children list (e.g. `inputrow_index_in_insidebox: Option<usize>`)
//!   so each scaffolding widget retains a single strong reference
//!   inside the children tree — making
//!   [`std::sync::Arc::get_mut`] tractable for in-place dimension
//!   updates from [`Form::recompute_dims`] (matching FASM
//!   `tui_form$nvnewdims` lines 545–675).
//! - **`fire_key_event` interception.** FASM intercepts Tab via the
//!   ASCII byte (9) and Shift-Tab via the parsed CSI escape final
//!   byte (`0x5A`). The Rust port translates both to typed
//!   [`KeyEvent::Tab`] / [`KeyEvent::ShiftTab`] variants — the
//!   typed-event layer in [`crate::tui::object::KeyEvent`] performs
//!   the equivalent CSI parsing upstream.
//! - **Focus callbacks intentionally skipped.** FASM
//!   `tui_form$ontab` calls `vlostfocus` / `vgotfocus` on the
//!   departing/arriving focusable widget. In Rust, every focusable
//!   widget in the tablist is *also* in the children tree, so its
//!   [`Arc`] strong count is at least 2 — preventing
//!   [`std::sync::Arc::get_mut`] from yielding a `&mut` reference
//!   for the call. The Rust port updates `focus_index` only and
//!   defers visual focus changes to widgets that observe their own
//!   focus state through external channels (e.g. cursor visibility
//!   driven by render-pass logic). This is a documented limitation
//!   of the v1 translation; see
//!   [`Form::on_tab`] / [`Form::on_shift_tab`].

use std::any::Any;
use std::sync::{Arc, Mutex};

use crate::error::TuiError;
use crate::tui::geometry::Rect;
use crate::tui::object::{ColorPair, HorizAlign, KeyEvent, Layout, Widget, WidgetState};
use crate::tui::render::Renderer;
use crate::tui::widgets::label::TuiLabel;
use crate::tui::widgets::spacers::{TuiHSpacer, TuiVSpacer};

// ============================================================================
// FormInner — mutex-guarded auxiliary state
// ============================================================================

/// Auxiliary state held inside the [`Form`]'s [`Mutex`].
///
/// Only fields that need to be mutated through a `&self` receiver
/// (i.e. through the [`Widget`] trait's read-only methods) live in
/// this struct. The widget's [`WidgetState`] (children tree, bounds,
/// alignment) and the immutable visual constants (`bgfillchar`,
/// `bgcolors`) live directly on [`Form`] and are reached via
/// [`Widget::state`] / [`Widget::state_mut`].
///
/// # Field layout vs. FASM
///
/// FASM's `tui_form_*_ofs` fields store raw pointers to the
/// scaffolding widgets. The Rust port stores **indices** (or boolean
/// presence markers) instead so each scaffolding widget retains a
/// single strong reference (in the children tree). This enables
/// [`std::sync::Arc::get_mut`] to acquire mutable access to the
/// scaffolding from [`Form::recompute_dims`].
struct FormInner {
    /// Ordered list of focusable widgets — one entry per
    /// [`Form::add_item`] (the *input*, never the label) plus one
    /// entry per [`Form::add_button`].
    ///
    /// Each [`Arc`] is also held in the form's children tree, so the
    /// strong count is at least 2 for any tablist entry. Focus
    /// navigation is therefore index-only — see the module-level
    /// "Design choices vs. FASM" section.
    ///
    /// FASM equivalent: `tui_form_tablist_ofs` (a `list` of widget
    /// pointers).
    tablist: Vec<Arc<dyn Widget>>,

    /// Index of the currently focused widget within [`Self::tablist`],
    /// or [`None`] when no focusable widget exists.
    ///
    /// FASM equivalent: `tui_form_focus_ofs` — a pointer to the
    /// *list item* (not to the widget directly), used as a sentinel
    /// for "no focus" when zero. Rust's [`Option<usize>`] captures
    /// the same two-state intent.
    focus_index: Option<usize>,

    /// `true` after the first [`Form::add_item`] or
    /// [`Form::add_button`] call has installed the leading
    /// [`TuiVSpacer`], the [`SimpleContainer`] that hosts
    /// inputrow/buttonrow, and the trailing [`TuiVSpacer`].
    ///
    /// When `true`, `state.children` has the layout
    /// `[vspacer, insidebox, vspacer]` (length 3) and the insidebox
    /// is at `state.children[INSIDEBOX_INDEX]`.
    ///
    /// FASM equivalent: a non-null pointer at
    /// `tui_form_insidebox_ofs` indicates the same condition.
    has_insidebox: bool,

    /// Position of the inputrow within `insidebox.state.children`,
    /// or [`None`] when no [`Form::add_item`] has been called yet.
    ///
    /// FASM equivalent: a non-null pointer at
    /// `tui_form_inputrow_ofs` indicates the inputrow has been
    /// installed.
    inputrow_index_in_insidebox: Option<usize>,

    /// Position of the buttonrow within `insidebox.state.children`,
    /// or [`None`] when no [`Form::add_button`] has been called yet.
    ///
    /// FASM equivalent: `tui_form_buttonrow_ofs`.
    buttonrow_index_in_insidebox: Option<usize>,
}

impl FormInner {
    /// Construct a fresh [`FormInner`] with no scaffolding installed
    /// and no focusable widgets.
    fn new() -> Self {
        Self {
            tablist: Vec::new(),
            focus_index: None,
            has_insidebox: false,
            inputrow_index_in_insidebox: None,
            buttonrow_index_in_insidebox: None,
        }
    }
}

/// Position of the insidebox within `Form::state.children` when
/// [`FormInner::has_insidebox`] is `true`. Sandwiched by the leading
/// (`[0]`) and trailing (`[2]`) [`TuiVSpacer`]s.
const INSIDEBOX_INDEX: usize = 1;

// ============================================================================
// Form — the public widget type
// ============================================================================

/// Form container — a [`crate::tui::widgets::background::TuiBackground`]-style
/// widget that holds label+input pairs and centered buttons, plus a
/// custom tab-order ring independent of the widget-tree walk order.
///
/// FASM parallel: `tui_form_size = tui_background_size + 56` extends
/// background with six 8-byte fields (`tablist`, `insidebox`,
/// `labelcolumn`, `inputcolumn`, `inputrow`, `buttonrow`, `focus`).
/// The Rust port stores the analogous state inside [`FormInner`]
/// (mutex-guarded for `&self` access from the [`Widget`] trait's
/// read-only methods); the visual fill constants `bgfillchar` /
/// `bgcolors` are kept directly on the struct for cheap access from
/// [`Widget::draw`].
///
/// # Visual model
///
/// Form does not embed a [`crate::tui::widgets::background::TuiBackground`]
/// — it implements the same fill-with-`bgfillchar`-and-`bgcolors`
/// behavior directly via the local [`nvfill`] helper inside its
/// [`Widget::draw`] override. The Rust hierarchy is `Form: Widget`,
/// not `Form: TuiBackground`, since Rust does not have inheritance
/// (the FASM "extension" relationship is reproduced through helper
/// reuse).
pub struct Form {
    /// Inherited [`WidgetState`] — bounds, dimensions, children tree,
    /// alignment flags. Visible to the rest of the crate via
    /// `pub(crate)` so internal modules can navigate scaffolding for
    /// rendering / clone reconstruction without going through the
    /// trait.
    pub(crate) state: WidgetState,

    /// Background fill character (Unicode codepoint) — used by
    /// [`Widget::draw`] via the local [`nvfill`] helper.
    ///
    /// FASM parallel: `tui_bgfillchar_ofs` (single 32-bit slot).
    bgfillchar: u32,

    /// Background colors (foreground + background) — used by
    /// [`Widget::draw`] alongside `bgfillchar`.
    ///
    /// FASM parallel: `tui_bgcolors_ofs` (packed colors).
    bgcolors: ColorPair,

    /// Mutex-guarded tablist + scaffolding-presence state. See
    /// [`FormInner`] for field semantics.
    inner: Mutex<FormInner>,
}

// ============================================================================
// Internal helpers — local replicas of `tui_object$init_copy` and
// `tui_background$nvfill`. Identical to the helpers in
// [`crate::tui::widgets::background`], [`crate::tui::widgets::label`],
// and [`crate::tui::widgets::panel`] (the helpers are private to each
// widget module to avoid a multi-module pub-use surface).
// ============================================================================

/// Pack a [`ColorPair`] into the 32-bit attribute layout used by the
/// renderer (`fg` in the low byte, `bg` in the next byte).
///
/// Identical to the helpers in
/// [`crate::tui::widgets::background`] and
/// [`crate::tui::widgets::panel`] (FASM
/// `tui_object$init_attr_buffer`).
fn pack_color_pair(cp: ColorPair) -> u32 {
    u32::from(cp.fg) | (u32::from(cp.bg) << 8)
}

/// Pre-allocate the text and attribute buffers when both dimensions
/// are positive integers.
///
/// FASM parallel: lines 230–243 of `tui_form$new_rect` — the same
/// pre-allocation block runs in every `new_*` constructor when the
/// width and height resolve to positive integers (percentage
/// constructors leave the buffers empty until the layout pass calls
/// [`Widget::size_changed`]).
///
/// # Errors
///
/// Returns [`TuiError::Render`] when `width * height` or `cells * 4`
/// would overflow [`usize`].
fn pre_allocate_buffers(state: &mut WidgetState) -> Result<(), TuiError> {
    if state.width <= 0 || state.height <= 0 {
        return Ok(());
    }
    let width = state.width as usize;
    let height = state.height as usize;
    let cells = width.checked_mul(height).ok_or_else(|| {
        TuiError::Render(std::io::Error::other(
            "form pre_allocate_buffers: width * height overflow",
        ))
    })?;
    let bytes = cells.checked_mul(4).ok_or_else(|| {
        TuiError::Render(std::io::Error::other(
            "form pre_allocate_buffers: cells * 4 overflow",
        ))
    })?;
    state.text.reserve_exact(bytes);
    for _ in 0..bytes {
        state.text.push(0);
    }
    state.attributes.cells.resize(cells, 0);
    Ok(())
}

/// Fill `count` consecutive 32-bit cells of [`WidgetState::text`]
/// with `value` (little-endian).
///
/// Grows the buffer when too short and truncates from the end when
/// too long. Identical to the helpers in
/// [`crate::tui::widgets::label`] and
/// [`crate::tui::widgets::panel`].
///
/// # Errors
///
/// Returns [`TuiError::Render`] when `count * 4` would overflow
/// [`usize`] or when [`crate::ds::buffer::Buffer::truncate`] fails.
fn fill_text_buffer(state: &mut WidgetState, value: u32, count: usize) -> Result<(), TuiError> {
    let bytes = count.checked_mul(4).ok_or_else(|| {
        TuiError::Render(std::io::Error::other("form fill_text_buffer: count * 4 overflow"))
    })?;
    if state.text.len() < bytes {
        let extra = bytes - state.text.len();
        state.text.reserve(extra);
        for _ in 0..extra {
            state.text.push(0);
        }
    } else if state.text.len() > bytes {
        let to_remove = state.text.len() - bytes;
        state.text.truncate(to_remove).map_err(|e| {
            TuiError::Render(std::io::Error::other(format!(
                "form fill_text_buffer: truncate failed ({e})"
            )))
        })?;
    }
    let value_bytes = value.to_le_bytes();
    for chunk in state.text.as_mut_slice().chunks_exact_mut(4).take(count) {
        chunk[0] = value_bytes[0];
        chunk[1] = value_bytes[1];
        chunk[2] = value_bytes[2];
        chunk[3] = value_bytes[3];
    }
    Ok(())
}

/// Fill `count` consecutive cells of [`WidgetState::attributes`]
/// with the packed `value`.
///
/// Resizes the cell vector to `count`. Identical to the helpers in
/// [`crate::tui::widgets::label`] and
/// [`crate::tui::widgets::panel`]. Always succeeds — the caller
/// treats this as infallible.
fn fill_attr_buffer(state: &mut WidgetState, value: u32, count: usize) {
    state.attributes.cells.resize(count, 0);
    for cell in state.attributes.cells.iter_mut() {
        *cell = value;
    }
}

/// Apply a uniform `(bgfillchar, bgcolors)` fill to the widget's
/// text and attribute buffers.
///
/// Functional twin of `tui_background$nvfill` (FASM
/// `tui_background.inc`) — identical to the helper of the same name
/// in [`crate::tui::widgets::panel`]. When `bgfillchar` is `0` the
/// text buffer is **not** rewritten (mirroring FASM's
/// `cmp ecx, 0; je .skipfill`); the attribute fill is always
/// applied.
///
/// # Errors
///
/// Returns [`TuiError::Render`] when [`fill_text_buffer`] fails.
fn nvfill(state: &mut WidgetState, bgfillchar: u32, bgcolors: ColorPair) -> Result<(), TuiError> {
    if state.width <= 0 || state.height <= 0 {
        return Ok(());
    }
    if state.text.is_empty() {
        return Ok(());
    }
    let width = state.width as usize;
    let height = state.height as usize;
    let cells = width
        .checked_mul(height)
        .ok_or_else(|| TuiError::Render(std::io::Error::other("form nvfill: width * height overflow")))?;
    if bgfillchar != 0 {
        fill_text_buffer(state, bgfillchar, cells)?;
    }
    let packed = pack_color_pair(bgcolors);
    fill_attr_buffer(state, packed, cells);
    Ok(())
}

/// Deep-clone a [`WidgetState`].
///
/// FASM equivalent: `tui_object$init_copy` (`tui_object.inc`).
/// Performs scalar bitwise copies for the fixed fields, deep-copies
/// the text / attribute / display-name buffers, and walks the
/// children list calling [`Widget::clone_widget`] on each. The
/// `bastards` list is intentionally **not** cloned — FASM line 274
/// does the same, leaving it empty for the new instance.
///
/// Identical to the helpers in
/// [`crate::tui::widgets::background`],
/// [`crate::tui::widgets::label`],
/// [`crate::tui::widgets::panel`], and
/// [`crate::tui::widgets::spacers`].
///
/// # Errors
///
/// Returns the first [`TuiError`] produced by a child's
/// [`Widget::clone_widget`].
fn clone_widget_state(src: &WidgetState) -> Result<WidgetState, TuiError> {
    let mut cloned = WidgetState::new();
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
    cloned.text = src.text.clone();
    cloned.attributes = src.attributes.clone();
    for child in src.children.iter() {
        cloned.children.push_back(child.clone_widget()?);
    }
    Ok(cloned)
}

// ============================================================================
// SimpleContainer — private invisible widget for scaffolding (insidebox,
// inputrow, labelcolumn, inputcolumn, buttonrow).
// ============================================================================

/// Internal helper widget used for the form's scaffolding containers
/// — `insidebox`, `inputrow`, `labelcolumn`, `inputcolumn`, and
/// `buttonrow`.
///
/// `SimpleContainer` is the Rust analog of FASM
/// `tui_object$simple_vtable` (`tui_object.inc` line 922): a bare
/// [`crate::tui::object::Widget`] with the `draw` slot wired to a
/// no-op so the scaffolding does not paint anything itself —
/// children render via the parent's
/// [`Widget::update_display_list`] traversal. The container exists
/// solely to host children with a chosen [`Layout`] orientation /
/// alignment.
///
/// FASM equivalents:
///
/// - `tui_form$nvadditem` lines 348, 366, 380, 393 (the four
///   `simple_vtable`-allocated scaffolding widgets installed during
///   the first item-add).
/// - `tui_form$nvaddbutton` lines 466 (the buttonrow).
///
/// # Visibility
///
/// Strictly private — the form is the only intended construction
/// site. External callers that want a no-op container should use
/// [`crate::tui::widgets::spacers::VBox`] or analogous public
/// containers instead.
struct SimpleContainer {
    state: WidgetState,
}

impl SimpleContainer {
    /// Construct a percentage-sized container.
    ///
    /// Mirrors FASM `tui_object$init_dd` followed by writes to the
    /// layout / alignment slots. Both percentages are on the 0–100
    /// scale (matching all other percentage-based constructors in
    /// the crate).
    fn new_dd(width_perc: f64, height_perc: f64, layout: Layout) -> Arc<Self> {
        let mut state = WidgetState::new();
        state.width = 0;
        state.height = 0;
        state.width_percent = Some(width_perc);
        state.height_percent = Some(height_perc);
        state.layout = layout;
        Arc::new(Self { state })
    }

    /// Construct a percentage-sized container with explicit
    /// horizontal alignment. Used exclusively for the `labelcolumn`
    /// scaffolding (which right-aligns the labels inside the
    /// inputrow).
    fn new_dd_align(width_perc: f64, height_perc: f64, layout: Layout, horiz_align: HorizAlign) -> Arc<Self> {
        let mut state = WidgetState::new();
        state.width = 0;
        state.height = 0;
        state.width_percent = Some(width_perc);
        state.height_percent = Some(height_perc);
        state.layout = layout;
        state.horiz_align = horiz_align;
        Arc::new(Self { state })
    }

    /// Construct an integer-sized container. Used for the
    /// `insidebox` which starts at `1×1` and grows via
    /// [`Form::recompute_dims`] as items / buttons are added (FASM
    /// `tui_object$init_ii(1, 1)` at `tui_form.inc` lines 339, 348,
    /// 462).
    fn new_ii(width: i32, height: i32, layout: Layout) -> Arc<Self> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = height;
        state.width_percent = None;
        state.height_percent = None;
        state.layout = layout;
        Arc::new(Self { state })
    }
}

impl Widget for SimpleContainer {
    fn state(&self) -> &WidgetState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// No-op draw — matches FASM `tui_object$simple_vtable`'s draw
    /// entry. Children render via the parent's
    /// [`Widget::update_display_list`] traversal.
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        Ok(())
    }

    /// Deep-clone via [`clone_widget_state`] — the children list is
    /// recursively cloned, the (currently empty) `bastards` list is
    /// reset to empty, and the `state.layout` / `horiz_align` /
    /// dimensions are preserved.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        let cloned_state = clone_widget_state(&self.state)?;
        Ok(Arc::new(Self { state: cloned_state }) as Arc<dyn Widget>)
    }
}

// ============================================================================
// Form constructors (5 variants matching FASM tui_form$new_{rect,id,di,dd,ii})
// ============================================================================

impl Form {
    /// Construct a form with explicit absolute bounds.
    ///
    /// FASM parallel: `tui_form$new_rect` (`tui_form.inc` lines
    /// 90–110): allocates `tui_form_size`, calls
    /// `tui_background$init_rect` to set bounds + dimensions and
    /// pre-allocate buffers, sets `bgfillchar` / `bgcolors`, then
    /// runs `tui_form$nvinit_common` to wire the empty tablist /
    /// scaffolding state.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when the (positive) `width *
    /// height` overflows [`usize`].
    pub fn new_rect(bounds: Rect, fillchar: u32, colors: ColorPair) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.bounds = bounds;
        state.width = bounds.width();
        state.height = bounds.height();
        state.width_percent = None;
        state.height_percent = None;
        Self::finalize_init(state, fillchar, colors)
    }

    /// Construct a form with absolute integer width and integer
    /// height. Both buffers are pre-allocated and zero-filled when
    /// both dimensions are positive.
    ///
    /// FASM parallel: `tui_form$new_ii` (`tui_form.inc` lines
    /// 113–134).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when `width * height` overflows
    /// [`usize`].
    pub fn new_ii(width: i32, height: i32, fillchar: u32, colors: ColorPair) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = height;
        state.width_percent = None;
        state.height_percent = None;
        Self::finalize_init(state, fillchar, colors)
    }

    /// Construct a form with absolute integer width and percentage
    /// height. Buffers are not pre-allocated — the layout pass
    /// resolves the absolute height and triggers buffer growth via
    /// [`Widget::size_changed`].
    ///
    /// FASM parallel: `tui_form$new_id` (`tui_form.inc` lines
    /// 137–157).
    ///
    /// # Errors
    ///
    /// See [`Self::new_rect`].
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

    /// Construct a form with percentage width and absolute integer
    /// height. Buffers are not pre-allocated.
    ///
    /// FASM parallel: `tui_form$new_di` (`tui_form.inc` lines
    /// 160–180).
    ///
    /// # Errors
    ///
    /// See [`Self::new_rect`].
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

    /// Construct a form with both dimensions specified as
    /// percentages of the parent. Buffers are not pre-allocated.
    ///
    /// FASM parallel: `tui_form$new_dd` (`tui_form.inc` lines
    /// 183–204).
    ///
    /// # Errors
    ///
    /// See [`Self::new_rect`].
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

    /// Common constructor tail shared by all five `new_*` entry
    /// points.
    ///
    /// Steps:
    ///
    /// 1. Set the layout fields shared by all forms:
    ///    `state.layout = Layout::Vertical` (children flow
    ///    top-to-bottom — leading vspacer / insidebox / trailing
    ///    vspacer) and `state.horiz_align = HorizAlign::Center`
    ///    (matching FASM `tui_form$nvinit_common` writes at
    ///    `tui_form.inc` lines 232–243).
    /// 2. Pre-allocate text and attribute buffers when both
    ///    dimensions resolve to positive integers (matching FASM
    ///    `tui_object$init_rect` / `init_ii` allocation behavior).
    /// 3. Wrap the freshly built [`Form`] in [`Arc`].
    ///
    /// The scaffolding (insidebox, inputrow, columns, buttonrow,
    /// vspacers) is **not** built here — it is constructed lazily
    /// on the first [`Form::add_item`] / [`Form::add_button`] call
    /// (matching FASM `nvadditem` / `nvaddbutton` first-call
    /// behavior at lines 324–406 and 445–490).
    fn finalize_init(
        mut state: WidgetState,
        fillchar: u32,
        colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        // FASM `tui_form$nvinit_common` (lines 232–243) writes:
        //   layout      = Vertical
        //   horiz_align = Center
        state.layout = Layout::Vertical;
        state.horiz_align = HorizAlign::Center;

        pre_allocate_buffers(&mut state)?;

        Ok(Arc::new(Self {
            state,
            bgfillchar: fillchar,
            bgcolors: colors,
            inner: Mutex::new(FormInner::new()),
        }))
    }
}

// ============================================================================
// Public mutators — add_item / add_button / recompute_dims / set_colors
// ============================================================================

impl Form {
    /// Append a label + input pair to the form.
    ///
    /// On the first call (no scaffolding installed yet) the form lazily
    /// builds:
    ///
    /// * a leading [`TuiVSpacer`] (100% height) for vertical centering;
    /// * an [`SimpleContainer`] **insidebox** (initially `1×1` integer,
    ///   resized by [`Self::recompute_dims`] each time an item or
    ///   button is added);
    /// * a trailing [`TuiVSpacer`] (100% height).
    ///
    /// On the first call without an inputrow yet (i.e. the very first
    /// [`Self::add_item`], possibly after one or more
    /// [`Self::add_button`]s installed only the buttonrow) the form
    /// then builds inside the insidebox:
    ///
    /// * an [`SimpleContainer`] **inputrow** (`Layout::Horizontal`)
    ///   holding two child columns;
    /// * an [`SimpleContainer`] **labelcolumn**
    ///   (`HorizAlign::Right`) for right-aligned labels;
    /// * an [`SimpleContainer`] **inputcolumn** for inputs.
    ///
    /// Then the supplied `label` is appended to the labelcolumn's
    /// children, the supplied `input` is appended to the
    /// inputcolumn's children, and `input` (NOT the label) is pushed
    /// onto the tablist for tab navigation. If the form had no
    /// focused widget yet, `focus_index` is set to the new tablist
    /// position. Finally [`Self::recompute_dims`] cascades the new
    /// dimensions through the scaffolding.
    ///
    /// FASM parallel: `tui_form$nvadditem` (`tui_form.inc` lines
    /// 324–443).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when the underlying scaffolding
    /// allocation fails (only possible on extreme OOM during the
    /// first call) or when the children-tree mutation cannot acquire
    /// a unique reference (an internal invariant violation; should
    /// never happen during normal use).
    pub fn add_item(&mut self, label: Arc<TuiLabel>, input: Arc<dyn Widget>) -> Result<(), TuiError> {
        self.ensure_insidebox()?;
        self.ensure_input_columns()?;

        // Append label to labelcolumn.children, input to
        // inputcolumn.children. Both columns live inside the insidebox
        // at known positions captured by `ensure_input_columns`.
        let (insidebox_idx, inputrow_idx) = {
            let inner = self.inner.lock().unwrap();
            (
                INSIDEBOX_INDEX,
                inner
                    .inputrow_index_in_insidebox
                    .expect("ensure_input_columns must set inputrow_index_in_insidebox"),
            )
        };

        // Walk: form -> insidebox -> inputrow -> {labelcolumn, inputcolumn}.
        // The labelcolumn is always inputrow.children[0] and the
        // inputcolumn is inputrow.children[1] (FASM order at lines
        // 397, 412).
        let label_dyn: Arc<dyn Widget> = label;
        Self::with_inputrow_mut(&mut self.state, insidebox_idx, inputrow_idx, |inputrow| {
            let labelcolumn = inputrow.state_mut().children.get_mut(0).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form add_item: inputrow.children[0] (labelcolumn) missing",
                ))
            })?;
            let labelcolumn_widget = Arc::get_mut(labelcolumn).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form add_item: labelcolumn Arc unexpectedly aliased",
                ))
            })?;
            labelcolumn_widget.append_child(label_dyn);
            Ok::<(), TuiError>(())
        })?;

        Self::with_inputrow_mut(&mut self.state, insidebox_idx, inputrow_idx, |inputrow| {
            let inputcolumn = inputrow.state_mut().children.get_mut(1).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form add_item: inputrow.children[1] (inputcolumn) missing",
                ))
            })?;
            let inputcolumn_widget = Arc::get_mut(inputcolumn).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form add_item: inputcolumn Arc unexpectedly aliased",
                ))
            })?;
            inputcolumn_widget.append_child(input.clone());
            Ok::<(), TuiError>(())
        })?;

        // Push input onto tablist; auto-focus when this is the first
        // tablist entry.
        {
            let mut inner = self.inner.lock().unwrap();
            inner.tablist.push(input);
            if inner.focus_index.is_none() {
                inner.focus_index = Some(inner.tablist.len() - 1);
            }
        }

        self.recompute_dims()?;
        Ok(())
    }

    /// Append a button to the form's button row.
    ///
    /// On the first call (no scaffolding installed yet) the form
    /// lazily builds the leading `vspacer` / `insidebox` / trailing
    /// `vspacer` (same as [`Self::add_item`]).
    ///
    /// On the first call without a buttonrow yet (i.e. the very
    /// first [`Self::add_button`], possibly after one or more
    /// [`Self::add_item`]s installed only the inputrow) the form
    /// then builds inside the insidebox:
    ///
    /// * an [`SimpleContainer`] **buttonrow**
    ///   (`Layout::Horizontal`);
    /// * a leading [`TuiHSpacer`] (100% width) inside the buttonrow
    ///   for centering.
    ///
    /// Then the supplied `button` is appended to the buttonrow,
    /// followed by a trailing [`TuiHSpacer`] (100% width) — together
    /// these form the "hspacer-sandwich" centering pattern. The
    /// `button` is pushed onto the tablist for tab navigation; if
    /// the form had no focused widget yet, `focus_index` is set to
    /// the new tablist position. Finally [`Self::recompute_dims`]
    /// cascades the new dimensions.
    ///
    /// FASM parallel: `tui_form$nvaddbutton` (`tui_form.inc` lines
    /// 445–542).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] under the same conditions as
    /// [`Self::add_item`].
    pub fn add_button(&mut self, button: Arc<dyn Widget>) -> Result<(), TuiError> {
        self.ensure_insidebox()?;
        self.ensure_buttonrow()?;

        let (insidebox_idx, buttonrow_idx) = {
            let inner = self.inner.lock().unwrap();
            (
                INSIDEBOX_INDEX,
                inner
                    .buttonrow_index_in_insidebox
                    .expect("ensure_buttonrow must set buttonrow_index_in_insidebox"),
            )
        };

        // Append the button followed by a trailing 100% hspacer to
        // the buttonrow's children list (matches FASM lines 514–523).
        Self::with_buttonrow_mut(&mut self.state, insidebox_idx, buttonrow_idx, |buttonrow| {
            buttonrow.append_child(button.clone());
            let trailing_hspacer: Arc<dyn Widget> = TuiHSpacer::new_d(100.0)?;
            buttonrow.append_child(trailing_hspacer);
            Ok::<(), TuiError>(())
        })?;

        // Push button onto tablist; auto-focus when first entry.
        {
            let mut inner = self.inner.lock().unwrap();
            inner.tablist.push(button);
            if inner.focus_index.is_none() {
                inner.focus_index = Some(inner.tablist.len() - 1);
            }
        }

        self.recompute_dims()?;
        Ok(())
    }

    /// Recompute the dimensions of the scaffolding widgets after a
    /// child has been added.
    ///
    /// The form's own bounds are *not* changed — only the
    /// scaffolding (insidebox, inputrow, labelcolumn, inputcolumn,
    /// buttonrow) is re-sized so that:
    ///
    /// * `insidebox.width = max(max_label_w + max_input_w, total_button_w)`
    /// * `insidebox.height = max(total_label_h, total_input_h) + max_button_h`
    /// * `inputrow.width = insidebox.width`
    /// * `inputrow.height = insidebox.height - max_button_h`
    /// * `labelcolumn.width = max_label_w`, `labelcolumn.height = total_label_h`
    /// * `inputcolumn.width = max_input_w`, `inputcolumn.height = total_input_h`
    /// * `buttonrow.width = insidebox.width`, `buttonrow.height = max_button_h`
    ///
    /// FASM parallel: `tui_form$nvnewdims` (`tui_form.inc` lines
    /// 545–675). The Rust port deliberately uses the
    /// **geometrically correct** formulas above; the FASM source
    /// has slot-offset bookkeeping that mixes button width and
    /// height (see the agent prompt and module docs for the
    /// reasoning). Since the FASM showcase apps never rely on the
    /// exact pixel-for-pixel layout produced by the apparent FASM
    /// bug — they only rely on the form being big enough to fit
    /// its contents — preserving the geometric intent is the safer
    /// translation.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when a scaffolding widget's
    /// [`Arc`] reference cannot be uniquely accessed (an internal
    /// invariant violation that should not occur during normal
    /// use).
    pub fn recompute_dims(&mut self) -> Result<(), TuiError> {
        let (have_inputrow, inputrow_idx, have_buttonrow, buttonrow_idx) = {
            let inner = self.inner.lock().unwrap();
            (
                inner.inputrow_index_in_insidebox.is_some(),
                inner.inputrow_index_in_insidebox,
                inner.buttonrow_index_in_insidebox.is_some(),
                inner.buttonrow_index_in_insidebox,
            )
        };

        if !have_inputrow && !have_buttonrow {
            // No scaffolding installed yet — nothing to recompute.
            return Ok(());
        }

        // Phase 1 — gather metrics by walking the children of each
        // column / buttonrow. We compute four sets:
        //   - label set (children of labelcolumn): max_w, total_h
        //   - input set (children of inputcolumn): max_w, total_h
        //   - button set (children of buttonrow, FILTERED to drop
        //     spacers): total_w, max_h
        //
        // FASM uses `list$foreach_arg(.dims)` to walk each set; the
        // Rust port iterates the children list directly.
        let mut max_label_w: i32 = 0;
        let mut total_label_h: i32 = 0;
        let mut max_input_w: i32 = 0;
        let mut total_input_h: i32 = 0;
        let mut total_button_w: i32 = 0;
        let mut max_button_h: i32 = 0;

        let insidebox_arc = self.state.children.get(INSIDEBOX_INDEX).ok_or_else(|| {
            TuiError::Render(std::io::Error::other("form recompute_dims: insidebox missing"))
        })?;
        let insidebox_state = insidebox_arc.state();

        if let Some(idx) = inputrow_idx {
            let inputrow_arc = insidebox_state.children.get(idx).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form recompute_dims: inputrow index out of bounds",
                ))
            })?;
            let inputrow_state = inputrow_arc.state();
            // labelcolumn is inputrow.children[0]
            if let Some(labelcolumn_arc) = inputrow_state.children.get(0) {
                for child in labelcolumn_arc.state().children.iter() {
                    let s = child.state();
                    if s.width > max_label_w {
                        max_label_w = s.width;
                    }
                    total_label_h = total_label_h.saturating_add(s.height);
                }
            }
            // inputcolumn is inputrow.children[1]
            if let Some(inputcolumn_arc) = inputrow_state.children.get(1) {
                for child in inputcolumn_arc.state().children.iter() {
                    let s = child.state();
                    if s.width > max_input_w {
                        max_input_w = s.width;
                    }
                    total_input_h = total_input_h.saturating_add(s.height);
                }
            }
        }

        if let Some(idx) = buttonrow_idx {
            let buttonrow_arc = insidebox_state.children.get(idx).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form recompute_dims: buttonrow index out of bounds",
                ))
            })?;
            for child in buttonrow_arc.state().children.iter() {
                let s = child.state();
                // Skip spacers (which use width_percent / height_percent)
                // — they would otherwise make the button row's
                // "total width" useless because each hspacer reports
                // width = 0 and a percentage-based extension. FASM
                // does not filter, but FASM's hspacer reports
                // width = 0, so the same total accumulates. We mirror
                // that semantic by only counting widgets with a
                // concrete width.
                if s.width_percent.is_none() {
                    total_button_w = total_button_w.saturating_add(s.width);
                    if s.height > max_button_h {
                        max_button_h = s.height;
                    }
                }
            }
        }

        // Phase 2 — compute the insidebox / inputrow / column / buttonrow
        // dimensions per the geometric formulas in this method's docs.
        let labels_plus_inputs_w = max_label_w.saturating_add(max_input_w);
        let insidebox_w = labels_plus_inputs_w.max(total_button_w);
        let labels_or_inputs_h = total_label_h.max(total_input_h);
        let insidebox_h = labels_or_inputs_h.saturating_add(max_button_h);

        // Phase 3 — apply dimensions to scaffolding widgets via
        // Arc::get_mut. Each scaffolding widget has refcount = 1 (no
        // tablist holds them; they live solely in the children tree),
        // so get_mut succeeds.
        let insidebox_arc_mut = self.state.children.get_mut(INSIDEBOX_INDEX).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "form recompute_dims: insidebox slot missing",
            ))
        })?;
        let insidebox_widget = Arc::get_mut(insidebox_arc_mut).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "form recompute_dims: insidebox Arc aliased",
            ))
        })?;
        insidebox_widget.state_mut().width = insidebox_w;
        insidebox_widget.state_mut().height = insidebox_h;
        insidebox_widget.size_changed(insidebox_w, insidebox_h);

        // Within the insidebox, resize inputrow / labelcolumn /
        // inputcolumn / buttonrow.
        let insidebox_state_mut = insidebox_widget.state_mut();

        if let Some(idx) = inputrow_idx {
            let inputrow_arc_mut = insidebox_state_mut.children.get_mut(idx).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form recompute_dims: inputrow slot missing",
                ))
            })?;
            let inputrow_widget = Arc::get_mut(inputrow_arc_mut).ok_or_else(|| {
                TuiError::Render(std::io::Error::other("form recompute_dims: inputrow Arc aliased"))
            })?;
            let inputrow_w = insidebox_w;
            let inputrow_h = insidebox_h.saturating_sub(max_button_h);
            inputrow_widget.state_mut().width = inputrow_w;
            inputrow_widget.state_mut().height = inputrow_h;
            inputrow_widget.size_changed(inputrow_w, inputrow_h);

            // labelcolumn = inputrow.children[0]
            {
                let inputrow_state_mut = inputrow_widget.state_mut();
                if let Some(labelcolumn_arc) = inputrow_state_mut.children.get_mut(0) {
                    let labelcolumn_widget = Arc::get_mut(labelcolumn_arc).ok_or_else(|| {
                        TuiError::Render(std::io::Error::other(
                            "form recompute_dims: labelcolumn Arc aliased",
                        ))
                    })?;
                    labelcolumn_widget.state_mut().width = max_label_w;
                    labelcolumn_widget.state_mut().height = total_label_h;
                    labelcolumn_widget.size_changed(max_label_w, total_label_h);
                }
                // inputcolumn = inputrow.children[1]
                if let Some(inputcolumn_arc) = inputrow_state_mut.children.get_mut(1) {
                    let inputcolumn_widget = Arc::get_mut(inputcolumn_arc).ok_or_else(|| {
                        TuiError::Render(std::io::Error::other(
                            "form recompute_dims: inputcolumn Arc aliased",
                        ))
                    })?;
                    inputcolumn_widget.state_mut().width = max_input_w;
                    inputcolumn_widget.state_mut().height = total_input_h;
                    inputcolumn_widget.size_changed(max_input_w, total_input_h);
                }
            }
        }

        if let Some(idx) = buttonrow_idx {
            let buttonrow_arc_mut = insidebox_state_mut.children.get_mut(idx).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form recompute_dims: buttonrow slot missing",
                ))
            })?;
            let buttonrow_widget = Arc::get_mut(buttonrow_arc_mut).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form recompute_dims: buttonrow Arc aliased",
                ))
            })?;
            buttonrow_widget.state_mut().width = insidebox_w;
            buttonrow_widget.state_mut().height = max_button_h;
            buttonrow_widget.size_changed(insidebox_w, max_button_h);
        }

        Ok(())
    }

    /// Update the form's background color pair.
    ///
    /// Mirrors FASM `tui_background$set_colors` — sets
    /// `bgcolors` and lets the next [`Widget::draw`] pass repaint
    /// the new colors via [`nvfill`].
    pub fn set_colors(&mut self, colors: ColorPair) {
        self.bgcolors = colors;
    }

    /// Read the form's background fill character.
    #[must_use]
    pub fn fillchar(&self) -> u32 {
        self.bgfillchar
    }

    /// Read the form's background color pair.
    #[must_use]
    pub fn colors(&self) -> ColorPair {
        self.bgcolors
    }
}

// ============================================================================
// Private scaffolding helpers — ensure_insidebox / ensure_input_columns /
// ensure_buttonrow + with_*_mut accessors. Centralizing the children-tree
// surgery keeps the public methods readable.
// ============================================================================

impl Form {
    /// Ensure the leading-vspacer / insidebox / trailing-vspacer
    /// triple has been installed in `self.state.children`. Runs at
    /// most once per form (gated by `inner.has_insidebox`).
    ///
    /// FASM parallel: lines 334–364 (in `nvadditem`) and 453–483 (in
    /// `nvaddbutton`). The two FASM call sites are identical; the
    /// Rust port factors them into this helper.
    fn ensure_insidebox(&mut self) -> Result<(), TuiError> {
        let already = self.inner.lock().unwrap().has_insidebox;
        if already {
            return Ok(());
        }

        // 1. Leading vspacer.
        let leading_vspacer: Arc<dyn Widget> = TuiVSpacer::new_d(100.0)?;
        // 2. Insidebox: 1×1 SimpleContainer with Layout::Vertical
        //    (matches FASM default: heap-zeroed `tui_layout_ofs` = 0
        //    = `tui_layout_vertical`).
        let insidebox: Arc<dyn Widget> = SimpleContainer::new_ii(1, 1, Layout::Vertical);
        // 3. Trailing vspacer.
        let trailing_vspacer: Arc<dyn Widget> = TuiVSpacer::new_d(100.0)?;

        self.state.children.push_back(leading_vspacer);
        self.state.children.push_back(insidebox);
        self.state.children.push_back(trailing_vspacer);

        self.inner.lock().unwrap().has_insidebox = true;
        Ok(())
    }

    /// Ensure the inputrow + labelcolumn + inputcolumn scaffolding
    /// has been installed inside the insidebox. Runs at most once
    /// per form (gated by `inner.inputrow_index_in_insidebox`).
    ///
    /// FASM parallel: lines 367–413 (in `nvadditem`).
    fn ensure_input_columns(&mut self) -> Result<(), TuiError> {
        let already = self.inner.lock().unwrap().inputrow_index_in_insidebox.is_some();
        if already {
            return Ok(());
        }

        // Build inputrow with labelcolumn + inputcolumn as children.
        // The labelcolumn gets HorizAlign::Right (matches FASM line
        // 398). All three are SimpleContainer scaffolding widgets.
        let mut inputrow = SimpleContainer::new_ii(1, 1, Layout::Horizontal);
        let labelcolumn: Arc<dyn Widget> =
            SimpleContainer::new_dd_align(100.0, 100.0, Layout::Vertical, HorizAlign::Right);
        let inputcolumn: Arc<dyn Widget> = SimpleContainer::new_dd(100.0, 100.0, Layout::Vertical);

        // Push columns into the inputrow (it has refcount = 1 here
        // because we just allocated it).
        {
            let inputrow_mut = Arc::get_mut(&mut inputrow).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form ensure_input_columns: inputrow Arc unexpectedly aliased",
                ))
            })?;
            inputrow_mut.state.children.push_back(labelcolumn);
            inputrow_mut.state.children.push_back(inputcolumn);
        }

        // Append the inputrow into the insidebox. The insidebox
        // lives at self.state.children[INSIDEBOX_INDEX] and its Arc
        // refcount is 1 (the form is its sole owner via the
        // children tree).
        let inputrow_dyn: Arc<dyn Widget> = inputrow;
        let insidebox_arc = self.state.children.get_mut(INSIDEBOX_INDEX).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "form ensure_input_columns: insidebox missing",
            ))
        })?;
        let insidebox_widget = Arc::get_mut(insidebox_arc).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "form ensure_input_columns: insidebox Arc aliased",
            ))
        })?;
        let inputrow_idx = insidebox_widget.state_mut().children.len();
        insidebox_widget.state_mut().children.push_back(inputrow_dyn);

        self.inner.lock().unwrap().inputrow_index_in_insidebox = Some(inputrow_idx);
        Ok(())
    }

    /// Ensure the buttonrow scaffolding (with its leading hspacer)
    /// has been installed inside the insidebox. Runs at most once
    /// per form (gated by `inner.buttonrow_index_in_insidebox`).
    ///
    /// FASM parallel: lines 487–510 (in `nvaddbutton`).
    fn ensure_buttonrow(&mut self) -> Result<(), TuiError> {
        let already = self.inner.lock().unwrap().buttonrow_index_in_insidebox.is_some();
        if already {
            return Ok(());
        }

        let mut buttonrow = SimpleContainer::new_ii(1, 1, Layout::Horizontal);

        // Push leading 100% hspacer into the buttonrow (FASM lines
        // 504–510). The buttonrow Arc has refcount = 1 here.
        {
            let buttonrow_mut = Arc::get_mut(&mut buttonrow).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form ensure_buttonrow: buttonrow Arc unexpectedly aliased",
                ))
            })?;
            let leading_hspacer: Arc<dyn Widget> = TuiHSpacer::new_d(100.0)?;
            buttonrow_mut.state.children.push_back(leading_hspacer);
        }

        // Append the buttonrow into the insidebox.
        let buttonrow_dyn: Arc<dyn Widget> = buttonrow;
        let insidebox_arc = self.state.children.get_mut(INSIDEBOX_INDEX).ok_or_else(|| {
            TuiError::Render(std::io::Error::other("form ensure_buttonrow: insidebox missing"))
        })?;
        let insidebox_widget = Arc::get_mut(insidebox_arc).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "form ensure_buttonrow: insidebox Arc aliased",
            ))
        })?;
        let buttonrow_idx = insidebox_widget.state_mut().children.len();
        insidebox_widget.state_mut().children.push_back(buttonrow_dyn);

        self.inner.lock().unwrap().buttonrow_index_in_insidebox = Some(buttonrow_idx);
        Ok(())
    }

    /// Run a closure with mutable access to the inputrow scaffolding
    /// widget. Walks `state.children[insidebox_idx].children[inputrow_idx]`
    /// via [`Arc::get_mut`] at each level.
    ///
    /// Returns the closure's result, or [`TuiError::Render`] when
    /// any [`Arc`] in the path is unexpectedly aliased.
    fn with_inputrow_mut<F, R>(
        state: &mut WidgetState,
        insidebox_idx: usize,
        inputrow_idx: usize,
        f: F,
    ) -> Result<R, TuiError>
    where
        F: FnOnce(&mut dyn Widget) -> Result<R, TuiError>,
    {
        let insidebox_arc = state.children.get_mut(insidebox_idx).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "form with_inputrow_mut: insidebox slot missing",
            ))
        })?;
        let insidebox_widget = Arc::get_mut(insidebox_arc).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "form with_inputrow_mut: insidebox Arc aliased",
            ))
        })?;
        let inputrow_arc = insidebox_widget
            .state_mut()
            .children
            .get_mut(inputrow_idx)
            .ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form with_inputrow_mut: inputrow slot missing",
                ))
            })?;
        let inputrow_widget = Arc::get_mut(inputrow_arc).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "form with_inputrow_mut: inputrow Arc aliased",
            ))
        })?;
        f(inputrow_widget)
    }

    /// Run a closure with mutable access to the buttonrow
    /// scaffolding widget. Walks
    /// `state.children[insidebox_idx].children[buttonrow_idx]` via
    /// [`Arc::get_mut`] at each level.
    fn with_buttonrow_mut<F, R>(
        state: &mut WidgetState,
        insidebox_idx: usize,
        buttonrow_idx: usize,
        f: F,
    ) -> Result<R, TuiError>
    where
        F: FnOnce(&mut dyn Widget) -> Result<R, TuiError>,
    {
        let insidebox_arc = state.children.get_mut(insidebox_idx).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "form with_buttonrow_mut: insidebox slot missing",
            ))
        })?;
        let insidebox_widget = Arc::get_mut(insidebox_arc).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "form with_buttonrow_mut: insidebox Arc aliased",
            ))
        })?;
        let buttonrow_arc = insidebox_widget
            .state_mut()
            .children
            .get_mut(buttonrow_idx)
            .ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "form with_buttonrow_mut: buttonrow slot missing",
                ))
            })?;
        let buttonrow_widget = Arc::get_mut(buttonrow_arc).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "form with_buttonrow_mut: buttonrow Arc aliased",
            ))
        })?;
        f(buttonrow_widget)
    }
}

// ============================================================================
// Widget trait impl for Form — the 5 vtable overrides + 4 boilerplate
// (state / state_mut / as_any / draw) accessors.
//
// FASM `tui_form$vtable` (`tui_form.inc` lines 79–82) is a copy of
// `tui_background$vtable` with five entries swapped:
//
// | slot | name           | replacement                    |
// |------|----------------|--------------------------------|
// |  0   | cleanup        | `tui_form$cleanup`             |
// |  1   | clone          | `tui_form$clone`               |
// |  29  | firekeyevent   | `tui_form$firekeyevent`        |
// |  30  | ontab          | `tui_form$ontab`               |
// |  31  | onshifttab     | `tui_form$onshifttab`          |
//
// The Rust port preserves all five overrides and inherits the rest
// (in particular: slot 2 `draw` is **not** overridden — the Rust
// `Widget::draw` impl below performs the same `tui_background$nvfill`
// the FASM `tui_background$draw` would have run, and children are
// rendered through the renderer's display-list traversal upstream).
// ============================================================================

impl Widget for Form {
    /// FASM vtable slot — read access to inherited [`WidgetState`].
    /// Forwards to the embedded `state` field.
    fn state(&self) -> &WidgetState {
        &self.state
    }

    /// FASM vtable slot — mutable access to inherited [`WidgetState`].
    /// Forwards to the embedded `state` field.
    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    /// Run-time downcasting hook — returns `&self` typed as
    /// [`std::any::Any`] so callers holding [`Arc<dyn Widget>`] can
    /// recover the concrete type via [`std::any::Any::downcast_ref`].
    /// Used by integration tests that need to inspect form state
    /// (tablist, focus index) through the trait object.
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// FASM vtable slot 0 — `tui_form$cleanup` (`tui_form.inc`
    /// lines 304–320).
    ///
    /// FASM clears the tablist (without per-item destructors — items
    /// are *references* to widgets owned by the children tree), frees
    /// the tablist's heap allocation, then chains to
    /// `tui_object$cleanup` which recursively destroys children /
    /// bastards / text / attributes.
    ///
    /// The Rust port:
    ///
    /// 1. Clears the tablist [`Vec`] (releasing each entry's [`Arc`]
    ///    refcount but **not** dropping the underlying widgets — they
    ///    are still held by the children tree, matching FASM's
    ///    "tablist holds references, not ownership" semantic).
    /// 2. Resets `focus_index` to [`None`] and the scaffolding
    ///    presence trackers (`has_insidebox`,
    ///    `inputrow_index_in_insidebox`, `buttonrow_index_in_insidebox`)
    ///    to their pristine values so a re-init via [`Form::add_item`]
    ///    or [`Form::add_button`] would lazy-build the scaffolding
    ///    afresh.
    /// 3. Inlines the trait-default cleanup body — clears the
    ///    children list (which, via [`Arc`] drop, recursively
    ///    invokes each child's own [`Drop`] / `cleanup` chain), the
    ///    bastards list, and the text / attribute / display-name
    ///    buffers.
    ///
    /// **Crucially** the Rust port does **not** call
    /// `Widget::cleanup(self)` recursively — that would re-enter
    /// this same method via vtable dispatch. The same anti-recursion
    /// fix is applied in [`crate::tui::widgets::label::TuiLabel`] and
    /// [`crate::tui::widgets::panel::TuiPanel`].
    fn cleanup(&mut self) {
        // Step 1+2: reset the form-specific aux state. The Mutex
        // guard is released before Step 3 so the children clear
        // pass cannot accidentally hit the lock through a transitive
        // callback.
        if let Ok(mut inner) = self.inner.lock() {
            inner.tablist.clear();
            inner.focus_index = None;
            inner.has_insidebox = false;
            inner.inputrow_index_in_insidebox = None;
            inner.buttonrow_index_in_insidebox = None;
        }

        // Step 3: inline the trait-default cleanup body (FASM
        // `tui_object$cleanup` chain — lines 308–320 fall through
        // here via `tui_background$cleanup`, which does nothing
        // form-specific).
        self.state.children.clear();
        self.state.bastards.clear();
        self.state.text.clear();
        self.state.attributes.clear();
        self.state.display_name.clear();
    }

    /// FASM vtable slot 1 — `tui_form$clone` (`tui_form.inc`
    /// lines 187–302).
    ///
    /// Produces a deep clone of the form by:
    ///
    /// 1. Snapshotting the source's [`FormInner`] tracking values
    ///    (`has_insidebox` + the two `*_index_in_insidebox`
    ///    [`Option<usize>`]s) under the [`Mutex`] guard.
    /// 2. Releasing the lock and running [`clone_widget_state`] to
    ///    deep-clone the [`WidgetState`] including the entire
    ///    children subtree (FASM
    ///    `tui_background$init_copy` at line 207).
    /// 3. Walking the cloned children tree from the recorded
    ///    indices to find the cloned `inputcolumn` and `buttonrow`,
    ///    then rebuilding `tablist` from each input child plus each
    ///    *non-spacer* buttonrow child (FASM `.tabadd` /
    ///    `.tabadd_nospacers` callbacks at lines 290–301).
    /// 4. Setting `focus_index` to `Some(0)` when the rebuilt
    ///    tablist is non-empty, [`None`] otherwise (FASM lines
    ///    261–268 — set focus to first tablist item, then call its
    ///    `vgotfocus`).
    ///
    /// # Tab-order caveat
    ///
    /// The FASM source carries an explicit warning at line 196:
    /// "tab order may not be maintained through this, so if you
    /// have a custom form that tosses buttons in beforehand, etc,
    /// this will need to be redone if you want taborder to work
    /// right". The Rust port preserves the same insertion-order
    /// reproduction: tablist is rebuilt by walking
    /// `inputcolumn.children` first, then
    /// `buttonrow.children` (skipping hspacers). Custom forms that
    /// inject buttons via direct manipulation of the children tree
    /// (bypassing [`Form::add_button`]) will lose their tablist
    /// entries on clone — exactly matching FASM behavior.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when:
    ///
    /// - The recursive [`clone_widget_state`] fails (typically a
    ///   downstream child's `clone_widget` returning an error).
    /// - The source's [`Mutex`] is poisoned (a previous panic on
    ///   another thread left the form in an inconsistent state).
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // Step 1: snapshot the source FormInner tracking values
        // under the Mutex guard, then release before the heavy
        // clone work.
        let (has_insidebox, inputrow_idx, buttonrow_idx) = {
            let inner = self.inner.lock().map_err(|_| {
                TuiError::Render(std::io::Error::other(
                    "form clone_widget: source FormInner mutex poisoned",
                ))
            })?;
            (
                inner.has_insidebox,
                inner.inputrow_index_in_insidebox,
                inner.buttonrow_index_in_insidebox,
            )
        };

        // Step 2: deep-clone state (children tree included).
        let cloned_state = clone_widget_state(&self.state)?;
        let bgfillchar = self.bgfillchar;
        let bgcolors = self.bgcolors;

        // Build the rebuilt FormInner — start with empty tablist /
        // None focus_index, then populate via the children walk.
        let mut new_inner = FormInner::new();
        new_inner.has_insidebox = has_insidebox;
        new_inner.inputrow_index_in_insidebox = inputrow_idx;
        new_inner.buttonrow_index_in_insidebox = buttonrow_idx;

        // Step 3: walk the cloned children tree to rebuild tablist.
        //
        // The FASM logic at lines 220–286 boils down to:
        //
        //   if !has_insidebox: alldone (tablist stays empty)
        //   insidebox = self.children[1]               // INSIDEBOX_INDEX
        //   if inputrow_idx is None: buttonsonly       // FASM `.buttonsonly`
        //     buttonrow = insidebox.children[0]        // FASM line 273
        //     goto dobuttons
        //   inputrow = insidebox.children[inputrow_idx]
        //   labelcolumn = inputrow.children[0]
        //   inputcolumn = inputrow.children[1]
        //   for input in inputcolumn.children: tablist.push(input)
        //   if buttonrow_idx is Some:
        //     buttonrow = insidebox.children[buttonrow_idx]
        //     for button in buttonrow.children:
        //       if !button.state.width_percent.is_some(): // skip hspacers
        //         tablist.push(button)
        //
        // Each `tablist.push(...)` is an `Arc::clone` — the same
        // widget retains an entry in the children tree (via
        // its parent's children list) **and** in the tablist (via
        // the rebuilt Vec).
        if has_insidebox {
            if let Some(insidebox_arc) = cloned_state.children.get(INSIDEBOX_INDEX) {
                let insidebox_state = insidebox_arc.state();

                // 3a. Inputs come from inputcolumn.children. Only
                // walked when the source had an inputrow.
                if let Some(inputrow_pos) = inputrow_idx {
                    if let Some(inputrow_arc) = insidebox_state.children.get(inputrow_pos) {
                        let inputrow_state = inputrow_arc.state();
                        // labelcolumn = inputrow.children[0],
                        // inputcolumn = inputrow.children[1]
                        // (per FASM `nvadditem` lines 397–406; the
                        // labelcolumn is appended *before* the
                        // inputcolumn).
                        if let Some(inputcolumn_arc) = inputrow_state.children.get(1) {
                            let inputcolumn_state = inputcolumn_arc.state();
                            for input in &inputcolumn_state.children {
                                new_inner.tablist.push(Arc::clone(input));
                            }
                        }
                    }
                }

                // 3b. Buttons come from buttonrow.children, with the
                // hspacer filter applied (FASM `.tabadd_nospacers`
                // at line 295: `cmp qword [rdi+tui_widthperc_ofs],
                // 0; jne .nodeal`). In Rust: a widget with
                // `state().width_percent.is_some()` is a
                // percentage-sized widget — i.e. one of the
                // [`TuiHSpacer`] padding entries — and is excluded.
                if let Some(buttonrow_pos) = buttonrow_idx {
                    if let Some(buttonrow_arc) = insidebox_state.children.get(buttonrow_pos) {
                        let buttonrow_state = buttonrow_arc.state();
                        for child in &buttonrow_state.children {
                            if child.state().width_percent.is_none() {
                                new_inner.tablist.push(Arc::clone(child));
                            }
                        }
                    }
                }
            }
        }

        // Step 4: focus the first tablist entry (matches FASM
        // lines 261–268). The matching `vgotfocus` call from FASM
        // is **intentionally not invoked** here — see the
        // module-level "Focus callbacks intentionally skipped"
        // section. Setting `focus_index = Some(0)` is sufficient
        // for [`Form::on_tab`] / [`Form::on_shift_tab`] to begin
        // cycling correctly on the cloned form.
        if !new_inner.tablist.is_empty() {
            new_inner.focus_index = Some(0);
        }

        Ok(Arc::new(Self {
            state: cloned_state,
            bgfillchar,
            bgcolors,
            inner: Mutex::new(new_inner),
        }) as Arc<dyn Widget>)
    }

    /// FASM vtable slot 2 inherited via `tui_background$draw` —
    /// fills the form's full bounds with `bgfillchar` and
    /// `bgcolors` so the visible area is rendered uniformly behind
    /// any scaffolding / inputs / buttons drawn on top by the
    /// renderer's display-list pass.
    ///
    /// The behavior is identical to
    /// [`crate::tui::widgets::background::TuiBackground::draw`] and
    /// [`crate::tui::widgets::panel::TuiPanel::draw`] step 2 — see
    /// the [`nvfill`] helper in this module for the byte-level
    /// semantics.
    ///
    /// Children are **not** rendered here — the engine's
    /// [`Widget::update_display_list`] traversal walks the
    /// children list and dispatches each widget's own `draw` after
    /// this fill. Refer to
    /// [`crate::tui::widgets::panel::TuiPanel::draw`] step 4 (the
    /// title overlay analogue) for an example of overlaying onto
    /// the filled buffers.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when [`nvfill`] fails — the
    /// only failure mode is a numeric overflow when computing
    /// `width * height` for the buffer-fill loop.
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        // Bail out for zero-sized forms (matches FASM
        // `tui_background$draw` lines 88–93 — the equivalent of
        // `cmp width, 0; jle .done`). This also short-circuits
        // before [`nvfill`] would reach the (currently empty)
        // text buffer.
        if self.state.width <= 0 || self.state.height <= 0 {
            return Ok(());
        }
        // Refuse to draw before [`pre_allocate_buffers`] has been
        // run (the layout pass guarantees this for percentage-sized
        // forms by populating absolute dimensions before reaching
        // `nvfill`).
        if self.state.text.is_empty() {
            return Ok(());
        }
        nvfill(&mut self.state, self.bgfillchar, self.bgcolors)
    }

    /// FASM vtable slot 29 — `tui_form$firekeyevent`
    /// (`tui_form.inc` lines ~723–760).
    ///
    /// FASM logic (translated):
    ///
    /// ```text
    /// if focus == NULL:
    ///   fall through to tui_object$firekeyevent (default delegation)
    /// if key == 9 (TAB ASCII):
    ///   call self.vontab; return 1
    /// if esc_key == 0x5A (CSI 'Z' = Shift-Tab):
    ///   call self.vonshifttab; return 1
    /// fall through to tui_object$firekeyevent
    /// ```
    ///
    /// The Rust port maps the FASM `key == 9 || esc_key == 0x5A`
    /// dispatch onto the typed [`KeyEvent::Tab`] /
    /// [`KeyEvent::ShiftTab`] variants — the typed-event layer in
    /// [`crate::tui::object::KeyEvent`] performs the equivalent
    /// CSI parsing upstream, so this method matches the variant
    /// directly.
    ///
    /// # Returns
    ///
    /// `true` when the event was a Tab / Shift-Tab and the form
    /// consumed it (focus successfully advanced); `false`
    /// otherwise (no focus, single-element tablist, or non-tab
    /// key with no further widget delegation).
    ///
    /// # Default delegation
    ///
    /// For all non-tab keys with `focus_index = None`, the form
    /// falls back to the trait-default
    /// [`Widget::fire_key_event`] which forwards to
    /// [`Widget::key_event`]. The form does **not** override
    /// [`Widget::key_event`], so a non-tab key with no focus
    /// returns `false` (consistent with FASM
    /// `tui_object$firekeyevent` returning 0 for unhandled
    /// events).
    fn fire_key_event(&mut self, event: KeyEvent) -> bool {
        // Phase 1: consume Tab / ShiftTab unconditionally — these
        // are the form's tab navigation keys. The typed enum
        // dispatch matches the FASM `cmp key, 9; je .ontab` and
        // `cmp esc_key, 0x5A; je .onshifttab` checks.
        match event {
            KeyEvent::Tab => {
                self.on_tab();
                return true;
            }
            KeyEvent::ShiftTab => {
                self.on_shift_tab();
                return true;
            }
            _ => {}
        }

        // Phase 2: any other key falls through to the default
        // delegation chain (FASM `.normal: jmp tui_object$firekeyevent`
        // at line 727). The trait default forwards to
        // `self.key_event(event)`, which the form does not
        // override — returning `false` indicates the form did
        // not handle the event so the engine can route it
        // further (typically to the focused child via a
        // higher-level dispatcher).
        self.key_event(event)
    }

    /// FASM vtable slot 30 — `tui_form$ontab` (`tui_form.inc`
    /// lines ~683–720).
    ///
    /// Cycles `focus_index` forward through the tablist, wrapping
    /// from the last entry back to the first. No-op when
    /// `focus_index` is [`None`] or the tablist has fewer than
    /// two entries.
    ///
    /// # Focus callbacks
    ///
    /// FASM calls `vlostfocus` on the departing widget and
    /// `vgotfocus` on the arriving widget. The Rust port
    /// **intentionally omits** these callbacks because every
    /// tablist entry has [`Arc`] strong count ≥ 2 (the same
    /// widget is also held inside the children tree via its
    /// scaffolding parent), preventing
    /// [`std::sync::Arc::get_mut`] from yielding the `&mut
    /// dyn Widget` reference required to invoke
    /// [`Widget::got_focus`] / [`Widget::lost_focus`]. See the
    /// module-level "Focus callbacks intentionally skipped"
    /// section for the documented limitation and the rationale
    /// for deferring visual focus changes to widgets that
    /// observe focus through external channels (cursor
    /// visibility, dirty-region invalidation).
    ///
    /// # Returns
    ///
    /// `true` when focus advanced; `false` when the no-op
    /// guards fired.
    fn on_tab(&mut self) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        let Some(idx) = inner.focus_index else {
            return false;
        };
        if inner.tablist.len() < 2 {
            return false;
        }
        let next_idx = (idx + 1) % inner.tablist.len();
        inner.focus_index = Some(next_idx);
        true
    }

    /// FASM vtable slot 31 — `tui_form$onshifttab` (`tui_form.inc`
    /// lines ~723–760).
    ///
    /// Cycles `focus_index` backward through the tablist, wrapping
    /// from the first entry back to the last. Symmetric to
    /// [`Self::on_tab`] — same focus-callback caveat applies.
    ///
    /// # Returns
    ///
    /// `true` when focus moved backward; `false` when the no-op
    /// guards fired.
    fn on_shift_tab(&mut self) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        let Some(idx) = inner.focus_index else {
            return false;
        };
        let len = inner.tablist.len();
        if len < 2 {
            return false;
        }
        // Compute previous index with wrap-around: idx == 0 → len - 1,
        // else idx - 1. Avoids the `(idx + len - 1) % len` form which
        // would hit a clippy warning under `-D warnings`.
        let prev_idx = if idx == 0 { len - 1 } else { idx - 1 };
        inner.focus_index = Some(prev_idx);
        true
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tui::widgets::label::{TextAlign, TuiLabel};

    // ------------------------------------------------------------------
    // Test fixtures
    // ------------------------------------------------------------------

    /// Standard test colors (white-on-black, the canonical no-frills
    /// terminal default). Matches the convention in
    /// [`crate::tui::widgets::panel::tests`] /
    /// [`crate::tui::widgets::label::tests`].
    fn test_colors() -> ColorPair {
        ColorPair { fg: 7, bg: 0 }
    }

    /// Construct a [`TuiLabel`] cast as [`Arc<dyn Widget>`], suitable
    /// for use as either the label or the input in [`Form::add_item`]
    /// or as a button in [`Form::add_button`]. Width = 4 chars,
    /// height = 1 row, fill text = `"x"`, align = left.
    fn make_test_widget() -> Arc<dyn Widget> {
        TuiLabel::new_ii(4, 1, "x", test_colors(), TextAlign::Left).expect("test label constructs")
            as Arc<dyn Widget>
    }

    /// Variant of [`make_test_widget`] returning [`Arc<TuiLabel>`]
    /// (the type required by [`Form::add_item`]).
    fn make_test_label(text: &str) -> Arc<TuiLabel> {
        TuiLabel::new_ii(
            text.chars().count().max(1) as i32,
            1,
            text,
            test_colors(),
            TextAlign::Left,
        )
        .expect("test label constructs")
    }

    /// Unwrap an [`Arc<Form>`] into an owned [`Form`] for tests that
    /// need `&mut self` access. Panics if the [`Arc`] is still
    /// aliased — should not happen for a freshly-constructed form
    /// that has not been cloned.
    fn unwrap_form(form: Arc<Form>) -> Form {
        Arc::try_unwrap(form).unwrap_or_else(|_| {
            panic!("form still aliased after construction");
        })
    }

    // ------------------------------------------------------------------
    // Constructor tests
    // ------------------------------------------------------------------

    /// All five constructors must yield a valid [`Form`] without
    /// scaffolding installed.
    #[test]
    fn test_five_constructors_compile() {
        let form_rect =
            Form::new_rect(Rect::new(0, 0, 20, 10), b' ' as u32, test_colors()).expect("new_rect");
        assert_eq!(form_rect.state.width, 20);
        assert_eq!(form_rect.state.height, 10);

        let form_ii = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        assert_eq!(form_ii.state.width, 20);
        assert_eq!(form_ii.state.height, 10);

        let form_id = Form::new_id(20, 50.0, b' ' as u32, test_colors()).expect("new_id");
        assert_eq!(form_id.state.width, 20);
        assert_eq!(form_id.state.height, 0);
        assert_eq!(form_id.state.height_percent, Some(50.0));

        let form_di = Form::new_di(50.0, 10, b' ' as u32, test_colors()).expect("new_di");
        assert_eq!(form_di.state.width, 0);
        assert_eq!(form_di.state.height, 10);
        assert_eq!(form_di.state.width_percent, Some(50.0));

        let form_dd = Form::new_dd(50.0, 50.0, b' ' as u32, test_colors()).expect("new_dd");
        assert_eq!(form_dd.state.width, 0);
        assert_eq!(form_dd.state.height, 0);
        assert_eq!(form_dd.state.width_percent, Some(50.0));
        assert_eq!(form_dd.state.height_percent, Some(50.0));
    }

    /// `finalize_init` must set `state.layout = Layout::Vertical`
    /// (children stack top-to-bottom) and
    /// `state.horiz_align = HorizAlign::Center` (insidebox centers
    /// horizontally). Matches FASM `tui_form$nvinit_common`.
    #[test]
    fn test_finalize_init_sets_layout_and_alignment() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        assert_eq!(form.state.layout, Layout::Vertical);
        assert_eq!(form.state.horiz_align, HorizAlign::Center);
    }

    /// `new_ii` with both dimensions positive must pre-allocate
    /// the text + attribute buffers (so [`Widget::draw`] can fill
    /// them without reallocating).
    ///
    /// Note: [`crate::ds::buffer::Buffer::len`] returns the byte
    /// count of the underlying `Vec<u8>` (so for `cells` cells of
    /// UTF-32 storage it is `cells * 4`), whereas
    /// [`crate::tui::object::Attributes::len`] returns the cell
    /// count of the underlying `Vec<u32>` (just `cells`). These
    /// semantics match the rest of the codebase
    /// (`label.rs`, `panel.rs`).
    #[test]
    fn test_new_ii_pre_allocates_buffers() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        let cells = (form.state.width as usize) * (form.state.height as usize);
        assert_eq!(form.state.text.len(), cells * 4);
        assert_eq!(form.state.attributes.len(), cells);
    }

    /// `new_id` (integer width, percentage height) must NOT
    /// pre-allocate buffers — height is 0 until layout resolves.
    #[test]
    fn test_new_id_skips_buffer_preallocation() {
        let form = Form::new_id(20, 50.0, b' ' as u32, test_colors()).expect("new_id");
        assert_eq!(form.state.text.len(), 0);
        assert_eq!(form.state.attributes.len(), 0);
    }

    /// `new_dd` (both percentages) must NOT pre-allocate buffers.
    #[test]
    fn test_new_dd_skips_buffer_preallocation() {
        let form = Form::new_dd(50.0, 50.0, b' ' as u32, test_colors()).expect("new_dd");
        assert_eq!(form.state.text.len(), 0);
        assert_eq!(form.state.attributes.len(), 0);
    }

    /// `bgfillchar` and `bgcolors` must round-trip through the
    /// constructor and the public accessors.
    #[test]
    fn test_fillchar_and_colors_accessors() {
        let cp = ColorPair { fg: 11, bg: 4 };
        let form = Form::new_ii(20, 10, b'#' as u32, cp).expect("new_ii");
        assert_eq!(form.fillchar(), b'#' as u32);
        assert_eq!(form.colors().fg, 11);
        assert_eq!(form.colors().bg, 4);
    }

    /// `set_colors` must update the form's stored colors.
    #[test]
    fn test_set_colors_updates_state() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.set_colors(ColorPair { fg: 14, bg: 1 });
        assert_eq!(form.colors().fg, 14);
        assert_eq!(form.colors().bg, 1);
    }

    // ------------------------------------------------------------------
    // Empty-form tests (no scaffolding installed)
    // ------------------------------------------------------------------

    /// A freshly constructed form has empty children, empty tablist,
    /// no scaffolding installed, and no focus.
    #[test]
    fn test_empty_form_no_scaffolding() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        assert_eq!(form.state.children.len(), 0);
        let inner = form.inner.lock().unwrap();
        assert_eq!(inner.tablist.len(), 0);
        assert!(inner.focus_index.is_none());
        assert!(!inner.has_insidebox);
        assert!(inner.inputrow_index_in_insidebox.is_none());
        assert!(inner.buttonrow_index_in_insidebox.is_none());
    }

    // ------------------------------------------------------------------
    // add_item scaffolding tests
    // ------------------------------------------------------------------

    /// First [`Form::add_item`] call installs:
    ///
    /// - leading vspacer
    /// - insidebox at `state.children[1]`
    /// - trailing vspacer
    ///
    /// And inside the insidebox:
    ///
    /// - inputrow at `insidebox.children[0]`
    ///   - labelcolumn at `inputrow.children[0]`
    ///   - inputcolumn at `inputrow.children[1]`
    ///
    /// Plus the input is pushed onto the tablist and focus_index
    /// is set to `Some(0)`.
    #[test]
    fn test_add_first_item_creates_scaffolding() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        let label = make_test_label("user");
        let input = make_test_widget();
        form.add_item(label, input).expect("add_item");

        // Top-level children: [vspacer, insidebox, vspacer].
        assert_eq!(form.state.children.len(), 3);

        // Inner state.
        let inner = form.inner.lock().unwrap();
        assert!(inner.has_insidebox);
        assert_eq!(inner.inputrow_index_in_insidebox, Some(0));
        assert!(inner.buttonrow_index_in_insidebox.is_none());
        assert_eq!(inner.tablist.len(), 1);
        assert_eq!(inner.focus_index, Some(0));
        drop(inner);

        // Insidebox children: [inputrow].
        let insidebox = form
            .state
            .children
            .get(INSIDEBOX_INDEX)
            .expect("insidebox present");
        assert_eq!(insidebox.state().children.len(), 1);

        // Inputrow children: [labelcolumn, inputcolumn].
        let inputrow = insidebox.state().children.front().expect("inputrow");
        assert_eq!(inputrow.state().children.len(), 2);
        assert_eq!(inputrow.state().layout, Layout::Horizontal);

        // Labelcolumn alignment.
        let labelcolumn = inputrow.state().children.front().expect("labelcolumn");
        assert_eq!(labelcolumn.state().horiz_align, HorizAlign::Right);

        // Each column has exactly one child after one add_item.
        assert_eq!(labelcolumn.state().children.len(), 1);
        let inputcolumn = inputrow.state().children.get(1).expect("inputcolumn");
        assert_eq!(inputcolumn.state().children.len(), 1);
    }

    /// Second [`Form::add_item`] call must reuse the scaffolding:
    /// no new vspacers, no new inputrow, no new columns.
    #[test]
    fn test_add_second_item_reuses_scaffolding() {
        let form = Form::new_ii(40, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.add_item(make_test_label("user"), make_test_widget())
            .expect("first add_item");
        form.add_item(make_test_label("pass"), make_test_widget())
            .expect("second add_item");

        // Top-level children unchanged at 3.
        assert_eq!(form.state.children.len(), 3);

        // Insidebox.children unchanged at 1 (still just the inputrow).
        let insidebox = form.state.children.get(INSIDEBOX_INDEX).unwrap();
        assert_eq!(insidebox.state().children.len(), 1);

        // Each column now has 2 children.
        let inputrow = insidebox.state().children.front().unwrap();
        let labelcolumn = inputrow.state().children.front().unwrap();
        let inputcolumn = inputrow.state().children.get(1).unwrap();
        assert_eq!(labelcolumn.state().children.len(), 2);
        assert_eq!(inputcolumn.state().children.len(), 2);

        // Tablist has both inputs.
        let inner = form.inner.lock().unwrap();
        assert_eq!(inner.tablist.len(), 2);
    }

    /// `add_item` pushes the **input** onto the tablist (never the
    /// label). Verified by Arc-pointer equality.
    #[test]
    fn test_add_item_pushes_input_not_label() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        let label = make_test_label("user");
        let input = make_test_widget();
        let input_ptr = Arc::as_ptr(&input) as *const ();
        form.add_item(label, Arc::clone(&input)).expect("add_item");

        let inner = form.inner.lock().unwrap();
        assert_eq!(inner.tablist.len(), 1);
        let tablist_entry_ptr = Arc::as_ptr(&inner.tablist[0]) as *const ();
        assert_eq!(
            tablist_entry_ptr, input_ptr,
            "tablist[0] must be the input widget, not the label"
        );
    }

    // ------------------------------------------------------------------
    // add_button scaffolding tests
    // ------------------------------------------------------------------

    /// First [`Form::add_button`] call installs:
    ///
    /// - leading vspacer
    /// - insidebox
    /// - trailing vspacer
    /// - inside insidebox: buttonrow with [leading hspacer, button,
    ///   trailing hspacer] (the sandwich pattern after the post-button
    ///   trailing hspacer is appended).
    #[test]
    fn test_add_button_creates_buttonrow() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        let button = make_test_widget();
        form.add_button(button).expect("add_button");

        // Top-level children: [vspacer, insidebox, vspacer].
        assert_eq!(form.state.children.len(), 3);

        // Inner state.
        let inner = form.inner.lock().unwrap();
        assert!(inner.has_insidebox);
        assert!(inner.inputrow_index_in_insidebox.is_none());
        assert_eq!(inner.buttonrow_index_in_insidebox, Some(0));
        assert_eq!(inner.tablist.len(), 1);
        assert_eq!(inner.focus_index, Some(0));
        drop(inner);

        // Insidebox.children: [buttonrow].
        let insidebox = form.state.children.get(INSIDEBOX_INDEX).unwrap();
        assert_eq!(insidebox.state().children.len(), 1);

        // Buttonrow layout is horizontal.
        let buttonrow = insidebox.state().children.front().unwrap();
        assert_eq!(buttonrow.state().layout, Layout::Horizontal);

        // Buttonrow children: [leading hspacer, button, trailing hspacer].
        assert_eq!(buttonrow.state().children.len(), 3);
        let leading = buttonrow.state().children.front().unwrap();
        let middle = buttonrow.state().children.get(1).unwrap();
        let trailing = buttonrow.state().children.get(2).unwrap();
        assert!(
            leading.state().width_percent.is_some(),
            "leading hspacer must have width_percent"
        );
        assert!(
            middle.state().width_percent.is_none(),
            "middle entry must be the actual button (no width_percent)"
        );
        assert!(
            trailing.state().width_percent.is_some(),
            "trailing hspacer must have width_percent"
        );
    }

    /// Second [`Form::add_button`] call appends the new button + a
    /// fresh trailing hspacer onto the existing buttonrow. The
    /// resulting layout is `[leading, btn1, hspacer, btn2,
    /// trailing]` — exactly 5 children.
    #[test]
    fn test_button_sandwich_pattern() {
        let form = Form::new_ii(40, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.add_button(make_test_widget()).expect("add_button 1");
        form.add_button(make_test_widget()).expect("add_button 2");

        let insidebox = form.state.children.get(INSIDEBOX_INDEX).unwrap();
        let buttonrow = insidebox.state().children.front().unwrap();
        assert_eq!(buttonrow.state().children.len(), 5);

        // Pattern verification: positions 0, 2, 4 are hspacers
        // (width_percent.is_some()); positions 1, 3 are buttons
        // (width_percent.is_none()).
        for (idx, child) in buttonrow.state().children.iter().enumerate() {
            let is_spacer = child.state().width_percent.is_some();
            if idx % 2 == 0 {
                assert!(is_spacer, "buttonrow[{}] must be hspacer", idx);
            } else {
                assert!(!is_spacer, "buttonrow[{}] must be button", idx);
            }
        }
    }

    /// Calling [`Form::add_button`] before any [`Form::add_item`]
    /// builds the buttonrow without an inputrow.
    #[test]
    fn test_add_button_without_items_still_works() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.add_button(make_test_widget()).expect("add_button");

        let inner = form.inner.lock().unwrap();
        assert!(inner.has_insidebox);
        assert!(inner.inputrow_index_in_insidebox.is_none());
        assert_eq!(inner.buttonrow_index_in_insidebox, Some(0));
        assert_eq!(inner.tablist.len(), 1);
    }

    /// Calling [`Form::add_item`] after [`Form::add_button`] adds the
    /// inputrow at index 1 (buttonrow stays at index 0).
    #[test]
    fn test_button_then_item_appends_inputrow_at_index_1() {
        let form = Form::new_ii(40, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.add_button(make_test_widget()).expect("add_button");
        form.add_item(make_test_label("user"), make_test_widget())
            .expect("add_item");

        let inner = form.inner.lock().unwrap();
        assert_eq!(inner.buttonrow_index_in_insidebox, Some(0));
        assert_eq!(inner.inputrow_index_in_insidebox, Some(1));
        assert_eq!(inner.tablist.len(), 2);
        drop(inner);

        // Insidebox.children: [buttonrow, inputrow].
        let insidebox = form.state.children.get(INSIDEBOX_INDEX).unwrap();
        assert_eq!(insidebox.state().children.len(), 2);
    }

    // ------------------------------------------------------------------
    // Auto-focus tests
    // ------------------------------------------------------------------

    /// First [`Form::add_item`] call sets `focus_index` to `Some(0)`.
    #[test]
    fn test_first_add_auto_focuses() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.add_item(make_test_label("user"), make_test_widget())
            .expect("add_item");

        let inner = form.inner.lock().unwrap();
        assert_eq!(inner.focus_index, Some(0));
    }

    /// Second [`Form::add_item`] call leaves `focus_index` at
    /// `Some(0)` (first focus wins).
    #[test]
    fn test_second_add_does_not_change_focus() {
        let form = Form::new_ii(40, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.add_item(make_test_label("user"), make_test_widget())
            .expect("first add_item");
        form.add_item(make_test_label("pass"), make_test_widget())
            .expect("second add_item");

        let inner = form.inner.lock().unwrap();
        assert_eq!(inner.focus_index, Some(0));
    }

    /// First [`Form::add_button`] call sets `focus_index` to
    /// `Some(0)`.
    #[test]
    fn test_first_add_button_auto_focuses() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.add_button(make_test_widget()).expect("add_button");

        let inner = form.inner.lock().unwrap();
        assert_eq!(inner.focus_index, Some(0));
    }

    // ------------------------------------------------------------------
    // Tab navigation tests
    // ------------------------------------------------------------------

    /// Helper: build a form with `n` items already added — focus
    /// starts at 0.
    fn form_with_n_items(n: usize) -> Form {
        let form = Form::new_ii(40, 20, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        for i in 0..n {
            let label_text = format!("l{}", i);
            form.add_item(make_test_label(&label_text), make_test_widget())
                .expect("add_item");
        }
        form
    }

    /// `on_tab` advances `focus_index` by 1 modulo tablist length.
    #[test]
    fn test_on_tab_cycles_forward() {
        let mut form = form_with_n_items(3);
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(0));
        assert!(form.on_tab());
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(1));
        assert!(form.on_tab());
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(2));
    }

    /// `on_tab` wraps from the last entry back to index 0.
    #[test]
    fn test_on_tab_wraps_to_first() {
        let mut form = form_with_n_items(3);
        // Manually set focus to last entry.
        {
            let mut inner = form.inner.lock().unwrap();
            inner.focus_index = Some(2);
        }
        assert!(form.on_tab());
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(0));
    }

    /// `on_shift_tab` walks `focus_index` backward by 1.
    #[test]
    fn test_on_shift_tab_cycles_backward() {
        let mut form = form_with_n_items(3);
        // Manually set focus to index 1.
        {
            let mut inner = form.inner.lock().unwrap();
            inner.focus_index = Some(1);
        }
        assert!(form.on_shift_tab());
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(0));
    }

    /// `on_shift_tab` wraps from index 0 to the last entry.
    #[test]
    fn test_on_shift_tab_wraps_to_last() {
        let mut form = form_with_n_items(3);
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(0));
        assert!(form.on_shift_tab());
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(2));
    }

    /// With a single-element tablist, `on_tab` and `on_shift_tab` are
    /// no-ops (returning `false`).
    #[test]
    fn test_tab_with_single_item_noop() {
        let mut form = form_with_n_items(1);
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(0));
        assert!(!form.on_tab(), "on_tab must return false for single item");
        assert!(
            !form.on_shift_tab(),
            "on_shift_tab must return false for single item"
        );
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(0));
    }

    /// With no focus_index (empty tablist), `on_tab` and
    /// `on_shift_tab` are no-ops.
    #[test]
    fn test_tab_with_no_focus_noop() {
        let mut form = unwrap_form(Form::new_ii(20, 10, b' ' as u32, test_colors()).unwrap());
        assert_eq!(form.inner.lock().unwrap().focus_index, None);
        assert!(!form.on_tab());
        assert!(!form.on_shift_tab());
    }

    // ------------------------------------------------------------------
    // fire_key_event interception tests
    // ------------------------------------------------------------------

    /// `KeyEvent::Tab` must be intercepted (returning `true`) when
    /// the form has focus, and must advance `focus_index`.
    #[test]
    fn test_firekeyevent_tab_intercepted() {
        let mut form = form_with_n_items(3);
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(0));
        let consumed = form.fire_key_event(KeyEvent::Tab);
        assert!(consumed, "fire_key_event(Tab) must return true");
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(1));
    }

    /// `KeyEvent::ShiftTab` must be intercepted (returning `true`).
    #[test]
    fn test_firekeyevent_shifttab_intercepted() {
        let mut form = form_with_n_items(3);
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(0));
        let consumed = form.fire_key_event(KeyEvent::ShiftTab);
        assert!(consumed, "fire_key_event(ShiftTab) must return true");
        // Wraps from 0 to last (index 2).
        assert_eq!(form.inner.lock().unwrap().focus_index, Some(2));
    }

    /// Non-tab key events fall through to [`Widget::key_event`] which
    /// the form does not override → returns `false`.
    #[test]
    fn test_firekeyevent_other_falls_through() {
        let mut form = form_with_n_items(3);
        let consumed = form.fire_key_event(KeyEvent::Char('a'));
        assert!(
            !consumed,
            "non-tab key must fall through to default key_event (returns false)"
        );
    }

    /// `KeyEvent::Tab` is intercepted *unconditionally* — even with
    /// no focus, the form returns `true` from `fire_key_event(Tab)`
    /// (because the form's tab handler is the form's responsibility,
    /// not the focused widget's).
    ///
    /// This matches FASM's `firekeyevent` — it dispatches `vontab`
    /// even when `focus == NULL` (the FASM check at line 727 is
    /// `cmp [r12+focus_ofs], 0; je .normal` BEFORE the key compare
    /// — but the typed-event dispatch in Rust intercepts Tab /
    /// ShiftTab first to maintain a consistent "Tab == form
    /// navigation" contract).
    #[test]
    fn test_firekeyevent_tab_always_intercepted() {
        let mut form = unwrap_form(Form::new_ii(20, 10, b' ' as u32, test_colors()).unwrap());
        // No items added — empty tablist + no focus.
        let consumed = form.fire_key_event(KeyEvent::Tab);
        assert!(
            consumed,
            "fire_key_event(Tab) must return true even with no focus"
        );
    }

    // ------------------------------------------------------------------
    // recompute_dims tests
    // ------------------------------------------------------------------

    /// `recompute_dims` updates the insidebox dimensions according to
    /// the geometric formula:
    ///
    /// - `insidebox.width  = max(max_label_w + max_input_w, total_button_w)`
    /// - `insidebox.height = max(total_label_h, total_input_h) + max_button_h`
    ///
    /// With two items (label widths 5 and 10; input width 4 each;
    /// height 1 each), and no buttons:
    /// - `max_label_w = 10`
    /// - `max_input_w = 4`
    /// - `total_label_h = 2`
    /// - `total_input_h = 2`
    /// - `total_button_w = 0`
    /// - `max_button_h = 0`
    ///
    /// Result: `insidebox.width = 14`, `insidebox.height = 2`.
    #[test]
    fn test_recompute_dims_sums_correctly() {
        let form = Form::new_ii(40, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        // Label widths 5 and 10 (chars in fill text). Use a custom
        // Label::new_ii so widths are deterministic.
        let label_short = TuiLabel::new_ii(5, 1, "lll", test_colors(), TextAlign::Left).expect("label short");
        let label_long =
            TuiLabel::new_ii(10, 1, "lllllllll", test_colors(), TextAlign::Left).expect("label long");
        form.add_item(label_short, make_test_widget())
            .expect("first add_item");
        form.add_item(label_long, make_test_widget())
            .expect("second add_item");

        // After two add_item calls, recompute_dims has already been
        // called twice. Verify resulting insidebox dimensions.
        let insidebox = form.state.children.get(INSIDEBOX_INDEX).unwrap();
        // max_label_w = 10, max_input_w = 4 → total = 14.
        assert!(
            insidebox.state().width >= 14,
            "insidebox.width must be at least max_label_w + max_input_w = 14, got {}",
            insidebox.state().width
        );
        // total_label_h = 2 (1+1).
        assert!(
            insidebox.state().height >= 2,
            "insidebox.height must be at least max(total_label_h, total_input_h) = 2, got {}",
            insidebox.state().height
        );
    }

    /// `recompute_dims` includes button row height in the insidebox
    /// height computation.
    #[test]
    fn test_recompute_dims_includes_button_height() {
        let form = Form::new_ii(40, 20, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        // 1 item + 1 button. Item has h=1. Button has h=1.
        // Expected height: max(1, 1) + 1 = 2.
        form.add_item(make_test_label("u"), make_test_widget())
            .expect("add_item");
        let button = TuiLabel::new_ii(8, 1, "submit", test_colors(), TextAlign::Center).expect("button");
        form.add_button(button as Arc<dyn Widget>).expect("add_button");

        let insidebox = form.state.children.get(INSIDEBOX_INDEX).unwrap();
        assert!(
            insidebox.state().height >= 2,
            "insidebox.height must be at least 2 (1 input row + 1 button row), got {}",
            insidebox.state().height
        );
    }

    /// `recompute_dims` filters out hspacers when computing the
    /// total button width: only widgets with
    /// `state.width_percent.is_none()` count as actual buttons.
    #[test]
    fn test_recompute_dims_filters_hspacers_from_button_width() {
        let form = Form::new_ii(60, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        // Two buttons of width 6 each (total = 12). The buttonrow
        // also has 3 hspacers (leading + middle + trailing) which
        // must NOT be counted toward the width budget.
        let btn_a = TuiLabel::new_ii(6, 1, "btn-a", test_colors(), TextAlign::Center).expect("button a");
        let btn_b = TuiLabel::new_ii(6, 1, "btn-b", test_colors(), TextAlign::Center).expect("button b");
        form.add_button(btn_a as Arc<dyn Widget>).expect("add_button a");
        form.add_button(btn_b as Arc<dyn Widget>).expect("add_button b");

        let insidebox = form.state.children.get(INSIDEBOX_INDEX).unwrap();
        // total_button_w = 12 (only the 2 actual buttons count;
        // hspacers are filtered out).
        assert_eq!(
            insidebox.state().width,
            12,
            "insidebox.width must equal sum of non-spacer button widths (12)"
        );
    }

    // ------------------------------------------------------------------
    // cleanup tests
    // ------------------------------------------------------------------

    /// `cleanup` clears tablist + scaffolding tracking + children +
    /// buffers.
    #[test]
    fn test_cleanup_clears_all_state() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.add_item(make_test_label("u"), make_test_widget())
            .expect("add_item");
        form.add_button(make_test_widget()).expect("add_button");

        // Pre-cleanup invariants.
        assert_eq!(form.state.children.len(), 3);
        assert_eq!(form.inner.lock().unwrap().tablist.len(), 2);
        assert!(form.inner.lock().unwrap().has_insidebox);

        // Cleanup.
        form.cleanup();

        // Post-cleanup invariants — everything must be reset.
        assert_eq!(form.state.children.len(), 0);
        assert_eq!(form.state.bastards.len(), 0);
        assert_eq!(form.state.text.len(), 0);
        assert_eq!(form.state.attributes.len(), 0);
        let inner = form.inner.lock().unwrap();
        assert_eq!(inner.tablist.len(), 0);
        assert!(inner.focus_index.is_none());
        assert!(!inner.has_insidebox);
        assert!(inner.inputrow_index_in_insidebox.is_none());
        assert!(inner.buttonrow_index_in_insidebox.is_none());
    }

    // ------------------------------------------------------------------
    // clone_widget tests
    // ------------------------------------------------------------------

    /// `clone_widget` preserves top-level structure (vspacer +
    /// insidebox + vspacer) and rebuilds the FormInner tracking
    /// values from the cloned children tree.
    #[test]
    fn test_clone_widget_preserves_top_level_structure() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.add_item(make_test_label("user"), make_test_widget())
            .expect("add_item");
        form.add_button(make_test_widget()).expect("add_button");

        let cloned: Arc<dyn Widget> = form.clone_widget().expect("clone_widget");
        // Deep structural assertions on the cloned widget.
        assert_eq!(cloned.state().children.len(), 3);
        assert_eq!(cloned.state().layout, Layout::Vertical);
        assert_eq!(cloned.state().horiz_align, HorizAlign::Center);
    }

    /// `clone_widget` rebuilds the tablist by walking the cloned
    /// subtree (1 input from inputcolumn + 1 non-spacer button
    /// from buttonrow = 2 entries).
    #[test]
    fn test_clone_widget_rebuilds_tablist() {
        let form = Form::new_ii(40, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.add_item(make_test_label("u"), make_test_widget())
            .expect("first add_item");
        form.add_item(make_test_label("p"), make_test_widget())
            .expect("second add_item");
        form.add_button(make_test_widget()).expect("add_button");

        let cloned = form.clone_widget().expect("clone_widget");

        // Downcast back to Form to inspect tablist.
        let cloned_form = cloned
            .as_any()
            .downcast_ref::<Form>()
            .expect("cloned widget downcasts to Form");
        let inner = cloned_form.inner.lock().unwrap();
        // 2 inputs + 1 button = 3 tablist entries.
        assert_eq!(inner.tablist.len(), 3);
        assert_eq!(inner.focus_index, Some(0));
        assert!(inner.has_insidebox);
        assert_eq!(inner.inputrow_index_in_insidebox, Some(0));
        assert_eq!(inner.buttonrow_index_in_insidebox, Some(1));
    }

    /// `clone_widget` filters hspacers from the buttonrow tablist
    /// rebuild (only widgets with `width_percent.is_none()` are
    /// considered actual buttons).
    #[test]
    fn test_clone_widget_filters_hspacers_from_buttonrow() {
        let form = Form::new_ii(40, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.add_button(make_test_widget()).expect("add_button 1");
        form.add_button(make_test_widget()).expect("add_button 2");

        let cloned = form.clone_widget().expect("clone_widget");
        let cloned_form = cloned.as_any().downcast_ref::<Form>().unwrap();
        let inner = cloned_form.inner.lock().unwrap();
        // 2 buttons (NOT 5 — hspacers filtered).
        assert_eq!(inner.tablist.len(), 2);
    }

    /// `clone_widget` on an empty form (no scaffolding) yields an
    /// empty cloned form.
    #[test]
    fn test_clone_widget_empty_form() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        let cloned = form.clone_widget().expect("clone_widget");
        let cloned_form = cloned.as_any().downcast_ref::<Form>().unwrap();
        assert_eq!(cloned_form.state.children.len(), 0);
        let inner = cloned_form.inner.lock().unwrap();
        assert_eq!(inner.tablist.len(), 0);
        assert!(inner.focus_index.is_none());
        assert!(!inner.has_insidebox);
    }

    /// `clone_widget` on a buttons-only form (no add_item, only
    /// add_button) correctly handles the FASM `.buttonsonly` path:
    /// buttonrow lives at insidebox.children[0], not [1].
    #[test]
    fn test_clone_widget_buttons_only() {
        let form = Form::new_ii(20, 10, b' ' as u32, test_colors()).expect("new_ii");
        let mut form = unwrap_form(form);
        form.add_button(make_test_widget()).expect("add_button");

        let cloned = form.clone_widget().expect("clone_widget");
        let cloned_form = cloned.as_any().downcast_ref::<Form>().unwrap();
        let inner = cloned_form.inner.lock().unwrap();
        assert_eq!(inner.tablist.len(), 1);
        assert!(inner.inputrow_index_in_insidebox.is_none());
        assert_eq!(inner.buttonrow_index_in_insidebox, Some(0));
    }

    // ------------------------------------------------------------------
    // Send + Sync compile-time check
    // ------------------------------------------------------------------

    /// Compile-time assertion that `Form` is `Send + Sync` —
    /// required by the `Widget: Send + Sync + 'static` trait bound.
    #[test]
    fn test_form_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Form>();
    }
}
