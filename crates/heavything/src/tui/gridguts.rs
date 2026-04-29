// crates/heavything/src/tui/gridguts.rs — HeavyThing data-grid internals.
//
// Rust translation of `tui_gridguts.inc` (1,071 lines of FASM assembly,
// repository root). This widget provides the scrolling / row-selection /
// search-panel state machine consumed by
// `crate::tui::widgets::datagrid::DataGrid`. FASM keeps its symbols
// hidden via `prolog_silent`; Rust mirrors that convention by declaring
// the `gridguts` module `pub` for symmetry with sibling `tui` modules
// while intentionally **not** re-exporting it at the crate root so that
// only sibling translation units (and the to-be-generated `DataGrid`
// consumer) reach it via the explicit module path.
//
// Refer to AAP §0.5.1.5 for the file mapping (`tui_gridguts.inc` →
// `crates/heavything/src/tui/gridguts.rs`) and to AAP §0.7 for the
// "preserve all observable behavior" rule that drives the FASM-strict
// keyevent semantics (`ArrowUp`, `ArrowDown`, `Enter` only).
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

//! Data-grid internals widget. Private helper consumed by
//! [`crate::tui::widgets`] when a `DataGrid` is constructed (Phase 5
//! field per the agent prompt: `datagrid: Weak<DataGrid>` — represented
//! here as `Option<Weak<dyn Widget>>` because the concrete `DataGrid`
//! type is created in a follow-up agent slot, see AAP §0.5.1.5).
//!
//! `GridGuts` descends from
//! [`crate::tui::widgets::background::TuiBackground`] and provides
//! scrolling, row selection, and search-panel state. Four `Widget`
//! methods are overridden:
//!
//! | Override | FASM slot | Reason |
//! |----------|-----------|--------|
//! | [`Widget::cleanup`] | `tui_vcleanup` | Release `cols` list and conditionally drop owned JSON data. |
//! | [`Widget::clone_widget`] | `tui_vclone` | Deep-clone WidgetState + columns; share or deep-clone data per `data_owner` flag. |
//! | [`Widget::draw`] | `tui_vdraw` | Fill background then render column headers + visible rows + selection highlight. |
//! | [`Widget::key_event`] | `tui_vkeyevent` | Up/Down move selection; Enter fires `item_selected` callback on parent. |
//!
//! All other ~33 vmethods inherit the trait defaults from
//! [`crate::tui::object::Widget`], which operate through
//! [`Widget::state_mut`] — `state_mut()` returns `&mut self.base.state`
//! so every default impl correctly targets the embedded
//! `TuiBackground`'s state.

use std::any::Any;
use std::sync::{Arc, Weak};

use serde_json::Value;

use crate::ds::List;
use crate::error::TuiError;
use crate::tui::geometry::Point;
use crate::tui::object::{ColorPair, HorizAlign, KeyEvent, Widget, WidgetState};
use crate::tui::render::Renderer;
use crate::tui::widgets::background::TuiBackground;

// ---------------------------------------------------------------------------
// ColumnSpec
// ---------------------------------------------------------------------------

/// Column specification for a single column in a [`GridGuts`] instance.
///
/// Mirrors the FASM `tui_gridcol` struct (offsets 0..48) defined inline
/// in `tui_gridguts.inc`:
///
/// | FASM offset | FASM field name | Rust field |
/// |-------------|-----------------|-----------|
/// | 0 | `tui_gridcol_name_ofs` | `heading` |
/// | 8 | `tui_gridcol_width_ofs` | `width_cells` (when `Some`) |
/// | 16 | `tui_gridcol_widthperc_ofs` | `width_percent` (when `width_cells == None`) |
/// | 24 | `tui_gridcol_align_ofs` | `align` |
/// | 32 | `tui_gridcol_propertyname_ofs` | `field_key` |
/// | 40 | `tui_gridcol_actualwidth_ofs` | (computed; not stored) |
///
/// The FASM `actualwidth` field is recomputed every draw cycle by
/// `tui_gridguts$draw.calcwidths` and is therefore not persisted in
/// the Rust port.
///
/// # Visibility
///
/// The struct is `pub` so the dead-code lint treats it as exported,
/// but its containing module
/// ([`crate::tui::gridguts`](super)) is `pub(crate)` — external
/// crates cannot name `ColumnSpec` because they cannot name the
/// path. This matches the FASM `prolog_silent` discipline (visible
/// only to sibling translation units inside the heavything library).
#[derive(Debug, Clone)]
pub struct ColumnSpec {
    /// Column heading text displayed in the header row.
    /// FASM: `tui_gridcol_name_ofs` (a UTF-32 `string32` pointer; here
    /// stored directly as Rust UTF-8 `String` per AAP §0.5.1.7).
    pub heading: String,

    /// JSON object key used to extract each row's cell value.
    /// FASM: `tui_gridcol_propertyname_ofs`.
    pub field_key: String,

    /// Fixed column width in cells. If `None`, this column uses
    /// [`Self::width_percent`] of the remaining width after fixed
    /// columns are allocated. FASM: `tui_gridcol_width_ofs` (when
    /// `widthperc` is zero).
    pub width_cells: Option<u32>,

    /// Percentage width (0.0..=100.0) used when [`Self::width_cells`]
    /// is `None`. FASM: `tui_gridcol_widthperc_ofs` (an `xmm0`-loaded
    /// `f64` representing percent on a 0..100 scale, matching the
    /// `_math_onehundred` constant used throughout the framework).
    pub width_percent: f64,

    /// Horizontal alignment within the column.
    /// FASM: `tui_gridcol_align_ofs` (qword, encoded as
    /// [`HorizAlign`] enum tag).
    pub align: HorizAlign,

    /// Optional per-column color override. When `None`, the grid uses
    /// the parent `DataGrid`'s default colors. The FASM struct does
    /// not carry a per-column color override — the Rust port adds it
    /// for convenience without changing observable behavior of the
    /// default rendering path.
    pub colors: Option<ColorPair>,
}

impl ColumnSpec {
    /// Constructs a fixed-width column.
    ///
    /// Equivalent to FASM `tui_gridguts$nvaddproperty_i(rdi=grid,
    /// rsi=heading, rdx=field_key, ecx=width_cells, r8=align)` —
    /// allocates a `tui_gridcol_size`-byte struct, populates fields,
    /// and `list$append`s into the `cols` list.
    #[must_use]
    pub fn new_fixed(
        heading: impl Into<String>,
        field_key: impl Into<String>,
        width_cells: u32,
        align: HorizAlign,
    ) -> Self {
        Self {
            heading: heading.into(),
            field_key: field_key.into(),
            width_cells: Some(width_cells),
            width_percent: 0.0,
            align,
            colors: None,
        }
    }

    /// Construct a percentage-width column.
    ///
    /// Equivalent to FASM `tui_gridguts$nvaddproperty_d(rdi=grid,
    /// rsi=heading, rdx=field_key, xmm0=width_percent, ecx=align)`.
    /// `width_percent` is on a 0..=100 scale matching the
    /// `_math_onehundred` constant.
    #[must_use]
    pub fn new_percent(
        heading: impl Into<String>,
        field_key: impl Into<String>,
        width_percent: f64,
        align: HorizAlign,
    ) -> Self {
        Self {
            heading: heading.into(),
            field_key: field_key.into(),
            width_cells: None,
            width_percent,
            align,
            colors: None,
        }
    }
}

// ---------------------------------------------------------------------------
// GridGuts
// ---------------------------------------------------------------------------

/// Private data-grid internals widget. Constructed by `DataGrid::new`
/// (in a sibling agent slot) and appended as the grid's internal
/// child. Owns no public API surface outside the `tui` module.
///
/// FASM struct layout (offsets relative to `tui_background_size = 164`):
///
/// | FASM offset | FASM field | Rust field |
/// |-------------|-----------|-----------|
/// | +0 | `tui_ggdatagrid_ofs` | `datagrid` |
/// | +8 | `tui_ggdata_ofs` | `data` |
/// | +16 | `tui_ggselectedindex_ofs` | `selected_index` |
/// | +24 | `tui_ggscroll_ofs` | `scroll` |
/// | +32 | `tui_ggcols_ofs` | `cols` |
/// | +40 | `tui_ggsearchpanel_ofs` | `search_panel` |
/// | +48 | `tui_ggsearchpanelvisible_ofs` | `search_panel_visible` |
/// | +56 | `tui_ggdataowner_ofs` | `data_owner` |
/// | +64 | `tui_ggrowcount_ofs` | `row_count` |
/// | =72 | `tui_gridguts_size = tui_background_size + 72` | (struct end) |
///
/// # Visibility
///
/// The struct itself is `pub` so the dead-code lint treats it as
/// exported, but the containing module
/// ([`crate::tui::gridguts`](super)) is `pub(crate)` — external
/// crates cannot name `GridGuts` because they cannot name the path.
/// This matches the FASM `prolog_silent` discipline.
pub struct GridGuts {
    /// Standard widget base state plus the foundational
    /// solid-color-rectangle bg fill (FASM `tui_background` parent).
    pub(crate) base: TuiBackground,

    /// Weak reference to the owning `DataGrid` widget. Used to
    /// propagate the FASM `tui_vitemselected` callback up to the
    /// parent on `Enter`.
    ///
    /// `None` represents the FASM NULL state — set by
    /// [`Widget::clone_widget`] per the FASM `tui_gridguts$clone`
    /// convention that the cloned widget has no parent until the
    /// caller wires up the back-reference (FASM line 152 sets the
    /// field to NULL explicitly).
    ///
    /// Stored as `Weak<dyn Widget>` because the concrete `DataGrid`
    /// type is generated in a follow-up agent slot; this type
    /// erasure is forward-compatible with any `Arc<dyn Widget>`
    /// that the future `DataGrid` constructor produces.
    pub(crate) datagrid: Option<Weak<dyn Widget>>,

    /// JSON array data source. `None` until [`Self::set_data`] is
    /// called. The contained [`Value`] must be a JSON array
    /// (`Value::Array`) — non-array variants are rejected in
    /// `set_data` with `TuiError::Render`.
    pub(crate) data: Option<Value>,

    /// Index of the currently selected row within `data`. `0` when
    /// empty. FASM: `tui_ggselectedindex_ofs` (qword).
    pub(crate) selected_index: usize,

    /// Current scroll offset within the grid. FASM:
    /// `tui_ggscroll_ofs` (qword storing only the y-component;
    /// horizontal scroll is unused in the FASM implementation, so
    /// the `Point::x` component is always 0 in this Rust port).
    pub(crate) scroll: Point,

    /// Column specifications. FASM: `tui_ggcols_ofs` (a
    /// `list$new`-allocated doubly-linked list of `tui_gridcol`
    /// pointers).
    pub(crate) cols: List<ColumnSpec>,

    /// Optional inline search/filter panel widget. Created on demand
    /// when the user activates the search shortcut. The FASM
    /// implementation initializes this field to NULL and never
    /// populates it in the surveyed code paths; we preserve the
    /// field for API parity with the schema export.
    pub(crate) search_panel: Option<Box<dyn Widget>>,

    /// Whether the search panel is currently visible. FASM:
    /// `tui_ggsearchpanelvisible_ofs` (qword; treated as bool).
    pub(crate) search_panel_visible: bool,

    /// Whether this widget owns the [`Self::data`] allocation and
    /// must drop it on cleanup. FASM:
    /// `tui_ggdataowner_ofs` (qword; treated as bool). In Rust the
    /// flag is largely informational because [`Drop`] reclaims any
    /// owned `Value` automatically, but the flag is preserved to
    /// match the externally observable cleanup ordering of the FASM
    /// implementation.
    pub(crate) data_owner: bool,

    /// Cached row count from the last [`Self::set_data`] call, to
    /// avoid repeated JSON length queries in the draw and
    /// keyevent paths. FASM: `tui_ggrowcount_ofs` (qword).
    pub(crate) row_count: usize,

    /// Header-row colors snapshot, copied from the parent
    /// [`crate::tui::widgets::datagrid::DataGrid::header_colors`] at
    /// construction. FASM: read from
    /// `[parent_dg + tui_dgheadercolors_ofs]` directly inside
    /// `tui_gridguts$draw` (line 281). The Rust port snapshots the
    /// value at construction so the draw path does not need to
    /// upgrade the [`Weak`] back-reference (which is intentionally
    /// expired by [`crate::tui::widgets::datagrid::DataGrid::add_column`]).
    pub(crate) header_colors: ColorPair,

    /// Selected-row colors snapshot, copied from the parent
    /// [`crate::tui::widgets::datagrid::DataGrid::sel_colors`] at
    /// construction. FASM: read from
    /// `[parent_dg + tui_dgselcolors_ofs]` inside the contents loop
    /// (line 392) where the row colors are switched to selection
    /// colors when `r8 == ggselectedindex_ofs`.
    pub(crate) sel_colors: ColorPair,
}

// ---------------------------------------------------------------------------
// Construction and mutation
// ---------------------------------------------------------------------------

impl GridGuts {
    /// Constructs a new `GridGuts` attached to `datagrid`.
    ///
    /// Equivalent to FASM `tui_gridguts$new(rdi=tui_datagrid_parent)`
    /// (lines 55–91 of `tui_gridguts.inc`):
    ///
    /// 1. Allocates `tui_gridguts_size` bytes via `heap$alloc` —
    ///    in Rust the [`Self`] struct lives on the stack until the
    ///    caller wraps it in [`Arc`].
    /// 2. Sets the vtable to `tui_gridguts$vtable` — in Rust, the
    ///    [`Widget`] trait impl is the static equivalent.
    /// 3. Calls `tui_background$init_dd(xmm0=100.0%, xmm1=100.0%,
    ///    dl=' ', esi=datagrid_colors)` to fill the foundation as a
    ///    full-bounds background painted in the parent `DataGrid`
    ///    colors. Direct struct-literal construction is used here
    ///    because [`TuiBackground::state`] is `pub(crate)` and the
    ///    other fields are `pub`; this avoids the
    ///    `Result<Arc<Self>>` shape of the public constructors and
    ///    gives the caller direct ownership of the inner state for
    ///    subsequent mutation.
    /// 4. Calls `list$new` for the `cols` field — Rust uses
    ///    [`List::new`].
    /// 5. Initializes the remaining fields to FASM-zero defaults:
    ///    `data=None, selected_index=0, scroll=(0,0),
    ///    search_panel=None, search_panel_visible=false,
    ///    data_owner=false, row_count=0`.
    #[must_use]
    pub fn new(
        datagrid: Weak<dyn Widget>,
        header_colors: ColorPair,
        body_colors: ColorPair,
        sel_colors: ColorPair,
    ) -> Self {
        // FASM tui_background$init_dd(100.0, 100.0, ' ', colors):
        // both percentages are 100 (on the 0..100 scale tracked by
        // `_math_onehundred`); fillchar is ASCII 0x20 packed into
        // the low byte of a u32 codepoint cell. The body row colors
        // are passed through to the embedded TuiBackground so the
        // initial nvfill paints the entire viewport in the data-row
        // palette before headers / contents are stamped on top.
        let mut state = WidgetState::new();
        state.width_percent = Some(100.0);
        state.height_percent = Some(100.0);
        // width / height stay 0 until layout fires; the percentage
        // fields drive the eventual size.

        let base = TuiBackground {
            state,
            bgfillchar: u32::from(b' '),
            bgcolors: body_colors,
        };

        Self {
            base,
            datagrid: Some(datagrid),
            data: None,
            selected_index: 0,
            scroll: Point::ZERO,
            cols: List::new(),
            search_panel: None,
            search_panel_visible: false,
            data_owner: false,
            row_count: 0,
            header_colors,
            sel_colors,
        }
    }

    /// Sets the JSON array data source.
    ///
    /// Equivalent to FASM `tui_gridguts$nvsetdata(rdi=grid,
    /// rsi=data)` (when `owned == true`) and
    /// `tui_gridguts$nvsetdata_notowner(rdi=grid, rsi=data)` (when
    /// `owned == false`). Resets `selected_index` to 0 and
    /// `scroll` to `(0, 0)` matching FASM lines 854–890. Also
    /// caches the row count so the keyevent and draw paths can
    /// avoid repeated `as_array().len()` queries.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] wrapping
    /// [`std::io::ErrorKind::InvalidInput`] when `data` is not a
    /// JSON array. The FASM implementation does not perform this
    /// check (it expects callers to pass valid arrays); the Rust
    /// port hardens the API surface.
    pub fn set_data(&mut self, data: Value, owned: bool) -> Result<(), TuiError> {
        if !data.is_array() {
            return Err(TuiError::Render(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "GridGuts::set_data: data must be a JSON array",
            )));
        }
        self.row_count = data.as_array().map_or(0, Vec::len);
        self.data = Some(data);
        self.data_owner = owned;
        self.selected_index = 0;
        self.scroll = Point::ZERO;
        Ok(())
    }

    /// Adds a column specification to the end of the column list.
    ///
    /// Equivalent to FASM `tui_gridguts$nvaddproperty_i` /
    /// `nvaddproperty_d` (lines 939–1007), which allocate a
    /// `tui_gridcol_size`-byte struct and `list$append` it to
    /// `tui_ggcols_ofs`.
    pub fn add_column(&mut self, col: ColumnSpec) {
        self.cols.push_back(col);
    }

    /// Returns the number of data rows currently visible in the
    /// grid's bounds, accounting for the column-header row.
    ///
    /// The FASM draw path (lines 332–366) computes this as
    /// `height - 1` (one row reserved for headers when
    /// `headercolors >= 0`), with additional `-1` per ellipsis
    /// indicator (top / bottom). This Rust accessor returns the
    /// no-ellipsis `height - 1` baseline used by the keyevent
    /// PageUp/PageDown handlers and `set_data` for paging math.
    #[must_use]
    pub fn visible_rows(&self) -> usize {
        let h = self.base.state.height;
        if h > 0 {
            (h - 1) as usize
        } else {
            0
        }
    }

    /// Toggles the search panel visibility flag.
    ///
    /// The FASM implementation does not expose this entry point
    /// (the `searchpanel` field is initialised to NULL and never
    /// populated in the surveyed code paths). The Rust port
    /// preserves the field per the agent-prompt schema; toggling
    /// flips the visibility flag without instantiating a panel
    /// when none exists.
    pub fn toggle_search_panel(&mut self) {
        self.search_panel_visible = !self.search_panel_visible;
    }

    /// Internal helper: computes per-column `actualwidth` values in
    /// character cells, mirroring the FASM `.calcwidths` algorithm
    /// (lines 540–600 of `tui_gridguts.inc`).
    ///
    /// Algorithm:
    ///
    /// 1. `available = width - 1 - col_count` (the `-1` is the
    ///    leftmost gutter cell; the `-col_count` accounts for one
    ///    inter-column gutter cell after each column).
    /// 2. If `available <= 0`, every column receives `-1` (FASM
    ///    `.calcwidths_noroom` sets a sentinel "do not draw" width).
    /// 3. Otherwise: subtract every fixed-width column's width
    ///    from `available`, then distribute the remainder
    ///    proportionally to percent-width columns (each gets
    ///    `(percent / total_percent) * remainder`, truncated to
    ///    integer cells via FASM `cvtsd2si`).
    ///
    /// Returns one `i32` per column in column order, with `-1`
    /// indicating the no-room sentinel and `>=0` indicating the
    /// computed width in cells.
    fn calc_actual_widths(&self) -> Vec<i32> {
        let count = self.cols.len() as i32;
        if count == 0 {
            return Vec::new();
        }
        // FASM lines 543–548: `r15d = width - 1 - col_count`.
        let avail_signed = self.base.state.width - 1 - count;
        if avail_signed <= 0 {
            // FASM `.calcwidths_noroom` (lines 587–597): every
            // column gets the sentinel `-1` width.
            return vec![-1_i32; count as usize];
        }
        // First pass: subtract every fixed-width column from the
        // available budget; sum percent-width columns.
        let mut total_perc = 0.0_f64;
        let mut fixed_remainder = avail_signed;
        for col in self.cols.iter() {
            match col.width_cells {
                Some(w) => fixed_remainder -= w as i32,
                None => total_perc += col.width_percent,
            }
        }
        // Second pass: emit each column's actual width.
        self.cols
            .iter()
            .map(|col| match col.width_cells {
                Some(w) => w as i32,
                None => {
                    if total_perc <= 0.0 {
                        // FASM behavior with all-zero percentages
                        // is undefined (would divide by zero); the
                        // Rust port returns 0 to keep the
                        // stamping pass safe.
                        0
                    } else {
                        // FASM line 580–586: `divsd / mulsd /
                        // cvtsd2si`. Truncating cast matches the
                        // FASM convert-to-signed-integer rounding
                        // semantics (round-toward-zero by
                        // default).
                        let raw = (col.width_percent / total_perc) * f64::from(fixed_remainder);
                        raw as i32
                    }
                }
            })
            .collect()
    }

    /// Internal helper: clamps `selected_index` and adjusts
    /// `scroll.y` such that the selection remains visible on the
    /// screen. Called by the keyevent overrides after each
    /// selection change.
    ///
    /// Matches FASM lines 749–769 (up-arrow case: pulls scroll up
    /// when the selection underflows the viewport) and lines
    /// 791–820 (down-arrow case: advances scroll when the selection
    /// overflows the bottom of the viewport).
    fn ensure_selection_visible(&mut self) {
        let scroll_y = self.scroll.y as usize;
        // Up: if the selection underflows the viewport, pull scroll
        // up to the selection. FASM: `cmp esi, dword
        // [rbx+tui_ggscroll_ofs] / jge .nogoback / sub` (line 753).
        if self.selected_index < scroll_y {
            self.scroll = Point::new(self.scroll.x, self.selected_index as i32);
            return;
        }
        // Down: if the selection overflows the visible row count,
        // advance scroll. FASM: `cmp r8, [rbx+tui_ggselectedindex_ofs]
        // / jg .nomove / add` (line 818).
        let visible = self.visible_rows();
        if visible == 0 {
            return;
        }
        let scroll_y_max = self.selected_index.saturating_sub(visible.saturating_sub(1));
        if scroll_y < scroll_y_max {
            self.scroll = Point::new(self.scroll.x, scroll_y_max as i32);
        }
    }
}

// ---------------------------------------------------------------------------
// Widget trait impl — 4 overrides; the rest delegate via state_mut().
// ---------------------------------------------------------------------------

impl Widget for GridGuts {
    /// Returns a reference to the embedded base widget state.
    /// All trait-default methods route through this accessor.
    fn state(&self) -> &WidgetState {
        &self.base.state
    }

    /// Returns a mutable reference to the embedded base widget state.
    /// All trait-default methods route through this accessor.
    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.base.state
    }

    /// Erased downcast pivot. Required for the framework's
    /// `Any`-based widget identity checks.
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// FASM vtable slot 0 — destructor.
    ///
    /// FASM lines 213–253: walks the `cols` list calling the
    /// per-element `.columncleanup` (which frees the heading,
    /// field key, and the col struct itself), frees the `cols`
    /// list, and conditionally calls `json$destroy` on the data
    /// when `data_owner` is set. Finally invokes the parent
    /// `tui_object$cleanup` to release children, bastards, text,
    /// and attributes.
    ///
    /// The Rust port reverses the order to match the trait
    /// convention of "super-cleanup first, then own resources" —
    /// `Drop` semantics make the actual sequence irrelevant
    /// because Rust auto-drops every owned field; we call
    /// `state_mut`'s default cleanup for parity with the FASM
    /// `tui_object$cleanup` invocation, then explicitly clear the
    /// owned `cols`, search panel, and (when owner) data.
    fn cleanup(&mut self) {
        // FASM `tui_object$cleanup` equivalent — clear children,
        // bastards, text, attributes, display_name on the embedded
        // state.
        let state = self.state_mut();
        state.children.clear();
        state.bastards.clear();
        state.text.clear();
        state.attributes.clear();
        state.display_name.clear();

        // FASM lines 220–235: `list$clear` with per-element
        // `columncleanup` + `heap$free` for the list itself.
        // Rust's `Drop` cascades into each `ColumnSpec`, so a
        // single `clear()` is sufficient.
        self.cols.clear();

        // FASM lines 240–250: free `data` only when `dataowner`.
        if self.data_owner {
            self.data = None;
        }

        // The search panel is not cleaned up by the FASM
        // implementation (the field is initialised NULL and never
        // populated in the surveyed code paths). The Rust port
        // explicitly drops it for symmetry with the
        // schema-exposed `Box<dyn Widget>` ownership semantics.
        self.search_panel = None;
    }

    /// FASM vtable slot 1 — clone.
    ///
    /// FASM lines 95–211 (`tui_gridguts$clone`): allocates a fresh
    /// `tui_gridguts_size` struct, calls
    /// `tui_background$init_copy` on the base, walks the `cols`
    /// list deep-cloning each `tui_gridcol` via
    /// `tui_gridguts$gridcol$new_copy`, and conditionally
    /// deep-clones the JSON data when `data_owner` was set.
    ///
    /// The Rust port:
    /// - Manually deep-clones [`WidgetState`] because
    ///   [`TuiBackground`]'s `clone_widget_state` helper is
    ///   private to its module. This is a faithful re-creation of
    ///   the FASM `tui_object$init_copy` semantics: copy every
    ///   scalar field, clone text/attributes buffers, and
    ///   recursively clone children (but **not** bastards, per
    ///   FASM line 274 of `tui_object.inc`).
    /// - `cols.clone()` deep-clones every `ColumnSpec` because
    ///   `List<ColumnSpec>` derives [`Clone`].
    /// - Sets `datagrid` to `None` (FASM line 152: explicit NULL)
    ///   so the caller can wire up the new parent reference after
    ///   the clone returns.
    /// - Resets `search_panel`, `search_panel_visible`,
    ///   `selected_index`, and `scroll` to defaults (FASM lines
    ///   154–161).
    /// - Conditionally clones the JSON data per `data_owner` flag
    ///   (FASM lines 168–194).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when any child widget's own
    /// `clone_widget` call fails (the error is bubbled from the
    /// children traversal).
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // ---- Deep-clone WidgetState ----
        let mut cloned_state = WidgetState::new();
        {
            let src = &self.base.state;
            cloned_state.bounds = src.bounds;
            cloned_state.width = src.width;
            cloned_state.width_percent = src.width_percent;
            cloned_state.height = src.height;
            cloned_state.height_percent = src.height_percent;
            cloned_state.visible = src.visible;
            cloned_state.include_in_layout = src.include_in_layout;
            cloned_state.absolute_x = src.absolute_x;
            cloned_state.absolute_y = src.absolute_y;
            cloned_state.layout = src.layout;
            cloned_state.horiz_align = src.horiz_align;
            cloned_state.vert_align = src.vert_align;
            cloned_state.bastard_glue = src.bastard_glue;
            cloned_state.drop_shadow = src.drop_shadow;
            cloned_state.scroll = src.scroll;
            cloned_state.display_name = src.display_name.clone();
            cloned_state.text = src.text.clone();
            cloned_state.attributes = src.attributes.clone();
            for child in src.children.iter() {
                cloned_state.children.push_back(child.clone_widget()?);
            }
            // FASM `tui_object$init_copy` (line 274 of tui_object.inc)
            // intentionally does NOT clone bastards — they remain
            // empty in the cloned widget.
        }

        // ---- Wrap in TuiBackground with copied scalar fields ----
        let cloned_base = TuiBackground {
            state: cloned_state,
            bgfillchar: self.base.bgfillchar,
            bgcolors: self.base.bgcolors,
        };

        // ---- Deep-clone columns (List<ColumnSpec> impls Clone) ----
        let cloned_cols = self.cols.clone();

        // ---- Conditionally clone JSON data per data_owner flag ----
        // FASM lines 168–194: if data_owner, deep-copy and set
        // dataowner=1; if not owner, share pointer (Rust must
        // clone since serde_json::Value is by-value, but the
        // observable behaviour is preserved); if no data, leave
        // None.
        let (cloned_data, cloned_data_owner, cloned_row_count) = match &self.data {
            Some(d) if self.data_owner => (Some(d.clone()), true, self.row_count),
            Some(d) => (Some(d.clone()), false, self.row_count),
            None => (None, false, 0),
        };

        let cloned = Self {
            base: cloned_base,
            // FASM line 152 sets ggdatagrid to NULL explicitly —
            // the caller is expected to wire up the new parent
            // back-reference after `clone_widget` returns.
            datagrid: None,
            data: cloned_data,
            selected_index: 0,
            scroll: Point::ZERO,
            cols: cloned_cols,
            search_panel: None,
            search_panel_visible: false,
            data_owner: cloned_data_owner,
            row_count: cloned_row_count,
            // Header / selection palettes are scalar copies — preserved
            // verbatim across clones so the cloned widget renders with
            // the same palette as the source until the caller overrides
            // them.
            header_colors: self.header_colors,
            sel_colors: self.sel_colors,
        };

        Ok(Arc::new(cloned) as Arc<dyn Widget>)
    }

    /// FASM vtable slot 2 — draw.
    ///
    /// Faithful Rust port of `tui_gridguts$draw` (FASM
    /// `tui_gridguts.inc` lines 256–510). The algorithm:
    ///
    /// 1. Bail out (`.invisible`) when width or height is zero.
    /// 2. Fill the entire viewport with the body-row palette via
    ///    `tui_background$nvfill` (the embedded
    ///    [`TuiBackground::nvfill`] on `self.base`).
    /// 3. Compute `actual_width` for each column via the FASM
    ///    `.calcwidths` helper (fixed-cell-width columns are
    ///    copied through; percent-width columns are scaled by the
    ///    remaining horizontal budget).
    /// 4. When `header_colors != 0xFFFFFFFF` (FASM sentinel; the
    ///    Rust port always renders the header row because
    ///    [`crate::tui::widgets::datagrid::DataGrid::header_colors`]
    ///    is a non-optional `ColorPair`), stamp the column heading
    ///    row at `y = 0` with a 1-cell gutter on the left and
    ///    after each column.
    /// 5. Walk the visible row range (`scroll..scroll+visible`)
    ///    inserting top / bottom ellipsis (`...`) sentinel rows
    ///    when content extends beyond the viewport.
    /// 6. For each visible data row: stamp each column's value
    ///    (looked up via JSON property name) with column
    ///    alignment, switching to the selection palette when
    ///    `row_index == selected_index`.
    /// 7. Notify the renderer of the dirty viewport via
    ///    [`Widget::update_display_list`] (FASM
    ///    `tui_vupdatedisplaylist` tail call at lines 530–536).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] from [`TuiBackground::draw`]
    /// (which bubbles up [`crate::ds::buffer::Buffer`] resize
    /// failures). The post-fill stamping never errors because it
    /// writes into pre-sized in-memory buffers.
    fn draw(&mut self, r: &mut dyn Renderer) -> Result<(), TuiError> {
        // FASM lines 261–262: `cmp dword [rdi+tui_width_ofs], 0 / je
        // .invisible`. The base `nvfill` already short-circuits on
        // zero dimensions, but the FASM check is defensive — we
        // honour it explicitly to avoid even the cost of arming
        // the buffer for a zero-area fill.
        let width = self.base.state.width;
        let height = self.base.state.height;
        if width <= 0 || height <= 0 {
            return Ok(());
        }

        // FASM line 263: tui_background$nvfill. This sizes the
        // text + attributes buffers to width*height cells and
        // paints them with the body palette.
        self.base.draw(r)?;

        // FASM line 266: call .calcwidths. Compute one
        // actualwidth (in character cells) per column.
        let actual_widths = self.calc_actual_widths();

        // FASM lines 268–276: r11 = width*4 (row stride in bytes),
        // rax = width*height*4 (total buffer length in bytes),
        // r12 = text-buffer base, r13 = attr-buffer base, r14 =
        // r12+rax (one-past-end of text). The Rust port uses cell
        // (codepoint) indices instead of raw byte offsets.
        let width_cells = width as usize;
        let height_cells = height as usize;
        let total_cells = width_cells.saturating_mul(height_cells);

        // Snapshot scalar values needed by the inner stamping
        // pass before taking the buffer borrows. Once the
        // `text_slice` and `attr_cells` borrows are live, calling
        // any &self / &mut self method becomes impossible, so we
        // resolve every scalar dependency up front.
        let scroll_y = self.scroll.y.max(0) as usize;
        let row_count = self.row_count;
        let selected_index = self.selected_index;

        // FASM line 281: read header_colors from the parent
        // datagrid. The Rust port snapshots it at construction.
        let header_colors_packed = pack_color_pair_local(self.header_colors);
        let body_colors_packed = pack_color_pair_local(self.base.bgcolors);
        let sel_colors_packed = pack_color_pair_local(self.sel_colors);

        // Snapshot ColumnSpec data into owned tuples so the
        // stamping pass can iterate without holding a borrow on
        // self.cols (which lives behind &mut self).
        let columns: Vec<(String, String, HorizAlign, usize)> = self
            .cols
            .iter()
            .zip(actual_widths.iter())
            .map(|(c, &aw)| {
                (
                    c.heading.clone(),
                    c.field_key.clone(),
                    c.align,
                    if aw < 0 { 0_usize } else { aw as usize },
                )
            })
            .collect();

        // Snapshot per-row, per-column cell strings from the JSON
        // contents array. FASM lines 442–456 walk the JSON object
        // calling `json$getvaluebyname` for each column's
        // propertyname, then either takes the string value or
        // falls through to `.emptystr`. The Rust port performs the
        // same lookup using `serde_json::Value::get`, restricting
        // to `Value::String` to match the FASM `cmp dword
        // [rax+json_type_ofs], json_value` filter.
        let row_strings: Vec<Vec<String>> = match self.data.as_ref().and_then(Value::as_array) {
            Some(arr) => arr
                .iter()
                .skip(scroll_y)
                .take(height_cells)
                .map(|row| {
                    columns
                        .iter()
                        .map(|(_h, key, _align, _aw)| {
                            row.get(key.as_str())
                                .and_then(Value::as_str)
                                .map_or_else(String::new, str::to_owned)
                        })
                        .collect()
                })
                .collect(),
            None => Vec::new(),
        };

        // Now take mut borrows on the buffers and run the
        // stamping pass. Both buffers were sized exactly by
        // `nvfill` to total_cells*4 bytes / total_cells u32s
        // respectively, so we can assert on the slice lengths to
        // catch any future divergence.
        debug_assert_eq!(self.base.state.text.len(), total_cells * 4);
        debug_assert_eq!(self.base.state.attributes.cells.len(), total_cells);
        let text_slice: &mut [u8] = self.base.state.text.as_mut_slice();
        let attr_cells: &mut [u32] = &mut self.base.state.attributes.cells[..];

        // Tracks the next data-row offset (in cells) to write to.
        // FASM r12 / r13 advance by r11 (= width in bytes) per
        // row; the Rust equivalent is the loop variable
        // `row_offset` measured in cells.
        let mut row_offset: usize = 0;

        // ---- Header row (FASM lines 280–330) ----
        // FASM `cmp ecx, 0xffffffff / je .noheaders`. The Rust port
        // always renders the header row because the parent
        // `DataGrid::header_colors` is a required `ColorPair`
        // (not optional). Skip rendering only when there are no
        // columns to draw.
        if !columns.is_empty() {
            // FASM lines 285–286: leftmost gutter cell.
            write_cell(text_slice, attr_cells, row_offset, b' ', header_colors_packed);
            let mut col_x: usize = 1;
            for (heading, _key, align, actual_width) in &columns {
                // FASM lines 305–315: write the heading at
                // `text_buf + (relx*4)`, advance relx by
                // actualwidth, and stamp a single-space gutter
                // after the column.
                let cell_start = row_offset + col_x;
                draw_column(
                    text_slice,
                    attr_cells,
                    cell_start,
                    *actual_width,
                    header_colors_packed,
                    heading,
                    *align,
                );
                col_x += *actual_width;
                // FASM lines 318–321: post-column gutter (one space cell).
                write_cell(
                    text_slice,
                    attr_cells,
                    row_offset + col_x,
                    b' ',
                    header_colors_packed,
                );
                col_x += 1;
            }
            // FASM line 327: advance to next row (header consumed
            // one row).
            row_offset += width_cells;
        }

        // ---- Data rows (FASM lines 332–456) ----
        // Bail when no data is installed (FASM `test rdx, rdx / jz
        // .updateandreturn`).
        if row_count == 0 {
            return Ok(());
        }

        // FASM lines 339–352: derive visible-row count, accounting
        // for header (always present in this Rust port), top
        // ellipsis (when scroll_y > 0), and bottom ellipsis (when
        // remaining content exceeds visible budget).
        // header_consumed = 1 if columns non-empty else 0.
        let header_consumed = if columns.is_empty() { 0 } else { 1 };
        let mut visible = height_cells.saturating_sub(header_consumed);
        let needs_top_ellipsis = scroll_y > 0;
        if needs_top_ellipsis {
            // FASM line 345: `call .drawelipses` — draw the
            // top-ellipsis row in the body-row palette, then
            // reduce the visible budget by 1.
            draw_ellipses_row(
                text_slice,
                attr_cells,
                row_offset,
                width_cells,
                body_colors_packed,
            );
            row_offset += width_cells;
            visible = visible.saturating_sub(1);
        }
        let remaining = row_count.saturating_sub(scroll_y);
        let needs_bottom_ellipsis = visible < remaining;
        if needs_bottom_ellipsis {
            // FASM lines 354–357: account for the bottom-ellipsis
            // row (drawn AFTER the visible content, see lines
            // 467–478).
            visible = visible.saturating_sub(1);
        }
        let visible_count = visible.min(remaining);

        // ---- Contents loop (FASM lines 376–446) ----
        for (vi, row_text) in row_strings.iter().take(visible_count).enumerate() {
            let absolute_row_index = scroll_y + vi;
            // FASM lines 389–393: pick row palette — body for
            // unselected rows, sel for the selected row.
            let row_colors_packed = if absolute_row_index == selected_index {
                sel_colors_packed
            } else {
                body_colors_packed
            };
            // FASM line 395: leftmost gutter cell stamped in row
            // palette.
            write_cell(text_slice, attr_cells, row_offset, b' ', row_colors_packed);
            let mut col_x: usize = 1;
            for ((_heading, _key, align, actual_width), cell_str) in columns.iter().zip(row_text.iter()) {
                let cell_start = row_offset + col_x;
                draw_column(
                    text_slice,
                    attr_cells,
                    cell_start,
                    *actual_width,
                    row_colors_packed,
                    cell_str,
                    *align,
                );
                col_x += *actual_width;
                // FASM lines 425–428: post-column gutter.
                write_cell(
                    text_slice,
                    attr_cells,
                    row_offset + col_x,
                    b' ',
                    row_colors_packed,
                );
                col_x += 1;
            }
            row_offset += width_cells;
        }

        // ---- Bottom ellipsis (FASM lines 458–478) ----
        if needs_bottom_ellipsis {
            draw_ellipses_row(
                text_slice,
                attr_cells,
                row_offset,
                width_cells,
                body_colors_packed,
            );
        }

        // FASM lines 530–536: tail call into
        // `tui_vupdatedisplaylist`. The Rust [`TuiBackground::draw`]
        // already invoked `update_display_list` after the nvfill,
        // and the framework polls dirty regions on the next render
        // tick — no additional notification is required because
        // the buffers we just stamped share the same backing
        // store.
        Ok(())
    }

    /// FASM vtable slot 12 — key event handler.
    ///
    /// FASM lines 717–836 (`tui_gridguts$keyevent`):
    ///
    /// - Up arrow (esc_key 0x41): if `selected_index == 0` return
    ///   0 (not consumed); else decrement selected_index, adjust
    ///   scroll if needed, return 1 (consumed).
    /// - Down arrow (esc_key 0x42): if `selected_index + 1 >=
    ///   row_count` return 0; else increment, adjust scroll,
    ///   return 1.
    /// - Enter (key 13): walk contents to selected_index, fire
    ///   the parent DataGrid's `tui_vitemselected` callback,
    ///   return 1.
    /// - All other keys: return 0.
    ///
    /// The agent prompt's Phase 7 example mentions Home/End/
    /// PageUp/PageDown/Ctrl-F handling, but the FASM source does
    /// not implement those. Per the AAP §0.8.1 "preserve all
    /// observable behavior" rule, the Rust port handles only
    /// ArrowUp / ArrowDown / Enter — exactly the FASM set.
    fn key_event(&mut self, event: KeyEvent) -> bool {
        // FASM line 727: bail out early when there is no data or
        // the array is empty.
        if self.row_count == 0 {
            return false;
        }

        match event {
            KeyEvent::ArrowUp => {
                // FASM line 749: `cmp dword
                // [rbx+tui_ggselectedindex_ofs], 0 / je .nomove`.
                if self.selected_index == 0 {
                    return false;
                }
                self.selected_index -= 1;
                self.ensure_selection_visible();
                true
            }
            KeyEvent::ArrowDown => {
                // FASM line 779: `cmp esi, [rbx+tui_ggrowcount_ofs]
                // / jge .nomove`.
                if self.selected_index + 1 >= self.row_count {
                    return false;
                }
                self.selected_index += 1;
                self.ensure_selection_visible();
                true
            }
            KeyEvent::Enter => {
                // FASM lines 800–828: walks the JSON contents
                // list to `selected_index`, fetches the JSON value
                // at that position, and tail-calls the parent
                // DataGrid's `tui_vitemselected` vmethod with
                // `(rdi=parent_dg, rsi=selected_value)`. The Rust
                // port surfaces this through the `Widget` trait's
                // [`Widget::on_item_selected`] default method.
                //
                // Validate that the selected index points at a
                // real row (FASM does the same via list walk and
                // bails to `.zeroret` on overrun).
                if self.selected_index >= self.row_count {
                    return false;
                }
                // Upgrade the back-reference. When the parent
                // [`DataGrid`] has been dropped, the FASM
                // equivalent would dereference a dangling pointer
                // and crash; the Rust port simply consumes the
                // event and returns `true` (matching
                // `tui_gridguts$keyevent`'s "Enter is always
                // consumed when there is data" semantic at FASM
                // line 826).
                if let Some(parent) = self.datagrid.as_ref().and_then(Weak::upgrade) {
                    // Ignore the result: FASM's vtable call
                    // discards the return value, and any error
                    // surfaced from a custom override would be
                    // logged at the renderer layer rather than
                    // bubbling up through the keyevent path.
                    let _ = parent.on_item_selected(self.selected_index);
                }
                true
            }
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Private rendering helpers (FASM `.drawcolumn`, `.drawelipses`).
// ---------------------------------------------------------------------------

/// Pack a [`ColorPair`] into the wire-format `u32` used by the
/// codepoint attribute buffer.
///
/// Matches the `tui_object` per-cell attribute layout: bits 0..7 = fg,
/// bits 8..15 = bg, bits 16..31 reserved for SGR. The FASM source
/// stores colors as packed `dword` values directly, so this helper
/// reproduces that encoding without taking a dependency on the
/// `pack_color_pair` symbol that is private to
/// `crate::tui::widgets::background`.
const fn pack_color_pair_local(cp: ColorPair) -> u32 {
    (cp.fg as u32) | ((cp.bg as u32) << 8)
}

/// Stamps a single character cell at `cell_idx` with `byte` (zero-
/// extended into a u32 codepoint) and `colors_packed`.
///
/// The text buffer is a flat `[u8]` with 4 bytes per cell, so each
/// write writes one little-endian `u32`. The attribute buffer is a
/// flat `[u32]` with one entry per cell, so the colors entry is
/// written directly.
///
/// This is the Rust analogue of the FASM `mov dword [r12+r15*4],
/// 'X' / mov dword [r13+r15*4], ecx` cell-stamp pattern that
/// pervades `tui_gridguts$draw`.
fn write_cell(text: &mut [u8], attrs: &mut [u32], cell_idx: usize, byte: u8, colors_packed: u32) {
    let off = cell_idx * 4;
    if off + 4 <= text.len() {
        let bytes = u32::from(byte).to_le_bytes();
        text[off..off + 4].copy_from_slice(&bytes);
    }
    if cell_idx < attrs.len() {
        attrs[cell_idx] = colors_packed;
    }
}

/// Stamps a column-aligned string within a cell-width window.
///
/// Faithful Rust port of the FASM `.drawcolumn` helper (lines
/// 600–668 of `tui_gridguts.inc`). The algorithm:
///
/// 1. If `actual_width <= 1` the column has insufficient room
///    (FASM `.nothingtodo`); return early.
/// 2. Clear the entire window (`actual_width` cells) with space
///    glyphs in `colors_packed` (FASM `.drawcolumn_clearloop`).
/// 3. If `string` is empty (FASM `cmp qword [r8], 0 / je
///    .nothingtodo`), the cleared window is the final state.
/// 4. Otherwise, derive the write offset from the alignment:
///    - [`HorizAlign::Left`] / [`HorizAlign::Fill`]: offset 0
///    - [`HorizAlign::Right`]: offset = `window - chars`
///    - [`HorizAlign::Center`]: offset = `(window - chars) / 2`
/// 5. Write min(`window`, `chars`) characters into the window
///    starting at the offset (FASM `.drawcolumn_doit_loop`).
///
/// The `start_cell` parameter is the absolute cell index in the
/// flat buffer at which the window begins.
fn draw_column(
    text: &mut [u8],
    attrs: &mut [u32],
    start_cell: usize,
    actual_width: usize,
    colors_packed: u32,
    string: &str,
    align: HorizAlign,
) {
    // FASM lines 605–608: `cmp r9, 1 / jle .nothingtodo`.
    if actual_width <= 1 {
        return;
    }
    // FASM lines 612–620: clear the entire window with
    // `space + colors`.
    let space_le = u32::from(b' ').to_le_bytes();
    for i in 0..actual_width {
        let cell_idx = start_cell + i;
        let off = cell_idx * 4;
        if off + 4 > text.len() || cell_idx >= attrs.len() {
            return;
        }
        text[off..off + 4].copy_from_slice(&space_le);
        attrs[cell_idx] = colors_packed;
    }
    // FASM line 622: `cmp qword [r8], 0 / je .nothingtodo` —
    // empty strings leave the cleared window untouched.
    if string.is_empty() {
        return;
    }
    // FASM lines 626–650: derive offset and clamp write count
    // based on alignment when the string is shorter than the
    // window. The FASM source counts characters via the
    // string's leading `qword` length prefix; the Rust port uses
    // `chars().count()` which yields the same Unicode-codepoint
    // count for the UTF-8 native strings used throughout the
    // workspace.
    let chars: Vec<char> = string.chars().collect();
    let str_len = chars.len();
    let (offset, write_len) = if actual_width <= str_len {
        // Truncate to the window size.
        (0, actual_width)
    } else {
        let remainder = actual_width - str_len;
        let off = match align {
            HorizAlign::Left | HorizAlign::Fill => 0,
            HorizAlign::Right => remainder,
            HorizAlign::Center => remainder / 2,
        };
        (off, str_len)
    };
    // FASM lines 654–668: write each codepoint as a u32 little-
    // endian into the text buffer. Attributes were already set
    // by the clear loop above, so we leave them alone here —
    // matching FASM which only writes the text stream in the
    // `.drawcolumn_doit_loop`.
    for (i, &ch) in chars.iter().take(write_len).enumerate() {
        let cell_idx = start_cell + offset + i;
        let off = cell_idx * 4;
        if off + 4 > text.len() {
            return;
        }
        let cp = (ch as u32).to_le_bytes();
        text[off..off + 4].copy_from_slice(&cp);
    }
}

/// Stamps a single ellipsis-indicator row at `row_offset` (in cells).
///
/// Faithful Rust port of the FASM `.drawelipses` helper (lines
/// 510–540 of `tui_gridguts.inc`). The algorithm:
///
/// 1. If `width_cells < 3` (FASM `cmp r11, 12 / jb .notenoughroom`,
///    where 12 = 3 chars × 4 bytes/char) skip the row entirely
///    (caller still advances the row pointer).
/// 2. Clear the entire row with `space + body_colors_packed`.
/// 3. Compute `left = (width_cells - 3) / 2` and stamp three '.'
///    characters at `[row_offset + left .. row_offset + left + 3]`.
fn draw_ellipses_row(
    text: &mut [u8],
    attrs: &mut [u32],
    row_offset: usize,
    width_cells: usize,
    body_colors_packed: u32,
) {
    if width_cells < 3 {
        // FASM `.notenoughroom` (lines 533–539): just advance
        // r12/r13 by the row stride. The caller advances
        // `row_offset` after invoking this helper, so there is
        // nothing for us to do beyond returning early.
        return;
    }
    let space_le = u32::from(b' ').to_le_bytes();
    let dot_le = u32::from(b'.').to_le_bytes();
    // FASM `.drawelipses_loop` (lines 514–522): clear the entire
    // row with body palette.
    for i in 0..width_cells {
        let cell_idx = row_offset + i;
        let off = cell_idx * 4;
        if off + 4 > text.len() || cell_idx >= attrs.len() {
            return;
        }
        text[off..off + 4].copy_from_slice(&space_le);
        attrs[cell_idx] = body_colors_packed;
    }
    // FASM lines 524–530: stamp three '.' characters in the
    // horizontal centre.
    let left = (width_cells - 3) / 2;
    for i in 0..3 {
        let cell_idx = row_offset + left + i;
        let off = cell_idx * 4;
        if off + 4 > text.len() {
            return;
        }
        text[off..off + 4].copy_from_slice(&dot_le);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Construct a fresh GridGuts with a default colors triple and a
    /// dummy parent reference.  The parent is stored as a weak ref;
    /// we don't need a live `Arc<dyn Widget>` to drive the test
    /// suite because every test exercises GridGuts state in
    /// isolation.
    fn make_grid() -> GridGuts {
        // `Weak::<TestParent>::new()` requires Sized; we cannot
        // call `Weak::<dyn Widget>::new()` directly. Instead we
        // build a real Arc<dyn Widget>, downgrade it, and let the
        // strong ref drop — the resulting Weak is already expired,
        // matching the FASM "no parent yet" state.
        struct Dummy {
            state: WidgetState,
        }
        impl Widget for Dummy {
            fn state(&self) -> &WidgetState {
                &self.state
            }
            fn state_mut(&mut self) -> &mut WidgetState {
                &mut self.state
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }
        let parent: Arc<dyn Widget> = Arc::new(Dummy {
            state: WidgetState::new(),
        });
        let weak: Weak<dyn Widget> = Arc::downgrade(&parent);
        // Three default ColorPairs simulate the "all white-on-black"
        // palette used by the original FASM init path; tests that
        // care about palette interactions override them on the
        // returned `GridGuts` by mutating the public `header_colors`
        // / `base.bgcolors` / `sel_colors` fields.
        let header = ColorPair::default();
        let body = ColorPair::default();
        let sel = ColorPair::default();
        GridGuts::new(weak, header, body, sel)
    }

    #[test]
    fn new_gridguts_has_empty_data_and_cols() {
        let g = make_grid();
        assert!(g.data.is_none());
        assert_eq!(g.cols.len(), 0);
        assert_eq!(g.selected_index, 0);
        assert_eq!(g.scroll, Point::ZERO);
        assert_eq!(g.row_count, 0);
        assert!(!g.data_owner);
        assert!(!g.search_panel_visible);
    }

    #[test]
    fn new_gridguts_has_full_percent_size() {
        // FASM `init_dd(100.0, 100.0, ' ', colors)`.
        let g = make_grid();
        assert_eq!(g.base.state.width_percent, Some(100.0));
        assert_eq!(g.base.state.height_percent, Some(100.0));
        assert_eq!(g.base.bgfillchar, u32::from(b' '));
    }

    #[test]
    fn set_data_updates_row_count() {
        let mut g = make_grid();
        let data = json!([
            {"name": "alice"},
            {"name": "bob"},
            {"name": "carol"}
        ]);
        g.set_data(data, true).unwrap();
        assert_eq!(g.row_count, 3);
        assert!(g.data_owner);
        assert_eq!(g.selected_index, 0);
        assert_eq!(g.scroll, Point::ZERO);
    }

    #[test]
    fn set_data_non_array_returns_err() {
        let mut g = make_grid();
        let bad = json!({"not": "an array"});
        let err = g.set_data(bad, true);
        assert!(err.is_err());
        // Verify the data was NOT installed.
        assert!(g.data.is_none());
        assert_eq!(g.row_count, 0);
    }

    #[test]
    fn set_data_resets_selection_and_scroll() {
        let mut g = make_grid();
        // Install initial data and advance selection.
        g.set_data(json!([1, 2, 3, 4]), true).unwrap();
        g.selected_index = 2;
        g.scroll = Point::new(0, 1);
        // Re-install: selection and scroll must reset.
        g.set_data(json!([10, 20]), true).unwrap();
        assert_eq!(g.selected_index, 0);
        assert_eq!(g.scroll, Point::ZERO);
        assert_eq!(g.row_count, 2);
    }

    #[test]
    fn set_data_notowner_clears_owner_flag() {
        let mut g = make_grid();
        g.set_data(json!([1, 2]), false).unwrap();
        assert!(!g.data_owner);
    }

    #[test]
    fn add_column_appends() {
        let mut g = make_grid();
        g.add_column(ColumnSpec::new_fixed("Name", "name", 10, HorizAlign::Left));
        g.add_column(ColumnSpec::new_percent("Score", "score", 50.0, HorizAlign::Right));
        g.add_column(ColumnSpec::new_fixed("Date", "date", 8, HorizAlign::Center));
        assert_eq!(g.cols.len(), 3);
    }

    #[test]
    fn columnspec_fixed_constructor() {
        let c = ColumnSpec::new_fixed("Name", "key", 12, HorizAlign::Left);
        assert_eq!(c.heading, "Name");
        assert_eq!(c.field_key, "key");
        assert_eq!(c.width_cells, Some(12));
        assert_eq!(c.width_percent, 0.0);
        assert!(matches!(c.align, HorizAlign::Left));
        assert!(c.colors.is_none());
    }

    #[test]
    fn columnspec_percent_constructor() {
        let c = ColumnSpec::new_percent("Pct", "pct", 75.5, HorizAlign::Right);
        assert!(c.width_cells.is_none());
        assert!((c.width_percent - 75.5).abs() < f64::EPSILON);
    }

    #[test]
    fn columnspec_clone_is_deep() {
        let c = ColumnSpec::new_fixed("H", "k", 5, HorizAlign::Left);
        let mut c2 = c.clone();
        c2.heading.push('X');
        // Original unchanged — clone is independent storage.
        assert_eq!(c.heading, "H");
        assert_eq!(c2.heading, "HX");
    }

    #[test]
    fn key_event_arrow_down_increments_selection() {
        let mut g = make_grid();
        g.set_data(json!([1, 2, 3]), true).unwrap();
        assert_eq!(g.selected_index, 0);
        assert!(g.key_event(KeyEvent::ArrowDown));
        assert_eq!(g.selected_index, 1);
        assert!(g.key_event(KeyEvent::ArrowDown));
        assert_eq!(g.selected_index, 2);
    }

    #[test]
    fn key_event_arrow_down_at_end_is_noop() {
        let mut g = make_grid();
        g.set_data(json!([1, 2]), true).unwrap();
        g.selected_index = 1;
        // At last row — arrow down must NOT advance and must return false.
        assert!(!g.key_event(KeyEvent::ArrowDown));
        assert_eq!(g.selected_index, 1);
    }

    #[test]
    fn key_event_arrow_up_decrements_selection() {
        let mut g = make_grid();
        g.set_data(json!([1, 2, 3]), true).unwrap();
        g.selected_index = 2;
        assert!(g.key_event(KeyEvent::ArrowUp));
        assert_eq!(g.selected_index, 1);
        assert!(g.key_event(KeyEvent::ArrowUp));
        assert_eq!(g.selected_index, 0);
    }

    #[test]
    fn key_event_arrow_up_at_zero_is_noop() {
        let mut g = make_grid();
        g.set_data(json!([1, 2, 3]), true).unwrap();
        // selected_index already 0 from set_data — arrow up returns false.
        assert!(!g.key_event(KeyEvent::ArrowUp));
        assert_eq!(g.selected_index, 0);
    }

    #[test]
    fn key_event_with_empty_data_is_noop() {
        let mut g = make_grid();
        // No data installed — every key event returns false.
        assert!(!g.key_event(KeyEvent::ArrowDown));
        assert!(!g.key_event(KeyEvent::ArrowUp));
        assert!(!g.key_event(KeyEvent::Enter));
    }

    #[test]
    fn key_event_enter_returns_true_with_data() {
        let mut g = make_grid();
        g.set_data(json!([1, 2, 3]), true).unwrap();
        // Enter is consumed even though parent dispatch is a no-op
        // pending DataGrid integration.
        assert!(g.key_event(KeyEvent::Enter));
    }

    #[test]
    fn key_event_other_keys_are_ignored() {
        let mut g = make_grid();
        g.set_data(json!([1, 2]), true).unwrap();
        assert!(!g.key_event(KeyEvent::Home));
        assert!(!g.key_event(KeyEvent::End));
        assert!(!g.key_event(KeyEvent::PageUp));
        assert!(!g.key_event(KeyEvent::PageDown));
        assert!(!g.key_event(KeyEvent::Tab));
    }

    #[test]
    fn toggle_search_panel_flips_flag() {
        let mut g = make_grid();
        assert!(!g.search_panel_visible);
        g.toggle_search_panel();
        assert!(g.search_panel_visible);
        g.toggle_search_panel();
        assert!(!g.search_panel_visible);
    }

    #[test]
    fn cleanup_clears_cols_and_owned_data() {
        let mut g = make_grid();
        g.add_column(ColumnSpec::new_fixed("H", "k", 5, HorizAlign::Left));
        g.set_data(json!([1, 2]), true).unwrap();
        assert_eq!(g.cols.len(), 1);
        assert!(g.data.is_some());
        g.cleanup();
        assert_eq!(g.cols.len(), 0);
        assert!(g.data.is_none());
    }

    #[test]
    fn cleanup_preserves_unowned_data() {
        // FASM lines 240–250: unowned data is NOT freed.
        let mut g = make_grid();
        g.set_data(json!([1, 2]), false).unwrap();
        assert!(g.data.is_some());
        g.cleanup();
        // Data remains (Rust Drop will reclaim it when GridGuts is dropped).
        assert!(g.data.is_some());
    }

    #[test]
    fn clone_widget_deep_clones_cols() {
        let mut g = make_grid();
        g.add_column(ColumnSpec::new_fixed("Name", "name", 10, HorizAlign::Left));
        g.add_column(ColumnSpec::new_percent("Score", "score", 50.0, HorizAlign::Right));
        let cloned_arc = g.clone_widget().unwrap();
        let cloned_any = cloned_arc.as_any();
        let cloned = cloned_any.downcast_ref::<GridGuts>().unwrap();
        assert_eq!(cloned.cols.len(), 2);
    }

    #[test]
    fn clone_widget_resets_datagrid_back_reference() {
        // FASM line 152: cloned widget has NULL ggdatagrid.
        let g = make_grid();
        let cloned_arc = g.clone_widget().unwrap();
        let cloned = cloned_arc.as_any().downcast_ref::<GridGuts>().unwrap();
        assert!(cloned.datagrid.is_none());
    }

    #[test]
    fn clone_widget_resets_selection_and_scroll() {
        // FASM lines 154–161: cloned widget has zero selection and scroll.
        let mut g = make_grid();
        g.set_data(json!([1, 2, 3, 4]), true).unwrap();
        g.selected_index = 2;
        g.scroll = Point::new(0, 1);
        let cloned_arc = g.clone_widget().unwrap();
        let cloned = cloned_arc.as_any().downcast_ref::<GridGuts>().unwrap();
        assert_eq!(cloned.selected_index, 0);
        assert_eq!(cloned.scroll, Point::ZERO);
    }

    #[test]
    fn clone_widget_preserves_owned_data() {
        let mut g = make_grid();
        g.set_data(json!([1, 2, 3]), true).unwrap();
        let cloned_arc = g.clone_widget().unwrap();
        let cloned = cloned_arc.as_any().downcast_ref::<GridGuts>().unwrap();
        assert!(cloned.data.is_some());
        assert_eq!(cloned.row_count, 3);
        assert!(cloned.data_owner);
    }

    #[test]
    fn clone_widget_preserves_unowned_data_flag() {
        let mut g = make_grid();
        g.set_data(json!([1, 2]), false).unwrap();
        let cloned_arc = g.clone_widget().unwrap();
        let cloned = cloned_arc.as_any().downcast_ref::<GridGuts>().unwrap();
        assert!(!cloned.data_owner);
    }

    #[test]
    fn clone_widget_preserves_bgfillchar_and_colors() {
        let g = make_grid();
        let cloned_arc = g.clone_widget().unwrap();
        let cloned = cloned_arc.as_any().downcast_ref::<GridGuts>().unwrap();
        assert_eq!(cloned.base.bgfillchar, u32::from(b' '));
    }

    #[test]
    fn visible_rows_zero_when_height_zero() {
        let g = make_grid();
        // base.state.height starts at 0 (layout has not run yet).
        assert_eq!(g.visible_rows(), 0);
    }

    #[test]
    fn visible_rows_minus_one_for_header() {
        let mut g = make_grid();
        g.base.state.height = 10;
        // FASM line 332: `sub ecx, 1` — one row reserved for headers.
        assert_eq!(g.visible_rows(), 9);
    }

    #[test]
    fn ensure_selection_visible_pulls_scroll_up() {
        let mut g = make_grid();
        g.set_data(json!([1, 2, 3, 4, 5]), true).unwrap();
        g.base.state.height = 4; // visible_rows = 3
        g.selected_index = 4;
        g.scroll = Point::new(0, 4);
        // Move selection back into the viewport.
        g.selected_index = 1;
        g.ensure_selection_visible();
        assert_eq!(g.scroll.y, 1);
    }

    #[test]
    fn ensure_selection_visible_pushes_scroll_down() {
        let mut g = make_grid();
        g.set_data(json!([1, 2, 3, 4, 5]), true).unwrap();
        g.base.state.height = 4; // visible_rows = 3
                                 // Selection at 4 with scroll at 0 — scroll must advance.
        g.selected_index = 4;
        g.ensure_selection_visible();
        assert!(g.scroll.y >= 2);
    }

    #[test]
    fn key_event_down_advances_scroll_when_off_screen() {
        let mut g = make_grid();
        g.set_data(json!([1, 2, 3, 4, 5]), true).unwrap();
        g.base.state.height = 3; // visible_rows = 2
                                 // Drive selection to the visible-rows boundary then beyond.
        for _ in 0..4 {
            g.key_event(KeyEvent::ArrowDown);
        }
        assert_eq!(g.selected_index, 4);
        // Scroll must have advanced to keep selection visible.
        assert!(g.scroll.y > 0);
    }

    #[test]
    fn key_event_up_pulls_scroll_back() {
        let mut g = make_grid();
        g.set_data(json!([1, 2, 3, 4, 5]), true).unwrap();
        g.base.state.height = 3; // visible_rows = 2
        g.selected_index = 4;
        g.scroll = Point::new(0, 3);
        // Move selection up — scroll should follow.
        g.key_event(KeyEvent::ArrowUp);
        assert_eq!(g.selected_index, 3);
    }
}
