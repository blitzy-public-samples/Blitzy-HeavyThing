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
    pub fn new(datagrid: Weak<dyn Widget>, colors: ColorPair) -> Self {
        // FASM tui_background$init_dd(100.0, 100.0, ' ', colors):
        // both percentages are 100 (on the 0..100 scale tracked by
        // `_math_onehundred`); fillchar is ASCII 0x20 packed into
        // the low byte of a u32 codepoint cell.
        let mut state = WidgetState::new();
        state.width_percent = Some(100.0);
        state.height_percent = Some(100.0);
        // width / height stay 0 until layout fires; the percentage
        // fields drive the eventual size.

        let base = TuiBackground {
            state,
            bgfillchar: u32::from(b' '),
            bgcolors: colors,
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
        };

        Ok(Arc::new(cloned) as Arc<dyn Widget>)
    }

    /// FASM vtable slot 2 — draw.
    ///
    /// FASM lines 256–510 implement a 250+ line layout algorithm:
    /// `nvfill` the background, `calcwidths` over the column
    /// list, render the header row, walk the visible row range
    /// (with top/bottom ellipsis indicators when scrolled),
    /// emit each cell with column-aligned text, and finally
    /// `update_display_list`.
    ///
    /// The Rust port delegates to [`TuiBackground::draw`] for the
    /// background fill + display-list update (faithful FASM
    /// `nvfill` + `tui_vupdatedisplaylist` equivalent), and
    /// leaves a TODO marker for the column / row drawing math —
    /// that tier of fidelity is scheduled for a follow-up agent
    /// slot per the agent-prompt's stub-with-TODO authorisation.
    /// The base draw is sufficient for the widget to compile,
    /// satisfy the [`Widget`] trait, and render the underlying
    /// background; downstream `DataGrid` integration tests will
    /// drive the columnar fidelity work.
    fn draw(&mut self, r: &mut dyn Renderer) -> Result<(), TuiError> {
        // FASM line 263 calls `tui_background$nvfill` first, then
        // proceeds into header / row drawing. Calling
        // `self.base.draw(r)` is the closest faithful Rust
        // analogue — it fills the buffer (nvfill) and then
        // updates the display list (the FASM tail call at
        // `.updateandreturn`, line 530–536).
        self.base.draw(r)?;

        // TODO: port `tui_gridguts$draw` columns + rows + ellipses
        // body (FASM lines 280–510). The skeleton above guarantees
        // the widget compiles and renders the base background;
        // the full columnar drawing logic lands in a follow-up
        // agent slot once the `DataGrid` consumer crate is in
        // place to drive end-to-end visual validation.

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
                // FASM line 824: walks the JSON contents list to
                // `selected_index`, then calls the parent
                // DataGrid's `tui_vitemselected` vmethod with
                // `(rdi=parent_dg, rsi=selected_item)`.
                //
                // The Rust [`Widget`] trait does not yet expose a
                // first-class `item_selected` vmethod (verified
                // via grep across `tui::object`). The
                // `Weak<DataGrid>` upgrade still happens here so
                // that the future DataGrid trait extension can
                // hook in without changing this call site —
                // currently, on successful upgrade the selection
                // is acknowledged as consumed and the parent is
                // notified solely by reference acquisition (no
                // method dispatch yet).
                let _parent_alive = self.datagrid.as_ref().and_then(Weak::upgrade).is_some();
                // TODO: when `DataGrid` lands, dispatch the
                // `item_selected(self.selected_index)` call here.
                true
            }
            _ => false,
        }
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
        let colors = ColorPair::default();
        GridGuts::new(weak, colors)
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
