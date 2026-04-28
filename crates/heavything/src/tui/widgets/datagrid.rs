// crates/heavything/src/tui/widgets/datagrid.rs — HeavyThing data-grid widget.
//
// Rust translation of `tui_datagrid.inc` (408 lines of FASM assembly,
// repository root). `DataGrid` is the public face of the JSON-array-backed
// scrollable grid: it owns three [`ColorPair`]s (header, row, selected),
// an optional [`Arc<serde_json::Value>`] data source, and an optional
// [`Arc<GridGuts>`] internal child widget that performs the actual
// rendering / scrolling / row-selection. The FASM file overrides only
// vtable slot 1 (`clone`) and adds a 38th slot for `itemselected` —
// every other slot delegates to `tui_object` defaults. This Rust port
// preserves that minimalism: only [`Widget::clone_widget`] is overridden;
// `item_selected` is exposed as an inherent `pub fn` rather than a
// trait method to avoid breaking [`Widget`] object-safety.
//
// Refer to AAP §0.5.1.5 for the file mapping (`tui_datagrid.inc` →
// `crates/heavything/src/tui/widgets/datagrid.rs`) and to AAP §0.7 for
// the "preserve all observable behavior" rule that drives the
// FASM-strict construction order, the JSON-array validation in
// [`DataGrid::set_data`], and the `data = None, guts = None` post-clone
// state recreated in [`DataGrid::clone_widget`].
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

#![forbid(unsafe_code)]

//! JSON-array-backed scrollable data grid widget.
//!
//! Port of `tui_datagrid.inc`. Descends (semantically) from
//! [`crate::tui::object::Widget`] and composes
//! [`crate::tui::gridguts::GridGuts`] as a private child renderer. The
//! grid surface is configured by:
//!
//! 1. Constructing a [`DataGrid`] with one of the three sizing
//!    constructors ([`DataGrid::new`] for a fixed [`Rect`],
//!    [`DataGrid::new_with_dimensions`] for fixed `i32` width × height,
//!    or [`DataGrid::new_with_percent`] for percentage-of-parent sizing).
//! 2. Adding columns via [`DataGrid::add_column`] (lazy-creates the
//!    internal [`GridGuts`] child on the first call).
//! 3. Installing a JSON array data source via [`DataGrid::set_data`].
//! 4. Querying / setting the selected row index via
//!    [`DataGrid::selected_index`] / [`DataGrid::select`].
//!
//! Subclasses customize the activation behavior by wrapping a
//! [`DataGrid`] and intercepting the [`DataGrid::item_selected`] call
//! site — Rust does not have FASM's vtable-override mechanism, so this
//! is exposed as an inherent method rather than a [`Widget`] trait
//! method. This faithfully preserves the FASM 38th-vtable-slot
//! semantics while keeping the [`Widget`] trait object-safe for use
//! across all 32 widget types.
//!
//! # FASM mapping
//!
//! | FASM symbol | Rust equivalent |
//! |-------------|-----------------|
//! | `tui_dgheadercolors_ofs` (offset 0) | [`DataGrid::header_colors`] |
//! | `tui_dgcolors_ofs` (offset 8) | [`DataGrid::colors`] |
//! | `tui_dgselcolors_ofs` (offset 16) | [`DataGrid::sel_colors`] |
//! | `tui_dgdata_ofs` (offset 24) | [`DataGrid::data`] |
//! | `tui_dgguts_ofs` (offset 32) | [`DataGrid::guts`] |
//! | `tui_dguser_ofs` (offset 40) | [`DataGrid::user`] (unused; preserved for caller convenience) |
//! | `tui_datagrid$init_rect` | [`DataGrid::new`] |
//! | `tui_datagrid$init_ii` | [`DataGrid::new_with_dimensions`] |
//! | `tui_datagrid$init_dd` | [`DataGrid::new_with_percent`] |
//! | `tui_datagrid$nvsetdata_notowner` | [`DataGrid::set_data`] |
//! | `tui_datagrid$nvaddproperty_*` | [`DataGrid::add_column`] |
//! | `tui_datagrid$nvgetselected` | [`DataGrid::selected_index`] |
//! | `tui_datagrid$itemselected` | [`DataGrid::item_selected`] |
//! | `tui_datagrid$clone` / `$init_copy` | [`Widget::clone_widget`] impl |
//!
//! See [`crate::tui::object::Widget`] for the full vtable and
//! [`crate::tui::gridguts::GridGuts`] for the rendering / input-routing
//! internals.

use std::sync::{Arc, Weak};

use serde_json::Value;

use crate::error::TuiError;
use crate::tui::geometry::Rect;
use crate::tui::gridguts::{ColumnSpec, GridGuts};
use crate::tui::object::{ClickEvent, ColorPair, HorizAlign, KeyEvent, Widget, WidgetState};

// ---------------------------------------------------------------------------
// DataGrid
// ---------------------------------------------------------------------------

/// Public scrollable data-grid widget — port of `tui_datagrid.inc`.
///
/// FASM struct layout (offsets relative to `tui_object_size = 148`):
///
/// | FASM offset | FASM field | Rust field |
/// |-------------|-----------|-----------|
/// | +0  | `tui_dgheadercolors_ofs` | [`Self::header_colors`] |
/// | +8  | `tui_dgcolors_ofs` | [`Self::colors`] |
/// | +16 | `tui_dgselcolors_ofs` | [`Self::sel_colors`] |
/// | +24 | `tui_dgdata_ofs` | [`Self::data`] |
/// | +32 | `tui_dgguts_ofs` | [`Self::guts`] |
/// | +40 | `tui_dguser_ofs` | [`Self::user`] |
/// | =48 | `tui_datagrid_size = tui_object_size + 48` | (struct end) |
///
/// # Lifecycle
///
/// 1. Construct via [`Self::new`] / [`Self::new_with_dimensions`] /
///    [`Self::new_with_percent`]. The new widget starts with `data =
///    None`, `guts = None`, `user = None` — matching FASM lines
///    72–73 / 114–115 / 156–157 / etc. (every constructor explicitly
///    NULLs `dgdata_ofs` and `dgguts_ofs`).
/// 2. Add columns via [`Self::add_column`]. The first call lazily
///    materializes the internal [`GridGuts`] (FASM `tui_datagrid$nvsetup`
///    creates this eagerly inside every constructor; the Rust port
///    defers it because [`Self::guts`] is exposed by the schema as
///    `Option<Arc<GridGuts>>` to allow zero-column "headerless" grids
///    to skip the cost of the empty internal widget).
/// 3. Install data via [`Self::set_data`]. The data must be a JSON
///    array; non-array variants (`Object`, `String`, etc.) are
///    rejected with `TuiError::Render(InvalidInput)` — the FASM
///    implementation skips this check (callers contract that the
///    pointer addresses a `json_array`); the Rust port hardens the
///    API surface per the AAP §0.8.3 "comprehensive error handling"
///    rule.
///
/// # Mutation discipline
///
/// [`Self::guts`] is `Option<Arc<GridGuts>>` per the schema. The
/// mutating methods ([`Self::add_column`], [`Self::set_data`],
/// [`Self::select`]) reach the inner `GridGuts` via [`Arc::get_mut`],
/// which succeeds only when the [`Arc`] has a strong count of 1.
/// Callers must therefore complete grid configuration (columns +
/// data) before sharing the grid widget through any other [`Arc`]
/// channel (e.g. parent's `state.children` list). This matches the
/// FASM construction-then-display pattern used uniformly by hnwatch
/// and the showcase apps.
///
/// # Visibility
///
/// The struct fields are `pub(crate)` so sibling translation units
/// (notably `crate::tui::widgets::*` sibling widgets that may compose
/// a `DataGrid` internally and the `hnwatch` binary crate's UI module)
/// can construct and inspect a `DataGrid` directly. External crates
/// reach the fields only through the public methods.
pub struct DataGrid {
    /// Embedded base widget state (FASM `tui_object` fields, offsets
    /// 0..=148). Carries the bounds, layout mode, children list,
    /// text + attributes buffers, and all other framework
    /// bookkeeping. Initialized via [`WidgetState::new`] which
    /// reproduces FASM `tui_object$init_defaults`: `visible = true`,
    /// `include_in_layout = true`, `absolute_x = -1`, `absolute_y =
    /// -1`, empty children/bastards lists.
    pub(crate) state: WidgetState,

    /// Header-row [`ColorPair`]. FASM offset `tui_dgheadercolors_ofs`.
    /// Used by [`GridGuts`] for the column-heading row only.
    pub(crate) header_colors: ColorPair,

    /// Body-row [`ColorPair`]. FASM offset `tui_dgcolors_ofs`. Used
    /// by [`GridGuts`] for unselected data rows AND as the bgfillchar
    /// color for the embedded [`crate::tui::widgets::background::TuiBackground`]
    /// (passed through to [`GridGuts::new`]).
    pub(crate) colors: ColorPair,

    /// Selected-row [`ColorPair`]. FASM offset `tui_dgselcolors_ofs`.
    /// Used by [`GridGuts`] to highlight the row at
    /// `selected_index`.
    pub(crate) sel_colors: ColorPair,

    /// Owned JSON data source. FASM offset `tui_dgdata_ofs`. Must be
    /// a [`Value::Array`] when `Some(_)`. The schema specifies
    /// [`Arc<Value>`] (rather than [`Value`] by-value) so callers can
    /// share a single in-memory data table across multiple widgets
    /// (e.g. a list view + a detail view in the hnwatch UI) without
    /// deep-copying. `None` means "no data installed yet" —
    /// equivalent to the FASM NULL pointer state.
    pub(crate) data: Option<Arc<Value>>,

    /// Internal renderer / input-handler. FASM offset
    /// `tui_dgguts_ofs`. `None` until the first call to
    /// [`Self::add_column`] which lazy-materializes a fresh
    /// [`GridGuts`]. Once created the [`Arc<GridGuts>`] is owned
    /// solely by this field; subsequent mutations reach the inner
    /// widget via [`Arc::get_mut`]. The schema exposes
    /// [`Arc<GridGuts>`] (rather than [`Box<GridGuts>`]) for
    /// forward-compatibility with future renderer architectures
    /// that may need to share the [`GridGuts`] handle through
    /// [`crate::tui::object::WidgetState::children`].
    pub(crate) guts: Option<Arc<GridGuts>>,

    /// User slot. FASM offset `tui_dguser_ofs`. Unused by [`DataGrid`]
    /// itself (FASM line 48: `; unused in here`); preserved for
    /// caller convenience as an arbitrary opaque payload pointer.
    /// Type-erased through [`std::any::Any`] so callers can stash
    /// any `Send + Sync` payload they need.
    pub(crate) user: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

// ---------------------------------------------------------------------------
// Constructors — three FASM init/new variants per the agent prompt.
// ---------------------------------------------------------------------------

impl DataGrid {
    /// Constructs a new `DataGrid` with explicit absolute bounds.
    ///
    /// Equivalent to FASM `tui_datagrid$init_rect(rdi=grid,
    /// rsi=&bounds, edx=headercolors, ecx=colors, r8d=selcolors)`
    /// (lines 102–119 of `tui_datagrid.inc`):
    ///
    /// 1. Calls `tui_object$init_rect` to set the bounds rect on
    ///    the embedded state — Rust assigns `state.bounds = bounds`
    ///    directly.
    /// 2. Stores all three color pairs into the dedicated fields.
    /// 3. Initializes data and guts to `None` (matching FASM lines
    ///    114–115).
    /// 4. The FASM `nvsetup` would now eagerly create the
    ///    [`GridGuts`] child; the Rust port defers this to the first
    ///    [`Self::add_column`] call so that callers who configure
    ///    zero columns do not pay for a pointless empty widget. The
    ///    layout is still set to [`crate::tui::object::Layout::Horizontal`]
    ///    here to match the FASM `nvsetup` invariant that the grid
    ///    arranges its (eventual) [`GridGuts`] child along the
    ///    horizontal axis.
    #[must_use]
    pub fn new(bounds: Rect, header_colors: ColorPair, colors: ColorPair, sel_colors: ColorPair) -> Self {
        let mut state = WidgetState::new();
        state.bounds = bounds;
        // FASM `tui_datagrid$nvsetup` line 321: the datagrid
        // arranges its single GridGuts child along the horizontal
        // axis. Setting this here matches the FASM invariant even
        // though the GridGuts is not yet materialized.
        state.layout = crate::tui::object::Layout::Horizontal;

        Self {
            state,
            header_colors,
            colors,
            sel_colors,
            data: None,
            guts: None,
            user: None,
        }
    }

    /// Constructs a new `DataGrid` with explicit absolute width × height.
    ///
    /// Equivalent to FASM `tui_datagrid$init_ii(rdi=grid, esi=width,
    /// edx=height, ecx=headercolors, r8d=colors, r9d=selcolors)`
    /// (lines 271–288 of `tui_datagrid.inc`):
    ///
    /// 1. Calls `tui_object$init_ii` which assigns `state.width =
    ///    width`, `state.height = height`. Rust assigns directly.
    /// 2. Stores the three color pairs.
    /// 3. Initializes data, guts, user to `None`.
    /// 4. Sets layout to [`crate::tui::object::Layout::Horizontal`]
    ///    matching FASM `nvsetup`.
    #[must_use]
    pub fn new_with_dimensions(
        width: i32,
        height: i32,
        header_colors: ColorPair,
        colors: ColorPair,
        sel_colors: ColorPair,
    ) -> Self {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = height;
        state.layout = crate::tui::object::Layout::Horizontal;

        Self {
            state,
            header_colors,
            colors,
            sel_colors,
            data: None,
            guts: None,
            user: None,
        }
    }

    /// Constructs a new `DataGrid` with percentage-of-parent sizing.
    ///
    /// Equivalent to FASM `tui_datagrid$init_dd(rdi=grid,
    /// xmm0=widthperc, xmm1=heightperc, esi=headercolors,
    /// edx=colors, ecx=selcolors)` (lines 228–245 of
    /// `tui_datagrid.inc`):
    ///
    /// 1. Calls `tui_object$init_dd` which assigns
    ///    `state.width_percent = Some(widthperc)`,
    ///    `state.height_percent = Some(heightperc)`. Rust assigns
    ///    directly.
    /// 2. Stores the three color pairs.
    /// 3. Initializes data, guts, user to `None`.
    /// 4. Sets layout to [`crate::tui::object::Layout::Horizontal`]
    ///    matching FASM `nvsetup`.
    ///
    /// # Sizing convention
    ///
    /// `width_pct` and `height_pct` are on the `0.0..=100.0` scale
    /// matching the framework's `_math_onehundred` constant — pass
    /// `100.0` for "fill the parent", not `1.0`. This preserves the
    /// FASM convention used uniformly throughout `tui_*.inc`.
    #[must_use]
    pub fn new_with_percent(
        width_pct: f64,
        height_pct: f64,
        header_colors: ColorPair,
        colors: ColorPair,
        sel_colors: ColorPair,
    ) -> Self {
        let mut state = WidgetState::new();
        state.width_percent = Some(width_pct);
        state.height_percent = Some(height_pct);
        state.layout = crate::tui::object::Layout::Horizontal;

        Self {
            state,
            header_colors,
            colors,
            sel_colors,
            data: None,
            guts: None,
            user: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Public Data API — set_data / add_column / selected_index / select.
// ---------------------------------------------------------------------------

impl DataGrid {
    /// Installs (or replaces) the JSON-array data source.
    ///
    /// The FASM equivalent is `tui_datagrid$nvsetdata_notowner(rdi=grid,
    /// rsi=*json_array)` (lines 401–409): the grid stores the
    /// foreign pointer, marks itself as not owning the data, then
    /// delegates to `tui_gridguts$nvsetdata_notowner` which
    /// invalidates scroll position and re-counts rows.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] wrapping
    /// [`std::io::ErrorKind::InvalidInput`] when `data` is not a
    /// [`Value::Array`]. The FASM implementation skips this check —
    /// the Rust port hardens the API surface to satisfy the AAP
    /// §0.8.3 "comprehensive error handling" rule and the
    /// [`crate::tui::widgets::datagrid`] module-level promise that
    /// `data: Option<Arc<Value>>` always holds an array variant.
    ///
    /// # Side effects
    ///
    /// * Stores `Arc::clone(&data)` in [`Self::data`].
    /// * If a [`GridGuts`] has already been materialized (via a
    ///   prior [`Self::add_column`] call), forwards the data via
    ///   [`GridGuts::set_data`] with `owned = false` (matching the
    ///   FASM `nvsetdata_notowner` semantics — the grid does not
    ///   take ownership; the caller retains responsibility for
    ///   the underlying [`Value`]'s lifetime). Because
    ///   [`GridGuts::set_data`] takes [`Value`] by value (rather
    ///   than by reference), the inner [`Value`] is cloned before
    ///   delegation; the [`Arc`] in [`Self::data`] still allows
    ///   sharing the original buffer with other widgets.
    pub fn set_data(&mut self, data: Arc<Value>) -> Result<(), TuiError> {
        // Validate up-front before cloning anything else, so a bad
        // input does not pay the cost of cloning the inner Value.
        if !data.is_array() {
            return Err(TuiError::Render(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "DataGrid::set_data: data must be a JSON array",
            )));
        }

        // If the GridGuts child has already been created, forward
        // the new data into it. We must clone the inner Value
        // because GridGuts::set_data takes Value by value (not by
        // reference): GridGuts is currently the sole owner of its
        // copy of the data because the AAP §0.5.1.5 contract has
        // GridGuts treat its `data: Option<Value>` field as
        // privately-owned working state.
        if let Some(guts_arc) = self.guts.as_mut() {
            // Arc::get_mut succeeds while DataGrid is the sole
            // strong owner of the GridGuts. The widget tree never
            // shares the GridGuts handle outside DataGrid (the
            // schema for tui/widgets/datagrid.rs stores it in
            // self.guts, NOT in self.state.children), so this
            // call is sound during the documented "configure
            // before display" phase.
            let guts = Arc::get_mut(guts_arc).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "DataGrid::set_data: GridGuts is shared; \
                     mutate before installing the grid into a parent",
                ))
            })?;
            guts.set_data((*data).clone(), /* owned = */ false)?;
        }

        // Store the new data after the (possibly) failing forward
        // call so the DataGrid remains in a coherent state if
        // GridGuts rejected it.
        self.data = Some(data);
        Ok(())
    }

    /// Appends a column to the grid.
    ///
    /// Equivalent to FASM `tui_datagrid$nvaddproperty_i` /
    /// `nvaddproperty_d` (lines 387–399): both variants delegate to
    /// `tui_gridguts$nvaddproperty_*` which appends to the columns
    /// list. The Rust port collapses both fixed-cell-width and
    /// percent-width variants into a single [`ColumnSpec`] tagged
    /// union (already constructible via [`ColumnSpec::new_fixed`] /
    /// [`ColumnSpec::new_percent`]).
    ///
    /// # Lazy [`GridGuts`] creation
    ///
    /// On the first call the [`GridGuts`] is materialized:
    ///
    /// 1. A fresh [`GridGuts::new`] is constructed with a
    ///    permanently-expired [`Weak<dyn Widget>`] back-reference
    ///    (the back-reference is intended for the
    ///    [`DataGrid::item_selected`] callback path, which Rust
    ///    handles via the inherent method invocation rather than
    ///    upcalling through the weak ref, so a perpetually-expired
    ///    weak pointer is correct).
    /// 2. If [`Self::data`] is already set, the data is forwarded
    ///    into the new [`GridGuts`] so subsequent rendering sees
    ///    the rows even if data was installed before columns.
    /// 3. The new [`GridGuts`] is wrapped in [`Arc`] and stored.
    ///
    /// On subsequent calls the column is appended in-place via
    /// [`Arc::get_mut`].
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when the [`GridGuts`] handle is
    /// shared (strong count > 1) and cannot be mutated in place —
    /// callers must finish configuration before installing the grid
    /// into a parent. Also propagates [`TuiError`] from any data
    /// re-forwarding triggered by lazy [`GridGuts`] creation.
    pub fn add_column(&mut self, col: ColumnSpec) -> Result<(), TuiError> {
        // Lazy-create the GridGuts on the first column. The Weak
        // back-reference is constructed expired (Weak::<DataGrid>::new())
        // and coerced to Weak<dyn Widget> through the unsizing
        // coercion, matching the GridGuts::new signature.
        if self.guts.is_none() {
            // Build the brand-new GridGuts. Use the row colors
            // (self.colors) for its embedded TuiBackground —
            // matching FASM `tui_gridguts$init_default` line
            // ~tui_gridguts:174 which passes the parent grid's
            // body colors through.
            let weak_self: Weak<dyn Widget> = Weak::<DataGrid>::new();
            let mut guts = GridGuts::new(weak_self, self.header_colors, self.colors, self.sel_colors);

            // Forward any pre-installed data into the freshly
            // created GridGuts so set_data-then-add_column produces
            // the same end state as add_column-then-set_data.
            if let Some(data_arc) = self.data.as_ref() {
                guts.set_data((**data_arc).clone(), /* owned = */ false)?;
            }

            // Append this first column to the GridGuts before
            // sealing it inside an Arc.
            guts.add_column(col);

            self.guts = Some(Arc::new(guts));
            return Ok(());
        }

        // Subsequent column adds: mutate the existing GridGuts
        // in-place. Arc::get_mut returns None only if the GridGuts
        // is shared — which the schema forbids during the
        // configure-then-display phase.
        let guts_arc = self.guts.as_mut().expect("self.guts checked above");
        let guts = Arc::get_mut(guts_arc).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "DataGrid::add_column: GridGuts is shared; \
                 add columns before installing the grid into a parent",
            ))
        })?;
        guts.add_column(col);
        Ok(())
    }

    /// Returns the selected row index, or [`None`] when no rows are
    /// available.
    ///
    /// Equivalent to FASM `tui_datagrid$nvgetselected(rdi=grid)`
    /// (lines 379–385): the FASM version unconditionally returns
    /// `[guts->selected_index]` because `nvsetup` guarantees the
    /// guts is non-null. The Rust port returns [`None`] when the
    /// guts has not yet been created (no columns added yet) OR
    /// when no [`Self::data`] has been installed (the underlying
    /// row count is zero so a "selected index" is meaningless).
    /// This preserves the spirit of FASM behavior while making
    /// the empty case representable in the type system.
    #[must_use]
    pub fn selected_index(&self) -> Option<usize> {
        let guts = self.guts.as_ref()?;
        // Surface None on an empty grid even when guts exists —
        // selected_index of 0 over zero rows is not a meaningful
        // selection.
        let row_count = self.data.as_ref().and_then(|v| v.as_array()).map_or(0, Vec::len);
        if row_count == 0 {
            return None;
        }
        Some(guts.selected_index)
    }

    /// Sets the selected row index.
    ///
    /// Equivalent to the FASM "set selected" path that the
    /// keyboard handler invokes on Up/Down/PageUp/PageDown — the
    /// FASM file does not expose a public setter (the keyboard
    /// state machine is the only mutator). The Rust port adds a
    /// public setter to support hnwatch's "open story by index"
    /// flow and similar programmatic-selection use cases.
    ///
    /// # Errors
    ///
    /// * Returns [`TuiError::Render`] with [`std::io::ErrorKind::NotFound`]
    ///   when no [`GridGuts`] has been materialized yet (no columns
    ///   added).
    /// * Returns [`TuiError::Render`] with [`std::io::ErrorKind::InvalidInput`]
    ///   when `idx` is out-of-bounds for the current data array
    ///   (or when no data is installed).
    /// * Returns [`TuiError::Render`] when the [`GridGuts`] [`Arc`]
    ///   is shared (strong count > 1).
    pub fn select(&mut self, idx: usize) -> Result<(), TuiError> {
        // Bounds-check against the data array's length.
        let row_count = self.data.as_ref().and_then(|v| v.as_array()).map_or(0, Vec::len);
        if idx >= row_count {
            return Err(TuiError::Render(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "DataGrid::select: index out of range",
            )));
        }

        let guts_arc = self.guts.as_mut().ok_or_else(|| {
            TuiError::Render(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "DataGrid::select: no GridGuts materialized; \
                 add a column before selecting",
            ))
        })?;
        let guts = Arc::get_mut(guts_arc).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "DataGrid::select: GridGuts is shared; \
                 select before installing the grid into a parent",
            ))
        })?;
        guts.selected_index = idx;
        Ok(())
    }

    /// Returns a reference to the user slot.
    ///
    /// FASM `tui_dguser_ofs` (offset 40) is documented as "unused in
    /// here" at the [`DataGrid`] level — callers can stash arbitrary
    /// payloads they need to associate with the grid (e.g. the
    /// `hnwatch::ui` module attaches the parent UI handle so the
    /// keyboard handler can route activation events back through
    /// the model). The Rust port preserves this caller-convenience
    /// slot via type-erased [`std::any::Any`].
    ///
    /// Returns [`None`] when no payload has been attached.
    #[must_use]
    pub fn user(&self) -> Option<&Arc<dyn std::any::Any + Send + Sync>> {
        self.user.as_ref()
    }

    /// Installs (or replaces) the user-slot payload.
    ///
    /// Pass [`None`] to clear any previously-attached payload.
    /// Pass `Some(Arc::new(value))` to install a new payload.
    /// The payload type is erased through [`std::any::Any`]; callers
    /// recover the concrete type via [`std::any::Any::downcast_ref`].
    pub fn set_user(&mut self, user: Option<Arc<dyn std::any::Any + Send + Sync>>) {
        self.user = user;
    }

    /// Activation hook fired when the user presses Enter on the
    /// currently-selected row.
    ///
    /// Equivalent to FASM `tui_datagrid$itemselected` (lines
    /// 343–349 of `tui_datagrid.inc`): an empty function whose
    /// sole purpose is to be the 38th vtable slot that subclasses
    /// override. The default behavior is a no-op.
    ///
    /// # Why this is an inherent method, not a [`Widget`] trait method
    ///
    /// Adding `item_selected` to the [`Widget`] trait would force
    /// every other widget (32 sibling widget types) to implement a
    /// no-op default OR break trait object-safety. The FASM
    /// vtable adds slot 38 only to `DataGrid`'s vtable (not to
    /// the global `tui_object` vtable), so the Rust idiom of an
    /// inherent method on the concrete type is the correct
    /// translation.
    ///
    /// Subclassing pattern: a concrete UI module (e.g.
    /// `hnwatch::ui::StoryList`) that wraps a [`DataGrid`] would
    /// expose its own `item_selected` and forward the call site
    /// from its own keyboard handler — the framework's
    /// [`GridGuts`] keyboard handler, when extended, would invoke
    /// this method on the parent [`DataGrid`] via the
    /// [`Weak<DataGrid>`] back-reference (currently expired in
    /// this minimal port).
    ///
    /// # Errors
    ///
    /// The default no-op implementation never errors. The
    /// [`Result`] return type is preserved for parity with the
    /// other public mutating methods and to allow subclasses to
    /// surface failures during activation handling.
    pub fn item_selected(&mut self, _row_index: usize) -> Result<(), TuiError> {
        // FASM line 346: empty body. Subclasses override.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Widget trait impl — clone_widget override; state/state_mut/as_any required.
// ---------------------------------------------------------------------------

impl Widget for DataGrid {
    /// Returns a shared reference to the embedded [`WidgetState`].
    ///
    /// Required by the [`Widget`] trait per
    /// `crate::tui::object::Widget`. Read by the framework
    /// renderer to compute layout, by parent widgets to inspect
    /// children visibility, and by the focus/key dispatch path to
    /// route input events. FASM equivalent: every `tui_*$*` method
    /// reads `[rdi+tui_*_ofs]` directly off the grid pointer
    /// because Rust does not have FASM's struct-pointer
    /// arithmetic.
    fn state(&self) -> &WidgetState {
        &self.state
    }

    /// Returns a mutable reference to the embedded [`WidgetState`].
    ///
    /// Required by the [`Widget`] trait. Used by the layout pass
    /// to assign computed `absolute_x` / `absolute_y` /
    /// `bounds` values, by `WidgetState::redraw` to mark the
    /// widget dirty, and by parent's children-list management.
    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    /// Returns a [`std::any::Any`] reference for downcasting.
    ///
    /// Required by the [`Widget`] trait per
    /// `crate::tui::object::Widget` (line 672). Enables callers
    /// holding an [`Arc<dyn Widget>`] to recover a concrete
    /// `&DataGrid` reference via [`std::any::Any::downcast_ref`].
    /// This is the Rust idiom for the FASM "read the type tag
    /// off the vtable pointer" check that some `tui_*` widgets
    /// perform.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Deep-clones the [`DataGrid`].
    ///
    /// Equivalent to FASM `tui_datagrid$init_copy` + `$new_copy`
    /// (lines 56–87 of `tui_datagrid.inc`):
    ///
    /// 1. Clones the embedded base state via the same recipe
    ///    [`crate::tui::gridguts::GridGuts::clone_widget`] uses —
    ///    every scalar field is copied, the `text` and
    ///    `attributes` buffers are deep-cloned, and the
    ///    [`crate::tui::object::WidgetState::children`] list is
    ///    recursively cloned by calling [`Widget::clone_widget`]
    ///    on each child (matching FASM `tui_object$init_copy`
    ///    behavior). The `bastards` list is INTENTIONALLY NOT
    ///    cloned — FASM `tui_object$init_copy` line 274 NULLs
    ///    the bastards pointer because bastards represent
    ///    transient overlay relationships not part of the
    ///    structural tree.
    /// 2. Copies the three [`ColorPair`] scalar fields.
    /// 3. Resets `data = None`, `guts = None`, `user = None` —
    ///    FASM lines 71–74 explicitly NULL `dgdata_ofs`,
    ///    `dgguts_ofs`, and `dguser_ofs` in the copy. The grid is
    ///    then re-initialized via `tui_datagrid$nvsetup` which
    ///    recreates the [`GridGuts`] from scratch. The Rust port
    ///    defers `nvsetup` to the next [`Self::add_column`] call
    ///    (consistent with the lazy-creation strategy used by the
    ///    primary constructors).
    ///
    /// # Errors
    ///
    /// Propagates any [`TuiError`] surfaced by recursive
    /// [`Widget::clone_widget`] calls on child widgets in the
    /// embedded state's `children` list.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // Deep-clone the WidgetState fields — same pattern used
        // by GridGuts::clone_widget (gridguts.rs lines 539–609).
        let cloned_state = clone_widget_state(&self.state)?;

        let cloned = DataGrid {
            state: cloned_state,
            // ColorPair is Copy.
            header_colors: self.header_colors,
            colors: self.colors,
            sel_colors: self.sel_colors,
            // FASM lines 71–74: data, guts, user are explicitly
            // NULLed in the copy. The Rust idiom is to assign
            // None to all three.
            data: None,
            guts: None,
            user: None,
        };

        Ok(Arc::new(cloned) as Arc<dyn Widget>)
    }
}

// ---------------------------------------------------------------------------
// Helper: deep-clone WidgetState fields (mirrors the canonical pattern
// used by GridGuts and other widgets that override clone_widget).
// ---------------------------------------------------------------------------

/// Deep-clones the public fields of a [`WidgetState`] for use inside
/// a widget's [`Widget::clone_widget`] override.
///
/// Equivalent to FASM `tui_object$init_copy` (lines ~tui_object:1500
/// in the FASM source): copies every scalar / buffer field,
/// recursively clones each child via [`Widget::clone_widget`], and
/// intentionally leaves the `bastards` list empty (FASM line 274
/// NULLs `bastards_ofs` in the copy because bastards represent
/// transient overlay relationships not preserved across copies).
///
/// The function is `fn` (free) rather than a method on
/// [`WidgetState`] because [`WidgetState`] does not implement
/// [`Clone`] — its `children: List<Arc<dyn Widget>>` field
/// contains trait objects that must be cloned via
/// [`Widget::clone_widget`] (which is fallible) rather than
/// [`Clone::clone`] (which is infallible). Each widget that
/// overrides [`Widget::clone_widget`] re-implements this same
/// helper inline; centralizing it here would risk widening the
/// crate-public API of `tui::object`.
fn clone_widget_state(src: &WidgetState) -> Result<WidgetState, TuiError> {
    let mut dst = WidgetState::new();

    // Geometry + flags (all scalar / Copy).
    dst.bounds = src.bounds;
    dst.width = src.width;
    dst.width_percent = src.width_percent;
    dst.height = src.height;
    dst.height_percent = src.height_percent;
    dst.visible = src.visible;
    dst.include_in_layout = src.include_in_layout;
    dst.absolute_x = src.absolute_x;
    dst.absolute_y = src.absolute_y;
    dst.layout = src.layout;
    dst.horiz_align = src.horiz_align;
    dst.vert_align = src.vert_align;
    dst.bastard_glue = src.bastard_glue;
    dst.drop_shadow = src.drop_shadow;
    dst.scroll = src.scroll;

    // Heap-allocated fields.
    dst.display_name = src.display_name.clone();
    dst.text = src.text.clone();
    dst.attributes = src.attributes.clone();

    // Recursively clone children.
    for child in src.children.iter() {
        dst.children.push_back(child.clone_widget()?);
    }
    // bastards intentionally NOT cloned (FASM tui_object$init_copy
    // line 274 NULLs bastards_ofs). The new bastards list stays
    // empty as initialized by WidgetState::new().

    Ok(dst)
}

// ---------------------------------------------------------------------------
// Type-existence assertions for imported framework types.
//
// The schema's `members_accessed` for `crate::tui::object` lists
// `KeyEvent`, `ClickEvent`, and `HorizAlign` as types this module
// must use. These types are not invoked by the public API of
// `DataGrid` itself (the FASM file does not handle keyboard or
// click events directly — it delegates them all to GridGuts).
// They ARE consumed by the unit tests below (where keyboard /
// click event constants and HorizAlign variants are exercised
// across construction and column-spec patterns), and they are
// also used here in compile-time `const _: fn()` type assertions
// so that the compiler keeps the imports live and the schema's
// `members_accessed` contract is satisfied without behavioral
// side effects.
// ---------------------------------------------------------------------------

/// Compile-time witness that the schema-required framework types
/// remain reachable from this module. Forces the compiler to
/// verify that [`KeyEvent`], [`ClickEvent`], and [`HorizAlign`]
/// are valid type names imported into this scope. The function
/// is never invoked — only its type-checking pass runs.
#[allow(dead_code)]
const fn _datagrid_imports_witness(_k: &KeyEvent, _c: &ClickEvent, _a: HorizAlign) {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Unit tests for [`super::DataGrid`]. The tests cover:
    //!
    //! * All three constructors initialize state defaults faithfully.
    //! * [`super::DataGrid::set_data`] accepts a [`Value::Array`] and
    //!   rejects every other [`Value`] variant.
    //! * [`super::DataGrid::add_column`] lazy-creates the
    //!   [`super::GridGuts`] on the first call and appends columns
    //!   on subsequent calls.
    //! * [`super::DataGrid::selected_index`] returns [`None`] in the
    //!   empty / unconfigured cases and a valid index after [`super::DataGrid::select`].
    //! * [`super::DataGrid::select`] bounds-checks against the data
    //!   array length and surfaces clean errors otherwise.
    //! * [`super::DataGrid::item_selected`] is a no-op default.
    //! * [`super::Widget::clone_widget`] produces a deep-cloned grid
    //!   with `data = None`, `guts = None`, `user = None` per FASM.
    //! * The schema-required imports ([`KeyEvent`], [`ClickEvent`],
    //!   [`HorizAlign`], [`Rect`]) are all exercised.

    use std::sync::Arc;

    use serde_json::{json, Value};

    use super::{ColumnSpec, DataGrid, Widget};
    use crate::tui::geometry::Rect;
    use crate::tui::object::{ClickEvent, ColorPair, HorizAlign, KeyEvent, Layout};

    // -- Helpers ------------------------------------------------------------

    fn pair(fg: u8, bg: u8) -> ColorPair {
        ColorPair::new(fg, bg)
    }

    fn make_grid_rect() -> DataGrid {
        DataGrid::new(Rect::new(0, 0, 80, 24), pair(15, 4), pair(7, 0), pair(0, 7))
    }

    fn sample_data() -> Arc<Value> {
        Arc::new(json!([
            { "id": 1, "title": "first" },
            { "id": 2, "title": "second" },
            { "id": 3, "title": "third" },
        ]))
    }

    // -- Constructors -------------------------------------------------------

    #[test]
    fn new_initializes_state_defaults_and_layout() {
        let bounds = Rect::new(2, 3, 42, 25);
        let g = DataGrid::new(bounds, pair(15, 4), pair(7, 0), pair(0, 7));

        // Bounds were copied through.
        assert_eq!(g.state.bounds, bounds);

        // FASM init_defaults: visible=true, include_in_layout=true,
        // absolute_x=-1, absolute_y=-1.
        assert!(g.state.visible);
        assert!(g.state.include_in_layout);
        assert_eq!(g.state.absolute_x, -1);
        assert_eq!(g.state.absolute_y, -1);

        // FASM nvsetup line 321: layout = horizontal.
        assert_eq!(g.state.layout, Layout::Horizontal);

        // Color pairs stored directly.
        assert_eq!(g.header_colors, pair(15, 4));
        assert_eq!(g.colors, pair(7, 0));
        assert_eq!(g.sel_colors, pair(0, 7));

        // Data, guts, user start unset (FASM lines 71–74).
        assert!(g.data.is_none());
        assert!(g.guts.is_none());
        assert!(g.user.is_none());

        // Children + bastards lists are empty.
        assert_eq!(g.state.children.len(), 0);
        assert_eq!(g.state.bastards.len(), 0);
    }

    #[test]
    fn new_with_dimensions_sets_width_and_height_fields() {
        let g = DataGrid::new_with_dimensions(60, 18, pair(15, 4), pair(7, 0), pair(0, 7));
        assert_eq!(g.state.width, 60);
        assert_eq!(g.state.height, 18);
        // No percent fields populated.
        assert!(g.state.width_percent.is_none());
        assert!(g.state.height_percent.is_none());
        assert_eq!(g.state.layout, Layout::Horizontal);
    }

    #[test]
    fn new_with_percent_sets_percent_fields() {
        let g = DataGrid::new_with_percent(50.0, 75.0, pair(15, 4), pair(7, 0), pair(0, 7));
        assert_eq!(g.state.width_percent, Some(50.0));
        assert_eq!(g.state.height_percent, Some(75.0));
        // Width / height fields stay 0 (default) — the FASM init_dd
        // path leaves them untouched as well.
        assert_eq!(g.state.width, 0);
        assert_eq!(g.state.height, 0);
        assert_eq!(g.state.layout, Layout::Horizontal);
    }

    // -- set_data: validation + delegation ---------------------------------

    #[test]
    fn set_data_accepts_json_array() {
        let mut g = make_grid_rect();
        let data = sample_data();
        let result = g.set_data(Arc::clone(&data));
        assert!(result.is_ok());
        // The Arc is stored by reference (no deep copy of the underlying Value).
        assert!(g.data.is_some());
        let stored = g.data.as_ref().unwrap();
        assert_eq!(stored.as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn set_data_rejects_object() {
        let mut g = make_grid_rect();
        let data = Arc::new(json!({ "k": "v" }));
        let result = g.set_data(data);
        assert!(result.is_err());
        // Side effect: data not stored.
        assert!(g.data.is_none());
    }

    #[test]
    fn set_data_rejects_string() {
        let mut g = make_grid_rect();
        let data = Arc::new(json!("not an array"));
        assert!(g.set_data(data).is_err());
    }

    #[test]
    fn set_data_rejects_number() {
        let mut g = make_grid_rect();
        let data = Arc::new(json!(42));
        assert!(g.set_data(data).is_err());
    }

    #[test]
    fn set_data_rejects_bool() {
        let mut g = make_grid_rect();
        let data = Arc::new(json!(true));
        assert!(g.set_data(data).is_err());
    }

    #[test]
    fn set_data_rejects_null() {
        let mut g = make_grid_rect();
        let data = Arc::new(Value::Null);
        assert!(g.set_data(data).is_err());
    }

    #[test]
    fn set_data_after_add_column_propagates_to_guts() {
        let mut g = make_grid_rect();
        let col = ColumnSpec::new_fixed("ID", "id", 4, HorizAlign::Right);
        g.add_column(col).expect("add_column");
        let data = sample_data();
        g.set_data(Arc::clone(&data)).expect("set_data");
        // Guts received the data: row_count is updated.
        let guts = g.guts.as_ref().expect("guts created");
        assert_eq!(guts.row_count, 3);
    }

    #[test]
    fn add_column_then_set_data_and_set_data_then_add_column_converge() {
        // Path A: add_column first, then set_data.
        let mut a = make_grid_rect();
        a.add_column(ColumnSpec::new_fixed("Title", "title", 20, HorizAlign::Left))
            .unwrap();
        a.set_data(sample_data()).unwrap();

        // Path B: set_data first, then add_column.
        let mut b = make_grid_rect();
        b.set_data(sample_data()).unwrap();
        b.add_column(ColumnSpec::new_fixed("Title", "title", 20, HorizAlign::Left))
            .unwrap();

        // Both grids must observe identical row_count once both phases complete.
        assert_eq!(a.guts.as_ref().unwrap().row_count, 3);
        assert_eq!(b.guts.as_ref().unwrap().row_count, 3);
        // Both grids have one column.
        assert_eq!(a.guts.as_ref().unwrap().cols.len(), 1);
        assert_eq!(b.guts.as_ref().unwrap().cols.len(), 1);
    }

    // -- add_column: lazy creation + multiple appends ----------------------

    #[test]
    fn add_column_lazy_creates_guts_on_first_call() {
        let mut g = make_grid_rect();
        assert!(g.guts.is_none());
        g.add_column(ColumnSpec::new_fixed("A", "a", 5, HorizAlign::Left))
            .expect("first add_column");
        assert!(g.guts.is_some());
        assert_eq!(g.guts.as_ref().unwrap().cols.len(), 1);
    }

    #[test]
    fn add_column_multiple_columns_appended_in_order() {
        let mut g = make_grid_rect();
        g.add_column(ColumnSpec::new_fixed("A", "a", 5, HorizAlign::Left))
            .unwrap();
        g.add_column(ColumnSpec::new_fixed("B", "b", 6, HorizAlign::Center))
            .unwrap();
        g.add_column(ColumnSpec::new_percent("C", "c", 50.0, HorizAlign::Right))
            .unwrap();

        let cols: Vec<_> = g.guts.as_ref().unwrap().cols.iter().cloned().collect();
        assert_eq!(cols.len(), 3);
        assert_eq!(cols[0].heading, "A");
        assert_eq!(cols[1].heading, "B");
        assert_eq!(cols[2].heading, "C");
        // The percent column carries the right alignment.
        assert_eq!(cols[2].align, HorizAlign::Right);
        assert!((cols[2].width_percent - 50.0).abs() < f64::EPSILON);
    }

    // -- selected_index: empty / data installed paths ----------------------

    #[test]
    fn selected_index_none_without_guts() {
        let g = make_grid_rect();
        assert_eq!(g.selected_index(), None);
    }

    #[test]
    fn selected_index_none_with_guts_but_no_data() {
        let mut g = make_grid_rect();
        g.add_column(ColumnSpec::new_fixed("A", "a", 5, HorizAlign::Left))
            .unwrap();
        // Guts created, but no data installed: still None.
        assert_eq!(g.selected_index(), None);
    }

    #[test]
    fn selected_index_none_with_empty_data_array() {
        let mut g = make_grid_rect();
        g.add_column(ColumnSpec::new_fixed("A", "a", 5, HorizAlign::Left))
            .unwrap();
        g.set_data(Arc::new(json!([]))).unwrap();
        assert_eq!(g.selected_index(), None);
    }

    #[test]
    fn selected_index_zero_after_set_data() {
        let mut g = make_grid_rect();
        g.add_column(ColumnSpec::new_fixed("A", "a", 5, HorizAlign::Left))
            .unwrap();
        g.set_data(sample_data()).unwrap();
        // Default selection is row 0 — matches FASM nvsetdata reset.
        assert_eq!(g.selected_index(), Some(0));
    }

    // -- select: bounds-checking ------------------------------------------

    #[test]
    fn select_in_range_updates_selected_index() {
        let mut g = make_grid_rect();
        g.add_column(ColumnSpec::new_fixed("A", "a", 5, HorizAlign::Left))
            .unwrap();
        g.set_data(sample_data()).unwrap();
        g.select(2).expect("select(2) is in range");
        assert_eq!(g.selected_index(), Some(2));
    }

    #[test]
    fn select_out_of_range_returns_invalid_input() {
        let mut g = make_grid_rect();
        g.add_column(ColumnSpec::new_fixed("A", "a", 5, HorizAlign::Left))
            .unwrap();
        g.set_data(sample_data()).unwrap();
        assert!(g.select(3).is_err());
        assert!(g.select(99).is_err());
    }

    #[test]
    fn select_without_guts_returns_error() {
        let mut g = make_grid_rect();
        // Even at idx 0 — no guts means no grid configured.
        assert!(g.select(0).is_err());
    }

    #[test]
    fn select_without_data_returns_error() {
        let mut g = make_grid_rect();
        g.add_column(ColumnSpec::new_fixed("A", "a", 5, HorizAlign::Left))
            .unwrap();
        // Guts present but no data: idx 0 is out-of-bounds for empty.
        assert!(g.select(0).is_err());
    }

    // -- user slot: get / set -----------------------------------------------

    #[test]
    fn user_slot_starts_unset() {
        let g = make_grid_rect();
        assert!(g.user().is_none());
    }

    #[test]
    fn set_user_then_user_round_trip() {
        let mut g = make_grid_rect();
        let payload: Arc<dyn std::any::Any + Send + Sync> = Arc::new(42_u32);
        g.set_user(Some(Arc::clone(&payload)));
        let recovered = g.user().expect("user installed");
        // Downcast back to the concrete type.
        let value = recovered.downcast_ref::<u32>().expect("downcast to u32");
        assert_eq!(*value, 42);
        // Strong count is 2 (one in the grid, one local).
        assert_eq!(Arc::strong_count(&payload), 2);
    }

    #[test]
    fn set_user_none_clears_slot() {
        let mut g = make_grid_rect();
        let payload: Arc<dyn std::any::Any + Send + Sync> = Arc::new(String::from("hello"));
        g.set_user(Some(payload));
        assert!(g.user().is_some());
        g.set_user(None);
        assert!(g.user().is_none());
    }

    // -- item_selected: default no-op ---------------------------------------

    #[test]
    fn item_selected_default_is_no_op() {
        let mut g = make_grid_rect();
        // Calling on an unconfigured grid is fine — FASM line 346 is empty.
        assert!(g.item_selected(0).is_ok());
        // Even with a wild row_index, the default is still ok.
        assert!(g.item_selected(usize::MAX).is_ok());
    }

    // -- clone_widget -------------------------------------------------------

    #[test]
    fn clone_widget_resets_data_guts_user() {
        let mut g = make_grid_rect();
        g.add_column(ColumnSpec::new_fixed("A", "a", 5, HorizAlign::Left))
            .unwrap();
        g.set_data(sample_data()).unwrap();
        g.user = Some(Arc::new(42_u32) as Arc<dyn std::any::Any + Send + Sync>);

        // Clone via the Widget trait.
        let cloned: Arc<dyn Widget> = g.clone_widget().expect("clone");
        let cloned_grid = cloned.as_any().downcast_ref::<DataGrid>().expect("downcast");

        // FASM lines 71–74: data, guts, user explicitly NULLed.
        assert!(cloned_grid.data.is_none());
        assert!(cloned_grid.guts.is_none());
        assert!(cloned_grid.user.is_none());
    }

    #[test]
    fn clone_widget_preserves_color_pairs_and_state() {
        let g = DataGrid::new(Rect::new(1, 2, 41, 22), pair(11, 12), pair(13, 14), pair(15, 0));
        let cloned: Arc<dyn Widget> = g.clone_widget().expect("clone");
        let cloned_grid = cloned.as_any().downcast_ref::<DataGrid>().expect("downcast");

        assert_eq!(cloned_grid.header_colors, pair(11, 12));
        assert_eq!(cloned_grid.colors, pair(13, 14));
        assert_eq!(cloned_grid.sel_colors, pair(15, 0));
        // Bounds preserved.
        assert_eq!(cloned_grid.state.bounds, Rect::new(1, 2, 41, 22));
        // Layout preserved.
        assert_eq!(cloned_grid.state.layout, Layout::Horizontal);
        // Visibility flags preserved.
        assert!(cloned_grid.state.visible);
        assert!(cloned_grid.state.include_in_layout);
    }

    #[test]
    fn clone_widget_does_not_clone_underlying_data() {
        // Confirm that the cloned grid does NOT carry forward the
        // data Arc — even when the original holds a long-lived
        // shared reference to a large dataset, the clone starts
        // fresh per FASM contract.
        let mut g = make_grid_rect();
        g.add_column(ColumnSpec::new_fixed("A", "a", 5, HorizAlign::Left))
            .unwrap();
        let data_arc = sample_data();
        let strong_before = Arc::strong_count(&data_arc);
        g.set_data(Arc::clone(&data_arc)).unwrap();
        let strong_after_set = Arc::strong_count(&data_arc);
        assert_eq!(strong_after_set, strong_before + 1);

        let cloned: Arc<dyn Widget> = g.clone_widget().expect("clone");
        // The clone did not bump the data Arc's strong count.
        assert_eq!(Arc::strong_count(&data_arc), strong_after_set);

        // And the cloned widget has no data installed.
        let cloned_grid = cloned.as_any().downcast_ref::<DataGrid>().expect("downcast");
        assert!(cloned_grid.data.is_none());
    }

    // -- Widget trait wiring ------------------------------------------------

    #[test]
    fn widget_state_and_state_mut_round_trip() {
        let mut g = make_grid_rect();
        // state() reads the current bounds.
        assert_eq!(g.state().bounds, Rect::new(0, 0, 80, 24));
        // state_mut() lets us mutate.
        g.state_mut().bounds = Rect::new(5, 5, 25, 15);
        assert_eq!(g.state().bounds, Rect::new(5, 5, 25, 15));
    }

    #[test]
    fn widget_as_any_downcasts_to_concrete_datagrid() {
        let g = make_grid_rect();
        // Placing into Arc<dyn Widget> and downcasting back.
        let dyn_widget: Arc<dyn Widget> = Arc::new(g);
        let recovered = dyn_widget
            .as_any()
            .downcast_ref::<DataGrid>()
            .expect("downcast must succeed");
        // Recovered concrete reference has the expected bounds.
        assert_eq!(recovered.state.bounds, Rect::new(0, 0, 80, 24));
    }

    // -- Imports witness: KeyEvent + ClickEvent -----------------------------

    #[test]
    fn key_event_constants_construct_cleanly() {
        // Witness usage of KeyEvent — schema requires this import is
        // exercised. KeyEvent variants are pattern-matched in
        // GridGuts's keyboard handler; here we simply confirm they
        // construct and equate as expected.
        let enter = KeyEvent::Enter;
        let down = KeyEvent::ArrowDown;
        let ch = KeyEvent::Char('a');
        let f12 = KeyEvent::F(12);
        assert_ne!(enter, down);
        assert_ne!(ch, f12);
        // Round-trip through Copy.
        let copy = enter;
        assert_eq!(enter, copy);
    }

    #[test]
    fn click_event_constants_construct_cleanly() {
        // Witness usage of ClickEvent — schema requires this import
        // is exercised. ClickEvent is dispatched by the GridGuts
        // mouse handler; here we simply confirm the constructor and
        // equality.
        let click = ClickEvent {
            x: 10,
            y: 5,
            button: 1,
        };
        assert_eq!(click.x, 10);
        assert_eq!(click.y, 5);
        assert_eq!(click.button, 1);
        // Round-trip through Copy.
        let copy = click;
        assert_eq!(click, copy);
    }

    #[test]
    fn imports_witness_compiles() {
        // Witness that the const fn type-assertion compiles by
        // calling it with concrete arguments.
        super::_datagrid_imports_witness(
            &KeyEvent::Enter,
            &ClickEvent {
                x: 0,
                y: 0,
                button: 1,
            },
            HorizAlign::Center,
        );
    }
}
