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
// tui_panel: bordered container widget with optional title.
//
// Ported from `tui_panel.inc` (641 lines of FASM assembly). The panel
// is the foundational TUI container: it is visually a [`TuiBackground`]
// with a one-cell box border drawn around the periphery and an optional
// title label overlaid on the top border row, bracketed by tee
// connectors so the box corners remain visually closed. User children
// — appended via [`Widget::append_child`] — are routed into a "guts"
// container that occupies the interior of the box, never overlapping
// the border.
//
// FASM struct layout (`tui_panel.inc` lines 47–53):
//
//   tui_panel_title_ofs       = tui_background_size + 0
//   tui_panel_titlecolors_ofs = tui_background_size + 8
//   tui_panel_titletext_ofs   = tui_background_size + 16
//   tui_panel_guts_ofs        = tui_background_size + 24
//   tui_panel_user_ofs        = tui_background_size + 32  ; descendants only
//   tui_panel_size            = tui_background_size + 40

//! TUI panel — bordered container with optional title.
//!
//! Architecture: `background + box border + title overlay + 'guts'
//! interior child container`. Corresponds to FASM `tui_panel.inc`
//! (641 lines). Vtable overrides 8 of the 37 base slots from
//! [`crate::tui::object::Widget`]; the remaining 29 inherit the trait
//! default behavior.
//!
//! ## Internal composition
//!
//! A panel's [`WidgetState::children`] list is **not** flat; it is a
//! three-element border-reservation tree built lazily by
//! [`TuiPanel::nvsetup`]:
//!
//! ```text
//! TuiPanel (layout = Vertical)
//! ├─ leading hspacer  (100% wide × 1 cell)        — top border placeholder
//! ├─ hbox            (100% wide × 100% tall, layout = Horizontal)
//! │  ├─ leading vspacer  (1 cell × 100% tall)     — left border placeholder
//! │  ├─ guts container   (100% × 100%, layout = None)
//! │  └─ trailing vspacer (1 cell × 100% tall)     — right border placeholder
//! └─ trailing hspacer (100% wide × 1 cell)        — bottom border placeholder
//! ```
//!
//! User code calls [`Widget::append_child`] on the panel; the override
//! routes the child into `guts.state.children` rather than
//! `panel.state.children`. The four spacers reserve a one-cell margin
//! around the interior so that the border characters drawn by
//! [`TuiPanel::nvbox`] do not collide with child content during render.
//!
//! ## Title overlay
//!
//! When the constructor receives a non-empty `title`, [`nvsetup`]
//! builds a centered single-row [`TuiLabel`] of width `chars+2` and
//! stores it in [`titletext`](TuiPanel::titletext) (the +2
//! accommodates the bracketing tee characters). The title is **not**
//! a child of the panel; it is rendered directly in
//! [`Widget::draw`] using absolute byte-offset writes onto the panel's
//! top-border row, surrounded by a left tee (┤, U+2524) before and a
//! right tee (├, U+251C) after — matching FASM `tui_panel$draw`
//! (`tui_panel.inc` lines 483–577).
//!
//! ## Cloning
//!
//! [`Widget::clone_widget`] follows FASM `tui_panel$init_copy`
//! (`tui_panel.inc` lines 62–109): the inherited [`WidgetState`] is
//! deep-cloned (which clones the entire `[hspacer, hbox, hspacer]`
//! children tree polymorphically), then a fresh [`TuiLabel`] is
//! constructed for the cloned title. The title string is owned by the
//! [`String`] field; Rust's [`String::clone`] is used in lieu of FASM
//! `string$copy`. The descendant `user` field is **not** cloned;
//! subclasses (e.g. progress-box, text-box, auth-panel) override
//! [`Widget::clone_widget`] themselves to re-establish their own
//! user-data slot.
//!
//! [`TuiBackground`]: crate::tui::widgets::background::TuiBackground

use std::any::Any;
use std::sync::Arc;

use crate::config::ACS_LINECHARS;
use crate::error::TuiError;
use crate::tui::ansi;
use crate::tui::geometry::Rect;
use crate::tui::object::{ColorPair, KeyEvent, Layout, Widget, WidgetState};
use crate::tui::render::Renderer;
use crate::tui::widgets::label::{TextAlign, TuiLabel};

// ============================================================================
// PanelContainer — internal invisible Widget for the hbox and guts roles
// ============================================================================

/// Internal helper widget used for the panel's middle `hbox` and its
/// `guts` interior container.
///
/// `PanelContainer` is the Rust analog of the bare `tui_object_size`
/// blocks that FASM `tui_panel$nvsetup` allocates at lines 145–183 for
/// the hbox and guts — each is a [`crate::tui::object::Widget`] with
/// the [`crate::tui::object::Widget::draw`] vmethod set to a no-op
/// (FASM `tui_object$simple_vtable`'s draw entry). The container does
/// not paint; it exists solely to host children with a chosen
/// [`Layout`] orientation.
///
/// FASM parallel: `tui_panel$nvsetup` (`tui_panel.inc` lines 144–148
/// for the hbox; lines 167–173 for the guts).
///
/// # Visibility
///
/// The struct and its constructor are `pub(crate)` because the
/// children-tree assembly in [`TuiPanel::nvsetup`] is the only
/// expected use site. External callers should construct user-visible
/// containers via [`crate::tui::widgets::spacers::VBox`] or analogous
/// dedicated widgets.
pub(crate) struct PanelContainer {
    /// Inherited base state (the only field the container owns; FASM
    /// allocates a bare `tui_object_size` block with no extra fields).
    pub(crate) state: WidgetState,
}

impl PanelContainer {
    /// Construct a percentage-sized container with the requested
    /// [`Layout`] orientation.
    ///
    /// FASM equivalent: `heap$alloc(tui_object_size)` followed by
    /// `tui_object$init_dd(self, width_perc, height_perc)` then
    /// `mov [tui_layout_ofs], <layout>` (`tui_panel.inc` lines 144–148
    /// for the hbox case; lines 167–173 for the guts case).
    pub(crate) fn new(width_perc: f64, height_perc: f64, layout: Layout) -> Arc<Self> {
        let mut state = WidgetState::new();
        state.width = 0;
        state.height = 0;
        state.width_percent = Some(width_perc);
        state.height_percent = Some(height_perc);
        state.layout = layout;
        Arc::new(Self { state })
    }
}

impl Widget for PanelContainer {
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

    /// Deep-clone via [`clone_widget_state`] which polymorphically
    /// clones the children tree (FASM `tui_object$init_copy` semantics).
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        let cloned_state = clone_widget_state(&self.state)?;
        Ok(Arc::new(Self { state: cloned_state }) as Arc<dyn Widget>)
    }
}

// ============================================================================
// TuiPanel — bordered container with optional title
// ============================================================================

/// Bordered container with optional title — the foundational TUI
/// container widget.
///
/// Inherits the rendering / layout / cursor-event behavior of
/// [`crate::tui::widgets::background::TuiBackground`] (which itself
/// inherits [`crate::tui::object::Widget`]) and adds:
///
/// * [`title`](Self::title) — optional title string (FASM
///   `tui_panel_title_ofs`).
/// * [`titlecolors`](Self::titlecolors) — color pair applied to the
///   title text (FASM `tui_panel_titlecolors_ofs`).
/// * [`titletext`](Self::titletext) — the [`TuiLabel`] used to paint
///   the title; `None` when [`title`](Self::title) is empty (FASM
///   `tui_panel_titletext_ofs`).
/// * [`user`](Self::user) — descendant-private user-data slot (FASM
///   `tui_panel_user_ofs`, used by `tui_progressbox`, `tui_textbox`,
///   `tui_simpleauth`, `tui_authpanel`).
///
/// The panel does **not** store a separate `guts` field. The interior
/// container is always reachable as
/// `self.state.children[1].state().children[1]` (i.e. the second
/// child of the middle hbox); this matches FASM
/// `tui_panel$init_copy`'s rebinding logic at lines 96–105 and avoids
/// the [`Arc`] aliasing problem that a stored guts pointer would
/// create (since [`Arc::get_mut`] requires unique ownership).
pub struct TuiPanel {
    /// Inherited base widget state (children list, bounds, layout,
    /// text/attribute buffers, etc.). FASM offsets `tui_object_size`
    /// bytes from the start of the struct; tuipanel-specific fields
    /// follow at `tui_background_size + N`.
    pub(crate) state: WidgetState,
    /// Background fill character (Unicode codepoint). 0 = skip text
    /// fill in [`Widget::draw`] (attribute fill always applies).
    /// FASM offset: `tui_bgfillchar_ofs = tui_object_size + 0`.
    pub bgfillchar: u32,
    /// Color pair applied to the panel's interior on every render.
    /// FASM offset: `tui_bgcolors_ofs = tui_object_size + 8`.
    pub bgcolors: ColorPair,
    /// Owned title string. Empty when no title was supplied at
    /// construction. FASM offset: `tui_panel_title_ofs`. The Rust
    /// [`String`] owns its bytes; FASM stores a pointer to a heap
    /// `string$copy` allocation.
    pub(crate) title: String,
    /// Color pair applied to the title text. FASM offset:
    /// `tui_panel_titlecolors_ofs`.
    pub(crate) titlecolors: ColorPair,
    /// [`TuiLabel`] that renders the title text on the top border row
    /// during [`Widget::draw`]. `None` when [`Self::title`] is empty.
    /// FASM offset: `tui_panel_titletext_ofs`. The label is **not** a
    /// child of `self` — it is referenced via this field and drawn
    /// inline by [`Self::draw_title_overlay`] using direct text-buffer
    /// memcopies.
    pub(crate) titletext: Option<Arc<TuiLabel>>,
    /// Descendant-private user-data slot. FASM offset:
    /// `tui_panel_user_ofs`. The base `tui_panel$cleanup` deliberately
    /// does **not** free this; descendants override `cleanup` to
    /// release their own user-data type.
    pub(crate) user: Option<Box<dyn Any + Send + Sync>>,
}

/// Public alias preserving the prompt's `Panel` export name.
///
/// All inherent methods on [`TuiPanel`] are reachable through this
/// alias; no separate type definition exists.
pub type Panel = TuiPanel;

// ============================================================================
// Constructors — five FASM `tui_panel$new_*` entry points
// ============================================================================

impl TuiPanel {
    /// Construct a panel from an explicit [`Rect`] with the supplied
    /// fill character, fill colors, and optional title.
    ///
    /// FASM equivalent: `tui_panel$new_rect` (`tui_panel.inc`
    /// lines 215–243).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if pre-allocation of the panel's
    /// text/attribute buffers fails or if construction of the title
    /// label (when `title` is non-empty) fails.
    pub fn new_rect(
        bounds: Rect,
        fillchar: u32,
        fill_colors: ColorPair,
        title: &str,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.bounds = bounds;
        state.width = bounds.width();
        state.height = bounds.height();
        state.width_percent = None;
        state.height_percent = None;
        Self::finalize_init(state, fillchar, fill_colors, title)
    }

    /// Construct a panel from absolute integer dimensions. FASM
    /// equivalent: `tui_panel$new_ii` (`tui_panel.inc` lines 246–276).
    ///
    /// # Errors
    ///
    /// See [`Self::new_rect`].
    pub fn new_ii(
        width: i32,
        height: i32,
        fillchar: u32,
        fill_colors: ColorPair,
        title: &str,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = height;
        state.width_percent = None;
        state.height_percent = None;
        Self::finalize_init(state, fillchar, fill_colors, title)
    }

    /// Construct a panel with absolute integer width and percentage
    /// height. FASM equivalent: `tui_panel$new_id` (`tui_panel.inc`
    /// lines 279–311).
    ///
    /// # Errors
    ///
    /// See [`Self::new_rect`].
    pub fn new_id(
        width: i32,
        height_perc: f64,
        fillchar: u32,
        fill_colors: ColorPair,
        title: &str,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = 0;
        state.width_percent = None;
        state.height_percent = Some(height_perc);
        Self::finalize_init(state, fillchar, fill_colors, title)
    }

    /// Construct a panel with percentage width and absolute integer
    /// height. FASM equivalent: `tui_panel$new_di` (`tui_panel.inc`
    /// lines 314–346).
    ///
    /// # Errors
    ///
    /// See [`Self::new_rect`].
    pub fn new_di(
        width_perc: f64,
        height: i32,
        fillchar: u32,
        fill_colors: ColorPair,
        title: &str,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = 0;
        state.height = height;
        state.width_percent = Some(width_perc);
        state.height_percent = None;
        Self::finalize_init(state, fillchar, fill_colors, title)
    }

    /// Construct a panel with both dimensions specified as
    /// percentages of the parent. FASM equivalent: `tui_panel$new_dd`
    /// (`tui_panel.inc` lines 349–383).
    ///
    /// # Errors
    ///
    /// See [`Self::new_rect`].
    pub fn new_dd(
        width_perc: f64,
        height_perc: f64,
        fillchar: u32,
        fill_colors: ColorPair,
        title: &str,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = 0;
        state.height = 0;
        state.width_percent = Some(width_perc);
        state.height_percent = Some(height_perc);
        Self::finalize_init(state, fillchar, fill_colors, title)
    }

    /// Common constructor tail: pre-allocate buffers (when both
    /// dimensions are absolute and positive), build the internal
    /// child tree via [`Self::nvsetup`], and wrap in [`Arc`].
    ///
    /// FASM parallel: lines 230–243 of `new_rect`, repeated by each of
    /// the five `new_*` entry points after dimension setup.
    fn finalize_init(
        mut state: WidgetState,
        fillchar: u32,
        fill_colors: ColorPair,
        title: &str,
    ) -> Result<Arc<Self>, TuiError> {
        // FASM allocates and zero-fills the text/attribute buffers
        // when both width and height are positive (i.e. fully known
        // at construction). Percentage-sized dimensions defer
        // allocation until `nvfill` is reached during the layout
        // pass; the buffers grow at first paint.
        pre_allocate_buffers(&mut state)?;
        let mut panel = Self {
            state,
            bgfillchar: fillchar,
            bgcolors: fill_colors,
            title: String::new(),
            titlecolors: fill_colors,
            titletext: None,
            user: None,
        };
        panel.nvsetup(title)?;
        Ok(Arc::new(panel))
    }
}

// ============================================================================
// nvsetup — build the internal `[hspacer, hbox(vspacer, guts, vspacer), hspacer]`
//          three-element child tree
// ============================================================================

impl TuiPanel {
    /// Build the panel's internal border-reservation tree and the
    /// optional title label.
    ///
    /// FASM equivalent: `tui_panel$nvsetup` (`tui_panel.inc`
    /// lines 111–203). Mutates `self` in place — sets the layout to
    /// [`Layout::Vertical`], appends the three border-reservation
    /// children directly into [`WidgetState::children`] (bypassing
    /// [`Widget::append_child`] to avoid the guts-routing override),
    /// and constructs the [`titletext`](Self::titletext) label when
    /// `title` is non-empty.
    ///
    /// # Internal tree shape
    ///
    /// ```text
    /// self (layout = Vertical)
    /// ├─ TuiHSpacer (100% wide × 1 tall)        — top border row
    /// ├─ PanelContainer (100% × 100%, layout = Horizontal)  — middle hbox
    /// │  ├─ TuiVSpacer (1 wide × 100% tall)     — left border column
    /// │  ├─ PanelContainer (100% × 100%)        — guts (interior)
    /// │  └─ TuiVSpacer (1 wide × 100% tall)     — right border column
    /// └─ TuiHSpacer (100% wide × 1 tall)        — bottom border row
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when [`TuiLabel::new_ii`] fails
    /// for a non-empty title (the spacer / container constructors
    /// themselves are infallible).
    fn nvsetup(&mut self, title: &str) -> Result<(), TuiError> {
        // FASM line 113: `mov dword [rdi + tui_layout_ofs], tui_layout_vertical`.
        self.state.layout = Layout::Vertical;

        // FASM lines 121–126: leading hspacer (100% wide × 1 tall) —
        // reserves the top border row.
        let leading_hspacer: Arc<dyn Widget> = crate::tui::widgets::spacers::TuiHSpacer::new_d(100.0)?;

        // FASM lines 144–148 + 154–161: middle hbox (100% × 100%,
        // layout = Horizontal) hosting the [vspacer, guts, vspacer]
        // triple.
        let mut hbox = PanelContainer::new(100.0, 100.0, Layout::Horizontal);

        // FASM lines 152–161 + 158–166: leading vspacer (1 wide × 100%
        // tall) — reserves the left border column.
        let leading_vspacer: Arc<dyn Widget> = crate::tui::widgets::spacers::TuiVSpacer::new_d(100.0)?;

        // FASM lines 167–173: guts container (100% × 100%, default
        // [`Layout::None`]) — user children land here via the
        // [`Widget::append_child`] override.
        let guts: Arc<dyn Widget> = PanelContainer::new(100.0, 100.0, Layout::None);

        // FASM lines 178–187: trailing vspacer (1 wide × 100% tall) —
        // reserves the right border column.
        let trailing_vspacer: Arc<dyn Widget> = crate::tui::widgets::spacers::TuiVSpacer::new_d(100.0)?;

        // Populate the hbox's children list directly. The hbox is
        // still solely owned at this point (no clone has been made),
        // so [`Arc::get_mut`] is guaranteed to succeed.
        {
            let hbox_mut = Arc::get_mut(&mut hbox).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "panel nvsetup: hbox Arc unexpectedly aliased",
                ))
            })?;
            hbox_mut.state.children.push_back(leading_vspacer);
            hbox_mut.state.children.push_back(guts);
            hbox_mut.state.children.push_back(trailing_vspacer);
        }

        // FASM lines 189–195: trailing hspacer — reserves the bottom
        // border row.
        let trailing_hspacer: Arc<dyn Widget> = crate::tui::widgets::spacers::TuiHSpacer::new_d(100.0)?;

        // Append the three top-level children directly into
        // [`self.state.children`] — bypassing [`Self::append_child`]
        // (which would route the children into guts and break the
        // border layout entirely).
        self.state.children.push_back(leading_hspacer);
        let hbox_dyn: Arc<dyn Widget> = hbox;
        self.state.children.push_back(hbox_dyn);
        self.state.children.push_back(trailing_hspacer);

        // FASM lines 197–203: build the title label only when the
        // string is non-empty. The label is sized to the title's
        // character count plus 2 cells of bracket padding (left tee +
        // text + right tee) and is rendered with center alignment so
        // the text is horizontally centered within its own bounds —
        // not within the panel's bounds (the bracket connectors
        // outside the label provide the visual flush).
        if !title.is_empty() {
            self.title = title.to_string();
            let label_width = title.chars().count() as i32 + 2;
            let label = TuiLabel::new_ii(label_width, 1, title, self.titlecolors, TextAlign::Center)?;
            self.titletext = Some(label);
        }

        Ok(())
    }
}

// ============================================================================
// Public setters and accessors
// ============================================================================

impl TuiPanel {
    /// Install or remove the descendant-private user-data slot.
    ///
    /// FASM parallel: descendants store an opaque pointer at
    /// `tui_panel_user_ofs` and read it via inline pointer
    /// arithmetic. The base `tui_panel$cleanup` deliberately does
    /// **not** touch this slot; descendants override `cleanup` to
    /// release their own user-data type.
    pub fn set_user(&mut self, user: Option<Box<dyn Any + Send + Sync>>) {
        self.user = user;
    }

    /// Toggle the [`WidgetState::drop_shadow`] flag controlling the
    /// renderer's drop-shadow effect.
    ///
    /// Mirrors descendants of FASM `tui_panel` that flip this bit
    /// (e.g. dialog widgets, splash widgets).
    pub fn set_drop_shadow(&mut self, enabled: bool) {
        self.state.drop_shadow = enabled;
    }

    /// Replace the panel's title.
    ///
    /// Empty strings drop the existing [`titletext`](Self::titletext)
    /// label; non-empty strings rebuild a fresh label with the
    /// current [`titlecolors`](Self::titlecolors). FASM parallel:
    /// `tui_panel$set_title` (`tui_panel.inc` lines 414–453).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when [`TuiLabel::new_ii`] fails
    /// for a non-empty replacement title.
    pub fn set_title(&mut self, new_title: &str) -> Result<(), TuiError> {
        self.title = new_title.to_string();
        if new_title.is_empty() {
            self.titletext = None;
        } else {
            let label_width = new_title.chars().count() as i32 + 2;
            let label = TuiLabel::new_ii(label_width, 1, new_title, self.titlecolors, TextAlign::Center)?;
            self.titletext = Some(label);
        }
        Ok(())
    }

    /// Replace the title's color pair, rebuilding [`titletext`] when
    /// the title string is non-empty so the new colors take effect on
    /// the next paint.
    ///
    /// FASM parallel: `tui_panel$set_titlecolors` (`tui_panel.inc`
    /// lines 456–478).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when [`TuiLabel::new_ii`] fails
    /// while rebuilding the label.
    pub fn set_title_colors(&mut self, colors: ColorPair) -> Result<(), TuiError> {
        self.titlecolors = colors;
        if !self.title.is_empty() {
            let label_width = self.title.chars().count() as i32 + 2;
            let label = TuiLabel::new_ii(label_width, 1, &self.title, colors, TextAlign::Center)?;
            self.titletext = Some(label);
        }
        Ok(())
    }

    /// Borrow the guts (interior) container as a [`Widget`] reference.
    ///
    /// `guts` is structurally `self.state.children[1].state().children[1]`
    /// — the second child of the middle hbox. Returns `None` only
    /// when the panel has been cleaned up (children list cleared).
    pub fn guts(&self) -> Option<&Arc<dyn Widget>> {
        let hbox = self.state.children.get(1)?;
        hbox.state().children.get(1)
    }

    /// Membership test against the guts' children list.
    ///
    /// FASM `tui_panel$contains` (`tui_panel.inc` lines 581–602)
    /// delegates to the guts' children list to test whether `child`
    /// is currently mounted inside the panel. The Rust [`Widget`]
    /// trait reserves [`Widget::contains`] for the geometric
    /// hit-test (cursor in bounds), so this membership test is
    /// exposed as an inherent method.
    pub fn contains_child(&self, child: &Arc<dyn Widget>) -> bool {
        match self.guts() {
            Some(guts) => guts.state().children.iter().any(|c| Arc::ptr_eq(c, child)),
            None => false,
        }
    }

    /// Borrow the `index`-th child of the guts' children list, or
    /// `None` when the index is out of range or the panel has no guts.
    pub fn get_child(&self, index: usize) -> Option<&Arc<dyn Widget>> {
        self.guts()?.state().children.get(index)
    }

    /// Typed clone — returns [`Arc<TuiPanel>`] directly rather than
    /// [`Arc<dyn Widget>`].
    ///
    /// Performs a direct typed clone (mirroring
    /// [`Widget::clone_widget`]) without going through trait dispatch
    /// and without an unsafe pointer downcast: the inherited
    /// [`WidgetState`] is deep-cloned via [`clone_widget_state`], a
    /// fresh [`TuiLabel`] is rebuilt for the title (matching FASM
    /// `tui_panel$init_copy` lines 96–105 which do not deep-copy the
    /// label — they construct a new one — see also the parallel
    /// pattern in [`crate::tui::widgets::label::TuiLabel::clone_widget`]),
    /// and the descendant `user` slot is reset to `None` (descendants
    /// override [`Widget::clone_widget`] to re-establish their own
    /// user-data type).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when [`clone_widget_state`] or
    /// [`TuiLabel::new_ii`] fails.
    pub fn clone_as_panel(&self) -> Result<Arc<TuiPanel>, TuiError> {
        let cloned_state = clone_widget_state(&self.state)?;
        let titletext = if self.title.is_empty() {
            None
        } else {
            let label_width = self.title.chars().count() as i32 + 2;
            Some(TuiLabel::new_ii(
                label_width,
                1,
                &self.title,
                self.titlecolors,
                TextAlign::Center,
            )?)
        };
        Ok(Arc::new(TuiPanel {
            state: cloned_state,
            bgfillchar: self.bgfillchar,
            bgcolors: self.bgcolors,
            title: self.title.clone(),
            titlecolors: self.titlecolors,
            titletext,
            user: None,
        }))
    }

    /// Forward a synthetic key event to the panel.
    ///
    /// `tui_panel` does not override `tui_object$key_event`, so this
    /// inherent method simply invokes the [`Widget::key_event`] trait
    /// default (which returns `false` to bubble the event). The
    /// method exists to satisfy the [`Panel`] export schema.
    pub fn key_event(&mut self, event: KeyEvent) -> bool {
        <Self as Widget>::key_event(self, event)
    }
}

// ============================================================================
// Widget trait implementation — 8 vmethod overrides
// ============================================================================

impl Widget for TuiPanel {
    fn state(&self) -> &WidgetState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Override slot 0 — FASM `tui_panel$cleanup` (`tui_panel.inc`
    /// lines 380–411).
    ///
    /// Drops the title string and the optional title label first
    /// (the label's own [`Widget::cleanup`] is invoked through
    /// [`Drop`] on the [`Arc`]) and then inlines the
    /// [`Widget::cleanup`] trait-default body — clearing the
    /// children list, the bastards list, and the text /
    /// attribute / display-name buffers. The descendant `user`
    /// field is intentionally left untouched; descendants override
    /// `cleanup` to release their own user-data type.
    fn cleanup(&mut self) {
        // Step 1: drop title-specific resources first. FASM frees
        // the title string then frees the title label allocation;
        // the Rust analog is to drop the [`Arc`]/[`String`]
        // allocations explicitly so they release before the children
        // list does.
        self.title = String::new();
        self.titletext = None;

        // Step 2: inline the trait-default cleanup body. We do
        // **not** call `Widget::cleanup(self)` recursively because
        // that would re-enter this same method via vtable dispatch
        // (the same anti-recursion fix applied in
        // [`crate::tui::widgets::label::TuiLabel::cleanup`]).
        self.state.children.clear();
        self.state.bastards.clear();
        self.state.text.clear();
        self.state.attributes.clear();
        self.state.display_name.clear();
    }

    /// Override slot 1 — FASM `tui_panel$init_copy` (`tui_panel.inc`
    /// lines 62–109). Deep-clones the panel including its border
    /// children and rebuilds a fresh title label.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        let cloned = self.clone_as_panel()?;
        Ok(cloned as Arc<dyn Widget>)
    }

    /// Override slot 2 — FASM `tui_panel$draw` (`tui_panel.inc`
    /// lines 483–577).
    ///
    /// Performs four steps in order:
    ///
    /// 1. Bail out when either dimension is zero (FASM lines 484–489).
    /// 2. Run the inherited background fill — write `bgfillchar` and
    ///    `bgcolors` across the entire text/attribute buffers
    ///    (matches the FASM `call tui_background$nvfill` at
    ///    line 491).
    /// 3. Paint the box border into the buffers via
    ///    [`Self::nvbox`] (FASM `tui_panel$nvbox` at line 493).
    /// 4. Overlay the title (when [`titletext`](Self::titletext)
    ///    is set and there is room) via
    ///    [`Self::draw_title_overlay`] (FASM lines 495–566).
    ///
    /// Children are rendered by the engine's display-list update
    /// pass after [`Widget::draw`] returns; this method does **not**
    /// recurse into the spacers/hbox/guts subtree.
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        let width = self.state.width;
        let height = self.state.height;

        // Step 1: zero-sized panel renders nothing.
        if width <= 0 || height <= 0 {
            return Ok(());
        }
        // Refuse to draw before [`pre_allocate_buffers`] has been
        // run (the layout pass guarantees this for percentage-sized
        // panels by populating absolute dimensions and reaching
        // `nvfill`).
        if self.state.text.is_empty() {
            return Ok(());
        }

        // Step 2: inherited background fill.
        nvfill(&mut self.state, self.bgfillchar, self.bgcolors)?;

        // Step 3: box border.
        self.nvbox()?;

        // Step 4: title overlay (only when there is a label and at
        // least the top border row's full width is addressable).
        if self.titletext.is_some() {
            self.draw_title_overlay()?;
        }

        Ok(())
    }

    /// Override slot 28 — FASM `tui_panel$append_child`
    /// (`tui_panel.inc` lines 580–597).
    ///
    /// Routes the child into the guts container's children list
    /// (preserving the border) instead of appending it directly to
    /// `self.state.children`. Silently no-ops when the panel's
    /// internal tree is malformed (e.g. cleaned-up panel) or when
    /// [`Arc::get_mut`] fails on the hbox or guts (i.e. another
    /// strong reference exists).
    fn append_child(&mut self, child: Arc<dyn Widget>) {
        if let Some(guts_mut) = guts_get_mut(&mut self.state) {
            guts_mut.append_child(child);
        }
    }

    /// Override slot 30 — FASM `tui_panel$prepend_child`
    /// (`tui_panel.inc` lines 599–614). See [`Self::append_child`]
    /// for the routing semantics.
    fn prepend_child(&mut self, child: Arc<dyn Widget>) {
        if let Some(guts_mut) = guts_get_mut(&mut self.state) {
            guts_mut.prepend_child(child);
        }
    }

    /// Override slot 32 — FASM `tui_panel$get_child_index`
    /// (`tui_panel.inc` lines 616–633). Looks up `child` in the
    /// guts container's children list; returns `None` when the
    /// panel is malformed or `child` is not mounted.
    fn get_child_index(&self, child: &Arc<dyn Widget>) -> Option<usize> {
        let guts = self.guts()?;
        guts.state().children.iter().position(|c| Arc::ptr_eq(c, child))
    }

    /// Override slot 33 — FASM `tui_panel$remove_child`
    /// (`tui_panel.inc` lines 635–641). Removes the [`Arc::ptr_eq`]
    /// match from the guts container's children list.
    fn remove_child(&mut self, child: &Arc<dyn Widget>) -> bool {
        let Some(guts_mut) = guts_get_mut(&mut self.state) else {
            return false;
        };
        guts_mut.remove_child(child)
    }
}

// ============================================================================
// nvbox + draw_title_overlay — buffer-based border / title rendering
// ============================================================================

impl TuiPanel {
    /// Paint a one-cell box border into the panel's text buffer.
    ///
    /// FASM equivalent: `tui_panel$nvbox` (`tui_panel.inc`
    /// lines 587–648 in the version distributed with this repo;
    /// the call is dispatched from `tui_panel$draw` line 493).
    /// FASM also uses `tui_object$nvbox` as a generic helper —
    /// both follow the same algorithm of stamping the four
    /// corners, the two horizontal edges, and the two vertical
    /// edges with the appropriate Unicode codepoints.
    ///
    /// The codepoints written are listed in [`crate::tui::ansi`];
    /// the [`Renderer`] flush layer translates them to ACS
    /// sequences (when [`crate::config::ACS_LINECHARS`] is set) or
    /// to UTF-8 multi-byte sequences directly.
    fn nvbox(&mut self) -> Result<(), TuiError> {
        let width = self.state.width;
        let height = self.state.height;
        if width <= 0 || height <= 0 {
            return Ok(());
        }
        let width_us = width as usize;
        let height_us = height as usize;

        // FASM `tui_object$nvbox` selects between ACS 7-bit chars
        // (`if acs_linechars`) and Unicode codepoints at compile
        // time. The Rust runtime equivalent lives here. Both paths
        // store 32-bit codepoints into the text buffer; the buffer
        // renderer is responsible for translating them to the
        // appropriate output bytes (ACS escape sequences or raw
        // UTF-8) when [`crate::config::ACS_LINECHARS`] is honored
        // by the active terminal.
        let (ulc, urc, llc, lrc, hl, vl): (u32, u32, u32, u32, u32, u32) = if ACS_LINECHARS {
            (
                u32::from(ansi::ACS_ULCORNER),
                u32::from(ansi::ACS_URCORNER),
                u32::from(ansi::ACS_LLCORNER),
                u32::from(ansi::ACS_LRCORNER),
                u32::from(ansi::ACS_HLINE),
                u32::from(ansi::ACS_VLINE),
            )
        } else {
            (
                ansi::UNICODE_ULCORNER as u32,
                ansi::UNICODE_URCORNER as u32,
                ansi::UNICODE_LLCORNER as u32,
                ansi::UNICODE_LRCORNER as u32,
                ansi::UNICODE_HLINE as u32,
                ansi::UNICODE_VLINE as u32,
            )
        };

        // Special-case width == 1: a single column means each row
        // is a single cell. We paint an interior pipe (or, when
        // height >= 2, the corners). The FASM code degrades
        // gracefully for these cases too.
        let buf = self.state.text.as_mut_slice();
        let cells = width_us
            .checked_mul(height_us)
            .ok_or_else(|| TuiError::Render(std::io::Error::other("panel nvbox: width*height overflow")))?;
        let needed_bytes = cells
            .checked_mul(4)
            .ok_or_else(|| TuiError::Render(std::io::Error::other("panel nvbox: cells*4 overflow")))?;
        if buf.len() < needed_bytes {
            return Err(TuiError::Render(std::io::Error::other(
                "panel nvbox: text buffer not pre-allocated to width*height*4",
            )));
        }

        // Helper closure: write a 32-bit codepoint at cell (row, col).
        let write_cell = |buf: &mut [u8], row: usize, col: usize, value: u32| {
            let idx = (row * width_us + col) * 4;
            let bytes = value.to_le_bytes();
            buf[idx] = bytes[0];
            buf[idx + 1] = bytes[1];
            buf[idx + 2] = bytes[2];
            buf[idx + 3] = bytes[3];
        };

        // --- Top row: ULC, HLINE * (width-2), URC -----------------
        if width_us == 1 {
            // Single-column box: top cell becomes the "top" of a
            // vertical pipe. FASM falls back to writing the corner
            // here too; we follow the same convention.
            write_cell(buf, 0, 0, ulc);
        } else {
            write_cell(buf, 0, 0, ulc);
            for col in 1..(width_us - 1) {
                write_cell(buf, 0, col, hl);
            }
            write_cell(buf, 0, width_us - 1, urc);
        }

        // --- Middle rows: VLINE on the left and right edges -------
        // FASM steps a row pointer by `width * 4` per row and
        // overwrites the leftmost and rightmost cells with VLINE.
        if height_us >= 3 {
            for row in 1..(height_us - 1) {
                write_cell(buf, row, 0, vl);
                if width_us >= 2 {
                    write_cell(buf, row, width_us - 1, vl);
                }
            }
        }

        // --- Bottom row: LLC, HLINE * (width-2), LRC --------------
        if height_us >= 2 {
            if width_us == 1 {
                write_cell(buf, height_us - 1, 0, llc);
            } else {
                write_cell(buf, height_us - 1, 0, llc);
                for col in 1..(width_us - 1) {
                    write_cell(buf, height_us - 1, col, hl);
                }
                write_cell(buf, height_us - 1, width_us - 1, lrc);
            }
        }

        Ok(())
    }

    /// Paint the title text and its bracket connectors over the
    /// existing top-border row.
    ///
    /// FASM equivalent: `tui_panel$draw` lines 495–566 — the title
    /// overlay sits on top of the top border row produced by
    /// [`Self::nvbox`]. The label has `chars+2` width: the central
    /// `chars` cells receive the label's text/attribute buffers
    /// verbatim, and the two flanking cells are overwritten with
    /// the bracket connectors so the box corners stay visually
    /// closed.
    ///
    /// Position calculation matches the FASM byte-arithmetic at
    /// lines 511–520: `((panel.width - title.width) * 2) & ~3`
    /// gives a 4-byte-aligned starting offset within the top-border
    /// row, equivalent to half the leftover space rounded down to
    /// the nearest 4-byte cell boundary (left-biased centering).
    fn draw_title_overlay(&mut self) -> Result<(), TuiError> {
        let Some(label_arc) = &self.titletext else {
            return Ok(());
        };

        let panel_width = self.state.width;
        if panel_width <= 0 {
            return Ok(());
        }
        let panel_width_us = panel_width as usize;

        // Snapshot the label's geometry / source buffers under a
        // temporary borrow so we can release the immutable borrow
        // before mutably borrowing `self.state.text`.
        let label_state = label_arc.state();
        let title_width = label_state.width;
        if title_width <= 0 {
            return Ok(());
        }
        let title_width_us = title_width as usize;
        let label_text_snapshot: Vec<u8> = label_state.text.as_slice().to_vec();
        let label_attr_snapshot: Vec<u32> = label_state.attributes.cells.clone();

        // FASM lines 511–520: compute the byte offset within the
        // top-border row where the title's text starts. `leftover`
        // is the count of cells unused after subtracting the title
        // width from the panel width. Negative leftover means
        // there is no room — FASM jumps to `.notitle`.
        let leftover = panel_width.checked_sub(title_width).unwrap_or(-1);
        if leftover < 0 {
            return Ok(());
        }
        // `leftover * 2` is the byte-distance for half the leftover
        // (each cell is 4 bytes; multiplying by 2 instead of 4
        // produces "half the leftover in bytes"); ANDing with `!3`
        // rounds down to a 4-byte cell boundary.
        let title_byte_offset = ((leftover as usize).saturating_mul(2)) & !0x3;
        let title_byte_count = title_width_us.saturating_mul(4);

        // We require enough underlying buffer for the entire top row.
        let buf = self.state.text.as_mut_slice();
        let row_byte_end = panel_width_us.saturating_mul(4);
        if buf.len() < row_byte_end {
            return Err(TuiError::Render(std::io::Error::other(
                "panel title overlay: text buffer too short for top row",
            )));
        }

        // Pick the bracket codepoints based on the same
        // ACS_LINECHARS gate used by [`Self::nvbox`].
        let (ltee, rtee): (u32, u32) = if ACS_LINECHARS {
            (u32::from(ansi::ACS_LTEE), u32::from(ansi::ACS_RTEE))
        } else {
            (ansi::UNICODE_LTEE as u32, ansi::UNICODE_RTEE as u32)
        };

        // FASM `tui_panel$draw` line 521: `r8 -= 4` to step one cell
        // before the title's start, then `cmp r8, text + 0` — only
        // write the LTEE bracket when at least one cell exists to
        // the left of the title's starting position. The bracket
        // FASM writes there is `0x2524` (LTEE — ┤, the right-facing
        // tee, which terminates a horizontal line on its right
        // side and connects to a vertical down-edge). We follow the
        // FASM-source convention: write `LTEE` BEFORE the title.
        if title_byte_offset >= 4 {
            let bracket_offset = title_byte_offset - 4;
            let bytes = ltee.to_le_bytes();
            buf[bracket_offset] = bytes[0];
            buf[bracket_offset + 1] = bytes[1];
            buf[bracket_offset + 2] = bytes[2];
            buf[bracket_offset + 3] = bytes[3];
        }

        // FASM lines 533–546: copy the title text into the row.
        // The label's text buffer has the same row-major u32-cell
        // layout as the panel's text buffer, so we memcpy
        // `title_byte_count` bytes from the label's row 0 into the
        // panel's row 0 starting at `title_byte_offset`.
        let copy_end = title_byte_offset.saturating_add(title_byte_count);
        if copy_end > row_byte_end {
            // Title would spill past the top border — clamp by
            // skipping the copy. (Should not happen because the
            // leftover check already gates on negative leftover.)
            return Ok(());
        }
        let copy_bytes = label_text_snapshot.len().min(title_byte_count);
        buf[title_byte_offset..title_byte_offset + copy_bytes]
            .copy_from_slice(&label_text_snapshot[..copy_bytes]);

        // FASM lines 555–562: write the RTEE bracket (`0x251c` —
        // ├, the left-facing tee) ONE CELL PAST the end of the
        // title text. Only do so when there is room; otherwise
        // skip (matches FASM line 561).
        let rtee_offset = title_byte_offset + title_byte_count;
        if rtee_offset + 4 <= row_byte_end {
            let bytes = rtee.to_le_bytes();
            buf[rtee_offset] = bytes[0];
            buf[rtee_offset + 1] = bytes[1];
            buf[rtee_offset + 2] = bytes[2];
            buf[rtee_offset + 3] = bytes[3];
        }

        // FASM lines 547–554: copy the title's attribute cells too,
        // so the title text inherits the title's color pair (the
        // bracket connectors keep the panel's `bgcolors` because we
        // overwrote the codepoint cells but did not touch the
        // attribute cells).
        let attr_start = title_byte_offset / 4;
        let attr_count = label_attr_snapshot.len().min(title_width_us);
        let dest_attrs = &mut self.state.attributes.cells;
        if dest_attrs.len() >= attr_start + attr_count {
            dest_attrs[attr_start..attr_start + attr_count]
                .copy_from_slice(&label_attr_snapshot[..attr_count]);
        }

        Ok(())
    }
}

// ============================================================================
// Module-private free helpers
// ============================================================================
//
// These helpers replicate the buffer-management routines in
// [`crate::tui::widgets::background`] and
// [`crate::tui::widgets::label`] verbatim. The duplication is
// intentional: each widget that owns its own [`WidgetState`] and
// renders directly into the inherited text/attribute buffers
// requires the same helpers, and FASM does the same — every
// `nvfill` / `init_copy` / `pre_allocate_buffers` lives in the file
// it is used from.

/// Pack a [`ColorPair`] into the 32-bit attribute-cell layout used
/// by the renderer.
///
/// Layout (little-endian):
///
/// ```text
/// bits 0..=7   foreground color index
/// bits 8..=15  background color index
/// bits 16..=23 SGR flags (bold, underline, ...) — zero for fills
/// bits 24..=31 reserved (zero)
/// ```
///
/// FASM equivalent: the pack at `tui_label$nvfill` and
/// `tui_background$nvfill`. Identical to the helpers in
/// [`crate::tui::widgets::background`] and
/// [`crate::tui::widgets::label`].
fn pack_color_pair(cp: ColorPair) -> u32 {
    u32::from(cp.fg) | (u32::from(cp.bg) << 8)
}

/// Pre-allocate the text and attribute buffers when both
/// dimensions are positive integers.
///
/// FASM equivalent: lines 230–243 of `tui_panel$new_rect` and the
/// matching tail of every `new_*` constructor. Mirrors
/// [`crate::tui::widgets::background::TuiBackground::finalize_init`]'s
/// pre-allocation block and the `pre_allocate_buffers` helper in
/// [`crate::tui::widgets::label`].
///
/// # Errors
///
/// Returns [`TuiError::Render`] when `width * height` or
/// `cells * 4` would overflow `usize`.
fn pre_allocate_buffers(state: &mut WidgetState) -> Result<(), TuiError> {
    if state.width <= 0 || state.height <= 0 {
        return Ok(());
    }
    let width = state.width as usize;
    let height = state.height as usize;
    let cells = width.checked_mul(height).ok_or_else(|| {
        TuiError::Render(std::io::Error::other(
            "panel pre_allocate_buffers: width * height overflow",
        ))
    })?;
    let bytes = cells.checked_mul(4).ok_or_else(|| {
        TuiError::Render(std::io::Error::other(
            "panel pre_allocate_buffers: cells * 4 overflow",
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
/// Grows the buffer when too short and truncates from the end
/// when too long. Matches the truncation semantic of
/// [`crate::ds::buffer::Buffer::truncate`] (which removes `n`
/// bytes from the end). Identical to
/// [`crate::tui::widgets::label`]'s `fill_text_buffer`.
///
/// # Errors
///
/// Returns [`TuiError::Render`] when `count * 4` would overflow
/// `usize` or when [`crate::ds::buffer::Buffer::truncate`] fails.
fn fill_text_buffer(state: &mut WidgetState, value: u32, count: usize) -> Result<(), TuiError> {
    let bytes = count.checked_mul(4).ok_or_else(|| {
        TuiError::Render(std::io::Error::other(
            "panel fill_text_buffer: count * 4 overflow",
        ))
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
                "panel fill_text_buffer: truncate failed ({e})"
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
/// Resizes the cell vector to `count`. Identical to
/// [`crate::tui::widgets::label`]'s `fill_attr_buffer`. Always
/// succeeds — the caller treats this as infallible.
fn fill_attr_buffer(state: &mut WidgetState, value: u32, count: usize) {
    state.attributes.cells.resize(count, 0);
    for cell in state.attributes.cells.iter_mut() {
        *cell = value;
    }
}

/// Apply a uniform `(bgfillchar, bgcolors)` fill to a widget's
/// text and attribute buffers.
///
/// Functional twin of `tui_background$nvfill` (FASM
/// `tui_background.inc`) — used by both the [`TuiPanel`] and the
/// `PanelContainer` interior helper. When `bgfillchar` is `0` the
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
        .ok_or_else(|| TuiError::Render(std::io::Error::other("panel nvfill: width * height overflow")))?;
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
/// [`crate::tui::widgets::label`], and
/// [`crate::tui::widgets::datagrid`].
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
    // bastards: FASM tui_object$init_copy line 274 leaves the
    // bastards list empty; we follow the same convention so a
    // freshly-cloned widget starts with no transient children.
    Ok(cloned)
}

/// Walk a panel's [`WidgetState`] to obtain a unique mutable
/// reference to the guts container.
///
/// Returns `None` when:
///
/// * the children tree is malformed (cleaned-up panel, or fewer
///   than two top-level children, or fewer than two hbox
///   children),
/// * the hbox or guts [`Arc`] is aliased elsewhere — i.e.
///   [`Arc::get_mut`] cannot acquire unique access. This case is
///   unreachable in correct usage because the panel solely owns
///   both Arcs after construction, but is treated as a soft
///   no-op (matching FASM's silent-failure convention when its
///   own pointer chain is broken).
fn guts_get_mut(state: &mut WidgetState) -> Option<&mut dyn Widget> {
    let hbox_arc = state.children.get_mut(1)?;
    let hbox_mut = Arc::get_mut(hbox_arc)?;
    let guts_arc = hbox_mut.state_mut().children.get_mut(1)?;
    Arc::get_mut(guts_arc).map(|w| w as &mut dyn Widget)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_colors() -> ColorPair {
        ColorPair { fg: 7, bg: 0 }
    }

    fn title_colors() -> ColorPair {
        ColorPair { fg: 15, bg: 4 }
    }

    // ------------------------------------------------------------------
    // Constructor smoke tests
    // ------------------------------------------------------------------

    #[test]
    fn new_ii_builds_three_top_level_children() {
        // After `nvsetup`, the panel's own children list must be
        // exactly `[leading_hspacer, hbox, trailing_hspacer]` —
        // never more, never fewer. This is the structural invariant
        // that the border layout depends on.
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("panel constructs");
        assert_eq!(panel.state.children.len(), 3);
    }

    #[test]
    fn new_ii_hbox_has_three_middle_children() {
        // The middle child (the hbox) must have exactly
        // `[leading_vspacer, guts, trailing_vspacer]`.
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("panel constructs");
        let hbox = panel.state.children.get(1).expect("middle child is the hbox");
        assert_eq!(hbox.state().children.len(), 3);
    }

    #[test]
    fn new_ii_layout_is_vertical() {
        // `nvsetup` must set the panel's layout to Vertical so the
        // three children stack as rows.
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("panel constructs");
        assert_eq!(panel.state.layout, Layout::Vertical);
    }

    #[test]
    fn new_ii_hbox_layout_is_horizontal() {
        // The middle hbox must be laid out horizontally so the
        // vspacers and guts arrange left-to-right.
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("panel constructs");
        let hbox = panel.state.children.get(1).unwrap();
        assert_eq!(hbox.state().layout, Layout::Horizontal);
    }

    #[test]
    fn new_ii_with_empty_title_has_no_titletext() {
        // An empty title string must NOT produce a title label.
        let panel =
            TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("empty-title panel constructs");
        assert!(panel.title.is_empty());
        assert!(panel.titletext.is_none());
    }

    #[test]
    fn new_ii_with_title_builds_label_of_correct_width() {
        // Non-empty title must produce a label of width `chars + 2`
        // (the +2 is reserved for the LTEE and RTEE bracket
        // connectors).
        let title = "hello";
        let panel =
            TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), title).expect("titled panel constructs");
        assert_eq!(panel.title, title);
        let label = panel
            .titletext
            .as_ref()
            .expect("titled panel must have titletext");
        assert_eq!(label.state().width, title.chars().count() as i32 + 2);
        assert_eq!(label.state().height, 1);
    }

    #[test]
    fn new_ii_with_unicode_title_uses_char_count_not_byte_count() {
        // FASM `tui_panel$nvsetup` uses character count (UTF-32
        // codepoints) to size the title label, not byte count. The
        // Rust port mirrors that with `title.chars().count()`.
        let title = "héllo";
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), title)
            .expect("unicode-title panel constructs");
        let label = panel.titletext.as_ref().unwrap();
        // 5 chars + 2 brackets = 7
        assert_eq!(label.state().width, 7);
    }

    #[test]
    fn new_rect_stores_bounds() {
        let rect = Rect::new(2, 3, 22, 13);
        let panel = TuiPanel::new_rect(rect, b' ' as u32, test_colors(), "ttl").expect("rect constructs");
        assert_eq!(panel.state.bounds, rect);
        assert_eq!(panel.state.width, rect.width());
        assert_eq!(panel.state.height, rect.height());
    }

    #[test]
    fn new_id_uses_percentage_height() {
        let panel = TuiPanel::new_id(40, 50.0, b' ' as u32, test_colors(), "").expect("id constructs");
        assert_eq!(panel.state.width, 40);
        assert!(panel.state.width_percent.is_none());
        assert_eq!(panel.state.height_percent, Some(50.0));
    }

    #[test]
    fn new_di_uses_percentage_width() {
        let panel = TuiPanel::new_di(75.0, 12, b' ' as u32, test_colors(), "").expect("di constructs");
        assert_eq!(panel.state.width_percent, Some(75.0));
        assert_eq!(panel.state.height, 12);
        assert!(panel.state.height_percent.is_none());
    }

    #[test]
    fn new_dd_uses_both_percentages() {
        let panel = TuiPanel::new_dd(80.0, 60.0, b' ' as u32, test_colors(), "").expect("dd constructs");
        assert_eq!(panel.state.width_percent, Some(80.0));
        assert_eq!(panel.state.height_percent, Some(60.0));
    }

    #[test]
    fn constructor_pre_allocates_text_and_attribute_buffers() {
        let panel = TuiPanel::new_ii(10, 4, b'.' as u32, test_colors(), "").expect("constructs");
        // 10 cols * 4 rows = 40 cells, * 4 bytes = 160 bytes
        assert_eq!(panel.state.text.len(), 160);
        assert_eq!(panel.state.attributes.cells.len(), 40);
    }

    #[test]
    fn percentage_dimensions_skip_pre_allocation() {
        // When width or height is zero (deferred to layout pass),
        // the buffers stay empty.
        let panel = TuiPanel::new_dd(50.0, 50.0, b' ' as u32, test_colors(), "").expect("dd constructs");
        assert!(panel.state.text.is_empty());
        assert!(panel.state.attributes.cells.is_empty());
    }

    // ------------------------------------------------------------------
    // append_child / prepend_child / get_child_index / remove_child
    // routing tests
    // ------------------------------------------------------------------

    fn make_test_label() -> Arc<dyn Widget> {
        TuiLabel::new_ii(4, 1, "x", test_colors(), TextAlign::Left).expect("label constructs")
            as Arc<dyn Widget>
    }

    #[test]
    fn append_child_routes_to_guts() {
        // Crucial invariant: appending a child to the panel must
        // route into the guts container — NOT into the panel's own
        // children list (which would corrupt the border layout).
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("panel constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| {
            panic!("panel still aliased after construction");
        });
        let child = make_test_label();
        panel.append_child(Arc::clone(&child));

        // Top-level children must STILL be exactly 3
        // (hspacer, hbox, hspacer) — unchanged.
        assert_eq!(panel.state.children.len(), 3);

        // The guts (panel.children[1].children[1]) must now hold
        // the appended child.
        let guts = panel.guts().expect("guts is reachable");
        assert_eq!(guts.state().children.len(), 1);
        assert!(panel.contains_child(&child));
    }

    #[test]
    fn prepend_child_routes_to_guts() {
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("panel constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| {
            panic!("panel still aliased after construction");
        });
        let child_a = make_test_label();
        let child_b = make_test_label();
        panel.append_child(Arc::clone(&child_a));
        panel.prepend_child(Arc::clone(&child_b));

        let guts = panel.guts().expect("guts is reachable");
        assert_eq!(guts.state().children.len(), 2);
        // child_b was prepended, so it should now be at index 0;
        // child_a was first appended, now at index 1.
        assert!(Arc::ptr_eq(guts.state().children.get(0).unwrap(), &child_b));
        assert!(Arc::ptr_eq(guts.state().children.get(1).unwrap(), &child_a));
    }

    #[test]
    fn get_child_index_returns_position_within_guts() {
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("panel constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| {
            panic!("panel still aliased after construction");
        });
        let child_a = make_test_label();
        let child_b = make_test_label();
        panel.append_child(Arc::clone(&child_a));
        panel.append_child(Arc::clone(&child_b));

        assert_eq!(panel.get_child_index(&child_a), Some(0));
        assert_eq!(panel.get_child_index(&child_b), Some(1));

        let unrelated = make_test_label();
        assert_eq!(panel.get_child_index(&unrelated), None);
    }

    #[test]
    fn remove_child_removes_from_guts() {
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("panel constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| {
            panic!("panel still aliased after construction");
        });
        let child = make_test_label();
        panel.append_child(Arc::clone(&child));
        assert!(panel.contains_child(&child));

        let removed = panel.remove_child(&child);
        assert!(removed);
        assert!(!panel.contains_child(&child));
        // Top-level children list still has the 3 border children.
        assert_eq!(panel.state.children.len(), 3);
    }

    #[test]
    fn get_child_returns_indexed_guts_entry() {
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("panel constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| {
            panic!("panel still aliased after construction");
        });
        let child_a = make_test_label();
        let child_b = make_test_label();
        panel.append_child(Arc::clone(&child_a));
        panel.append_child(Arc::clone(&child_b));

        assert!(Arc::ptr_eq(panel.get_child(0).unwrap(), &child_a));
        assert!(Arc::ptr_eq(panel.get_child(1).unwrap(), &child_b));
        assert!(panel.get_child(99).is_none());
    }

    // ------------------------------------------------------------------
    // Setter tests
    // ------------------------------------------------------------------

    #[test]
    fn set_user_replaces_user_slot() {
        let panel = TuiPanel::new_ii(10, 3, b' ' as u32, test_colors(), "").expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        assert!(panel.user.is_none());
        panel.set_user(Some(Box::new(42_i32)));
        let stored = panel.user.as_ref().and_then(|u| u.downcast_ref::<i32>()).copied();
        assert_eq!(stored, Some(42));
        panel.set_user(None);
        assert!(panel.user.is_none());
    }

    #[test]
    fn set_drop_shadow_toggles_state_flag() {
        let panel = TuiPanel::new_ii(10, 3, b' ' as u32, test_colors(), "").expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        assert!(!panel.state.drop_shadow);
        panel.set_drop_shadow(true);
        assert!(panel.state.drop_shadow);
        panel.set_drop_shadow(false);
        assert!(!panel.state.drop_shadow);
    }

    #[test]
    fn set_title_replaces_title_and_label() {
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "old").expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        assert_eq!(panel.title, "old");
        let original_label_width = panel.titletext.as_ref().unwrap().state().width;
        assert_eq!(original_label_width, 5); // 3 chars + 2

        panel.set_title("brand new title").unwrap();
        assert_eq!(panel.title, "brand new title");
        let new_label_width = panel.titletext.as_ref().unwrap().state().width;
        assert_eq!(new_label_width, 17); // 15 chars + 2
    }

    #[test]
    fn set_title_to_empty_drops_label() {
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "title").expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        assert!(panel.titletext.is_some());
        panel.set_title("").unwrap();
        assert!(panel.titletext.is_none());
        assert!(panel.title.is_empty());
    }

    #[test]
    fn set_title_colors_rebuilds_label() {
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "t").expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        let original_colors = panel.titlecolors;
        let new_colors = ColorPair { fg: 12, bg: 5 };
        assert_ne!(original_colors, new_colors);
        panel.set_title_colors(new_colors).unwrap();
        assert_eq!(panel.titlecolors, new_colors);
        // Label was rebuilt; new label exists.
        assert!(panel.titletext.is_some());
    }

    #[test]
    fn set_title_colors_with_empty_title_does_not_create_label() {
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        assert!(panel.titletext.is_none());
        panel.set_title_colors(title_colors()).unwrap();
        assert!(panel.titletext.is_none());
    }

    // ------------------------------------------------------------------
    // Cleanup
    // ------------------------------------------------------------------

    #[test]
    fn cleanup_clears_all_state() {
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "test").expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        panel.append_child(make_test_label());
        assert_eq!(panel.state.children.len(), 3);
        assert!(!panel.title.is_empty());
        assert!(panel.titletext.is_some());

        panel.cleanup();
        assert_eq!(panel.state.children.len(), 0);
        assert_eq!(panel.state.bastards.len(), 0);
        assert_eq!(panel.state.text.len(), 0);
        assert_eq!(panel.state.attributes.cells.len(), 0);
        assert!(panel.title.is_empty());
        assert!(panel.titletext.is_none());
    }

    // ------------------------------------------------------------------
    // Cloning
    // ------------------------------------------------------------------

    #[test]
    fn clone_widget_preserves_top_level_structure() {
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "title").expect("constructs");
        let cloned_dyn = panel.clone_widget().expect("clone succeeds");
        // Three top-level children (the border tree).
        assert_eq!(cloned_dyn.state().children.len(), 3);
        // Middle hbox has three children (vspacer, guts, vspacer).
        let cloned_hbox = cloned_dyn.state().children.get(1).unwrap();
        assert_eq!(cloned_hbox.state().children.len(), 3);
    }

    #[test]
    fn clone_as_panel_preserves_title_and_colors() {
        let title = "title";
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), title).expect("constructs");
        let cloned = panel.clone_as_panel().expect("clone succeeds");
        assert_eq!(cloned.title, title);
        assert_eq!(cloned.bgfillchar, panel.bgfillchar);
        assert_eq!(cloned.bgcolors, panel.bgcolors);
        assert_eq!(cloned.titlecolors, panel.titlecolors);
        assert!(cloned.titletext.is_some());
        assert_eq!(
            cloned.titletext.as_ref().unwrap().state().width,
            title.chars().count() as i32 + 2
        );
    }

    #[test]
    fn clone_resets_user_field() {
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        panel.set_user(Some(Box::new(42_i32)));
        assert!(panel.user.is_some());

        let cloned = panel.clone_as_panel().expect("clone succeeds");
        // FASM tui_panel$init_copy does NOT clone the user slot;
        // descendants override clone to re-establish their own.
        assert!(cloned.user.is_none());
    }

    #[test]
    fn clone_with_empty_title_omits_label() {
        let panel = TuiPanel::new_ii(20, 5, b' ' as u32, test_colors(), "").expect("constructs");
        let cloned = panel.clone_as_panel().expect("clone succeeds");
        assert!(cloned.title.is_empty());
        assert!(cloned.titletext.is_none());
    }

    // ------------------------------------------------------------------
    // Draw
    // ------------------------------------------------------------------

    /// A no-op renderer used by the draw tests. Real rendering is
    /// performed via the buffer-based path inside `nvfill`,
    /// `nvbox`, and `draw_title_overlay`; the [`Renderer`] passed
    /// into `draw` is unused by [`TuiPanel`] (FASM
    /// `tui_panel$draw` is composition-only — it writes directly
    /// to the text/attribute buffers and lets the engine flush
    /// them).
    struct StubRenderer {
        state: crate::tui::render::RenderState,
    }

    impl StubRenderer {
        fn new() -> Self {
            Self {
                state: crate::tui::render::RenderState::default(),
            }
        }
    }

    impl Renderer for StubRenderer {
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

    #[test]
    fn draw_with_zero_width_is_noop() {
        let panel = TuiPanel::new_ii(0, 5, b' ' as u32, test_colors(), "").expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        let mut renderer = StubRenderer::new();
        panel.draw(&mut renderer).expect("draw succeeds");
        // Buffers stay empty when width is zero.
        assert!(panel.state.text.is_empty());
        assert!(panel.state.attributes.cells.is_empty());
    }

    #[test]
    fn draw_with_zero_height_is_noop() {
        let panel = TuiPanel::new_ii(20, 0, b' ' as u32, test_colors(), "").expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        let mut renderer = StubRenderer::new();
        panel.draw(&mut renderer).expect("draw succeeds");
        assert!(panel.state.text.is_empty());
    }

    #[test]
    fn draw_paints_corners_and_edges() {
        // Verify the four corners of the box border match the
        // expected codepoints. The middle of the buffer should hold
        // the bgfillchar.
        let width: i32 = 8;
        let height: i32 = 4;
        let panel = TuiPanel::new_ii(width, height, b'.' as u32, test_colors(), "").expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        let mut renderer = StubRenderer::new();
        panel.draw(&mut renderer).expect("draw");

        let buf = panel.state.text.as_slice();
        let read = |row: usize, col: usize| -> u32 {
            let idx = (row * width as usize + col) * 4;
            u32::from_le_bytes([buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]])
        };

        let (ulc, urc, llc, lrc, hl, vl): (u32, u32, u32, u32, u32, u32) = if ACS_LINECHARS {
            (
                u32::from(ansi::ACS_ULCORNER),
                u32::from(ansi::ACS_URCORNER),
                u32::from(ansi::ACS_LLCORNER),
                u32::from(ansi::ACS_LRCORNER),
                u32::from(ansi::ACS_HLINE),
                u32::from(ansi::ACS_VLINE),
            )
        } else {
            (
                ansi::UNICODE_ULCORNER as u32,
                ansi::UNICODE_URCORNER as u32,
                ansi::UNICODE_LLCORNER as u32,
                ansi::UNICODE_LRCORNER as u32,
                ansi::UNICODE_HLINE as u32,
                ansi::UNICODE_VLINE as u32,
            )
        };

        // Corners
        assert_eq!(read(0, 0), ulc);
        assert_eq!(read(0, width as usize - 1), urc);
        assert_eq!(read(height as usize - 1, 0), llc);
        assert_eq!(read(height as usize - 1, width as usize - 1), lrc);
        // Top edge
        assert_eq!(read(0, 1), hl);
        // Bottom edge
        assert_eq!(read(height as usize - 1, 1), hl);
        // Vertical edges (interior row)
        assert_eq!(read(1, 0), vl);
        assert_eq!(read(1, width as usize - 1), vl);
        // Interior cell uses bgfillchar
        assert_eq!(read(1, 1), b'.' as u32);
    }

    #[test]
    fn draw_paints_title_with_brackets() {
        // Verify the title overlay places LTEE (┤) before the
        // title and RTEE (├) after it on the top border row.
        let title = "ti";
        let width: i32 = 12;
        let panel = TuiPanel::new_ii(width, 4, b'.' as u32, test_colors(), title).expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        let mut renderer = StubRenderer::new();
        panel.draw(&mut renderer).expect("draw");

        let buf = panel.state.text.as_slice();
        let read = |row: usize, col: usize| -> u32 {
            let idx = (row * width as usize + col) * 4;
            u32::from_le_bytes([buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]])
        };

        let (ltee, rtee): (u32, u32) = if ACS_LINECHARS {
            (u32::from(ansi::ACS_LTEE), u32::from(ansi::ACS_RTEE))
        } else {
            (ansi::UNICODE_LTEE as u32, ansi::UNICODE_RTEE as u32)
        };

        // Title-label width = chars().count() + 2 = 2 + 2 = 4
        // cells. Leftover = 12 - 4 = 8 cells. byte_offset =
        // ((8 * 2) & ~3) = 16. Cell 16/4 = 4. Title-label
        // (centered " ti ") occupies cells 4, 5, 6, 7. LTEE
        // bracket goes at cell 3 (one cell before the title) and
        // RTEE bracket goes at cell 8 (one cell after the title).
        assert_eq!(read(0, 3), ltee);
        assert_eq!(read(0, 8), rtee);
    }

    #[test]
    fn draw_skips_title_when_panel_too_narrow() {
        // Panel width < title.width (= chars + 2) means leftover is
        // negative → title overlay is skipped entirely; the border
        // still draws.
        let title = "this title is far too long";
        let panel = TuiPanel::new_ii(8, 4, b'.' as u32, test_colors(), title).expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        let mut renderer = StubRenderer::new();
        // Should not panic, should not error.
        panel.draw(&mut renderer).expect("draw succeeds");
        // Top-left corner is still the ULC codepoint.
        let buf = panel.state.text.as_slice();
        let cp = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let expected_ulc: u32 = if ACS_LINECHARS {
            u32::from(ansi::ACS_ULCORNER)
        } else {
            ansi::UNICODE_ULCORNER as u32
        };
        assert_eq!(cp, expected_ulc);
    }

    // ------------------------------------------------------------------
    // PanelContainer
    // ------------------------------------------------------------------

    #[test]
    fn panel_container_clone_preserves_state() {
        let container = PanelContainer::new(50.0, 50.0, Layout::Horizontal);
        let cloned = container.clone_widget().expect("clone");
        assert_eq!(cloned.state().layout, Layout::Horizontal);
        assert_eq!(cloned.state().width_percent, Some(50.0));
        assert_eq!(cloned.state().height_percent, Some(50.0));
    }

    #[test]
    fn panel_container_draw_is_noop() {
        let container = PanelContainer::new(100.0, 100.0, Layout::None);
        let mut container = Arc::try_unwrap(container).unwrap_or_else(|_| panic!("aliased"));
        let mut renderer = StubRenderer::new();
        // Should not panic, should not error.
        container.draw(&mut renderer).expect("noop draw");
    }

    // ------------------------------------------------------------------
    // Configuration sanity
    // ------------------------------------------------------------------

    #[test]
    fn acs_linechars_const_is_a_bool() {
        // The panel border code paths gate on `config::ACS_LINECHARS`;
        // this sanity check ensures the symbol resolves to a `bool`
        // at compile time and is not a runtime mutable value.
        let _: bool = ACS_LINECHARS;
    }

    #[test]
    fn key_event_returns_false_by_trait_default() {
        // `tui_panel` does not override `tui_object$key_event`, so
        // the inherent `key_event` method must surface the trait
        // default's `false` (bubble-up) verdict.
        let panel = TuiPanel::new_ii(10, 3, b' ' as u32, test_colors(), "").expect("constructs");
        let mut panel = Arc::try_unwrap(panel).unwrap_or_else(|_| panic!("aliased"));
        assert!(!panel.key_event(KeyEvent::Enter));
        assert!(!panel.key_event(KeyEvent::Char('x')));
    }
}
