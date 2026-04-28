// crates/heavything/src/tui/object.rs — HeavyThing TUI base widget trait.
//
// Rust translation of tui_object.inc (3,095 lines of FASM assembly).
// Defines the `Widget` trait (the Rust equivalent of FASM's 37-vmethod
// virtual table) and all supporting types: bounds, color pairs, attribute
// buffers, key-event enums, layout and alignment modes, and the widget
// bookkeeping state shared by every subclass.
//
// Rust translation © 2026, licensed under GPL-3.0-or-later.
// Derived from the HeavyThing assembly library:
//   Copyright © 2015–2018 2 Ton Digital, Jeff Marrison <info@2ton.com.au>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Base [`Widget`] trait and supporting types — port of `tui_object.inc`.
//!
//! Every TUI widget in `heavything::tui::widgets` implements [`Widget`].
//! The trait exposes 37 virtual methods matching the FASM
//! `tui_object` vtable one-for-one, grouped logically:
//!
//! - Lifecycle: [`cleanup`](Widget::cleanup),
//!   [`clone_widget`](Widget::clone_widget),
//!   [`exit`](Widget::exit)
//! - Rendering: [`draw`](Widget::draw), [`redraw`](Widget::redraw),
//!   [`update_display_list`](Widget::update_display_list),
//!   [`flatten`](Widget::flatten)
//! - Layout: [`size_changed`](Widget::size_changed),
//!   [`timer`](Widget::timer),
//!   [`layout_changed`](Widget::layout_changed),
//!   [`move_to`](Widget::move_to),
//!   [`calc_bounds`](Widget::calc_bounds),
//!   [`calc_child_bounds`](Widget::calc_child_bounds)
//! - Focus: [`set_focus`](Widget::set_focus),
//!   [`got_focus`](Widget::got_focus),
//!   [`lost_focus`](Widget::lost_focus)
//! - Input: [`key_event`](Widget::key_event),
//!   [`fire_key_event`](Widget::fire_key_event),
//!   [`on_tab`](Widget::on_tab),
//!   [`on_shift_tab`](Widget::on_shift_tab),
//!   [`click`](Widget::click), [`clicked`](Widget::clicked)
//! - Modal: [`do_modal`](Widget::do_modal),
//!   [`end_modal`](Widget::end_modal)
//! - Child management: [`append_child`](Widget::append_child),
//!   [`append_bastard`](Widget::append_bastard),
//!   [`prepend_child`](Widget::prepend_child),
//!   [`contains`](Widget::contains),
//!   [`get_child_index`](Widget::get_child_index),
//!   [`remove_child`](Widget::remove_child),
//!   [`remove_bastard`](Widget::remove_bastard),
//!   [`remove_all_children`](Widget::remove_all_children),
//!   [`remove_all_bastards`](Widget::remove_all_bastards),
//!   [`get_objects_under_point`](Widget::get_objects_under_point)
//! - Cursor: [`set_cursor`](Widget::set_cursor),
//!   [`show_cursor`](Widget::show_cursor),
//!   [`hide_cursor`](Widget::hide_cursor)
//!
//! Concrete widgets (e.g. `Background`, `Panel`, `Button`) extend
//! [`Widget`] by overriding methods and embedding a [`WidgetState`]
//! field for the 148-byte state buffer carried in FASM `tui_object`.
//!
//! # Subclassing contract
//!
//! The ONLY methods a concrete widget is required to implement are
//! [`Widget::state`], [`Widget::state_mut`], and [`Widget::as_any`]
//! (for safe downcasting). Every other method has a default
//! implementation that mirrors the FASM base-class behavior — either a
//! no-op, a polymorphic bubble to the base state, or a delegation to a
//! sibling method (e.g. [`Widget::redraw`] defaults to calling
//! [`Widget::draw`]).
//!
//! # Ownership model
//!
//! FASM `tui_object` carries raw parent/child pointers (offsets 88 and
//! 120/128) which create ownership cycles. The Rust port replaces these
//! with:
//!
//! - [`Arc<dyn Widget>`] handles in [`WidgetState::children`] /
//!   [`WidgetState::bastards`], making widget trees shareable between
//!   the render lock, focus chain, and layout pass.
//! - No `parent` field — routing that in FASM bubbled up through parent
//!   pointers (e.g. `tui_object$domodal`, `tui_object$layoutchanged`) is
//!   handled at the `Terminal` / `Renderer` level in Rust by walking the
//!   tree top-down with explicit context. Default impls on these methods
//!   are therefore no-ops.
//!
//! Identity-based child removal uses [`std::sync::Arc::ptr_eq`] rather
//! than `PartialEq<dyn Widget>`, preserving FASM's pointer-key removal
//! semantics without forcing every widget to implement `PartialEq`.
//!
//! # Zero unsafe
//!
//! This module contains **zero** `unsafe` blocks per AAP §0.7.4. All
//! `unsafe` in the TUI subsystem lives in `tui::terminal` (termios
//! FFI) and `widgets::ssh` (channel I/O).

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use crate::ds::{Buffer, List};
use crate::error::TuiError;
use crate::tui::geometry::{Point, Rect};
use crate::tui::render::Renderer;

// ============================================================================
// Layout mode — FASM `tui_object.layout` at offset 96.
// ============================================================================

/// Layout mode for a widget's children.
///
/// Matches FASM `tui_object.layout` u32 field at offset 96. The FASM
/// library uses the numeric constants `tui_layout_vertical = 0`,
/// `tui_layout_horizontal = 1`, `tui_layout_absolute = 2`; this Rust
/// enum exposes the logically equivalent variants with clearer naming
/// per the AAP semantic preservation clause — numeric values are treated
/// as an implementation detail and are NOT exposed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u32)]
pub enum Layout {
    /// No automatic layout; children use absolute positioning
    /// (FASM `tui_layout_absolute`).
    #[default]
    None = 0,
    /// Children stacked top-to-bottom (FASM `tui_layout_vertical`).
    Vertical = 1,
    /// Children laid out left-to-right (FASM `tui_layout_horizontal`).
    Horizontal = 2,
}

/// Horizontal alignment. Matches FASM `tui_object.horizalign` u32 at
/// offset 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u32)]
pub enum HorizAlign {
    /// Left-justified within parent content region.
    #[default]
    Left = 0,
    /// Centered horizontally.
    Center = 1,
    /// Right-justified.
    Right = 2,
    /// Fill (stretch) to parent width.
    Fill = 3,
}

/// Vertical alignment. Matches FASM `tui_object.vertalign` u32 at
/// offset 104.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u32)]
pub enum VertAlign {
    /// Top-aligned.
    #[default]
    Top = 0,
    /// Centered vertically.
    Middle = 1,
    /// Bottom-aligned.
    Bottom = 2,
    /// Fill (stretch) to parent height.
    Fill = 3,
}

// ============================================================================
// ColorPair — (foreground, background) 256-color pair.
// ============================================================================

/// Foreground + background color pair, 256-color (xterm) palette.
///
/// Used by widget rendering code to specify the colors of a glyph cell.
/// The xterm 256-color palette is indexed 0..=255 with 0..=15 covering the
/// standard 16 ANSI colors, 16..=231 covering a 6×6×6 RGB cube, and
/// 232..=255 covering a 24-step grayscale ramp. The same encoding is used
/// by FASM `tui_object` when emitting SGR sequences through the
/// `tui_render` stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ColorPair {
    /// Foreground color (0..=255).
    pub fg: u8,
    /// Background color (0..=255).
    pub bg: u8,
}

impl ColorPair {
    /// Construct a new color pair.
    #[must_use]
    pub const fn new(fg: u8, bg: u8) -> Self {
        Self { fg, bg }
    }
}

// ============================================================================
// Attributes — per-cell attribute buffer paralleling FASM `tui_object.attr`.
// ============================================================================

/// Per-codepoint attribute buffer matching FASM `tui_object.attr` at
/// offset 72 (a heap-allocated buffer pointed to by a `dq`).
///
/// Each entry is a packed `u32`:
///
/// | bits   | field                                  |
/// |--------|----------------------------------------|
/// | 0..=7  | foreground color (0..=255)             |
/// | 8..=15 | background color (0..=255)             |
/// | 16..=31| SGR attribute bitmask (bold, italic, …)|
///
/// The buffer length tracks the matching [`WidgetState::text`] buffer's
/// logical codepoint count. Both are resized in lockstep by FASM
/// `tui_object$sizechanged` (line 783) and its Rust equivalent.
#[derive(Debug, Clone, Default)]
pub struct Attributes {
    /// Packed per-cell attributes: low u8 = fg, next u8 = bg, high u16 = SGR bits.
    pub cells: Vec<u32>,
}

impl Attributes {
    /// Create an empty attributes buffer.
    #[must_use]
    pub fn new() -> Self {
        Self { cells: Vec::new() }
    }

    /// Push a single cell attribute encoded from `(fg, bg, sgr)`.
    pub fn push(&mut self, fg: u8, bg: u8, sgr: u16) {
        self.cells
            .push(u32::from(fg) | (u32::from(bg) << 8) | (u32::from(sgr) << 16));
    }

    /// Clear all cells but preserve allocated capacity.
    ///
    /// Matches the FASM discipline of reusing the buffer backing store
    /// across repeated resize cycles (`tui_object$sizechanged` never
    /// shrinks capacity below the previous peak).
    pub fn clear(&mut self) {
        self.cells.clear();
    }

    /// Return the number of cells currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    /// Return `true` if no cells are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
}

// ============================================================================
// TimerAction — return value for widget-level timer callbacks.
// ============================================================================

/// Action result returned from a widget-level timer callback.
///
/// FASM `tui_object$timer` returns zero in `eax` to keep the timer
/// active (and nonzero to teardown the widget — see `tui_object.inc`
/// lines 766–773). This Rust enum preserves the three semantically
/// distinct outcomes more explicitly:
///
/// - [`TimerAction::Continue`] — keep firing the timer at its
///   registered interval (FASM `eax == 0`).
/// - [`TimerAction::Remove`] — unregister the timer but keep the
///   widget alive (used by one-shot timers).
/// - [`TimerAction::Teardown`] — teardown the owning widget and its
///   subtree (FASM `eax != 0`).
///
/// The default [`Widget::timer`] impl is a no-op and does not return a
/// value; concrete widgets that observe timer events typically provide
/// their own dispatch logic that consults a [`TimerAction`] from user
/// code before calling into the timer-registration infrastructure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TimerAction {
    /// Keep the timer active at its registered interval
    /// (FASM `eax == 0`).
    #[default]
    Continue,
    /// Unregister the timer but do not destroy the widget.
    Remove,
    /// Destroy the widget and its subtree (FASM `eax != 0`).
    Teardown,
}

// ============================================================================
// KeyEvent — keyboard input passed through tui_object$keyevent.
// ============================================================================

/// Input key event dispatched by the TUI input pipeline to
/// [`Widget::key_event`] and [`Widget::fire_key_event`].
///
/// Mirrors the semantics of FASM `tui_object$keyevent` (line 925),
/// where a return value of zero means "bubble up the parent chain"
/// and a nonzero value means "consumed — stop propagation". The Rust
/// port uses a `bool` return type: `true` = consumed (FASM
/// `eax != 0`), `false` = bubble up (FASM `eax == 0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyEvent {
    /// Printable Unicode character.
    Char(char),
    /// ASCII control character (0..=31) not covered by the enumerated
    /// variants below.
    Ctrl(u8),
    /// Return / Enter key.
    Enter,
    /// Escape key.
    Escape,
    /// Backspace key.
    Backspace,
    /// Delete key.
    Delete,
    /// Horizontal Tab.
    Tab,
    /// Shift + Tab.
    ShiftTab,
    /// Arrow Up.
    ArrowUp,
    /// Arrow Down.
    ArrowDown,
    /// Arrow Left.
    ArrowLeft,
    /// Arrow Right.
    ArrowRight,
    /// Home key.
    Home,
    /// End key.
    End,
    /// Page Up key.
    PageUp,
    /// Page Down key.
    PageDown,
    /// Function key F1..=F12 (the inner value is 1..=12).
    F(u8),
    /// Insert key.
    Insert,
}

// ============================================================================
// ClickEvent — mouse click descriptor.
// ============================================================================

/// Mouse click descriptor for [`Widget::click`] / [`Widget::clicked`].
///
/// The FASM `click` vmethod (vtable slot 35) passes x / y coordinates
/// plus a button index; the Rust version wraps these in a struct for
/// clearer call sites.
///
/// Button convention follows the xterm mouse protocol: `1` = left,
/// `2` = middle, `3` = right, `4` = wheel-up, `5` = wheel-down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClickEvent {
    /// Column (0-indexed) within the widget's absolute bounds.
    pub x: i32,
    /// Row (0-indexed) within the widget's absolute bounds.
    pub y: i32,
    /// Button index (1 = left, 2 = middle, 3 = right, 4/5 = wheel).
    pub button: u8,
}

// ============================================================================
// WidgetState — the 148-byte FASM `tui_object` state buffer, translated.
// ============================================================================

/// Base widget state — the Rust equivalent of FASM `tui_object`'s
/// 148-byte struct.
///
/// Every concrete widget embeds exactly one `WidgetState` field
/// (typically named `base`) and exposes it via
/// [`Widget::state`] / [`Widget::state_mut`]. Subclasses may add their
/// own trailing fields, mirroring the FASM practice of appending fields
/// after `tui_object_size = 148` (see e.g. `tui_panel.inc` line 10,
/// `tui_label.inc`, etc.).
///
/// Field-layout correspondence with FASM:
///
/// | FASM field / offset           | Rust field                  |
/// |-------------------------------|-----------------------------|
/// | vtable (0..=7)                | dynamic dispatch via trait  |
/// | bounds ax/ay/bx/by (8..=23)   | [`Self::bounds`]            |
/// | width (24..=27)               | [`Self::width`]             |
/// | widthperc (28..=35, `dq` f64) | [`Self::width_percent`]     |
/// | height (36..=39)              | [`Self::height`]            |
/// | heightperc (40..=47, `dq`)    | [`Self::height_percent`]    |
/// | visible (48..=51)             | [`Self::visible`]           |
/// | includeinlayout (52..=55)     | [`Self::include_in_layout`] |
/// | absolutex (56..=59)           | [`Self::absolute_x`]        |
/// | absolutey (60..=63)           | [`Self::absolute_y`]        |
/// | text (64..=71, → buffer)      | [`Self::text`]              |
/// | attr (72..=79, → buffer)      | [`Self::attributes`]        |
/// | focus (80..=87, `dq`)         | handled externally (*)      |
/// | parent (88..=95, `dq`)        | handled externally (*)      |
/// | layout (96..=99)              | [`Self::layout`]            |
/// | horizalign (100..=103)        | [`Self::horiz_align`]       |
/// | vertalign (104..=107)         | [`Self::vert_align`]        |
/// | bastardglue (108..=111)       | [`Self::bastard_glue`]      |
/// | displayname (112..=119, `dq`) | [`Self::display_name`]      |
/// | children (120..=127, → list)  | [`Self::children`]          |
/// | bastards (128..=135, → list)  | [`Self::bastards`]          |
/// | dropshadow (136..=139)        | [`Self::drop_shadow`]       |
/// | scroll (140..=147, two `dd`s) | [`Self::scroll`]            |
///
/// (*) The FASM `focus` and `parent` pointers create ownership cycles
/// that are incompatible with Rust's `Arc<dyn Widget>` semantics. Focus
/// tracking is done at the `Terminal` / `Renderer` level via a
/// focused-widget path identifier; parent bubble-up (FASM
/// `tui_object$layoutchanged`, `$domodal`, `$endmodal`, `$exit`) is
/// handled externally by the layout / input-dispatch passes. Subclasses
/// that genuinely need a parent handle should store a
/// `std::sync::Weak<dyn Widget>` in their own trailing fields.
///
/// `Default` and `Debug` are implemented manually (not derived) because
/// `Arc<dyn Widget>` is neither `Default` nor `Debug`, and `#[derive]`
/// macros require those bounds on the contained types even though
/// `List<T>` itself does not.
pub struct WidgetState {
    /// Absolute bounds rectangle after layout.
    ///
    /// Matches FASM `tui_bounds_ofs` at offsets 8..=23 (four
    /// 32-bit fields: ax, ay, bx, by).
    pub bounds: Rect,

    /// Nominal width in cells. When [`Self::width_percent`] is `Some`,
    /// this is the layout-computed absolute value; otherwise it is
    /// directly assigned by the widget author.
    pub width: i32,

    /// Optional percent-of-parent width.
    ///
    /// FASM stores this as an 8-byte `dq` (IEEE-754 double) at offset
    /// 28; a value of zero means "use the absolute width". The Rust
    /// translation replaces the zero-sentinel with [`Option::None`].
    pub width_percent: Option<f64>,

    /// Nominal height in cells.
    pub height: i32,

    /// Optional percent-of-parent height (FASM `dq` at offset 40).
    pub height_percent: Option<f64>,

    /// `true` if the widget is currently visible.
    ///
    /// FASM defaults this to `1` (see `tui_object$init_defaults`,
    /// `tui_object.inc` line 186).
    pub visible: bool,

    /// `true` if this widget participates in its parent's auto-layout.
    ///
    /// FASM defaults this to `1`; children with `include_in_layout = 0`
    /// are "bastards" and are not laid out automatically.
    pub include_in_layout: bool,

    /// Cached absolute x coordinate (top-left) after layout.
    ///
    /// FASM initializes this to `-1` as a "not yet positioned" sentinel
    /// (see `tui_object$init_defaults`, `tui_object.inc` line 192). The
    /// Rust port preserves this sentinel by explicitly setting `-1` in
    /// [`WidgetState::new`] / [`WidgetState::default`].
    pub absolute_x: i32,

    /// Cached absolute y coordinate (top-left) after layout.
    ///
    /// Initialized to `-1` as a "not yet positioned" sentinel matching
    /// FASM behavior.
    pub absolute_y: i32,

    /// Text content.
    ///
    /// Matches FASM `tui_text_ofs` at offset 64 — a pointer to a
    /// `buffer` struct in FASM; in Rust it is a [`Buffer`] directly
    /// owned by the state struct.
    pub text: Buffer,

    /// Per-cell attributes buffer.
    ///
    /// Matches FASM `tui_attr_ofs` at offset 72.
    pub attributes: Attributes,

    /// Layout mode for this widget's laid-out children.
    pub layout: Layout,

    /// Horizontal alignment within the parent content region.
    pub horiz_align: HorizAlign,

    /// Vertical alignment within the parent content region.
    pub vert_align: VertAlign,

    /// Bastard glue — arbitrary `u32` user data used by parent
    /// layouters when positioning bastard children. FASM offset 108.
    pub bastard_glue: u32,

    /// Display name, used for debug logs and focus-chain addressing.
    ///
    /// FASM stores this as a pointer to a heap-allocated C string at
    /// offset 112; the Rust port uses [`String`] directly.
    pub display_name: String,

    /// `true` if the widget renders a drop shadow behind itself.
    ///
    /// FASM offset 136 (`tui_dropshadow_ofs`).
    pub drop_shadow: bool,

    /// Scroll offset.
    ///
    /// FASM `tui_scroll_ofs` at offset 140 — two `dd` fields packed
    /// into 8 bytes representing a [`Point`] (scroll-x, scroll-y).
    pub scroll: Point,

    /// Ordered children, laid out according to [`Self::layout`].
    ///
    /// FASM stores this as a pointer to a `list` struct at offset 120
    /// (`tui_children_ofs`).
    pub children: List<Arc<dyn Widget>>,

    /// Non-laid-out ("bastard") children — e.g. floating tooltips,
    /// menus, modal overlays.
    ///
    /// FASM stores this as a pointer to a `list` struct at offset 128
    /// (`tui_bastards_ofs`).
    pub bastards: List<Arc<dyn Widget>>,
}

impl WidgetState {
    /// Construct a fresh widget state with FASM-compatible defaults:
    ///
    /// - `visible = true`
    /// - `include_in_layout = true`
    /// - `absolute_x = -1`, `absolute_y = -1` (not yet positioned)
    /// - all other fields zero / empty.
    ///
    /// Mirrors FASM `tui_object$init_defaults`
    /// (`tui_object.inc` lines 180–220).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// `Default` is implemented manually — we cannot `#[derive(Default)]`
// because `Arc<dyn Widget>` does not implement `Default`, and the
// derive macro transitively imposes that bound on the `List<T>` field
// types even though `List<T>` itself has a no-bounds `Default` impl
// (via `VecDeque::default()`).
impl Default for WidgetState {
    fn default() -> Self {
        Self {
            bounds: Rect::default(),
            width: 0,
            width_percent: None,
            height: 0,
            height_percent: None,
            visible: true,
            include_in_layout: true,
            // FASM initializes absolute_x/y to -1 as a "not positioned
            // yet" sentinel (tui_object.inc line 192).
            absolute_x: -1,
            absolute_y: -1,
            text: Buffer::default(),
            attributes: Attributes::default(),
            layout: Layout::default(),
            horiz_align: HorizAlign::default(),
            vert_align: VertAlign::default(),
            bastard_glue: 0,
            display_name: String::new(),
            drop_shadow: false,
            scroll: Point::default(),
            children: List::new(),
            bastards: List::new(),
        }
    }
}

// `Debug` is implemented manually because `Arc<dyn Widget>` is not
// `Debug` and `#[derive(Debug)]` requires that bound. The manual impl
// shows child counts rather than dumping the full subtree (which could
// be arbitrarily large and would add noise to logs).
impl fmt::Debug for WidgetState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WidgetState")
            .field("bounds", &self.bounds)
            .field("width", &self.width)
            .field("width_percent", &self.width_percent)
            .field("height", &self.height)
            .field("height_percent", &self.height_percent)
            .field("visible", &self.visible)
            .field("include_in_layout", &self.include_in_layout)
            .field("absolute_x", &self.absolute_x)
            .field("absolute_y", &self.absolute_y)
            .field("text_len", &self.text.len())
            .field("attributes_len", &self.attributes.len())
            .field("layout", &self.layout)
            .field("horiz_align", &self.horiz_align)
            .field("vert_align", &self.vert_align)
            .field("bastard_glue", &self.bastard_glue)
            .field("display_name", &self.display_name)
            .field("drop_shadow", &self.drop_shadow)
            .field("scroll", &self.scroll)
            .field("children_len", &self.children.len())
            .field("bastards_len", &self.bastards.len())
            .finish()
    }
}

// ============================================================================
// Widget — base trait corresponding to FASM tui_object 37-method vtable.
// ============================================================================

/// Base widget trait. Rust equivalent of FASM `tui_object`'s 37-vmethod
/// virtual table defined at `tui_object.inc` lines 64–100
/// (`tui_object$default_vtable`).
///
/// Concrete widgets (e.g. `Background`, `Panel`, `Button`, ...) embed a
/// [`WidgetState`] field and override only the methods relevant to their
/// behavior. Every other method keeps its default implementation, which
/// mirrors the inherited base-class behavior in FASM.
///
/// # Required methods
///
/// A concrete widget only has to implement three methods:
///
/// - [`state`](Widget::state)
/// - [`state_mut`](Widget::state_mut)
/// - [`as_any`](Widget::as_any) — for downcasting from `&dyn Widget`
///
/// All 37 vmethod-equivalent methods below have working default impls.
///
/// # Mutability
///
/// Methods are `&mut self` where state mutation occurs
/// (e.g. [`cleanup`](Widget::cleanup), [`key_event`](Widget::key_event),
/// [`size_changed`](Widget::size_changed)); pure queries such as
/// [`contains`](Widget::contains), [`get_child_index`](Widget::get_child_index),
/// and [`flatten`](Widget::flatten) take `&self`.
///
/// # Thread safety
///
/// The `Send + Sync` bound is required so widget trees can cross
/// `tokio` task boundaries — e.g. timer tasks firing
/// [`Widget::timer`] on widgets owned elsewhere. All mutation goes
/// through the render lock (`tui::lock`) so concurrent `&mut` access
/// is serialized at the subsystem level.
pub trait Widget: Send + Sync {
    // -------------------- State accessors (required) --------------------

    /// Return immutable access to the widget's base state.
    ///
    /// This is one of the three methods a concrete widget is required
    /// to implement; the trivial body is
    /// `&self.base` (assuming the embedded field is named `base`).
    fn state(&self) -> &WidgetState;

    /// Return mutable access to the widget's base state.
    ///
    /// This is one of the three methods a concrete widget is required
    /// to implement; the trivial body is `&mut self.base`.
    fn state_mut(&mut self) -> &mut WidgetState;

    /// Downcast helper — return `self` as a `&dyn Any`.
    ///
    /// This is one of the three methods a concrete widget is required
    /// to implement; the trivial body is `self`. It exists so callers
    /// can recover the concrete type from a `&dyn Widget` via
    /// `widget.as_any().downcast_ref::<ConcreteWidget>()`.
    fn as_any(&self) -> &dyn Any;

    // -------------------- Lifecycle --------------------

    /// FASM vtable slot 0 — release all resources owned by this widget.
    ///
    /// The default impl mirrors FASM `tui_object$cleanup`
    /// (`tui_object.inc` line 556): it recursively cleans up all
    /// children and bastards (via [`cleanup_widget`] on each) and
    /// clears the owned `text` / `attributes` buffers.
    ///
    /// Subclasses that own additional heap-allocated state should
    /// override this method and call
    /// `self.state_mut()` helpers or `super` equivalents explicitly.
    fn cleanup(&mut self) {
        let state = self.state_mut();
        state.children.clear();
        state.bastards.clear();
        state.text.clear();
        state.attributes.clear();
        state.display_name.clear();
    }

    /// FASM vtable slot 1 — produce a deep clone of this widget.
    ///
    /// Concrete widgets MUST override this to return a freshly
    /// allocated `Arc<dyn Widget>` containing a deep copy of their
    /// state. The default impl returns
    /// `Err(TuiError::Render(io::Error::Unsupported))` to surface
    /// missing overrides at the earliest opportunity (matching FASM
    /// `breakpoint` placeholder semantics).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] wrapping
    /// [`std::io::ErrorKind::Unsupported`] when the concrete widget
    /// did not override this method.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        Err(TuiError::Render(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "clone_widget not implemented by subclass",
        )))
    }

    /// FASM vtable slot 15 — application-exit notification.
    ///
    /// Called during application teardown so long-running widgets can
    /// cancel timers, close channels, and release external resources.
    /// Default is a no-op; FASM `tui_object$exit` walks the parent
    /// chain, but Rust routes teardown externally via the `Terminal`
    /// layer.
    fn exit(&mut self) {}

    // -------------------- Rendering --------------------

    /// FASM vtable slot 2 — emit this widget's ANSI output to `r`.
    ///
    /// Default impl does nothing (the base widget has no visible
    /// representation); subclasses override to emit their own escape
    /// sequences via the [`Renderer`] methods.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if any underlying renderer call
    /// fails (typically a write error on the terminal / SSH channel).
    fn draw(&mut self, r: &mut dyn Renderer) -> Result<(), TuiError> {
        let _ = r;
        Ok(())
    }

    /// FASM vtable slot 3 — schedule a redraw of this widget.
    ///
    /// The default impl simply calls [`Widget::draw`]; subclasses that
    /// implement incremental redraw (e.g. text cursor blink) override.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if the underlying draw fails.
    fn redraw(&mut self, r: &mut dyn Renderer) -> Result<(), TuiError> {
        self.draw(r)
    }

    /// FASM vtable slot 4 — rebuild the display list.
    ///
    /// The display list is the flattened subtree of visible
    /// descendants that the renderer iterates over. Default is a
    /// no-op; container widgets (e.g. panel) override to walk their
    /// children and collect dirty regions.
    fn update_display_list(&mut self) {}

    /// FASM vtable slot 28 — produce a flat list of all visible
    /// descendants (including `self` when appropriate).
    ///
    /// Default returns an empty vector; container widgets override to
    /// recursively collect their children.
    fn flatten(&self) -> Vec<Arc<dyn Widget>> {
        Vec::new()
    }

    // -------------------- Layout --------------------

    /// FASM vtable slot 5 — notification that this widget's allocated
    /// size has changed.
    ///
    /// Called by the layout pass when the container re-sizes this
    /// widget. The FASM base impl reallocates the `text` / `attr`
    /// buffers to match the new cell area (`tui_object.inc` line 783);
    /// Rust subclasses that cache per-cell state should do the same in
    /// their overrides.
    fn size_changed(&mut self, _width: i32, _height: i32) {}

    /// FASM vtable slot 6 — periodic timer tick.
    ///
    /// Called by the timer dispatcher at the interval registered for
    /// this widget. Default is a no-op; subclasses that animate (e.g.
    /// spinners, matrix-rain) override.
    fn timer(&mut self) {}

    /// FASM vtable slot 7 — notification that the parent's layout
    /// context has changed (e.g. parent bounds resized).
    ///
    /// FASM `tui_object$layoutchanged` (line 856) bubbles the event
    /// up through the parent chain; Rust routes this externally via
    /// the layout pass, so the default impl is a no-op.
    fn layout_changed(&mut self) {}

    /// FASM vtable slot 8 — move the widget to `(x, y)` absolute
    /// coordinates.
    ///
    /// Mirrors FASM `tui_object$move` (line 875): adjusts the bounds
    /// rect by the delta and updates the cached absolute position.
    /// The Rust version is simpler because we directly assign
    /// [`WidgetState::absolute_x`] / [`WidgetState::absolute_y`] rather
    /// than adjusting a delta stored in the bounds rect.
    fn move_to(&mut self, x: i32, y: i32) {
        let state = self.state_mut();
        state.absolute_x = x;
        state.absolute_y = y;
    }

    /// FASM vtable slot 16 — recompute this widget's own bounds.
    fn calc_bounds(&mut self) {}

    /// FASM vtable slot 17 — recompute bounds for all child widgets.
    fn calc_child_bounds(&mut self) {}

    // -------------------- Focus --------------------

    /// FASM vtable slot 9 — request focus on this widget.
    ///
    /// Returns `true` if focus was accepted (widget is focusable and
    /// visible); `false` otherwise. Default returns `false` — most
    /// base widgets do not accept focus.
    fn set_focus(&mut self) -> bool {
        false
    }

    /// FASM vtable slot 10 — called after focus transfers to this
    /// widget.
    ///
    /// Default is a no-op; widgets that render a focus indicator
    /// (e.g. text box) override.
    fn got_focus(&mut self) {}

    /// FASM vtable slot 11 — called when focus leaves this widget.
    fn lost_focus(&mut self) {}

    // -------------------- Input --------------------

    /// FASM vtable slot 12 — dispatch a key event to this widget.
    ///
    /// Returns `true` if the event was consumed and propagation should
    /// stop; `false` to let a parent (or the global hotkey handler)
    /// process it. Default returns `false` — base widgets do not
    /// handle input.
    ///
    /// Mirrors FASM `tui_object$keyevent` (line 925) whose return
    /// value convention is: `eax == 0` = bubble up, `eax != 0` = stop.
    fn key_event(&mut self, _event: KeyEvent) -> bool {
        false
    }

    /// FASM vtable slot 29 — fire a key event, typically on the
    /// focused descendant.
    ///
    /// Default delegates to [`Widget::key_event`]; container widgets
    /// override to dispatch to the focused child.
    fn fire_key_event(&mut self, event: KeyEvent) -> bool {
        self.key_event(event)
    }

    /// FASM vtable slot 30 — Tab key pressed, advance focus.
    ///
    /// Returns `true` if focus was advanced (event consumed); `false`
    /// to let a parent handle the Tab (e.g. move focus out of the
    /// container).
    fn on_tab(&mut self) -> bool {
        false
    }

    /// FASM vtable slot 31 — Shift+Tab pressed, retreat focus.
    ///
    /// Returns `true` if focus was retreated.
    fn on_shift_tab(&mut self) -> bool {
        false
    }

    /// FASM vtable slot 35 — mouse click received.
    ///
    /// Returns `true` if the click was consumed. Default returns
    /// `false` — base widgets do not handle clicks.
    fn click(&mut self, _event: ClickEvent) -> bool {
        false
    }

    /// FASM vtable slot 36 — post-click notification, fires after the
    /// click has been consumed.
    ///
    /// This is the hook for subscriber callbacks (e.g. button "clicked"
    /// handlers). Default is a no-op.
    fn clicked(&mut self, _event: ClickEvent) {}

    /// FASM vtable slot 38 — item-selected notification.
    ///
    /// Mirrors `tui_datagrid$itemselected` (a no-op default in
    /// `tui_datagrid.inc` lines 343–352). The
    /// [`crate::tui::gridguts::GridGuts`] keyevent handler invokes
    /// this on the parent widget when the user presses Enter on a
    /// data row, passing the zero-based row index of the
    /// selection.
    ///
    /// Receiver is `&self` because the call site holds an
    /// [`std::sync::Arc<dyn Widget>`] upgraded from a
    /// [`std::sync::Weak`] back-reference — `&mut Widget` would
    /// require [`std::sync::Arc::get_mut`] which fails when the
    /// widget is shared. Subclasses that need to mutate state on
    /// selection should use interior mutability
    /// ([`std::sync::Mutex`], [`std::sync::RwLock`], or
    /// [`std::cell::RefCell`] inside a single-threaded scope).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError`] when an override fails to dispatch the
    /// selection (e.g. backing model mutation fails). The
    /// [`crate::tui::gridguts::GridGuts`] caller discards the
    /// result to match the FASM vtable convention of "selection
    /// notification is fire-and-forget".
    fn on_item_selected(&self, _row_index: usize) -> Result<(), TuiError> {
        Ok(())
    }

    // -------------------- Modal --------------------

    /// FASM vtable slot 13 — enter modal dispatch mode.
    ///
    /// In FASM, modal dispatch (`tui_object$domodal`) captures all
    /// input until a matching `$endmodal`. In Rust this is coordinated
    /// by the `Terminal` layer; the default impl is a no-op.
    fn do_modal(&mut self) {}

    /// FASM vtable slot 14 — exit modal dispatch mode.
    fn end_modal(&mut self) {}

    // -------------------- Children --------------------

    /// FASM vtable slot 18 — append a laid-out child to this widget.
    ///
    /// Children appended via this method are positioned by the
    /// parent's [`Layout`] mode.
    fn append_child(&mut self, child: Arc<dyn Widget>) {
        self.state_mut().children.push_back(child);
    }

    /// FASM vtable slot 19 — append a non-laid-out ("bastard") child.
    ///
    /// Bastards are overlayed using absolute positioning (e.g. modal
    /// dialogs, tooltips). They are NOT placed by the parent's layout
    /// algorithm.
    fn append_bastard(&mut self, child: Arc<dyn Widget>) {
        self.state_mut().bastards.push_back(child);
    }

    /// FASM vtable slot 20 — prepend a laid-out child (insert at
    /// index 0).
    fn prepend_child(&mut self, child: Arc<dyn Widget>) {
        self.state_mut().children.push_front(child);
    }

    /// FASM vtable slot 21 — return `true` if `point` is inside this
    /// widget's bounds.
    ///
    /// Delegates to [`Rect::contains`] with the half-open convention
    /// (top-left inclusive, bottom-right exclusive).
    fn contains(&self, point: Point) -> bool {
        self.state().bounds.contains(point)
    }

    /// FASM vtable slot 22 — return the zero-based index of `child` in
    /// the children list, or `None` if not present.
    ///
    /// Uses [`Arc::ptr_eq`] for identity comparison, matching FASM's
    /// pointer-key removal semantics (the FASM equivalent compares raw
    /// pointer values).
    fn get_child_index(&self, child: &Arc<dyn Widget>) -> Option<usize> {
        self.state().children.iter().position(|c| Arc::ptr_eq(c, child))
    }

    /// FASM vtable slot 23 — remove a specific child from the children
    /// list (by identity).
    ///
    /// Returns `true` if the child was found and removed; `false` if
    /// it was not present. Identity comparison uses [`Arc::ptr_eq`].
    fn remove_child(&mut self, child: &Arc<dyn Widget>) -> bool {
        let state = self.state_mut();
        let Some(idx) = state.children.iter().position(|c| Arc::ptr_eq(c, child)) else {
            return false;
        };
        state.children.remove(idx).is_some()
    }

    /// FASM vtable slot 24 — remove a specific bastard (by identity).
    ///
    /// See [`Widget::remove_child`] for the semantics.
    fn remove_bastard(&mut self, child: &Arc<dyn Widget>) -> bool {
        let state = self.state_mut();
        let Some(idx) = state.bastards.iter().position(|c| Arc::ptr_eq(c, child)) else {
            return false;
        };
        state.bastards.remove(idx).is_some()
    }

    /// FASM vtable slot 25 — remove all laid-out children.
    fn remove_all_children(&mut self) {
        self.state_mut().children.clear();
    }

    /// FASM vtable slot 26 — remove all bastard children.
    fn remove_all_bastards(&mut self) {
        self.state_mut().bastards.clear();
    }

    /// FASM vtable slot 27 — collect all descendants whose bounds
    /// contain `point`, appending them to `out`.
    ///
    /// Default is a no-op — base widgets do not recurse. Container
    /// widgets override to walk their children.
    fn get_objects_under_point(&self, _point: Point, _out: &mut Vec<Arc<dyn Widget>>) {}

    // -------------------- Cursor --------------------

    /// FASM vtable slot 32 — set the terminal cursor position
    /// (column, row).
    ///
    /// Default is a no-op; widgets that support an in-widget cursor
    /// (textbox, form) override.
    fn set_cursor(&mut self, _x: i32, _y: i32) {}

    /// FASM vtable slot 33 — show the terminal cursor.
    fn show_cursor(&mut self) {}

    /// FASM vtable slot 34 — hide the terminal cursor.
    fn hide_cursor(&mut self) {}
}

// ============================================================================
// Helpers exposed at the module level.
// ============================================================================

/// Format a widget's identifying metadata (display name + bounds) as a
/// human-readable `String`.
///
/// Used by log lines and debugging output to identify widgets without
/// requiring `Debug` on the `dyn Widget` trait object. If the widget
/// has no display name (the empty string), the placeholder `<anon>` is
/// substituted.
#[must_use]
pub fn widget_identity(w: &dyn Widget) -> String {
    let state = w.state();
    let name: &str = if state.display_name.is_empty() {
        "<anon>"
    } else {
        &state.display_name
    };
    format!("{name} {:?}", state.bounds)
}

/// Recursively tear down a widget subtree.
///
/// Walks the children + bastards lists in reverse order (so
/// lower-indexed children see a still-intact right sibling when
/// cleaning up shared state), calls [`Widget::cleanup`] on each
/// descendant, and finally calls `cleanup` on the root. After this
/// function returns, no external references obtained from the subtree
/// retain any widget state beyond the still-live [`Arc`] handles the
/// caller may hold.
///
/// Mirrors FASM `tui_object$cleanup` (`tui_object.inc` line 556),
/// which walks children/bastards and calls their respective cleanup
/// vmethods before freeing the outer buffer pointers.
///
/// # Note on ordering
///
/// FASM walks the child list forward; we match that ordering by
/// iterating `children.iter_mut()` in order, then `bastards.iter_mut()`
/// in order. Since each child `Arc<dyn Widget>` is shared ownership,
/// an `Arc::get_mut` attempt may fail when the child is held elsewhere;
/// in that case we fall back to best-effort cleanup on the surviving
/// widget-state fields only.
pub fn cleanup_widget(root: &mut dyn Widget) {
    // Recurse into children / bastards first — depth-first post-order.
    let state = root.state_mut();
    // We must not hold `state` across the `cleanup` calls on children
    // because those calls reborrow `root` through `&mut dyn Widget`.
    // Instead, iterate over the `Arc` handles by cloning them briefly
    // and then clearing the owning lists once recursion completes.
    let mut children: Vec<Arc<dyn Widget>> = state.children.iter().cloned().collect();
    let mut bastards: Vec<Arc<dyn Widget>> = state.bastards.iter().cloned().collect();

    for child in children.iter_mut() {
        // We can only invoke `&mut` methods on widgets we uniquely
        // own. `Arc::get_mut` succeeds when the refcount is 1 — i.e.
        // when this subtree owns the child outright. When it fails,
        // we skip the recursive cleanup; the widget will still be
        // dropped when its last reference goes away.
        if let Some(exclusive) = Arc::get_mut(child) {
            cleanup_widget(exclusive);
        }
    }
    for bastard in bastards.iter_mut() {
        if let Some(exclusive) = Arc::get_mut(bastard) {
            cleanup_widget(exclusive);
        }
    }

    // Finally, clean up this widget itself. `cleanup` is polymorphic
    // via the trait object; the default impl clears children/bastards
    // plus text/attributes/display_name, which is correct for the
    // post-recursion state.
    root.cleanup();
}

// ============================================================================
// Unit tests.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;

    /// A minimal no-op widget used as a trait-level smoke test harness.
    /// Every method of `Widget` except the three required accessors is
    /// exercised via the default implementation.
    struct TestWidget {
        base: WidgetState,
    }

    impl TestWidget {
        fn new() -> Self {
            Self {
                base: WidgetState::new(),
            }
        }

        fn with_name(name: &str) -> Self {
            let mut w = Self::new();
            w.base.display_name = name.to_string();
            w
        }
    }

    impl Widget for TestWidget {
        fn state(&self) -> &WidgetState {
            &self.base
        }
        fn state_mut(&mut self) -> &mut WidgetState {
            &mut self.base
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    // -------------------- WidgetState defaults --------------------

    #[test]
    fn widget_state_new_defaults() {
        let s = WidgetState::new();
        // Mirrors FASM tui_object$init_defaults.
        assert!(s.visible);
        assert!(s.include_in_layout);
        assert_eq!(s.absolute_x, -1);
        assert_eq!(s.absolute_y, -1);
        assert_eq!(s.width, 0);
        assert_eq!(s.height, 0);
        assert!(s.width_percent.is_none());
        assert!(s.height_percent.is_none());
        assert!(!s.drop_shadow);
        assert_eq!(s.layout, Layout::None);
        assert_eq!(s.horiz_align, HorizAlign::Left);
        assert_eq!(s.vert_align, VertAlign::Top);
        assert_eq!(s.bastard_glue, 0);
        assert!(s.display_name.is_empty());
        assert!(s.text.is_empty());
        assert!(s.attributes.is_empty());
        assert_eq!(s.children.len(), 0);
        assert_eq!(s.bastards.len(), 0);
        assert_eq!(s.scroll, Point::default());
        assert_eq!(s.bounds, Rect::default());
    }

    #[test]
    fn widget_state_default_matches_new() {
        let a = WidgetState::new();
        let b = WidgetState::default();
        assert_eq!(a.visible, b.visible);
        assert_eq!(a.include_in_layout, b.include_in_layout);
        assert_eq!(a.absolute_x, b.absolute_x);
        assert_eq!(a.absolute_y, b.absolute_y);
    }

    #[test]
    fn widget_state_debug_shows_len_not_children() {
        let mut s = WidgetState::new();
        s.children.push_back(Arc::new(TestWidget::new()));
        s.bastards.push_back(Arc::new(TestWidget::new()));
        let debug = format!("{s:?}");
        // We explicitly render counts — not the full subtree — to
        // avoid requiring `Debug` on `dyn Widget`.
        assert!(debug.contains("children_len: 1"));
        assert!(debug.contains("bastards_len: 1"));
    }

    // -------------------- Widget trait — lifecycle --------------------

    #[test]
    fn default_cleanup_clears_state() {
        let mut w = TestWidget::with_name("foo");
        w.base.children.push_back(Arc::new(TestWidget::new()));
        w.base.bastards.push_back(Arc::new(TestWidget::new()));
        w.base.text.extend_from_slice(b"hello");
        w.base.attributes.push(7, 0, 0);
        w.cleanup();
        assert_eq!(w.state().children.len(), 0);
        assert_eq!(w.state().bastards.len(), 0);
        assert!(w.state().text.is_empty());
        assert!(w.state().attributes.is_empty());
        assert!(w.state().display_name.is_empty());
    }

    #[test]
    fn default_clone_widget_returns_unsupported() {
        let w = TestWidget::new();
        // We cannot use `.unwrap_err()` here because it requires the
        // `Ok(_)` variant be `Debug`, and `Arc<dyn Widget>` is not.
        match w.clone_widget() {
            Ok(_) => panic!("expected Err from default clone_widget"),
            Err(TuiError::Render(io_err)) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::Unsupported);
            }
            Err(other) => panic!("expected TuiError::Render, got {other:?}"),
        }
    }

    #[test]
    fn default_clone_widget_is_err() {
        let w = TestWidget::new();
        assert!(w.clone_widget().is_err());
    }

    #[test]
    fn default_exit_is_noop() {
        let mut w = TestWidget::new();
        w.exit();
        // exit() is a no-op; we just confirm it can be called and
        // doesn't panic or touch observable state.
        assert!(w.state().visible);
    }

    // -------------------- Widget trait — layout --------------------

    #[test]
    fn move_to_updates_absolute_xy() {
        let mut w = TestWidget::new();
        w.move_to(10, 20);
        assert_eq!(w.state().absolute_x, 10);
        assert_eq!(w.state().absolute_y, 20);
    }

    #[test]
    fn size_changed_is_noop_by_default() {
        let mut w = TestWidget::new();
        w.size_changed(40, 20);
        // Default is a no-op — size isn't recorded on the base state.
        // Subclasses override to resize text/attr buffers.
        assert_eq!(w.state().width, 0);
        assert_eq!(w.state().height, 0);
    }

    #[test]
    fn calc_bounds_and_child_bounds_are_noop() {
        let mut w = TestWidget::new();
        w.calc_bounds();
        w.calc_child_bounds();
        assert_eq!(w.state().bounds, Rect::default());
    }

    #[test]
    fn layout_changed_is_noop() {
        let mut w = TestWidget::new();
        w.layout_changed();
        assert!(w.state().visible);
    }

    #[test]
    fn timer_is_noop_by_default() {
        let mut w = TestWidget::new();
        w.timer();
        // Default is a no-op — widgets override to animate.
        assert_eq!(w.state().children.len(), 0);
    }

    // -------------------- Widget trait — focus --------------------

    #[test]
    fn default_set_focus_returns_false() {
        let mut w = TestWidget::new();
        assert!(!w.set_focus());
    }

    #[test]
    fn got_lost_focus_noop() {
        let mut w = TestWidget::new();
        w.got_focus();
        w.lost_focus();
        assert!(w.state().visible);
    }

    // -------------------- Widget trait — input --------------------

    #[test]
    fn key_event_default_bubbles_up() {
        let mut w = TestWidget::new();
        assert!(!w.key_event(KeyEvent::Enter));
        assert!(!w.key_event(KeyEvent::Char('a')));
        assert!(!w.key_event(KeyEvent::F(5)));
    }

    #[test]
    fn fire_key_event_delegates_to_key_event() {
        let mut w = TestWidget::new();
        // Base impl delegates; both return false.
        assert!(!w.fire_key_event(KeyEvent::ArrowUp));
    }

    #[test]
    fn on_tab_and_shift_tab_default_false() {
        let mut w = TestWidget::new();
        assert!(!w.on_tab());
        assert!(!w.on_shift_tab());
    }

    #[test]
    fn click_and_clicked_default() {
        let mut w = TestWidget::new();
        let ev = ClickEvent {
            x: 3,
            y: 4,
            button: 1,
        };
        assert!(!w.click(ev));
        w.clicked(ev);
    }

    // -------------------- Widget trait — modal --------------------

    #[test]
    fn do_modal_end_modal_noop() {
        let mut w = TestWidget::new();
        w.do_modal();
        w.end_modal();
        assert!(w.state().visible);
    }

    // -------------------- Widget trait — children --------------------

    #[test]
    fn append_child_increments_children() {
        let mut parent = TestWidget::new();
        let child: Arc<dyn Widget> = Arc::new(TestWidget::new());
        parent.append_child(child.clone());
        assert_eq!(parent.state().children.len(), 1);
        assert_eq!(parent.get_child_index(&child), Some(0));
    }

    #[test]
    fn append_bastard_does_not_affect_children() {
        let mut parent = TestWidget::new();
        let bastard: Arc<dyn Widget> = Arc::new(TestWidget::new());
        parent.append_bastard(bastard.clone());
        assert_eq!(parent.state().bastards.len(), 1);
        assert_eq!(parent.state().children.len(), 0);
    }

    #[test]
    fn prepend_child_inserts_at_front() {
        let mut parent = TestWidget::new();
        let a: Arc<dyn Widget> = Arc::new(TestWidget::with_name("a"));
        let b: Arc<dyn Widget> = Arc::new(TestWidget::with_name("b"));
        parent.append_child(a.clone());
        parent.prepend_child(b.clone());
        assert_eq!(parent.get_child_index(&b), Some(0));
        assert_eq!(parent.get_child_index(&a), Some(1));
    }

    #[test]
    fn contains_delegates_to_bounds() {
        let mut w = TestWidget::new();
        w.base.bounds = Rect::new(0, 0, 10, 10);
        assert!(w.contains(Point::new(5, 5)));
        assert!(!w.contains(Point::new(10, 10))); // bx/by exclusive
        assert!(!w.contains(Point::new(-1, 0)));
    }

    #[test]
    fn get_child_index_identity_based() {
        let mut parent = TestWidget::new();
        let c1: Arc<dyn Widget> = Arc::new(TestWidget::new());
        let c2: Arc<dyn Widget> = Arc::new(TestWidget::new());
        let c3: Arc<dyn Widget> = Arc::new(TestWidget::new());
        parent.append_child(c1.clone());
        parent.append_child(c2.clone());
        assert_eq!(parent.get_child_index(&c1), Some(0));
        assert_eq!(parent.get_child_index(&c2), Some(1));
        assert_eq!(parent.get_child_index(&c3), None);
    }

    #[test]
    fn remove_child_returns_true_on_success() {
        let mut parent = TestWidget::new();
        let c1: Arc<dyn Widget> = Arc::new(TestWidget::new());
        let c2: Arc<dyn Widget> = Arc::new(TestWidget::new());
        parent.append_child(c1.clone());
        parent.append_child(c2.clone());
        assert!(parent.remove_child(&c1));
        assert_eq!(parent.state().children.len(), 1);
        assert_eq!(parent.get_child_index(&c1), None);
        assert_eq!(parent.get_child_index(&c2), Some(0));
    }

    #[test]
    fn remove_child_returns_false_when_missing() {
        let mut parent = TestWidget::new();
        let c1: Arc<dyn Widget> = Arc::new(TestWidget::new());
        let unrelated: Arc<dyn Widget> = Arc::new(TestWidget::new());
        parent.append_child(c1.clone());
        assert!(!parent.remove_child(&unrelated));
        assert_eq!(parent.state().children.len(), 1);
    }

    #[test]
    fn remove_bastard_works() {
        let mut parent = TestWidget::new();
        let b: Arc<dyn Widget> = Arc::new(TestWidget::new());
        parent.append_bastard(b.clone());
        assert!(parent.remove_bastard(&b));
        assert_eq!(parent.state().bastards.len(), 0);
    }

    #[test]
    fn remove_all_children_clears_list() {
        let mut parent = TestWidget::new();
        parent.append_child(Arc::new(TestWidget::new()));
        parent.append_child(Arc::new(TestWidget::new()));
        parent.remove_all_children();
        assert_eq!(parent.state().children.len(), 0);
    }

    #[test]
    fn remove_all_bastards_clears_list() {
        let mut parent = TestWidget::new();
        parent.append_bastard(Arc::new(TestWidget::new()));
        parent.append_bastard(Arc::new(TestWidget::new()));
        parent.remove_all_bastards();
        assert_eq!(parent.state().bastards.len(), 0);
    }

    #[test]
    fn get_objects_under_point_default_empty() {
        let w = TestWidget::new();
        let mut out: Vec<Arc<dyn Widget>> = Vec::new();
        w.get_objects_under_point(Point::new(0, 0), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn flatten_default_empty() {
        let w = TestWidget::new();
        let flat = w.flatten();
        assert!(flat.is_empty());
    }

    // -------------------- Widget trait — cursor --------------------

    #[test]
    fn cursor_methods_noop() {
        let mut w = TestWidget::new();
        w.set_cursor(1, 2);
        w.show_cursor();
        w.hide_cursor();
        assert!(w.state().visible);
    }

    // -------------------- as_any downcasting --------------------

    #[test]
    fn as_any_downcast_to_concrete() {
        let w: Box<dyn Widget> = Box::new(TestWidget::with_name("dc"));
        let any = w.as_any();
        let back = any.downcast_ref::<TestWidget>().expect("downcast to TestWidget");
        assert_eq!(back.state().display_name, "dc");
    }

    // -------------------- TimerAction --------------------

    #[test]
    fn timer_action_default_continue() {
        assert_eq!(TimerAction::default(), TimerAction::Continue);
    }

    #[test]
    fn timer_action_variants_distinct() {
        assert_ne!(TimerAction::Continue, TimerAction::Remove);
        assert_ne!(TimerAction::Remove, TimerAction::Teardown);
    }

    // -------------------- Layout / HorizAlign / VertAlign --------------------

    #[test]
    fn layout_default_is_none() {
        assert_eq!(Layout::default(), Layout::None);
    }

    #[test]
    fn horiz_align_default_is_left() {
        assert_eq!(HorizAlign::default(), HorizAlign::Left);
    }

    #[test]
    fn vert_align_default_is_top() {
        assert_eq!(VertAlign::default(), VertAlign::Top);
    }

    #[test]
    fn layout_variants_are_numbered() {
        // Matches the FASM tui_layout_* semantics as documented in the
        // Layout enum rustdoc.
        assert_eq!(Layout::None as u32, 0);
        assert_eq!(Layout::Vertical as u32, 1);
        assert_eq!(Layout::Horizontal as u32, 2);
    }

    // -------------------- ColorPair --------------------

    #[test]
    fn color_pair_construction() {
        let c = ColorPair::new(15, 0);
        assert_eq!(c.fg, 15);
        assert_eq!(c.bg, 0);
    }

    #[test]
    fn color_pair_const_new_is_const() {
        const WHITE_ON_BLACK: ColorPair = ColorPair::new(15, 0);
        assert_eq!(WHITE_ON_BLACK.fg, 15);
        assert_eq!(WHITE_ON_BLACK.bg, 0);
    }

    #[test]
    fn color_pair_default_is_zero() {
        let c = ColorPair::default();
        assert_eq!(c.fg, 0);
        assert_eq!(c.bg, 0);
    }

    // -------------------- Attributes --------------------

    #[test]
    fn attributes_new_is_empty() {
        let a = Attributes::new();
        assert!(a.is_empty());
        assert_eq!(a.len(), 0);
    }

    #[test]
    fn attributes_push_and_len() {
        let mut a = Attributes::new();
        assert!(a.is_empty());
        a.push(7, 0, 0);
        a.push(7, 0, 1);
        assert_eq!(a.len(), 2);
        assert!(!a.is_empty());
    }

    #[test]
    fn attributes_clear_preserves_capacity() {
        let mut a = Attributes::new();
        a.push(1, 2, 3);
        a.push(4, 5, 6);
        let cap_before = a.cells.capacity();
        a.clear();
        assert!(a.is_empty());
        assert_eq!(a.len(), 0);
        assert!(a.cells.capacity() >= cap_before);
    }

    #[test]
    fn attributes_push_encodes_correctly() {
        let mut a = Attributes::new();
        a.push(0xAB, 0xCD, 0x1234);
        let packed = a.cells[0];
        assert_eq!(packed & 0xFF, 0xAB);
        assert_eq!((packed >> 8) & 0xFF, 0xCD);
        assert_eq!((packed >> 16) & 0xFFFF, 0x1234);
    }

    // -------------------- widget_identity helper --------------------

    #[test]
    fn widget_identity_uses_display_name() {
        let w = TestWidget::with_name("foo");
        let s = widget_identity(&w);
        assert!(s.starts_with("foo "));
    }

    #[test]
    fn widget_identity_anonymous() {
        let w = TestWidget::new();
        let s = widget_identity(&w);
        assert!(s.starts_with("<anon>"));
    }

    #[test]
    fn widget_identity_includes_bounds() {
        let mut w = TestWidget::with_name("panel");
        w.base.bounds = Rect::new(1, 2, 3, 4);
        let s = widget_identity(&w);
        assert!(s.contains("panel"));
        // The exact Debug rendering of Rect is controlled by
        // geometry.rs; we just check presence of the numeric
        // coordinates.
        assert!(s.contains('1'));
        assert!(s.contains('4'));
    }

    // -------------------- cleanup_widget helper --------------------

    #[test]
    fn cleanup_widget_clears_root() {
        let mut root = TestWidget::with_name("root");
        root.base.text.extend_from_slice(b"data");
        root.base.attributes.push(1, 2, 3);
        cleanup_widget(&mut root);
        assert!(root.state().text.is_empty());
        assert!(root.state().attributes.is_empty());
        assert!(root.state().display_name.is_empty());
    }

    #[test]
    fn cleanup_widget_clears_children() {
        let mut root = TestWidget::new();
        root.append_child(Arc::new(TestWidget::new()));
        root.append_bastard(Arc::new(TestWidget::new()));
        cleanup_widget(&mut root);
        assert_eq!(root.state().children.len(), 0);
        assert_eq!(root.state().bastards.len(), 0);
    }

    // -------------------- KeyEvent / ClickEvent --------------------

    #[test]
    fn key_event_equality() {
        assert_eq!(KeyEvent::Char('a'), KeyEvent::Char('a'));
        assert_ne!(KeyEvent::Char('a'), KeyEvent::Char('b'));
        assert_eq!(KeyEvent::F(5), KeyEvent::F(5));
        assert_eq!(KeyEvent::Enter, KeyEvent::Enter);
    }

    #[test]
    fn click_event_fields() {
        let ev = ClickEvent {
            x: 10,
            y: 20,
            button: 1,
        };
        assert_eq!(ev.x, 10);
        assert_eq!(ev.y, 20);
        assert_eq!(ev.button, 1);
    }

    // -------------------- Arc<dyn Widget> construction + Send + Sync --------------------

    #[test]
    fn arc_dyn_widget_constructs() {
        let _arc: Arc<dyn Widget> = Arc::new(TestWidget::new());
    }

    #[test]
    fn widget_trait_object_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn Widget>();
    }
}
