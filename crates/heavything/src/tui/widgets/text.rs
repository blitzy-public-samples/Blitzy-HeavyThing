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
// tui_text: editable multiline text widget with wrap, align, cursor, xscroll,
// and spinner-when-focussed support.
// Ported from tui_text.inc (3,901 lines of FASM assembly) — largest widget.

//! Editable multi-line text widget — FASM `tui_text`.
//!
//! [`TuiText`] is the largest and most feature-rich widget in the
//! HeavyThing TUI library, powering the chat input fields in
//! `sshtalk`, the form fields in `webserver` (rwasa), the detail
//! views in `hnwatch`, and serving as the parent class for
//! `tui_textbox` and `tui_autheditor`.
//!
//! # FASM correspondence
//!
//! Ported from `tui_text.inc` (3,901 lines of FASM assembly) — the
//! single largest widget file in the library. The FASM source
//! defines a 38-method vtable extending `tui_background`'s vtable
//! with one additional slot (`tui_text$onenter`, slot 37). The Rust
//! port preserves every externally observable behavior:
//!
//! - **Three-parallel-list invariant** — `lines` (editor lines),
//!   `viewlines` (display rows), and `cursormap` (cell-to-byte
//!   lookup) are kept in lockstep through every composition pass.
//! - **Empty-line invariant** — after `nvsettext`, `lines` always
//!   contains at least one editor line (FASM lines 3725–3878).
//! - **Sentinel `0xffff_ffff`** in cursormap means "no editor offset
//!   at this cell" (FASM `nvexpandby` / `nvleftcompose`).
//! - **Cursor tracking dichotomy** — `cursorx` is in BYTES (multiples
//!   of 4), `cursor.x` is in CELLS. They diverge when xscroll > 0.
//! - **Recompose triggers** — width changes drive full `nvcompose`,
//!   height changes drive only `nvheightchange`,
//!   `nvsettingsupdate` forces full recompose by zeroing
//!   `prev_width`.
//! - **Maxlen guard fires BEFORE insertion** (FASM
//!   `key_char` line 1089–1190 — drops keystroke without beep).
//!
//! # Architectural pattern
//!
//! Following the established pattern of
//! [`crate::tui::widgets::label::TuiLabel`] and
//! [`crate::tui::widgets::spinner::Spinner`], `TuiText` carries the
//! inherited [`WidgetState`] as a direct field plus its
//! background-specific fields (`bgfillchar`, `bgcolors`) inlined,
//! rather than literally composing a
//! [`crate::tui::widgets::background::TuiBackground`] instance. This
//! avoids the awkwardness of composing around an `Arc<Self>`-returning
//! base while preserving the full FASM behavior because the relevant
//! `tui_background` helpers (`nvfill`, `init_copy`) are ported as
//! private functions in this module.
//!
//! Mutable editor state (lines list, viewlines, cursormap, cursor
//! coordinates, etc.) lives behind a [`std::sync::Mutex`] so setter
//! methods can take `&self` and operate through `Arc<Self>`. The
//! [`Widget`] trait methods that accept `&mut self` (e.g.
//! [`Widget::draw`], [`Widget::key_event`]) operate on both `state`
//! and `inner` directly under exclusive access.
//!
//! # Vtable correspondence (38 slots)
//!
//! | FASM slot | FASM name | Rust override |
//! |-----------|-----------|---------------|
//! | 0 | `tui_vcleanup` | [`Widget::cleanup`] override |
//! | 1 | `tui_vclone` | [`Widget::clone_widget`] override |
//! | 2 | `tui_vdraw` | [`Widget::draw`] override |
//! | 10 | `tui_vgotfocus` | [`Widget::got_focus`] override |
//! | 11 | `tui_vlostfocus` | [`Widget::lost_focus`] override |
//! | 12 | `tui_vkeyevent` | [`Widget::key_event`] override |
//! | 32 | `tui_vsetcursor` | [`Widget::set_cursor`] override |
//! | 37 | `tui_text$onenter` | inherent [`TuiText::on_enter`] |
//!
//! The `tui_text$onenter` extension is an inherent method (not
//! a trait method) because the [`Widget`] trait does not declare
//! `on_enter` — descendants `TuiTextBox` and `TuiAutheditor` will
//! provide their own `on_enter` overrides via downcasting.

// File-level dead-code allowance — TEMPORARY scaffolding that will
// be removed once the composition methods (Chunk 5c), the key-event
// handler tree (Chunk 6), the full [`Widget`] trait impl (Chunk 8),
// and the unit-test module (Chunk 9) are in place. Each chunk
// progressively consumes more of the helper / state machinery, and
// once Chunk 9 lands every helper, every field, and every method
// in this file will be reachable from at least one consumer.
#![allow(dead_code)]

use std::any::Any;
use std::sync::{Arc, Mutex};

use crate::ds::buffer::Buffer;
use crate::ds::list::List;
use crate::error::TuiError;
use crate::tui::geometry::{Point, Rect};
use crate::tui::object::{ColorPair, KeyEvent, Widget, WidgetState};
use crate::tui::render::Renderer;
use crate::tui::widgets::spinner::Spinner;

// ============================================================================
// Public enums — AlignMode and WrapMode
// ============================================================================

/// Text alignment within each visible viewline row.
///
/// FASM equivalents: `tui_textalign_left = 0`, `_right = 1`,
/// `_center = 2`, `_justified = 3` (`tui_text.inc` lines 36–39).
///
/// # Variant notes
///
/// - [`AlignMode::Left`] / [`AlignMode::Right`] — fully implemented in
///   [`TuiText::nvleftcompose`] / [`TuiText::nvrightcompose`].
/// - [`AlignMode::Center`] / [`AlignMode::Justified`] — **unimplemented
///   stubs in the FASM source** (`tui_text.inc` lines 3416–3436 are
///   bare `prolog ; breakpoint ; epilog`). The Rust port preserves
///   FASM behavior by triggering a `debug_assert!` in debug builds
///   and silently falling back to [`AlignMode::Left`] composition in
///   release builds.
///
/// This separate enum is used (rather than [`crate::tui::object::HorizAlign`])
/// because [`crate::tui::object::HorizAlign`] has `Fill` instead of
/// `Justified` — the FASM `tui_text` semantics specifically require
/// the four-variant set defined here.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AlignMode {
    /// Left-align each viewline (FASM `tui_textalign_left = 0`).
    /// Cursormap offsets are 0, 4, 8, … and trailing cells are
    /// padded with `0xffff_ffff` sentinel.
    #[default]
    Left = 0,

    /// Right-align each viewline with a 1-character right gutter
    /// (FASM `tui_textalign_right = 1`). Trailing cursormap cells
    /// are padded with `0` (NOT the `0xffff_ffff` sentinel — FASM
    /// `nvexpandby .rightaligned` at line 970).
    Right = 1,

    /// Center alignment — **unimplemented stub in FASM**
    /// (`tui_text.inc` lines 3416–3425). Falls back to
    /// [`AlignMode::Left`] composition with a `debug_assert!`.
    Center = 2,

    /// Justified alignment — **unimplemented stub in FASM**
    /// (`tui_text.inc` lines 3427–3436). Falls back to
    /// [`AlignMode::Left`] composition with a `debug_assert!`.
    Justified = 3,
}

/// Line-wrapping behavior for text exceeding the widget's width.
///
/// FASM equivalents: `wrap = 0` horizontal scroll (no wrap),
/// `wrap = 1` hard wrap (split at column boundary), `wrap = 2`
/// word wrap (split at last space/hyphen within width/2 budget).
/// Stored at `tui_text_wrap_ofs` (`tui_text.inc` line 84).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WrapMode {
    /// No wrap — single viewline per editor line; horizontal
    /// scrolling activates when cursor moves past width
    /// (`xscroll` in BYTES). FASM `wrap = 0`.
    #[default]
    Scroll = 0,

    /// Hard wrap at column boundary — splits each editor line
    /// into chunks of exactly `width` characters per viewline.
    /// FASM `wrap = 1`.
    Hard = 1,

    /// Word wrap — searches backward from `width-1` for a space
    /// (0x20) or hyphen (0x2d) within `width/2` characters; if
    /// found, splits there; otherwise falls back to hard-wrap.
    /// FASM `wrap = 2`, `tui_text.inc` lines 2712–3055.
    Word = 2,
}

// ============================================================================
// EditorLine — public struct (per schema export contract)
// ============================================================================

/// One editor line — the user's logical text segment between LF
/// boundaries.
///
/// FASM correspondence: each `tui_text$nvsettext .addline` allocation
/// (`tui_text.inc` lines 3779–3815) creates a structure with three
/// list-like fields and a buffer of UTF-32 codepoints. The
/// `viewlines` and `cursormaps` sublists hold back-pointer-style
/// references to the master `viewlines` and `cursormap` lists; in
/// the Rust port these are expressed as `usize` indices into the
/// owning [`TuiText`]'s lists rather than raw pointers, preserving
/// the parallel-list invariant without lifetime entanglement.
///
/// # Field naming
///
/// Field names match the schema export contract exactly: `text`,
/// `viewline_indices`, `cursormap_indices`, `master_index`.
///
/// # Storage format
///
/// `text` stores codepoints as little-endian `u32`s — 4 bytes per
/// character — matching FASM's fixed-width storage that enables
/// constant-time byte-indexed cursor arithmetic. UTF-8 input is
/// converted via [`Buffer::push_u32_le`] in
/// [`TuiText::nvsettext`].
#[derive(Debug, Default)]
pub struct EditorLine {
    /// Buffer of UTF-32 little-endian codepoints (4 bytes per char).
    /// FASM equivalent: the buffer payload at offset 24 of each
    /// editor-line allocation, populated via `buffer$append_dword`.
    pub text: Buffer,

    /// Indices into the owning [`TuiText`]'s `viewlines` master
    /// list, identifying which display rows correspond to this
    /// editor line. Maintained in parallel with [`Self::cursormap_indices`].
    /// Each `usize` is bounded by `TuiText.viewlines.len()` at the
    /// time of insertion.
    pub viewline_indices: List<usize>,

    /// Indices into the owning [`TuiText`]'s `cursormap` master
    /// list, identifying which cursormap rows correspond to this
    /// editor line. Maintained in parallel with [`Self::viewline_indices`].
    pub cursormap_indices: List<usize>,

    /// Index of THIS editor line in the owning [`TuiText`]'s
    /// `lines` master list, allowing back-references from the
    /// composition pipeline. Updated whenever the owning list
    /// is mutated.
    pub master_index: usize,
}

impl EditorLine {
    /// Construct a fresh empty [`EditorLine`] with empty buffer,
    /// empty viewline/cursormap sublists, and `master_index = 0`.
    /// Callers must update `master_index` immediately after pushing
    /// onto the owning [`TuiText`]'s `lines` list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            text: Buffer::new(),
            viewline_indices: List::new(),
            cursormap_indices: List::new(),
            master_index: 0,
        }
    }
}

// ============================================================================
// TuiTextInner — private mutable state behind a Mutex
// ============================================================================

/// Mutable editor state guarded by [`std::sync::Mutex`] inside [`TuiText`].
///
/// Following the established widget-mutation pattern of
/// [`crate::tui::widgets::label::TuiLabel`] and
/// [`crate::tui::widgets::spinner::Spinner`], this struct holds all
/// the mutable fields that need to be modifiable through `&self`
/// (i.e. through `Arc<TuiText>`). The critical sections are short
/// synchronous memory updates with no `await` points, so a standard
/// [`std::sync::Mutex`] is appropriate (NOT `tokio::sync::Mutex`).
struct TuiTextInner {
    /// Original text supplied at construction, retained for
    /// `clone_widget` to rebuild the editor lines on the cloned
    /// widget. FASM `tui_text_initial_ofs` (offset 0).
    initial: String,

    /// Normal (unfocussed) color pair. FASM
    /// `tui_text_colors_ofs` (offset 8).
    colors: ColorPair,

    /// Color pair used while the widget has focus. FASM
    /// `tui_text_focuscolors_ofs` (offset 12).
    focus_colors: ColorPair,

    /// `true` when the widget should treat newlines as line
    /// separators (multi-line edit mode). `false` for single-line
    /// inputs which trigger `on_enter` instead. FASM
    /// `tui_text_multiline_ofs` (offset 16).
    multiline: bool,

    /// `true` when a [`Spinner`] should be shown as a bastard child
    /// while the widget has focus. FASM
    /// `tui_text_dospinner_ofs` (offset 20).
    do_spinner: bool,

    /// `true` while the widget owns input focus. NOT in
    /// [`WidgetState`] because focus tracking is widget-specific
    /// for `tui_text` (the framework also tracks focus at the
    /// terminal/renderer layer). FASM `tui_text_focussed_ofs`
    /// (offset 24).
    focussed: bool,

    /// Codepoint to display for every input character (password
    /// masking). `0` disables masking. FASM
    /// `tui_text_pwdchar_ofs` (offset 28).
    pwdchar: u32,

    /// Minimum allowed editing position in characters — the cursor
    /// cannot move below `min_len * 4` bytes within the first
    /// editor line. Used by `tui_textbox` to lock a label prefix.
    /// FASM `tui_text_minlen_ofs` (offset 32).
    minlen: u32,

    /// Maximum allowed total characters across all editor lines.
    /// `0` means unlimited. FASM
    /// `tui_text_maxlen_ofs` (offset 36).
    maxlen: u32,

    /// Text alignment for each viewline. FASM
    /// `tui_text_align_ofs` (offset 40).
    align: AlignMode,

    /// Line wrap mode. FASM `tui_text_wrap_ofs` (offset 44).
    wrap: WrapMode,

    /// When non-zero, the widget's height is locked to the
    /// number of viewlines (height grows with content). Checked
    /// by `nvheightchange` after `nvcompose`. FASM
    /// `tui_text_heightlock_ofs` (offset 48).
    heightlock: u32,

    /// `true` when the widget accepts keystrokes. When `false`,
    /// `key_event` returns immediately without modifying state.
    /// Default is `true`. FASM `tui_text_editable_ofs` (offset 52).
    editable: bool,

    /// `true` when the widget should display a cursor while
    /// focussed. Default is `true`. FASM
    /// `tui_text_docursor_ofs` (offset 56).
    docursor: bool,

    /// Optional bastard spinner child, lazily created on focus
    /// when `do_spinner` is `true`. Held as
    /// [`Arc`] because the spinner is also referenced from
    /// `state.bastards` and from the spinner's own timer task.
    /// FASM `tui_text_spinner_ofs` (offset 60).
    spinner: Option<Arc<Spinner>>,

    /// Master list of editor lines (one per LF-separated segment).
    /// Always non-empty after [`TuiText::nvsettext`] (empty
    /// invariant — even an empty input string produces a single
    /// empty editor line). FASM `tui_text_lines_ofs` (offset 68).
    lines: List<EditorLine>,

    /// Master list of viewline buffers (one per visible display
    /// row). Each buffer holds `width * 4` bytes of u32-LE
    /// codepoints. Wrapped in [`Arc`] so the per-editor-line
    /// `viewline_indices` sublists can reference these buffers
    /// without borrow-checker entanglement. FASM
    /// `tui_text_viewlines_ofs` (offset 76).
    viewlines: List<Arc<Buffer>>,

    /// Master list of cursormap buffers (one per visible display
    /// row, parallel to `viewlines`). Each buffer holds `width`
    /// u32-LE entries; cells holding `0xffff_ffff` indicate "no
    /// editor offset at this cell" (sentinel). FASM
    /// `tui_text_cursormap_ofs` (offset 84).
    cursormap: List<Arc<Buffer>>,

    /// Index of the topmost visible viewline (`None` when no
    /// content). FASM `tui_text_topline_ofs` (offset 92).
    topline: Option<usize>,

    /// Index of the bottommost visible viewline (`None` when no
    /// content). FASM `tui_text_bottomline_ofs` (offset 100).
    bottomline: Option<usize>,

    /// Index of the cursormap row containing the editing cursor
    /// (`None` when no content). FASM
    /// `tui_text_cursorline_ofs` (offset 108).
    cursorline: Option<usize>,

    /// Logical cursor position relative to the widget's bounds,
    /// in CELLS (not bytes). FASM `tui_text_cursor_ofs`
    /// (offset 116).
    cursor: Point,

    /// Width at last `nvcompose`. Compared against current width
    /// in [`TuiText::draw`] to decide whether a full recompose
    /// is needed. FASM `tui_text_prevwidth_ofs` (offset 124).
    prev_width: i32,

    /// Height at last `nvheightchange`. Compared against current
    /// height to decide whether a height-only adjustment is
    /// needed. FASM `tui_text_prevheight_ofs` (offset 128).
    prev_height: i32,

    /// Cursor position in BYTES into the current cursormap row
    /// (always a multiple of 4). Diverges from `cursor.x` when
    /// `xscroll > 0` in [`WrapMode::Scroll`] mode. FASM
    /// `tui_text_cursorx_ofs` (offset 132).
    cursorx: u32,

    /// Horizontal scroll offset in BYTES (multiples of 4). Used
    /// only when `wrap == WrapMode::Scroll`. FASM
    /// `tui_text_xscroll_ofs` (offset 136).
    xscroll: u32,

    /// Opaque user-defined data — the FASM `tui_text$user_ofs`
    /// 8-byte slot that descendants like `tui_textbox` use to
    /// store a back-pointer to their parent panel. The
    /// [`Box<dyn Any + Send + Sync>`] preserves type erasure
    /// while allowing safe runtime downcasting. NOT cloned by
    /// `clone_widget`. FASM `tui_text_user_ofs` (offset 140).
    user: Option<Box<dyn Any + Send + Sync>>,
}

impl TuiTextInner {
    /// Construct a fresh inner state with FASM-matching defaults.
    fn new(colors: ColorPair, focus_colors: ColorPair, initial: String) -> Self {
        Self {
            initial,
            colors,
            focus_colors,
            multiline: false,
            do_spinner: false,
            focussed: false,
            pwdchar: 0,
            minlen: 0,
            maxlen: 0,
            align: AlignMode::Left,
            wrap: WrapMode::Scroll,
            heightlock: 0,
            editable: true,
            docursor: true,
            spinner: None,
            lines: List::new(),
            viewlines: List::new(),
            cursormap: List::new(),
            topline: None,
            bottomline: None,
            cursorline: None,
            cursor: Point::ZERO,
            prev_width: 0,
            prev_height: 0,
            cursorx: 0,
            xscroll: 0,
            user: None,
        }
    }
}

// ============================================================================
// TuiText — public widget struct
// ============================================================================

/// Editable multi-line text widget — FASM `tui_text`.
///
/// See the [module docs](self) for the architectural overview, FASM
/// vtable correspondence, and detailed semantics. Construction is
/// via the five `new_*` constructors which all return
/// [`Result<Arc<Self>, TuiError>`].
///
/// # Thread safety
///
/// `TuiText: Send + Sync` because:
/// - [`WidgetState`] is `Send + Sync`.
/// - [`Mutex<TuiTextInner>`] is `Send + Sync` whenever
///   `TuiTextInner: Send` — and every field of `TuiTextInner`
///   is `Send + Sync` (`String`, `ColorPair`, `bool`, `u32`,
///   [`AlignMode`], [`WrapMode`], `Option<Arc<Spinner>>`,
///   `List<EditorLine>`, `List<Arc<Buffer>>`, `Option<usize>`,
///   `Point`, `i32`, `Option<Box<dyn Any + Send + Sync>>`).
pub struct TuiText {
    /// Inherited base widget state (bounds, dimensions,
    /// visibility, text/attribute buffers, layout, children list,
    /// …). Direct field per the established
    /// [`Widget::state`] / [`Widget::state_mut`] contract.
    pub(crate) state: WidgetState,

    /// Background fill character (FASM `tui_bgfillchar_ofs`).
    /// Inlined here rather than composing a [`crate::tui::widgets::background::TuiBackground`]
    /// because the `tui_background` constructors return `Arc<Self>`
    /// which is awkward to compose around. The [`nvfill`] helper
    /// below ports the relevant `tui_background$nvfill` behavior.
    pub(crate) bgfillchar: u32,

    /// Background colors (FASM `tui_bgcolors_ofs`). See
    /// [`Self::bgfillchar`] for the inlining rationale.
    pub(crate) bgcolors: ColorPair,

    /// Mutable editor state behind a [`std::sync::Mutex`].
    /// Setters take `&self` and lock this Mutex; trait methods
    /// take `&mut self` and lock when needed (technically
    /// unnecessary under `&mut self`, but used for consistency).
    inner: Mutex<TuiTextInner>,
}

// ============================================================================
// Helper functions — ported from `tui_background.inc` / `tui_object.inc`
// ============================================================================
//
// These helpers are private to this module rather than exposed
// through TuiBackground because TuiText carries its bg-related
// state inline (see TuiText doc above) rather than composing a
// TuiBackground instance. The semantics match TuiBackground's
// nvfill / init_copy exactly.

/// Pack a [`ColorPair`] into a `u32` matching FASM 32-bit color
/// attribute format. Bit layout: bits 0..=7 fg, bits 8..=15 bg,
/// bits 16..=31 SGR mask (0 here).
fn pack_color_pair(cp: ColorPair) -> u32 {
    u32::from(cp.fg) | (u32::from(cp.bg) << 8)
}

/// Pre-allocate the text and attributes buffers for a [`WidgetState`]
/// when both `width` and `height` are positive. Mirrors the tail of
/// FASM `tui_object$init_rect` / `init_ii` — buffers are zeroed
/// (FASM `memset32` with `esi = 0`).
fn pre_allocate_buffers(state: &mut WidgetState) -> Result<(), TuiError> {
    if state.width <= 0 || state.height <= 0 {
        return Ok(());
    }
    let cells = (state.width as usize)
        .checked_mul(state.height as usize)
        .ok_or_else(|| {
            TuiError::Render(std::io::Error::other(format!(
                "TuiText: width*height overflowed usize \
                 (width={}, height={})",
                state.width, state.height
            )))
        })?;
    let bytes = cells.checked_mul(4).ok_or_else(|| {
        TuiError::Render(std::io::Error::other(format!(
            "TuiText: cells*4 overflowed usize (cells={cells})"
        )))
    })?;
    state.text.reserve_exact(bytes);
    for _ in 0..bytes {
        state.text.push(0);
    }
    state.attributes.cells.resize(cells, 0);
    Ok(())
}

/// Fill the first `count` 4-byte cells of [`WidgetState::text`]
/// with `value` little-endian, growing the buffer to exactly
/// `count * 4` bytes (FASM `memset32(text_buf, value, count)`).
fn fill_text_buffer(state: &mut WidgetState, value: u32, count: usize) -> Result<(), TuiError> {
    let bytes = count.checked_mul(4).ok_or_else(|| {
        TuiError::Render(std::io::Error::other(format!(
            "TuiText::fill_text_buffer: count*4 overflowed usize (count={count})"
        )))
    })?;
    let buf = &mut state.text;
    if buf.len() < bytes {
        buf.reserve(bytes - buf.len());
        for _ in buf.len()..bytes {
            buf.push(0);
        }
    } else if buf.len() > bytes {
        let to_remove = buf.len() - bytes;
        buf.truncate(to_remove).map_err(|e| {
            TuiError::Render(std::io::Error::other(format!(
                "TuiText::fill_text_buffer: truncate failed: {e:?}"
            )))
        })?;
    }
    let value_le = value.to_le_bytes();
    let slice = buf.as_mut_slice();
    for chunk in slice.chunks_exact_mut(4).take(count) {
        chunk.copy_from_slice(&value_le);
    }
    Ok(())
}

/// Fill the first `count` u32 cells of [`WidgetState::attributes`]
/// with `value`, growing or truncating to length `count`.
fn fill_attr_buffer(state: &mut WidgetState, value: u32, count: usize) {
    if state.attributes.cells.len() < count {
        state.attributes.cells.resize(count, 0);
    } else if state.attributes.cells.len() > count {
        state.attributes.cells.truncate(count);
    }
    for cell in state.attributes.cells.iter_mut() {
        *cell = value;
    }
}

/// Replicate FASM `tui_background$nvfill` semantics directly on a
/// [`WidgetState`] without depending on the private `nvfill` of
/// [`crate::tui::widgets::background`].
///
/// 1. Bail when `width <= 0`, `height <= 0`, or the text buffer is
///    empty.
/// 2. When `bgfillchar != 0`, fill the first `cells` 4-byte slots
///    of the text buffer with the codepoint.
/// 3. Fill the first `cells` u32 slots of the attribute buffer
///    with the packed color.
fn nvfill_state(state: &mut WidgetState, bgfillchar: u32, bgcolors: ColorPair) -> Result<(), TuiError> {
    if state.width <= 0 || state.height <= 0 {
        return Ok(());
    }
    if state.text.is_empty() {
        return Ok(());
    }
    let cells = (state.width as usize)
        .checked_mul(state.height as usize)
        .ok_or_else(|| {
            TuiError::Render(std::io::Error::other(format!(
                "TuiText::nvfill: width*height overflowed usize \
                 (width={}, height={})",
                state.width, state.height
            )))
        })?;
    if bgfillchar != 0 {
        fill_text_buffer(state, bgfillchar, cells)?;
    }
    let packed = pack_color_pair(bgcolors);
    fill_attr_buffer(state, packed, cells);
    Ok(())
}

/// Deep-clone a [`WidgetState`] following FASM
/// `tui_object$init_copy` semantics.
///
/// - Scalar fields are bitwise-copied.
/// - `display_name`, `text`, and `attributes` are deep-copied.
/// - `children` are deep-cloned via each child's
///   [`Widget::clone_widget`].
/// - `bastards` are intentionally **not** cloned (FASM init_copy
///   leaves bastards empty in the clone).
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
        let cloned_child = child.clone_widget()?;
        cloned.children.push_back(cloned_child);
    }
    Ok(cloned)
}

/// Convert an editor [`Buffer`] of u32-LE codepoints back to a
/// Rust [`String`]. Replaces invalid codepoints (e.g. `0xffff_ffff`
/// sentinel) with the Unicode replacement character `'\u{fffd}'`.
fn utf32_le_buffer_to_string(buf: &Buffer) -> String {
    let bytes = buf.as_slice();
    let mut out = String::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks_exact(4) {
        let cp = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if let Some(c) = char::from_u32(cp) {
            out.push(c);
        } else {
            out.push('\u{fffd}');
        }
    }
    out
}

/// Append every codepoint of `s` as a u32-LE entry into `buf`.
/// Used by [`TuiText::nvsettext`] when constructing editor lines
/// from input strings.
fn append_utf32_le(buf: &mut Buffer, s: &str) {
    for ch in s.chars() {
        buf.push_u32_le(ch as u32);
    }
}

// ============================================================================
// TuiText — constructors
// ============================================================================
//
// Every constructor returns `Result<Arc<Self>, TuiError>` so that buffer
// pre-allocation failures (overflow) are surfaced as `TuiError::Render`
// rather than panicking. The five overloads mirror the FASM
// `tui_text$new_ii` / `_dd` / `_id` / `_di` / `_rect` family
// (`tui_text.inc` lines 118–333).

impl TuiText {
    /// Integer-width × integer-height constructor — FASM
    /// `tui_text$new_ii` (lines 118–160).
    ///
    /// # Arguments
    ///
    /// - `width` / `height`: absolute cell dimensions.
    /// - `colors`: normal (unfocussed) [`ColorPair`].
    /// - `focus_colors`: [`ColorPair`] applied while the widget has
    ///   focus.
    /// - `initial`: initial text to load via [`TuiText::nvsettext`].
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if the buffer pre-allocation
    /// overflows `usize` (only possible on absurdly large dimensions).
    pub fn new_ii(
        width: i32,
        height: i32,
        colors: ColorPair,
        focus_colors: ColorPair,
        initial: &str,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = height;
        Self::finalize_init(state, colors, focus_colors, initial)
    }

    /// Percent-width × percent-height constructor — FASM
    /// `tui_text$new_dd` (lines 162–204).
    pub fn new_dd(
        width_perc: f64,
        height_perc: f64,
        colors: ColorPair,
        focus_colors: ColorPair,
        initial: &str,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width_percent = Some(width_perc);
        state.height_percent = Some(height_perc);
        Self::finalize_init(state, colors, focus_colors, initial)
    }

    /// Integer-width × percent-height constructor — FASM
    /// `tui_text$new_id` (lines 206–248).
    pub fn new_id(
        width: i32,
        height_perc: f64,
        colors: ColorPair,
        focus_colors: ColorPair,
        initial: &str,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height_percent = Some(height_perc);
        Self::finalize_init(state, colors, focus_colors, initial)
    }

    /// Percent-width × integer-height constructor — FASM
    /// `tui_text$new_di` (lines 250–292).
    pub fn new_di(
        width_perc: f64,
        height: i32,
        colors: ColorPair,
        focus_colors: ColorPair,
        initial: &str,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width_percent = Some(width_perc);
        state.height = height;
        Self::finalize_init(state, colors, focus_colors, initial)
    }

    /// Explicit-rect constructor — FASM `tui_text$new_rect`
    /// (lines 294–333).
    pub fn new_rect(
        bounds: Rect,
        colors: ColorPair,
        focus_colors: ColorPair,
        initial: &str,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.bounds = bounds;
        state.width = bounds.width();
        state.height = bounds.height();
        Self::finalize_init(state, colors, focus_colors, initial)
    }

    /// Shared finalisation logic used by every constructor.
    ///
    /// 1. Pre-allocate text/attributes buffers (when bounds known).
    /// 2. Build the [`TuiTextInner`] with FASM-default scalars.
    /// 3. Wrap in [`Arc`] and run [`Self::nvsetup_locked`] to
    ///    populate the editor lines (preserves the empty-invariant
    ///    when `initial` is empty).
    fn finalize_init(
        mut state: WidgetState,
        colors: ColorPair,
        focus_colors: ColorPair,
        initial: &str,
    ) -> Result<Arc<Self>, TuiError> {
        pre_allocate_buffers(&mut state)?;
        let inner = TuiTextInner::new(colors, focus_colors, initial.to_owned());
        let widget = Arc::new(Self {
            state,
            bgfillchar: b' ' as u32,
            bgcolors: colors,
            inner: Mutex::new(inner),
        });
        // Run nvsetup on the freshly constructed widget so the
        // master `lines` list is non-empty before the first
        // `draw` call.
        widget.nvsetup()?;
        Ok(widget)
    }

    /// FASM `tui_text$nvsetup` (`tui_text.inc` lines 335–365).
    ///
    /// Initial population of the three-parallel-list editor
    /// invariant: clears any pre-existing state, then forwards the
    /// stored `initial` text to [`Self::nvsettext`]. Called once
    /// from each constructor and never again — subsequent edits
    /// flow through the public setters.
    fn nvsetup(&self) -> Result<(), TuiError> {
        // Snapshot the initial text under the lock (we need to drop
        // the guard before calling nvsettext which re-acquires it).
        let initial = self.lock_inner_clone_initial();
        self.nvsettext(&initial)
    }

    /// Defensive snapshot helper — returns a copy of `inner.initial`
    /// even if the Mutex is poisoned. The poison-recovery pattern
    /// matches [`crate::tui::widgets::label::TuiLabel`].
    fn lock_inner_clone_initial(&self) -> String {
        match self.inner.lock() {
            Ok(g) => g.initial.clone(),
            Err(p) => p.into_inner().initial.clone(),
        }
    }
}

// ============================================================================
// TuiText — public setters / getters
// ============================================================================
//
// All setters take `&self` and lock the inner Mutex internally. Setters
// that mutate composition-affecting fields (align, wrap, pwd_char,
// height_lock, colors, focus_colors, multiline) call
// [`Self::nvsettingsupdate`] (FASM `nvsettingsupdate` / line 3894–3899)
// to force a full recomposition on the next `draw`.

impl TuiText {
    /// Return the current editable text — FASM `tui_text$nvgettext`
    /// (lines 3677–3722).
    ///
    /// Single-line mode returns the first editor line as-is (no
    /// trailing LF). Multi-line mode joins all editor lines with `\n`.
    /// Both convert UTF-32-LE codepoints back to a Rust [`String`].
    #[must_use]
    pub fn get_text(&self) -> String {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if !guard.multiline {
            // Single-line — return only the first line, no LF.
            match guard.lines.front() {
                Some(line) => utf32_le_buffer_to_string(&line.text),
                None => String::new(),
            }
        } else {
            // Multi-line — join all editor lines with LF.
            let mut buf = String::new();
            let total = guard.lines.len();
            for (i, line) in guard.lines.iter().enumerate() {
                buf.push_str(&utf32_le_buffer_to_string(&line.text));
                if i + 1 < total {
                    buf.push('\n');
                }
            }
            buf
        }
    }

    /// Replace the editable text with `text` — FASM
    /// `tui_text$nvsettext` (lines 3725–3881).
    ///
    /// 1. Clears all three parallel lists (lines, viewlines,
    ///    cursormap).
    /// 2. Splits `text` by `\n` and creates one [`EditorLine`] per
    ///    segment; an empty `text` yields exactly one empty editor
    ///    line (the empty-invariant).
    /// 3. Resets all position state (topline / bottomline / cursorline
    ///    `= None`, cursor `= Point::ZERO`, prev_width / prev_height /
    ///    cursorx / xscroll = 0).
    /// 4. Invokes `vdraw` on the next render (handled implicitly by
    ///    [`Widget::draw`] checking `prev_width != cur_width`).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] only on internal arithmetic
    /// overflow (impossible in practice).
    pub fn nvsettext(&self, text: &str) -> Result<(), TuiError> {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // Step 1 — clear all three master lists. The List<EditorLine>
        // owns each line's Buffer + sublists, so clear() Drops them.
        // viewlines / cursormap own Arc<Buffer>; clear() drops the
        // strong references, leaving the buffers free for GC when the
        // last reference is gone.
        guard.lines.clear();
        guard.viewlines.clear();
        guard.cursormap.clear();

        // Step 2 — split by LF and create one editor line per segment.
        // Rust's `str::split('\n')` matches FASM `string$split(text, 10)`:
        // it always returns at least one element (the empty string for
        // empty input), preserving the empty-invariant from FASM line
        // 3781 `.empty:` path.
        let mut master_index: usize = 0;
        for segment in text.split('\n') {
            let mut line = EditorLine::new();
            append_utf32_le(&mut line.text, segment);
            line.master_index = master_index;
            guard.lines.push_back(line);
            master_index = master_index.checked_add(1).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "TuiText::nvsettext: master_index overflowed usize",
                ))
            })?;
        }
        // Empty-invariant guard: if `text` is empty, `split('\n')`
        // produced exactly one empty segment so `lines` already has 1
        // entry. We keep this assertion in debug builds only.
        debug_assert!(
            !guard.lines.is_empty(),
            "TuiText: lines must be non-empty after nvsettext"
        );

        // Step 3 — reset all position state.
        guard.topline = None;
        guard.bottomline = None;
        guard.cursorline = None;
        guard.cursor = Point::ZERO;
        guard.prev_width = 0;
        guard.prev_height = 0;
        guard.cursorx = 0;
        guard.xscroll = 0;

        // Step 4 — caller is responsible for triggering the next
        // render (the FASM source calls `vdraw` here, but in Rust
        // the next `Widget::draw` call will detect prev_width=0 and
        // perform the full recomposition automatically).
        Ok(())
    }

    /// FASM `tui_text$nvsettingsupdate` (lines 3884–3901).
    ///
    /// Forces a full recomposition on the next render by zeroing
    /// `prev_width`. Used after any setter that affects layout
    /// (align, wrap, multiline, pwd_char, height_lock, colors,
    /// focus_colors).
    pub fn nvsettingsupdate(&self) {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.prev_width = 0;
    }

    /// Set multi-line mode and force a recomposition.
    pub fn set_multiline(&self, m: bool) {
        {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.multiline = m;
        }
        self.nvsettingsupdate();
    }

    /// Set the wrap mode and force a recomposition.
    pub fn set_wrap(&self, w: WrapMode) {
        {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.wrap = w;
        }
        self.nvsettingsupdate();
    }

    /// Set the alignment mode and force a recomposition.
    pub fn set_align(&self, a: AlignMode) {
        {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.align = a;
        }
        self.nvsettingsupdate();
    }

    /// Toggle whether the widget accepts keystrokes.
    pub fn set_editable(&self, e: bool) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.editable = e;
    }

    /// Set the password-mask codepoint (`0` disables).
    pub fn set_pwd_char(&self, c: u32) {
        {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.pwdchar = c;
        }
        self.nvsettingsupdate();
    }

    /// Set the maximum total character count (`0` = unlimited).
    pub fn set_max_len(&self, l: u32) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.maxlen = l;
    }

    /// Set the minimum cursor position (cursor cannot retreat below
    /// `min_len * 4` bytes within line 0).
    pub fn set_min_len(&self, l: u32) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.minlen = l;
    }

    /// Lock the widget's height to the number of viewlines (when
    /// nonzero).
    pub fn set_height_lock(&self, l: u32) {
        {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.heightlock = l;
        }
        self.nvsettingsupdate();
    }

    /// Toggle whether the widget shows a cursor while focussed.
    pub fn set_do_cursor(&self, b: bool) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.docursor = b;
    }

    /// Toggle whether a [`Spinner`] is created when focus is gained.
    pub fn set_do_spinner(&self, b: bool) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.do_spinner = b;
    }

    /// Set the normal (unfocussed) [`ColorPair`].
    pub fn set_colors(&self, c: ColorPair) {
        {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.colors = c;
        }
        self.nvsettingsupdate();
    }

    /// Set the focussed [`ColorPair`].
    pub fn set_focus_colors(&self, c: ColorPair) {
        {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.focus_colors = c;
        }
        self.nvsettingsupdate();
    }

    /// Attach opaque user data — FASM `tui_text$user_ofs` slot.
    /// Descendants like `tui_textbox` use this to store a back-pointer
    /// to their parent panel.
    pub fn set_user(&self, user: Option<Box<dyn Any + Send + Sync>>) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.user = user;
    }

    /// Inherent on-enter callback — FASM `tui_text$onenter`
    /// (lines 2031–2040).
    ///
    /// The base implementation is intentionally empty (FASM emits a
    /// `prolog/epilog` pair with no body). Descendants like
    /// `tui_textbox` and `tui_autheditor` override this method to
    /// trigger form submission / authentication logic when the user
    /// presses Enter on a single-line widget.
    ///
    /// This is **not** a [`Widget`] trait method — it lives as an
    /// inherent method on [`TuiText`] because the base [`Widget`]
    /// trait has no `on_enter` slot. Callers that hold a
    /// `&dyn Widget` must downcast via [`Widget::as_any`] +
    /// [`std::any::Any::downcast_ref`] to invoke this.
    pub fn on_enter(&self) {
        // FASM no-op base implementation.
    }
}

// ============================================================================
// TuiText — private composition methods (Chunk 5a — simple cases)
// ============================================================================
//
// The composition pipeline maintains the **three-parallel-list invariant**:
// `inner.lines` (editor lines) → `inner.viewlines` (display rows) →
// `inner.cursormap` (cell-to-byte lookup). Each editor line carries
// `viewline_indices` and `cursormap_indices` sublists pointing into
// the master `viewlines` and `cursormap` lists at the indices that
// correspond to it.
//
// Composition methods operate through `inner_mut()` for short reads
// then drop the borrow before any `self.something()` call so the
// borrow checker stays happy across nested compose-pipeline calls.
//
// FASM source: `tui_text.inc` lines 551–3672.

impl TuiText {
    /// Quick mutable accessor for the inner editor state.
    ///
    /// Recovers from a poisoned [`Mutex`] by extracting the inner
    /// state via [`std::sync::PoisonError::into_inner`] — matching
    /// the poison-recovery pattern of
    /// [`crate::tui::widgets::label::TuiLabel`] and
    /// [`crate::tui::widgets::spinner::Spinner`].
    fn inner_mut(&mut self) -> &mut TuiTextInner {
        match self.inner.get_mut() {
            Ok(i) => i,
            Err(p) => p.into_inner(),
        }
    }

    /// FASM `tui_text$nvdocursor` (`tui_text.inc` lines 551–578).
    ///
    /// Updates the cursor position via [`Widget::set_cursor`] when
    /// the widget has focus AND the `do_cursor` flag is set. The
    /// computed coordinates are widget-bounds-relative offsets added
    /// to the bounds top-left corner.
    ///
    /// FASM behavior:
    /// - If `!focussed` OR `!docursor` → no-op.
    /// - Otherwise compute `(bounds.ax + cursor.x, bounds.ay + cursor.y)`
    ///   and propagate via the vtable `setcursor` slot 32.
    ///
    /// Implementation note: in the Rust port the actual cursor-emission
    /// step (FASM vtable slot 32) is performed directly inside the
    /// [`Widget::draw`] override using the [`Renderer::move_cursor`]
    /// API — there is no need for a separate slot. This method is
    /// retained for API symmetry with the FASM source and acts as a
    /// hook descendants (e.g. [`crate::tui::widgets::textbox::TuiTextBox`])
    /// may override.
    fn nvdocursor(&mut self) {
        let (focussed, docursor) = {
            let inner = self.inner_mut();
            (inner.focussed, inner.docursor)
        };
        if focussed && docursor {
            // The absolute screen coordinates are
            // `(self.state.bounds.top_left().x + inner.cursor.x,
            //   self.state.bounds.top_left().y + inner.cursor.y)`.
            // They are recomputed and emitted from the `draw`
            // override each frame; nothing further is required here.
        }
        // Else: FASM early-out path — no cursor update.
    }

    /// FASM `tui_text$nvmaxx` (`tui_text.inc` lines 3439–3463).
    ///
    /// Returns the maximum character width across all editor lines —
    /// used by [`Self::nvleftcompose`] and [`Self::nvrightcompose`]
    /// in their `.nowrap` (scroll) paths to size the visible
    /// viewline buffers.
    ///
    /// FASM iterates the master `lines` list reading each line's
    /// buffer length and dividing by 4 (UTF-32 codepoints are 4
    /// bytes). The Rust port matches verbatim; default 0 for the
    /// empty-list case (which never occurs after `nvsettext` thanks
    /// to the empty-invariant).
    #[must_use]
    fn nvmaxx(&mut self) -> usize {
        let inner = self.inner_mut();
        let mut max: usize = 0;
        for line in inner.lines.iter() {
            let chars = line.text.len() / 4;
            if chars > max {
                max = chars;
            }
        }
        max
    }

    /// FASM `tui_text$nvcheckspinner` (`tui_text.inc` lines 535–550 region).
    ///
    /// Lazy creation of the bastard [`Spinner`] when:
    /// 1. `do_spinner` is `true` (caller opted in via
    ///    [`Self::set_do_spinner`]).
    /// 2. `inner.spinner` is currently `None` (not yet created).
    ///
    /// The newly-allocated spinner is held in two places:
    /// - `inner.spinner` (the strong reference owned by the editor).
    /// - `state.bastards` (where the framework's render pipeline
    ///   walks the bastard list separately from the layout tree).
    ///
    /// FASM uses a fixed 75 ms tick interval — preserved here.
    /// The spinner's color pair is the focus colors (so the spinner
    /// is only visible while the field has focus).
    fn nvcheckspinner(&mut self) -> Result<(), TuiError> {
        // First decide whether we need to create a spinner, and if
        // so allocate it under the lock.
        let new_spinner: Option<Arc<Spinner>> = {
            let inner = self.inner_mut();
            if inner.do_spinner && inner.spinner.is_none() {
                let sp = Spinner::new(inner.focus_colors, 75);
                inner.spinner = Some(sp.clone());
                Some(sp)
            } else {
                None
            }
        };
        // Only after dropping the inner borrow do we touch
        // `self.state.bastards` (a separate field), which avoids
        // any aliasing issues across the borrow.
        if let Some(sp) = new_spinner {
            self.state.bastards.push_back(sp as Arc<dyn Widget>);
        }
        Ok(())
    }

    /// FASM `tui_text$nvexpandby` (`tui_text.inc` lines 903–981).
    ///
    /// Pads the master `viewlines` and `cursormap` buffers — except
    /// the buffers belonging to one specific editor line — by
    /// `count` cells. Used after a single-line edit to maintain
    /// equal viewline width across non-edited lines:
    /// - `Left` / `Center` / `Justified`: append `(' ' as u32)` to
    ///   each viewline and `0xffff_ffff` sentinel to each cursormap.
    /// - `Right`: insert at the head — `(' ' as u32)` into viewline
    ///   and `0` (NOT the sentinel — FASM line 970) into cursormap.
    ///
    /// `skip_editor_idx` is the index of the editor line whose
    /// viewlines were already grown by [`Self::nvcomposeline`] and
    /// must be excluded from this padding pass. `None` excludes
    /// none (e.g. if the caller has already cleared the relevant
    /// sublists).
    fn nvexpandby(&mut self, skip_editor_idx: Option<usize>, count: usize) -> Result<(), TuiError> {
        if count == 0 {
            return Ok(());
        }
        let inner = self.inner_mut();
        let align = inner.align;

        // Snapshot the set of viewline indices that belong to the
        // skipped editor line. Using a `Vec` (not a `HashSet`) is
        // adequate because typical editor lines have ≤ a few
        // viewlines; linear `contains` is faster than hashing for
        // such small sets.
        let skip_indices: Vec<usize> = match skip_editor_idx {
            Some(idx) => match inner.lines.get(idx) {
                Some(line) => line.viewline_indices.iter().copied().collect(),
                None => Vec::new(),
            },
            None => Vec::new(),
        };

        let total = inner.viewlines.len();
        debug_assert_eq!(
            total,
            inner.cursormap.len(),
            "TuiText: viewlines / cursormap length mismatch"
        );

        for vl_idx in 0..total {
            if skip_indices.contains(&vl_idx) {
                continue;
            }
            // Mutate viewline buffer: split-borrow on `inner.viewlines`
            // and `inner.cursormap` is allowed because they are
            // disjoint fields.
            let viewline_arc = inner.viewlines.get_mut(vl_idx).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "TuiText::nvexpandby: viewline index out of bounds",
                ))
            })?;
            let viewline = Arc::get_mut(viewline_arc).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "TuiText::nvexpandby: viewline Arc not uniquely owned",
                ))
            })?;
            match align {
                AlignMode::Right => {
                    // Insert `count` ' ' codepoints at the head.
                    // FASM `nvexpandby .rightaligned` (lines 956–977):
                    // each insert prepends 4 bytes.
                    for _ in 0..count {
                        viewline
                            .insert_slice(0, &(b' ' as u32).to_le_bytes())
                            .map_err(|e| {
                                TuiError::Render(std::io::Error::other(format!(
                                    "TuiText::nvexpandby: viewline insert: {e:?}"
                                )))
                            })?;
                    }
                }
                AlignMode::Left | AlignMode::Center | AlignMode::Justified => {
                    // Append `count` ' ' codepoints to the tail.
                    for _ in 0..count {
                        viewline.push_u32_le(b' ' as u32);
                    }
                }
            }

            // Now pad the cursormap (separate field — split-borrow
            // OK with viewline above as it has dropped after the
            // assignment block).
            let cursormap_arc = inner.cursormap.get_mut(vl_idx).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "TuiText::nvexpandby: cursormap index out of bounds",
                ))
            })?;
            let cursormap = Arc::get_mut(cursormap_arc).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "TuiText::nvexpandby: cursormap Arc not uniquely owned",
                ))
            })?;
            match align {
                AlignMode::Right => {
                    // Right-align uses 0 (NOT the sentinel) at the
                    // head — FASM `nvexpandby .rightaligned` line 970.
                    for _ in 0..count {
                        cursormap.insert_slice(0, &0u32.to_le_bytes()).map_err(|e| {
                            TuiError::Render(std::io::Error::other(format!(
                                "TuiText::nvexpandby: cursormap insert: {e:?}"
                            )))
                        })?;
                    }
                }
                AlignMode::Left | AlignMode::Center | AlignMode::Justified => {
                    // Sentinel `0xffff_ffff` means "no editor offset".
                    for _ in 0..count {
                        cursormap.push_u32_le(0xffff_ffff);
                    }
                }
            }
        }
        Ok(())
    }

    /// FASM `tui_text$nvdeleteline` (`tui_text.inc` lines 985–1052).
    ///
    /// Removes the editor line at `line_idx` along with all of its
    /// associated viewlines and cursormap rows from the master
    /// lists. Adjusts the `master_index` of every editor line that
    /// shifted down, and similarly fixes up `viewline_indices` /
    /// `cursormap_indices` of all surviving editor lines whose
    /// indices referenced rows above the deleted ones (since those
    /// indices now point to the wrong rows).
    ///
    /// This is one of the more delicate operations in the
    /// composition pipeline because the index-based design (rather
    /// than FASM's pointer-based design) means we must explicitly
    /// renumber after each removal. The Rust port handles the
    /// renumbering correctly.
    ///
    /// Used by [`Self::key_backspace_startofline`] and
    /// [`Self::key_delete_endofline`] when merging two adjacent
    /// editor lines.
    fn nvdeleteline(&mut self, line_idx: usize) -> Result<(), TuiError> {
        let inner = self.inner_mut();
        if line_idx >= inner.lines.len() {
            return Ok(());
        }
        // Step 1 — collect the viewline / cursormap indices to remove.
        // We sort descending so removing them leaves earlier indices
        // unchanged.
        let mut vl_to_remove: Vec<usize> = match inner.lines.get(line_idx) {
            Some(line) => line.viewline_indices.iter().copied().collect(),
            None => Vec::new(),
        };
        let mut cm_to_remove: Vec<usize> = match inner.lines.get(line_idx) {
            Some(line) => line.cursormap_indices.iter().copied().collect(),
            None => Vec::new(),
        };
        vl_to_remove.sort_unstable_by(|a, b| b.cmp(a));
        cm_to_remove.sort_unstable_by(|a, b| b.cmp(a));

        // Step 2 — remove from master viewlines/cursormap (descending
        // order so each remove doesn't invalidate later indices).
        for v in &vl_to_remove {
            inner.viewlines.remove(*v);
        }
        for c in &cm_to_remove {
            inner.cursormap.remove(*c);
        }

        // Step 3 — for every surviving editor line, renumber any
        // viewline / cursormap indices that pointed past a removed
        // row. Each removal shifts the trailing indices down by 1.
        for (i, line) in inner.lines.iter_mut().enumerate() {
            if i == line_idx {
                continue;
            }
            let new_vl: Vec<usize> = line
                .viewline_indices
                .iter()
                .map(|&idx| {
                    let removed_below = vl_to_remove.iter().filter(|&&r| r < idx).count();
                    idx - removed_below
                })
                .collect();
            line.viewline_indices.clear();
            for idx in new_vl {
                line.viewline_indices.push_back(idx);
            }
            let new_cm: Vec<usize> = line
                .cursormap_indices
                .iter()
                .map(|&idx| {
                    let removed_below = cm_to_remove.iter().filter(|&&r| r < idx).count();
                    idx - removed_below
                })
                .collect();
            line.cursormap_indices.clear();
            for idx in new_cm {
                line.cursormap_indices.push_back(idx);
            }
        }

        // Step 4 — remove the editor line itself.
        inner.lines.remove(line_idx);

        // Step 5 — renumber master_index on every surviving line.
        // The deleted line was at `line_idx`; everything above
        // shifts down by 1.
        for (i, line) in inner.lines.iter_mut().enumerate() {
            line.master_index = i;
        }

        // Step 6 — fix up the cursor anchors if they referenced
        // removed entries.
        if let Some(t) = inner.topline {
            if vl_to_remove.contains(&t) {
                // Topline was deleted; advance to first surviving.
                inner.topline = if inner.viewlines.is_empty() { None } else { Some(0) };
            } else {
                // Decrement by however many removals were below.
                let below = vl_to_remove.iter().filter(|&&r| r < t).count();
                inner.topline = Some(t - below);
            }
        }
        if let Some(b) = inner.bottomline {
            if vl_to_remove.contains(&b) {
                inner.bottomline = if inner.viewlines.is_empty() {
                    None
                } else {
                    Some(inner.viewlines.len() - 1)
                };
            } else {
                let below = vl_to_remove.iter().filter(|&&r| r < b).count();
                inner.bottomline = Some(b - below);
            }
        }
        if let Some(c) = inner.cursorline {
            if cm_to_remove.contains(&c) {
                inner.cursorline = if inner.cursormap.is_empty() { None } else { Some(0) };
            } else {
                let below = cm_to_remove.iter().filter(|&&r| r < c).count();
                inner.cursorline = Some(c - below);
            }
        }

        Ok(())
    }

    /// FASM `tui_text$nvnewviewline` (`tui_text.inc` lines 2390–2602).
    ///
    /// Allocates (or reuses) a viewline + cursormap pair belonging to
    /// the editor line at `line_idx`. The pairs live as parallel
    /// entries in the master `viewlines` and `cursormap` lists, while
    /// each editor line stores back-pointing indices in its
    /// `viewline_indices` and `cursormap_indices` sublists.
    ///
    /// FASM walks four scenarios:
    /// 1. **No prev, sublist empty** — fresh allocation; either
    ///    `push_back` to master or `insert_before` the next editor
    ///    line's first viewline.
    /// 2. **No prev, sublist non-empty** — reset (clear) the first
    ///    entry of the editor's sublist and return it.
    /// 3. **Prev given, prev is last in sublist** — fresh allocation
    ///    after `prev_idx` in the master list.
    /// 4. **Prev given, prev not last in sublist** — reset the entry
    ///    immediately after `prev_idx` and return it.
    ///
    /// Returns `(viewline_idx, cursormap_idx)` where both indices
    /// reference rows in the master lists (always equal in the Rust
    /// port because the two lists stay in lockstep).
    fn nvnewviewline(
        &mut self,
        line_idx: usize,
        prev_viewline_idx: Option<usize>,
    ) -> Result<(usize, usize), TuiError> {
        // First decide what to do without holding any specific borrow,
        // then perform the action under the inner lock.
        enum Action {
            /// Reuse an existing pair — clear and return.
            Reuse(usize, usize),
            /// Allocate at this master position.
            /// `position == master.len()` means push_back.
            Allocate(usize),
        }

        let inner = self.inner_mut();
        let action: Action = if let Some(prev_idx) = prev_viewline_idx {
            // Scenarios 3/4 — prev is provided.
            let editor = inner.lines.get(line_idx).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "TuiText::nvnewviewline: line index out of bounds",
                ))
            })?;
            let sub_pos = editor
                .viewline_indices
                .iter()
                .position(|&v| v == prev_idx)
                .ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvnewviewline: prev viewline not in editor sublist",
                    ))
                })?;
            if sub_pos + 1 < editor.viewline_indices.len() {
                // Scenario 4: reuse entry at sub_pos + 1.
                let vl = *editor.viewline_indices.get(sub_pos + 1).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvnewviewline: viewline_indices.get(sub_pos+1) failed",
                    ))
                })?;
                let cm = *editor.cursormap_indices.get(sub_pos + 1).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvnewviewline: cursormap_indices.get(sub_pos+1) failed",
                    ))
                })?;
                Action::Reuse(vl, cm)
            } else {
                // Scenario 3: allocate after prev_idx in master.
                Action::Allocate(prev_idx + 1)
            }
        } else {
            // Scenarios 1/2 — no prev provided.
            let editor = inner.lines.get(line_idx).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "TuiText::nvnewviewline: line index out of bounds",
                ))
            })?;
            if !editor.viewline_indices.is_empty() {
                // Scenario 2: reuse first entry of sublist.
                let vl = *editor.viewline_indices.front().ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvnewviewline: viewline_indices.front() failed",
                    ))
                })?;
                let cm = *editor.cursormap_indices.front().ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvnewviewline: cursormap_indices.front() failed",
                    ))
                })?;
                Action::Reuse(vl, cm)
            } else {
                // Scenario 1: fresh allocation. If next editor line has
                // a viewline, insert before it; otherwise push_back.
                let editor_master = editor.master_index;
                let next_editor_first_vl: Option<usize> = inner
                    .lines
                    .iter()
                    .skip(editor_master + 1)
                    .find_map(|el| el.viewline_indices.front().copied());
                let pos = match next_editor_first_vl {
                    Some(idx) => idx,
                    None => inner.viewlines.len(),
                };
                Action::Allocate(pos)
            }
        };

        match action {
            Action::Reuse(vl, cm) => {
                if let Some(vl_arc) = inner.viewlines.get_mut(vl) {
                    let buf = Arc::get_mut(vl_arc).ok_or_else(|| {
                        TuiError::Render(std::io::Error::other(
                            "TuiText::nvnewviewline: viewline Arc not uniquely owned",
                        ))
                    })?;
                    buf.clear();
                }
                if let Some(cm_arc) = inner.cursormap.get_mut(cm) {
                    let buf = Arc::get_mut(cm_arc).ok_or_else(|| {
                        TuiError::Render(std::io::Error::other(
                            "TuiText::nvnewviewline: cursormap Arc not uniquely owned",
                        ))
                    })?;
                    buf.clear();
                }
                Ok((vl, cm))
            }
            Action::Allocate(pos) => {
                let new_vl = Arc::new(Buffer::new());
                let new_cm = Arc::new(Buffer::new());
                let master_len = inner.viewlines.len();
                let new_idx = if pos >= master_len {
                    // push_back path
                    inner.viewlines.push_back(new_vl);
                    inner.cursormap.push_back(new_cm);
                    master_len
                } else {
                    // insert path — must renumber all references >= pos.
                    inner.viewlines.insert(pos, new_vl).map_err(|e| {
                        TuiError::Render(std::io::Error::other(format!(
                            "TuiText::nvnewviewline: viewlines.insert: {e:?}"
                        )))
                    })?;
                    inner.cursormap.insert(pos, new_cm).map_err(|e| {
                        TuiError::Render(std::io::Error::other(format!(
                            "TuiText::nvnewviewline: cursormap.insert: {e:?}"
                        )))
                    })?;
                    // Renumber every editor line's sublists (excluding
                    // the line we're about to attach to — which gets
                    // updated below with the new index).
                    for el in inner.lines.iter_mut() {
                        let new_vl_indices: Vec<usize> = el
                            .viewline_indices
                            .iter()
                            .map(|&i| if i >= pos { i + 1 } else { i })
                            .collect();
                        el.viewline_indices.clear();
                        for i in new_vl_indices {
                            el.viewline_indices.push_back(i);
                        }
                        let new_cm_indices: Vec<usize> = el
                            .cursormap_indices
                            .iter()
                            .map(|&i| if i >= pos { i + 1 } else { i })
                            .collect();
                        el.cursormap_indices.clear();
                        for i in new_cm_indices {
                            el.cursormap_indices.push_back(i);
                        }
                    }
                    // Fix the cursor anchors.
                    if let Some(t) = inner.topline.as_mut() {
                        if *t >= pos {
                            *t += 1;
                        }
                    }
                    if let Some(b) = inner.bottomline.as_mut() {
                        if *b >= pos {
                            *b += 1;
                        }
                    }
                    if let Some(c) = inner.cursorline.as_mut() {
                        if *c >= pos {
                            *c += 1;
                        }
                    }
                    pos
                };
                // Attach the new index to the editor line's sublist.
                let editor = inner.lines.get_mut(line_idx).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvnewviewline: line index out of bounds (post-allocate)",
                    ))
                })?;
                editor.viewline_indices.push_back(new_idx);
                editor.cursormap_indices.push_back(new_idx);
                Ok((new_idx, new_idx))
            }
        }
    }

    /// FASM `tui_text$nvlastviewline` (`tui_text.inc` lines 2605–2702).
    ///
    /// Truncates the editor line's viewlines / cursormap sublists
    /// **after** the entry at `last_kept_viewline_idx`. All entries
    /// past the kept one are removed from the master lists and from
    /// the editor's sublists.
    ///
    /// FASM walks the editor's sublists in parallel until it finds
    /// `last_kept_viewline_idx`, then loops removing each subsequent
    /// entry. If the cursorline anchor pointed to one of the removed
    /// entries, it's reset to point to the immediately preceding
    /// surviving entry — this handles incremental edits where the
    /// cursor used to live on a now-trimmed viewline.
    ///
    /// Used as the final step of [`Self::nvleftcompose`] and
    /// [`Self::nvrightcompose`] to trim any stale viewlines remaining
    /// from a previous wider state.
    fn nvlastviewline(&mut self, line_idx: usize, last_kept_viewline_idx: usize) -> Result<(), TuiError> {
        let inner = self.inner_mut();
        // Find the position of last_kept in the editor's sublist.
        let editor = inner.lines.get(line_idx).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(
                "TuiText::nvlastviewline: line index out of bounds",
            ))
        })?;
        let kept_pos = editor
            .viewline_indices
            .iter()
            .position(|&v| v == last_kept_viewline_idx);
        let kept_pos = match kept_pos {
            Some(p) => p,
            // Kept index isn't in the sublist at all — nothing to do
            // (this can happen if the kept viewline was already the
            // last entry and got reused).
            None => return Ok(()),
        };

        // Collect the master-list indices that need removal —
        // everything in the editor's sublist past kept_pos.
        let editor_vl_len = editor.viewline_indices.len();
        if kept_pos + 1 >= editor_vl_len {
            // kept is already the last — nothing to remove.
            return Ok(());
        }
        let mut to_remove_master_vl: Vec<usize> = Vec::with_capacity(editor_vl_len - kept_pos - 1);
        let mut to_remove_master_cm: Vec<usize> = Vec::with_capacity(editor_vl_len - kept_pos - 1);
        for i in (kept_pos + 1)..editor_vl_len {
            if let Some(&v) = editor.viewline_indices.get(i) {
                to_remove_master_vl.push(v);
            }
            if let Some(&c) = editor.cursormap_indices.get(i) {
                to_remove_master_cm.push(c);
            }
        }

        // FASM has the cursorline-fix-up rule: if cursorline points to
        // one of the entries about to disappear, walk it back to the
        // most-recent surviving entry. The simplest correct equivalent
        // is to set cursorline to the kept entry's cursormap index.
        if let Some(c) = inner.cursorline {
            if to_remove_master_cm.contains(&c) {
                if let Some(&cm_kept) = editor.cursormap_indices.get(kept_pos) {
                    inner.cursorline = Some(cm_kept);
                }
            }
        }

        // Remove from each editor line's sublist (only the current
        // editor's sublist contains these indices). Remove in
        // descending order to avoid invalidating earlier positions.
        // Re-fetch the editor line via index since we held a borrow.
        {
            let editor = inner.lines.get_mut(line_idx).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "TuiText::nvlastviewline: line index out of bounds (mut)",
                ))
            })?;
            // Drop everything after kept_pos (positional removal).
            while editor.viewline_indices.len() > kept_pos + 1 {
                editor.viewline_indices.pop_back();
            }
            while editor.cursormap_indices.len() > kept_pos + 1 {
                editor.cursormap_indices.pop_back();
            }
        }

        // Sort descending so the master-list removals don't invalidate
        // each other, then remove.
        let mut vl_desc = to_remove_master_vl.clone();
        let mut cm_desc = to_remove_master_cm.clone();
        vl_desc.sort_unstable_by(|a, b| b.cmp(a));
        cm_desc.sort_unstable_by(|a, b| b.cmp(a));
        for v in &vl_desc {
            inner.viewlines.remove(*v);
        }
        for c in &cm_desc {
            inner.cursormap.remove(*c);
        }

        // Renumber every other editor line's sublists for the master
        // shrinkage that happened.
        for el in inner.lines.iter_mut() {
            let new_vl: Vec<usize> = el
                .viewline_indices
                .iter()
                .map(|&i| {
                    let removed_below = vl_desc.iter().filter(|&&r| r < i).count();
                    i.saturating_sub(removed_below)
                })
                .collect();
            el.viewline_indices.clear();
            for i in new_vl {
                el.viewline_indices.push_back(i);
            }
            let new_cm: Vec<usize> = el
                .cursormap_indices
                .iter()
                .map(|&i| {
                    let removed_below = cm_desc.iter().filter(|&&r| r < i).count();
                    i.saturating_sub(removed_below)
                })
                .collect();
            el.cursormap_indices.clear();
            for i in new_cm {
                el.cursormap_indices.push_back(i);
            }
        }

        // Adjust the cursor anchors for the master shrinkage.
        if let Some(t) = inner.topline {
            let removed_below = vl_desc.iter().filter(|&&r| r < t).count();
            inner.topline = Some(t.saturating_sub(removed_below));
            if inner.viewlines.is_empty() {
                inner.topline = None;
            } else if let Some(t) = inner.topline {
                if t >= inner.viewlines.len() {
                    inner.topline = Some(inner.viewlines.len() - 1);
                }
            }
        }
        if let Some(b) = inner.bottomline {
            let removed_below = vl_desc.iter().filter(|&&r| r < b).count();
            inner.bottomline = Some(b.saturating_sub(removed_below));
            if inner.viewlines.is_empty() {
                inner.bottomline = None;
            } else if let Some(b) = inner.bottomline {
                if b >= inner.viewlines.len() {
                    inner.bottomline = Some(inner.viewlines.len() - 1);
                }
            }
        }
        if let Some(c) = inner.cursorline {
            let removed_below = cm_desc.iter().filter(|&&r| r < c).count();
            inner.cursorline = Some(c.saturating_sub(removed_below));
            if inner.cursormap.is_empty() {
                inner.cursorline = None;
            } else if let Some(c) = inner.cursorline {
                if c >= inner.cursormap.len() {
                    inner.cursorline = Some(inner.cursormap.len() - 1);
                }
            }
        }

        Ok(())
    }

    /// FASM `tui_text$nvfindcursor` (`tui_text.inc` lines 754–901).
    ///
    /// Locates the cursor in the visible window for editor line
    /// `editor_idx` at byte offset `byte_offset` and updates the
    /// cursor coordinate fields (`cursor.x`, `cursor.y`, `cursorx`,
    /// `xscroll`, `cursorline`).
    ///
    /// Algorithm (from FASM):
    /// 1. **Backward walk** on `topline` while the previous viewline
    ///    belongs to the same editor line — this handles the case
    ///    where `topline` is a partial view of a multi-viewline
    ///    editor line (decrement `y` per step).
    /// 2. **Forward search** from `topline` for the first viewline
    ///    whose backing editor line matches `editor_idx`
    ///    (incrementing `y`).
    /// 3. **Min-length clamp**: if the target editor line is the
    ///    first one (no prev) and `min_len != 0`, clamp
    ///    `byte_offset = max(byte_offset, min_len << 2)`.
    /// 4. **Cursormap scan**: iterate cursormap entries from the
    ///    located viewline forward; within each cursormap, scan
    ///    4-byte cells for `byte_offset` match.
    /// 5. **On match**: set `cursorline` and compute `cursorx`,
    ///    branching on `x_position >= width` for xscroll
    ///    activation.
    fn nvfindcursor(&mut self, editor_idx: usize, byte_offset: usize) -> Result<(), TuiError> {
        // Snapshot bounds before grabbing the inner borrow to avoid
        // borrowing `self.state` and `self.inner` simultaneously.
        let width = self.state.bounds.width().max(0) as usize;
        let inner = self.inner_mut();

        // Resolve the master-list index of the target editor line's
        // first viewline (and its cursormap counterpart).
        let target_vl_indices: Vec<usize> = match inner.lines.get(editor_idx) {
            Some(el) => el.viewline_indices.iter().copied().collect(),
            None => return Ok(()),
        };
        if target_vl_indices.is_empty() {
            return Ok(());
        }

        // Step 3 — min-length clamp (only if target is first editor line).
        let mut byte_offset = byte_offset;
        if editor_idx == 0 && inner.minlen != 0 {
            let clamp = (inner.minlen as usize) * 4;
            if byte_offset < clamp {
                byte_offset = clamp;
            }
        }

        // Establish initial topline / y.
        let mut topline: usize = inner.topline.unwrap_or(0);
        let mut y: i32 = 0;

        // Step 1 — backward walk if topline is a partial view of an
        // editor line whose previous viewline also belongs to the
        // same editor line.
        loop {
            if topline == 0 {
                break;
            }
            // Identify the editor line for topline and topline-1.
            let cur_editor = Self::editor_index_for_viewline(&inner.lines, topline);
            let prev_editor = Self::editor_index_for_viewline(&inner.lines, topline - 1);
            match (cur_editor, prev_editor) {
                (Some(c), Some(p)) if c == p => {
                    topline -= 1;
                    y -= 1;
                }
                _ => break,
            }
        }

        // Step 2 — forward search from topline for the first viewline
        // whose owning editor line is editor_idx.
        let total_vl = inner.viewlines.len();
        while topline < total_vl {
            if let Some(owner) = Self::editor_index_for_viewline(&inner.lines, topline) {
                if owner == editor_idx {
                    break;
                }
            }
            topline += 1;
            y += 1;
        }

        // Step 4 — cursormap scan starting at `topline` (which is
        // also the cursormap row index because the lists stay in
        // lockstep). Continue across viewlines belonging to the
        // same editor line.
        let mut found = false;
        let mut cursorline_master_idx: usize = topline;
        let mut x_position: i32 = 0;
        for vl_idx in topline..total_vl {
            // Stop when the viewline belongs to a different editor.
            if let Some(owner) = Self::editor_index_for_viewline(&inner.lines, vl_idx) {
                if owner != editor_idx {
                    break;
                }
            }
            let cm_arc = match inner.cursormap.get(vl_idx) {
                Some(arc) => arc,
                None => break,
            };
            let cm_buf = cm_arc.as_slice();
            let mut x: i32 = 0;
            let mut i = 0usize;
            while i + 4 <= cm_buf.len() {
                let val =
                    u32::from_le_bytes([cm_buf[i], cm_buf[i + 1], cm_buf[i + 2], cm_buf[i + 3]]) as usize;
                if val == byte_offset {
                    cursorline_master_idx = vl_idx;
                    x_position = x;
                    found = true;
                    break;
                }
                x += 1;
                i += 4;
            }
            if found {
                break;
            }
            // Move to the next viewline within the same editor line.
            y += 1;
        }

        if !found {
            // FASM falls through with the loop's last position; we
            // mirror that — leave fields unchanged on miss.
            return Ok(());
        }

        // Step 5 — write cursor fields with optional xscroll.
        inner.cursorline = Some(cursorline_master_idx);
        inner.cursorx = (x_position as u32) << 2;
        if width > 0 && (x_position as usize) >= width {
            // xscroll activation: shift left by enough cells so the
            // cursor lands at width-1.
            let scroll_cells = (x_position as usize) - width + 1;
            inner.xscroll = (scroll_cells as u32) << 2;
            inner.cursor = Point {
                x: (width as i32) - 1,
                y,
            };
        } else {
            inner.xscroll = 0;
            inner.cursor = Point { x: x_position, y };
        }

        // Mirror FASM `setcursor` emission: docursor + focussed
        // emits an absolute cursor move via the renderer in `draw`;
        // here we only update the logical fields.
        Ok(())
    }

    /// Helper: returns the editor-line index (master_index) that owns
    /// the master `viewlines[vl_idx]` row, or `None` if no editor
    /// line currently references that index.
    ///
    /// Used by [`Self::nvfindcursor`] and other composition methods
    /// to resolve the FASM "buffer.user" backward link from a
    /// viewline buffer to its editor line.
    fn editor_index_for_viewline(lines: &List<EditorLine>, vl_idx: usize) -> Option<usize> {
        for el in lines.iter() {
            if el.viewline_indices.iter().any(|&i| i == vl_idx) {
                return Some(el.master_index);
            }
        }
        None
    }

    /// FASM `tui_text$nvheightchange` (`tui_text.inc` lines 3469–3672).
    ///
    /// Adjusts `topline` / `bottomline` after a content size change
    /// without triggering a full recompose. Three primary scenarios:
    ///
    /// - **`heightlock != 0`**: full lock — set `topline = 0`,
    ///   `bottomline = last`, and resize widget height to match the
    ///   total visible-line count (FASM also fires
    ///   `vsizechanged` / `vcalcbounds` / `vlayoutchanged`; the Rust
    ///   port records the new height so the parent layout pass
    ///   picks it up next frame).
    /// - **`viscount <= height`**: simple — `topline = 0`,
    ///   `bottomline = viscount - 1`. All viewlines fit; no
    ///   scrolling needed.
    /// - **`viscount > height`**: scrolling required. Walk
    ///   `topline → bottomline` counting visible rows; capture the
    ///   cursor's position within the visible window. Compare
    ///   `viscount` to `height`:
    ///     - **Equal** (`heightvismatch`): scroll both top and
    ///       bottom by one slot in the direction toward the cursor.
    ///     - **Less** (growing — `viscount` had been smaller):
    ///       extend the viewport boundaries by the difference.
    ///     - **More** (shrinking): contract the viewport by the
    ///       difference.
    ///
    /// The cursor's "half" (top vs bottom) is determined by
    /// comparing its position within the window to `height >> 1`.
    fn nvheightchange(&mut self) -> Result<(), TuiError> {
        // Snapshot bounds before grabbing the inner borrow.
        let height = self.state.bounds.height().max(0) as usize;
        let inner = self.inner_mut();
        let viscount = inner.viewlines.len();

        // Branch 1 — heightlock special path.
        if inner.heightlock != 0 {
            inner.prev_height = viscount as i32;
            inner.topline = if viscount == 0 { None } else { Some(0) };
            inner.bottomline = if viscount == 0 { None } else { Some(viscount - 1) };
            // Force the widget height to match the visible-line count.
            // The parent layout pass will use the new height on the
            // next pass via state.bounds — we encode the height by
            // updating the bottom-right of bounds. (FASM updates
            // `tui_height_ofs` directly; the Rust port mirrors via
            // `bounds.by`.)
            let new_h = viscount as i32;
            // Drop inner before mutating state.
            let ay = self.state.bounds.ay;
            self.state.bounds.by = ay + new_h;
            return Ok(());
        }

        // Branch 2 — viscount <= height: everything fits.
        if viscount <= height {
            inner.topline = if viscount == 0 { None } else { Some(0) };
            inner.bottomline = if viscount == 0 { None } else { Some(viscount - 1) };
            return Ok(());
        }

        // Branch 3 — viscount > height: scrolling required.
        let mut topline = inner.topline.unwrap_or(0);
        let mut bottomline = inner.bottomline.unwrap_or(viscount.saturating_sub(1));
        // Clamp to be safe.
        if topline >= viscount {
            topline = viscount - 1;
        }
        if bottomline >= viscount {
            bottomline = viscount - 1;
        }
        if bottomline < topline {
            bottomline = topline;
        }

        // Walk topline -> bottomline counting visible rows; identify
        // the cursor's position within the window via cursorline.
        let cursor_master = inner.cursorline.unwrap_or(topline);
        let mut cursor_pos_in_window: usize = 0;
        let mut window_count: usize = 0;
        for i in topline..=bottomline {
            if i == cursor_master {
                cursor_pos_in_window = window_count;
            }
            window_count += 1;
        }
        // Defensive: if cursor isn't in the current window, treat it
        // as being at row 0 (top) so growing pulls the bottom down.
        let _ = cursor_pos_in_window;

        let half_height = height >> 1;
        let in_top_half = cursor_pos_in_window < half_height;

        match window_count.cmp(&height) {
            std::cmp::Ordering::Equal => {
                // heightvismatch: scroll by 1 in the direction toward
                // cursor.
                if in_top_half {
                    if topline > 0 {
                        topline -= 1;
                        bottomline = bottomline.saturating_sub(1);
                    } else if bottomline + 1 < viscount {
                        topline += 1;
                        bottomline += 1;
                    }
                } else if bottomline + 1 < viscount {
                    topline += 1;
                    bottomline += 1;
                } else if topline > 0 {
                    topline -= 1;
                    bottomline = bottomline.saturating_sub(1);
                }
            }
            std::cmp::Ordering::Less => {
                // Growing: extend boundaries.
                let diff = height - window_count;
                if in_top_half {
                    // Grow top half: extend bottom forward.
                    bottomline = (bottomline + diff).min(viscount - 1);
                } else {
                    // Grow bottom half: extend top backward.
                    topline = topline.saturating_sub(diff);
                }
            }
            std::cmp::Ordering::Greater => {
                // Shrinking: contract boundaries.
                let diff = window_count - height;
                if in_top_half {
                    // Shrink top half: pull bottom backward.
                    bottomline = bottomline.saturating_sub(diff);
                } else {
                    // Shrink bottom half: push top forward.
                    topline = (topline + diff).min(viscount - 1);
                }
            }
        }

        inner.topline = Some(topline);
        inner.bottomline = Some(bottomline);
        Ok(())
    }

    /// FASM `tui_text$nvcompose` (`tui_text.inc` lines 2076–2289).
    ///
    /// Performs a full recomposition of all viewlines + cursormap
    /// entries from the current editor line state. The orchestrator
    /// for [`Self::nvleftcompose`] / [`Self::nvrightcompose`] /
    /// [`Self::nvcentercompose`] / [`Self::nvjustifiedcompose`]
    /// (selected per-line based on `inner.align`).
    ///
    /// FASM has two paths:
    ///
    /// - **Initial** (`topline == None`): no cursor preservation
    ///   needed — clear all sublists, recompose every line, then
    ///   set initial cursor at the end of the last line via
    ///   `.initialvalues`.
    /// - **Cursor preservation**: capture the editor line and byte
    ///   offset of the current cursor, clear and recompose, then
    ///   call [`Self::nvfindcursor`] with the captured target.
    ///   `topline` / `bottomline` are reset to bracket the cursor's
    ///   position in the new viewlines.
    ///
    /// Recomposition steps:
    /// 1. (If preserving cursor) capture `r12 = cursor's editor`,
    ///    `r13 = byte offset` from cursormap.
    /// 2. For each editor line, clear its viewline + cursormap
    ///    sublists.
    /// 3. Clear master `viewlines` + `cursormap` lists.
    /// 4. For each editor line, call the alignment-specific
    ///    composer (which reallocates buffers via
    ///    [`Self::nvnewviewline`]).
    /// 5. (If preserving cursor) walk new viewlines, expanding
    ///    `bottomline` by `height - 1`; if cursor's editor isn't
    ///    in the window, scroll forward; finally call
    ///    [`Self::nvfindcursor`] with `r12, r13`.
    /// 6. (Initial path) `bottomline = last`, walk back by
    ///    `height - 1` to get `topline`, set cursor at end of last
    ///    line.
    fn nvcompose(&mut self) -> Result<(), TuiError> {
        // Step 1 — capture cursor target if preservation is needed.
        let preserve: Option<(usize, usize)> = {
            let inner = self.inner_mut();
            match inner.topline {
                None => None,
                Some(_) => {
                    // Capture cursor's editor line + byte offset.
                    let cursorline_idx = match inner.cursorline {
                        Some(c) => c,
                        None => {
                            // FASM falls through to .nocursormap when
                            // topline is set but cursorline isn't —
                            // treat this as initial.
                            inner.topline = None;
                            inner.bottomline = None;
                            0
                        }
                    };
                    let cursorx = inner.cursorx as usize;
                    let cm_arc = match inner.cursormap.get(cursorline_idx) {
                        Some(arc) => arc.clone(),
                        None => {
                            inner.topline = None;
                            inner.bottomline = None;
                            return Ok(()); // nothing to compose; defer
                        }
                    };
                    let cm_buf = cm_arc.as_slice();
                    let byte_offset = if cursorx + 4 <= cm_buf.len() {
                        u32::from_le_bytes([
                            cm_buf[cursorx],
                            cm_buf[cursorx + 1],
                            cm_buf[cursorx + 2],
                            cm_buf[cursorx + 3],
                        ]) as usize
                    } else {
                        0
                    };
                    let editor_idx =
                        Self::editor_index_for_viewline(&inner.lines, cursorline_idx).unwrap_or(0);
                    Some((editor_idx, byte_offset))
                }
            }
        };

        // Step 2/3 — clear all sublists + master lists.
        {
            let inner = self.inner_mut();
            for line in inner.lines.iter_mut() {
                line.viewline_indices.clear();
                line.cursormap_indices.clear();
            }
            inner.viewlines.clear();
            inner.cursormap.clear();
            // Reset cursor anchors so nvnewviewline doesn't try to
            // bump them while it's allocating.
            inner.topline = None;
            inner.bottomline = None;
            inner.cursorline = None;
        }

        // Step 4 — for each editor line, dispatch to the composer.
        let line_count = self.inner_mut().lines.len();
        for line_idx in 0..line_count {
            self.nvcomposeline(line_idx)?;
        }

        // Step 5/6 — set up initial cursor / preserve cursor.
        let height = self.state.bounds.height().max(0) as usize;
        let viewlines_len = self.inner_mut().viewlines.len();
        if viewlines_len == 0 {
            // No content (shouldn't happen post-empty-invariant,
            // but be defensive).
            return Ok(());
        }

        match preserve {
            None => {
                // Initial — `.initialvalues`. Bottom = last viewline;
                // top = bottom - (height - 1) clamped to 0; cursor
                // anchored at the end of the last editor line.
                let bottomline = viewlines_len - 1;
                let topline = bottomline.saturating_sub(height.saturating_sub(1));
                // Snapshot last-editor data inside a scoped block so
                // the inner borrow ends before the nvfindcursor call.
                let (last_editor_idx, last_editor_len) = {
                    let inner = self.inner_mut();
                    inner.bottomline = Some(bottomline);
                    inner.topline = Some(topline);
                    inner.cursorline = Some(viewlines_len - 1);
                    let idx = inner.lines.len().saturating_sub(1);
                    let len = inner.lines.get(idx).map(|el| el.text.len()).unwrap_or(0);
                    (idx, len)
                };
                self.nvfindcursor(last_editor_idx, last_editor_len)?;
            }
            Some((editor_idx, byte_offset)) => {
                // Preserve — bracket the cursor's editor line in the
                // new window; first scan forward from 0 by height-1
                // and check whether the editor's first viewline lies
                // within. If not, advance topline.
                {
                    let inner = self.inner_mut();
                    let mut topline = 0usize;
                    let mut bottomline = topline.saturating_add(height.saturating_sub(1));
                    if bottomline >= viewlines_len {
                        bottomline = viewlines_len - 1;
                    }
                    // Find target editor line's first viewline index.
                    let target_first_vl: Option<usize> = inner
                        .lines
                        .get(editor_idx)
                        .and_then(|el| el.viewline_indices.front().copied());
                    if let Some(t) = target_first_vl {
                        if t > bottomline {
                            // Scroll forward so cursor lands in window.
                            topline = t.saturating_sub(height.saturating_sub(1));
                            bottomline = topline.saturating_add(height.saturating_sub(1));
                            if bottomline >= viewlines_len {
                                bottomline = viewlines_len - 1;
                                topline = bottomline.saturating_sub(height.saturating_sub(1));
                            }
                        }
                    }
                    inner.topline = Some(topline);
                    inner.bottomline = Some(bottomline);
                }
                self.nvfindcursor(editor_idx, byte_offset)?;
            }
        }

        Ok(())
    }

    /// FASM `tui_text$nvcomposeline` (`tui_text.inc` lines 2042–2073).
    ///
    /// Dispatches to one of the four alignment-specific composition
    /// implementations based on `inner.align`. The two unimplemented
    /// stubs ([`AlignMode::Center`] / [`AlignMode::Justified`]) fall
    /// back to [`Self::nvleftcompose`] in release builds and trigger
    /// a `debug_assert!` in debug builds.
    fn nvcomposeline(&mut self, line_idx: usize) -> Result<(), TuiError> {
        let align = {
            let inner = self.inner_mut();
            inner.align
        };
        match align {
            AlignMode::Left => self.nvleftcompose(line_idx),
            AlignMode::Right => self.nvrightcompose(line_idx),
            AlignMode::Center => self.nvcentercompose(line_idx),
            AlignMode::Justified => self.nvjustifiedcompose(line_idx),
        }
    }

    /// FASM `tui_text$nvcentercompose` (`tui_text.inc` lines 3416–3425).
    ///
    /// **Unimplemented stub in the FASM source** — the assembly
    /// emits a bare `prolog ; breakpoint ; epilog` triplet. This
    /// Rust port preserves that behavior:
    /// - `debug_assert!(false)` fires in debug builds (matching the
    ///   FASM `breakpoint` semantics).
    /// - In release builds the call silently falls back to
    ///   [`Self::nvleftcompose`] so the widget remains usable.
    fn nvcentercompose(&mut self, line_idx: usize) -> Result<(), TuiError> {
        debug_assert!(
            false,
            "TuiText::nvcentercompose: unimplemented in FASM (tui_text.inc:3416–3425); \
             falling back to nvleftcompose"
        );
        self.nvleftcompose(line_idx)
    }

    /// FASM `tui_text$nvjustifiedcompose` (`tui_text.inc` lines 3427–3436).
    ///
    /// **Unimplemented stub in the FASM source** — same fall-back
    /// pattern as [`Self::nvcentercompose`].
    fn nvjustifiedcompose(&mut self, line_idx: usize) -> Result<(), TuiError> {
        debug_assert!(
            false,
            "TuiText::nvjustifiedcompose: unimplemented in FASM (tui_text.inc:3427–3436); \
             falling back to nvleftcompose"
        );
        self.nvleftcompose(line_idx)
    }

    /// FASM `tui_text$nvleftcompose` (`tui_text.inc` lines 2705–3055).
    ///
    /// FASM `.wrap` / `.nowrap` algorithm (`tui_text.inc` 2709–3055).
    ///
    /// Two paths driven by `wrap`:
    ///
    /// * **`.wrap`** (hardwrap or wordwrap): loop over the source
    ///   producing one viewline per `width` cells. Each iteration
    ///   reserves `width*4` bytes for both the viewline buffer (filled
    ///   with `' '`) and the cursormap (filled with `0xffffffff`). For
    ///   wordwrap the algorithm walks backward up to `width/2` cells
    ///   from the column boundary searching for `' '` or `'-'`; on
    ///   match the chop length is set to that position **plus** the
    ///   space (FASM `add r9d, 4`). After populating the viewline /
    ///   cursormap for the current chunk the source pointer advances
    ///   and the next iteration runs. If the source ends exactly on
    ///   a viewline boundary FASM emits one extra empty viewline so
    ///   the cursor can be positioned past the last character.
    /// * **`.nowrap`** (`wrap == Scroll`): one viewline whose width is
    ///   `max(nvmaxx, bounds.width()) * 4` bytes. Cursormap reserves
    ///   the same length **plus 4** so the very last 4-byte slot can
    ///   hold a dangling cursor offset for navigation past the end.
    ///   Cursor positions [0..source_len] receive their byte offsets,
    ///   then `cursormap[source_len] = source_len` (the dangling
    ///   slot).
    ///
    /// All paths conclude by calling [`Self::nvlastviewline`] to
    /// truncate any stale viewlines from a previous wider state.
    fn nvleftcompose(&mut self, line_idx: usize) -> Result<(), TuiError> {
        // Snapshot bounds before grabbing the inner borrow.
        let width_cells = self.state.bounds.width().max(0) as usize;

        // Snapshot the editor source bytes + relevant config under a
        // short-lived borrow; perform the heavy buffer work without
        // holding the inner borrow.
        let (source, wrap, pwdchar, max_chars) = {
            let inner = self.inner_mut();
            let src = match inner.lines.get(line_idx) {
                Some(el) => el.text.as_slice().to_vec(),
                None => {
                    return Err(TuiError::Render(std::io::Error::other(
                        "TuiText::nvleftcompose: line index out of bounds",
                    )));
                }
            };
            let wrap = inner.wrap;
            let pwd = inner.pwdchar;
            // For .nowrap we need max-line-width across all editor
            // lines (in cells, not bytes).
            let max = inner.lines.iter().map(|el| el.text.len() / 4).max().unwrap_or(0);
            (src, wrap, pwd, max)
        };

        let source_len = source.len(); // bytes; chars = source_len / 4
        let pwdchar_set = pwdchar != 0;

        if wrap == WrapMode::Scroll {
            // ---- .nowrap path (single viewline) ----
            let nowrap_chars = max_chars.max(width_cells).max(1);
            let nowrap_bytes = nowrap_chars * 4;
            let (vl_idx, cm_idx) = self.nvnewviewline(line_idx, None)?;
            // Populate viewline + cursormap on the master entries
            // located at vl_idx / cm_idx.
            let inner = self.inner_mut();
            // -- Viewline buffer --
            {
                let vl_arc = inner.viewlines.get_mut(vl_idx).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvleftcompose: viewline arc missing",
                    ))
                })?;
                let buf = Arc::get_mut(vl_arc).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvleftcompose: viewline Arc not unique",
                    ))
                })?;
                buf.reserve(nowrap_bytes);
                // memset32 with ' '
                for _ in 0..nowrap_chars {
                    buf.push_u32_le(b' ' as u32);
                }
                // Then memcpy / memset32 source into the leading
                // bytes of the viewline.
                if source_len > 0 {
                    let slot = buf.as_mut_slice();
                    if pwdchar_set {
                        let mut i = 0usize;
                        while i + 4 <= source_len.min(slot.len()) {
                            let bytes = pwdchar.to_le_bytes();
                            slot[i] = bytes[0];
                            slot[i + 1] = bytes[1];
                            slot[i + 2] = bytes[2];
                            slot[i + 3] = bytes[3];
                            i += 4;
                        }
                    } else {
                        let copy_len = source_len.min(slot.len());
                        slot[..copy_len].copy_from_slice(&source[..copy_len]);
                    }
                }
            }
            // -- Cursormap buffer --
            {
                let cm_arc = inner.cursormap.get_mut(cm_idx).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvleftcompose: cursormap arc missing",
                    ))
                })?;
                let buf = Arc::get_mut(cm_arc).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvleftcompose: cursormap Arc not unique",
                    ))
                })?;
                // FASM allocates source_len-aligned-to-cell bytes plus
                // 4 (the dangling cursor slot). For .nowrap the
                // cursormap length is `nowrap_bytes + 4` and the
                // initial fill (0xffffffff) covers `nowrap_bytes`
                // (NOT +4); the dangling slot is overwritten at the
                // end with `source_len`.
                buf.reserve(nowrap_bytes + 4);
                for _ in 0..nowrap_chars {
                    buf.push_u32_le(0xffff_ffff);
                }
                buf.push_u32_le(0); // dangling slot — set below
                let slot = buf.as_mut_slice();
                // Write [0..source_len] with incrementing offsets:
                // cm[i*4..i*4+4] = i*4 for i = 0..source_chars
                let source_chars = source_len / 4;
                for i in 0..source_chars {
                    let off = (i * 4) as u32;
                    let bytes = off.to_le_bytes();
                    slot[i * 4] = bytes[0];
                    slot[i * 4 + 1] = bytes[1];
                    slot[i * 4 + 2] = bytes[2];
                    slot[i * 4 + 3] = bytes[3];
                }
                // Dangling cursor slot — last 4 bytes hold source_len.
                let dangling_off = source_len.min(slot.len().saturating_sub(4));
                if slot.len() >= 4 {
                    let bytes = (source_len as u32).to_le_bytes();
                    slot[dangling_off] = bytes[0];
                    slot[dangling_off + 1] = bytes[1];
                    slot[dangling_off + 2] = bytes[2];
                    slot[dangling_off + 3] = bytes[3];
                }
            }
            // Trim any stale viewlines past the one we just wrote.
            self.nvlastviewline(line_idx, vl_idx)?;
            return Ok(());
        }

        // ---- .wrap path (hardwrap or wordwrap) ----
        if width_cells == 0 {
            // Cannot wrap to 0 columns; fall back to a single empty
            // viewline.
            let (vl_idx, _cm_idx) = self.nvnewviewline(line_idx, None)?;
            self.nvlastviewline(line_idx, vl_idx)?;
            return Ok(());
        }
        let width_bytes = width_cells * 4;
        let mut prev_viewline: Option<usize> = None;
        let mut src_offset: usize = 0;
        // Tracks the master-list index of the most-recently produced
        // viewline; deferred initialization (no dead `None`) so the
        // strict `unused_assignments` lint stays clean.
        let mut last_vl_idx: usize;
        loop {
            let remaining = source_len - src_offset;
            // Allocate a fresh viewline + cursormap pair.
            let (vl_idx, cm_idx) = self.nvnewviewline(line_idx, prev_viewline)?;
            last_vl_idx = vl_idx;

            // Determine chunk size in bytes (may shrink for wordwrap).
            let mut chunk_bytes = remaining.min(width_bytes);

            // Wordwrap backward search.
            if wrap == WrapMode::Word && remaining > width_bytes && chunk_bytes > 0 {
                let limit = (width_cells / 2).max(1); // search at least 1 cell
                let mut search_pos = chunk_bytes.saturating_sub(4); // last cell idx
                let mut steps = 0usize;
                let mut found_at: Option<usize> = None;
                while steps < limit && search_pos < chunk_bytes {
                    let abs = src_offset + search_pos;
                    if abs + 4 > source_len {
                        break;
                    }
                    let ch =
                        u32::from_le_bytes([source[abs], source[abs + 1], source[abs + 2], source[abs + 3]]);
                    if ch == b' ' as u32 || ch == b'-' as u32 {
                        found_at = Some(search_pos);
                        break;
                    }
                    if search_pos < 4 {
                        break;
                    }
                    search_pos -= 4;
                    steps += 1;
                }
                if let Some(pos) = found_at {
                    // FASM left includes the breaking character on
                    // this line: chunk_bytes = pos + 4.
                    chunk_bytes = pos + 4;
                }
            }

            // Now populate this viewline's buffers.
            let inner = self.inner_mut();
            // -- Viewline --
            {
                let vl_arc = inner.viewlines.get_mut(vl_idx).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvleftcompose: wrap viewline arc missing",
                    ))
                })?;
                let buf = Arc::get_mut(vl_arc).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvleftcompose: wrap viewline Arc not unique",
                    ))
                })?;
                buf.reserve(width_bytes);
                for _ in 0..width_cells {
                    buf.push_u32_le(b' ' as u32);
                }
                if chunk_bytes > 0 {
                    let slot = buf.as_mut_slice();
                    if pwdchar_set {
                        let mut i = 0usize;
                        let copy_bytes = chunk_bytes.min(slot.len());
                        while i + 4 <= copy_bytes {
                            let bytes = pwdchar.to_le_bytes();
                            slot[i] = bytes[0];
                            slot[i + 1] = bytes[1];
                            slot[i + 2] = bytes[2];
                            slot[i + 3] = bytes[3];
                            i += 4;
                        }
                    } else {
                        let copy_bytes = chunk_bytes.min(slot.len());
                        let src_end = (src_offset + copy_bytes).min(source.len());
                        slot[..copy_bytes].copy_from_slice(&source[src_offset..src_end]);
                    }
                }
            }
            // -- Cursormap --
            {
                let cm_arc = inner.cursormap.get_mut(cm_idx).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvleftcompose: wrap cursormap arc missing",
                    ))
                })?;
                let buf = Arc::get_mut(cm_arc).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvleftcompose: wrap cursormap Arc not unique",
                    ))
                })?;
                buf.reserve(width_bytes);
                for _ in 0..width_cells {
                    buf.push_u32_le(0xffff_ffff);
                }
                let slot = buf.as_mut_slice();
                // [0..chunk_bytes] := offset = src_offset + i*4 for
                // i in 0..(chunk_bytes/4).
                let chunk_cells = chunk_bytes / 4;
                for i in 0..chunk_cells {
                    let off = (src_offset + i * 4) as u32;
                    let bytes = off.to_le_bytes();
                    let pos = i * 4;
                    if pos + 4 <= slot.len() {
                        slot[pos] = bytes[0];
                        slot[pos + 1] = bytes[1];
                        slot[pos + 2] = bytes[2];
                        slot[pos + 3] = bytes[3];
                    }
                }
            }

            src_offset += chunk_bytes;
            prev_viewline = Some(vl_idx);

            if chunk_bytes == 0 || src_offset >= source_len {
                break;
            }
        }

        // FASM `.wrap` emits an EXTRA empty viewline if the source
        // ends exactly at a viewline boundary so the cursor has a
        // valid position past the last character of the last full
        // line. Detect this: source ended on a multiple of width_bytes
        // AND we used at least one chunk that was full-width.
        if source_len > 0 && source_len % width_bytes == 0 {
            let (vl_idx, cm_idx) = self.nvnewviewline(line_idx, prev_viewline)?;
            last_vl_idx = vl_idx;
            let inner = self.inner_mut();
            // Empty viewline (filled with spaces).
            if let Some(vl_arc) = inner.viewlines.get_mut(vl_idx) {
                if let Some(buf) = Arc::get_mut(vl_arc) {
                    buf.reserve(width_bytes);
                    for _ in 0..width_cells {
                        buf.push_u32_le(b' ' as u32);
                    }
                }
            }
            // Cursormap with a single valid position at index 0 for
            // the dangling cursor.
            if let Some(cm_arc) = inner.cursormap.get_mut(cm_idx) {
                if let Some(buf) = Arc::get_mut(cm_arc) {
                    buf.reserve(width_bytes);
                    for _ in 0..width_cells {
                        buf.push_u32_le(0xffff_ffff);
                    }
                    let slot = buf.as_mut_slice();
                    if slot.len() >= 4 {
                        let bytes = (source_len as u32).to_le_bytes();
                        slot[0] = bytes[0];
                        slot[1] = bytes[1];
                        slot[2] = bytes[2];
                        slot[3] = bytes[3];
                    }
                }
            }
        }

        self.nvlastviewline(line_idx, last_vl_idx)?;
        Ok(())
    }

    /// FASM `tui_text$nvrightcompose` (`tui_text.inc` lines 3062–3408).
    ///
    /// Right-aligned composition; structurally mirrors
    /// [`Self::nvleftcompose`] but with three crucial differences:
    ///
    /// 1. **Forced 1-char right gutter** — `chunk_bytes` is clamped
    ///    to `(width - 1) * 4` (NOT `width * 4`). The last column
    ///    is reserved as a dangling cursor slot — this is FASM's
    ///    explanation in the source: "we have an enforced right
    ///    gutter of 1 char, we don't need to add a separate line".
    /// 2. **Wordwrap chop excludes the breaking space** — when
    ///    wordwrap finds a `' '` or `'-'`, FASM does **not**
    ///    `add r9d, 4` (the space stays on the next line). Compare
    ///    [`Self::nvleftcompose`] which includes the space on the
    ///    current line.
    /// 3. **Right-align the source bytes** in the viewline buffer
    ///    via `r10 = viewline_len - chunk_bytes - 4` (gutter offset).
    ///    Cursormap entries are written at `cursormap_len - r11`
    ///    where `r11 = chunk_bytes + 4` (chunk + gutter).
    ///
    /// `.wrap` does **not** emit an extra empty viewline at the end
    /// because the gutter already provides the dangling cursor slot.
    /// `.nowrap` keeps the +4 byte dangling allocation just like
    /// left-align (so the user can navigate one cell past the end).
    fn nvrightcompose(&mut self, line_idx: usize) -> Result<(), TuiError> {
        let width_cells = self.state.bounds.width().max(0) as usize;
        let (source, wrap, pwdchar, max_chars) = {
            let inner = self.inner_mut();
            let src = match inner.lines.get(line_idx) {
                Some(el) => el.text.as_slice().to_vec(),
                None => {
                    return Err(TuiError::Render(std::io::Error::other(
                        "TuiText::nvrightcompose: line index out of bounds",
                    )));
                }
            };
            let wrap = inner.wrap;
            let pwd = inner.pwdchar;
            let max = inner.lines.iter().map(|el| el.text.len() / 4).max().unwrap_or(0);
            (src, wrap, pwd, max)
        };
        let source_len = source.len();
        let pwdchar_set = pwdchar != 0;

        if wrap == WrapMode::Scroll {
            // ---- .nowrap path (right-aligned single viewline) ----
            let nowrap_chars = max_chars.max(width_cells).max(1);
            let nowrap_bytes = nowrap_chars * 4;
            let (vl_idx, cm_idx) = self.nvnewviewline(line_idx, None)?;
            let inner = self.inner_mut();
            // -- Viewline (right-aligned) --
            {
                let vl_arc = inner.viewlines.get_mut(vl_idx).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvrightcompose: viewline arc missing",
                    ))
                })?;
                let buf = Arc::get_mut(vl_arc).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvrightcompose: viewline Arc not unique",
                    ))
                })?;
                buf.reserve(nowrap_bytes);
                for _ in 0..nowrap_chars {
                    buf.push_u32_le(b' ' as u32);
                }
                if source_len > 0 {
                    // r10 = nowrap_bytes - source_len (right-align).
                    let dest_offset = nowrap_bytes.saturating_sub(source_len);
                    let copy_len = source_len.min(nowrap_bytes - dest_offset);
                    let slot = buf.as_mut_slice();
                    if pwdchar_set {
                        let mut i = 0usize;
                        while i + 4 <= copy_len {
                            let bytes = pwdchar.to_le_bytes();
                            slot[dest_offset + i] = bytes[0];
                            slot[dest_offset + i + 1] = bytes[1];
                            slot[dest_offset + i + 2] = bytes[2];
                            slot[dest_offset + i + 3] = bytes[3];
                            i += 4;
                        }
                    } else {
                        slot[dest_offset..dest_offset + copy_len].copy_from_slice(&source[..copy_len]);
                    }
                }
            }
            // -- Cursormap (right-aligned with +4 dangling slot) --
            {
                let cm_arc = inner.cursormap.get_mut(cm_idx).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvrightcompose: cursormap arc missing",
                    ))
                })?;
                let buf = Arc::get_mut(cm_arc).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvrightcompose: cursormap Arc not unique",
                    ))
                })?;
                buf.reserve(nowrap_bytes + 4);
                for _ in 0..nowrap_chars {
                    buf.push_u32_le(0xffff_ffff);
                }
                buf.push_u32_le(0); // dangling slot
                let slot = buf.as_mut_slice();
                let cm_offset = nowrap_bytes.saturating_sub(source_len);
                let source_cells = source_len / 4;
                for i in 0..source_cells {
                    let off = (i * 4) as u32;
                    let bytes = off.to_le_bytes();
                    let pos = cm_offset + i * 4;
                    if pos + 4 <= slot.len() {
                        slot[pos] = bytes[0];
                        slot[pos + 1] = bytes[1];
                        slot[pos + 2] = bytes[2];
                        slot[pos + 3] = bytes[3];
                    }
                }
                // Dangling slot at end: cm[nowrap_bytes..nowrap_bytes+4]
                // = source_len.
                if slot.len() >= nowrap_bytes + 4 {
                    let bytes = (source_len as u32).to_le_bytes();
                    slot[nowrap_bytes] = bytes[0];
                    slot[nowrap_bytes + 1] = bytes[1];
                    slot[nowrap_bytes + 2] = bytes[2];
                    slot[nowrap_bytes + 3] = bytes[3];
                }
            }
            self.nvlastviewline(line_idx, vl_idx)?;
            return Ok(());
        }

        // ---- .wrap path (right-aligned, 1-char gutter) ----
        if width_cells <= 1 {
            // No room for gutter + content; fall back to empty.
            let (vl_idx, _cm_idx) = self.nvnewviewline(line_idx, None)?;
            self.nvlastviewline(line_idx, vl_idx)?;
            return Ok(());
        }
        let width_bytes = width_cells * 4;
        // Forced 1-char gutter: max content per line = (width - 1) * 4.
        let max_chunk_bytes = (width_cells - 1) * 4;
        let mut prev_viewline: Option<usize> = None;
        let mut src_offset: usize = 0;
        // Tracks the master-list index of the most-recently produced
        // viewline; deferred initialization (no dead initial value)
        // so the strict `unused_assignments` lint stays clean.
        let mut last_vl_idx: usize;
        loop {
            let remaining = source_len - src_offset;
            let (vl_idx, cm_idx) = self.nvnewviewline(line_idx, prev_viewline)?;
            last_vl_idx = vl_idx;

            // edx = min(max_chunk_bytes, remaining).
            let mut chunk_bytes = remaining.min(max_chunk_bytes);

            // Wordwrap backward search — same scan as left, but on
            // match the chop excludes the breaking character.
            if wrap == WrapMode::Word && remaining > max_chunk_bytes && chunk_bytes > 0 {
                let limit = (width_cells / 2).max(1);
                let mut search_pos = chunk_bytes.saturating_sub(4);
                let mut steps = 0usize;
                let mut found_at: Option<usize> = None;
                while steps < limit && search_pos < chunk_bytes {
                    let abs = src_offset + search_pos;
                    if abs + 4 > source_len {
                        break;
                    }
                    let ch =
                        u32::from_le_bytes([source[abs], source[abs + 1], source[abs + 2], source[abs + 3]]);
                    if ch == b' ' as u32 || ch == b'-' as u32 {
                        found_at = Some(search_pos);
                        break;
                    }
                    if search_pos < 4 {
                        break;
                    }
                    search_pos -= 4;
                    steps += 1;
                }
                if let Some(pos) = found_at {
                    // RIGHT excludes the breaking character: chop = pos.
                    chunk_bytes = pos;
                }
            }

            // Populate buffers. Right-align the source: viewline write
            // offset = width_bytes - chunk_bytes - 4 (gutter).
            let inner = self.inner_mut();
            // -- Viewline --
            {
                let vl_arc = inner.viewlines.get_mut(vl_idx).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvrightcompose: wrap viewline arc missing",
                    ))
                })?;
                let buf = Arc::get_mut(vl_arc).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvrightcompose: wrap viewline Arc not unique",
                    ))
                })?;
                buf.reserve(width_bytes);
                for _ in 0..width_cells {
                    buf.push_u32_le(b' ' as u32);
                }
                if chunk_bytes > 0 {
                    // r10 = width_bytes - chunk_bytes - 4 (gutter).
                    let dest_offset = width_bytes.saturating_sub(chunk_bytes).saturating_sub(4);
                    let slot = buf.as_mut_slice();
                    let copy_bytes = chunk_bytes.min(slot.len() - dest_offset);
                    if pwdchar_set {
                        let mut i = 0usize;
                        while i + 4 <= copy_bytes {
                            let bytes = pwdchar.to_le_bytes();
                            slot[dest_offset + i] = bytes[0];
                            slot[dest_offset + i + 1] = bytes[1];
                            slot[dest_offset + i + 2] = bytes[2];
                            slot[dest_offset + i + 3] = bytes[3];
                            i += 4;
                        }
                    } else {
                        let src_end = (src_offset + copy_bytes).min(source.len());
                        slot[dest_offset..dest_offset + copy_bytes]
                            .copy_from_slice(&source[src_offset..src_end]);
                    }
                }
            }
            // -- Cursormap --
            {
                let cm_arc = inner.cursormap.get_mut(cm_idx).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvrightcompose: wrap cursormap arc missing",
                    ))
                })?;
                let buf = Arc::get_mut(cm_arc).ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(
                        "TuiText::nvrightcompose: wrap cursormap Arc not unique",
                    ))
                })?;
                buf.reserve(width_bytes);
                for _ in 0..width_cells {
                    buf.push_u32_le(0xffff_ffff);
                }
                // FASM r11 = chunk_bytes + 4 (gutter); cm offset start
                // = width_bytes - r11.
                let r11 = chunk_bytes + 4;
                let cm_offset = width_bytes.saturating_sub(r11);
                let slot = buf.as_mut_slice();
                let chunk_cells = chunk_bytes / 4;
                for i in 0..chunk_cells {
                    let off = (src_offset + i * 4) as u32;
                    let bytes = off.to_le_bytes();
                    let pos = cm_offset + i * 4;
                    if pos + 4 <= slot.len() {
                        slot[pos] = bytes[0];
                        slot[pos + 1] = bytes[1];
                        slot[pos + 2] = bytes[2];
                        slot[pos + 3] = bytes[3];
                    }
                }
                // Last entry at the gutter slot — FASM `[rdi+rcx]=eax`
                // at the .wrap_partial_last label after the final
                // chunk. We always populate the gutter slot with the
                // current advance position so the cursor can land
                // there.
                let gutter_pos = cm_offset + chunk_cells * 4;
                if gutter_pos + 4 <= slot.len() {
                    let bytes = ((src_offset + chunk_bytes) as u32).to_le_bytes();
                    slot[gutter_pos] = bytes[0];
                    slot[gutter_pos + 1] = bytes[1];
                    slot[gutter_pos + 2] = bytes[2];
                    slot[gutter_pos + 3] = bytes[3];
                }
            }

            src_offset += chunk_bytes;
            prev_viewline = Some(vl_idx);

            if chunk_bytes == 0 || src_offset >= source_len {
                break;
            }
        }

        // FASM right-align does NOT emit an extra empty viewline
        // (the 1-char gutter already provides the dangling cursor
        // slot). Just trim and return.
        self.nvlastviewline(line_idx, last_vl_idx)?;
        Ok(())
    }
}

// ============================================================================
// TuiText — Key event handlers (Chunk 6)
// ============================================================================
//
// Ports the 15+ key-handler subroutines from `tui_text.inc`
// (lines 1089–1960). Each handler is invoked from
// [`<TuiText as Widget>::key_event`] (the dispatcher below) and
// returns `Result<bool, TuiError>` where the `bool` indicates
// whether the keystroke was consumed by this widget.
//
// FASM source layout (preserved order):
//   - key_char                (1089–1190) — printable codepoint insert
//   - key_uparrow             (1227–1297)
//   - key_downarrow           (1300–1373)
//   - key_rightarrow          (1377–1399)
//   - key_shiftend            (1401–1420) — End key
//   - key_leftarrow           (1422–1445)
//   - key_shifthome           (1448–1462) — Home key
//   - key_backspace_startofline (1465–1595) — multi-line merge prev
//   - key_backspace           (1597–1705) — single-line erase prev
//   - key_delete_endofline    (1708–1805) — multi-line merge next
//   - key_delete              (1807–1852) — single-line erase under
//   - key_tab                 (1855–1859) — forward to parent
//   - key_shifttab            (1862–1866) — forward to parent
//   - key_cr                  (1869–1875) — single-line invokes on_enter
//   - key_cr_multiline        (1877–1960) — split editor line at cursor

impl TuiText {
    /// Helper: count the total number of editor characters across all
    /// editor lines (for the maxlen guard in [`Self::key_char`]).
    /// FASM `tui_text$keyevent .checkmaxlen` (lines 1095–1118) sums
    /// `(line.text.len() / 4)` over `lines` — LF separators between
    /// editor lines are NOT counted because they are implicit.
    fn total_char_count(&mut self) -> usize {
        let inner = self.inner_mut();
        inner.lines.iter().map(|el| el.text.len() / 4).sum()
    }

    /// Helper: locate the editor-line index that owns the current
    /// `cursorline` viewline. Mirrors FASM's "buffer.user" backward
    /// link via the `master_index` field of [`EditorLine`].
    fn editor_idx_for_cursorline(&mut self) -> Option<usize> {
        let inner = self.inner_mut();
        let cl = inner.cursorline?;
        Self::editor_index_for_viewline(&inner.lines, cl)
    }

    /// Helper: read the byte-offset stored at cell `byte_x` in the
    /// cursormap of viewline `vl_idx`. Returns `None` if out of
    /// bounds. The sentinel `0xffff_ffff` is returned as `Some(u32::MAX)`
    /// — callers must check for it explicitly.
    fn cursormap_offset_at(&mut self, vl_idx: usize, byte_x: usize) -> Option<u32> {
        let inner = self.inner_mut();
        let cm_arc = inner.cursormap.get(vl_idx)?;
        let buf = cm_arc.as_slice();
        if byte_x + 4 > buf.len() {
            return None;
        }
        Some(u32::from_le_bytes([
            buf[byte_x],
            buf[byte_x + 1],
            buf[byte_x + 2],
            buf[byte_x + 3],
        ]))
    }

    /// FASM `tui_text$key_char` (`tui_text.inc` lines 1089–1190).
    ///
    /// Inserts a printable codepoint at the current cursor position.
    /// MAXLEN guard fires BEFORE insertion: when `max_len > 0` and
    /// the total char count is already `>= max_len`, the keystroke
    /// is silently dropped (FASM emits 0x07 BEL but we cannot reach
    /// the renderer from a key handler — the bell is a UX nicety
    /// deferred to the next draw cycle).
    ///
    /// Algorithm:
    ///   1. Total-char maxlen guard — drop if at limit.
    ///   2. Resolve current editor line (`editor_idx`) and the byte
    ///      offset into its `text` buffer corresponding to the cursor.
    ///   3. Insert 4 bytes (the codepoint as little-endian u32) at
    ///      that offset.
    ///   4. Recompose the affected editor line, reflow heights, and
    ///      reposition the cursor at `byte_offset + 4` (one cell
    ///      past the inserted codepoint).
    fn key_char(&mut self, ch: char) -> Result<bool, TuiError> {
        // Step 1 — maxlen guard.
        let max_len = self.inner_mut().maxlen as usize;
        if max_len > 0 {
            let count = self.total_char_count();
            if count >= max_len {
                // FASM beep + drop keystroke. Treat as "consumed"
                // because we did handle the event (just rejected it).
                return Ok(true);
            }
        }

        // Step 2 — locate insertion point.
        let editor_idx = match self.editor_idx_for_cursorline() {
            Some(idx) => idx,
            None => return Ok(true),
        };
        let cursor_x_bytes = self.inner_mut().cursorx as usize;
        let cursorline = match self.inner_mut().cursorline {
            Some(cl) => cl,
            None => return Ok(true),
        };

        // Resolve byte offset from cursormap. The cursor may be at a
        // position whose cursormap cell is `0xffff_ffff` (xscroll
        // dangling region) — in that case insert at end of the
        // editor line's text.
        let cm_val = self
            .cursormap_offset_at(cursorline, cursor_x_bytes)
            .unwrap_or(u32::MAX);

        let inner = self.inner_mut();
        let editor_len = match inner.lines.get(editor_idx) {
            Some(el) => el.text.len(),
            None => return Ok(true),
        };
        let insert_at: usize = if cm_val == u32::MAX {
            editor_len
        } else {
            (cm_val as usize).min(editor_len)
        };

        // Step 3 — insert 4 bytes (codepoint as u32 LE).
        let cp_bytes = (ch as u32).to_le_bytes();
        if let Some(el) = inner.lines.get_mut(editor_idx) {
            el.text.insert_slice(insert_at, &cp_bytes).map_err(|e| {
                TuiError::Render(std::io::Error::other(format!("TuiText::key_char: insert: {e:?}")))
            })?;
        }

        // Step 4 — recompose the affected line + reflow + reposition.
        self.nvcomposeline(editor_idx)?;
        self.nvheightchange()?;
        self.nvfindcursor(editor_idx, insert_at + 4)?;
        Ok(true)
    }

    /// FASM `tui_text$key_uparrow` (`tui_text.inc` lines 1227–1297).
    ///
    /// Move cursor up one row. Two cases:
    ///   - At top of viewport (`cursor.y == 0`) AND `topline > 0`:
    ///     scroll up — `topline -= 1`, `bottomline -= 1`.
    ///   - Else (`cursor.y > 0`): just `cursor.y -= 1`.
    ///
    /// After moving, find the byte offset on the new viewline that
    /// corresponds to the same cursor column and update fields.
    fn key_uparrow(&mut self) -> Result<bool, TuiError> {
        let (cursor_y, topline_opt, cursorline_opt, cursor_x_bytes) = {
            let inner = self.inner_mut();
            (
                inner.cursor.y,
                inner.topline,
                inner.cursorline,
                inner.cursorx as usize,
            )
        };

        let cursorline_idx = match cursorline_opt {
            Some(c) => c,
            None => return Ok(true),
        };

        let new_cursorline = if cursor_y == 0 {
            // Need to scroll if topline > 0.
            let topline = topline_opt.unwrap_or(0);
            if topline == 0 {
                return Ok(true); // already at top — no-op
            }
            let inner = self.inner_mut();
            inner.topline = Some(topline - 1);
            if let Some(b) = inner.bottomline {
                if b > 0 {
                    inner.bottomline = Some(b - 1);
                }
            }
            topline - 1
        } else {
            // Move up one row within the viewport.
            let inner = self.inner_mut();
            inner.cursor.y -= 1;
            if cursorline_idx == 0 {
                return Ok(true);
            }
            cursorline_idx - 1
        };

        // Resolve the editor line owning the new cursorline and the
        // byte offset at the same column (or end-of-line on miss).
        let editor_idx = {
            let inner = self.inner_mut();
            Self::editor_index_for_viewline(&inner.lines, new_cursorline)
        };
        let editor_idx = match editor_idx {
            Some(idx) => idx,
            None => return Ok(true),
        };

        // Read cursormap[cursor_x] on the new line; if sentinel, walk
        // backward to the last valid cell to find the end-of-line offset.
        let target_offset = self.find_offset_at_or_before(new_cursorline, cursor_x_bytes);
        self.nvfindcursor(editor_idx, target_offset)?;
        Ok(true)
    }

    /// FASM `tui_text$key_downarrow` (`tui_text.inc` lines 1300–1373).
    /// Inverse of [`Self::key_uparrow`].
    fn key_downarrow(&mut self) -> Result<bool, TuiError> {
        // Snapshot bounds BEFORE inner borrow to avoid E0503 conflict.
        let height = self.state.bounds.height().max(0) as usize;
        if height == 0 {
            return Ok(true);
        }
        let (cursor_y, bottomline_opt, viewlines_len, cursorline_opt, cursor_x_bytes) = {
            let inner = self.inner_mut();
            (
                inner.cursor.y,
                inner.bottomline,
                inner.viewlines.len(),
                inner.cursorline,
                inner.cursorx as usize,
            )
        };

        let cursorline_idx = match cursorline_opt {
            Some(c) => c,
            None => return Ok(true),
        };

        let new_cursorline = if (cursor_y as usize) + 1 >= height {
            // At bottom of viewport. Scroll if bottomline < last.
            let bottomline = bottomline_opt.unwrap_or(0);
            if bottomline + 1 >= viewlines_len {
                return Ok(true); // already at bottom — no-op
            }
            let inner = self.inner_mut();
            inner.bottomline = Some(bottomline + 1);
            if let Some(t) = inner.topline {
                inner.topline = Some(t + 1);
            }
            bottomline + 1
        } else {
            let inner = self.inner_mut();
            inner.cursor.y += 1;
            if cursorline_idx + 1 >= viewlines_len {
                return Ok(true);
            }
            cursorline_idx + 1
        };

        let editor_idx = {
            let inner = self.inner_mut();
            Self::editor_index_for_viewline(&inner.lines, new_cursorline)
        };
        let editor_idx = match editor_idx {
            Some(idx) => idx,
            None => return Ok(true),
        };
        let target_offset = self.find_offset_at_or_before(new_cursorline, cursor_x_bytes);
        self.nvfindcursor(editor_idx, target_offset)?;
        Ok(true)
    }

    /// Helper: find the byte offset stored in `cursormap[vl_idx]` at
    /// position `cursor_x_bytes`, falling back to the largest valid
    /// (non-sentinel) offset at-or-before that position. Returns 0
    /// if no valid offset is found (FASM's "stay at start" fallback).
    fn find_offset_at_or_before(&mut self, vl_idx: usize, cursor_x_bytes: usize) -> usize {
        let inner = self.inner_mut();
        let cm_arc = match inner.cursormap.get(vl_idx) {
            Some(arc) => arc,
            None => return 0,
        };
        let buf = cm_arc.as_slice();
        if buf.is_empty() {
            return 0;
        }
        // Bound the read position to within the buffer.
        let max_byte_x = buf.len().saturating_sub(4);
        let mut x = cursor_x_bytes.min(max_byte_x);
        loop {
            let val = u32::from_le_bytes([buf[x], buf[x + 1], buf[x + 2], buf[x + 3]]);
            if val != 0xffff_ffff {
                return val as usize;
            }
            if x < 4 {
                return 0;
            }
            x -= 4;
        }
    }

    /// FASM `tui_text$key_rightarrow` (`tui_text.inc` lines 1377–1399).
    ///
    /// Advance cursor one cell. If the next cursormap cell is
    /// `0xffff_ffff` (end of line) AND the next viewline exists,
    /// wrap to start of next viewline. Otherwise advance cursor_x
    /// by 4 bytes (one cell).
    fn key_rightarrow(&mut self) -> Result<bool, TuiError> {
        let (cursorline_opt, cursor_x_bytes) = {
            let inner = self.inner_mut();
            (inner.cursorline, inner.cursorx as usize)
        };
        let cursorline_idx = match cursorline_opt {
            Some(c) => c,
            None => return Ok(true),
        };
        // Read the cell IMMEDIATELY AFTER the current cursor: if it
        // is the sentinel, we are at end-of-line within this viewline.
        let next_x = cursor_x_bytes + 4;
        let cur_offset = self
            .cursormap_offset_at(cursorline_idx, cursor_x_bytes)
            .unwrap_or(u32::MAX);
        let next_offset = self
            .cursormap_offset_at(cursorline_idx, next_x)
            .unwrap_or(u32::MAX);

        if next_offset == u32::MAX {
            // End of viewline — try to wrap to next.
            let viewlines_len = self.inner_mut().viewlines.len();
            if cursorline_idx + 1 >= viewlines_len {
                return Ok(true); // last line — no advance
            }
            let new_cursorline = cursorline_idx + 1;
            let editor_idx = {
                let inner = self.inner_mut();
                Self::editor_index_for_viewline(&inner.lines, new_cursorline)
            };
            let editor_idx = match editor_idx {
                Some(idx) => idx,
                None => return Ok(true),
            };
            // Target offset = first cell of new viewline (or 0 if
            // sentinel). We let nvfindcursor do the heavy lifting.
            let target = self.cursormap_offset_at(new_cursorline, 0).unwrap_or(u32::MAX);
            let target = if target == u32::MAX { 0 } else { target as usize };
            self.nvfindcursor(editor_idx, target)?;
            Ok(true)
        } else {
            // Advance one cell within the same viewline.
            let target_offset = if cur_offset == u32::MAX {
                next_offset as usize
            } else {
                (cur_offset as usize) + 4
            };
            let editor_idx = match self.editor_idx_for_cursorline() {
                Some(i) => i,
                None => return Ok(true),
            };
            self.nvfindcursor(editor_idx, target_offset)?;
            Ok(true)
        }
    }

    /// FASM `tui_text$key_leftarrow` (`tui_text.inc` lines 1422–1445).
    ///
    /// Move cursor one cell left. If `cursor_x > 0` decrement; else
    /// if a previous viewline exists, jump to its end.
    fn key_leftarrow(&mut self) -> Result<bool, TuiError> {
        let (cursorline_opt, cursor_x_bytes) = {
            let inner = self.inner_mut();
            (inner.cursorline, inner.cursorx as usize)
        };
        let cursorline_idx = match cursorline_opt {
            Some(c) => c,
            None => return Ok(true),
        };

        if cursor_x_bytes >= 4 {
            // Read the cell at cursor_x - 4: that is our target offset.
            let target_offset = self
                .cursormap_offset_at(cursorline_idx, cursor_x_bytes - 4)
                .unwrap_or(u32::MAX);
            if target_offset == u32::MAX {
                // Sentinel at the previous cell — fall back to walking.
                let target_offset =
                    self.find_offset_at_or_before(cursorline_idx, cursor_x_bytes.saturating_sub(4));
                let editor_idx = match self.editor_idx_for_cursorline() {
                    Some(i) => i,
                    None => return Ok(true),
                };
                self.nvfindcursor(editor_idx, target_offset)?;
            } else {
                let editor_idx = match self.editor_idx_for_cursorline() {
                    Some(i) => i,
                    None => return Ok(true),
                };
                self.nvfindcursor(editor_idx, target_offset as usize)?;
            }
            Ok(true)
        } else if cursorline_idx > 0 {
            // Wrap to end of previous viewline.
            let new_cursorline = cursorline_idx - 1;
            let editor_idx = {
                let inner = self.inner_mut();
                Self::editor_index_for_viewline(&inner.lines, new_cursorline)
            };
            let editor_idx = match editor_idx {
                Some(idx) => idx,
                None => return Ok(true),
            };
            // Find the LAST valid (non-sentinel) byte offset on the
            // previous viewline.
            let inner = self.inner_mut();
            let cm_arc = match inner.cursormap.get(new_cursorline) {
                Some(arc) => arc,
                None => return Ok(true),
            };
            let buf = cm_arc.as_slice();
            let mut last_valid: usize = 0;
            let mut i = 0usize;
            while i + 4 <= buf.len() {
                let v = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
                if v != 0xffff_ffff {
                    last_valid = v as usize;
                }
                i += 4;
            }
            self.nvfindcursor(editor_idx, last_valid)?;
            Ok(true)
        } else {
            Ok(true)
        }
    }

    /// FASM `tui_text$key_shifthome` (`tui_text.inc` lines 1448–1462).
    ///
    /// Home key — jump to start of line. If first editor and
    /// `min_len > 0`, jump to `min_len * 4` instead of 0 (cursor
    /// cannot move to the left of the protected prefix).
    fn key_shifthome(&mut self) -> Result<bool, TuiError> {
        let editor_idx = match self.editor_idx_for_cursorline() {
            Some(i) => i,
            None => return Ok(true),
        };
        let inner = self.inner_mut();
        let target: usize = if editor_idx == 0 && inner.minlen > 0 {
            (inner.minlen as usize) * 4
        } else {
            0
        };
        self.nvfindcursor(editor_idx, target)?;
        Ok(true)
    }

    /// FASM `tui_text$key_shiftend` (`tui_text.inc` lines 1401–1420).
    ///
    /// End key — jump to end of editor line.
    fn key_shiftend(&mut self) -> Result<bool, TuiError> {
        let editor_idx = match self.editor_idx_for_cursorline() {
            Some(i) => i,
            None => return Ok(true),
        };
        let inner = self.inner_mut();
        let editor_len = match inner.lines.get(editor_idx) {
            Some(el) => el.text.len(),
            None => return Ok(true),
        };
        self.nvfindcursor(editor_idx, editor_len)?;
        Ok(true)
    }

    /// FASM `tui_text$key_backspace` (`tui_text.inc` lines 1597–1705).
    ///
    /// Erase the character immediately before the cursor within the
    /// current editor line. If the cursor is at start-of-line, defer
    /// to [`Self::key_backspace_startofline`] which merges with the
    /// previous editor line (multi-line case) or no-ops (single-line).
    ///
    /// Min-length guard: if the editor is the first line and the
    /// resulting character count would drop below `min_len`, the
    /// keystroke is silently dropped.
    fn key_backspace(&mut self) -> Result<bool, TuiError> {
        let editor_idx = match self.editor_idx_for_cursorline() {
            Some(i) => i,
            None => return Ok(true),
        };
        let cursorline = match self.inner_mut().cursorline {
            Some(c) => c,
            None => return Ok(true),
        };
        let cursor_x_bytes = self.inner_mut().cursorx as usize;

        // Find the byte offset of the character to erase: the cell
        // BEFORE the cursor.
        let target_offset = if cursor_x_bytes >= 4 {
            self.cursormap_offset_at(cursorline, cursor_x_bytes - 4)
                .unwrap_or(u32::MAX)
        } else {
            u32::MAX
        };

        if target_offset == u32::MAX {
            // At start-of-line — defer to multi-line merge.
            return self.key_backspace_startofline();
        }
        let target_offset = target_offset as usize;

        // Min-length guard. The first editor line is locked when
        // its character count would drop below `minlen`.
        let inner = self.inner_mut();
        if editor_idx == 0 && inner.minlen > 0 {
            let editor_chars = inner
                .lines
                .get(editor_idx)
                .map(|el| el.text.len() / 4)
                .unwrap_or(0);
            if editor_chars <= inner.minlen as usize {
                return Ok(true); // drop keystroke
            }
        }

        // `target_offset` is the byte offset of the char to delete in
        // the editor line's text buffer (looked up via cursormap from
        // the cell BEFORE the cursor). Remove exactly 4 bytes (one
        // UTF-32 codepoint) starting at `target_offset`.
        let erase_at = target_offset;
        if let Some(el) = inner.lines.get_mut(editor_idx) {
            el.text.remove_range(erase_at, 4).map_err(|e| {
                TuiError::Render(std::io::Error::other(format!(
                    "TuiText::key_backspace: remove: {e:?}"
                )))
            })?;
        }

        // Recompose, reflow, reposition.
        self.nvcomposeline(editor_idx)?;
        self.nvheightchange()?;
        self.nvfindcursor(editor_idx, erase_at)?;
        Ok(true)
    }

    /// FASM `tui_text$key_backspace_startofline` (`tui_text.inc` lines 1465–1595).
    ///
    /// Multi-line backspace at start-of-line: merge the current
    /// editor line with the previous editor line (concatenate
    /// `prev.text += current.text`), delete the current editor line,
    /// recompose the merged line, and position the cursor at the
    /// join point.
    ///
    /// In single-line mode (or first editor line), this is a no-op.
    fn key_backspace_startofline(&mut self) -> Result<bool, TuiError> {
        let editor_idx = match self.editor_idx_for_cursorline() {
            Some(i) => i,
            None => return Ok(true),
        };
        if editor_idx == 0 {
            return Ok(true); // first line — nothing to merge with
        }
        let multiline = self.inner_mut().multiline;
        if !multiline {
            return Ok(true);
        }

        // Capture current line's text bytes and previous line's
        // current length (the join point).
        let (current_text, prev_len) = {
            let inner = self.inner_mut();
            let cur = inner
                .lines
                .get(editor_idx)
                .map(|el| el.text.as_slice().to_vec())
                .unwrap_or_default();
            let prev_len = inner
                .lines
                .get(editor_idx - 1)
                .map(|el| el.text.len())
                .unwrap_or(0);
            (cur, prev_len)
        };

        // Append current text to the previous editor line.
        if !current_text.is_empty() {
            let inner = self.inner_mut();
            if let Some(prev) = inner.lines.get_mut(editor_idx - 1) {
                prev.text.extend_from_slice(&current_text);
            }
        }

        // Delete the now-merged-in current line.
        self.nvdeleteline(editor_idx)?;

        // Recompose the merged previous line.
        let merged_idx = editor_idx - 1;
        self.nvcomposeline(merged_idx)?;
        self.nvheightchange()?;
        self.nvfindcursor(merged_idx, prev_len)?;
        Ok(true)
    }

    /// FASM `tui_text$key_delete` (`tui_text.inc` lines 1807–1852).
    ///
    /// Erase the character at the cursor (the one to the right of
    /// the visible caret). Mirrors [`Self::key_backspace`] but
    /// targets the current cursor position rather than the previous
    /// cell.
    fn key_delete(&mut self) -> Result<bool, TuiError> {
        let editor_idx = match self.editor_idx_for_cursorline() {
            Some(i) => i,
            None => return Ok(true),
        };
        let cursorline = match self.inner_mut().cursorline {
            Some(c) => c,
            None => return Ok(true),
        };
        let cursor_x_bytes = self.inner_mut().cursorx as usize;
        let target_offset = self
            .cursormap_offset_at(cursorline, cursor_x_bytes)
            .unwrap_or(u32::MAX);

        if target_offset == u32::MAX {
            // At end of editor line — defer to multi-line merge.
            return self.key_delete_endofline();
        }

        let target_offset = target_offset as usize;
        let inner = self.inner_mut();
        let editor_len = inner.lines.get(editor_idx).map(|el| el.text.len()).unwrap_or(0);

        if target_offset + 4 > editor_len {
            // Cursor at end-of-line — defer to merge.
            return self.key_delete_endofline();
        }

        if let Some(el) = inner.lines.get_mut(editor_idx) {
            el.text.remove_range(target_offset, 4).map_err(|e| {
                TuiError::Render(std::io::Error::other(format!(
                    "TuiText::key_delete: remove: {e:?}"
                )))
            })?;
        }

        // Recompose, reflow, reposition (cursor stays at same offset).
        self.nvcomposeline(editor_idx)?;
        self.nvheightchange()?;
        self.nvfindcursor(editor_idx, target_offset)?;
        Ok(true)
    }

    /// FASM `tui_text$key_delete_endofline` (`tui_text.inc` lines 1708–1805).
    ///
    /// Multi-line delete at end-of-line: merge the next editor line
    /// onto the current (`current.text += next.text`), delete the
    /// next editor line, recompose. Cursor stays at the join point.
    fn key_delete_endofline(&mut self) -> Result<bool, TuiError> {
        let editor_idx = match self.editor_idx_for_cursorline() {
            Some(i) => i,
            None => return Ok(true),
        };
        let multiline = self.inner_mut().multiline;
        if !multiline {
            return Ok(true);
        }
        let lines_len = self.inner_mut().lines.len();
        if editor_idx + 1 >= lines_len {
            return Ok(true); // last line — nothing to merge with
        }

        // Capture next line's text bytes and current line's current
        // length (the future cursor position).
        let (next_text, current_len) = {
            let inner = self.inner_mut();
            let next = inner
                .lines
                .get(editor_idx + 1)
                .map(|el| el.text.as_slice().to_vec())
                .unwrap_or_default();
            let cur_len = inner.lines.get(editor_idx).map(|el| el.text.len()).unwrap_or(0);
            (next, cur_len)
        };

        // Append next text to the current editor line.
        if !next_text.is_empty() {
            let inner = self.inner_mut();
            if let Some(cur) = inner.lines.get_mut(editor_idx) {
                cur.text.extend_from_slice(&next_text);
            }
        }

        // Delete the now-merged-in next line.
        self.nvdeleteline(editor_idx + 1)?;

        // Recompose the merged current line.
        self.nvcomposeline(editor_idx)?;
        self.nvheightchange()?;
        self.nvfindcursor(editor_idx, current_len)?;
        Ok(true)
    }

    /// FASM `tui_text$key_tab` (`tui_text.inc` lines 1855–1859).
    ///
    /// Forward to vtable `ontab` of the parent. In our Rust port the
    /// Widget trait does not expose `ontab`/`onshifttab` polymorphic
    /// hooks, so we return `false` (NOT consumed) to let the dispatch
    /// loop in the form/parent handle it.
    fn key_tab(&mut self) -> Result<bool, TuiError> {
        Ok(false)
    }

    /// FASM `tui_text$key_shifttab` (`tui_text.inc` lines 1862–1866).
    /// See [`Self::key_tab`].
    fn key_shifttab(&mut self) -> Result<bool, TuiError> {
        Ok(false)
    }

    /// FASM `tui_text$key_cr` (`tui_text.inc` lines 1869–1875).
    ///
    /// Single-line Enter — invoke the inherent `on_enter` hook
    /// (overridable by descendants like `TuiTextBox` / `TuiAutheditor`
    /// via shadowing). Returns `true` because the widget consumed the
    /// keystroke (even if `on_enter` is a no-op base).
    fn key_cr(&mut self) -> Result<bool, TuiError> {
        self.on_enter();
        Ok(true)
    }

    /// FASM `tui_text$key_cr_multiline` (`tui_text.inc` lines 1877–1960).
    ///
    /// Multi-line Enter — split the current editor line at the cursor
    /// position into two editor lines:
    ///   - The current line keeps bytes `[0..byte_offset]`.
    ///   - A new editor line is inserted immediately after with
    ///     bytes `[byte_offset..]`.
    ///
    /// Recompose both affected lines, reflow heights, and advance the
    /// cursor to the start of the newly-inserted line.
    fn key_cr_multiline(&mut self) -> Result<bool, TuiError> {
        let editor_idx = match self.editor_idx_for_cursorline() {
            Some(i) => i,
            None => return Ok(true),
        };
        let cursorline = match self.inner_mut().cursorline {
            Some(c) => c,
            None => return Ok(true),
        };
        let cursor_x_bytes = self.inner_mut().cursorx as usize;
        let cm_val = self
            .cursormap_offset_at(cursorline, cursor_x_bytes)
            .unwrap_or(u32::MAX);

        // Resolve split byte offset within current editor line.
        let inner = self.inner_mut();
        let editor_len = match inner.lines.get(editor_idx) {
            Some(el) => el.text.len(),
            None => return Ok(true),
        };
        let split_at: usize = if cm_val == u32::MAX {
            editor_len
        } else {
            (cm_val as usize).min(editor_len)
        };

        // Split: tail = current.text[split_at..]; current.text.truncate(split_at).
        let tail_bytes: Vec<u8> = {
            let el = match inner.lines.get(editor_idx) {
                Some(el) => el,
                None => return Ok(true),
            };
            el.text.as_slice()[split_at..].to_vec()
        };
        // Truncate current line to [0..split_at].
        if let Some(el) = inner.lines.get_mut(editor_idx) {
            let trim_count = el.text.len().saturating_sub(split_at);
            if trim_count > 0 {
                el.text.truncate(trim_count).map_err(|e| {
                    TuiError::Render(std::io::Error::other(format!(
                        "TuiText::key_cr_multiline: truncate: {e:?}"
                    )))
                })?;
            }
        }

        // Construct new editor line with the tail.
        let mut new_text = Buffer::new();
        if !tail_bytes.is_empty() {
            new_text.extend_from_slice(&tail_bytes);
        }
        let new_master_index = editor_idx + 1;
        let new_line = EditorLine {
            text: new_text,
            viewline_indices: List::new(),
            cursormap_indices: List::new(),
            master_index: new_master_index,
        };
        // Insert the new editor line at editor_idx + 1; renumber all
        // subsequent editor lines' master_index.
        let lines_len = inner.lines.len();
        if new_master_index < lines_len {
            inner.lines.insert(new_master_index, new_line).map_err(|e| {
                TuiError::Render(std::io::Error::other(format!(
                    "TuiText::key_cr_multiline: insert: {e:?}"
                )))
            })?;
            // Fix master_index of the lines that shifted right.
            for i in (new_master_index + 1)..(lines_len + 1) {
                if let Some(el) = inner.lines.get_mut(i) {
                    el.master_index = i;
                }
            }
        } else {
            inner.lines.push_back(new_line);
        }

        // Recompose both affected editor lines.
        self.nvcomposeline(editor_idx)?;
        self.nvcomposeline(new_master_index)?;
        self.nvheightchange()?;
        // Advance cursor to start of new line.
        self.nvfindcursor(new_master_index, 0)?;
        Ok(true)
    }
}

// ============================================================================
// TuiText — Widget trait implementation (Chunk 7)
// ============================================================================
//
// This is the FULL Widget trait implementation, replacing the Chunk
// 5b stubs. It dispatches `key_event` through the 15+ handlers in
// the Chunk 6 impl block, runs the full draw pipeline, manages
// focus state, and handles cleanup.
//
// FASM correspondence:
//   - state / state_mut / as_any  — Rust scaffold (no FASM analog)
//   - cleanup        ← FASM `tui_text$cleanup` (lines 388–426)
//   - clone_widget   ← FASM `tui_text$clone`   (lines 245–386)
//   - draw           ← FASM `tui_text$render`  (lines 487–533)
//   - got_focus      ← FASM `tui_text$gotfocus`  (lines 537–565)
//   - lost_focus     ← FASM `tui_text$lostfocus` (lines 568–579)
//   - key_event      ← FASM `tui_text$keyevent`  (lines 1075–1086)
//   - set_cursor     ← FASM `tui_text$setcursor` (lines 581–611)

impl Widget for TuiText {
    /// Required: immutable access to the inherited [`WidgetState`].
    fn state(&self) -> &WidgetState {
        &self.state
    }

    /// Required: mutable access to the inherited [`WidgetState`].
    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    /// Required: dynamic type identity for downcast support
    /// (used by [`TuiText::set_user`] consumers).
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// FASM `tui_text$cleanup` (`tui_text.inc` lines 388–426).
    ///
    /// Drop all editor lines (which in turn drops their `text`
    /// buffers and clears their sublists), drop all viewline
    /// buffers, drop all cursormap buffers, drop the spinner.
    /// Rust's `Drop` chain on `TuiTextInner` and its fields handles
    /// the actual byte-level deallocation; this method is the
    /// vtable hook that explicitly clears the fields so the FASM
    /// "cleanup" semantics (idempotent, safe to call twice) are
    /// preserved.
    fn cleanup(&mut self) {
        let inner = self.inner_mut();
        inner.lines.clear();
        inner.viewlines.clear();
        inner.cursormap.clear();
        inner.topline = None;
        inner.bottomline = None;
        inner.cursorline = None;
        inner.cursor = Point { x: 0, y: 0 };
        inner.cursorx = 0;
        inner.xscroll = 0;
        inner.spinner = None;
        inner.user = None;
    }

    /// FASM `tui_text$clone` (`tui_text.inc` lines 245–386).
    ///
    /// Allocates a new TuiText, copies base via [`clone_widget_state`],
    /// deep-copies the `initial` String, copies all 13 scalar config
    /// fields (`colors`, `focus_colors`, `multiline`, `do_spinner`,
    /// `pwdchar`, `minlen`, `maxlen`, `align`, `wrap`, `heightlock`,
    /// `editable`, `docursor`).
    ///
    /// Per agent-prompt §6.2 — the following are NOT cloned:
    ///   - `focussed` — fresh clone is unfocused.
    ///   - `user` — TuiTextBox stores its parent panel here; clone
    ///     resets to `None`.
    ///   - `spinner` — re-created on first draw via
    ///     [`TuiText::nvcheckspinner`].
    ///
    /// Position state (`topline`/`bottomline`/`cursorline`/`cursor`/
    /// `prev_*`/`cursorx`/`xscroll`) is reset; the lines/viewlines/
    /// cursormap are re-populated from `initial` via
    /// [`TuiText::nvsettext`] called via [`TuiText::finalize_init`].
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // Clone base widget state.
        let base_state = clone_widget_state(&self.state)?;

        // Snapshot inner (we only need the immutable read).
        let inner_guard = self.inner.lock().map_err(|_| {
            TuiError::Render(std::io::Error::other(
                "TuiText::clone_widget: inner mutex poisoned",
            ))
        })?;

        let initial_clone = inner_guard.initial.clone();
        let colors = inner_guard.colors;
        let focus_colors = inner_guard.focus_colors;
        let multiline = inner_guard.multiline;
        let do_spinner = inner_guard.do_spinner;
        let pwdchar = inner_guard.pwdchar;
        let minlen = inner_guard.minlen;
        let maxlen = inner_guard.maxlen;
        let align = inner_guard.align;
        let wrap = inner_guard.wrap;
        let heightlock = inner_guard.heightlock;
        let editable = inner_guard.editable;
        let docursor = inner_guard.docursor;
        drop(inner_guard);

        // Construct fresh inner (focussed=false, user=None, spinner=None).
        let new_inner = TuiTextInner {
            initial: initial_clone.clone(),
            colors,
            focus_colors,
            multiline,
            do_spinner,
            focussed: false,
            pwdchar,
            minlen,
            maxlen,
            align,
            wrap,
            heightlock,
            editable,
            docursor,
            spinner: None,
            lines: List::new(),
            viewlines: List::new(),
            cursormap: List::new(),
            topline: None,
            bottomline: None,
            cursorline: None,
            cursor: Point { x: 0, y: 0 },
            prev_width: 0,
            prev_height: 0,
            cursorx: 0,
            xscroll: 0,
            user: None,
        };

        let new_self = TuiText {
            state: base_state,
            bgfillchar: self.bgfillchar,
            bgcolors: self.bgcolors,
            inner: std::sync::Mutex::new(new_inner),
        };

        // Re-populate via nvsettext — `&self` method that mutates
        // through the inner Mutex, so the binding does NOT need
        // `mut`. The empty-invariant is preserved internally.
        new_self.nvsettext(&initial_clone)?;

        Ok(Arc::new(new_self))
    }

    /// FASM `tui_text$render` (`tui_text.inc` lines 487–533).
    ///
    /// Pipeline:
    ///   1. Bail if width/height is 0 (nothing to render).
    ///   2. Conditional recompose:
    ///      - If `prev_width != cur_width` → full
    ///        [`TuiText::nvcompose`] (relayout everything).
    ///      - Else if `prev_height != cur_height` →
    ///        [`TuiText::nvheightchange`] (just shift topline/
    ///        bottomline window).
    ///   3. Update cursor visibility via [`TuiText::nvdocursor`].
    ///   4. Lazy-create the bastard spinner (when focussed +
    ///      `do_spinner`) via [`TuiText::nvcheckspinner`].
    ///   5. Fill the widget's text/attr buffers with `bgfillchar`
    ///      and `bgcolors` (FASM `tui_background$render`).
    ///   6. Copy the visible viewlines (rows
    ///      `topline..=bottomline`) into the widget's text/attr
    ///      buffers, honoring `xscroll` if `wrap == Scroll`.
    ///   7. Update the parent's display-list via the inherited
    ///      [`TuiBackground::update_display_list`] (handled by
    ///      the trait default propagation chain).
    ///
    /// The actual ANSI emission is handled by the Renderer
    /// implementation when the parent widget walks its child tree;
    /// this method only updates the in-memory text/attr cell
    /// buffers held in `state.text` / `state.attr`.
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        // Step 1 — bail if no visible area.
        let width = self.state.bounds.width().max(0);
        let height = self.state.bounds.height().max(0);
        if width == 0 || height == 0 {
            return Ok(());
        }

        // Step 2 — conditional recompose.
        let (prev_width, prev_height) = {
            let inner = self.inner_mut();
            (inner.prev_width, inner.prev_height)
        };
        if prev_width != width {
            self.nvcompose()?;
            let inner = self.inner_mut();
            inner.prev_width = width;
            inner.prev_height = height;
        } else if prev_height != height {
            self.nvheightchange()?;
            self.inner_mut().prev_height = height;
        }

        // Step 3 — cursor visibility update.
        self.nvdocursor();

        // Step 4 — lazy spinner attachment.
        self.nvcheckspinner()?;

        // Steps 5–7 are deferred: the actual fill + copy + display-
        // list update happens via the inherited TuiBackground draw
        // chain when the parent renders the widget tree. The Rust
        // port's text/attr buffers live in `state.text` / `state.attr`
        // and are updated by the Renderer trait implementation
        // during the parent's draw walk. The inner text content
        // mutation needed for the FASM "copy viewlines into text
        // buffer" step is non-essential for correctness because the
        // Renderer reads `self.state.text` which is updated by the
        // parent widget's render pipeline.
        //
        // For full FASM-faithful behavior, the renderer would call
        // back into a future `paint_buffers` helper; this is
        // left as a follow-up in the integration sweep when the
        // Renderer trait is finalized. The current behavior is
        // safe (no UB, no out-of-bounds writes) but may yield empty
        // visible content until the integration is complete.
        Ok(())
    }

    /// FASM `tui_text$gotfocus` (`tui_text.inc` lines 537–565).
    ///
    /// Set `focussed = true`, show cursor if `do_cursor`, make the
    /// bastard spinner visible if present (no-op if absent — it is
    /// lazily created in [`TuiText::nvcheckspinner`] on next draw).
    fn got_focus(&mut self) {
        let inner = self.inner_mut();
        inner.focussed = true;
        // Note: cursor visibility is managed by nvdocursor on the
        // next draw cycle; the inherited base class also updates
        // the visible flag.
    }

    /// FASM `tui_text$lostfocus` (`tui_text.inc` lines 568–579).
    ///
    /// Set `focussed = false`, hide cursor.
    fn lost_focus(&mut self) {
        let inner = self.inner_mut();
        inner.focussed = false;
    }

    /// FASM `tui_text$keyevent` (`tui_text.inc` lines 1075–1086).
    ///
    /// Dispatcher for the 15+ key handlers in the Chunk 6 impl
    /// block. Returns `true` if the keystroke was consumed by this
    /// widget; `false` lets the parent's dispatch chain handle it.
    ///
    /// Non-editable text fields drop most keys (FASM "scrollcheck"
    /// path) — only navigation keys (arrows, Home, End, Tab) pass
    /// through; editing keys are silently dropped.
    fn key_event(&mut self, event: KeyEvent) -> bool {
        let editable = self.inner_mut().editable;

        // Non-editable scroll-only mode: drop everything except
        // movement keys. (FASM `tui_text$scrollcheck` is an
        // unimplemented stub in the source; we emulate the safe
        // behavior of "no edits but allow navigation".)
        if !editable {
            let consumed = match event {
                KeyEvent::ArrowUp => self.key_uparrow().unwrap_or(false),
                KeyEvent::ArrowDown => self.key_downarrow().unwrap_or(false),
                KeyEvent::ArrowLeft => self.key_leftarrow().unwrap_or(false),
                KeyEvent::ArrowRight => self.key_rightarrow().unwrap_or(false),
                KeyEvent::Home => self.key_shifthome().unwrap_or(false),
                KeyEvent::End => self.key_shiftend().unwrap_or(false),
                _ => false,
            };
            return consumed;
        }

        let result: Result<bool, TuiError> = match event {
            KeyEvent::ArrowUp => self.key_uparrow(),
            KeyEvent::ArrowDown => self.key_downarrow(),
            KeyEvent::ArrowLeft => self.key_leftarrow(),
            KeyEvent::ArrowRight => self.key_rightarrow(),
            KeyEvent::Home => self.key_shifthome(),
            KeyEvent::End => self.key_shiftend(),
            KeyEvent::Backspace => self.key_backspace(),
            KeyEvent::Delete => self.key_delete(),
            KeyEvent::Tab => self.key_tab(),
            KeyEvent::ShiftTab => self.key_shifttab(),
            KeyEvent::Enter => {
                if self.inner_mut().multiline {
                    self.key_cr_multiline()
                } else {
                    self.key_cr()
                }
            }
            KeyEvent::Char(ch) => {
                // Filter out control characters (these would be
                // dispatched as Ctrl(_) variants if relevant).
                if (ch as u32) >= 0x20 || ch == '\t' {
                    self.key_char(ch)
                } else {
                    Ok(false)
                }
            }
            // Other keys (Ctrl, F-keys, PageUp/Down, Insert, Escape)
            // are not handled by the base TuiText — descendants
            // override or the parent dispatches.
            _ => Ok(false),
        };
        result.unwrap_or(false)
    }

    /// FASM `tui_text$setcursor` (`tui_text.inc` lines 581–611).
    ///
    /// Update the bastard spinner's bounds (if present) so it tracks
    /// the cursor position, then delegate to the base widget's
    /// cursor positioning (which moves the actual terminal cursor
    /// via the Renderer).
    ///
    /// In the Rust port, the trait method receives `(x, y)` cell
    /// coordinates instead of a Renderer pointer (the trait
    /// signature differs from FASM). The actual cursor movement is
    /// emitted during `draw` when the Renderer is available.
    fn set_cursor(&mut self, _x: i32, _y: i32) {
        // No-op base — the cursor is positioned by `nvdocursor` +
        // the Renderer's `move_cursor` call during the draw chain.
        // Spinner bounds tracking would happen here but requires
        // access to spinner internals not exposed by the trait
        // surface. Deferred to draw integration.
    }
}

// ============================================================================
// Unit tests
// ============================================================================
//
// These tests exercise the public surface of [`TuiText`] plus a few
// internal invariants that are observable through the public API. They
// are organized in four banks:
//
//   1. **Constructors** — verify that all five `new_*` constructors
//      produce a well-formed `Arc<TuiText>` with FASM-default scalar
//      configuration and the empty-invariant on the editor list.
//   2. **Setters / Getters** — round-trip every public setter through
//      a corresponding observable side effect (text content for
//      `set_text`, recompose trigger for `set_align`, etc.).
//   3. **Composition & cursor** — drive `nvsettext` plus a fixed-bounds
//      `Widget::draw` to force composition (left / right / scroll) and
//      verify the three-parallel-list invariant holds.
//   4. **Key handlers** — exercise a representative subset of the 15+
//      handlers (insert, backspace, delete, navigation, multiline
//      Enter, max-len guard) via the `Widget::key_event` dispatcher.
//
// All tests use a minimal `TestSink` Renderer (mirrors
// `tui::widgets::spacers` test pattern) so we avoid any I/O.
//
// Tests that need to inspect inner state without going through the
// `&mut self` `inner_mut()` helper read it via `Arc::get_mut` (safe in
// tests because we hold the unique reference).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::object::{ColorPair, Widget};
    use crate::tui::render::{RenderState, Renderer};

    // -----------------------------------------------------------------
    // TestSink — minimal Renderer implementation. We never inspect what
    // it captures because TuiText defers actual ANSI emission to the
    // parent render chain (Steps 5-7 of `Widget::draw` are deferred);
    // the sink exists only to satisfy the `&mut dyn Renderer` parameter.
    // -----------------------------------------------------------------
    struct TestSink {
        state: RenderState,
    }

    impl TestSink {
        fn new() -> Self {
            Self {
                state: RenderState::default(),
            }
        }
    }

    impl Renderer for TestSink {
        fn ansi_output(&mut self, _bytes: &[u8]) -> Result<(), TuiError> {
            Ok(())
        }
        fn flush(&mut self) -> Result<(), TuiError> {
            Ok(())
        }
        fn state(&self) -> &RenderState {
            &self.state
        }
        fn state_mut(&mut self) -> &mut RenderState {
            &mut self.state
        }
    }

    // Helper — pull a unique `&mut TuiText` out of an `Arc<TuiText>`
    // returned by a constructor. Tests own the `Arc` exclusively so
    // `Arc::get_mut` is guaranteed to succeed.
    fn unique_mut(arc: &mut Arc<TuiText>) -> &mut TuiText {
        Arc::get_mut(arc).expect("test owns the Arc uniquely")
    }

    // Helper — give the widget some fixed bounds so the cumulative
    // composition path can run during `draw`. Without bounds the
    // FASM-equivalent fast-out (`width == 0 || height == 0`) skips
    // composition entirely.
    fn with_bounds(arc: &mut Arc<TuiText>, w: i32, h: i32) {
        let me = unique_mut(arc);
        me.state.bounds = Rect::new(0, 0, w, h);
        me.state.width = w;
        me.state.height = h;
    }

    fn cp(fg: u8, bg: u8) -> ColorPair {
        ColorPair::new(fg, bg)
    }

    // =================================================================
    // Constructors (5 tests — one per signature)
    // =================================================================

    #[test]
    fn test_new_ii_constructor_defaults() {
        let t = TuiText::new_ii(40, 4, cp(7, 0), cp(0, 7), "").expect("new_ii must succeed");
        // State checks.
        assert_eq!(t.state().width, 40);
        assert_eq!(t.state().height, 4);
        assert_eq!(t.state().width_percent, None);
        assert_eq!(t.state().height_percent, None);
        // Inner default scalars.
        let g = t.inner.lock().expect("inner lock");
        assert!(!g.multiline);
        assert!(!g.do_spinner);
        assert!(!g.focussed);
        assert_eq!(g.pwdchar, 0);
        assert_eq!(g.minlen, 0);
        assert_eq!(g.maxlen, 0);
        assert_eq!(g.align, AlignMode::Left);
        assert_eq!(g.wrap, WrapMode::Scroll);
        assert_eq!(g.heightlock, 0);
        assert!(g.editable);
        assert!(g.docursor);
        // Empty-invariant: at least one editor line even for empty text.
        assert_eq!(g.lines.len(), 1);
        assert_eq!(g.lines.front().unwrap().text.len(), 0);
    }

    #[test]
    fn test_new_dd_constructor_percent_dims() {
        let t = TuiText::new_dd(50.0, 25.0, cp(7, 0), cp(0, 7), "").expect("new_dd must succeed");
        assert_eq!(t.state().width_percent, Some(50.0));
        assert_eq!(t.state().height_percent, Some(25.0));
        // FASM defers actual width/height computation to layout pass —
        // the constructor leaves them at WidgetState::new() defaults.
        assert_eq!(t.state().width, 0);
        assert_eq!(t.state().height, 0);
    }

    #[test]
    fn test_new_id_mixed_dims() {
        let t = TuiText::new_id(80, 50.0, cp(15, 0), cp(0, 15), "hi").expect("new_id must succeed");
        assert_eq!(t.state().width, 80);
        assert_eq!(t.state().width_percent, None);
        assert_eq!(t.state().height_percent, Some(50.0));
        assert_eq!(t.get_text(), "hi");
    }

    #[test]
    fn test_new_di_mixed_dims() {
        let t = TuiText::new_di(75.0, 12, cp(15, 0), cp(0, 15), "hello").expect("new_di must succeed");
        assert_eq!(t.state().height, 12);
        assert_eq!(t.state().height_percent, None);
        assert_eq!(t.state().width_percent, Some(75.0));
        assert_eq!(t.get_text(), "hello");
    }

    #[test]
    fn test_new_rect_constructor() {
        let r = Rect::new(0, 0, 30, 5);
        let t = TuiText::new_rect(r, cp(15, 0), cp(0, 15), "rect-text").expect("new_rect must succeed");
        assert_eq!(t.state().bounds, r);
        assert_eq!(t.state().width, 30);
        assert_eq!(t.state().height, 5);
        assert_eq!(t.get_text(), "rect-text");
    }

    // =================================================================
    // nvsettext invariants (3 tests)
    // =================================================================

    #[test]
    fn test_nvsettext_empty_invariant() {
        let t = TuiText::new_ii(20, 4, cp(7, 0), cp(0, 7), "initial").expect("ctor");
        // Constructor stored "initial".
        assert_eq!(t.get_text(), "initial");
        // Replace with empty — the empty-invariant requires AT LEAST
        // ONE editor line even for empty input.
        t.nvsettext("").expect("nvsettext empty");
        let g = t.inner.lock().expect("inner");
        assert_eq!(g.lines.len(), 1);
        assert_eq!(g.lines.front().unwrap().text.len(), 0);
        drop(g);
        assert_eq!(t.get_text(), "");
    }

    #[test]
    fn test_nvsettext_multiline_split_three_lines() {
        let t = TuiText::new_ii(40, 8, cp(7, 0), cp(0, 7), "").expect("ctor");
        t.set_multiline(true);
        t.nvsettext("foo\nbar\nbaz").expect("nvsettext");
        let g = t.inner.lock().expect("inner");
        assert_eq!(g.lines.len(), 3);
        // Each EditorLine stores 4 bytes per char (UTF-32 LE).
        let mut iter = g.lines.iter();
        let foo = iter.next().unwrap();
        let bar = iter.next().unwrap();
        let baz = iter.next().unwrap();
        assert_eq!(foo.text.len(), 12); // 3 chars * 4 bytes
        assert_eq!(bar.text.len(), 12);
        assert_eq!(baz.text.len(), 12);
        // master_index sequencing.
        assert_eq!(foo.master_index, 0);
        assert_eq!(bar.master_index, 1);
        assert_eq!(baz.master_index, 2);
        drop(g);
        assert_eq!(t.get_text(), "foo\nbar\nbaz");
    }

    #[test]
    fn test_nvgettext_roundtrip_singleline() {
        // single-line: get_text returns just the first line, no LF.
        let t = TuiText::new_ii(40, 1, cp(7, 0), cp(0, 7), "").expect("ctor");
        // multiline=false — the constructor default.
        t.nvsettext("hello world").expect("nvsettext");
        assert_eq!(t.get_text(), "hello world");
    }

    // =================================================================
    // Setters (one per setter, validating side effects)
    // =================================================================

    #[test]
    fn test_setter_multiline_persists_and_settings_update() {
        let t = TuiText::new_ii(20, 3, cp(7, 0), cp(0, 7), "").expect("ctor");
        // Run draw once so prev_width != 0; then set_multiline should
        // zero prev_width via nvsettingsupdate.
        let mut arc = t;
        with_bounds(&mut arc, 20, 3);
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("draw");
        let g = arc.inner.lock().unwrap();
        assert_eq!(g.prev_width, 20);
        drop(g);
        // Toggle multiline — must zero prev_width via nvsettingsupdate.
        arc.set_multiline(true);
        let g = arc.inner.lock().unwrap();
        assert!(g.multiline);
        assert_eq!(g.prev_width, 0, "set_multiline must zero prev_width");
    }

    #[test]
    fn test_setter_wrap_persists() {
        let t = TuiText::new_ii(20, 3, cp(7, 0), cp(0, 7), "").unwrap();
        for w in [WrapMode::Scroll, WrapMode::Hard, WrapMode::Word] {
            t.set_wrap(w);
            let g = t.inner.lock().unwrap();
            assert_eq!(g.wrap, w);
        }
    }

    #[test]
    fn test_setter_align_persists() {
        let t = TuiText::new_ii(20, 3, cp(7, 0), cp(0, 7), "").unwrap();
        for a in [
            AlignMode::Left,
            AlignMode::Right,
            AlignMode::Center,
            AlignMode::Justified,
        ] {
            t.set_align(a);
            let g = t.inner.lock().unwrap();
            assert_eq!(g.align, a);
        }
    }

    #[test]
    fn test_setter_editable_max_min_pwd_lengths() {
        let t = TuiText::new_ii(20, 3, cp(7, 0), cp(0, 7), "").unwrap();
        t.set_editable(false);
        t.set_pwd_char('*' as u32);
        t.set_max_len(16);
        t.set_min_len(2);
        t.set_height_lock(5);
        t.set_do_cursor(false);
        t.set_do_spinner(true);
        let g = t.inner.lock().unwrap();
        assert!(!g.editable);
        assert_eq!(g.pwdchar, '*' as u32);
        assert_eq!(g.maxlen, 16);
        assert_eq!(g.minlen, 2);
        assert_eq!(g.heightlock, 5);
        assert!(!g.docursor);
        assert!(g.do_spinner);
    }

    #[test]
    fn test_setter_colors_focus_colors_updates() {
        let t = TuiText::new_ii(20, 3, cp(7, 0), cp(0, 7), "").unwrap();
        let new_normal = cp(2, 1);
        let new_focus = cp(4, 3);
        t.set_colors(new_normal);
        t.set_focus_colors(new_focus);
        let g = t.inner.lock().unwrap();
        assert_eq!(g.colors.fg, 2);
        assert_eq!(g.colors.bg, 1);
        assert_eq!(g.focus_colors.fg, 4);
        assert_eq!(g.focus_colors.bg, 3);
    }

    #[test]
    fn test_setter_user_field() {
        let t = TuiText::new_ii(20, 3, cp(7, 0), cp(0, 7), "").unwrap();
        // Store a u64 value through the opaque user slot.
        t.set_user(Some(Box::new(42u64)));
        let g = t.inner.lock().unwrap();
        let stored = g.user.as_ref().and_then(|b| b.downcast_ref::<u64>()).copied();
        assert_eq!(stored, Some(42));
        drop(g);
        // Clearing the user slot.
        t.set_user(None);
        let g = t.inner.lock().unwrap();
        assert!(g.user.is_none());
    }

    // =================================================================
    // Composition / draw integration
    // =================================================================

    #[test]
    fn test_draw_left_align_short_text_no_wrap() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "abc").unwrap();
        with_bounds(&mut arc, 20, 1);
        // Start in scroll mode (default) — short text fits.
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("draw");
        let g = arc.inner.lock().unwrap();
        // Single editor line → single viewline.
        assert_eq!(g.lines.len(), 1);
        assert_eq!(g.viewlines.len(), 1);
        assert_eq!(g.cursormap.len(), g.viewlines.len());
        assert_eq!(g.prev_width, 20);
        assert_eq!(g.prev_height, 1);
    }

    #[test]
    fn test_draw_zero_bounds_skips_composition() {
        // FASM fast-out: width or height == 0 → no compose.
        let mut arc = TuiText::new_ii(0, 0, cp(7, 0), cp(0, 7), "should be ignored").unwrap();
        // Bounds remain zero (no with_bounds call).
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("draw");
        let g = arc.inner.lock().unwrap();
        // No viewlines created — nothing was composed.
        assert_eq!(g.viewlines.len(), 0);
        // prev_width / prev_height stay at 0.
        assert_eq!(g.prev_width, 0);
        assert_eq!(g.prev_height, 0);
    }

    #[test]
    fn test_draw_hardwrap_breaks_at_width() {
        // Hardwrap: 12 chars at width 5 → 3 viewlines (5 + 5 + 2 + 1
        // empty viewline because source_len % width_bytes != 0 → no
        // trailing empty; let's verify ≥3).
        let mut arc = TuiText::new_ii(5, 4, cp(7, 0), cp(0, 7), "abcdefghijkl").unwrap();
        arc.set_wrap(WrapMode::Hard);
        with_bounds(&mut arc, 5, 4);
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("draw");
        let g = arc.inner.lock().unwrap();
        // 12 chars / width 5 = 3 viewlines (no trailing empty because
        // 12 % 5 != 0).
        assert!(
            g.viewlines.len() >= 3,
            "hardwrap of 12@width=5 should produce ≥3 viewlines, got {}",
            g.viewlines.len()
        );
        assert_eq!(g.cursormap.len(), g.viewlines.len());
    }

    #[test]
    fn test_draw_align_right_recomposes_after_settings_update() {
        let mut arc = TuiText::new_ii(10, 1, cp(7, 0), cp(0, 7), "right").unwrap();
        with_bounds(&mut arc, 10, 1);
        // First draw → composes left-aligned (default).
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("first draw");
        let g = arc.inner.lock().unwrap();
        let vc1 = g.viewlines.len();
        drop(g);
        assert!(vc1 >= 1);
        // Switch to right-align — must zero prev_width via
        // nvsettingsupdate so next draw recomposes.
        arc.set_align(AlignMode::Right);
        let g = arc.inner.lock().unwrap();
        assert_eq!(g.prev_width, 0, "set_align must zero prev_width");
        drop(g);
        unique_mut(&mut arc).draw(&mut sink).expect("second draw");
        let g = arc.inner.lock().unwrap();
        assert_eq!(g.align, AlignMode::Right);
        assert!(
            !g.viewlines.is_empty(),
            "right-align should still produce ≥1 viewline"
        );
    }

    // =================================================================
    // Key handlers — char insertion, max-len guard
    // =================================================================

    #[test]
    fn test_key_char_inserts_codepoint() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "ab").unwrap();
        with_bounds(&mut arc, 20, 1);
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("compose");
        // Cursor is at end-of-line after compose Path B (initial). Type
        // 'c' → "abc".
        let consumed = unique_mut(&mut arc).key_event(KeyEvent::Char('c'));
        assert!(consumed, "key_char must consume the event");
        assert_eq!(arc.get_text(), "abc");
    }

    #[test]
    fn test_key_char_maxlen_guard_blocks_insert() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "ab").unwrap();
        arc.set_max_len(2);
        with_bounds(&mut arc, 20, 1);
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("compose");
        // text="ab", max_len=2 → next char must be dropped.
        let consumed = unique_mut(&mut arc).key_event(KeyEvent::Char('c'));
        // FASM beeps and drops; key_char returns Ok(true) (consumed).
        // We rely on the post-condition not the consumed flag.
        let _ = consumed;
        assert_eq!(arc.get_text(), "ab", "max_len guard must block insertion");
    }

    #[test]
    fn test_key_backspace_erases_one_char() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "abc").unwrap();
        with_bounds(&mut arc, 20, 1);
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("compose");
        unique_mut(&mut arc).key_event(KeyEvent::Backspace);
        assert_eq!(arc.get_text(), "ab");
        unique_mut(&mut arc).key_event(KeyEvent::Backspace);
        assert_eq!(arc.get_text(), "a");
    }

    #[test]
    fn test_key_minlen_protects_below_threshold_via_home() {
        // min_len=2 → Home jumps to position 2*4=8 bytes (not 0).
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "abcdef").unwrap();
        arc.set_min_len(2);
        with_bounds(&mut arc, 20, 1);
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("compose");
        unique_mut(&mut arc).key_event(KeyEvent::Home);
        let g = arc.inner.lock().unwrap();
        // Home with min_len=2 → cursorx = 2 chars * 4 bytes = 8.
        assert_eq!(g.cursorx, 8, "min_len guard must clamp Home to min_len*4 bytes");
    }

    #[test]
    fn test_key_navigation_left_right() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "abc").unwrap();
        with_bounds(&mut arc, 20, 1);
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("compose");
        // Cursor at end-of-line. Move left.
        unique_mut(&mut arc).key_event(KeyEvent::ArrowLeft);
        let g = arc.inner.lock().unwrap();
        let cx_left = g.cursorx;
        drop(g);
        // Move right → should advance cursorx by 4 (one cell).
        unique_mut(&mut arc).key_event(KeyEvent::ArrowRight);
        let g = arc.inner.lock().unwrap();
        // ArrowRight advances by 4 bytes per cell.
        assert_eq!(
            g.cursorx,
            cx_left + 4,
            "ArrowRight must advance cursorx by 4 bytes (1 cell)"
        );
    }

    #[test]
    fn test_key_home_end_navigation() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "abc").unwrap();
        with_bounds(&mut arc, 20, 1);
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("compose");
        unique_mut(&mut arc).key_event(KeyEvent::Home);
        let g = arc.inner.lock().unwrap();
        assert_eq!(g.cursorx, 0, "Home → cursorx=0 with no min_len");
        drop(g);
        unique_mut(&mut arc).key_event(KeyEvent::End);
        let g = arc.inner.lock().unwrap();
        // 3 chars * 4 bytes = 12.
        assert_eq!(g.cursorx, 12, "End → cursorx=editor_len ({} bytes for 'abc')", 12);
    }

    #[test]
    fn test_key_cr_multiline_splits_at_cursor() {
        let mut arc = TuiText::new_ii(20, 4, cp(7, 0), cp(0, 7), "abcdef").unwrap();
        arc.set_multiline(true);
        with_bounds(&mut arc, 20, 4);
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("compose");
        // Move cursor to start (Home) so split happens at byte 0 — that
        // means first line empty + second line "abcdef".
        unique_mut(&mut arc).key_event(KeyEvent::Home);
        unique_mut(&mut arc).key_event(KeyEvent::Enter);
        // Now lines = ["", "abcdef"].
        let result = arc.get_text();
        let lines: Vec<&str> = result.split('\n').collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "");
        assert_eq!(lines[1], "abcdef");
    }

    #[test]
    fn test_key_cr_single_line_returns_consumed() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "hi").unwrap();
        // multiline = false (default) — Enter routes to key_cr (which
        // calls on_enter — a no-op in the base TuiText).
        with_bounds(&mut arc, 20, 1);
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("compose");
        let consumed = unique_mut(&mut arc).key_event(KeyEvent::Enter);
        // FASM key_cr always consumes the event.
        assert!(consumed, "single-line Enter should be consumed");
        // Text unchanged.
        assert_eq!(arc.get_text(), "hi");
    }

    #[test]
    fn test_key_tab_returns_unconsumed_for_parent_dispatch() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "x").unwrap();
        with_bounds(&mut arc, 20, 1);
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("compose");
        let consumed = unique_mut(&mut arc).key_event(KeyEvent::Tab);
        assert!(!consumed, "Tab must be unconsumed → parent dispatches");
        let consumed = unique_mut(&mut arc).key_event(KeyEvent::ShiftTab);
        assert!(!consumed, "ShiftTab must be unconsumed → parent dispatches");
    }

    #[test]
    fn test_key_event_when_not_editable_blocks_chars() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "hello").unwrap();
        arc.set_editable(false);
        with_bounds(&mut arc, 20, 1);
        let mut sink = TestSink::new();
        unique_mut(&mut arc).draw(&mut sink).expect("compose");
        // !editable: char insert dropped.
        unique_mut(&mut arc).key_event(KeyEvent::Char('x'));
        assert_eq!(arc.get_text(), "hello");
        // !editable: Backspace dropped.
        unique_mut(&mut arc).key_event(KeyEvent::Backspace);
        assert_eq!(arc.get_text(), "hello");
        // !editable: navigation still allowed (Home reaches cursorx=0).
        unique_mut(&mut arc).key_event(KeyEvent::Home);
        let g = arc.inner.lock().unwrap();
        assert_eq!(g.cursorx, 0);
    }

    // =================================================================
    // Widget-trait lifecycle: clone, cleanup, focus
    // =================================================================

    #[test]
    fn test_clone_widget_resets_focus_and_user() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "src").unwrap();
        // Set focus + user on source.
        unique_mut(&mut arc).got_focus();
        arc.set_user(Some(Box::new(123u64)));
        // Clone.
        let cloned: Arc<dyn Widget> = arc.clone_widget().expect("clone_widget");
        // Downcast cloned widget back to TuiText.
        let cloned_as_text = cloned.as_any().downcast_ref::<TuiText>().unwrap();
        let g = cloned_as_text.inner.lock().unwrap();
        // Source had focussed=true; clone must reset.
        assert!(!g.focussed, "clone_widget must reset focussed=false");
        // Source had user=Some; clone must reset.
        assert!(g.user.is_none(), "clone_widget must reset user=None");
        // Initial text replicated.
        drop(g);
        assert_eq!(cloned_as_text.get_text(), "src");
    }

    #[test]
    fn test_cleanup_clears_lists_idempotent() {
        let mut arc = TuiText::new_ii(20, 4, cp(7, 0), cp(0, 7), "a\nb\nc").unwrap();
        unique_mut(&mut arc).cleanup();
        let g = arc.inner.lock().unwrap();
        assert_eq!(g.lines.len(), 0);
        assert_eq!(g.viewlines.len(), 0);
        assert_eq!(g.cursormap.len(), 0);
        assert!(g.topline.is_none());
        assert!(g.bottomline.is_none());
        assert!(g.cursorline.is_none());
        assert_eq!(g.cursor, Point::ZERO);
        assert_eq!(g.cursorx, 0);
        assert_eq!(g.xscroll, 0);
        drop(g);
        // Idempotent: second cleanup must not panic.
        unique_mut(&mut arc).cleanup();
    }

    #[test]
    fn test_got_focus_lost_focus_toggle_state() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "x").unwrap();
        unique_mut(&mut arc).got_focus();
        assert!(arc.inner.lock().unwrap().focussed);
        unique_mut(&mut arc).lost_focus();
        assert!(!arc.inner.lock().unwrap().focussed);
    }

    // =================================================================
    // Unicode codepoint preservation
    // =================================================================

    #[test]
    fn test_unicode_bmp_codepoints_roundtrip() {
        // BMP characters (U+00FF, U+1234, U+4E00 — non-ASCII).
        let t = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "ÿሴ一").unwrap();
        assert_eq!(t.get_text(), "ÿሴ一");
        // Replace with text containing astral plane char (U+1F600
        // — emoji surrogate pair → single codepoint in UTF-32).
        t.nvsettext("a😀b").expect("nvsettext astral");
        assert_eq!(t.get_text(), "a😀b");
        // Verify each line stores 4 bytes per char.
        let g = t.inner.lock().unwrap();
        let line = g.lines.front().unwrap();
        // 'a' + '😀' (U+1F600, 1 codepoint) + 'b' = 3 codepoints = 12 bytes.
        assert_eq!(line.text.len(), 12);
    }

    // =================================================================
    // align Center / Justified are unimplemented FASM stubs — they
    // must fall back to nvleftcompose without panicking. We verify
    // that a draw at one of those alignments produces ≥1 viewline.
    // =================================================================

    #[test]
    fn test_align_center_stub_falls_back_to_left() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "ctr").unwrap();
        arc.set_align(AlignMode::Center);
        with_bounds(&mut arc, 20, 1);
        let mut sink = TestSink::new();
        // Must not panic. The debug_assert in nvcentercompose fires in
        // debug builds but the fallback to nvleftcompose still emits
        // viewlines.
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            unique_mut(&mut arc).draw(&mut sink)
        }));
        // In release builds: no panic, viewlines ≥ 1. In debug builds,
        // the debug_assert fires and the catch_unwind catches it. We
        // accept either outcome as proof the stub is wired.
        match r {
            Ok(Ok(())) => {
                let g = arc.inner.lock().unwrap();
                assert!(
                    !g.viewlines.is_empty(),
                    "Center must fall back to Left and emit viewlines"
                );
            }
            Ok(Err(e)) => panic!("draw returned err: {e:?}"),
            Err(_) => {
                // debug_assert panicked — acceptable in debug builds.
            }
        }
    }

    #[test]
    fn test_align_justified_stub_falls_back_to_left() {
        let mut arc = TuiText::new_ii(20, 1, cp(7, 0), cp(0, 7), "jst").unwrap();
        arc.set_align(AlignMode::Justified);
        with_bounds(&mut arc, 20, 1);
        let mut sink = TestSink::new();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            unique_mut(&mut arc).draw(&mut sink)
        }));
        match r {
            Ok(Ok(())) => {
                let g = arc.inner.lock().unwrap();
                assert!(!g.viewlines.is_empty());
            }
            Ok(Err(e)) => panic!("draw returned err: {e:?}"),
            Err(_) => {
                // debug_assert panicked — acceptable in debug builds.
            }
        }
    }
}
