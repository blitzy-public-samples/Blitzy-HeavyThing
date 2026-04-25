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
// tui_label.inc → tui/widgets/label.rs: text displaying goods
// ... basically a background with layout-aware text goodies, string based
// ... deals with multiline, but is not particularly smart about it, nor editable
//
// if you want heavier text layout/editing/etc, see tui_text.inc / text.rs
//
// uses list and string of course in addition to tui_background, tui_object
//
// NOTE (FASM): "this requires string32 not string16 (makes things simpler
// due to our dd buffer sizing)". The Rust port stores codepoints as `u32`
// in a `Vec<u8>` text buffer (matching the rest of the widget tree) so the
// 4-bytes-per-cell invariant carries over transparently while the public
// API trades in idiomatic `&str` / `String`.
//
// ========================================================================

//! Label widget: [`crate::tui::widgets::background::TuiBackground`] descendant
//! displaying multi-line text with three alignments and optional
//! per-character highlighting.
//!
//! Translation of FASM `tui_label.inc` (789 lines). This widget is **not
//! editable** — see [`crate::tui::widgets::text`] for the editable text
//! widget once that translation is delivered. The label OWNS a copy of
//! its fill text (FASM comment: *"we do not assume ownership of filltext
//! strings passed to us at new; we make a copy of it"*).
//!
//! ## Architectural pattern
//!
//! `TuiLabel` follows the established sibling-widget convention used by
//! [`crate::tui::widgets::spinner::Spinner`] and
//! [`crate::tui::widgets::matrix::Matrix`]:
//!
//! - `pub(crate) state: WidgetState` is held directly on the struct
//!   (NOT via composition of [`crate::tui::widgets::background::TuiBackground`])
//!   to satisfy the [`Widget::state`] / [`Widget::state_mut`] contract
//!   without `Arc::into_inner` gymnastics.
//! - `inner: Mutex<LabelInner>` holds the label-specific extras
//!   (`bgfillchar`, `bgcolors`, `filltext`, `align`, `lines`,
//!   `highlight_char`, `highlight_color`) and provides interior
//!   mutability for the `&self` setters
//!   ([`TuiLabel::set_text`], [`TuiLabel::set_align`],
//!   [`TuiLabel::set_colors`], [`TuiLabel::add_line`],
//!   [`TuiLabel::set_highlight`]).
//! - The TUI render loop polls the widget tree on a tick interval and
//!   invokes [`Widget::draw`] under exclusive `&mut self` access; the
//!   `Mutex<LabelInner>` ensures setter mutations remain atomic relative
//!   to draw reads.
//!
//! ## Vmethod overrides (vs. [`Widget`] trait defaults)
//!
//! Per FASM `tui_label$vtable` (label.rs line 44): identical to
//! `tui_background$vtable` with three overrides at slots 0/1/2, all
//! other 34 vmethods inherit the defaults from
//! [`crate::tui::object::Widget`].
//!
//! | FASM vtable slot | [`Widget`] method        | Override?         |
//! |------------------|--------------------------|-------------------|
//! | 0 cleanup        | [`Widget::cleanup`]      | YES               |
//! | 1 clone          | [`Widget::clone_widget`] | YES               |
//! | 2 draw           | [`Widget::draw`]         | YES               |
//! | All other 34     | various                  | inherit defaults  |
//!
//! ## FASM struct byte layout (preserved logically)
//!
//! | FASM offset (over `tui_background_size`) | Field            | Size |
//! |------------------------------------------|------------------|------|
//! | +0                                       | `filltext`       | dq   |
//! | +8                                       | `textalign`      | dd   |
//! | +16                                      | `lines`          | dq   |
//! | +24                                      | `highlightchar`  | dd   |
//! | +32                                      | `highlightcolor` | dd   |
//! | (total)                                  | `tui_label_size = tui_background_size + 40` |  |
//!
//! Rust does not preserve the byte layout literally (a `Mutex<LabelInner>`
//! does not have a stable byte-for-byte layout) but every FASM field has
//! a 1:1 Rust counterpart in [`LabelInner`].
//!
//! Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
//! Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

use std::any::Any;
use std::sync::{Arc, Mutex};

use crate::ds::List;
use crate::error::TuiError;
use crate::tui::geometry::Rect;
use crate::tui::object::{ColorPair, Widget, WidgetState};
use crate::tui::render::Renderer;

// ============================================================================
// TextAlign enum — FASM `tui_textalign_*` constants
// ============================================================================

/// Text alignment modes per FASM `tui_textalign_*` constants
/// (`tui_label.inc` lines 56–59).
///
/// `Justified` (FASM `tui_textalign_justified = 3`) is intentionally
/// **NOT** included here — the FASM source explicitly notes that
/// justified alignment is unsupported in `tui_label` and reserved for
/// the editable `tui_text` widget. Adding a `Justified` variant here
/// would make the [`TuiLabel::draw`] dispatch lie about its capability.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum TextAlign {
    /// `tui_textalign_left = 0` — flush-left placement (FASM
    /// `.placeline_left` / `.placeline_left_highlight`).
    #[default]
    Left = 0,
    /// `tui_textalign_center = 1` — centered placement with leading
    /// padding rounded down to a 4-byte boundary (FASM
    /// `.placeline_center` `and r11, not 3`).
    Center = 1,
    /// `tui_textalign_right = 2` — flush-right placement (FASM
    /// `.placeline_right`).
    Right = 2,
}

// ============================================================================
// LabelInner — interior-mutable state guarded by `TuiLabel::inner: Mutex<…>`
// ============================================================================

/// Private extra-state struct guarded by [`TuiLabel`]'s `inner` Mutex.
///
/// FASM stores these fields as inline dwords/qwords starting at the
/// `tui_background_size` offset of the `tui_label` heap allocation. The
/// Rust port collapses them into a single `Mutex<LabelInner>` so that
/// the public [`TuiLabel`] setters can take `&self` (matching the
/// reactive UI convention used by [`crate::tui::widgets::spinner`] and
/// [`crate::tui::widgets::matrix`]) while still mutating internal state.
///
/// ## Field-to-FASM correspondence
///
/// | Rust field        | FASM offset                          | FASM size |
/// |-------------------|--------------------------------------|-----------|
/// | `bgfillchar`      | inherits from `TuiBackground`        | dd        |
/// | `bgcolors`        | inherits from `TuiBackground`        | dd        |
/// | `filltext`        | `tui_label_filltext_ofs (+0)`        | dq        |
/// | `align`           | `tui_label_textalign_ofs (+8)`       | dd        |
/// | `lines`           | `tui_label_lines_ofs (+16)`          | dq        |
/// | `highlight_char`  | `tui_label_highlightchar_ofs (+24)`  | dd        |
/// | `highlight_color` | `tui_label_highlightcolor_ofs (+32)` | dd        |
///
/// `bgfillchar` and `bgcolors` are kept here (rather than on `TuiLabel`
/// directly) so that [`TuiLabel::set_colors`] and any future
/// `set_fillchar` can take `&self`. This faithfully replicates the FASM
/// `nvsetcolors` semantic (`tui_label.inc` lines 451–460) which writes
/// to the BACKGROUND's colors field — important for downstream code
/// like the statusbar widget that calls `set_colors` on its label
/// children expecting the background-fill color to update.
struct LabelInner {
    /// Background fill character (always `' ' = 0x20` for labels;
    /// FASM constructors load `ecx = ' '` before delegating to
    /// `tui_background$init_*` at lines 99, 187, 232, 274).
    /// Kept in `inner` for symmetry with the FASM `tui_bgfillchar_ofs`
    /// field even though no public setter currently exposes it.
    bgfillchar: u32,

    /// Background colors — written by [`TuiLabel::set_colors`] per
    /// FASM `tui_label$nvsetcolors` (lines 451–460):
    /// `mov [rdi + tui_bgcolors_ofs], edx`. Note this targets the
    /// BACKGROUND's colors field, not a label-specific one — preserving
    /// this semantic is critical for [`crate::tui::widgets::statusbar`]
    /// (FASM `tui_statusbar.inc`) which calls `set_colors` on its label
    /// children expecting the background-fill color to update.
    bgcolors: ColorPair,

    /// FASM `tui_label_filltext_ofs` (offset 0 over `tui_background_size`).
    /// **Owned** copy of the label text (FASM `tui_label.inc` line 84:
    /// `call string$copy` produces an owned copy of the caller's
    /// string). The FASM source comment at line 79 explicitly states:
    /// *"we do not assume ownership of filltext strings passed to us
    /// at new; we make a copy of it"*.
    filltext: String,

    /// FASM `tui_label_textalign_ofs` (offset 8 over `tui_background_size`).
    /// Stored as a `dd` (4 bytes) in FASM but only the three values
    /// `0/1/2` are valid — the Rust port encodes this constraint via
    /// the [`TextAlign`] enum.
    align: TextAlign,

    /// FASM `tui_label_lines_ofs` (offset 16 over `tui_background_size`).
    /// LF-split lines populated by [`TuiLabel::lineate_locked`] from
    /// `filltext`. Drawing in [`TuiLabel::draw`] iterates this list
    /// (in forward order in Rust, vs. FASM's reverse order — the final
    /// rendered output is identical because both produce the same
    /// row-to-line mapping).
    lines: List<String>,

    /// FASM `tui_label_highlightchar_ofs` (offset 24 over
    /// `tui_background_size`). Codepoint that triggers highlight
    /// coloring during draw. `0` (the default) disables highlighting
    /// (FASM `cmp dword [rsi+tui_label_highlightchar_ofs], 0; jne
    /// .highlighter` at line 553).
    highlight_char: u32,

    /// FASM `tui_label_highlightcolor_ofs` (offset 32 over
    /// `tui_background_size`). Color pair applied to characters
    /// matching `highlight_char`. Stored as a `ColorPair` rather than
    /// a packed `u32` so that the public [`TuiLabel::set_highlight`]
    /// API trades in the idiomatic Rust type.
    highlight_color: ColorPair,
}

// ============================================================================
// TuiLabel — public widget struct
// ============================================================================

/// Multi-line text label widget — FASM `tui_label`.
///
/// See the [module docs](self) for the architectural overview, FASM
/// vtable correspondence, and field-by-field byte layout. The constructor
/// family ([`TuiLabel::new_ii`], [`TuiLabel::new_str`],
/// [`TuiLabel::new_dd`], [`TuiLabel::new_id`], [`TuiLabel::new_di`],
/// [`TuiLabel::new_rect`]) all return `Result<Arc<Self>, TuiError>` to
/// match the [`crate::tui::widgets::background::TuiBackground`]
/// constructor signature and propagate buffer-allocation errors.
///
/// ## Type alias
///
/// [`Label`] is exported as a `pub type Label = TuiLabel` alias so that
/// AAP-listed callers can reach the type via the shorter name. Both
/// names refer to the same concrete struct.
///
/// ## Thread safety
///
/// `TuiLabel: Send + Sync` because:
/// - [`WidgetState`] is `Send + Sync` (its `Arc<dyn Widget>` children
///   list inherits the trait bound from [`Widget`]).
/// - [`Mutex<LabelInner>`] is `Send + Sync` whenever
///   `LabelInner: Send` — and [`LabelInner`] is `Send` because each
///   field is `Send` (`u32`, `ColorPair`, `String`, [`TextAlign`],
///   [`List<String>`]).
pub struct TuiLabel {
    /// Inherited base widget state (bounds, dimensions, visibility,
    /// text/attribute buffers, layout, children list, ...). Direct
    /// field per the established [`Widget::state`] /
    /// [`Widget::state_mut`] contract; see the module docs for the
    /// design rationale.
    pub(crate) state: WidgetState,

    /// Mutable extra-state — fill character, colors, filltext, alignment,
    /// LF-split lines, and highlight pair. Guarded by [`std::sync::Mutex`]
    /// (NOT [`tokio::sync::Mutex`]) because the critical sections are
    /// short synchronous memory updates with no `await` points,
    /// matching the established widget-mutation pattern in
    /// [`crate::tui::widgets::background`] and
    /// [`crate::tui::widgets::spinner`].
    inner: Mutex<LabelInner>,
}

/// Type alias matching the AAP-listed `Label` export.
///
/// Provided so that AAP file-by-file translation tables and external
/// callers can reach the type via either `Label` or [`TuiLabel`]. The
/// two names refer to the same concrete struct; methods defined on
/// [`TuiLabel`] (and the `Label::new_dd_vec` factory below) are
/// equally accessible via either name.
pub type Label = TuiLabel;

// ============================================================================
// Helpers — packed-color formatting and buffer fill primitives
// ============================================================================

/// Pack a [`ColorPair`] into a `u32` matching the FASM 32-bit color
/// attribute format used by `tui_object.attr` and the per-cell entries
/// of [`crate::tui::object::Attributes::cells`].
///
/// Bit layout:
/// - bits  0..= 7: foreground color (u8)
/// - bits  8..=15: background color (u8)
/// - bits 16..=31: SGR attribute mask (u16, defaulted to 0)
///
/// This helper is replicated locally rather than re-using
/// [`crate::tui::widgets::background`]'s `pack_color_pair` (which is
/// private at the time of writing) to keep `label.rs` self-contained
/// and avoid a cross-module visibility dependency. The byte layout is
/// fixed by the FASM `tui_object` ABI so re-derivation here is safe.
#[inline]
fn pack_color_pair(cp: ColorPair) -> u32 {
    u32::from(cp.fg) | (u32::from(cp.bg) << 8)
}

/// Pre-allocate the text and attributes buffers for a [`WidgetState`]
/// when both `width` and `height` are positive.
///
/// FASM parallel: the `heap$alloc(cells * 4) + memset32(buf, 0, bytes)`
/// sequence at the tail of `tui_object$init_rect` / `init_ii`
/// (`tui_object.inc` lines 336–397 / 494–548). The buffers are zeroed
/// because FASM `memset32` with `esi = 0` writes zero dwords.
///
/// When either dimension is non-positive the buffers stay empty and
/// the layout pass owns their later sizing (FASM `init_id` / `init_di`
/// / `init_dd` skip allocation pending layout resolution).
fn pre_allocate_buffers(state: &mut WidgetState) -> Result<(), TuiError> {
    if state.width <= 0 || state.height <= 0 {
        return Ok(());
    }
    let cells = (state.width as usize)
        .checked_mul(state.height as usize)
        .ok_or_else(|| {
            TuiError::Render(std::io::Error::other(format!(
                "TuiLabel: width*height overflowed usize \
                 (width={}, height={})",
                state.width, state.height
            )))
        })?;
    let bytes = cells.checked_mul(4).ok_or_else(|| {
        TuiError::Render(std::io::Error::other(format!(
            "TuiLabel: cells*4 overflowed usize (cells={cells})"
        )))
    })?;
    state.text.reserve_exact(bytes);
    for _ in 0..bytes {
        state.text.push(0);
    }
    state.attributes.cells.resize(cells, 0);
    Ok(())
}

/// Fill the first `count` 4-byte cells of the [`WidgetState::text`]
/// buffer with `value` little-endian, growing the buffer to exactly
/// `count * 4` bytes (FASM `memset32(rdi=text_buf, esi=value,
/// rdx=count)` from `memfuncs.inc`).
fn fill_text_buffer(state: &mut WidgetState, value: u32, count: usize) -> Result<(), TuiError> {
    let bytes = count.checked_mul(4).ok_or_else(|| {
        TuiError::Render(std::io::Error::other(format!(
            "TuiLabel::fill_text_buffer: count*4 overflowed usize (count={count})"
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
                "TuiLabel::fill_text_buffer: truncate failed: {e:?}"
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
/// with `value`, growing or truncating to length `count` (FASM
/// `memset32(rdi=attr_buf, esi=value, rdx=count)`).
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

/// Replicate FASM `tui_background$nvfill` (`tui_background.inc` lines
/// 220–263) without depending on the private `nvfill` of
/// [`crate::tui::widgets::background`].
///
/// 1. Bail when `width <= 0`, `height <= 0`, or the text buffer is
///    empty (matching FASM `.nothingtodo` / `.bailout`).
/// 2. When `bgfillchar != 0`: fill the first `cells` 4-byte slots of
///    the text buffer with the codepoint (FASM `.attronly` skip is
///    avoided here only when `bgfillchar == 0`).
/// 3. Always fill the first `cells` u32 slots of the attribute buffer
///    with the packed color (FASM falls through into the attribute
///    memset32 unconditionally).
fn nvfill(state: &mut WidgetState, bgfillchar: u32, bgcolors: ColorPair) -> Result<(), TuiError> {
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
                "TuiLabel::nvfill: width*height overflowed usize \
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

/// Deep-clone a [`WidgetState`] following FASM `tui_object$init_copy`
/// (`tui_object.inc` lines 235–333) semantics.
///
/// Mirrors the private `clone_widget_state` helper in
/// [`crate::tui::widgets::background`]:
///
/// - All scalar fields are bitwise-copied.
/// - `display_name`, `text`, and `attributes` are deep-copied.
/// - `children` are deep-cloned by invoking each child's
///   [`Widget::clone_widget`] vmethod (FASM `list$foreach` with
///   `.childrencopy` callback at lines 308–331).
/// - `bastards` are intentionally **not** cloned — the cloned state's
///   bastards list is freshly empty, matching FASM line 274.
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
    cloned.text = src.text.clone();
    cloned.attributes = src.attributes.clone();

    // Children — deep-clone via each child's `clone_widget`.
    // Bastards remain empty (matching FASM init_copy at line 274).
    for child in src.children.iter() {
        let cloned_child = child.clone_widget()?;
        cloned.children.push_back(cloned_child);
    }

    Ok(cloned)
}

// ============================================================================
// Constructors — six FASM `tui_label$new_*` variants
// ============================================================================

impl TuiLabel {
    /// Constructor — integer width and integer height (FASM
    /// `tui_label$new_ii`, `tui_label.inc` lines 76–116).
    ///
    /// Five arguments: `width`, `height`, `filltext`, `colors`, `align`.
    /// FASM register binding: `edi=width, esi=height, rdx=filltext,
    /// ecx=colors, r8d=align`.
    ///
    /// Construction sequence:
    /// 1. Build a fresh [`WidgetState`] with the supplied `width` /
    ///    `height` and pre-allocate the text + attribute buffers when
    ///    both dimensions are positive (matches FASM
    ///    `tui_background$init_ii` at line 99).
    /// 2. Build [`LabelInner`] with `bgfillchar = ' '` (FASM line 100:
    ///    `mov ecx, ' '`), the supplied `colors`, an owned copy of
    ///    `filltext`, the supplied `align`, a fresh empty
    ///    [`List<String>`] for `lines`, and `highlight_char = 0`
    ///    (FASM line 109: `mov qword [...highlightchar_ofs], 0`).
    /// 3. Run [`Self::lineate_locked`] to LF-split `filltext` into
    ///    `lines` (FASM line 111: `call tui_label$nvlineate`).
    /// 4. Wrap in [`Arc::new`] and return.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if buffer pre-allocation overflows
    /// (`width * height * 4 > usize::MAX`); infallible for any
    /// realistic terminal dimension.
    pub fn new_ii(
        width: i32,
        height: i32,
        filltext: &str,
        colors: ColorPair,
        align: TextAlign,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = height;
        state.width_percent = None;
        state.height_percent = None;
        Self::finalize_init(state, filltext, colors, align)
    }

    /// Constructor — auto-computed integer dimensions from `filltext`
    /// (FASM `tui_label$new_str`, `tui_label.inc` lines 118–148).
    ///
    /// Three arguments: `filltext`, `colors`, `align`. FASM register
    /// binding: `rdi=filltext, esi=colors, edx=align`.
    ///
    /// FASM algorithm (lines 122–147):
    /// 1. Split `filltext` by LF (`string$split` with `esi = 10`).
    /// 2. Walk the resulting list with the `.linelength` callback
    ///    which tracks `max_line_length` and `line_count` in a
    ///    16-byte stack-frame slot.
    /// 3. Free the temporary list.
    /// 4. Call `tui_label$new_ii` with `edi = max_line_length,
    ///    esi = line_count` plus the original `filltext`/`colors`/`align`.
    ///
    /// The Rust port computes the same `(max_line_chars, line_count)`
    /// pair via [`str::split`] + [`Iterator::count`] / [`Iterator::map`]
    /// and delegates to [`Self::new_ii`].
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] only on buffer pre-allocation
    /// overflow (forwarded from [`Self::new_ii`]).
    pub fn new_str(filltext: &str, colors: ColorPair, align: TextAlign) -> Result<Arc<Self>, TuiError> {
        // Replicate FASM `.linelength` callback semantics: count chars
        // (NOT bytes) per line and track the maximum line width.
        let mut max_line_chars: i32 = 0;
        let mut line_count: i32 = 0;
        for line in filltext.split('\n') {
            let chars = line.chars().count() as i32;
            if chars > max_line_chars {
                max_line_chars = chars;
            }
            line_count += 1;
        }
        Self::new_ii(max_line_chars, line_count, filltext, colors, align)
    }

    /// Constructor — percentage width and percentage height (FASM
    /// `tui_label$new_dd`, `tui_label.inc` lines 161–198).
    ///
    /// Five arguments: `width_perc`, `height_perc`, `filltext`,
    /// `colors`, `align`. FASM register binding: `xmm0=widthperc,
    /// xmm1=heightperc, rdi=filltext, esi=colors, edx=align`.
    ///
    /// Buffers are **not** pre-allocated because absolute dimensions
    /// are unknown until layout resolves. FASM `tui_background$init_dd`
    /// (line 187) likewise skips buffer allocation; the layout pass
    /// owns sizing.
    pub fn new_dd(
        width_perc: f64,
        height_perc: f64,
        filltext: &str,
        colors: ColorPair,
        align: TextAlign,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = 0;
        state.height = 0;
        state.width_percent = Some(width_perc);
        state.height_percent = Some(height_perc);
        Self::finalize_init(state, filltext, colors, align)
    }

    /// Constructor — integer width, percentage height (FASM
    /// `tui_label$new_id`, `tui_label.inc` lines 201–239).
    ///
    /// Five arguments: `width`, `height_perc`, `filltext`, `colors`,
    /// `align`. FASM register binding: `edi=width, xmm0=heightperc,
    /// rsi=filltext, edx=colors, ecx=align`.
    ///
    /// Buffers are **not** pre-allocated — height is unknown until
    /// layout resolves.
    pub fn new_id(
        width: i32,
        height_perc: f64,
        filltext: &str,
        colors: ColorPair,
        align: TextAlign,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = 0;
        state.width_percent = None;
        state.height_percent = Some(height_perc);
        Self::finalize_init(state, filltext, colors, align)
    }

    /// Constructor — percentage width, integer height (FASM
    /// `tui_label$new_di`, `tui_label.inc` lines 242–280).
    ///
    /// Five arguments: `width_perc`, `height`, `filltext`, `colors`,
    /// `align`. FASM register binding: `xmm0=widthperc, esi=height,
    /// rdi=filltext, edx=colors, ecx=align`.
    ///
    /// Buffers are **not** pre-allocated — width is unknown until
    /// layout resolves.
    pub fn new_di(
        width_perc: f64,
        height: i32,
        filltext: &str,
        colors: ColorPair,
        align: TextAlign,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = 0;
        state.height = height;
        state.width_percent = Some(width_perc);
        state.height_percent = None;
        Self::finalize_init(state, filltext, colors, align)
    }

    /// Constructor — explicit [`Rect`] bounds (FASM
    /// `tui_label$new_rect`, `tui_label.inc` lines 283–319).
    ///
    /// Four arguments: `rect`, `filltext`, `colors`, `align`. FASM
    /// register binding: `rdi=rect_ptr, rsi=filltext, edx=colors,
    /// ecx=align`.
    ///
    /// Computes `width = rect.width()` and `height = rect.height()`
    /// from the half-open rectangle and pre-allocates the text +
    /// attribute buffers when both dimensions are positive (matches
    /// FASM `tui_background$init_rect` at line 295).
    pub fn new_rect(
        rect: Rect,
        filltext: &str,
        colors: ColorPair,
        align: TextAlign,
    ) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.bounds = rect;
        state.width = rect.width();
        state.height = rect.height();
        state.width_percent = None;
        state.height_percent = None;
        Self::finalize_init(state, filltext, colors, align)
    }

    /// Internal helper — shared post-init setup used by all six
    /// constructors above.
    ///
    /// Pre-allocates the text/attr buffers (when both dimensions are
    /// positive), constructs [`LabelInner`] with FASM-matching defaults
    /// (`bgfillchar = ' '`, `highlight_char = 0`,
    /// `highlight_color = ColorPair::default()`), and runs
    /// [`Self::lineate_locked`] to LF-split `filltext` into
    /// `inner.lines` before the constructor returns.
    fn finalize_init(
        mut state: WidgetState,
        filltext: &str,
        colors: ColorPair,
        align: TextAlign,
    ) -> Result<Arc<Self>, TuiError> {
        pre_allocate_buffers(&mut state)?;
        let mut inner = LabelInner {
            bgfillchar: b' ' as u32,
            bgcolors: colors,
            filltext: String::from(filltext),
            align,
            lines: List::new(),
            highlight_char: 0,
            highlight_color: ColorPair::default(),
        };
        Self::lineate_locked(&mut inner);
        Ok(Arc::new(Self {
            state,
            inner: Mutex::new(inner),
        }))
    }
}

// ============================================================================
// Label::new_dd_vec — Vec<u8>-input convenience factory
// ============================================================================

impl Label {
    /// Convenience constructor accepting `filltext` as a `Vec<u8>`
    /// (typically a UTF-8 byte buffer captured from network input or a
    /// file read).
    ///
    /// Behaviorally equivalent to [`Self::new_dd`] after lossy UTF-8
    /// conversion of the input bytes; non-UTF-8 sequences are replaced
    /// with the Unicode replacement character (U+FFFD) — the same
    /// degradation policy applied throughout the `heavything::util`
    /// helpers when bridging FASM byte slices to Rust strings.
    ///
    /// Five arguments: `width_perc`, `height_perc`, `filltext`
    /// (Vec<u8>), `colors`, `align`. The function consumes `filltext`
    /// to avoid an extra allocation when the caller already owns the
    /// bytes (matching the FASM convention of passing pre-allocated
    /// buffers).
    ///
    /// # Errors
    ///
    /// Forwards [`TuiError::Render`] from [`Self::new_dd`] (impossible
    /// in practice for percentage-based dimensions which skip
    /// allocation).
    pub fn new_dd_vec(
        width_perc: f64,
        height_perc: f64,
        filltext: Vec<u8>,
        colors: ColorPair,
        align: TextAlign,
    ) -> Result<Arc<Self>, TuiError> {
        // String::from_utf8_lossy returns a Cow<'_, str>; we always
        // consume it into an owned String for storage in LabelInner.
        let owned = String::from_utf8_lossy(&filltext).into_owned();
        Self::new_dd(width_perc, height_perc, &owned, colors, align)
    }
}

// ============================================================================
// TuiLabel — lineate helper + non-virtual public methods
// ============================================================================

impl TuiLabel {
    /// Internal LF-split helper — populates `inner.lines` from
    /// `inner.filltext`.
    ///
    /// FASM parallel: `tui_label$nvlineate`
    /// (`tui_label.inc` lines 363–388):
    ///
    /// ```text
    ///   list$clear(self.lines)         ; drop existing entries
    ///   heap$free(self.lines)          ; free old list backing
    ///   self.lines = string$split(self.filltext, LF=10)
    /// ```
    ///
    /// Behavior:
    /// 1. Clears `inner.lines` (drops previously stored `String`
    ///    entries via Rust's `Drop`).
    /// 2. Iterates `inner.filltext.split('\n')` and pushes each
    ///    substring as an owned [`String`] onto `inner.lines`.
    ///
    /// FASM `string$split` returns a `List` containing a single
    /// empty string when the input is empty, and N+1 entries when
    /// the input contains N LF separators (trailing-LF inputs
    /// produce a trailing empty string). [`str::split`] in Rust
    /// matches this contract exactly.
    fn lineate_locked(inner: &mut LabelInner) {
        inner.lines.clear();
        for segment in inner.filltext.split('\n') {
            inner.lines.push_back(String::from(segment));
        }
    }

    /// Replace this label's `filltext` and rebuild the line cache.
    ///
    /// FASM parallel: `tui_label$nvsettext`
    /// (`tui_label.inc` lines 415–432):
    ///
    /// ```text
    ///   heap$free(self.filltext)
    ///   self.filltext = string$copy(new_text)
    ///   tui_label$nvlineate(self)
    ///   self.vdraw()
    /// ```
    ///
    /// 1. Replace `inner.filltext` with an owned copy of `new_text`
    ///    (FASM `string$copy` allocates and copies; Rust
    ///    [`String::from`] does the same).
    /// 2. Re-run [`Self::lineate_locked`] to rebuild
    ///    `inner.lines` from the new text.
    /// 3. The FASM tail call to `vdraw` is intentionally omitted
    ///    here: in this Rust port, [`Widget::draw`] is invoked by
    ///    the render pipeline rather than self-triggered by setter
    ///    methods. This matches the sibling
    ///    [`crate::tui::widgets::matrix`] /
    ///    [`crate::tui::widgets::spinner`] convention where
    ///    state-mutation public methods do not invoke `draw`
    ///    directly. Callers wishing to force an immediate redraw
    ///    can invoke [`Widget::update_display_list`] on the parent
    ///    widget tree.
    pub fn set_text(&self, new_text: &str) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.filltext = String::from(new_text);
        Self::lineate_locked(&mut inner);
    }

    /// Replace this label's [`TextAlign`] mode.
    ///
    /// FASM parallel: `tui_label$nvsetalign`
    /// (`tui_label.inc` lines 435–443):
    ///
    /// ```text
    ///   self.textalign = new_align
    ///   self.vdraw()
    /// ```
    ///
    /// Sets `inner.align`. The FASM tail call to `vdraw` is
    /// intentionally omitted — see [`Self::set_text`] rationale.
    pub fn set_align(&self, align: TextAlign) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.align = align;
    }

    /// Replace this label's background colors.
    ///
    /// FASM parallel: `tui_label$nvsetcolors`
    /// (`tui_label.inc` lines 446–454):
    ///
    /// ```text
    ///   mov dword [self + tui_bgcolors_ofs], edx
    ///   self.vdraw()
    /// ```
    ///
    /// **CRITICAL** (per AAP transformation map): the FASM
    /// implementation writes to the **background**'s `tui_bgcolors`
    /// field, NOT a label-specific field. This Rust port preserves
    /// that semantic by writing to `inner.bgcolors` (the field that
    /// is consulted by [`nvfill`] and [`Widget::draw`] for the
    /// background color), matching the FASM `tui_bgcolors_ofs`
    /// access. This consistency is required for
    /// `tui_statusbar`-style callers that invoke `set_colors` on
    /// children expecting Background-field updates rather than a
    /// label-specific override.
    pub fn set_colors(&self, colors: ColorPair) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.bgcolors = colors;
    }

    /// Append a single line to `inner.lines` **without modifying**
    /// `inner.filltext`.
    ///
    /// FASM parallel: `tui_label$nvaddline`
    /// (`tui_label.inc` lines 457–476):
    ///
    /// ```text
    ///   ; cheater method — does NOT modify filltext, only appends
    ///   ; to lines list for drawing.
    ///   string$copy(line) -> rax
    ///   list$push_back(self.lines, rax)
    ///   self.vdraw()
    /// ```
    ///
    /// FASM comment at line 459 explicitly labels this a "cheater"
    /// method — appended lines are visible during draw but a
    /// subsequent [`Self::set_text`] / [`Self::lineate_locked`] call
    /// will wipe them when rebuilding `lines` from `filltext`.
    pub fn add_line(&self, line: &str) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.lines.push_back(String::from(line));
    }

    /// Configure per-character highlight marking.
    ///
    /// When `ch != 0`, [`Widget::draw`] re-colors any rendered cell
    /// whose codepoint matches `ch` with `color` instead of the
    /// label's default `bgcolors`. When `ch == 0`, highlight is
    /// disabled.
    ///
    /// FASM parallel: there is no public `nvsethighlight` in the
    /// `tui_label.inc` source; the highlight fields are populated by
    /// the parent widget directly via the inherited memory layout
    /// (`tui_label_highlightchar_ofs` / `tui_label_highlightcolor_ofs`
    /// at offsets +24/+32). The Rust port exposes a typed setter for
    /// the same fields because Rust does not permit external pokes
    /// at private struct fields — see AAP §0.7.2.4 inner-state
    /// encapsulation rationale.
    pub fn set_highlight(&self, ch: u32, color: ColorPair) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.highlight_char = ch;
        inner.highlight_color = color;
    }

    /// Public re-export of the LF-split helper for callers that need
    /// to force a re-lineate after directly mutating `filltext` via
    /// any path other than [`Self::set_text`].
    ///
    /// In normal usage [`Self::set_text`] is the canonical entry
    /// point and this method need not be called explicitly. The
    /// public form is provided for API symmetry with the FASM
    /// `tui_label$nvlineate` which is also exposed externally.
    pub fn lineate(&self) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        Self::lineate_locked(&mut inner);
    }
}

// ============================================================================
// Widget trait impl — 3 vmethod overrides + 3 required base accessors
// ============================================================================

impl Widget for TuiLabel {
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
    /// so callers holding an `Arc<dyn Widget>` can recover the
    /// concrete `TuiLabel` type via [`Any::downcast_ref`].
    fn as_any(&self) -> &dyn Any {
        self
    }

    // ---------------- Override 1: cleanup (vtable slot 0) ----------------

    /// Override — vtable slot 0 (`tui_vcleanup`).
    ///
    /// FASM parallel: `tui_label$cleanup`
    /// (`tui_label.inc` lines 393–413):
    ///
    /// ```text
    ///   ; free per-line strings + the lines list itself
    ///   list$foreach(self.lines, .freeline)
    ///   list$cleanup(self.lines)
    ///   heap$free(self.lines)
    ///   ; free the owned filltext copy
    ///   heap$free(self.filltext)
    ///   ; chain to base
    ///   tui_object$cleanup(self)
    /// ```
    ///
    /// Rust translation:
    /// 1. Acquire the `inner` lock and clear `inner.filltext` and
    ///    `inner.lines`. The `String` and `List<String>` types own
    ///    their backing allocations; `clear()` drops the contents
    ///    while retaining capacity (matching FASM
    ///    `heap$free`-then-realloc patterns where the freed regions
    ///    are immediately ready for reuse).
    /// 2. Inline the [`Widget::cleanup`] trait-default body
    ///    (clearing `state.children`, `state.bastards`,
    ///    `state.text`, `state.attributes`, `state.display_name`)
    ///    rather than calling [`crate::tui::object::cleanup_widget`]
    ///    — the latter dispatches polymorphically through
    ///    `self.cleanup()` and would re-enter this method
    ///    recursively. The
    ///    [`crate::tui::widgets::spinner::Spinner`] override uses
    ///    the same inline pattern.
    fn cleanup(&mut self) {
        // ---- Step 1: clear label-owned heap allocations.
        match self.inner.lock() {
            Ok(mut guard) => {
                guard.filltext.clear();
                guard.lines.clear();
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.filltext.clear();
                guard.lines.clear();
            }
        }

        // ---- Step 2: inline the trait-default cleanup body.
        let state = &mut self.state;
        state.children.clear();
        state.bastards.clear();
        state.text.clear();
        state.attributes.clear();
        state.display_name.clear();
    }

    // ---------------- Override 2: clone_widget (vtable slot 1) -----------

    /// Override — vtable slot 1 (`tui_vclone`).
    ///
    /// FASM parallel: `tui_label$clone`
    /// (`tui_label.inc` lines 323–359):
    ///
    /// ```text
    ///   alloc_clear(tui_label_size)
    ///   string$copy(self.filltext)        -> dst.filltext
    ///   list$new                           -> dst.lines (FRESH empty)
    ///   tui_background$init_copy(dst, src) ; deep clone state
    ///   dst.textalign      = src.textalign
    ///   dst.highlightchar  = src.highlightchar
    ///   dst.highlightcolor = src.highlightcolor
    ///   ; rebuild lines from filltext (DO NOT deep-copy lines list)
    ///   tui_label$nvlineate(dst)
    /// ```
    ///
    /// Rust translation:
    /// 1. Read the source `inner` snapshot (under the lock) — copies
    ///    out `filltext`, `align`, `bgfillchar`, `bgcolors`,
    ///    `highlight_char`, `highlight_color`. The `lines` field is
    ///    intentionally **not** read because the FASM clone
    ///    explicitly rebuilds lines from `filltext` rather than
    ///    deep-copying.
    /// 2. Deep-clone `self.state` via [`clone_widget_state`] which
    ///    polymorphically clones all children (FASM
    ///    `tui_background$init_copy` -> `tui_object$init_copy`).
    /// 3. Construct a fresh [`LabelInner`] with a fresh empty
    ///    `lines: List<String>`.
    /// 4. Run [`Self::lineate_locked`] on the new inner to populate
    ///    `lines` from `filltext`.
    /// 5. Wrap in [`Arc::new`] and return as `Arc<dyn Widget>`.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when [`clone_widget_state`]
    /// reports an error from a nested child's [`Widget::clone_widget`]
    /// (e.g. the trait-default's `Unsupported` for an unimplemented
    /// override). Propagates via the `?` operator.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // ---- Step 1: snapshot source inner (under the lock).
        let (filltext, align, bgfillchar, bgcolors, highlight_char, highlight_color) = match self.inner.lock()
        {
            Ok(g) => (
                g.filltext.clone(),
                g.align,
                g.bgfillchar,
                g.bgcolors,
                g.highlight_char,
                g.highlight_color,
            ),
            Err(p) => {
                let g = p.into_inner();
                (
                    g.filltext.clone(),
                    g.align,
                    g.bgfillchar,
                    g.bgcolors,
                    g.highlight_char,
                    g.highlight_color,
                )
            }
        };

        // ---- Step 2: deep-clone the inherited WidgetState.
        let cloned_state = clone_widget_state(&self.state)?;

        // ---- Step 3: build the fresh inner.
        let mut cloned_inner = LabelInner {
            bgfillchar,
            bgcolors,
            filltext,
            align,
            lines: List::new(),
            highlight_char,
            highlight_color,
        };

        // ---- Step 4: rebuild lines from filltext (FASM lines 354–355).
        Self::lineate_locked(&mut cloned_inner);

        // ---- Step 5: wrap and return.
        Ok(Arc::new(Self {
            state: cloned_state,
            inner: Mutex::new(cloned_inner),
        }) as Arc<dyn Widget>)
    }

    // ---------------- Override 3: draw (vtable slot 2) -------------------

    /// Override — vtable slot 2 (`tui_vdraw`).
    ///
    /// FASM parallel: `tui_label$draw`
    /// (`tui_label.inc` lines 489–789).
    ///
    /// FASM algorithm (faithful summary):
    ///
    /// 1. Bail when `width <= 0` or `height <= 0` (FASM
    ///    `.nothingtodo` shortcut at line 514).
    /// 2. Call `tui_background$nvfill` to blast the configured
    ///    `bgfillchar` and `bgcolors` across the full text and
    ///    attribute buffers (FASM line 517).
    /// 3. Compute the byte-pointer to the **last** row of the text
    ///    buffer (`text + cells*4 - row_bytes`) and the matching
    ///    pointer for the attribute buffer.
    /// 4. Bottom-anchor adjustment: when the line cache contains
    ///    fewer entries than the widget's height, advance the
    ///    write pointers UP by `(height - line_count) * row_bytes`
    ///    to preserve the FASM "render bottom to top" geometry
    ///    that yields top-anchored content when shorter than the
    ///    widget (this is the inverse of what naive top-down
    ///    rendering would produce).
    /// 5. Iterate the `lines` cache from **last to first**,
    ///    writing each line's UTF-32 codepoints into the text
    ///    buffer at the alignment-determined column offset and
    ///    overlaying `highlight_color` on cells whose codepoint
    ///    matches `highlight_char` (when non-zero). After each
    ///    line the pointers move UP by `row_bytes` and the
    ///    line-counter decrements; the loop terminates at
    ///    counter == 0.
    ///
    /// Rust translation:
    ///
    /// We invert the iteration direction to top-to-bottom (which is
    /// equivalent in final output) for clarity:
    ///
    /// - Compute `start_row = max(0, height - line_count)`.
    /// - For each line `i` in `0..line_count.min(height)`, render
    ///   into row `start_row + i`.
    ///
    /// This produces the same final buffer state as the FASM
    /// `bottom-to-top` walk because both algorithms write the same
    /// `(line_index → row_index)` mapping; the order of writes does
    /// not matter since they target disjoint cells.
    ///
    /// Column offset per [`TextAlign`]:
    ///
    /// - [`TextAlign::Left`]:   `col = 0`
    /// - [`TextAlign::Center`]: `col = (width - line_chars) / 2`
    /// - [`TextAlign::Right`]:  `col = width - line_chars`
    ///
    /// FASM `and r11, not 3` 4-byte alignment of the center offset
    /// (line 596) is a no-op in Rust because we operate on
    /// chars-per-cell rather than bytes-per-cell; the per-cell
    /// granularity already matches FASM's 4-byte step.
    ///
    /// Width clipping: lines longer than `width` are truncated via
    /// [`Iterator::take`] on the char iterator (no wrapping). FASM
    /// performs the same clipping by capping `copy_bytes` at
    /// `row_bytes` (line 569).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] only on `usize`-arithmetic
    /// overflow when computing the cell count (impossible for
    /// realistic terminal sizes; preserved for trait-signature
    /// symmetry).
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        // ---- Step 1: dimension bail (FASM .nothingtodo).
        let width = self.state.width;
        let height = self.state.height;
        if width <= 0 || height <= 0 {
            return Ok(());
        }
        let width_u = width as usize;
        let height_u = height as usize;
        let cells = width_u.checked_mul(height_u).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(format!(
                "TuiLabel::draw: width*height overflowed usize \
                 (width={width}, height={height})"
            )))
        })?;

        // ---- Step 2: snapshot inner state under the lock so we can
        // release it before mutating self.state.text/attributes
        // (avoids any potential nested-lock contention with
        // descendants).
        let (lines, align, highlight_char, highlight_color, bgfillchar, bgcolors) = match self.inner.lock() {
            Ok(g) => (
                g.lines.iter().cloned().collect::<Vec<String>>(),
                g.align,
                g.highlight_char,
                g.highlight_color,
                g.bgfillchar,
                g.bgcolors,
            ),
            Err(p) => {
                let g = p.into_inner();
                (
                    g.lines.iter().cloned().collect::<Vec<String>>(),
                    g.align,
                    g.highlight_char,
                    g.highlight_color,
                    g.bgfillchar,
                    g.bgcolors,
                )
            }
        };

        // ---- Step 3: replicate `tui_background$nvfill`.
        nvfill(&mut self.state, bgfillchar, bgcolors)?;

        // ---- Step 4: ensure the buffers are sized to (cells * 4)
        // bytes / `cells` u32 attributes. Constructors that skipped
        // pre-allocation (percentage-based dimensions) need this on
        // the first draw after layout resolves.
        let target_bytes = cells * 4;
        if self.state.text.len() < target_bytes {
            self.state.text.reserve(target_bytes - self.state.text.len());
            for _ in self.state.text.len()..target_bytes {
                self.state.text.push(0);
            }
        }
        if self.state.attributes.cells.len() < cells {
            self.state.attributes.cells.resize(cells, 0);
        }

        // ---- Step 5: bottom-anchor adjustment.
        let line_count = lines.len();
        let line_count_capped = line_count.min(height_u);
        let start_row = height_u - line_count_capped;

        // Pre-pack the highlight color for fast per-cell overlay.
        let highlight_packed = pack_color_pair(highlight_color);

        // ---- Step 6: render each line into its target row.
        for (i, line) in lines.iter().take(line_count_capped).enumerate() {
            let row = start_row + i;

            // Collect chars (NOT bytes) and clip to `width_u`.
            let chars: Vec<char> = line.chars().take(width_u).collect();
            let line_width = chars.len();
            if line_width == 0 {
                continue;
            }

            // Compute alignment-determined column offset.
            let col_off: usize = match align {
                TextAlign::Left => 0,
                TextAlign::Center => {
                    // FASM `(row_bytes - copy_bytes) >> 1` then
                    // `and r11, not 3` (4-byte aligned). At
                    // chars-per-cell granularity this is just
                    // integer division by 2 — the bottom 2 bits
                    // never carry per-char meaning.
                    (width_u - line_width) / 2
                }
                TextAlign::Right => width_u - line_width,
            };

            // Per-cell write: codepoint into text buffer, optional
            // highlight overlay into attribute buffer.
            let row_offset_bytes = row * width_u * 4;
            let row_offset_cells = row * width_u;
            for (j, ch) in chars.iter().enumerate() {
                let col = col_off + j;
                if col >= width_u {
                    break;
                }
                let cell_byte_off = row_offset_bytes + col * 4;
                let cell_idx = row_offset_cells + col;
                let codepoint = *ch as u32;

                // Write 4 little-endian bytes for the codepoint
                // (matching FASM `mov dword [rsi+offset], eax`).
                let le = codepoint.to_le_bytes();
                let dst = self.state.text.as_mut_slice();
                if cell_byte_off + 4 <= dst.len() {
                    dst[cell_byte_off..cell_byte_off + 4].copy_from_slice(&le);
                }

                // Highlight overlay.
                if highlight_char != 0
                    && codepoint == highlight_char
                    && cell_idx < self.state.attributes.cells.len()
                {
                    self.state.attributes.cells[cell_idx] = highlight_packed;
                }
            }
        }

        // ---- Step 7: dispatch display-list update.
        self.update_display_list();
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::geometry::Rect;

    /// Helper — produce a default test [`ColorPair`] (white on black).
    fn test_colors() -> ColorPair {
        ColorPair { fg: 7, bg: 0 }
    }

    /// Helper — produce a contrasting highlight [`ColorPair`].
    fn test_highlight_colors() -> ColorPair {
        ColorPair { fg: 1, bg: 7 }
    }

    /// Helper — read the codepoint at row `r`, col `c` from a label's
    /// text buffer (4 little-endian bytes per cell, `width` cells per
    /// row).
    fn cell_codepoint_at(label: &TuiLabel, r: usize, c: usize) -> u32 {
        let width = label.state.width as usize;
        let off = (r * width + c) * 4;
        let s = label.state.text.as_slice();
        if off + 4 > s.len() {
            return 0;
        }
        u32::from_le_bytes([s[off], s[off + 1], s[off + 2], s[off + 3]])
    }

    /// Helper — read the packed attribute at row `r`, col `c`.
    fn cell_attr_at(label: &TuiLabel, r: usize, c: usize) -> u32 {
        let width = label.state.width as usize;
        let idx = r * width + c;
        if idx >= label.state.attributes.cells.len() {
            return 0;
        }
        label.state.attributes.cells[idx]
    }

    /// Test 1 — TextAlign discriminants must match FASM constants.
    ///
    /// Per `tui_label.inc` lines 60–62:
    /// `tui_textalign_left = 0`,
    /// `tui_textalign_center = 1`,
    /// `tui_textalign_right = 2`.
    /// Justified (=3) is intentionally NOT supported.
    #[test]
    fn test_text_align_variants() {
        assert_eq!(TextAlign::Left as u32, 0);
        assert_eq!(TextAlign::Center as u32, 1);
        assert_eq!(TextAlign::Right as u32, 2);
        // Default must be Left to match FASM `xor edx, edx` initial.
        assert_eq!(TextAlign::default(), TextAlign::Left);
    }

    /// Test 2 — `new_ii(width, height, ...)` propagates dimensions
    /// to `state.width` / `state.height`.
    #[test]
    fn test_new_ii_sets_size() {
        let label = TuiLabel::new_ii(10, 3, "test", test_colors(), TextAlign::Left)
            .expect("new_ii must succeed for 10x3 dimensions");
        assert_eq!(label.state.width, 10);
        assert_eq!(label.state.height, 3);
        assert_eq!(label.state.width_percent, None);
        assert_eq!(label.state.height_percent, None);
    }

    /// Test 3 — `new_str("hi\nworld", ...)` must auto-compute
    /// width = 5 (max line chars) and height = 2 (line count) per
    /// FASM `.linelength` callback semantics
    /// (`tui_label.inc` lines 122–143).
    #[test]
    fn test_new_str_auto_dims() {
        let label =
            TuiLabel::new_str("hi\nworld", test_colors(), TextAlign::Left).expect("new_str must succeed");
        assert_eq!(label.state.width, 5);
        assert_eq!(label.state.height, 2);
    }

    /// Test 4 — `filltext` must be OWNED, not borrowed. Mutating
    /// the source `&str` after construction must not affect the
    /// label (FASM `string$copy` deep-allocates). Implemented by
    /// dropping the source [`String`] and verifying lines remain
    /// correct.
    #[test]
    fn test_filltext_is_owned() {
        let owned = String::from("alpha");
        let label =
            TuiLabel::new_ii(10, 1, &owned, test_colors(), TextAlign::Left).expect("new_ii must succeed");
        // Drop the source string — label must retain its own copy.
        drop(owned);
        let inner = label.inner.lock().expect("lock must not be poisoned");
        assert_eq!(inner.filltext, "alpha");
        assert_eq!(inner.lines.len(), 1);
        assert_eq!(inner.lines.iter().next().map(String::as_str), Some("alpha"));
    }

    /// Test 5 — `lineate()` splits filltext by LF (\n) into N+1
    /// segments where N = LF count (FASM `string$split` with
    /// separator = 10).
    #[test]
    fn test_lineate_splits_by_lf() {
        let label =
            TuiLabel::new_ii(10, 3, "a\nb\nc", test_colors(), TextAlign::Left).expect("new_ii must succeed");
        let inner = label.inner.lock().expect("lock must not be poisoned");
        assert_eq!(inner.lines.len(), 3);
        let collected: Vec<String> = inner.lines.iter().cloned().collect();
        assert_eq!(collected, vec!["a", "b", "c"]);
    }

    /// Test 6 — empty filltext lineates to a single empty line
    /// (FASM `string$split("", LF)` returns [""]).
    #[test]
    fn test_lineate_empty_string() {
        let label = TuiLabel::new_ii(10, 1, "", test_colors(), TextAlign::Left).expect("new_ii must succeed");
        let inner = label.inner.lock().expect("lock must not be poisoned");
        assert_eq!(inner.lines.len(), 1);
        assert_eq!(inner.lines.iter().next().map(String::as_str), Some(""));
    }

    /// Test 7 — trailing LF produces an extra empty line
    /// (FASM `string$split("a\n", LF)` returns ["a", ""]).
    #[test]
    fn test_lineate_trailing_lf() {
        let label =
            TuiLabel::new_ii(10, 2, "a\n", test_colors(), TextAlign::Left).expect("new_ii must succeed");
        let inner = label.inner.lock().expect("lock must not be poisoned");
        assert_eq!(inner.lines.len(), 2);
        let collected: Vec<String> = inner.lines.iter().cloned().collect();
        assert_eq!(collected, vec!["a".to_string(), "".to_string()]);
    }

    /// Test 8 — `clone_widget` produces a fresh `lines` list
    /// rebuilt from `filltext` rather than deep-copying the source's
    /// `lines` (FASM `tui_label$clone` lines 354–355 explicitly
    /// re-call `nvlineate` on the clone).
    ///
    /// Verification: mutate the source's `lines` post-clone via
    /// [`TuiLabel::add_line`] (which appends without touching
    /// `filltext`) and confirm the clone retains the lineate-derived
    /// state, NOT the source's mutated state.
    #[test]
    fn test_clone_relineate_not_deepcopy() {
        let label =
            TuiLabel::new_ii(10, 3, "x\ny", test_colors(), TextAlign::Left).expect("new_ii must succeed");

        // Mutate source post-construction — appends an extra entry
        // to `lines` without touching filltext.
        label.add_line("z");
        {
            let g = label.inner.lock().expect("lock must not be poisoned");
            assert_eq!(g.lines.len(), 3, "source must show 3 lines after add_line");
        }

        // Clone — must rebuild lines from filltext, dropping the
        // appended "z".
        let cloned: Arc<dyn Widget> = label.clone_widget().expect("clone must succeed");
        let cloned_label: &TuiLabel = cloned
            .as_any()
            .downcast_ref::<TuiLabel>()
            .expect("cloned widget must be a TuiLabel");
        let inner = cloned_label
            .inner
            .lock()
            .expect("clone lock must not be poisoned");
        assert_eq!(inner.lines.len(), 2, "clone must lineate fresh from filltext");
        let collected: Vec<String> = inner.lines.iter().cloned().collect();
        assert_eq!(collected, vec!["x", "y"]);
    }

    /// Test 9 — `set_text` triggers re-lineate (FASM
    /// `tui_label$nvsettext` lines 415–432: sets filltext then
    /// calls `nvlineate`).
    #[test]
    fn test_set_text_resets_lines() {
        let label =
            TuiLabel::new_ii(10, 2, "old", test_colors(), TextAlign::Left).expect("new_ii must succeed");

        // Initial state: 1 line "old".
        {
            let g = label.inner.lock().expect("lock must not be poisoned");
            assert_eq!(g.lines.len(), 1);
        }

        // Replace with 3-line text.
        label.set_text("a\nb\nc");

        let inner = label.inner.lock().expect("lock must not be poisoned");
        assert_eq!(inner.filltext, "a\nb\nc");
        assert_eq!(inner.lines.len(), 3);
        let collected: Vec<String> = inner.lines.iter().cloned().collect();
        assert_eq!(collected, vec!["a", "b", "c"]);
    }

    /// Test 10 — `add_line` is a "cheater" method per FASM line
    /// 459 comment: appends to `lines` WITHOUT modifying `filltext`.
    #[test]
    fn test_add_line_does_not_modify_filltext() {
        let label =
            TuiLabel::new_ii(10, 2, "base", test_colors(), TextAlign::Left).expect("new_ii must succeed");

        label.add_line("appended");

        let inner = label.inner.lock().expect("lock must not be poisoned");
        // filltext must remain "base" (no LF, no "appended").
        assert_eq!(inner.filltext, "base");
        // lines must have 2 entries: "base" (from lineate) + "appended".
        assert_eq!(inner.lines.len(), 2);
        let collected: Vec<String> = inner.lines.iter().cloned().collect();
        assert_eq!(collected, vec!["base", "appended"]);
    }

    /// Test 11 — `draw` with [`TextAlign::Left`] must place the
    /// rendered chars starting at column 0, with the remaining
    /// columns filled by `bgfillchar` (space).
    #[test]
    fn test_draw_alignment_left() {
        let mut label_owned =
            TuiLabel::new_ii(5, 1, "ab", test_colors(), TextAlign::Left).expect("new_ii must succeed");
        let label = Arc::get_mut(&mut label_owned).expect("unique reference");

        // Use a pseudo-renderer; spinner pattern uses `&mut dyn Renderer`
        // but the body never touches it — pass a no-op stub.
        let mut stub_renderer = StubRenderer;
        label.draw(&mut stub_renderer).expect("draw must succeed");

        // Cells [0..2] must hold 'a', 'b'; cells [2..5] must hold ' '.
        assert_eq!(cell_codepoint_at(label, 0, 0), b'a' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 1), b'b' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 2), b' ' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 3), b' ' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 4), b' ' as u32);
    }

    /// Test 12 — `draw` with [`TextAlign::Center`] must center the
    /// rendered chars within `width` cells: for a 2-char line in a
    /// 5-wide widget, `(5-2)/2 = 1` left-padding cell.
    #[test]
    fn test_draw_alignment_center() {
        let mut label_owned =
            TuiLabel::new_ii(5, 1, "ab", test_colors(), TextAlign::Center).expect("new_ii must succeed");
        let label = Arc::get_mut(&mut label_owned).expect("unique reference");

        let mut stub_renderer = StubRenderer;
        label.draw(&mut stub_renderer).expect("draw must succeed");

        // Expected layout for "ab" in 5-wide center: ` ab  `.
        assert_eq!(cell_codepoint_at(label, 0, 0), b' ' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 1), b'a' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 2), b'b' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 3), b' ' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 4), b' ' as u32);
    }

    /// Test 13 — `draw` with [`TextAlign::Right`] must place the
    /// rendered chars at the right edge: for a 2-char line in a
    /// 5-wide widget, columns 3–4 hold the chars.
    #[test]
    fn test_draw_alignment_right() {
        let mut label_owned =
            TuiLabel::new_ii(5, 1, "ab", test_colors(), TextAlign::Right).expect("new_ii must succeed");
        let label = Arc::get_mut(&mut label_owned).expect("unique reference");

        let mut stub_renderer = StubRenderer;
        label.draw(&mut stub_renderer).expect("draw must succeed");

        // Expected: `   ab`.
        assert_eq!(cell_codepoint_at(label, 0, 0), b' ' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 1), b' ' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 2), b' ' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 3), b'a' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 4), b'b' as u32);
    }

    /// Test 14 — bottom-anchor: when `lines.count() < height`, the
    /// content must occupy the LAST `lines.count()` rows.
    /// Specifically, 2 lines in a 4-row widget → rows 0,1 are
    /// blank; rows 2,3 hold "a","b".
    #[test]
    fn test_draw_bottom_anchor() {
        let mut label_owned =
            TuiLabel::new_ii(3, 4, "a\nb", test_colors(), TextAlign::Left).expect("new_ii must succeed");
        let label = Arc::get_mut(&mut label_owned).expect("unique reference");

        let mut stub_renderer = StubRenderer;
        label.draw(&mut stub_renderer).expect("draw must succeed");

        // Top 2 rows must hold ' ' (background fill).
        for row in 0..2 {
            for col in 0..3 {
                assert_eq!(
                    cell_codepoint_at(label, row, col),
                    b' ' as u32,
                    "row {row} col {col} must be background fill"
                );
            }
        }
        // Row 2 must hold "a  " (left-aligned in 3-wide).
        assert_eq!(cell_codepoint_at(label, 2, 0), b'a' as u32);
        assert_eq!(cell_codepoint_at(label, 2, 1), b' ' as u32);
        // Row 3 must hold "b  ".
        assert_eq!(cell_codepoint_at(label, 3, 0), b'b' as u32);
        assert_eq!(cell_codepoint_at(label, 3, 1), b' ' as u32);
    }

    /// Test 15 — highlight: cells whose codepoint matches
    /// `highlight_char` receive `highlight_color` while
    /// non-matching cells retain the background color.
    #[test]
    fn test_draw_highlight() {
        let mut label_owned =
            TuiLabel::new_ii(4, 1, "abca", test_colors(), TextAlign::Left).expect("new_ii must succeed");
        // `set_highlight` takes `&self`, so we can call it through
        // `label_owned` (an `Arc<TuiLabel>`) without cloning. Cloning
        // the Arc would produce a second strong reference and block
        // the subsequent `Arc::get_mut` from succeeding.
        label_owned.set_highlight(b'a' as u32, test_highlight_colors());
        let label = Arc::get_mut(&mut label_owned).expect("unique reference");

        let mut stub_renderer = StubRenderer;
        label.draw(&mut stub_renderer).expect("draw must succeed");

        let bg_packed = pack_color_pair(test_colors());
        let hl_packed = pack_color_pair(test_highlight_colors());

        // Cells [0] and [3] hold 'a' → must be highlight color.
        assert_eq!(
            cell_attr_at(label, 0, 0),
            hl_packed,
            "col 0 'a' must be highlighted"
        );
        assert_eq!(
            cell_attr_at(label, 0, 3),
            hl_packed,
            "col 3 'a' must be highlighted"
        );
        // Cells [1] and [2] hold 'b','c' → must remain bg color.
        assert_eq!(cell_attr_at(label, 0, 1), bg_packed, "col 1 'b' must be bg color");
        assert_eq!(cell_attr_at(label, 0, 2), bg_packed, "col 2 'c' must be bg color");
    }

    /// Test 16 — width clipping: a line longer than `width` must
    /// be truncated (no wrapping), per FASM `min(line_bytes,
    /// row_bytes)` clamp at line 569.
    #[test]
    fn test_draw_clip_too_wide() {
        let mut label_owned = TuiLabel::new_ii(5, 1, "abcdefghij", test_colors(), TextAlign::Left)
            .expect("new_ii must succeed");
        let label = Arc::get_mut(&mut label_owned).expect("unique reference");

        let mut stub_renderer = StubRenderer;
        label.draw(&mut stub_renderer).expect("draw must succeed");

        // Only the first 5 chars must appear; cells [0..5] = "abcde".
        assert_eq!(cell_codepoint_at(label, 0, 0), b'a' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 1), b'b' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 2), b'c' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 3), b'd' as u32);
        assert_eq!(cell_codepoint_at(label, 0, 4), b'e' as u32);
        // Buffer must be exactly 5 cells * 4 bytes = 20 bytes
        // (no overflow/wrap into a phantom row 1).
        assert_eq!(label.state.text.len(), 20);
    }

    // ---- Bonus tests covering remaining validation-checklist items ----

    /// Validation checklist item 11 — `draw` bails with no buffer
    /// mutation when `width == 0` or `height == 0`.
    #[test]
    fn test_draw_bails_on_zero_dimensions() {
        let mut label_owned =
            TuiLabel::new_dd(0.5, 0.5, "x", test_colors(), TextAlign::Left).expect("new_dd must succeed");
        // Pre-condition: width/height are 0 (percentage-based with no
        // layout pass).
        assert_eq!(label_owned.state.width, 0);
        assert_eq!(label_owned.state.height, 0);

        let label = Arc::get_mut(&mut label_owned).expect("unique reference");
        let mut stub_renderer = StubRenderer;
        label.draw(&mut stub_renderer).expect("draw must bail cleanly");

        // Buffers must remain empty.
        assert!(label.state.text.is_empty());
        assert!(label.state.attributes.cells.is_empty());
    }

    /// Validation checklist item 20 — `set_colors` writes to
    /// BACKGROUND's color field (`inner.bgcolors`), not a
    /// label-specific override. Verifies that a follow-up `draw`
    /// uses the new color across all cells.
    #[test]
    fn test_set_colors_writes_to_background() {
        let mut label_owned =
            TuiLabel::new_ii(3, 1, "ab", test_colors(), TextAlign::Left).expect("new_ii must succeed");

        let new_colors = ColorPair { fg: 4, bg: 6 };
        label_owned.set_colors(new_colors);

        let label = Arc::get_mut(&mut label_owned).expect("unique reference");
        let mut stub_renderer = StubRenderer;
        label.draw(&mut stub_renderer).expect("draw must succeed");

        // All 3 cells must carry the NEW packed color (set_colors
        // -> inner.bgcolors, then draw -> nvfill -> attr buffer).
        let new_packed = pack_color_pair(new_colors);
        for col in 0..3 {
            assert_eq!(
                cell_attr_at(label, 0, col),
                new_packed,
                "col {col} must reflect the new background color"
            );
        }
    }

    /// `new_rect` — Rect-based dimension propagation.
    #[test]
    fn test_new_rect_dimensions() {
        let rect = Rect::new(0, 0, 8, 3); // ax=0, ay=0, bx=8, by=3
        let label =
            TuiLabel::new_rect(rect, "hi", test_colors(), TextAlign::Center).expect("new_rect must succeed");
        assert_eq!(label.state.bounds, rect);
        assert_eq!(label.state.width, 8);
        assert_eq!(label.state.height, 3);
    }

    /// `new_id` — integer width, percentage height: width is
    /// concrete, height awaits layout.
    #[test]
    fn test_new_id_dimensions() {
        let label =
            TuiLabel::new_id(20, 0.5, "abc", test_colors(), TextAlign::Left).expect("new_id must succeed");
        assert_eq!(label.state.width, 20);
        assert_eq!(label.state.height, 0);
        assert_eq!(label.state.width_percent, None);
        assert_eq!(label.state.height_percent, Some(0.5));
    }

    /// `new_di` — percentage width, integer height: height is
    /// concrete, width awaits layout.
    #[test]
    fn test_new_di_dimensions() {
        let label =
            TuiLabel::new_di(0.75, 4, "abc", test_colors(), TextAlign::Right).expect("new_di must succeed");
        assert_eq!(label.state.width, 0);
        assert_eq!(label.state.height, 4);
        assert_eq!(label.state.width_percent, Some(0.75));
        assert_eq!(label.state.height_percent, None);
    }

    /// `new_dd_vec` — Label::new_dd_vec convenience factory accepting
    /// `Vec<u8>` filltext. Verifies the lossy UTF-8 conversion.
    #[test]
    fn test_label_new_dd_vec() {
        let bytes: Vec<u8> = b"hello\nworld".to_vec();
        let label = Label::new_dd_vec(0.5, 0.5, bytes, test_colors(), TextAlign::Left)
            .expect("new_dd_vec must succeed");
        let inner = label.inner.lock().expect("lock must not be poisoned");
        assert_eq!(inner.filltext, "hello\nworld");
        assert_eq!(inner.lines.len(), 2);
    }

    /// Cleanup — verifies all label-owned heap state is cleared.
    #[test]
    fn test_cleanup_clears_label_state() {
        let mut label_owned =
            TuiLabel::new_ii(5, 2, "a\nb", test_colors(), TextAlign::Left).expect("new_ii must succeed");
        let label = Arc::get_mut(&mut label_owned).expect("unique reference");

        label.cleanup();

        let inner = label.inner.lock().expect("lock must not be poisoned");
        assert!(inner.filltext.is_empty(), "filltext must be cleared");
        assert!(inner.lines.is_empty(), "lines must be cleared");
        assert!(label.state.text.is_empty(), "state.text must be cleared");
        assert!(
            label.state.attributes.cells.is_empty(),
            "state.attributes must be cleared"
        );
    }

    /// Stub Renderer — minimal no-op implementation used by `draw`
    /// tests. The label `draw` method does NOT invoke any renderer
    /// methods (it only stages buffer state and dispatches the
    /// trait-default no-op `update_display_list`), so a stub is
    /// sufficient.
    struct StubRenderer;

    impl crate::tui::render::Renderer for StubRenderer {
        fn ansi_output(&mut self, _bytes: &[u8]) -> Result<(), TuiError> {
            unreachable!("TuiLabel::draw never invokes Renderer::ansi_output")
        }
        fn flush(&mut self) -> Result<(), TuiError> {
            unreachable!("TuiLabel::draw never invokes Renderer::flush")
        }
        fn state(&self) -> &crate::tui::render::RenderState {
            unreachable!("TuiLabel::draw never invokes Renderer::state")
        }
        fn state_mut(&mut self) -> &mut crate::tui::render::RenderState {
            unreachable!("TuiLabel::draw never invokes Renderer::state_mut")
        }
    }
}
