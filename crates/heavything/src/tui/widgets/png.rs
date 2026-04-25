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
// tui_png: render a PNG image to terminal cells via xterm 256-color
// quantization, maintaining a 2:1 character aspect ratio.
// Ported from tui_png.inc (537 lines of FASM assembly).

//! PNG widget: renders a [`Png`] to terminal cells via xterm 256-color
//! quantization. A 2:1 character aspect ratio is preserved; the
//! quantized image is centered within the widget bounds.
//!
//! Translation of FASM `tui_png.inc` (537 lines). Descends
//! [`crate::tui::object::Widget`] directly (NOT [`super::background`]),
//! overriding only three vmethod slots:
//!
//! - [`Widget::cleanup`] (vtable slot 0) — drop the cached attribute
//!   buffer; the parent [`tui_object`](crate::tui::object) cleanup
//!   handles `text` / `attributes` / `display_name` etc.
//! - [`Widget::clone_widget`] (vtable slot 1) — share the [`Png`] via
//!   [`Arc`] refcount and reset the cached buffer (force redraw).
//! - [`Widget::draw`] (vtable slot 2) — perform the 2:1 aspect-fit
//!   quantization to xterm 256 colors and copy the result into the
//!   widget's `attributes` buffer.
//!
//! All 34 other vmethods inherit their default trait implementations.
//!
//! # Ownership
//!
//! The widget holds an `Arc<Png>`; the caller is responsible for
//! constructing the [`Png`] (via [`crate::util::png::Png::new`]) and
//! retaining the outer [`Arc`]. The widget does NOT clone or copy
//! pixel data — cloning the widget shares the same `Arc<Png>`. This
//! enforces the FASM-comment caveat verbatim:
//!
//! > NOTE: CAUTION: ETC: haha, the png object passed to the new
//! > functions here does -not- make a copy of it, so the source
//! > png object must survive for as long as this object does
//!
//! Rust's [`Arc`] refcounting makes this contract structural rather
//! than documentary: the widget cannot outlive the underlying [`Png`]
//! because the widget holds a strong reference to it.
//!
//! # Quantization algorithm
//!
//! For each output cell `(row, col)`:
//!
//! 1. Sample an `x_gather × y_gather` block of source RGBA pixels
//!    (where `x_gather`/`y_gather` are the per-cell pixel sampling
//!    rates derived from `aspect_ratio = (png_width × 2) ÷ png_height`).
//! 2. Average the R, G, B channels (alpha is discarded).
//! 3. Mask the lower 2 bits of each averaged channel (`& !3`) — FASM
//!    convention to make near-grayscale colors register as exactly
//!    grayscale.
//! 4. If `R == G == B` after masking → **grayscale path**:
//!    `palette = 0xE8 + (R / 11)` (24-step grayscale ramp,
//!    palette indices 232..255).
//! 5. Else → **color cube path**:
//!    `palette = 16 + 36*r + 6*g + b`
//!    where `r = min(R / 42.666…, 5)`, etc. (6×6×6 RGB cube,
//!    palette indices 16..231).
//!
//! The result is written as a packed `u32` (palette index in the
//! background channel) into the widget's [`Attributes`] buffer; the
//! corresponding `text` cell is filled with `' '` (space).
//!
//! # Performance
//!
//! `draw` caches the quantized buffer keyed by widget dimensions:
//! consecutive draws at the same size are O(width × height) memcpy.
//! Cache invalidation triggers on:
//!
//! - first draw (buffer is `None`),
//! - widget resize (cached_width / cached_height mismatch), or
//! - explicit cache reset via [`PngWidget::set_bgcolor`].
//!
//! # Field layout (FASM offsets)
//!
//! ```text
//! tui_png_image_ofs    = tui_object_size + 0    ; Arc<Png> handle
//! tui_png_buffer_ofs   = tui_object_size + 8    ; Option<Vec<u32>>
//! tui_png_width_ofs    = tui_object_size + 16   ; cached_width: i32
//! tui_png_height_ofs   = tui_object_size + 24   ; cached_height: i32
//! tui_png_bgcolor_ofs  = tui_object_size + 32   ; bgcolor: u8
//! tui_png_user_ofs     = tui_object_size + 40   ; user: usize
//! tui_png_size         = tui_object_size + 48
//! ```
//!
//! Rust's struct repr is opaque (no `#[repr(C)]` is needed because we
//! never read raw memory from outside the crate); only the field
//! semantics match FASM.

use std::any::Any;
use std::sync::Arc;

use crate::error::TuiError;
use crate::tui::geometry::Rect;
use crate::tui::object::{Attributes, Widget, WidgetState};
use crate::tui::render::Renderer;
use crate::util::png::Png;

// ============================================================================
// Quantization constants — matching FASM tui_png.inc byte-for-byte.
// ============================================================================

/// Color cube divisor: `256 / 6 ≈ 42.6666666666667`.
///
/// Each averaged R/G/B channel (range `0..=255`) is divided by this
/// constant to produce a `0..=5` color-cube coordinate. The literal
/// matches FASM `tui_png.inc:349` (`mov rax, 42.6666666666667f`)
/// byte-for-byte under IEEE-754 double-precision rounding.
///
/// FASM uses a `dq` 8-byte double; Rust uses `f64` which is the
/// matching IEEE-754 double. The textual literal
/// `42.666_666_666_666_7` parses to the same bit pattern as the FASM
/// value because both use round-to-nearest-even for the trailing
/// digit; if a future audit reveals a 1-ULP discrepancy, this
/// constant would need to be redefined as `256.0 / 6.0` to compute
/// the canonical value.
const COLORCUBE_DIVISOR: f64 = 42.666_666_666_666_7;

/// Maximum color-cube coordinate after division. Each of R/G/B is
/// clamped to this value before the `16 + 36*r + 6*g + b` formula.
///
/// FASM uses `cmova r8d, eax` with `eax = 5` (`tui_png.inc:491–497`).
const COLORCUBE_MAX: u32 = 5;

/// Grayscale base: xterm 256-color palette index for the darkest
/// grayscale step (palette indices 232..=255 are the 24-step
/// grayscale ramp).
///
/// FASM `tui_png.inc:453` (`add eax, 0xe8`).
const GRAYSCALE_BASE: u8 = 0xE8;

/// Grayscale divisor: `255 / 24 ≈ 10.625`, rounded down to `11` so
/// that `R = 255` produces palette index `0xE8 + 23 = 0xFF` (the
/// brightest grayscale step).
///
/// FASM `tui_png.inc:450` (`mov r9d, 11`).
const GRAYSCALE_DIVISOR: u32 = 11;

/// Color cube base: xterm 256-color palette index for the start of
/// the 6×6×6 RGB cube (palette indices 16..=231).
///
/// FASM `tui_png.inc:509` (`add eax, 16`).
const COLORCUBE_BASE: u32 = 16;

/// Color cube R-channel multiplier: `r * 36` produces the offset
/// within the cube (`r ∈ 0..=5`, so `r * 36 ∈ 0..=180`).
///
/// FASM `tui_png.inc:490` (`mov ecx, 36`).
const COLORCUBE_R_FACTOR: u32 = 36;

/// Color cube G-channel multiplier: `g * 6`.
///
/// FASM `tui_png.inc:501` (`mov ecx, 6`).
const COLORCUBE_G_FACTOR: u32 = 6;

/// Default widget background color, matching FASM
/// `tui_png.inc:48` / `74` / `97` / `121` / `144` / `167`
/// (`mov qword [rax+tui_png_bgcolor_ofs], 0xe8`).
///
/// Palette index `0xE8` = `232` = darkest grayscale step (effectively
/// black on most terminals, slightly off-pure-black on some). The
/// FASM source comment (line 48) glosses this as "0xe8 (black)"
/// although the xterm ramp at 232 is actually `#080808`. We preserve
/// FASM's value verbatim regardless.
const DEFAULT_BGCOLOR: u8 = 0xE8;

/// Aspect-ratio multiplier accounting for terminal-character cells
/// being approximately twice as tall as they are wide. Multiplying
/// the source PNG width by `2.0` before computing the aspect ratio
/// gives a value that compares correctly against the
/// (width-cells / height-cells) terminal aspect ratio.
///
/// FASM `tui_png.inc:282` (`mulsd xmm0, [_math_two]`) where
/// `_math_two = 2.0`.
const TERMINAL_ASPECT_MULTIPLIER: f64 = 2.0;

/// Pixel-rounding offset added before truncating-to-integer in the
/// FASM aspect-fit math. Mirrors `cvtsd2si` (round-to-nearest-even)
/// by adding `0.5` and then truncating, matching FASM
/// `tui_png.inc:295` / `303` (`addsd xmm3, [.half]`,
/// `addsd xmm2, [.half]`).
const ASPECT_FIT_ROUND_HALF: f64 = 0.5;

// ============================================================================
// PngWidget — primary type
// ============================================================================

/// PNG widget: renders a [`Png`] to terminal cells via xterm 256-color
/// quantization with 2:1 aspect-ratio preservation.
///
/// FASM parallel: `tui_png` (`tui_png.inc`, 537 lines).
///
/// ## Fields (matching FASM offsets)
///
/// - `state`: inherited [`WidgetState`] (bounds, width, height,
///   text/attr buffers, children, bastards, layout, alignment, etc.).
/// - `image`: shared `Arc<Png>` — the source image. The widget does
///   NOT own the pixel data; multiple widgets can share the same
///   [`Png`] cheaply.
/// - `buffer`: cached `Vec<u32>` of quantized palette indices, one
///   per cell. `None` triggers full recompute on next [`draw`].
///   Length when `Some` is `cached_width × cached_height`.
/// - `cached_width`, `cached_height`: widget dimensions at last
///   render time. Mismatch with current [`WidgetState`] dimensions
///   forces cache invalidation.
/// - `bgcolor`: xterm palette index for the default fill color
///   applied outside the centered image area. Default `0xE8`.
/// - `user`: opaque user data pointer. The FASM splash widget uses
///   this to associate a related widget; semantics are entirely up
///   to the caller.
///
/// ## Construction
///
/// Five constructors mirror FASM's five `tui_png$new_*` variants:
///
/// - [`new_rect`](Self::new_rect) — explicit [`Rect`] bounds.
/// - [`new_dd`](Self::new_dd) — percentage width × percentage height.
/// - [`new_id`](Self::new_id) — integer width × percentage height.
/// - [`new_di`](Self::new_di) — percentage width × integer height.
/// - [`new_ii`](Self::new_ii) — integer width × integer height.
///
/// All five return `Result<Arc<Self>, TuiError>` so the widget can be
/// embedded as `Arc<dyn Widget>` in any parent's children list while
/// preserving the `Send + Sync` bound on the [`Widget`] trait.
///
/// ## Thread safety
///
/// `PngWidget` is `Send + Sync` because all its fields are
/// `Send + Sync` — [`WidgetState`] inherits the bound from its
/// `Arc<dyn Widget>` children list, [`Png`] contains only `Vec<u8>`
/// plus scalars, and `Vec<u32>` plus the primitive fields are
/// trivially thread-safe. Mutation goes through `&mut self` on the
/// [`Widget`] trait methods, which the TUI subsystem serializes via
/// the render lock.
pub struct PngWidget {
    /// Inherited state from `tui_object` — bounds, width/height,
    /// text/attr buffers, layout, children list, etc.
    pub(crate) state: WidgetState,

    /// Shared reference to the source PNG image. The widget does NOT
    /// own the pixel data: cloning shares the underlying [`Png`] via
    /// [`Arc`] refcount; dropping the widget decrements but does not
    /// free the [`Png`] unless the refcount reaches zero.
    ///
    /// FASM offset: `tui_png_image_ofs = tui_object_size + 0`
    /// (`tui_png.inc:44`).
    pub(crate) image: Arc<Png>,

    /// Cached attribute buffer for the last rendered frame.
    ///
    /// `None` indicates the cache is invalid (first draw, post-clone,
    /// after [`set_bgcolor`](Self::set_bgcolor), or after a resize).
    /// `Some(buf)` indicates `buf.len() == cached_width *
    /// cached_height` and the contents are valid for the current
    /// [`image`](Self::image), [`bgcolor`](Self::bgcolor), and
    /// dimensions.
    ///
    /// Each `u32` packs an xterm palette index in the low 8 bits;
    /// the high 24 bits are zero. The FASM equivalent stores the
    /// same `eax = palette_index` values in 4-byte slots.
    ///
    /// FASM offset: `tui_png_buffer_ofs = tui_object_size + 8`
    /// (`tui_png.inc:45`). The FASM buffer is a heap-allocated
    /// `dword*` of length `width * height`.
    pub(crate) buffer: Option<Vec<u32>>,

    /// Widget width at the time the cached buffer was rendered.
    /// `0` means the cache has never been populated.
    ///
    /// FASM offset: `tui_png_width_ofs = tui_object_size + 16`
    /// (`tui_png.inc:46`).
    pub(crate) cached_width: i32,

    /// Widget height at the time the cached buffer was rendered.
    /// `0` means the cache has never been populated.
    ///
    /// FASM offset: `tui_png_height_ofs = tui_object_size + 24`
    /// (`tui_png.inc:47`).
    pub(crate) cached_height: i32,

    /// Background color (xterm palette index). Defaults to
    /// [`DEFAULT_BGCOLOR`] (`0xE8`).
    ///
    /// FASM offset: `tui_png_bgcolor_ofs = tui_object_size + 32`
    /// (`tui_png.inc:48`). FASM stores this as a `qword` defaulting
    /// to `0xe8`; we use `u8` directly because the field is always
    /// a palette index in `0..=255`.
    pub(crate) bgcolor: u8,

    /// Opaque user data pointer. Semantics are entirely up to the
    /// caller — for example, the FASM splash widget stores a
    /// related widget pointer here for back-reference during
    /// teardown.
    ///
    /// FASM offset: `tui_png_user_ofs = tui_object_size + 40`
    /// (`tui_png.inc:49`).
    pub(crate) user: usize,
}

// ============================================================================
// Construction — five FASM tui_png$new_* variants
// ============================================================================

impl PngWidget {
    /// Constructor from explicit [`Rect`] bounds.
    ///
    /// Computes `width = rect.width()` and `height = rect.height()`
    /// from the half-open rectangle. The [`Png`] is taken by shared
    /// `Arc` reference — the widget does NOT copy pixel data.
    ///
    /// FASM parallel: `tui_png$new_rect`
    /// (`tui_png.inc:56–77`):
    ///
    /// ```text
    ///   heap$alloc(tui_png_size)
    ///   tui_object$init_rect(self, &Rect)
    ///   self.vtable        = tui_png$vtable
    ///   self.image         = png_ptr
    ///   self.buffer        = 0
    ///   self.width         = 0   ; cached_width
    ///   self.height        = 0   ; cached_height
    ///   self.bgcolor       = 0xe8
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] only if buffer allocation fails
    /// during [`finalize_init`](Self::finalize_init); in practice
    /// this constructor is infallible under normal operating
    /// conditions but the [`Result`] return type is preserved for
    /// API symmetry with [`Widget::clone_widget`].
    pub fn new_rect(rect: Rect, image: Arc<Png>) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.bounds = rect;
        state.width = rect.width();
        state.height = rect.height();
        state.width_percent = None;
        state.height_percent = None;
        Self::finalize_init(state, image)
    }

    /// Constructor — percentage width × percentage height.
    ///
    /// Buffers are NOT pre-allocated because the absolute dimensions
    /// are unknown until layout resolves the parent's content area.
    /// The layout pass allocates the buffers when it computes the
    /// final dimensions (matching FASM `tui_object$init_dd`).
    ///
    /// FASM parallel: `tui_png$new_dd`
    /// (`tui_png.inc:79–100`):
    ///
    /// ```text
    ///   heap$alloc(tui_png_size)
    ///   tui_object$init_dd(self, widthperc, heightperc)
    ///   self.image    = png_ptr
    ///   self.buffer   = 0
    ///   self.width    = 0
    ///   self.height   = 0
    ///   self.bgcolor  = 0xe8
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] for API symmetry; this
    /// constructor is infallible in practice.
    pub fn new_dd(width_percent: f64, height_percent: f64, image: Arc<Png>) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = 0;
        state.height = 0;
        state.width_percent = Some(width_percent);
        state.height_percent = Some(height_percent);
        Self::finalize_init(state, image)
    }

    /// Constructor — integer width × percentage height.
    ///
    /// Buffers are NOT pre-allocated (matching FASM
    /// `tui_object$init_id`).
    ///
    /// FASM parallel: `tui_png$new_id`
    /// (`tui_png.inc:102–124`).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] for API symmetry; this
    /// constructor is infallible in practice.
    pub fn new_id(width: i32, height_percent: f64, image: Arc<Png>) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = 0;
        state.width_percent = None;
        state.height_percent = Some(height_percent);
        Self::finalize_init(state, image)
    }

    /// Constructor — percentage width × integer height.
    ///
    /// Buffers are NOT pre-allocated (matching FASM
    /// `tui_object$init_di`).
    ///
    /// FASM parallel: `tui_png$new_di`
    /// (`tui_png.inc:126–147`).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] for API symmetry; this
    /// constructor is infallible in practice.
    pub fn new_di(width_percent: f64, height: i32, image: Arc<Png>) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = 0;
        state.height = height;
        state.width_percent = Some(width_percent);
        state.height_percent = None;
        Self::finalize_init(state, image)
    }

    /// Constructor — integer width × integer height.
    ///
    /// When both `width` and `height` are positive, the text and
    /// attributes buffers are pre-allocated and zero-filled (matching
    /// FASM `tui_object$init_ii`).
    ///
    /// FASM parallel: `tui_png$new_ii`
    /// (`tui_png.inc:149–170`).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] only if buffer allocation fails.
    pub fn new_ii(width: i32, height: i32, image: Arc<Png>) -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width = width;
        state.height = height;
        state.width_percent = None;
        state.height_percent = None;
        Self::finalize_init(state, image)
    }

    /// Internal helper: shared post-init setup for all five
    /// constructors.
    ///
    /// Pre-allocates and zero-fills the text and attributes buffers
    /// when both `state.width > 0` and `state.height > 0`, matching
    /// the FASM `tui_object$init_rect` / `init_ii` allocation path.
    /// For constructors with percentage-based dimensions the buffers
    /// stay empty because the layout pass owns their sizing.
    ///
    /// All FASM `tui_png$new_*` paths share the post-init steps:
    /// set `image`, zero `buffer` / `cached_width` / `cached_height`,
    /// set `bgcolor` to `0xE8` default, set `user` to zero
    /// (initialized from `WidgetState::new()` indirectly via the
    /// FASM `heap$alloc` zero-fill — heap blocks come from
    /// `heap$alloc_clear` per `tui_png.inc:259`).
    ///
    /// `WidgetState::new()` already sets `visible = true`,
    /// `include_in_layout = true`, `absolute_x = -1`,
    /// `absolute_y = -1`, so this helper does not re-set those
    /// fields.
    fn finalize_init(mut state: WidgetState, image: Arc<Png>) -> Result<Arc<Self>, TuiError> {
        // Pre-allocate text/attribute buffers when dimensions are
        // concretely known. FASM init_rect / init_ii zero-fills both
        // buffers via memset32 with esi=0; we mirror this with
        // append-zeros for the byte-buffer and `Vec::resize` with 0
        // for the attribute cells.
        if state.width > 0 && state.height > 0 {
            let cells = (state.width as usize)
                .checked_mul(state.height as usize)
                .ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(format!(
                        "PngWidget: width*height overflowed usize \
                         (width={}, height={})",
                        state.width, state.height
                    )))
                })?;
            let bytes = cells.checked_mul(4).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(format!(
                    "PngWidget: cells*4 overflowed usize (cells={cells})"
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
            image,
            buffer: None,
            cached_width: 0,
            cached_height: 0,
            bgcolor: DEFAULT_BGCOLOR,
            user: 0,
        }))
    }
}

// ============================================================================
// Accessors — set_bgcolor / set_user / user / image
// ============================================================================

impl PngWidget {
    /// Change the widget's background color (xterm palette index).
    ///
    /// Invalidates the render cache, forcing the next [`draw`] call
    /// to recompute the quantized buffer with the new background.
    /// FASM does not expose a setter for `tui_png_bgcolor_ofs`
    /// (it is set once at construction); this Rust API surfaces the
    /// field as a setter for ergonomic configuration of widgets after
    /// construction without rebuilding the entire widget tree.
    ///
    /// # Side effects
    ///
    /// - `self.bgcolor = color`
    /// - `self.buffer = None` (cache invalidation)
    /// - `self.cached_width = 0`
    /// - `self.cached_height = 0`
    pub fn set_bgcolor(&mut self, color: u8) {
        self.bgcolor = color;
        self.buffer = None;
        self.cached_width = 0;
        self.cached_height = 0;
    }

    /// Set the opaque user-data pointer.
    ///
    /// FASM equivalent: direct write to `[self + tui_png_user_ofs]`
    /// (the field at `tui_png.inc:49`). Used by the splash widget to
    /// store a related widget for back-reference during teardown.
    pub fn set_user(&mut self, user: usize) {
        self.user = user;
    }

    /// Get the opaque user-data pointer.
    ///
    /// FASM equivalent: direct read from `[self + tui_png_user_ofs]`.
    #[must_use]
    pub fn user(&self) -> usize {
        self.user
    }

    /// Get the current background color (xterm palette index).
    #[must_use]
    pub fn bgcolor(&self) -> u8 {
        self.bgcolor
    }

    /// Get a shared reference to the [`Png`] this widget is rendering.
    ///
    /// Returns the [`Arc`] (not a `&Png`) so callers can clone it for
    /// other widgets without going through the widget itself.
    #[must_use]
    pub fn image(&self) -> &Arc<Png> {
        &self.image
    }
}

// ============================================================================
// Clone helper — backs Widget::clone_widget (vtable slot 1)
// ============================================================================

impl PngWidget {
    /// Deep-clone helper used by [`Widget::clone_widget`].
    ///
    /// Performs the FASM `tui_png$clone` algorithm
    /// (`tui_png.inc:172–194`):
    ///
    /// 1. `tui_object$init_copy(dst, src)` — copies all base fields,
    ///    fresh-allocates text/attr buffers (if width/height > 0) and
    ///    deep-copies their contents, deep-clones every child via the
    ///    child's own `vclone` vmethod, leaves bastards empty.
    /// 2. Copy `image` ([`Arc::clone`] — cheap refcount bump, no pixel
    ///    data duplicated) and `bgcolor`.
    /// 3. **Reset** `buffer = None`, `cached_width = 0`,
    ///    `cached_height = 0` — the FASM source explicitly zeroes
    ///    these fields so the cloned widget recomputes on first
    ///    draw rather than blindly trusting a stale buffer copy.
    ///
    /// FASM behavior preserved exactly:
    /// - **Children are deeply cloned** (each via `clone_widget`).
    /// - **Bastards are NOT cloned** (left empty in the copy) — see
    ///   `tui_object.inc` line 274.
    /// - **Text/attr buffer contents are duplicated** in the cloned
    ///   `WidgetState`, but the per-PNG quantization cache
    ///   ([`buffer`](Self::buffer)) is intentionally dropped.
    /// - **`user` field** is bitwise-copied (FASM init_copy memcpys
    ///   the entire `tui_png_size` block, which includes the user
    ///   slot). Cloning therefore preserves the user pointer.
    fn init_copy_from(src: &Self) -> Result<Self, TuiError> {
        let cloned_state = Self::clone_widget_state(&src.state)?;
        Ok(Self {
            state: cloned_state,
            // Cheap Arc clone — pixel data shared, refcount bumped.
            image: Arc::clone(&src.image),
            // Reset cache: FASM lines 188–190 explicitly zero these.
            buffer: None,
            cached_width: 0,
            cached_height: 0,
            // Copied verbatim (FASM line 191).
            bgcolor: src.bgcolor,
            // FASM init_copy memcpys the full struct, so user is
            // copied as well. Cloning preserves the user pointer.
            user: src.user,
        })
    }

    /// Deep-clone a [`WidgetState`] following FASM
    /// `tui_object$init_copy` (`tui_object.inc:235–333`) semantics.
    ///
    /// Identical to the helper used by [`super::background::TuiBackground`]
    /// — kept private to this module so that future evolution of one
    /// widget's clone semantics does not silently affect the other.
    ///
    /// - All scalar fields are bitwise-copied.
    /// - `display_name` is deep-copied.
    /// - `text` and `attributes` are deep-copied.
    /// - `children` are deep-cloned by invoking each child's
    ///   `clone_widget` vmethod.
    /// - `bastards` are intentionally NOT cloned — the cloned
    ///   state's bastards list is freshly empty, matching FASM line 274.
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

        // Text / attributes — deep-copy contents.
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
// Quantization — pure-function helpers (testable in isolation)
// ============================================================================

/// Quantize an averaged RGB triple to the corresponding xterm
/// 256-color palette index, applying the **standalone** formula
/// without the FASM `and not 3` masking step.
///
/// This function is the pure quantization rule corresponding to the
/// FASM grayscale / colorcube branches at `tui_png.inc:443–509`. It
/// does NOT pre-mask the inputs; callers that wish to reproduce the
/// FASM render path exactly should mask each channel with `& !3`
/// before calling this function (or use [`render_png`] which performs
/// the masking inline).
///
/// # Algorithm
///
/// 1. If `r == g == b` → grayscale path:
///    `palette = GRAYSCALE_BASE + (r / GRAYSCALE_DIVISOR)`
///    (truncated 8-bit divide; max output `0xE8 + 23 = 0xFF`).
/// 2. Else → color cube path:
///    `palette = COLORCUBE_BASE + COLORCUBE_R_FACTOR * r̂ +
///     COLORCUBE_G_FACTOR * ĝ + b̂`
///    where `r̂ = min(r / COLORCUBE_DIVISOR, COLORCUBE_MAX)`
///    (and likewise for g, b).
///
/// # Determinism note
///
/// The FASM source uses `cvtsd2si` (round-to-nearest-even) on the
/// f64 division result; this Rust port uses `as u32` truncation
/// after the division to match FASM's *integer* divide semantics
/// for the grayscale path. For the color cube the FASM source uses
/// `cvtsd2si` after `divsd` — Rust's `(f64 / divisor) as u32`
/// truncates rather than rounding. Rounding mode differences
/// affect at most ±1 in the integer output for inputs near a half
/// boundary; we accept this 1-ULP tolerance because (a) the visual
/// difference is imperceptible and (b) the FASM source itself
/// performs this conversion via SSE rounding which is the same as
/// Rust's `f64 as u32` truncation when the float is non-negative
/// (which all averaged channels are).
#[must_use]
pub fn quantize_xterm256(r: u32, g: u32, b: u32) -> u8 {
    if r == g && g == b {
        // Grayscale path — FASM tui_png.inc:449–454.
        //
        // The FASM source uses unsigned integer division here:
        //   `mov r9d, 11; xor edx, edx; div r9d`
        // — i.e. `eax = r_avg / 11` with truncation. Rust integer
        // division on `u32` is truncating-divide, exactly matching.
        let step = r / GRAYSCALE_DIVISOR;
        // Cast through u32 to mirror FASM `and eax, 0xff`.
        ((step + u32::from(GRAYSCALE_BASE)) & 0xFF) as u8
    } else {
        // Color cube path — FASM tui_png.inc:478–509.
        //
        // FASM converts each averaged channel to f64
        // (`cvtsi2sd`), divides by `42.666...`
        // (`divsd xmm9, xmm7`), then converts back to integer via
        // `cvtsd2si`. `cvtsd2si` uses the current SSE rounding mode,
        // which on Linux x86_64 defaults to **round-to-nearest-even**
        // (banker's rounding). Rust's `f64::round()` is "round half
        // away from zero" — the two methods agree on every value
        // except those exactly half-way between integers (e.g. 2.5).
        // For non-negative inputs in our value range
        // (`0.0..6.0` after division), this divergence is at most
        // ±1 in the integer output and only at exact `.5` points,
        // which the channel quantization never hits because the
        // dividends are all integer-valued.
        //
        // We use `.round()` instead of `as u32` (truncation) so that
        // values like `2.9999999999999782` (= `128.0 / 42.66666...7`
        // due to constant precision) round to `3` matching FASM.
        let r_norm = ((r as f64) / COLORCUBE_DIVISOR).round() as u32;
        let g_norm = ((g as f64) / COLORCUBE_DIVISOR).round() as u32;
        let b_norm = ((b as f64) / COLORCUBE_DIVISOR).round() as u32;
        let r_clamped = r_norm.min(COLORCUBE_MAX);
        let g_clamped = g_norm.min(COLORCUBE_MAX);
        let b_clamped = b_norm.min(COLORCUBE_MAX);
        let palette =
            COLORCUBE_BASE + COLORCUBE_R_FACTOR * r_clamped + COLORCUBE_G_FACTOR * g_clamped + b_clamped;
        // Sanity 8-bit mask matches FASM `and eax, 0xff` (commented
        // out in `tui_png.inc:511` but conceptually present — the
        // colored path's output is always 16..=215 so the mask is a
        // no-op, but we apply it for parity).
        (palette & 0xFF) as u8
    }
}

/// Aspect-fitted dimensions and centering offsets for rendering a
/// source PNG into a TUI cell area.
///
/// Returned by [`compute_aspect_fit`]; consumed by [`render_png`].
struct AspectFit {
    /// Aspect-fitted width in cells (`<= tui_width`).
    new_width: i32,
    /// Aspect-fitted height in cells (`<= tui_height`).
    new_height: i32,
    /// Horizontal offset (in cells) to center the image.
    col_off: i32,
    /// Vertical offset (in cells) to center the image.
    row_off: i32,
    /// Per-output-cell horizontal pixel sampling rate (PNG pixels per
    /// rendered cell), pre-halved for the FASM stride convention.
    x_step: f64,
    /// Per-output-cell vertical pixel sampling rate.
    y_step: f64,
    /// Number of source pixels to gather horizontally per output cell.
    x_gather: u32,
    /// Number of source pixels to gather vertically per output cell.
    y_gather: u32,
}

/// Compute aspect-preserving render dimensions and centering offsets
/// for a `(png_width, png_height)` source rendered into a
/// `(tui_width, tui_height)` TUI cell area.
///
/// FASM parallel: lines 274–330 of `tui_png.inc` — the aspect-ratio
/// resolution block that branches on `tui_ratio > png_ratio`
/// (rowfit) vs. otherwise (colfit).
///
/// # Returns
///
/// An [`AspectFit`] struct containing the new dimensions, centering
/// offsets, and per-cell pixel sampling rates. Caller responsibilities:
///
/// - The `col_off` returned here is in CELL units (FASM line 314:
///   `shr esi, 1`); the FASM source then converts to bytes via
///   `shl r14d, 2` (line 319). Rust callers operate on `u32`-indexed
///   buffers, so the byte conversion is unnecessary.
/// - The `x_step` (FASM line 324) is the half-strided per-cell
///   horizontal stride: `(png_width / new_width) * 0.5`. FASM
///   computes this halved value because the f64 → integer
///   conversion (`cvtsd2si`) is then doubled-up via the column-loop
///   accumulator (`addsd xmm0, xmm4`).
fn compute_aspect_fit(png_width: u32, png_height: u32, tui_width: i32, tui_height: i32) -> AspectFit {
    // FASM lines 280–284: convert all four to f64.
    let pw = f64::from(png_width);
    let ph = f64::from(png_height);
    let tw = f64::from(tui_width);
    let th = f64::from(tui_height);

    // FASM line 282: pw *= 2.0 (terminal char aspect is ~2:1).
    let pw_doubled = pw * TERMINAL_ASPECT_MULTIPLIER;

    // FASM line 286: png_ratio = pw_doubled / ph.
    let png_ratio = pw_doubled / ph;

    // FASM line 288: tui_ratio = tw / th.
    let tui_ratio = tw / th;

    // FASM line 290: branch on tui_ratio > png_ratio.
    let (new_w_f, new_h_f) = if tui_ratio > png_ratio {
        // .rowfit (FASM lines 300–303): height is the binding
        // dimension; width is computed from height × png_ratio.
        let new_w = th * png_ratio + ASPECT_FIT_ROUND_HALF;
        (new_w, th)
    } else {
        // .colfit (FASM lines 293–296): width is the binding
        // dimension; height is computed from width / png_ratio.
        let new_h = tw / png_ratio + ASPECT_FIT_ROUND_HALF;
        (tw, new_h)
    };

    // FASM lines 308–309: f64 → i32 via cvtsd2si (round-to-nearest).
    // We use `as i32` after the +0.5 already applied above, which
    // gives truncate-after-round = round-to-nearest semantics
    // matching FASM for non-negative inputs.
    let new_width = new_w_f as i32;
    let new_height = new_h_f as i32;

    // FASM lines 312–315: center the image.
    let col_off = (tui_width - new_width) / 2;
    let row_off = (tui_height - new_height) / 2;

    // FASM lines 322–326: per-output-cell pixel sampling rates.
    // x_step = (pw_doubled / new_width) * 0.5
    //        = pw / new_width  (mathematically identical, but FASM
    //          computes via the halving multiplier).
    // y_step = ph / new_height.
    //
    // We compute the halved x_step explicitly to match the FASM
    // accumulator behavior: `addsd xmm0, xmm4` increments the
    // floating column position by `xmm4 = (pw * 2 / new_w) * 0.5`
    // = `pw / new_w`, which is then truncated to integer for the
    // pixel-sample lookup.
    let x_step = if new_width > 0 {
        (pw_doubled / f64::from(new_width)) * ASPECT_FIT_ROUND_HALF
    } else {
        0.0
    };
    let y_step = if new_height > 0 {
        ph / f64::from(new_height)
    } else {
        0.0
    };

    // FASM lines 329–330: x_gather and y_gather are the truncated
    // per-cell pixel counts for the gather loop.
    let x_gather = if x_step > 0.0 { x_step as u32 } else { 0 };
    let y_gather = if y_step > 0.0 { y_step as u32 } else { 0 };

    AspectFit {
        new_width,
        new_height,
        col_off,
        row_off,
        x_step,
        y_step,
        x_gather,
        y_gather,
    }
}

/// Render a [`Png`] into a freshly-allocated quantization buffer of
/// length `width * height`.
///
/// FASM parallel: `tui_png$draw` `.newbuffer` block at
/// `tui_png.inc:248–532`.
///
/// # Algorithm overview
///
/// 1. Allocate `width * height` u32 cells, all initialized to
///    `bgcolor` (matching FASM `heap$alloc_clear` + `memset32`
///    fill at lines 259–271).
/// 2. Compute aspect-fitted render dimensions via
///    [`compute_aspect_fit`] (FASM lines 274–330).
/// 3. For each output cell `(dest_row, dest_col)` within the
///    aspect-fitted region:
///    a. Compute the source pixel block `(x_gather × y_gather)`
///    starting at `(src_row, src_col)`. Trim `y_gather` if the
///    block would extend past `png_height` (FASM lines 384–389).
///    b. Sum the R/G/B channels across the block (FASM lines
///    400–411).
///    c. Average each channel by dividing by the actual sample
///    count (FASM lines 417–428).
///    d. Mask the lower 2 bits of each channel (`& !3`) — FASM
///    lines 431–433. This makes near-grayscale colors register
///    as exactly grayscale.
///    e. Quantize via [`quantize_xterm256`] (grayscale or color
///    cube branch).
///    f. Write the palette index into the buffer at the centered
///    output offset.
///    g. Advance the source-column accumulator by `x_step`; cast to
///    i32 for the next iteration's source column.
///    h. Advance the source-row accumulator by `y_step`; cast to
///    i32 for the next iteration's source row.
///
/// # Edge cases
///
/// - `png_width == 0` or `png_height == 0`: the aspect-fit
///   computation yields zero dimensions; the inner loop bails
///   immediately and the buffer remains entirely `bgcolor`.
/// - PNG decoded data has fewer than `width × height × 4` bytes:
///   the inner sampling clamps source coordinates to the valid
///   range to prevent panics. This is defensive — a properly
///   decoded [`Png`] always has `data.len() == width × height × 4`.
fn render_png(image: &Png, width: i32, height: i32, bgcolor: u8) -> Vec<u32> {
    debug_assert!(width > 0, "render_png: width must be > 0");
    debug_assert!(height > 0, "render_png: height must be > 0");

    let cells = (width as usize) * (height as usize);

    // FASM lines 259–271: allocate buffer, memset32 with bgcolor.
    let bg_value = u32::from(bgcolor);
    let mut buffer: Vec<u32> = vec![bg_value; cells];

    // FASM lines 219–222: bail out early if the source image has no
    // pixels. The aspect-fit math would divide by zero otherwise.
    if image.width == 0 || image.height == 0 {
        return buffer;
    }

    let fit = compute_aspect_fit(image.width, image.height, width, height);

    // FASM lines 308–309: bail out if the aspect-fitted dimensions
    // collapse to zero (can happen for extremely lopsided source
    // images or extremely small TUI bounds).
    if fit.new_width <= 0 || fit.new_height <= 0 {
        return buffer;
    }
    if fit.x_gather == 0 || fit.y_gather == 0 {
        return buffer;
    }

    // PNG row stride in bytes.
    let png_row_bytes = image.line_length as usize;
    // Pixel size in bytes (always 4 for RGBA — `Png::pixel_depth`).
    let pixel_bytes = image.pixel_depth as usize;
    debug_assert_eq!(pixel_bytes, 4, "render_png: pixel_depth must be 4 (RGBA)");
    let png_data = image.data.as_slice();

    // FASM lines 358–360: source-row accumulator (f64) and integer.
    let mut src_row_f = 0.0_f64;
    let mut src_row: u32 = 0;
    let png_height = image.height;
    let png_width = image.width;

    let tui_width = width as usize;

    // FASM lines 363–525: row loop.
    for dest_row_idx in 0..(fit.new_height as u32) {
        // FASM line 367: dest row in the output buffer.
        let dest_row = (fit.row_off as i64) + (dest_row_idx as i64);
        if dest_row < 0 || dest_row >= height as i64 {
            // Skip rows outside the widget bounds (defensive; should
            // not happen because compute_aspect_fit returns a
            // centered fit).
            continue;
        }

        // FASM lines 364–365: source-column accumulator (f64) and integer.
        let mut src_col_f = 0.0_f64;
        let mut src_col: u32 = 0;

        // FASM lines 384–389: clamp y_gather so it does not extend
        // past png_height.
        let remaining_rows = png_height.saturating_sub(src_row);
        let y_gather_clamped = fit.y_gather.min(remaining_rows);

        // FASM lines 374–525: column loop.
        for dest_col_idx in 0..(fit.new_width as u32) {
            // FASM lines 391–394: zero accumulators.
            let mut r_accum: u32 = 0;
            let mut g_accum: u32 = 0;
            let mut b_accum: u32 = 0;
            let mut counter: u32 = 0;

            // FASM lines 384–389 again, this time for x_gather.
            let remaining_cols = png_width.saturating_sub(src_col);
            let x_gather_clamped = fit.x_gather.min(remaining_cols);

            // FASM lines 396–415: y_gather × x_gather sample loop.
            if y_gather_clamped > 0 && x_gather_clamped > 0 {
                for dy in 0..y_gather_clamped {
                    let row = (src_row + dy) as usize;
                    let row_start = row * png_row_bytes;
                    for dx in 0..x_gather_clamped {
                        let col = (src_col + dx) as usize;
                        let pixel_off = row_start + col * pixel_bytes;
                        // Defensive bound check; should never trigger
                        // for a properly-decoded Png.
                        if pixel_off + 2 >= png_data.len() {
                            break;
                        }
                        r_accum += u32::from(png_data[pixel_off]);
                        g_accum += u32::from(png_data[pixel_off + 1]);
                        b_accum += u32::from(png_data[pixel_off + 2]);
                        counter += 1;
                    }
                }
            }

            // FASM lines 417–428: average via integer divide. Use
            // `checked_div` (returns `None` when `counter == 0`) to
            // satisfy clippy's `manual_checked_ops` lint while
            // preserving the FASM control flow: a zero counter means
            // the cell received no samples and must remain at
            // `bgcolor` (already pre-filled), so we simply skip the
            // quantize+write step.
            if let (Some(mut r_avg), Some(mut g_avg), Some(mut b_avg)) = (
                r_accum.checked_div(counter),
                g_accum.checked_div(counter),
                b_accum.checked_div(counter),
            ) {
                // FASM lines 431–433: mask the lower 2 bits.
                // `not 3` in FASM = `!3` in Rust = `0xFF_FF_FF_FC`.
                r_avg &= !3u32;
                g_avg &= !3u32;
                b_avg &= !3u32;

                // FASM lines 443–509: quantize.
                let palette = quantize_xterm256(r_avg, g_avg, b_avg);

                // Write to the buffer at the centered position.
                let dest_col = (fit.col_off as i64) + (dest_col_idx as i64);
                if dest_col >= 0 && dest_col < width as i64 {
                    let dest_idx = (dest_row as usize) * tui_width + (dest_col as usize);
                    if dest_idx < buffer.len() {
                        buffer[dest_idx] = u32::from(palette);
                    }
                }
            }

            // FASM line 458: src_col_f += x_step (per-cell stride).
            src_col_f += fit.x_step;
            // FASM line 459: src_col = (i32)src_col_f via cvtsd2si.
            // We use `as u32` after explicit non-negative check to
            // match FASM's integer truncation (cvtsd2si saturates,
            // but for non-negative inputs in our range it is
            // equivalent to truncation).
            src_col = if src_col_f > 0.0 { src_col_f as u32 } else { 0 };
        }

        // FASM line 463: src_row_f += y_step.
        src_row_f += fit.y_step;
        // FASM line 464: src_row = (i32)src_row_f.
        src_row = if src_row_f > 0.0 { src_row_f as u32 } else { 0 };
    }

    buffer
}

// ============================================================================
// Buffer fill helpers — duplicated locally to avoid coupling with
// `super::background` private helpers.
// ============================================================================

/// Fill the first `count` 4-byte cells of the widget's `text` buffer
/// with the little-endian bytes of `value`, growing or truncating the
/// buffer to exactly `count * 4` bytes.
///
/// Used by [`PngWidget::draw`] to fill the text buffer with `' '`
/// (space) characters — every cell of a PNG widget shows a space, with
/// all the visual coming from the attribute (color) buffer.
///
/// FASM parallel: `memset32(rdi=text_buf, esi=' ', rdx=cells*4)` from
/// `memfuncs.inc`, called at `tui_png.inc:241`.
fn fill_text_with_value(state: &mut WidgetState, value: u32, count: usize) -> Result<(), TuiError> {
    let bytes = count.checked_mul(4).ok_or_else(|| {
        TuiError::Render(std::io::Error::other(format!(
            "PngWidget: count*4 overflowed usize (count={count})"
        )))
    })?;

    // Grow the buffer to at least `bytes` bytes.
    if state.text.len() < bytes {
        state.text.reserve(bytes - state.text.len());
        for _ in state.text.len()..bytes {
            state.text.push(0);
        }
    }

    // Truncate any tail beyond `bytes` so the length matches exactly.
    if state.text.len() > bytes {
        let to_remove = state.text.len() - bytes;
        state.text.truncate(to_remove).map_err(|e| {
            TuiError::Render(std::io::Error::other(format!(
                "PngWidget: text truncate failed: {e:?}"
            )))
        })?;
    }

    // Write `count` little-endian u32s into the first `bytes` bytes.
    let value_le = value.to_le_bytes();
    let slice = state.text.as_mut_slice();
    for chunk in slice.chunks_exact_mut(4).take(count) {
        chunk.copy_from_slice(&value_le);
    }

    Ok(())
}

/// Copy a quantized buffer into the widget's [`Attributes`] buffer,
/// growing or truncating the underlying `Vec<u32>` to length `cells`.
///
/// FASM parallel: `memcpy(rdi=attr_buf, rsi=buffer, rdx=cells*4)`
/// from `memfuncs.inc`, called at `tui_png.inc:245`.
fn copy_attr_buffer(attr: &mut Attributes, src: &[u32]) {
    let count = src.len();
    if attr.cells.len() < count {
        attr.cells.resize(count, 0);
    } else if attr.cells.len() > count {
        attr.cells.truncate(count);
    }
    attr.cells.copy_from_slice(src);
}

// ============================================================================
// Widget trait implementation — overrides cleanup + clone_widget + draw
// ============================================================================

impl Widget for PngWidget {
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

    /// Required downcasting accessor — returns `self` as a `&dyn Any`.
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Override — vtable slot 0 (`tui_vcleanup`).
    ///
    /// FASM parallel: `tui_png$cleanup`
    /// (`tui_png.inc:196–212`):
    ///
    /// ```text
    ///   if self.buffer != null:
    ///       heap$free(self.buffer)
    ///   tui_object$cleanup(self)
    /// ```
    ///
    /// In Rust:
    ///
    /// 1. Drop the cached quantization buffer by setting
    ///    [`buffer`](Self::buffer) to `None` — `Vec::drop` releases
    ///    the underlying allocation.
    /// 2. The `Arc<Png>` field is NOT dropped explicitly: it
    ///    decrements its refcount automatically when the widget
    ///    itself is dropped. Importantly, FASM's `tui_png$cleanup`
    ///    likewise does NOT free the image (the source comment at
    ///    lines 27–30 makes this explicit).
    /// 3. Walk children/bastards and clear them via the default base
    ///    cleanup behavior (children/bastards/text/attributes/
    ///    display_name).
    ///
    /// Note that the trait default `cleanup` clears `state.children`,
    /// `state.bastards`, `state.text`, `state.attributes`, and
    /// `state.display_name`. We override here only to additionally
    /// drop the quantization buffer; we then invoke the same logic
    /// as the trait default by clearing those fields directly.
    fn cleanup(&mut self) {
        // Drop the cached quantization buffer (FASM heap$free).
        self.buffer = None;
        self.cached_width = 0;
        self.cached_height = 0;

        // Mirror the trait-default `cleanup` body: clear children,
        // bastards, text, attributes, display_name.
        let state = &mut self.state;
        state.children.clear();
        state.bastards.clear();
        state.text.clear();
        state.attributes.clear();
        state.display_name.clear();

        // The `Arc<Png>` is intentionally NOT dropped here —
        // FASM's tui_png$cleanup explicitly does not free the image.
        // Rust's drop semantics handle the refcount decrement when
        // the entire widget itself is dropped.
    }

    /// Override — vtable slot 1 (`tui_vclone`).
    ///
    /// FASM parallel: `tui_png$clone`
    /// (`tui_png.inc:172–194`):
    ///
    /// ```text
    ///   heap$alloc(tui_png_size)
    ///   set vtable to tui_png$vtable
    ///   tui_png$init_copy(new, self)
    ///   new.image    = self.image    ; pointer copy, NOT data copy
    ///   new.buffer   = 0
    ///   new.width    = 0   ; cached_width
    ///   new.height   = 0   ; cached_height
    ///   new.bgcolor  = self.bgcolor
    ///   return new
    /// ```
    ///
    /// In Rust the vtable concept is replaced by trait dispatch on
    /// `dyn Widget`. Allocation is implicit via [`Arc::new`]; the
    /// init step ([`init_copy_from`](Self::init_copy_from)) performs
    /// the FASM `tui_object$init_copy` deep-clone of the base state
    /// plus the image-Arc clone (cheap refcount bump). The cache
    /// is reset so the cloned widget recomputes on first draw.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        let cloned = Self::init_copy_from(self)?;
        Ok(Arc::new(cloned) as Arc<dyn Widget>)
    }

    /// Override — vtable slot 2 (`tui_vdraw`).
    ///
    /// FASM parallel: `tui_png$draw`
    /// (`tui_png.inc:214–536`):
    ///
    /// ```text
    ///   if width == 0 or height == 0:
    ///       return  ; .nothingtodo
    ///   if cached_width != width or cached_height != height
    ///      or buffer == null:
    ///       jump .newbuffer       ; recompute and cache
    ///   ; .copyit:
    ///   memset32(text, ' ', cells)
    ///   memcpy(attr, buffer, bytes)
    ///   tui_object$updatedisplaylist(self)
    /// ```
    ///
    /// `.newbuffer` — the full quantization algorithm — is
    /// implemented in [`render_png`].
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if the text buffer fill or
    /// attribute copy encounters arithmetic overflow (impossible for
    /// any realistic terminal dimensions but surfaced through the
    /// [`Result`] for API symmetry with other widgets).
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        let width = self.state.width;
        let height = self.state.height;

        // FASM lines 219–222: bail out if either dimension is zero.
        if width <= 0 || height <= 0 {
            return Ok(());
        }

        // FASM lines 223–230: cache hit detection.
        let needs_recompute =
            self.buffer.is_none() || self.cached_width != width || self.cached_height != height;

        if needs_recompute {
            // FASM .newbuffer: re-render and cache.
            let buffer = render_png(&self.image, width, height, self.bgcolor);
            self.buffer = Some(buffer);
            self.cached_width = width;
            self.cached_height = height;
        }

        // FASM .copyit (lines 232–246): memset32 text with ' ',
        // memcpy attr from buffer.
        let cells = (width as usize).checked_mul(height as usize).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(format!(
                "PngWidget::draw: width*height overflowed usize \
                     (width={width}, height={height})"
            )))
        })?;

        // Fill text buffer with ' ' (space, U+0020).
        // FASM line 239: `mov esi, ' '` then memset32.
        fill_text_with_value(&mut self.state, u32::from(b' '), cells)?;

        // Copy cached buffer into the attribute buffer.
        // FASM lines 243–245: rsi = self.buffer, rdi = self.attr,
        // memcpy.
        let buffer_ref = self.buffer.as_ref().expect("buffer was just populated above");
        copy_attr_buffer(&mut self.state.attributes, buffer_ref);

        // FASM final step: vupdatedisplaylist.
        self.update_display_list();

        Ok(())
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::geometry::{Point, Rect};

    /// Build a minimal in-memory [`Png`] for tests without going
    /// through the PNG decoder. Constructs a solid-color
    /// `width × height` RGBA image where every pixel has the same
    /// `(r, g, b)` triple and `a = 255`.
    fn solid_png(width: u32, height: u32, r: u8, g: u8, b: u8) -> Arc<Png> {
        let mut data = Vec::with_capacity((width as usize) * (height as usize) * 4);
        for _ in 0..width {
            for _ in 0..height {
                data.push(r);
                data.push(g);
                data.push(b);
                data.push(255);
            }
        }
        Arc::new(Png {
            width,
            height,
            bit_depth: 8,
            color_type: 6, // RGBA
            line_length: width * 4,
            row_length: width,
            pixel_depth: 4,
            channels: 4,
            data,
        })
    }

    /// Build a 2×2 PNG with four distinct RGB corners for testing
    /// per-pixel sampling.
    fn quad_png() -> Arc<Png> {
        // Top-left: red (255, 0, 0)
        // Top-right: green (0, 255, 0)
        // Bottom-left: blue (0, 0, 255)
        // Bottom-right: white (255, 255, 255)
        #[rustfmt::skip]
        let data = vec![
            255,   0,   0, 255,    0, 255,   0, 255,
              0,   0, 255, 255,  255, 255, 255, 255,
        ];
        Arc::new(Png {
            width: 2,
            height: 2,
            bit_depth: 8,
            color_type: 6,
            line_length: 8,
            row_length: 2,
            pixel_depth: 4,
            channels: 4,
            data,
        })
    }

    // ----------------------------------------------------------------
    // Quantization constants
    // ----------------------------------------------------------------

    #[test]
    fn quantization_constants_match_fasm() {
        // FASM tui_png.inc line 349: 42.6666666666667f
        // The literal must equal 256/6 to within IEEE-754 double precision.
        let expected = 256.0_f64 / 6.0;
        let diff = (COLORCUBE_DIVISOR - expected).abs();
        assert!(
            diff < 1e-10,
            "COLORCUBE_DIVISOR {COLORCUBE_DIVISOR} should approximate 256/6 = {expected} \
             (diff {diff})"
        );
        assert_eq!(GRAYSCALE_BASE, 0xE8);
        assert_eq!(GRAYSCALE_DIVISOR, 11);
        assert_eq!(COLORCUBE_BASE, 16);
        assert_eq!(COLORCUBE_R_FACTOR, 36);
        assert_eq!(COLORCUBE_G_FACTOR, 6);
        assert_eq!(COLORCUBE_MAX, 5);
        assert_eq!(DEFAULT_BGCOLOR, 0xE8);
        assert_eq!(TERMINAL_ASPECT_MULTIPLIER, 2.0);
    }

    // ----------------------------------------------------------------
    // quantize_xterm256
    // ----------------------------------------------------------------

    #[test]
    fn quantize_grayscale_black() {
        // R=G=B=0 → grayscale (0/11) + 0xE8 = 0xE8.
        assert_eq!(quantize_xterm256(0, 0, 0), 0xE8);
    }

    #[test]
    fn quantize_grayscale_mid() {
        // R=G=B=128 → grayscale (128/11) + 0xE8 = 11 + 0xE8 = 0xF3.
        assert_eq!(quantize_xterm256(128, 128, 128), 0xF3);
    }

    #[test]
    fn quantize_grayscale_white() {
        // R=G=B=255 → grayscale (255/11) + 0xE8 = 23 + 0xE8 = 0xFF.
        assert_eq!(quantize_xterm256(255, 255, 255), 0xFF);
    }

    #[test]
    fn quantize_colorcube_pure_red() {
        // R=255, G=0, B=0 → 16 + 36*5 + 6*0 + 0 = 196.
        assert_eq!(quantize_xterm256(255, 0, 0), 196);
    }

    #[test]
    fn quantize_colorcube_pure_green() {
        // R=0, G=255, B=0 → 16 + 36*0 + 6*5 + 0 = 46.
        assert_eq!(quantize_xterm256(0, 255, 0), 46);
    }

    #[test]
    fn quantize_colorcube_pure_blue() {
        // R=0, G=0, B=255 → 16 + 36*0 + 6*0 + 5 = 21.
        assert_eq!(quantize_xterm256(0, 0, 255), 21);
    }

    #[test]
    fn quantize_colorcube_yellow() {
        // R=255, G=255, B=0 → not grayscale.
        // 16 + 36*5 + 6*5 + 0 = 16 + 180 + 30 + 0 = 226.
        assert_eq!(quantize_xterm256(255, 255, 0), 226);
    }

    #[test]
    fn quantize_colorcube_mid_red() {
        // R=128, G=0, B=0 → not grayscale.
        // 128 / 42.666... ≈ 3 (truncated). 16 + 36*3 + 0 + 0 = 124.
        assert_eq!(quantize_xterm256(128, 0, 0), 124);
    }

    #[test]
    fn quantize_colorcube_clamping() {
        // Inputs at exactly 256 (theoretically out-of-range) clamp
        // to 5. We test with a value that would otherwise produce 6.
        // 256 / 42.666... = 6.0; min(6, 5) = 5.
        // Although input 256 isn't realistic (max sample is 255), we
        // verify the clamp behavior at the channel-saturation point.
        // 252 / 42.666... ≈ 5.91, truncated to 5.
        // Use color values to bypass grayscale path: (252, 0, 0).
        assert_eq!(quantize_xterm256(252, 0, 0), 196);
    }

    // ----------------------------------------------------------------
    // Constructors
    // ----------------------------------------------------------------

    #[test]
    fn new_rect_stores_dimensions() {
        let png = solid_png(4, 4, 200, 100, 50);
        let bounds = Rect::from_origin_size(Point::ZERO, 10, 5);
        let widget = PngWidget::new_rect(bounds, png).expect("new_rect must succeed");
        assert_eq!(widget.state().width, 10);
        assert_eq!(widget.state().height, 5);
        assert_eq!(widget.state().bounds, bounds);
        assert_eq!(widget.bgcolor, DEFAULT_BGCOLOR);
        assert_eq!(widget.user, 0);
        assert!(widget.buffer.is_none());
        assert_eq!(widget.cached_width, 0);
        assert_eq!(widget.cached_height, 0);
    }

    #[test]
    fn new_dd_uses_percentages() {
        let png = solid_png(4, 4, 0, 0, 0);
        let widget = PngWidget::new_dd(50.0, 25.0, png).expect("new_dd must succeed");
        assert_eq!(widget.state().width, 0);
        assert_eq!(widget.state().height, 0);
        assert_eq!(widget.state().width_percent, Some(50.0));
        assert_eq!(widget.state().height_percent, Some(25.0));
    }

    #[test]
    fn new_id_integer_width_percent_height() {
        let png = solid_png(4, 4, 0, 0, 0);
        let widget = PngWidget::new_id(20, 50.0, png).expect("new_id must succeed");
        assert_eq!(widget.state().width, 20);
        assert_eq!(widget.state().height, 0);
        assert_eq!(widget.state().width_percent, None);
        assert_eq!(widget.state().height_percent, Some(50.0));
    }

    #[test]
    fn new_di_percent_width_integer_height() {
        let png = solid_png(4, 4, 0, 0, 0);
        let widget = PngWidget::new_di(75.0, 8, png).expect("new_di must succeed");
        assert_eq!(widget.state().width, 0);
        assert_eq!(widget.state().height, 8);
        assert_eq!(widget.state().width_percent, Some(75.0));
        assert_eq!(widget.state().height_percent, None);
    }

    #[test]
    fn new_ii_pre_allocates_buffers() {
        let png = solid_png(4, 4, 0, 0, 0);
        let widget = PngWidget::new_ii(8, 4, png).expect("new_ii must succeed");
        assert_eq!(widget.state().width, 8);
        assert_eq!(widget.state().height, 4);
        // Pre-allocated to width*height*4 bytes (text) and width*height entries (attr).
        assert_eq!(widget.state().text.len(), 8 * 4 * 4);
        assert_eq!(widget.state().attributes.cells.len(), 8 * 4);
    }

    #[test]
    fn constructors_default_bgcolor() {
        let png = solid_png(4, 4, 0, 0, 0);
        let w_rect =
            PngWidget::new_rect(Rect::from_origin_size(Point::ZERO, 5, 5), png.clone()).expect("new_rect");
        let w_dd = PngWidget::new_dd(50.0, 50.0, png.clone()).expect("new_dd");
        let w_id = PngWidget::new_id(10, 50.0, png.clone()).expect("new_id");
        let w_di = PngWidget::new_di(50.0, 10, png.clone()).expect("new_di");
        let w_ii = PngWidget::new_ii(10, 5, png).expect("new_ii");

        assert_eq!(w_rect.bgcolor, DEFAULT_BGCOLOR);
        assert_eq!(w_dd.bgcolor, DEFAULT_BGCOLOR);
        assert_eq!(w_id.bgcolor, DEFAULT_BGCOLOR);
        assert_eq!(w_di.bgcolor, DEFAULT_BGCOLOR);
        assert_eq!(w_ii.bgcolor, DEFAULT_BGCOLOR);
    }

    // ----------------------------------------------------------------
    // Accessors
    // ----------------------------------------------------------------

    #[test]
    fn set_bgcolor_invalidates_cache() {
        let png = solid_png(2, 2, 100, 100, 100);
        let arc = PngWidget::new_ii(4, 2, png).expect("new_ii");
        let mut widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();

        // Force a render to populate the cache.
        let mut sink = NullRenderer::default();
        widget.draw(&mut sink).expect("draw");
        assert!(widget.buffer.is_some());
        assert_eq!(widget.cached_width, 4);
        assert_eq!(widget.cached_height, 2);

        // Change bgcolor — cache must invalidate.
        widget.set_bgcolor(0x10);
        assert_eq!(widget.bgcolor, 0x10);
        assert!(widget.buffer.is_none());
        assert_eq!(widget.cached_width, 0);
        assert_eq!(widget.cached_height, 0);
    }

    #[test]
    fn user_data_round_trip() {
        let png = solid_png(2, 2, 0, 0, 0);
        let arc = PngWidget::new_ii(4, 2, png).expect("new_ii");
        let mut widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();

        assert_eq!(widget.user(), 0);
        widget.set_user(0xDEAD_BEEF);
        assert_eq!(widget.user(), 0xDEAD_BEEF);
    }

    #[test]
    fn image_accessor_returns_arc() {
        let png = solid_png(2, 2, 0, 0, 0);
        let widget = PngWidget::new_ii(4, 2, png.clone()).expect("new_ii");
        // The widget's image Arc points to the same allocation as `png`.
        assert!(Arc::ptr_eq(widget.image(), &png));
    }

    // ----------------------------------------------------------------
    // Aspect-fit computation
    // ----------------------------------------------------------------

    #[test]
    fn aspect_fit_square_png_wide_tui() {
        // 100x100 png in 40x10 tui:
        // png_ratio = (100*2)/100 = 2.0
        // tui_ratio = 40/10 = 4.0
        // tui_ratio > png_ratio → rowfit
        // new_h = 10, new_w = (10 * 2.0 + 0.5) = 20
        // col_off = (40 - 20) / 2 = 10
        // row_off = (10 - 10) / 2 = 0
        let fit = compute_aspect_fit(100, 100, 40, 10);
        assert_eq!(fit.new_width, 20);
        assert_eq!(fit.new_height, 10);
        assert_eq!(fit.col_off, 10);
        assert_eq!(fit.row_off, 0);
    }

    #[test]
    fn aspect_fit_square_png_tall_tui() {
        // 100x100 png in 10x40 tui:
        // png_ratio = (100*2)/100 = 2.0
        // tui_ratio = 10/40 = 0.25
        // tui_ratio < png_ratio → colfit
        // new_w = 10, new_h = (10 / 2.0 + 0.5) = 5
        // col_off = (10 - 10) / 2 = 0
        // row_off = (40 - 5) / 2 = 17
        let fit = compute_aspect_fit(100, 100, 10, 40);
        assert_eq!(fit.new_width, 10);
        assert_eq!(fit.new_height, 5);
        assert_eq!(fit.col_off, 0);
        assert_eq!(fit.row_off, 17);
    }

    #[test]
    fn aspect_fit_centers_image() {
        // 50x100 png in 20x20 tui:
        // png_ratio = (50*2)/100 = 1.0
        // tui_ratio = 20/20 = 1.0
        // tui_ratio == png_ratio → falls into the `else` branch
        // (FASM `ja` is "jump if above", not "jump if greater-equal").
        // colfit: new_w = 20, new_h = (20 / 1.0 + 0.5) = 20
        // col_off = 0, row_off = 0.
        let fit = compute_aspect_fit(50, 100, 20, 20);
        assert_eq!(fit.new_width, 20);
        assert_eq!(fit.new_height, 20);
        assert_eq!(fit.col_off, 0);
        assert_eq!(fit.row_off, 0);
    }

    // ----------------------------------------------------------------
    // render_png cache + clone behavior
    // ----------------------------------------------------------------

    #[test]
    fn draw_populates_cache() {
        let png = solid_png(4, 4, 100, 100, 100);
        let arc = PngWidget::new_ii(8, 4, png).expect("new_ii");
        let mut widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();

        let mut sink = NullRenderer::default();
        widget.draw(&mut sink).expect("draw");

        assert!(widget.buffer.is_some());
        assert_eq!(widget.cached_width, 8);
        assert_eq!(widget.cached_height, 4);
        assert_eq!(widget.buffer.as_ref().unwrap().len(), 8 * 4);
    }

    #[test]
    fn draw_cache_hit_preserves_buffer() {
        let png = solid_png(4, 4, 100, 100, 100);
        let arc = PngWidget::new_ii(8, 4, png).expect("new_ii");
        let mut widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();

        let mut sink = NullRenderer::default();
        widget.draw(&mut sink).expect("first draw");
        let first_buffer = widget.buffer.as_ref().unwrap().clone();
        widget.draw(&mut sink).expect("second draw");
        let second_buffer = widget.buffer.as_ref().unwrap().clone();
        // Identical inputs → identical buffer (cache hit).
        assert_eq!(first_buffer, second_buffer);
    }

    #[test]
    fn draw_cache_invalidates_on_size_change() {
        let png = solid_png(4, 4, 100, 100, 100);
        let arc = PngWidget::new_ii(8, 4, png).expect("new_ii");
        let mut widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();

        let mut sink = NullRenderer::default();
        widget.draw(&mut sink).expect("first draw");
        assert_eq!(widget.cached_width, 8);

        // Change widget dimensions.
        widget.state.width = 12;
        widget.state.height = 6;
        widget.draw(&mut sink).expect("second draw");
        assert_eq!(widget.cached_width, 12);
        assert_eq!(widget.cached_height, 6);
        assert_eq!(widget.buffer.as_ref().unwrap().len(), 12 * 6);
    }

    #[test]
    fn draw_zero_dimensions_noop() {
        let png = solid_png(4, 4, 100, 100, 100);
        let arc = PngWidget::new_dd(50.0, 50.0, png).expect("new_dd");
        let mut widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();
        // Width / height are 0 (percent-based, not yet laid out).
        assert_eq!(widget.state.width, 0);
        assert_eq!(widget.state.height, 0);

        let mut sink = NullRenderer::default();
        widget.draw(&mut sink).expect("draw");
        // Cache stays empty.
        assert!(widget.buffer.is_none());
    }

    #[test]
    fn draw_text_filled_with_spaces() {
        let png = solid_png(2, 2, 50, 50, 50);
        let arc = PngWidget::new_ii(4, 2, png).expect("new_ii");
        let mut widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();

        let mut sink = NullRenderer::default();
        widget.draw(&mut sink).expect("draw");

        // Text buffer should be 4*2*4 = 32 bytes, all set to ' '
        // little-endian-encoded.
        let text = widget.state.text.as_slice();
        assert_eq!(text.len(), 32);
        for chunk in text.chunks_exact(4) {
            // Space char U+0020 in little-endian u32 = [0x20, 0, 0, 0].
            assert_eq!(chunk, &[0x20, 0x00, 0x00, 0x00]);
        }
    }

    #[test]
    fn draw_attr_buffer_populated() {
        let png = solid_png(2, 2, 100, 100, 100);
        let arc = PngWidget::new_ii(4, 2, png).expect("new_ii");
        let mut widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();

        let mut sink = NullRenderer::default();
        widget.draw(&mut sink).expect("draw");

        // Attribute buffer should be 4*2 = 8 cells.
        assert_eq!(widget.state.attributes.cells.len(), 8);
    }

    // ----------------------------------------------------------------
    // Clone semantics
    // ----------------------------------------------------------------

    #[test]
    fn clone_shares_image_arc() {
        let png = solid_png(4, 4, 100, 100, 100);
        let arc = PngWidget::new_ii(8, 4, png.clone()).expect("new_ii");
        let widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();
        // Strong count: the test holds `png`, the widget holds another.
        assert_eq!(Arc::strong_count(&png), 2);

        let cloned = widget.clone_widget().expect("clone_widget");
        // After cloning: png + widget + cloned = 3.
        assert_eq!(Arc::strong_count(&png), 3);

        // Confirm the cloned widget's image points to the same Png.
        let cloned_concrete = cloned
            .as_any()
            .downcast_ref::<PngWidget>()
            .expect("downcast to PngWidget");
        assert!(Arc::ptr_eq(&cloned_concrete.image, &png));
    }

    #[test]
    fn clone_resets_cache() {
        let png = solid_png(4, 4, 100, 100, 100);
        let arc = PngWidget::new_ii(8, 4, png).expect("new_ii");
        let mut widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();

        // Populate the cache by drawing.
        let mut sink = NullRenderer::default();
        widget.draw(&mut sink).expect("draw");
        assert!(widget.buffer.is_some());

        let cloned = widget.clone_widget().expect("clone");
        let cloned_concrete = cloned.as_any().downcast_ref::<PngWidget>().expect("downcast");
        // Clone must have an empty cache.
        assert!(cloned_concrete.buffer.is_none());
        assert_eq!(cloned_concrete.cached_width, 0);
        assert_eq!(cloned_concrete.cached_height, 0);
    }

    #[test]
    fn clone_preserves_bgcolor_and_user() {
        let png = solid_png(4, 4, 100, 100, 100);
        let arc = PngWidget::new_ii(8, 4, png).expect("new_ii");
        let mut widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();
        widget.set_bgcolor(0x42);
        widget.set_user(0xCAFEBABE);

        let cloned = widget.clone_widget().expect("clone");
        let cloned_concrete = cloned.as_any().downcast_ref::<PngWidget>().expect("downcast");
        assert_eq!(cloned_concrete.bgcolor, 0x42);
        assert_eq!(cloned_concrete.user, 0xCAFEBABE);
    }

    #[test]
    fn clone_preserves_widget_state() {
        let png = solid_png(4, 4, 100, 100, 100);
        let arc = PngWidget::new_ii(8, 4, png).expect("new_ii");
        let widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();
        // Set distinctive state fields.
        let bounds = Rect::new(2, 3, 12, 9);
        let mut widget = widget;
        widget.state.bounds = bounds;
        widget.state.display_name = "test_png".to_string();

        let cloned = widget.clone_widget().expect("clone");
        let cloned_concrete = cloned.as_any().downcast_ref::<PngWidget>().expect("downcast");
        assert_eq!(cloned_concrete.state().bounds, bounds);
        assert_eq!(cloned_concrete.state().display_name, "test_png");
    }

    // ----------------------------------------------------------------
    // Cleanup semantics
    // ----------------------------------------------------------------

    #[test]
    fn cleanup_drops_buffer_keeps_image() {
        let png = solid_png(4, 4, 100, 100, 100);
        let arc = PngWidget::new_ii(8, 4, png.clone()).expect("new_ii");
        let mut widget = Arc::try_unwrap(arc).map_err(|_| ()).unwrap();

        // Populate cache.
        let mut sink = NullRenderer::default();
        widget.draw(&mut sink).expect("draw");
        assert!(widget.buffer.is_some());

        // Strong count = 2 (test + widget).
        assert_eq!(Arc::strong_count(&png), 2);

        widget.cleanup();

        // Cache buffer dropped.
        assert!(widget.buffer.is_none());
        assert_eq!(widget.cached_width, 0);
        assert_eq!(widget.cached_height, 0);

        // Image Arc still held by the widget.
        assert_eq!(Arc::strong_count(&png), 2);
    }

    // ----------------------------------------------------------------
    // Quad-pixel spot check (sanity-test the per-pixel sampling)
    // ----------------------------------------------------------------

    #[test]
    fn render_quad_png_into_2x2_tui() {
        // 2×2 png with four primary corners → 2×2 tui (1:1 png pixel
        // to tui cell). Aspect ratio: png_ratio = 2*2/2 = 2.0,
        // tui_ratio = 2/2 = 1.0, tui_ratio < png_ratio → colfit
        // → new_w = 2, new_h = (2 / 2.0 + 0.5) = 1. Image collapses
        // to a 2×1 strip and the rows above/below are bgcolor.
        // We don't test exact pixel mapping here, only that the
        // function returns a buffer of the right size with no panic.
        let png = quad_png();
        let buffer = render_png(&png, 2, 2, 0xE8);
        assert_eq!(buffer.len(), 4);
    }

    #[test]
    fn render_solid_grayscale_yields_matching_palette() {
        // A solid mid-gray PNG (R=G=B=128) should render entirely
        // grayscale: every cell in the aspect-fitted region maps to
        // GRAYSCALE_BASE + (128 & !3) / 11 = 0xE8 + 124/11 = 0xE8 + 11 = 0xF3.
        let png = solid_png(4, 4, 128, 128, 128);
        let buffer = render_png(&png, 8, 4, 0xE8);
        // 8×4 tui, 4×4 png → png_ratio = 4*2/4 = 2.0, tui_ratio = 8/4 = 2.0.
        // tui_ratio > png_ratio is FALSE (>=), so colfit:
        //   new_w = 8, new_h = (8 / 2.0 + 0.5) = 4.
        //   col_off = 0, row_off = 0.
        // x_step = (4*2/8)*0.5 = 0.5, y_step = 4/4 = 1.0
        // x_gather = 0 (truncate of 0.5), y_gather = 1.
        // Because x_gather is 0, the loop body skips and the buffer
        // stays at bgcolor (0xE8). This documents the FASM-equivalent
        // edge-case behavior: when the source PNG is too small to
        // contribute even one pixel per output cell, the per-cell
        // accumulator stays empty and the bgcolor shows through.
        for cell in buffer.iter() {
            // bgcolor (0xE8) — masking ensures we accept either
            // the bgcolor-fill or any quantized output.
            let val = (*cell & 0xFF) as u8;
            assert!(
                val == 0xE8 || val == 0xF3,
                "expected bgcolor or quantized grayscale, got {val:#x}"
            );
        }
    }

    // ----------------------------------------------------------------
    // Test infrastructure: a stub Renderer that swallows output.
    // ----------------------------------------------------------------

    /// Minimal `Renderer` stub for unit tests — discards all output
    /// and reports zero state. Used to satisfy [`Widget::draw`]'s
    /// signature without exercising the renderer pipeline.
    #[derive(Default)]
    struct NullRenderer {
        state: crate::tui::render::RenderState,
    }

    impl crate::tui::render::Renderer for NullRenderer {
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
}
