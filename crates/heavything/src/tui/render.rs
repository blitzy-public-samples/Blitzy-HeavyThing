// crates/heavything/src/tui/render.rs — HeavyThing TUI rendering engine.
//
// Rust translation of tui_render.inc (1,782 lines of FASM assembly).
// Defines the Renderer trait and supporting types that mediate between
// widget draw() calls and the concrete terminal / SSH output sinks.
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

//! Rendering engine sitting between [`crate::tui::object`] widgets and a
//! concrete output sink (terminal or SSH channel).
//!
//! The rendering layer was implemented in FASM as `tui_render` — a
//! specialization of the base widget class that added three new virtual
//! methods (`ansioutput`, `newlayoutonresize`, `newwindowsize`) plus the
//! bookkeeping needed to elide redundant cursor moves and colour changes.
//! This module is the Rust port of that layer.
//!
//! A [`Renderer`] accepts ANSI byte sequences from widget `draw` methods
//! and writes them to the underlying sink. Implementations track cursor
//! position, active colours, attributes, and ACS-mode status so that
//! successive render passes produce the minimum necessary output bytes —
//! a performance optimisation the FASM library relies on heavily when
//! painting large panels every 16 ms.
//!
//! Two concrete implementations live downstream:
//!
//! - [`crate::tui::terminal::RawTerminal`] — writes bytes to
//!   `STDOUT_FILENO` via the local terminal driver.
//! - `crate::tui::widgets::ssh::SshRenderer` — sends bytes over an SSH
//!   channel using a `tokio::sync::mpsc::Sender<Bytes>`.
//!
//! This module itself performs **no** direct I/O and contains **zero**
//! `unsafe` blocks; all syscalls happen inside the concrete
//! implementations. Object-safety of the [`Renderer`] trait is
//! preserved so that widget `draw` signatures can take
//! `&mut dyn Renderer`.

use bytes::BufMut;

use crate::config::ACS_LINECHARS;
use crate::ds::Buffer;
use crate::error::TuiError;
use crate::tui::ansi;
use crate::tui::geometry::{Point, Rect};

// ---------------------------------------------------------------------------
// RenderAttr — hand-rolled SGR attribute bitflags.
//
// The FASM library packed attribute state into a byte; we expose a newtype
// over `u32` with associated constants mirroring the SGR codes used by
// `tui_render`. Hand-rolled (rather than via the `bitflags` crate) to keep
// the dependency graph minimal per AAP §0.8.7.
// ---------------------------------------------------------------------------

/// SGR attribute flags tracked by a [`Renderer`].
///
/// Each constant corresponds to a single SGR transition emitted via the
/// matching `ansi::SGR_*` byte constants. The bit layout is internal and
/// not exposed as a public invariant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RenderAttr(u32);

impl RenderAttr {
    /// Empty attribute set — no SGR modifiers active.
    pub const NONE: Self = Self(0);

    /// Bold intensity (SGR 1).
    pub const BOLD: Self = Self(1 << 0);

    /// Dim / faint intensity (SGR 2).
    ///
    /// Shares the SGR 22 "reset intensity" off-code with [`Self::BOLD`];
    /// toggling between bold and dim requires an explicit reset first.
    pub const DIM: Self = Self(1 << 1);

    /// Single underline (SGR 4).
    pub const UNDERLINE: Self = Self(1 << 2);

    /// Reversed foreground/background (SGR 7).
    pub const REVERSE: Self = Self(1 << 3);

    /// Slow blink (SGR 5).
    pub const BLINK: Self = Self(1 << 4);

    /// Returns `true` when every bit set in `other` is also set in `self`.
    ///
    /// `RenderAttr::NONE` is contained by every set, mirroring the
    /// identity behaviour of the empty flag set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns the bitwise union of `self` and `other`.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the set of bits present in `self` but not in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Returns `true` when the flag set has no bits set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

// ---------------------------------------------------------------------------
// RenderState — per-renderer state tracked to elide redundant output.
//
// The FASM `tui_render` struct appended 8 qword fields after the base
// tui_object fields; this Rust struct preserves the same semantic slots:
// cursor position, foreground, background, attributes, ACS-mode flag and
// window bounds. Remaining FASM slots (tui_noupdate, tui_noupdatecount,
// tui_outputbytes, tui_lastrender_*) are renderer-implementation concerns
// kept private to concrete implementations rather than the public trait.
// ---------------------------------------------------------------------------

/// Per-renderer state used to elide redundant cursor moves and colour
/// changes.
///
/// Fields use the 1-indexed ANSI convention: the top-left cell is
/// `(col=1, row=1)`. The default value represents "unknown state" — the
/// first operation after construction always emits its corresponding
/// escape sequence because every initial field disagrees with the first
/// value a widget writes (`fg` / `bg` default to `0`, which matches the
/// terminal's default colour and is therefore also elided on the very
/// first write — but a subsequent differing colour forces a write, which
/// is the only invariant the renderer needs to guarantee correct output).
#[derive(Debug, Clone, Default)]
pub struct RenderState {
    /// Current cursor position as `(col=x, row=y)`, 1-indexed.
    pub cursor: Point,

    /// Current foreground colour (256-colour palette index).
    pub fg: u8,

    /// Current background colour (256-colour palette index).
    pub bg: u8,

    /// Bitflags of currently enabled SGR attributes.
    pub attr: RenderAttr,

    /// `true` when the renderer is currently in VT100 Alternate Character
    /// Set mode (entered via `ESC(0`, exited via `ESC(B`).
    pub acs_active: bool,

    /// Cached window bounds from the most recent resize event.
    ///
    /// Always stored in 1-indexed ANSI coordinates with origin
    /// `Point::new(1, 1)` so that widget layout code can compose
    /// sub-rectangles without having to translate origins.
    pub window: Rect,
}

// ---------------------------------------------------------------------------
// Renderer trait — the object-safe interface concrete sinks implement.
//
// Methods follow the FASM naming convention where practical; default
// implementations perform the redundancy-elision logic described by the
// cursor / colour / attribute caching behaviour in tui_render.inc. Only
// `ansi_output`, `flush`, `state` and `state_mut` are required methods;
// everything else is provided as a default.
// ---------------------------------------------------------------------------

/// Output sink for TUI rendering.
///
/// Widget `draw` methods receive a `&mut dyn Renderer` and invoke its
/// methods to emit ANSI sequences, move the cursor, set colours, and
/// so on. The renderer tracks state internally to elide no-op
/// transitions — this is the `tui_render` layer's main performance
/// optimisation and must be preserved for parity with the FASM build.
///
/// # Required methods
///
/// Concrete implementations must provide:
///
/// - [`Self::ansi_output`] — write raw bytes to the sink
/// - [`Self::flush`] — flush any sink-level buffering
/// - [`Self::state`] / [`Self::state_mut`] — expose the cached
///   [`RenderState`] so the default methods can read & mutate it
///
/// Every other method has a default implementation that composes these
/// four primitives with the [`ansi`] module's formatters. Implementations
/// may override the defaults for protocol-specific optimisations (for
/// example, the SSH renderer may batch output into a single channel
/// message).
///
/// # Object-safety
///
/// All methods take `&mut self` or `&self`, have no generic parameters,
/// and return concrete types, so `&mut dyn Renderer` is valid.
/// `BufferedRenderer` relies on this.
pub trait Renderer: Send {
    /// Emit a raw byte sequence to the underlying sink.
    ///
    /// This is the Rust equivalent of FASM `tui_render$ansioutput`, which
    /// in the assembly library was a `breakpoint` (abstract) base
    /// implementation always overridden by derived classes such as
    /// `tui_terminal` and `tui_ssh_renderer`.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if the underlying sink rejects the
    /// write.
    fn ansi_output(&mut self, bytes: &[u8]) -> Result<(), TuiError>;

    /// Flush any renderer-level buffering down to the sink.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if the underlying sink rejects the
    /// flush.
    fn flush(&mut self) -> Result<(), TuiError>;

    /// Immutable access to the cached render state.
    fn state(&self) -> &RenderState;

    /// Mutable access to the cached render state.
    fn state_mut(&mut self) -> &mut RenderState;

    /// Move the cursor to `(row, col)`, 1-indexed.
    ///
    /// The move is elided when the cursor is already at the requested
    /// position, matching FASM `tui_render$setcursor`'s sentinel-compare
    /// behaviour.
    ///
    /// # Errors
    ///
    /// Propagates any [`TuiError::Render`] from the underlying sink.
    fn move_cursor(&mut self, row: u16, col: u16) -> Result<(), TuiError> {
        // Point uses (x=col, y=row) convention.
        let target = Point::new(i32::from(col), i32::from(row));
        if self.state().cursor == target {
            return Ok(());
        }
        // `ansi::move_cursor_to` writes ~10 bytes maximum for u16 params.
        let mut buf: Vec<u8> = Vec::with_capacity(16);
        ansi::move_cursor_to(&mut (&mut buf) as &mut dyn BufMut, u32::from(row), u32::from(col));
        self.ansi_output(&buf)?;
        self.state_mut().cursor = target;
        Ok(())
    }

    /// Set the 256-colour palette foreground index.
    ///
    /// The write is elided when the requested colour matches the cached
    /// value, mirroring the FASM renderer's colour-diff bookkeeping.
    ///
    /// # Errors
    ///
    /// Propagates any [`TuiError::Render`] from the underlying sink.
    fn set_fg(&mut self, color: u8) -> Result<(), TuiError> {
        if self.state().fg == color {
            return Ok(());
        }
        let mut buf: Vec<u8> = Vec::with_capacity(16);
        ansi::set_fg_256(&mut (&mut buf) as &mut dyn BufMut, color);
        self.ansi_output(&buf)?;
        self.state_mut().fg = color;
        Ok(())
    }

    /// Set the 256-colour palette background index.
    ///
    /// The write is elided when the requested colour matches the cached
    /// value.
    ///
    /// # Errors
    ///
    /// Propagates any [`TuiError::Render`] from the underlying sink.
    fn set_bg(&mut self, color: u8) -> Result<(), TuiError> {
        if self.state().bg == color {
            return Ok(());
        }
        let mut buf: Vec<u8> = Vec::with_capacity(16);
        ansi::set_bg_256(&mut (&mut buf) as &mut dyn BufMut, color);
        self.ansi_output(&buf)?;
        self.state_mut().bg = color;
        Ok(())
    }

    /// Set the SGR attribute bitflags, diffing against the cached value
    /// and emitting only the transitions needed.
    ///
    /// BOLD and DIM share the SGR 22 "reset intensity" off-code, so any
    /// change to either flag causes both to be re-emitted from a clean
    /// state. UNDERLINE / REVERSE / BLINK each have independent on/off
    /// codes and are diffed individually.
    ///
    /// # Errors
    ///
    /// Propagates any [`TuiError::Render`] from the underlying sink.
    fn set_attr(&mut self, attr: RenderAttr) -> Result<(), TuiError> {
        let current = self.state().attr;
        if current == attr {
            return Ok(());
        }
        let to_add = attr.difference(current);
        let to_remove = current.difference(attr);

        // BOLD and DIM share the SGR 22 "reset intensity" off-code.
        // Emit it only when an intensity bit is actually being cleared —
        // in that case we also need to re-assert any intensity bit that
        // remains set in the target `attr`. This matches the FASM
        // renderer's sequencing for intensity transitions.
        let intensity_mask = RenderAttr::BOLD.union(RenderAttr::DIM);
        // `to_remove intersects intensity_mask` — true iff any intensity
        // bit is being cleared in this transition.
        let removing_intensity = (to_remove.0 & intensity_mask.0) != 0;

        if removing_intensity {
            // Reset intensity (clears both BOLD and DIM), then
            // re-assert whichever intensity bits are set in `attr`.
            self.ansi_output(ansi::SGR_BOLD_OFF)?;
            if attr.contains(RenderAttr::BOLD) {
                self.ansi_output(ansi::SGR_BOLD)?;
            }
            if attr.contains(RenderAttr::DIM) {
                self.ansi_output(ansi::SGR_DIM)?;
            }
        } else {
            // No intensity bit is being removed; we can just add any
            // newly-enabled intensity bits directly.
            if to_add.contains(RenderAttr::BOLD) {
                self.ansi_output(ansi::SGR_BOLD)?;
            }
            if to_add.contains(RenderAttr::DIM) {
                self.ansi_output(ansi::SGR_DIM)?;
            }
        }

        // Independent SGR flags — toggle each direction that changed.
        if to_add.contains(RenderAttr::UNDERLINE) {
            self.ansi_output(ansi::SGR_UNDERLINE)?;
        }
        if to_remove.contains(RenderAttr::UNDERLINE) {
            self.ansi_output(ansi::SGR_UNDERLINE_OFF)?;
        }
        if to_add.contains(RenderAttr::REVERSE) {
            self.ansi_output(ansi::SGR_REVERSE)?;
        }
        if to_remove.contains(RenderAttr::REVERSE) {
            self.ansi_output(ansi::SGR_REVERSE_OFF)?;
        }
        if to_add.contains(RenderAttr::BLINK) {
            self.ansi_output(ansi::SGR_BLINK)?;
        }
        if to_remove.contains(RenderAttr::BLINK) {
            self.ansi_output(ansi::SGR_BLINK_OFF)?;
        }

        self.state_mut().attr = attr;
        Ok(())
    }

    /// Enter or exit VT100 Alternate Character Set mode.
    ///
    /// Gated on the compile-time [`ACS_LINECHARS`] flag: if ACS line
    /// drawing is disabled the call is a silent no-op and widgets are
    /// expected to use the Unicode box-drawing characters exported from
    /// [`ansi`] instead. The write is also elided when the requested
    /// state matches the cached value.
    ///
    /// # Errors
    ///
    /// Propagates any [`TuiError::Render`] from the underlying sink.
    fn set_acs(&mut self, active: bool) -> Result<(), TuiError> {
        if !ACS_LINECHARS {
            return Ok(());
        }
        if self.state().acs_active == active {
            return Ok(());
        }
        let seq: &[u8] = if active { ansi::ACS_ENTER } else { ansi::ACS_EXIT };
        self.ansi_output(seq)?;
        self.state_mut().acs_active = active;
        Ok(())
    }

    /// Write a UTF-8 text slice at the current cursor position.
    ///
    /// The caller is responsible for having set colours, attributes and
    /// the cursor position beforehand. This method performs no diffing —
    /// the text bytes are passed verbatim to the sink.
    ///
    /// # Errors
    ///
    /// Propagates any [`TuiError::Render`] from the underlying sink.
    fn write_text(&mut self, text: &str) -> Result<(), TuiError> {
        self.ansi_output(text.as_bytes())
    }

    /// Clear the entire screen and home the cursor to `(1, 1)`.
    ///
    /// # Errors
    ///
    /// Propagates any [`TuiError::Render`] from the underlying sink.
    fn clear_screen(&mut self) -> Result<(), TuiError> {
        self.ansi_output(ansi::CLEAR_SCREEN)?;
        self.ansi_output(ansi::CURSOR_HOME)?;
        self.state_mut().cursor = Point::new(1, 1);
        Ok(())
    }

    /// Notify the renderer of a new window size.
    ///
    /// Updates the cached [`RenderState::window`] rectangle, rooted at
    /// `Point::new(1, 1)` (the 1-indexed ANSI top-left). Concrete
    /// renderers may override this to perform additional bookkeeping
    /// such as re-laying-out the widget tree — the FASM renderer
    /// dispatched to `sizechanged` and `newlayoutonresize` at this point.
    fn new_window_size(&mut self, width: u16, height: u16) {
        self.state_mut().window =
            Rect::from_origin_size(Point::new(1, 1), i32::from(width), i32::from(height));
    }

    /// Returns the currently cached window bounds.
    fn window_bounds(&self) -> Rect {
        self.state().window
    }
}

// ---------------------------------------------------------------------------
// BufferedRenderer — batching wrapper around a `Renderer`.
//
// Widgets that want to emit many small writes (e.g. the `tui_datagrid`
// row painter in the FASM build) can wrap their inner renderer in a
// `BufferedRenderer`, accumulate output, then issue a single `flush` to
// send it downstream. This mirrors FASM's `tui_outputbuffer` bookkeeping
// without requiring every concrete renderer to implement batching on its
// own.
// ---------------------------------------------------------------------------

/// A [`Renderer`] adapter that accumulates ANSI bytes into an internal
/// [`Buffer`] before forwarding them to an inner renderer.
///
/// `BufferedRenderer` is constructed around an exclusive mutable borrow
/// of the inner renderer so its lifetime ends with the outer borrow.
/// Dropping the adapter flushes any unsent bytes as a best-effort
/// operation (errors during `Drop` are suppressed because a panicking
/// destructor would abort the process); callers that care about error
/// propagation should call [`Self::flush`] explicitly before drop.
///
/// The adapter forwards [`Renderer::state`] / [`Renderer::state_mut`] to
/// the inner renderer so that redundancy elision continues to work
/// correctly across buffered and unbuffered operations.
pub struct BufferedRenderer<'a, R: Renderer + ?Sized> {
    inner: &'a mut R,
    pending: Buffer,
}

impl<'a, R: Renderer + ?Sized> BufferedRenderer<'a, R> {
    /// Wrap `inner` in a new batching renderer.
    ///
    /// The returned renderer begins with an empty pending buffer.
    pub fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            pending: Buffer::new(),
        }
    }

    /// Flush any pending buffered bytes to the inner renderer, then
    /// flush the inner renderer itself.
    ///
    /// # Errors
    ///
    /// Propagates any [`TuiError::Render`] from the underlying sink.
    pub fn flush(&mut self) -> Result<(), TuiError> {
        // UFCS to avoid recursing back into this inherent `flush` via
        // the trait impl's `fn flush`.
        <Self as Renderer>::flush(self)
    }
}

impl<R: Renderer + ?Sized> Renderer for BufferedRenderer<'_, R> {
    fn ansi_output(&mut self, bytes: &[u8]) -> Result<(), TuiError> {
        self.pending.extend_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), TuiError> {
        if !self.pending.is_empty() {
            self.inner.ansi_output(self.pending.as_slice())?;
            self.pending.clear();
        }
        self.inner.flush()
    }

    fn state(&self) -> &RenderState {
        self.inner.state()
    }

    fn state_mut(&mut self) -> &mut RenderState {
        self.inner.state_mut()
    }
}

impl<R: Renderer + ?Sized> Drop for BufferedRenderer<'_, R> {
    fn drop(&mut self) {
        // Best-effort drain of the pending buffer on drop. Errors are
        // intentionally swallowed: a panicking destructor would abort
        // the process, and callers who need reliable error propagation
        // are expected to call `flush()` explicitly before letting the
        // adapter drop.
        //
        // We only drain the pending bytes here; we do NOT cascade to
        // `self.inner.flush()`. Skipping the inner flush avoids a
        // surprise second flush when the caller already invoked
        // `flush()` and keeps the number of inner flush operations
        // proportional to explicit caller intent.
        if !self.pending.is_empty() {
            let _ = self.inner.ansi_output(self.pending.as_slice());
            self.pending.clear();
        }
    }
}

// ---------------------------------------------------------------------------
// draw_box_border — convenience helper for widgets that render bordered
// panels. Uses Unicode box-drawing characters regardless of the
// ACS_LINECHARS config flag: modern terminals render the Unicode
// characters faithfully and the helper stays renderer-agnostic. Widgets
// that require strict VT100 ACS output can build their own border logic
// using the `ACS_*` constants plus `set_acs(true)`.
// ---------------------------------------------------------------------------

/// Draw a rectangular border using Unicode box-drawing characters.
///
/// The rectangle is specified in the same 1-indexed ANSI coordinate
/// system that [`RenderState::window`] uses: `rect.ax` / `rect.ay` are
/// the inclusive top-left column / row, `rect.bx` / `rect.by` are the
/// exclusive bottom-right column / row.
///
/// When `double` is `true` the border uses heavy double-line characters
/// (`╔ ╗ ╚ ╝ ═ ║`); otherwise it uses the light single-line characters
/// exposed from [`crate::tui::ansi`] (`┌ ┐ └ ┘ ─ │`).
///
/// Rectangles with width or height below 2 are silently ignored — there
/// isn't enough room to draw both corners plus an edge, which is the
/// same early-exit behaviour as the FASM `tui_render$drawbox` helper.
///
/// # Errors
///
/// Propagates any [`TuiError::Render`] from the underlying sink.
pub fn draw_box_border<R: Renderer + ?Sized>(r: &mut R, rect: Rect, double: bool) -> Result<(), TuiError> {
    let width = rect.width();
    let height = rect.height();
    if width < 2 || height < 2 {
        return Ok(());
    }
    // Width / height checked above; cast is safe because the values are
    // positive i32 and bounded by u16 window sizes in practice.
    let width = width as usize;
    let height = height as usize;

    let (ul, ur, ll, lr, h_char, v_char) = if double {
        ('╔', '╗', '╚', '╝', '═', '║')
    } else {
        (
            ansi::UNICODE_ULCORNER,
            ansi::UNICODE_URCORNER,
            ansi::UNICODE_LLCORNER,
            ansi::UNICODE_LRCORNER,
            ansi::UNICODE_HLINE,
            ansi::UNICODE_VLINE,
        )
    };

    // Guard the coordinate casts: ax/ay should be non-negative for any
    // sensible rect, but clamp to zero to keep the cast lossless.
    let top = rect.ay.max(0).min(i32::from(u16::MAX)) as u16;
    let left = rect.ax.max(0).min(i32::from(u16::MAX)) as u16;
    let bottom_row = (rect.by - 1).max(0).min(i32::from(u16::MAX)) as u16;
    let right_col = (rect.bx - 1).max(0).min(i32::from(u16::MAX)) as u16;

    // Build the horizontal edge strings once (max 4 UTF-8 bytes per char).
    let mut top_row = String::with_capacity(width * 4);
    top_row.push(ul);
    for _ in 0..(width - 2) {
        top_row.push(h_char);
    }
    top_row.push(ur);

    let mut bottom_row_str = String::with_capacity(width * 4);
    bottom_row_str.push(ll);
    for _ in 0..(width - 2) {
        bottom_row_str.push(h_char);
    }
    bottom_row_str.push(lr);

    let mut v_str = String::with_capacity(4);
    v_str.push(v_char);

    // Top row.
    r.move_cursor(top, left)?;
    r.write_text(&top_row)?;

    // Vertical edges — one cell per interior row.
    for row_offset in 1..(height - 1) {
        let row = top.saturating_add(row_offset as u16);
        r.move_cursor(row, left)?;
        r.write_text(&v_str)?;
        r.move_cursor(row, right_col)?;
        r.write_text(&v_str)?;
    }

    // Bottom row.
    r.move_cursor(bottom_row, left)?;
    r.write_text(&bottom_row_str)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — unit tests exercising trait object-safety, elision behaviour,
// and the BufferedRenderer / draw_box_border helpers.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal test double that captures every emitted byte into a
    /// growable buffer. Proves the [`Renderer`] trait is object-safe
    /// and that the default method implementations emit the expected
    /// byte sequences.
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

    // -------------------------- RenderAttr --------------------------

    #[test]
    fn render_attr_none_is_empty() {
        assert!(RenderAttr::NONE.is_empty());
        assert!(RenderAttr::default().is_empty());
    }

    #[test]
    fn render_attr_contains_itself_and_none() {
        let a = RenderAttr::BOLD.union(RenderAttr::UNDERLINE);
        assert!(a.contains(RenderAttr::BOLD));
        assert!(a.contains(RenderAttr::UNDERLINE));
        assert!(!a.contains(RenderAttr::BLINK));
        assert!(a.contains(RenderAttr::NONE));
        assert!(a.contains(a));
    }

    #[test]
    fn render_attr_union_and_difference() {
        let a = RenderAttr::BOLD.union(RenderAttr::UNDERLINE);
        let b = a.difference(RenderAttr::BOLD);
        assert!(!b.contains(RenderAttr::BOLD));
        assert!(b.contains(RenderAttr::UNDERLINE));
        // Self-difference clears everything.
        assert!(a.difference(a).is_empty());
    }

    #[test]
    fn render_attr_equality_is_structural() {
        let a = RenderAttr::BOLD.union(RenderAttr::REVERSE);
        let b = RenderAttr::REVERSE.union(RenderAttr::BOLD);
        assert_eq!(a, b);
    }

    // -------------------------- RenderState --------------------------

    #[test]
    fn render_state_default_is_zeroed() {
        let s = RenderState::default();
        assert_eq!(s.cursor, Point::default());
        assert_eq!(s.fg, 0);
        assert_eq!(s.bg, 0);
        assert_eq!(s.attr, RenderAttr::NONE);
        assert!(!s.acs_active);
        assert_eq!(s.window, Rect::default());
    }

    // -------------------------- Cursor elision --------------------------

    #[test]
    fn move_cursor_writes_sequence_first_call() {
        let mut r = TestSink::new();
        r.move_cursor(5, 10).expect("move_cursor");
        // Contains ESC[ prefix from CSI.
        assert!(r.out.starts_with(b"\x1b["));
        assert_eq!(r.state().cursor, Point::new(10, 5));
    }

    #[test]
    fn move_cursor_elides_redundant_moves() {
        let mut r = TestSink::new();
        r.move_cursor(3, 7).expect("first");
        let after_first = r.out.len();
        r.move_cursor(3, 7).expect("second");
        assert_eq!(r.out.len(), after_first, "redundant move not elided");
    }

    #[test]
    fn move_cursor_writes_when_position_changes() {
        let mut r = TestSink::new();
        r.move_cursor(1, 1).expect("first");
        let after_first = r.out.len();
        r.move_cursor(2, 2).expect("second");
        assert!(r.out.len() > after_first, "real move should produce bytes");
    }

    // -------------------------- Color elision --------------------------

    #[test]
    fn set_fg_elides_redundant_sets() {
        let mut r = TestSink::new();
        // First call matches default `fg = 0` so no bytes are emitted —
        // this is intentional: the terminal begins at default colour.
        r.set_fg(0).expect("set default");
        let n0 = r.out.len();
        r.set_fg(0).expect("same again");
        assert_eq!(r.out.len(), n0);
        r.set_fg(15).expect("change to 15");
        let n1 = r.out.len();
        assert!(n1 > n0, "colour change should emit bytes");
        r.set_fg(15).expect("same as before");
        assert_eq!(r.out.len(), n1, "redundant colour set not elided");
    }

    #[test]
    fn set_bg_elides_redundant_sets() {
        let mut r = TestSink::new();
        r.set_bg(42).expect("first set");
        let n1 = r.out.len();
        r.set_bg(42).expect("same again");
        assert_eq!(r.out.len(), n1);
        r.set_bg(43).expect("change");
        assert!(r.out.len() > n1);
    }

    // -------------------------- Attr diffing --------------------------

    #[test]
    fn set_attr_noop_when_unchanged() {
        let mut r = TestSink::new();
        r.set_attr(RenderAttr::NONE).expect("noop");
        assert!(r.out.is_empty(), "no-op set_attr should not emit bytes");
    }

    #[test]
    fn set_attr_adds_underline() {
        let mut r = TestSink::new();
        r.set_attr(RenderAttr::UNDERLINE).expect("add underline");
        assert_eq!(r.out, ansi::SGR_UNDERLINE);
    }

    #[test]
    fn set_attr_adds_reverse_and_blink() {
        let mut r = TestSink::new();
        let attrs = RenderAttr::REVERSE.union(RenderAttr::BLINK);
        r.set_attr(attrs).expect("set reverse+blink");
        // Both on-codes should appear in the output.
        let expected_len = ansi::SGR_REVERSE.len() + ansi::SGR_BLINK.len();
        assert_eq!(r.out.len(), expected_len);
    }

    #[test]
    fn set_attr_removes_underline() {
        let mut r = TestSink::new();
        r.set_attr(RenderAttr::UNDERLINE).expect("enable");
        r.out.clear();
        r.set_attr(RenderAttr::NONE).expect("disable");
        assert_eq!(r.out, ansi::SGR_UNDERLINE_OFF);
    }

    #[test]
    fn set_attr_transitions_bold_to_dim() {
        let mut r = TestSink::new();
        r.set_attr(RenderAttr::BOLD).expect("enable bold");
        r.out.clear();
        r.set_attr(RenderAttr::DIM).expect("switch to dim");
        // Must emit SGR_BOLD_OFF (shared intensity reset) followed by SGR_DIM.
        let mut expected = Vec::new();
        expected.extend_from_slice(ansi::SGR_BOLD_OFF);
        expected.extend_from_slice(ansi::SGR_DIM);
        assert_eq!(r.out, expected);
    }

    #[test]
    fn set_attr_caches_state() {
        let mut r = TestSink::new();
        let attrs = RenderAttr::BOLD.union(RenderAttr::UNDERLINE);
        r.set_attr(attrs).expect("apply");
        assert_eq!(r.state().attr, attrs);
    }

    // -------------------------- ACS gating --------------------------

    #[test]
    fn set_acs_respects_config_flag() {
        let mut r = TestSink::new();
        r.set_acs(true).expect("enter ACS");
        if ACS_LINECHARS {
            assert_eq!(r.out, ansi::ACS_ENTER);
            assert!(r.state().acs_active);
        } else {
            assert!(r.out.is_empty());
            assert!(!r.state().acs_active);
        }
    }

    #[test]
    fn set_acs_elides_repeated_state() {
        let mut r = TestSink::new();
        r.set_acs(true).expect("enter");
        r.out.clear();
        r.set_acs(true).expect("enter again");
        assert!(r.out.is_empty(), "repeat ACS enter should be elided");
    }

    // -------------------------- write_text --------------------------

    #[test]
    fn write_text_copies_bytes_verbatim() {
        let mut r = TestSink::new();
        r.write_text("hello").expect("write");
        assert_eq!(r.out, b"hello");
    }

    #[test]
    fn write_text_handles_utf8() {
        let mut r = TestSink::new();
        r.write_text("héllo").expect("write utf8");
        assert_eq!(r.out, "héllo".as_bytes());
    }

    // -------------------------- clear_screen --------------------------

    #[test]
    fn clear_screen_emits_sequences_and_resets_cursor() {
        let mut r = TestSink::new();
        r.clear_screen().expect("clear");
        let mut expected = Vec::new();
        expected.extend_from_slice(ansi::CLEAR_SCREEN);
        expected.extend_from_slice(ansi::CURSOR_HOME);
        assert_eq!(r.out, expected);
        assert_eq!(r.state().cursor, Point::new(1, 1));
    }

    // -------------------------- window size --------------------------

    #[test]
    fn new_window_size_updates_cached_window() {
        let mut r = TestSink::new();
        r.new_window_size(80, 24);
        let bounds = r.window_bounds();
        assert_eq!(bounds.width(), 80);
        assert_eq!(bounds.height(), 24);
    }

    #[test]
    fn new_window_size_is_1_indexed() {
        let mut r = TestSink::new();
        r.new_window_size(100, 30);
        let bounds = r.window_bounds();
        // Top-left should be (1, 1) per ANSI convention.
        assert_eq!(bounds.top_left(), Point::new(1, 1));
    }

    // -------------------------- trait object safety --------------------------

    #[test]
    fn renderer_is_object_safe() {
        let mut r = TestSink::new();
        // Erasing to `&mut dyn Renderer` compiles iff the trait is
        // object-safe. This assertion is primarily a compile-time check.
        let dyn_r: &mut dyn Renderer = &mut r;
        dyn_r.write_text("ok").expect("dyn write");
        assert!(!dyn_r.state().acs_active);
    }

    // -------------------------- BufferedRenderer --------------------------

    #[test]
    fn buffered_renderer_batches_output() {
        let mut sink = TestSink::new();
        {
            let mut buffered = BufferedRenderer::new(&mut sink);
            buffered.ansi_output(b"hello").expect("batched");
            buffered.ansi_output(b" world").expect("batched");
            // Before flush, the inner sink has nothing.
            assert!(buffered.inner.out.is_empty());
            buffered.flush().expect("flush");
        }
        assert_eq!(sink.out, b"hello world");
        assert_eq!(sink.flush_count, 1);
    }

    #[test]
    fn buffered_renderer_flushes_on_drop() {
        let mut sink = TestSink::new();
        {
            let mut buffered = BufferedRenderer::new(&mut sink);
            buffered.ansi_output(b"drop-me").expect("batched");
        } // Drop here should flush.
        assert_eq!(sink.out, b"drop-me");
    }

    #[test]
    fn buffered_renderer_forwards_state() {
        let mut sink = TestSink::new();
        sink.state_mut().fg = 7;
        let buffered = BufferedRenderer::new(&mut sink);
        assert_eq!(buffered.state().fg, 7);
    }

    #[test]
    fn buffered_renderer_elides_redundant_moves_via_shared_state() {
        let mut sink = TestSink::new();
        {
            let mut buffered = BufferedRenderer::new(&mut sink);
            buffered.move_cursor(1, 1).expect("first");
            buffered.move_cursor(1, 1).expect("second redundant");
            buffered.flush().expect("flush");
        }
        // Exactly one ESC[1;1H sequence should have been buffered and
        // then flushed — the redundant second call must be elided by
        // the shared render state.
        let mut expected = Vec::new();
        let mut tmp: Vec<u8> = Vec::new();
        ansi::move_cursor_to(&mut (&mut tmp) as &mut dyn BufMut, 1, 1);
        expected.extend_from_slice(&tmp);
        assert_eq!(sink.out, expected);
    }

    #[test]
    fn buffered_renderer_empty_flush_still_calls_inner() {
        let mut sink = TestSink::new();
        {
            let mut buffered = BufferedRenderer::new(&mut sink);
            buffered.flush().expect("flush empty");
        }
        assert_eq!(sink.flush_count, 1, "inner flush must still be called");
        assert!(sink.out.is_empty());
    }

    // -------------------------- draw_box_border --------------------------

    #[test]
    fn draw_box_border_skips_tiny_rects() {
        let mut r = TestSink::new();
        let rect = Rect::from_origin_size(Point::new(1, 1), 1, 5);
        draw_box_border(&mut r, rect, false).expect("tiny");
        assert!(r.out.is_empty(), "tiny rect should produce no output");
    }

    #[test]
    fn draw_box_border_emits_corners_for_small_rect() {
        let mut r = TestSink::new();
        let rect = Rect::from_origin_size(Point::new(2, 3), 4, 3);
        draw_box_border(&mut r, rect, false).expect("draw");
        // Every light-box corner and the single-line edge char must appear.
        let out = String::from_utf8(r.out).expect("utf8");
        assert!(out.contains(ansi::UNICODE_ULCORNER));
        assert!(out.contains(ansi::UNICODE_URCORNER));
        assert!(out.contains(ansi::UNICODE_LLCORNER));
        assert!(out.contains(ansi::UNICODE_LRCORNER));
        assert!(out.contains(ansi::UNICODE_HLINE));
        assert!(out.contains(ansi::UNICODE_VLINE));
    }

    #[test]
    fn draw_box_border_double_uses_double_characters() {
        let mut r = TestSink::new();
        let rect = Rect::from_origin_size(Point::new(1, 1), 3, 3);
        draw_box_border(&mut r, rect, true).expect("draw double");
        let out = String::from_utf8(r.out).expect("utf8");
        assert!(out.contains('╔'));
        assert!(out.contains('╗'));
        assert!(out.contains('╚'));
        assert!(out.contains('╝'));
        assert!(out.contains('═'));
        assert!(out.contains('║'));
    }

    #[test]
    fn draw_box_border_via_trait_object() {
        // Prove the helper accepts `&mut dyn Renderer`.
        let mut sink = TestSink::new();
        let dyn_r: &mut dyn Renderer = &mut sink;
        let rect = Rect::from_origin_size(Point::new(1, 1), 3, 3);
        draw_box_border(dyn_r, rect, false).expect("dyn draw");
        assert!(!sink.out.is_empty());
    }
}
