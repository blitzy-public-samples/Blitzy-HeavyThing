// crates/heavything/src/tui/widgets/matrix.rs — Matrix-rain animation widget.
//
// Direct Rust translation of `tui_matrix.inc` (676 lines) per AAP §0.5.1.5.
// The FASM author calls this a "joke" widget intentionally designed to
// "kill the CPU" — a 100-stream raining-character effect refreshed at
// 20 fps. We preserve that behavior exactly: 100 parallel streams, six
// shade-step dimming tail, half-width kana character pool starting at
// U+FF61, 50 ms ticker, and a never-stop timer convention so cleanup
// is the only place the ticker is torn down.
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.
//
// Rust translation © 2026, licensed under GPL-3.0-or-later.
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

#![forbid(unsafe_code)]

//! Matrix-rain animation widget — port of `tui_matrix.inc`.
//!
//! ## Behavior
//!
//! Renders a "Matrix"-style cascade of half-width kana glyphs flowing
//! top-to-bottom across the widget's full extent. Up to
//! [`MAX_STREAMS`]=100 streams are alive simultaneously; each stream
//! has an independent x-column, y-position, fall speed, and head/body
//! glyphs. Each frame the head glyph is rendered at full
//! ([`BASE_R`], [`BASE_G`], [`BASE_B`])=(150, 255, 100) brightness; the
//! body glyph one cell above is rendered at a third of that brightness
//! (per the [`INC_R_S`]=8 / `INC_G_S`=14 / `INC_B_S`=5 secondary-shade
//! step); and the tail cell [`BACKTRACE`]=30 cells above is cleared to
//! green-on-black. Per FASM commentary at lines 22–44 this is
//! intentionally CPU-intensive — terminals will hit 100 % CPU at
//! 20 fps.
//!
//! ## FASM-vs-Rust architectural mapping
//!
//! In FASM the widget owns six parallel `i32[100]` arrays plus an
//! `i64` stream counter and an epoll-timer pointer (see offsets
//! `tui_matrix_startx_ofs` through `tui_matrix_timer_ofs` in
//! `tui_matrix.inc` lines 103–113). The Rust port mirrors this layout
//! by hiding the same six arrays plus counter, PRNG state, timer
//! handle, and a pair of shadow render buffers inside a private
//! [`MatrixInner`] struct guarded by `std::sync::Mutex`. The widget
//! itself only directly exposes [`WidgetState`] (per the
//! [`Widget`](crate::tui::object::Widget) contract) — every other
//! "field" listed in the schema lives inside `MatrixInner` and is
//! manipulated through the Mutex.
//!
//! The 50 ms (20 fps) ticker is implemented by spawning a tokio task
//! against the runtime [`Handle`](tokio::runtime::Handle) supplied to
//! [`Matrix::start_timer`]. The task holds a [`Weak`] reference to
//! `Matrix` so the widget can be dropped without leaking the timer
//! task. Per the FASM convention `tui_matrix$timer` ALWAYS returns
//! "reset timer" (`eax = 0` at line 674) — there is no stop signal —
//! so the spawn loop is unconditional with cancellation driven by
//! either widget drop (Weak upgrade fails) or by the
//! [`MatrixInner::timer_active`] flag flipped to `false` from
//! [`Widget::cleanup`].
//!
//! The FASM `tui_matrix$display` routine writes characters and
//! attribute words directly into the inherited
//! [`WidgetState::text`](crate::tui::object::WidgetState::text) and
//! [`WidgetState::attributes`](crate::tui::object::WidgetState::attributes)
//! buffers (offsets `tui_text_ofs` / `tui_attr_ofs`). Because
//! [`Widget::draw`](crate::tui::object::Widget::draw) is the only
//! method on the Widget trait that gets `&mut self` access from the
//! framework's render pass, we cannot mutate `state.text` /
//! `state.attributes` directly from a `&self`-only spawned task.
//! Instead we keep matching `text_shadow` / `attr_shadow` buffers
//! inside `MatrixInner` and write the cell deltas there. Both the
//! framework-driven [`Widget::timer`] path (which has `&mut self`)
//! and the [`Widget::draw`] path call
//! [`Matrix::flush_shadow_to_state`] to copy the shadow into
//! `WidgetState`. The spawned task only writes to the shadow; the
//! next call to `draw` synchronizes it to the visible buffers.
//!
//! ## ANSI color packing — FASM-vs-Rust byte order
//!
//! FASM packs 16-bit attribute words as `(fg << 8) | bg` (foreground
//! in the upper byte, background in the lower byte) per the
//! `ansi_colors` macro in `tui_ansi.inc` line 1207. The Rust crate
//! convention (see [`crate::tui::object::Attributes::push`] and
//! the precedent in `widgets/background.rs`) is the OPPOSITE:
//! `fg | (bg << 8)`. All packing in this file therefore emits the
//! Rust-convention layout — foreground in the lower byte. The
//! `0xe8` byte that FASM ORs into the low byte of every primary /
//! secondary color word IS the background palette index (xterm
//! 256-color near-black grayscale per the `ansi_wci_rgbi` macro at
//! `tui_ansi.inc` line 1183 mapping RGB(0,0,0) → 0xe8). The same
//! semantic value packed Rust-style becomes
//! `(fg_palette_idx) | (0xe8 << 8) = fg_palette_idx | 0xe800`.
//!
//! Similarly, FASM emits the green-on-black tail-clear cell as
//! `ansi_colors green, black` which evaluates to `(46 << 8) | 232 =
//! 0x2EE8` (FASM `ansi_wci_rgbi` maps RGB(0,255,0)='green' → palette
//! index 46, and RGB(0,0,0)='black' → 0xe8 = 232). Packed Rust-style
//! the same value becomes `46 | (232 << 8) = 0xE82E`.
//!
//! ## Per-tick allocation budget
//!
//! Per FASM `tui_matrix$createdestroy` (line 268) a single tick
//! creates AT MOST one new stream — searching for the first
//! inactive slot, populating it, and breaking out via `jmp .dostops`.
//! Subsequently a sweep over all 100 slots terminates any stream
//! whose `start_y` exceeds `height + BACKTRACE`. This rate-limiting
//! is preserved exactly in [`MatrixInner::createdestroy`].

use std::any::Any;
use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

use crate::ds::Buffer;
use crate::error::TuiError;
use crate::tui::object::{Attributes, ColorPair, Widget, WidgetState};
use crate::tui::render::Renderer;

// Suppress "unused import" warning for `ColorPair` — the import is
// listed in the file schema's `internal_imports` directive even though
// the matrix widget emits 24-bit RGB through individually computed
// `(fg, bg)` palette bytes rather than via `ColorPair` aggregation.
// Keeping it in scope per the schema preserves API-surface parity
// with sibling widget files (e.g. `spacers.rs`).
#[allow(dead_code)]
type _ColorPairAlias = ColorPair;

// ============================================================================
// Compile-time constants — exact ports of `tui_matrix.inc` lines 58–86.
// ============================================================================

/// Maximum number of simultaneously active streams
/// (`tui_matrix.inc` line 58: `tui_matrix_maxstream = 100`).
///
/// All six per-stream physics arrays in [`MatrixInner`] are sized to
/// this value. The constant is exported so callers writing test
/// fixtures can size scratch arrays consistently with the widget.
pub const MAX_STREAMS: usize = 100;

/// Number of trailing cells per stream, i.e. how far above the head
/// the tail-clear cell is positioned
/// (`tui_matrix.inc` line 59: `tui_matrix_backtrace = 30`).
pub const BACKTRACE: i32 = 30;

/// Reserved leading-glyph distance per FASM
/// (`tui_matrix.inc` line 60: `tui_matrix_leading = 10`).
///
/// Defined-but-unused in the FASM source — kept for API parity with
/// the schema's `members_exposed` list. The active rendering uses
/// only [`BACKTRACE`] for tail-clear positioning.
pub const LEADING: i32 = 10;

/// Reserved space-padding distance per FASM
/// (`tui_matrix.inc` line 61: `tui_matrix_spacepad = 30`).
///
/// Defined-but-unused in the FASM source — kept for API parity with
/// the schema's `members_exposed` list.
pub const SPACE_PAD: i32 = 30;

/// Base red channel for the primary head-glyph color
/// (`tui_matrix.inc` line 63: `tui_matrix_r = 150`).
pub const BASE_R: u8 = 150;

/// Base green channel for the primary head-glyph color
/// (`tui_matrix.inc` line 64: `tui_matrix_g = 255`).
pub const BASE_G: u8 = 255;

/// Base blue channel for the primary head-glyph color
/// (`tui_matrix.inc` line 65: `tui_matrix_b = 100`).
pub const BASE_B: u8 = 100;

/// When `true`, [`Matrix::display_stream`] also emits Latin
/// alphanumerics in addition to half-width kana
/// (`tui_matrix.inc` line 67: `tui_matrix_cpukiller = 0`).
///
/// FASM disables this by default with the comment "messy with
/// Terminal.app" and "cranks CPU further". Preserved as `false`
/// here to match FASM default behavior. Toggling this requires
/// rebuilding the widget — the constant is compile-time.
pub const CPU_KILLER: bool = false;

/// Per-stream red dimming step for the primary color
/// (`tui_matrix.inc` line 70: `tui_matrix_incr = tui_matrix_r / 6`
/// = 25).
pub const INC_R: u8 = BASE_R / 6;

/// Per-stream green dimming step for the primary color
/// (`tui_matrix.inc` line 71: `tui_matrix_incg = tui_matrix_g / 6`
/// = 42).
pub const INC_G: u8 = BASE_G / 6;

/// Per-stream blue dimming step for the primary color
/// (`tui_matrix.inc` line 72: `tui_matrix_incb = tui_matrix_b / 6`
/// = 16).
pub const INC_B: u8 = BASE_B / 6;

/// Per-stream red dimming step for the secondary (body) color
/// (`tui_matrix.inc` line 78: `tui_matrix_incr_s = tui_matrix_r / 3
/// / 6` = 8).
pub const INC_R_S: u8 = BASE_R / 3 / 6;

/// Per-stream green dimming step for the secondary (body) color
/// (`tui_matrix.inc` line 79: `tui_matrix_incg_s = tui_matrix_g / 3
/// / 6` = 14). Internal helper — not part of the public surface.
const INC_G_S: u8 = BASE_G / 3 / 6;

/// Per-stream blue dimming step for the secondary (body) color
/// (`tui_matrix.inc` line 80: `tui_matrix_incb_s = tui_matrix_b / 3
/// / 6` = 5). Internal helper — not part of the public surface.
const INC_B_S: u8 = BASE_B / 3 / 6;

/// Timer interval in milliseconds — 20 fps cadence
/// (`tui_matrix.inc` line 142: `epoll$timer_new(50ms)`).
pub const TIMER_MS: u64 = 50;

// ============================================================================
// Internal constants — derived but not part of the schema.
// ============================================================================

/// xterm 256-color palette divisor used by `ansi_wci_rgbi`
/// (`tui_ansi.inc` line 1192: `ansi_wcr / 43`). Each 8-bit RGB
/// channel maps to a 0..6 6-step grid via integer division.
const PALETTE_DIVISOR: u8 = 43;

/// Base offset added to the rgbi-mapped channel sum (per
/// `tui_ansi.inc` line 1196: `+ 16`) — the xterm 256-color cube
/// starts at palette index 16.
const PALETTE_BASE: u8 = 16;

/// xterm 256-color palette index for "near-black" used by
/// `ansi_wci_rgbi` for RGB(0, 0, 0) — see
/// `tui_ansi.inc` line 1186 (`ansi_wci_val = 0xe8`). FASM ORs this
/// into the low byte of every primary/secondary color word as the
/// background. We use it as the BG byte in the Rust packing.
const BG_NEAR_BLACK: u8 = 0xe8;

/// Half-width kana code-point base — the 63 glyphs from U+FF61 to
/// U+FF9F per FASM `tui_matrix.inc` line 588 random-character
/// selection (`rng$intmax(62) + 0xff61`).
const KANA_BASE: u32 = 0xFF61;

/// Number of distinct kana glyphs in the random pool — matches FASM
/// `rng$intmax(62)` (62 because the original source treats the
/// upper-bound as exclusive even though there are 63 code points;
/// faithfully preserved).
const KANA_RANGE: u64 = 62;

/// Maximum random fall-speed minus 1 — FASM `rng$intmax(5)` returns
/// 0..=4 inclusive (uniform over 5 values).
const SPEED_RANGE: u64 = 5;

/// Tail-clear cell character — single Latin space (FASM
/// `tui_matrix.inc` line 213 `memset32(text, ' ', cells)`).
const TAIL_CHAR: u32 = b' ' as u32;

/// Number of bytes per cell in the [`WidgetState::text`] buffer.
/// Each cell stores one little-endian `u32` Unicode code point.
const BYTES_PER_CELL: usize = 4;

// ============================================================================
// Helper functions — color packing and PRNG.
// ============================================================================

/// Pack `(fg, bg)` palette indices into the Rust attribute-cell layout
/// (`fg` in bits 0–7, `bg` in bits 8–15, SGR flags zero).
///
/// This corresponds to the inverse byte order from FASM's
/// `ansi_colors` macro (`tui_ansi.inc` line 1207) which packs
/// `(fg << 8) | bg`. Per
/// [`crate::tui::object::Attributes::push`] and the
/// `widgets/background.rs::pack_color_pair` helper, the Rust
/// crate-wide convention places foreground in the low byte.
///
/// Defined `const` so the [`TAIL_ATTR`] constant below can be
/// computed at compile time.
const fn pack_attr(fg: u8, bg: u8) -> u32 {
    (fg as u32) | ((bg as u32) << 8)
}

/// Pre-computed tail-clear attribute word — green foreground
/// (palette 46 per RGB(0, 255, 0) through `ansi_wci_rgbi`) on
/// near-black background (palette 0xe8 per RGB(0, 0, 0)).
///
/// FASM emits this via `ansi_colors green, black` at line 220 which
/// produces the FASM-packed value `(46 << 8) | 232 = 0x2EE8`. The
/// Rust-packed equivalent is `46 | (232 << 8) = 0xE82E`.
const TAIL_ATTR: u32 = pack_attr(46, BG_NEAR_BLACK);

/// Compute the xterm 256-color palette index for an `(r, g, b)`
/// channel triple via the FASM `ansi_wci_rgbi` algorithm
/// (`tui_ansi.inc` lines 1183–1199): each channel is divided by 43
/// to land in 0..=6, the cube index is `b + g*6 + r*36`, and
/// `+ 16` shifts past the standard 16-color region.
///
/// FASM falls back to a grayscale ramp when `r == g == b`; in
/// matrix's primary/secondary color path the channel values are
/// always derived from `BASE_*` minus a `sos`-scaled `INC_*` step
/// where the channels diverge — so the cube path is the only one
/// exercised. This helper covers the cube path exclusively.
///
/// Returns the final byte (palette index in 16..=231 inclusive for
/// any cube input).
fn rgbi_cube(r: u8, g: u8, b: u8) -> u8 {
    let r_idx = r / PALETTE_DIVISOR;
    let g_idx = g / PALETTE_DIVISOR;
    let b_idx = b / PALETTE_DIVISOR;
    // Order: b + g*6 + r*36 + 16 — exact FASM algebra.
    b_idx
        .wrapping_add(g_idx.wrapping_mul(6))
        .wrapping_add(r_idx.wrapping_mul(36))
        .wrapping_add(PALETTE_BASE)
}

/// Compute the primary head-glyph color for a stream with
/// fall-speed `sos` (the original `orig_speed` value, in the range
/// 0..=4). Returns the Rust-packed `(fg, bg=0xe8, sgr=0)`
/// attribute word — foreground in the low byte, near-black
/// background in the next byte, no SGR flags.
///
/// The FASM equivalent at `tui_matrix.inc` lines 458–504 computes:
/// `r = (BASE_R - sos*INC_R) / 43`,
/// `g = (BASE_G - sos*INC_G) / 43`,
/// `b = (BASE_B - sos*INC_B) / 43`,
/// `fg = b + g*6 + r*36 + 16`,
/// then packs `(fg << 8) | 0xe8` — FASM byte order. We emit the
/// Rust-byte-order packing of the same `(fg, 0xe8)` semantic.
///
/// `sos` is clamped to `u8` because the FASM source's `imul`
/// operates on `r9d` (32-bit) but the values themselves never
/// exceed 4 by construction (`rng$intmax(5)` at line 313).
fn primary_color(sos: u8) -> u32 {
    let r = BASE_R.saturating_sub(sos.saturating_mul(INC_R));
    let g = BASE_G.saturating_sub(sos.saturating_mul(INC_G));
    let b = BASE_B.saturating_sub(sos.saturating_mul(INC_B));
    let fg = rgbi_cube(r, g, b);
    pack_attr(fg, BG_NEAR_BLACK)
}

/// Compute the secondary (body-glyph) color for a stream with
/// fall-speed `sos`. Same algebra as [`primary_color`] but with
/// `BASE_R/3` / `BASE_G/3` / `BASE_B/3` as the base channels and
/// [`INC_R_S`] / [`INC_G_S`] / [`INC_B_S`] as the per-stream steps.
///
/// FASM equivalent at `tui_matrix.inc` lines 506–551.
fn secondary_color(sos: u8) -> u32 {
    let r = (BASE_R / 3).saturating_sub(sos.saturating_mul(INC_R_S));
    let g = (BASE_G / 3).saturating_sub(sos.saturating_mul(INC_G_S));
    let b = (BASE_B / 3).saturating_sub(sos.saturating_mul(INC_B_S));
    let fg = rgbi_cube(r, g, b);
    pack_attr(fg, BG_NEAR_BLACK)
}

/// `xorshift64` — generates the next 64-bit pseudo-random value
/// from the supplied state and updates it in place. Vavilov &
/// Marsaglia 2003 triple `(13, 7, 17)` — the same triple chosen
/// by `rand` and many other Rust crates for its proven period
/// (2^64 - 1) and quality.
///
/// This intentionally departs from FASM's HMAC-DRBG-backed
/// `rng$intmax` because matrix's randomness is purely visual /
/// non-cryptographic per AAP §0.7.4 (reduce `unsafe` surface and
/// avoid the synchronization cost of a global DRBG for a "joke"
/// widget). The visual outcome is statistically indistinguishable.
fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    if x == 0 {
        // xorshift64 is degenerate at 0; reseed with a distinctive
        // constant rather than panicking. Use the golden-ratio
        // hash `0x9E37_79B9_7F4A_7C15` so the rest of the cycle is
        // immediate rather than stuck on the zero attractor.
        x = 0x9E37_79B9_7F4A_7C15;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// Return a uniform sample in `0..max` using [`xorshift64`].
///
/// Matches the contract of FASM `rng$intmax(N)`: returns a value in
/// `[0, max)`. Returns 0 when `max == 0` (defensive — the FASM
/// source never invokes `rng$intmax(0)` in matrix). Bias from
/// modulo is acceptable for visual / non-cryptographic use.
fn rng_intmax(state: &mut u64, max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    xorshift64(state) % max
}

/// Initial PRNG seed derived from the system clock — matches the
/// FASM `tui_matrix$new` path which obtains randomness via the
/// global DRBG. Falls back to a fixed constant if the clock is
/// somehow before the UNIX epoch (impossible on Linux).
fn seed_from_system_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
}

/// Recoverable Mutex-lock helper — translates poison errors back
/// into the inner guard so a panic in one tick path doesn't
/// cascade into permanent unavailability of the matrix. Matches
/// the [`crate::tui::widgets::effect`] precedent at line 1342 and
/// the [`crate::tui::widgets::spinner`] poison-recovery branch at
/// line 425.
fn lock_inner_recoverable(m: &Mutex<MatrixInner>) -> std::sync::MutexGuard<'_, MatrixInner> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Resize `buf` to exactly `count * 4` bytes and write `count`
/// little-endian `u32` words equal to `value`. Matches the
/// `widgets/background.rs::fill_u32_buffer` helper (lines 674–718)
/// — duplicated here because that helper is private to the
/// `background` module.
fn fill_u32_buffer(buf: &mut Buffer, value: u32, count: usize) -> Result<(), TuiError> {
    let bytes = count.checked_mul(BYTES_PER_CELL).ok_or_else(|| {
        TuiError::Render(std::io::Error::other(format!(
            "matrix::fill_u32_buffer: count*4 overflowed usize (count={count})"
        )))
    })?;
    if buf.len() < bytes {
        buf.reserve(bytes - buf.len());
        for _ in buf.len()..bytes {
            buf.push(0);
        }
    }
    if buf.len() > bytes {
        let to_remove = buf.len() - bytes;
        buf.truncate(to_remove).map_err(|e| {
            TuiError::Render(std::io::Error::other(format!(
                "matrix::fill_u32_buffer: truncate failed: {e:?}"
            )))
        })?;
    }
    let value_le = value.to_le_bytes();
    let slice = buf.as_mut_slice();
    debug_assert!(
        slice.len() >= bytes,
        "matrix::fill_u32_buffer: slice unexpectedly shorter than bytes"
    );
    for chunk in slice.chunks_exact_mut(BYTES_PER_CELL).take(count) {
        chunk.copy_from_slice(&value_le);
    }
    Ok(())
}

/// Resize `attr.cells` to exactly `count` and fill every cell with
/// `value`. Matches the `widgets/background.rs::fill_u32_attributes`
/// helper (lines 727–737) — duplicated here for module locality.
fn fill_u32_attributes(attr: &mut Attributes, value: u32, count: usize) {
    if attr.cells.len() < count {
        attr.cells.resize(count, 0);
    } else if attr.cells.len() > count {
        attr.cells.truncate(count);
    }
    for cell in attr.cells.iter_mut() {
        *cell = value;
    }
}

/// Write a single `u32` little-endian word into `buf` at byte
/// offset `byte_offset`. Returns silently if the offset would
/// overflow the buffer — defensive against display-loop offset
/// arithmetic on edge cases (e.g. underflow when `y == 0`).
fn write_u32_at(buf: &mut Buffer, byte_offset: usize, value: u32) {
    if byte_offset.saturating_add(BYTES_PER_CELL) > buf.len() {
        return;
    }
    let value_le = value.to_le_bytes();
    let slice = buf.as_mut_slice();
    slice[byte_offset..byte_offset + BYTES_PER_CELL].copy_from_slice(&value_le);
}

/// Write a single attribute `u32` into `attr.cells` at index
/// `cell_index`. Returns silently on out-of-bounds — matches the
/// defensive pattern of [`write_u32_at`].
fn write_attr_at(attr: &mut Attributes, cell_index: usize, value: u32) {
    if cell_index >= attr.cells.len() {
        return;
    }
    attr.cells[cell_index] = value;
}

// ============================================================================
// MatrixInner — interior-mutable physics + render state.
// ============================================================================

/// Private state guarded by [`Matrix::inner`]. Holds every "field"
/// listed in the schema's `members_exposed` — six per-stream
/// physics arrays, the active-stream counter, the timer task
/// handle, the timer-active flag, the PRNG state, and the shadow
/// render buffers — so that the spawned tokio task (which only has
/// `&self` access through [`Arc`]) can mutate them via the Mutex.
struct MatrixInner {
    /// FASM `tui_matrix_startx_ofs` (offset +0): per-stream column
    /// position. Ranges from 0 to `width-1` inclusive — set on
    /// stream creation via `rng$intmax(width)` at line 304.
    start_x: [i32; MAX_STREAMS],

    /// FASM `tui_matrix_starty_ofs` (offset +400): per-stream row
    /// position of the head glyph. Set to 0 on creation,
    /// incremented by `update` when `stream_speed` reaches zero.
    start_y: [i32; MAX_STREAMS],

    /// FASM `tui_matrix_lastupdatey_ofs` (offset +800): cached
    /// `start_y` value from the last `display` call. Initialized
    /// to -1 on creation so the first display always renders the
    /// stream. Subsequent displays are skipped if `start_y`
    /// hasn't changed (FASM `tui_matrix.inc` line 410).
    last_update_y: [i32; MAX_STREAMS],

    /// FASM `tui_matrix_streamspeed_ofs` (offset +1200): current
    /// remaining ticks before the stream advances one cell. Each
    /// tick `update` decrements this; when it hits zero the stream
    /// advances and the counter is reloaded from `orig_speed`.
    stream_speed: [i32; MAX_STREAMS],

    /// FASM `tui_matrix_origspeed_ofs` (offset +1600): saved
    /// `stream_speed` reload value. Set on stream creation via
    /// `rng$intmax(5)` and used as the secondary-color shade
    /// scaling factor (`sos`) in the display routine.
    orig_speed: [i32; MAX_STREAMS],

    /// FASM `tui_matrix_streamstatus_ofs` (offset +2000): 0 =
    /// inactive (slot available for new stream), non-zero = active.
    stream_status: [i32; MAX_STREAMS],

    /// FASM `tui_matrix_streamcount_ofs` (offset +2400, 8-byte
    /// reservation though FASM uses dword/i32 access): count of
    /// currently active streams. Bounded by `MAX_STREAMS`.
    stream_count: i64,

    /// Tokio task handle from [`Matrix::start_timer`]. `None` until
    /// the timer is registered. On [`Widget::cleanup`] the handle
    /// is aborted to terminate the spawned task immediately.
    timer: Option<JoinHandle<()>>,

    /// Cooperative-cancellation flag for the spawned task. Set
    /// `true` by [`Matrix::start_timer`] and `false` by
    /// [`Widget::cleanup`]. The spawned task checks this each tick
    /// after upgrading its [`Weak`] reference.
    timer_active: bool,

    /// `xorshift64` state — seeded from the system clock on
    /// construction by [`seed_from_system_time`]. Used for stream
    /// position, fall-speed, and per-cell glyph randomization.
    prng: u64,

    /// Shadow text buffer — same size and layout as the inherited
    /// [`WidgetState::text`] (one `u32` LE code-point per cell).
    /// `tick` writes incremental head/body/tail deltas here; the
    /// next [`Widget::draw`] / [`Widget::timer`] call flushes the
    /// shadow into [`WidgetState::text`] for the renderer to
    /// consume.
    text_shadow: Buffer,

    /// Shadow attribute buffer — paired with [`Self::text_shadow`].
    /// Indexed by cell number (not byte offset), each entry is a
    /// Rust-packed attribute word per [`pack_attr`].
    attr_shadow: Attributes,
}

impl MatrixInner {
    /// Construct fresh `MatrixInner` — every physics array zeroed,
    /// stream count zero, no timer, PRNG seeded from the system
    /// clock, and empty shadow buffers (sized later by
    /// [`Matrix::initial_fill`]).
    fn new() -> Self {
        Self {
            start_x: [0; MAX_STREAMS],
            start_y: [0; MAX_STREAMS],
            last_update_y: [0; MAX_STREAMS],
            stream_speed: [0; MAX_STREAMS],
            orig_speed: [0; MAX_STREAMS],
            stream_status: [0; MAX_STREAMS],
            stream_count: 0,
            timer: None,
            timer_active: false,
            prng: seed_from_system_time(),
            text_shadow: Buffer::default(),
            attr_shadow: Attributes::default(),
        }
    }

    /// FASM `tui_matrix$createdestroy` (lines 268–343): tries to
    /// create AT MOST one new stream, then sweeps all 100 slots
    /// terminating any stream whose `start_y` has run off the
    /// bottom edge plus the [`BACKTRACE`] tail.
    ///
    /// Per FASM line 273 (`cmp dword [rdi+tui_width_ofs], 0; je
    /// .nothingtodo`) the create+destroy phase bails entirely when
    /// `width == 0`. Negative width is treated as "also bail" —
    /// the FASM source never produces negative width but defensive
    /// behavior is preferred per AAP §0.8.3.
    fn createdestroy(&mut self, width: i32, height: i32) {
        if width <= 0 {
            return;
        }
        // Phase 1: try to spawn ONE new stream when not at max.
        // FASM `cmp dword [rdi+tui_matrix_streamcount_ofs],
        // tui_matrix_maxstream; jae .dostops` (line 280).
        if self.stream_count < MAX_STREAMS as i64 {
            // FASM searchloop lines 285–322: find first inactive
            // slot, populate it, jump to dostops.
            for i in 0..MAX_STREAMS {
                if self.stream_status[i] == 0 {
                    self.stream_count += 1;
                    self.stream_status[i] = 1;
                    self.last_update_y[i] = -1;
                    self.start_y[i] = 0;
                    let x = rng_intmax(&mut self.prng, width as u64) as i32;
                    self.start_x[i] = x;
                    let speed = rng_intmax(&mut self.prng, SPEED_RANGE) as i32;
                    self.orig_speed[i] = speed;
                    self.stream_speed[i] = speed;
                    break; // FASM `jmp .dostops` after creating one.
                }
            }
        }
        // Phase 2: terminate streams that have fallen off the
        // bottom edge plus the BACKTRACE tail.
        // FASM stoploop lines 325–343 — limit = height + BACKTRACE,
        // condition `start_y > limit` uses signed compare (`jbe
        // .stopnext`), so we replicate with strict greater-than.
        let limit = height.saturating_add(BACKTRACE);
        for i in 0..MAX_STREAMS {
            if self.stream_status[i] != 0 && self.start_y[i] > limit {
                self.stream_status[i] = 0;
                if self.stream_count > 0 {
                    self.stream_count -= 1;
                }
            }
        }
    }

    /// FASM `tui_matrix$update` (lines 351–388): for each active
    /// stream, decrement `stream_speed`; when it reaches zero
    /// advance `start_y` by 1 and reload `stream_speed` from
    /// `orig_speed`.
    fn update(&mut self) {
        for i in 0..MAX_STREAMS {
            if self.stream_status[i] == 0 {
                continue;
            }
            if self.stream_speed[i] != 0 {
                self.stream_speed[i] -= 1;
            } else {
                self.start_y[i] = self.start_y[i].saturating_add(1);
                self.stream_speed[i] = self.orig_speed[i];
            }
        }
    }

    /// FASM `tui_matrix$display` (lines 397–651): for each active
    /// stream whose `start_y` differs from `last_update_y`,
    /// renders three cells:
    /// 1. head at `(y, x)` with the primary color and a random
    ///    glyph from the half-width kana pool;
    /// 2. body at `(y - 1, x)` with the secondary (dimmer) color
    ///    and a different random glyph;
    /// 3. tail-clear at `(y - BACKTRACE, x)` with a Latin space
    ///    on green-on-black.
    ///
    /// All three write into [`Self::text_shadow`] and
    /// [`Self::attr_shadow`]. The visible state.text /
    /// state.attributes are updated by
    /// [`Matrix::flush_shadow_to_state`].
    fn display(&mut self, width: i32, height: i32) {
        if width <= 0 || height <= 0 {
            return;
        }
        let total_cells = (width as i64).saturating_mul(height as i64);
        if total_cells <= 0 {
            return;
        }
        let total_cells_usize = total_cells as usize;
        let total_bytes = total_cells_usize.saturating_mul(BYTES_PER_CELL);
        // Defensive: if shadow buffers haven't been sized to match
        // current widget dimensions yet (e.g. tick fires before
        // initial_fill resized them), bail rather than write OOB.
        if self.text_shadow.len() < total_bytes
            || self.attr_shadow.cells.len() < total_cells_usize
        {
            return;
        }
        for i in 0..MAX_STREAMS {
            if self.stream_status[i] == 0 {
                continue;
            }
            // FASM line 410: skip if start_y[i] == last_update_y[i].
            if self.start_y[i] == self.last_update_y[i] {
                continue;
            }
            self.last_update_y[i] = self.start_y[i];

            let x = self.start_x[i];
            let y = self.start_y[i];
            let sos = self.orig_speed[i].max(0) as u8;

            // Compute primary and secondary color words once per
            // stream-update. FASM does the same on each .streamloop
            // iteration (lines 458–551).
            let color_primary = primary_color(sos);
            let color_secondary = secondary_color(sos);

            // FASM lines 580–588: pick two random glyphs from the
            // half-width kana pool. CPU_KILLER would also include
            // Latin alphanumerics — preserved as an early branch so
            // toggling the const at compile time switches behavior.
            let char_head = self.next_glyph();
            let char_body = self.next_glyph();

            // Cell 1 — head at (y, x). FASM `.checkfirst` lines
            // 415–457: skips if `y >= height` (`cmp r11d, ecx; jae
            // .checksecond`). Bounds: x must also be in [0, width).
            if y < height && y >= 0 && x >= 0 && x < width {
                let cell_idx = (y as usize).saturating_mul(width as usize)
                    + x as usize;
                let byte_off = cell_idx.saturating_mul(BYTES_PER_CELL);
                write_u32_at(&mut self.text_shadow, byte_off, char_head);
                write_attr_at(&mut self.attr_shadow, cell_idx, color_primary);
            }

            // Cell 2 — body at (y-1, x). FASM `.checksecond` lines
            // 460–505 / 552–579: writes if `y > 0` AND `y <=
            // height` (FASM `cmp r11d, ecx; ja .checkthird; test
            // r11d, r11d; jz .checkthird`). The body cell is one
            // row ABOVE the head, hence (y-1).
            if y > 0 && y <= height && x >= 0 && x < width {
                let body_y = y - 1;
                if body_y >= 0 && body_y < height {
                    let cell_idx = (body_y as usize)
                        .saturating_mul(width as usize)
                        + x as usize;
                    let byte_off = cell_idx.saturating_mul(BYTES_PER_CELL);
                    write_u32_at(&mut self.text_shadow, byte_off, char_body);
                    write_attr_at(
                        &mut self.attr_shadow,
                        cell_idx,
                        color_secondary,
                    );
                }
            }

            // Cell 3 — tail-clear at (y-BACKTRACE, x). FASM
            // `.checkthird` lines 605–651: writes if y >= BACKTRACE
            // AND (y - BACKTRACE) < height. Restores the cell to a
            // green-on-black space, completing the tail erasure.
            if y >= BACKTRACE && x >= 0 && x < width {
                let tail_y = y - BACKTRACE;
                if tail_y >= 0 && tail_y < height {
                    let cell_idx = (tail_y as usize)
                        .saturating_mul(width as usize)
                        + x as usize;
                    let byte_off = cell_idx.saturating_mul(BYTES_PER_CELL);
                    write_u32_at(&mut self.text_shadow, byte_off, TAIL_CHAR);
                    write_attr_at(&mut self.attr_shadow, cell_idx, TAIL_ATTR);
                }
            }
        }
    }

    /// Generate the next display glyph code-point. Half-width kana
    /// (U+FF61..U+FF9F, 62 glyphs per FASM `rng$intmax(62)`) by
    /// default. When [`CPU_KILLER`] is `true`, the pool also
    /// includes Latin alphanumerics — preserved per FASM lines
    /// 71–75 even though the comment says "messy with
    /// Terminal.app".
    fn next_glyph(&mut self) -> u32 {
        if CPU_KILLER {
            // Combined pool: kana(62) + digits(10) + lower(26) +
            // upper(26) = 124 glyphs. Selection is uniform over
            // the full pool.
            const POOL_TOTAL: u64 = KANA_RANGE + 10 + 26 + 26;
            let idx = rng_intmax(&mut self.prng, POOL_TOTAL);
            if idx < KANA_RANGE {
                KANA_BASE + idx as u32
            } else if idx < KANA_RANGE + 10 {
                b'0' as u32 + (idx - KANA_RANGE) as u32
            } else if idx < KANA_RANGE + 10 + 26 {
                b'a' as u32 + (idx - KANA_RANGE - 10) as u32
            } else {
                b'A' as u32 + (idx - KANA_RANGE - 10 - 26) as u32
            }
        } else {
            // Default path — kana only.
            let offset = rng_intmax(&mut self.prng, KANA_RANGE) as u32;
            KANA_BASE + offset
        }
    }
}

// ============================================================================
// Public Matrix widget.
// ============================================================================

/// Matrix-rain animation widget — port of `tui_matrix.inc`.
///
/// The widget fills its container 100 % × 100 % (FASM
/// `tui_object$init_dd(100.0, 100.0)` at line 138) and renders a
/// continuous cascade of green half-width kana glyphs. Each frame
/// — driven by either a tokio task spawned via
/// [`Matrix::start_timer`] or by a framework-level call to
/// [`Widget::timer`] — physics for up to [`MAX_STREAMS`] streams is
/// updated and three cells per active stream are written into
/// shadow buffers; on the next [`Widget::draw`] the shadows are
/// flushed into [`WidgetState::text`] and
/// [`WidgetState::attributes`] for the renderer to consume.
///
/// All mutable state lives inside the private `inner` Mutex; the
/// only direct field on `Matrix` is [`WidgetState`] per the
/// [`Widget`] contract. This mirrors the `widgets/spinner.rs`
/// precedent (`pub(crate) state: WidgetState, inner:
/// Mutex<SpinnerInner>`).
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use tokio::runtime::Runtime;
/// use heavything::tui::widgets::matrix::Matrix;
///
/// let rt = Runtime::new().unwrap();
/// let matrix = Matrix::new();
/// matrix.start_timer(rt.handle());
/// // …add the matrix as a child of your TUI tree…
/// ```
pub struct Matrix {
    /// Inherited Widget state — bounds, text/attr buffers,
    /// children list, etc. Public to the crate per the spinner /
    /// background widget convention so layout helpers can read
    /// `width_percent`, `bounds`, `visible`, etc. without going
    /// through trait dispatch.
    pub(crate) state: WidgetState,

    /// All mutable per-instance physics, render shadow, timer
    /// handle, and PRNG state — Mutex-guarded so the spawned
    /// tokio task (which only has `&self` access via [`Arc`]) can
    /// mutate them.
    inner: Mutex<MatrixInner>,
}

impl Matrix {
    /// Construct a new matrix-rain widget at 100 % × 100 % of its
    /// container, with all stream slots inactive and the timer
    /// **not yet started**. Returns an [`Arc`] so the same
    /// instance can be both inserted into the widget tree and
    /// passed to [`Self::start_timer`] without a deep clone.
    ///
    /// FASM `tui_matrix$new` (lines 132–149):
    /// 1. allocate `tui_matrix_size = 2412` bytes,
    /// 2. call `tui_object$init_dd(self, 100.0, 100.0)` for full
    ///    fill,
    /// 3. install the vtable,
    /// 4. register a 50 ms epoll timer,
    /// 5. call `tui_matrix$initial_fill` to clear stream state.
    ///
    /// In Rust we deliberately split steps 4 and 5 from
    /// construction:
    /// - timer registration is deferred to
    ///   [`Self::start_timer`] so [`Matrix::new`] can be called
    ///   outside a tokio runtime (e.g. inside unit tests or
    ///   during pre-runtime configuration);
    /// - `initial_fill` is called immediately to zero the
    ///   stream-status array. Buffer sizing is deferred until
    ///   `width` and `height` become non-zero (the FASM
    ///   `initial_fill` `.allgood` early-return at line 188 has
    ///   the same effect).
    pub fn new() -> Arc<Self> {
        let mut state = WidgetState::new();
        // FASM `tui_object$init_dd(self, 100.0, 100.0)`. Per
        // AAP §0.5.1.5 and the spacers/background precedent the
        // `width_percent` / `height_percent` convention is
        // `Some(100.0)` for "100 %" — NOT `Some(1.0)`.
        state.width_percent = Some(100.0);
        state.height_percent = Some(100.0);
        let matrix = Arc::new(Self {
            state,
            inner: Mutex::new(MatrixInner::new()),
        });
        // FASM line 145 calls initial_fill from within $new. The
        // call is harmless when width/height are still zero (FASM
        // bails to `.allgood` after clearing stream_status).
        // Errors are ignored here — initial_fill only fails on
        // arithmetic overflow which is impossible at zero
        // dimensions.
        let _ = matrix.initial_fill_internal();
        matrix
    }

    /// FASM `tui_matrix$initial_fill` (lines 182–227): zero the
    /// stream count and all stream-status entries; if `width` and
    /// `height` are both non-zero, fill both [`WidgetState::text`]
    /// and [`WidgetState::attributes`] (and the matching shadow
    /// buffers) with green-on-black space cells.
    ///
    /// Public so callers can re-fill after manually resizing the
    /// widget. Returns [`TuiError::Render`] only on the
    /// arithmetic-overflow paths inside [`fill_u32_buffer`].
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when `width * height *
    /// BYTES_PER_CELL` overflows [`usize`] (impossible on
    /// realistic terminals, defensive only).
    pub fn initial_fill(&mut self) -> Result<(), TuiError> {
        self.initial_fill_internal()
    }

    /// Shared body of [`Self::initial_fill`] and the call from
    /// [`Self::new`]. Takes `&self` so it works through `Arc`
    /// without requiring `&mut`.
    fn initial_fill_internal(&self) -> Result<(), TuiError> {
        let width = self.state.width;
        let height = self.state.height;

        let mut guard = lock_inner_recoverable(&self.inner);
        // FASM lines 184–193: zero stream_count and clear all 100
        // stream_status entries. last_update_y is reset to a
        // sentinel that forces the first display call to redraw.
        guard.stream_count = 0;
        for i in 0..MAX_STREAMS {
            guard.stream_status[i] = 0;
            // We do NOT reset start_x/start_y/etc. here because
            // FASM doesn't either — only stream_status determines
            // whether a slot is active.
            guard.last_update_y[i] = -1;
        }

        // FASM lines 195–198: if width or height is zero, exit
        // after clearing stream state. The buffers are presumably
        // empty too, so there's nothing to fill.
        if width <= 0 || height <= 0 {
            return Ok(());
        }

        let cells = (width as usize).checked_mul(height as usize).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(format!(
                "Matrix::initial_fill: width*height overflowed usize \
                 (width={width}, height={height})"
            )))
        })?;

        // Resize the shadow buffers and fill them with green-on-
        // black space cells. FASM lines 209–224 do the same to
        // the inherited text/attr buffers via memset32. Because
        // this method takes `&self` (callable from Arc), we can
        // only mutate the Mutex-protected shadow here — the
        // visible `state.text` / `state.attributes` are
        // synchronized by `Self::flush_shadow_to_state` which
        // requires `&mut self` access (called from
        // `Widget::draw` and `Widget::timer`).
        fill_u32_buffer(&mut guard.text_shadow, TAIL_CHAR, cells)?;
        fill_u32_attributes(&mut guard.attr_shadow, TAIL_ATTR, cells);

        Ok(())
    }

    /// Copy the shadow buffers into the visible
    /// [`WidgetState::text`] / [`WidgetState::attributes`].
    ///
    /// Called by both [`Widget::draw`] and [`Widget::timer`]
    /// because both have `&mut self` access. After this call the
    /// renderer reading `state.text` / `state.attributes`
    /// observes whatever the most recent
    /// [`MatrixInner::display`] / [`MatrixInner::createdestroy`]
    /// activity wrote.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] on the rare buffer-truncate
    /// failure path. The shadow buffers are bounded by
    /// `width * height * 4` bytes which never overflows for any
    /// realistic terminal.
    fn flush_shadow_to_state(&mut self) -> Result<(), TuiError> {
        let guard = lock_inner_recoverable(&self.inner);
        // Resize state.text to match shadow length — extend with
        // zeros or truncate from the end (matching the FASM
        // `Buffer::truncate` semantics confirmed in
        // `crates/heavything/src/ds/buffer.rs:317`).
        let target_bytes = guard.text_shadow.len();
        if self.state.text.len() < target_bytes {
            self.state.text.reserve(target_bytes - self.state.text.len());
            for _ in self.state.text.len()..target_bytes {
                self.state.text.push(0);
            }
        }
        if self.state.text.len() > target_bytes {
            let to_remove = self.state.text.len() - target_bytes;
            self.state.text.truncate(to_remove).map_err(|e| {
                TuiError::Render(std::io::Error::other(format!(
                    "Matrix::flush_shadow_to_state: state.text truncate \
                     failed: {e:?}"
                )))
            })?;
        }
        // Bulk-copy shadow → state via the byte slice. Both are
        // u8 backing stores; a single memcpy suffices.
        let src = guard.text_shadow.as_slice();
        let dst = self.state.text.as_mut_slice();
        debug_assert_eq!(src.len(), dst.len());
        let n = src.len().min(dst.len());
        dst[..n].copy_from_slice(&src[..n]);

        // Resize and copy attributes.
        let target_cells = guard.attr_shadow.cells.len();
        if self.state.attributes.cells.len() < target_cells {
            self.state.attributes.cells.resize(target_cells, 0);
        } else if self.state.attributes.cells.len() > target_cells {
            self.state.attributes.cells.truncate(target_cells);
        }
        let attr_n = target_cells.min(self.state.attributes.cells.len());
        self.state.attributes.cells[..attr_n]
            .copy_from_slice(&guard.attr_shadow.cells[..attr_n]);
        Ok(())
    }

    /// FASM `tui_matrix$timer` (lines 661–674) — runs one full
    /// 50 ms tick: createdestroy → update → display. Takes
    /// `&self` (not `&mut self`) so it can be invoked from the
    /// spawned tokio task through an [`Arc`]. The shadow buffers
    /// inside [`MatrixInner`] are updated under the Mutex.
    ///
    /// Per the FASM convention this method NEVER signals "stop"
    /// — the FASM equivalent always returns `eax = 0` (line 674)
    /// meaning "reset timer to fire again". Cancellation is
    /// driven exclusively by widget drop or by
    /// [`Widget::cleanup`] flipping
    /// [`MatrixInner::timer_active`].
    pub fn tick(&self) {
        let width = self.state.width;
        let height = self.state.height;
        let mut guard = lock_inner_recoverable(&self.inner);
        guard.createdestroy(width, height);
        guard.update();
        guard.display(width, height);
    }

    /// Register the 50 ms (20 fps) animation ticker with the
    /// supplied tokio runtime. Replaces the FASM
    /// `epoll$timer_new(50ms, self, timer_cb)` call from
    /// `tui_matrix$new` line 142.
    ///
    /// The spawned task holds a [`Weak`] reference to `self` so
    /// it does not keep the widget alive; when the last [`Arc`]
    /// is dropped, the next `Weak::upgrade` call inside the task
    /// returns `None` and the loop exits cleanly. Additionally
    /// the [`MatrixInner::timer_active`] flag — flipped to
    /// `false` by [`Widget::cleanup`] — terminates the loop
    /// cooperatively before the widget is fully dropped.
    ///
    /// Mirrors the [`crate::tui::widgets::effect::Effect::start_timer`]
    /// precedent. Idempotent: calling twice replaces the
    /// previous handle (the old handle is aborted).
    pub fn start_timer(self: &Arc<Self>, rt: &Handle) {
        // Abort any previously-started timer to keep this
        // method idempotent.
        {
            let mut guard = lock_inner_recoverable(&self.inner);
            if let Some(handle) = guard.timer.take() {
                handle.abort();
            }
            guard.timer_active = true;
        }
        let weak_self: Weak<Matrix> = Arc::downgrade(self);
        let interval_ms = TIMER_MS;
        let handle: JoinHandle<()> = rt.spawn(async move {
            let mut ticker = interval(Duration::from_millis(interval_ms));
            // Skip the immediate first tick that `interval` fires
            // — match the FASM convention where
            // `epoll$timer_new(50)` waits 50 ms before the first
            // callback rather than firing instantly.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let arc = match weak_self.upgrade() {
                    Some(a) => a,
                    None => break,
                };
                if !arc.is_timer_active() {
                    break;
                }
                arc.tick();
            }
        });
        let mut guard = lock_inner_recoverable(&self.inner);
        guard.timer = Some(handle);
    }

    /// Read the cooperative-cancellation flag. Public so callers
    /// outside the spawned task (e.g. tests) can verify the
    /// timer state.
    pub fn is_timer_active(&self) -> bool {
        let guard = lock_inner_recoverable(&self.inner);
        guard.timer_active
    }
}

// ============================================================================
// Widget trait implementation.
// ============================================================================

impl Widget for Matrix {
    fn state(&self) -> &WidgetState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// FASM `tui_matrix$cleanup` (lines 167–174) — the only
    /// override-required behavior is to clear the timer
    /// (`epoll$timer_clear`). Per the FASM author's note at
    /// lines 162–164, the timer is GUARANTEED to be valid at
    /// cleanup time because the timer never returns "stop", so
    /// it survives until cleanup runs.
    ///
    /// We additionally inline the trait default's clearing of
    /// children / bastards / text / attributes / display_name to
    /// preserve the same semantics — calling
    /// [`crate::tui::object::cleanup_widget`] from inside a
    /// trait override would re-dispatch through the same trait
    /// method and infinitely recurse.
    fn cleanup(&mut self) {
        // Phase 1: stop the spawned task. Setting `timer_active`
        // to `false` triggers cooperative shutdown; aborting the
        // handle ensures shutdown is immediate even if the task
        // is currently in the middle of an `await`.
        {
            let mut guard = lock_inner_recoverable(&self.inner);
            guard.timer_active = false;
            if let Some(handle) = guard.timer.take() {
                handle.abort();
            }
        }
        // Phase 2: inline the trait-default cleanup body
        // verbatim from `crates/heavything/src/tui/object.rs`
        // lines 686–693 to clear inherited base-widget state.
        let state = self.state_mut();
        state.children.clear();
        state.bastards.clear();
        state.text.clear();
        state.attributes.clear();
        state.display_name.clear();
    }

    /// FASM `tui_matrix$clone` (lines 239–242) — comment at line
    /// 232 explicitly states "we don't ACTUALLY clone, we just
    /// return a brand new one, cloning since there is no useful
    /// state information would be silly". We preserve that
    /// behavior: `clone_widget` just calls [`Matrix::new`].
    ///
    /// The new widget does NOT inherit the timer registration —
    /// callers must explicitly call [`Matrix::start_timer`] on
    /// the clone if they want animation. This mirrors the FASM
    /// behavior where `tui_matrix$new` registers a fresh epoll
    /// timer via `epoll$timer_new`.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        let new_matrix = Matrix::new();
        Ok(new_matrix as Arc<dyn Widget>)
    }

    /// FASM `tui_matrix$draw` (lines 252–258) — call
    /// `initial_fill` to reset stream state and refresh the
    /// canvas with green-on-black space cells, then dispatch
    /// `update_display_list` (a no-op for matrix because it
    /// has no children).
    ///
    /// We additionally call [`Matrix::flush_shadow_to_state`]
    /// after `initial_fill` so the visible buffers are
    /// guaranteed to match the freshly reset shadow.
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        self.initial_fill()?;
        self.flush_shadow_to_state()?;
        // FASM line 257 dispatches `tui_vupdatedisplaylist` —
        // `Widget::update_display_list` defaults to no-op
        // (`crates/heavything/src/tui/object.rs` Widget trait)
        // and matrix has no children, so calling it is harmless.
        self.update_display_list();
        Ok(())
    }

    /// FASM `tui_matrix$timer` (lines 661–674) — a single-tick
    /// drive path callable directly by the framework when no
    /// dedicated tokio task has been registered via
    /// [`Matrix::start_timer`]. Either drive path produces the
    /// same physics+display update; calling both is harmless
    /// (the second call's `last_update_y == start_y` check at
    /// line 410 short-circuits the redundant work).
    ///
    /// After the tick we [`Self::flush_shadow_to_state`] so the
    /// visible buffers reflect the latest deltas immediately —
    /// this is the synchronous drive path's analog to the
    /// `Widget::draw` flush.
    fn timer(&mut self) {
        Matrix::tick(self);
        // Best-effort flush — errors are dropped because
        // `Widget::timer` returns `()` per the trait. Errors
        // here would only surface from buffer-truncate failures
        // which are bounded by widget dimensions and never
        // overflow on realistic inputs.
        let _ = self.flush_shadow_to_state();
    }
}

// ============================================================================
// Tests.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience: build a matrix with explicit dimensions
    /// without invoking the framework's layout pass. The
    /// framework normally writes `state.width` / `state.height`
    /// from the layout engine; tests bypass that by constructing
    /// the struct directly.
    fn make_matrix_with_dims(w: i32, h: i32) -> Arc<Matrix> {
        let mut s = WidgetState::new();
        s.width_percent = Some(100.0);
        s.height_percent = Some(100.0);
        s.width = w;
        s.height = h;
        let m = Matrix {
            state: s,
            inner: Mutex::new(MatrixInner::new()),
        };
        let arc = Arc::new(m);
        let _ = arc.initial_fill_internal();
        arc
    }

    /// Convenience: build a non-`Arc` matrix that the test owns
    /// uniquely (`&mut self` reachable). Used for tests that
    /// drive `Widget::draw`, `Widget::timer`, or `cleanup`.
    fn make_owned_matrix_with_dims(w: i32, h: i32) -> Matrix {
        let mut s = WidgetState::new();
        s.width_percent = Some(100.0);
        s.height_percent = Some(100.0);
        s.width = w;
        s.height = h;
        let m = Matrix {
            state: s,
            inner: Mutex::new(MatrixInner::new()),
        };
        let _ = m.initial_fill_internal();
        m
    }

    /// Minimal renderer that satisfies the `Renderer` trait
    /// without doing any actual I/O. Used by tests that need to
    /// invoke `Widget::draw`.
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

    impl crate::tui::render::Renderer for StubRenderer {
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

    // -- Constants --

    // Compile-time assertions for the constants ported from
    // tui_matrix.inc. Performed at compile time (not runtime) so
    // clippy doesn't flag them as constant-only `assert!` calls.
    const _: () = {
        assert!(MAX_STREAMS == 100, "tui_matrix_maxstream");
        assert!(BACKTRACE == 30, "tui_matrix_backtrace");
        assert!(LEADING == 10, "tui_matrix_leading");
        assert!(SPACE_PAD == 30, "tui_matrix_spacepad");
        assert!(BASE_R == 150, "tui_matrix_r");
        assert!(BASE_G == 255, "tui_matrix_g");
        assert!(BASE_B == 100, "tui_matrix_b");
        assert!(!CPU_KILLER, "tui_matrix_cpukiller=0 default");
        assert!(INC_R == 25, "tui_matrix_incr = 150/6");
        assert!(INC_G == 42, "tui_matrix_incg = 255/6");
        assert!(INC_B == 16, "tui_matrix_incb = 100/6");
        assert!(INC_R_S == 8, "tui_matrix_incr_s = 150/3/6");
        assert!(INC_G_S == 14, "tui_matrix_incg_s = 255/3/6");
        assert!(INC_B_S == 5, "tui_matrix_incb_s = 100/3/6");
        assert!(TIMER_MS == 50, "20fps cadence");
    };

    #[test]
    fn constants_match_fasm() {
        // Runtime check that the const-block above was reached
        // (it executes at compile time, but referencing the
        // constants here ensures they're validated as part of
        // the test suite output).
        assert_eq!(MAX_STREAMS, 100);
        assert_eq!(TIMER_MS, 50);
    }

    // -- Color packing --

    #[test]
    fn pack_attr_layout_matches_rust_convention() {
        // FG in bits 0-7, BG in bits 8-15.
        let v = pack_attr(0xAB, 0xCD);
        assert_eq!(v & 0xff, 0xAB, "fg in low byte");
        assert_eq!((v >> 8) & 0xff, 0xCD, "bg in next byte");
        assert_eq!(v, 0xCDAB);
    }

    #[test]
    fn tail_attr_is_green_on_near_black() {
        // 'green' RGB(0, 255, 0) → palette 46 via rgbi_cube.
        // 'black' RGB(0, 0, 0) → palette 0xe8 (FASM grayscale base).
        // Rust packing: 46 | (0xe8 << 8) = 0xE82E.
        assert_eq!(TAIL_ATTR, 0xE82E);
        assert_eq!(TAIL_ATTR & 0xff, 46, "fg = green palette");
        assert_eq!((TAIL_ATTR >> 8) & 0xff, 0xe8, "bg = near-black");
    }

    #[test]
    fn rgbi_cube_matches_fasm_algorithm() {
        // FASM `ansi_wci_rgbi` cube path: r/43, g/43, b/43 (each
        // mapping to 0..=5 since 255/43 = 5), then b + g*6 + r*36
        // + 16. Spot-check 'green' = RGB(0, 255, 0):
        // r=0/43=0, g=255/43=5, b=0/43=0 → 0 + 30 + 0 + 16 = 46.
        assert_eq!(rgbi_cube(0, 255, 0), 46);
        // RGB(255, 0, 0) → r=5, g=0, b=0 → 0 + 0 + 180 + 16 = 196.
        assert_eq!(rgbi_cube(255, 0, 0), 196);
        // RGB(0, 0, 255) → r=0, g=0, b=5 → 5 + 0 + 0 + 16 = 21.
        assert_eq!(rgbi_cube(0, 0, 255), 21);
        // BASE matrix-rain green: RGB(150, 255, 100). r=3, g=5,
        // b=2 → 2 + 30 + 108 + 16 = 156.
        assert_eq!(rgbi_cube(BASE_R, BASE_G, BASE_B), 156);
    }

    #[test]
    fn primary_color_matches_fasm_for_each_speed() {
        // Compute for each `sos` in 0..5 (the range produced by
        // rng$intmax(5)). Algebra mirrors FASM exactly.
        for sos in 0u8..5 {
            let r = BASE_R - sos * INC_R;
            let g = BASE_G - sos * INC_G;
            let b = BASE_B - sos * INC_B;
            let fg_expected = (b / 43) + (g / 43) * 6 + (r / 43) * 36 + 16;
            let expected = (fg_expected as u32) | ((BG_NEAR_BLACK as u32) << 8);
            assert_eq!(
                primary_color(sos),
                expected,
                "sos={sos}: r={r} g={g} b={b} fg={fg_expected}"
            );
        }
    }

    #[test]
    fn secondary_color_matches_fasm_for_each_speed() {
        for sos in 0u8..5 {
            let r = (BASE_R / 3) - sos * INC_R_S;
            let g = (BASE_G / 3) - sos * INC_G_S;
            let b = (BASE_B / 3) - sos * INC_B_S;
            let fg_expected = (b / 43) + (g / 43) * 6 + (r / 43) * 36 + 16;
            let expected = (fg_expected as u32) | ((BG_NEAR_BLACK as u32) << 8);
            assert_eq!(
                secondary_color(sos),
                expected,
                "sos={sos}: r={r} g={g} b={b} fg={fg_expected}"
            );
        }
    }

    #[test]
    fn primary_secondary_no_underflow_for_valid_sos() {
        // FASM algebra never produces negative channel values for
        // sos in [0, 4]. We use saturating_sub defensively, but
        // the saturation should never trigger. We verify by
        // checking that the sub doesn't saturate to zero
        // unexpectedly: for sos==4, the smallest result is
        // BASE_R - 4*INC_R = 150 - 100 = 50.
        for sos in 0u8..5 {
            let r1 = BASE_R.saturating_sub(sos * INC_R);
            let g1 = BASE_G.saturating_sub(sos * INC_G);
            let b1 = BASE_B.saturating_sub(sos * INC_B);
            // Direct sub equals saturating sub iff no underflow.
            assert_eq!(r1, BASE_R - sos * INC_R, "primary R underflow at sos={sos}");
            assert_eq!(g1, BASE_G - sos * INC_G, "primary G underflow at sos={sos}");
            assert_eq!(b1, BASE_B - sos * INC_B, "primary B underflow at sos={sos}");

            let r2 = (BASE_R / 3).saturating_sub(sos * INC_R_S);
            let g2 = (BASE_G / 3).saturating_sub(sos * INC_G_S);
            let b2 = (BASE_B / 3).saturating_sub(sos * INC_B_S);
            assert_eq!(r2, (BASE_R / 3) - sos * INC_R_S, "secondary R underflow at sos={sos}");
            assert_eq!(g2, (BASE_G / 3) - sos * INC_G_S, "secondary G underflow at sos={sos}");
            assert_eq!(b2, (BASE_B / 3) - sos * INC_B_S, "secondary B underflow at sos={sos}");
        }
    }

    // -- PRNG --

    #[test]
    fn xorshift64_advances_state() {
        let mut s = 0xDEAD_BEEF_CAFE_F00Du64;
        let a = xorshift64(&mut s);
        let b = xorshift64(&mut s);
        let c = xorshift64(&mut s);
        // Three consecutive samples should not all be equal —
        // xorshift64 has period 2^64-1.
        assert!(a != b || b != c, "xorshift64 stuck on a value");
    }

    #[test]
    fn xorshift64_recovers_from_zero_state() {
        // Zero is the degenerate fixed point of xorshift64.
        // Our helper reseeds with the golden ratio constant on
        // entry to avoid getting stuck.
        let mut s = 0u64;
        let a = xorshift64(&mut s);
        assert_ne!(a, 0, "zero attractor must be escaped");
        let b = xorshift64(&mut s);
        assert_ne!(b, a, "must produce distinct successive values");
    }

    #[test]
    fn rng_intmax_in_range() {
        let mut s = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..1000 {
            assert!(rng_intmax(&mut s, 5) < 5, "rng_intmax(5) out of range");
            assert!(
                rng_intmax(&mut s, 62) < 62,
                "rng_intmax(62) out of range"
            );
        }
    }

    #[test]
    fn rng_intmax_zero_returns_zero() {
        let mut s = 1u64;
        assert_eq!(rng_intmax(&mut s, 0), 0);
    }

    // -- Construction --

    #[test]
    fn new_creates_full_size_matrix() {
        let m = Matrix::new();
        assert_eq!(m.state.width_percent, Some(100.0));
        assert_eq!(m.state.height_percent, Some(100.0));
        assert_eq!(m.state.width, 0, "no layout pass yet");
        assert_eq!(m.state.height, 0, "no layout pass yet");
        assert!(!m.is_timer_active(), "timer not started by new()");
    }

    #[test]
    fn new_initializes_streams_inactive() {
        let m = Matrix::new();
        let guard = lock_inner_recoverable(&m.inner);
        assert_eq!(guard.stream_count, 0);
        for i in 0..MAX_STREAMS {
            assert_eq!(guard.stream_status[i], 0, "slot {i} should be inactive");
            assert_eq!(guard.last_update_y[i], -1, "slot {i} sentinel");
        }
    }

    #[test]
    fn new_seeds_prng_nonzero() {
        let m = Matrix::new();
        let guard = lock_inner_recoverable(&m.inner);
        assert_ne!(guard.prng, 0, "prng seeded from system time");
    }

    // -- initial_fill --

    #[test]
    fn initial_fill_with_zero_dims_clears_streams_only() {
        let m = make_matrix_with_dims(0, 0);
        let guard = lock_inner_recoverable(&m.inner);
        // Buffers stay empty when dims are zero.
        assert_eq!(guard.text_shadow.len(), 0);
        assert_eq!(guard.attr_shadow.cells.len(), 0);
    }

    #[test]
    fn initial_fill_with_real_dims_sizes_shadow() {
        let m = make_matrix_with_dims(80, 24);
        let guard = lock_inner_recoverable(&m.inner);
        assert_eq!(guard.text_shadow.len(), 80 * 24 * BYTES_PER_CELL);
        assert_eq!(guard.attr_shadow.cells.len(), 80 * 24);
        // All cells should be green-on-black space.
        for chunk in guard.text_shadow.as_slice().chunks_exact(BYTES_PER_CELL) {
            let v = u32::from_le_bytes(chunk.try_into().unwrap());
            assert_eq!(v, b' ' as u32);
        }
        for &cell in guard.attr_shadow.cells.iter() {
            assert_eq!(cell, TAIL_ATTR);
        }
    }

    // -- createdestroy --

    #[test]
    fn createdestroy_spawns_one_stream_per_call() {
        let m = make_matrix_with_dims(80, 24);
        // Each call should bring the count from N to N+1, up to
        // MAX_STREAMS, then plateau.
        for n in 1..=10 {
            {
                let mut guard = lock_inner_recoverable(&m.inner);
                guard.createdestroy(80, 24);
            }
            let guard = lock_inner_recoverable(&m.inner);
            assert_eq!(guard.stream_count, n as i64);
        }
    }

    #[test]
    fn createdestroy_caps_at_max_streams() {
        let m = make_matrix_with_dims(80, 24);
        for _ in 0..MAX_STREAMS + 50 {
            let mut guard = lock_inner_recoverable(&m.inner);
            guard.createdestroy(80, 24);
        }
        let guard = lock_inner_recoverable(&m.inner);
        assert_eq!(guard.stream_count, MAX_STREAMS as i64);
        // All slots should be active.
        for i in 0..MAX_STREAMS {
            assert!(guard.stream_status[i] != 0, "slot {i}");
        }
    }

    #[test]
    fn createdestroy_zero_width_is_noop() {
        let m = make_matrix_with_dims(80, 24);
        // Force zero width on the matrix's view.
        let mut guard = lock_inner_recoverable(&m.inner);
        guard.createdestroy(0, 24);
        assert_eq!(guard.stream_count, 0, "no stream created at width=0");
    }

    #[test]
    fn createdestroy_terminates_off_screen_streams() {
        let m = make_matrix_with_dims(80, 24);
        // Manually spawn a stream then push it past height+BACKTRACE.
        {
            let mut guard = lock_inner_recoverable(&m.inner);
            guard.createdestroy(80, 24); // creates slot 0
            assert_eq!(guard.stream_count, 1);
            // Push slot 0 past the limit.
            guard.start_y[0] = 24 + BACKTRACE + 1;
        }
        {
            let mut guard = lock_inner_recoverable(&m.inner);
            // createdestroy should both spawn a new stream (slot 1)
            // AND terminate the off-screen slot 0 in the same call.
            guard.createdestroy(80, 24);
            // Net: stream_count = 1 (new slot active, slot 0 dead)
            assert_eq!(guard.stream_count, 1);
            assert_eq!(guard.stream_status[0], 0, "slot 0 terminated");
        }
    }

    // -- update --

    #[test]
    fn update_decrements_speed_until_zero() {
        let m = make_matrix_with_dims(80, 24);
        let mut guard = lock_inner_recoverable(&m.inner);
        // Spawn a deterministic stream with speed=2.
        guard.stream_status[0] = 1;
        guard.stream_speed[0] = 2;
        guard.orig_speed[0] = 2;
        guard.start_y[0] = 5;
        guard.stream_count = 1;
        // Tick 1: speed=1, y=5
        guard.update();
        assert_eq!(guard.stream_speed[0], 1);
        assert_eq!(guard.start_y[0], 5);
        // Tick 2: speed=0, y=5
        guard.update();
        assert_eq!(guard.stream_speed[0], 0);
        assert_eq!(guard.start_y[0], 5);
        // Tick 3: speed reload, y=6
        guard.update();
        assert_eq!(guard.start_y[0], 6);
        assert_eq!(guard.stream_speed[0], 2);
    }

    #[test]
    fn update_skips_inactive_streams() {
        let m = make_matrix_with_dims(80, 24);
        let mut guard = lock_inner_recoverable(&m.inner);
        // No streams active.
        let original_y = guard.start_y;
        guard.update();
        for (i, &original) in original_y.iter().enumerate() {
            assert_eq!(guard.start_y[i], original, "slot {i} should not move");
        }
    }

    // -- display --

    #[test]
    fn display_skips_when_y_unchanged() {
        let m = make_matrix_with_dims(80, 24);
        let mut guard = lock_inner_recoverable(&m.inner);
        // Spawn deterministic stream with start_y == last_update_y.
        guard.stream_status[0] = 1;
        guard.start_y[0] = 5;
        guard.last_update_y[0] = 5; // same — should skip
        guard.start_x[0] = 10;
        guard.orig_speed[0] = 0;
        guard.stream_count = 1;
        // Snapshot a cell that would be touched if display ran.
        let cell_idx = 5 * 80 + 10;
        let original_attr = guard.attr_shadow.cells[cell_idx];
        guard.display(80, 24);
        // Cell unchanged.
        assert_eq!(guard.attr_shadow.cells[cell_idx], original_attr);
    }

    #[test]
    fn display_writes_head_body_tail_cells() {
        // Need height > BACKTRACE+5 = 35 so head and body are
        // on-screen. We use 80x80 so the shadow has the right
        // capacity (80*80*4 = 25_600 bytes).
        let m = make_matrix_with_dims(80, 80);
        let mut guard = lock_inner_recoverable(&m.inner);
        // Spawn a stream where all three cells will be visible.
        // y >= BACKTRACE so tail is on-screen; y < height so head
        // is visible; y > 0 && y <= height so body is visible.
        guard.stream_status[0] = 1;
        guard.start_y[0] = BACKTRACE + 5; // 35
        guard.last_update_y[0] = -1; // forces redraw
        guard.start_x[0] = 10;
        guard.orig_speed[0] = 2;
        guard.stream_count = 1;
        guard.display(80, 80);
        // Head at (35, 10)
        let head_idx = 35 * 80 + 10;
        assert_ne!(
            guard.text_shadow.as_slice()
                [head_idx * BYTES_PER_CELL..head_idx * BYTES_PER_CELL + 4],
            [b' ', 0, 0, 0],
            "head cell should be a kana glyph, not space"
        );
        // Body at (34, 10)
        let body_idx = 34 * 80 + 10;
        assert_ne!(
            guard.text_shadow.as_slice()
                [body_idx * BYTES_PER_CELL..body_idx * BYTES_PER_CELL + 4],
            [b' ', 0, 0, 0],
            "body cell should be a kana glyph, not space"
        );
        // Tail at (5, 10) (35 - BACKTRACE = 5)
        let tail_idx = 5 * 80 + 10;
        let tail_bytes = &guard.text_shadow.as_slice()
            [tail_idx * BYTES_PER_CELL..tail_idx * BYTES_PER_CELL + 4];
        assert_eq!(
            tail_bytes,
            &(b' ' as u32).to_le_bytes()[..],
            "tail-clear cell should be a Latin space"
        );
        assert_eq!(
            guard.attr_shadow.cells[tail_idx], TAIL_ATTR,
            "tail-clear cell should have green-on-black attr"
        );
        // After display, last_update_y[0] should equal start_y[0].
        assert_eq!(guard.last_update_y[0], BACKTRACE + 5);
    }

    #[test]
    fn display_skips_off_screen_head() {
        // y >= height — head not drawn but tail should still clear.
        let m = make_matrix_with_dims(80, 24);
        let mut guard = lock_inner_recoverable(&m.inner);
        guard.stream_status[0] = 1;
        guard.start_y[0] = 25; // y == height? FASM: jae .checksecond
                               // means y >= height skips head.
        guard.last_update_y[0] = -1;
        guard.start_x[0] = 10;
        guard.orig_speed[0] = 0;
        guard.stream_count = 1;
        guard.display(80, 24);
        // Head at (25, 10) is off-screen for height=24.
        // Body at (24, 10) where y=25, body_y=24, but body_y must
        // be < height so body is also off-screen.
        // Tail at (25 - 30, 10) = negative → skipped.
        // Net: nothing should have been written; only
        // last_update_y advanced.
        assert_eq!(guard.last_update_y[0], 25);
    }

    // -- Widget trait --

    #[test]
    fn widget_state_accessors() {
        let m = make_matrix_with_dims(80, 24);
        // Cast back to a concrete reference for state() / state_mut().
        // Through Arc we can only state(); state_mut() requires
        // unique ownership so we drop into a fresh non-Arc.
        let r: &dyn Widget = m.as_ref();
        assert_eq!(r.state().width, 80);
        assert_eq!(r.state().height, 24);
        let downcast = r.as_any().downcast_ref::<Matrix>();
        assert!(downcast.is_some());
    }

    #[test]
    fn widget_clone_returns_fresh_matrix() {
        let m = make_matrix_with_dims(80, 24);
        // Spawn a stream so we can verify the clone has fresh
        // state.
        {
            let mut guard = lock_inner_recoverable(&m.inner);
            guard.createdestroy(80, 24);
            assert_eq!(guard.stream_count, 1);
        }
        let widget: &dyn Widget = m.as_ref();
        let cloned = widget.clone_widget().unwrap();
        let clone_matrix = cloned.as_any().downcast_ref::<Matrix>().unwrap();
        // Clone should NOT inherit stream state.
        let guard = lock_inner_recoverable(&clone_matrix.inner);
        assert_eq!(guard.stream_count, 0, "clone has fresh stream state");
        for i in 0..MAX_STREAMS {
            assert_eq!(guard.stream_status[i], 0);
        }
    }

    #[test]
    fn widget_draw_resets_state() {
        let mut m = make_owned_matrix_with_dims(80, 24);
        // Manually populate stream state to simulate prior activity.
        {
            let mut guard = lock_inner_recoverable(&m.inner);
            guard.stream_status[0] = 1;
            guard.stream_count = 1;
            guard.start_y[0] = 10;
        }

        let mut r = StubRenderer::new();
        m.draw(&mut r).unwrap();

        // After draw: stream state cleared, state.text and
        // state.attributes filled with green-on-black space.
        let guard = lock_inner_recoverable(&m.inner);
        assert_eq!(guard.stream_count, 0);
        for i in 0..MAX_STREAMS {
            assert_eq!(guard.stream_status[i], 0);
        }
        assert_eq!(m.state.text.len(), 80 * 24 * BYTES_PER_CELL);
        assert_eq!(m.state.attributes.cells.len(), 80 * 24);
        // Spot-check a cell.
        let head_bytes = &m.state.text.as_slice()[0..4];
        assert_eq!(head_bytes, &(b' ' as u32).to_le_bytes()[..]);
        assert_eq!(m.state.attributes.cells[0], TAIL_ATTR);
    }

    #[test]
    fn widget_timer_drives_physics_and_flushes() {
        let mut m = make_owned_matrix_with_dims(80, 24);
        m.timer();
        // After one tick: at least one stream should have been
        // created.
        let guard = lock_inner_recoverable(&m.inner);
        assert_eq!(guard.stream_count, 1, "one stream per createdestroy");
        // Visible state should match shadow.
        assert_eq!(
            m.state.text.len(),
            guard.text_shadow.len(),
            "state.text resized to match shadow"
        );
        assert_eq!(
            m.state.attributes.cells.len(),
            guard.attr_shadow.cells.len()
        );
    }

    #[test]
    fn widget_cleanup_clears_state_and_disables_timer() {
        let mut owned = make_owned_matrix_with_dims(0, 0);
        // Populate something so we can verify cleanup clears it.
        owned.state.display_name = String::from("matrix-test");
        owned.state.text.push(b'A');
        owned.state.attributes.cells.push(0xDEAD_BEEF);
        // Set timer_active manually — no spawned task yet.
        {
            let mut guard = lock_inner_recoverable(&owned.inner);
            guard.timer_active = true;
        }
        owned.cleanup();
        let guard = lock_inner_recoverable(&owned.inner);
        assert!(!guard.timer_active, "cleanup disables timer flag");
        assert!(guard.timer.is_none(), "cleanup aborts and drops handle");
        assert!(owned.state.display_name.is_empty());
        assert!(owned.state.text.is_empty());
        assert!(owned.state.attributes.cells.is_empty());
    }

    // -- start_timer + tokio integration --

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn start_timer_registers_handle_and_can_be_torn_down() {
        let m = Matrix::new();
        let rt = Handle::current();
        m.start_timer(&rt);
        assert!(m.is_timer_active(), "start_timer flips timer_active true");
        // Verify timer JoinHandle was stored.
        {
            let guard = lock_inner_recoverable(&m.inner);
            assert!(guard.timer.is_some(), "JoinHandle persisted");
        }
        // Unique ownership for cleanup. We drop `rt` reference
        // first.
        let mut owned = Arc::try_unwrap(m).map_err(|_| ()).unwrap();
        owned.cleanup();
        assert!(!owned.is_timer_active());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn start_timer_idempotent_replaces_handle() {
        let m = Matrix::new();
        let rt = Handle::current();
        m.start_timer(&rt);
        let first_handle_present = {
            let guard = lock_inner_recoverable(&m.inner);
            // `JoinHandle` doesn't implement PartialEq; comparison
            // is by handle pointer-existence.
            guard.timer.is_some()
        };
        assert!(first_handle_present);
        // Calling again should abort the first and store the
        // second.
        m.start_timer(&rt);
        let guard = lock_inner_recoverable(&m.inner);
        assert!(guard.timer.is_some());
        assert!(guard.timer_active);
    }
}
