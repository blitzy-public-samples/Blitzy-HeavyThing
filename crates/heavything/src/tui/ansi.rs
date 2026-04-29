// crates/heavything/src/tui/ansi.rs — HeavyThing TUI ANSI escape constants.
//
// Rust translation of tui_ansi.inc (1,212 lines of FASM assembly). Pure
// data module: cursor / screen / color / attribute / ACS / mode escape
// sequences as &'static [u8] constants, plus helper functions that emit
// parametric sequences (e.g. move_cursor_to(x, y), set_fg_256(n),
// set_fg_rgb(r, g, b)).
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

//! ANSI escape constants and formatters for terminal output.
//!
//! All byte-string constants are `&'static [u8]` because
//! [`crate::tui::render::Renderer`] operates on raw bytes rather than
//! `&str` (escape sequences are pre-validated ASCII and we want to avoid
//! redundant UTF-8 validation on every emit). The constants cover:
//!
//! - Screen buffer switching (alternate screen enter/exit)
//! - Cursor show/hide, save/restore, home, absolute move
//! - Clear screen, clear line, clear-to-EOL, clear-to-EOS
//! - SGR reset, bold, dim, italic, underline, reverse, blink,
//!   strikethrough and their `*_OFF` counterparts
//! - VT100 ACS line-drawing enable/disable plus the 11 line-drawing
//!   glyph bytes emitted between [`ACS_ENTER`] and [`ACS_EXIT`]
//! - Unicode box-drawing fallback codepoints used when the renderer is
//!   configured to bypass ACS mode
//!
//! Parametric escape sequences (cursor movement, 256-color / 24-bit RGB
//! SGR) are emitted via helper functions taking `&mut dyn BufMut` so
//! callers can append directly into [`bytes::BytesMut`] or `Vec<u8>`
//! without any intermediate allocation.
//!
//! The companion [`rgb_to_256`] function approximates a 24-bit RGB
//! triple as a 256-color palette index using the exact two-branch
//! arithmetic of the FASM `ansi_wci_rgbi` macro from `tui_ansi.inc`,
//! ported verbatim per AAP §0.4.4 (TUI tables and arithmetic ported
//! verbatim to preserve identical behavior across translations). See
//! the function's doc comment for the full algorithm.

use bytes::BufMut;

// =====================================================================
// Prefixes
// =====================================================================

/// CSI (Control Sequence Introducer) — `ESC[`. Emitted at the start of
/// every parametric CSI sequence.
pub const CSI: &[u8] = b"\x1b[";

/// Bare ESC (`0x1b`). Useful as a building block for non-CSI sequences
/// such as the DECSC/DECRC cursor save/restore or the `ESC(0` /
/// `ESC(B` VT100 G0 charset switches.
pub const ESC: &[u8] = b"\x1b";

// =====================================================================
// Screen buffer switching
// =====================================================================

/// Enter the alternate screen buffer (`ESC[?1049h`). Paired with
/// [`ALT_SCREEN_EXIT`] on shutdown so the user's scrollback is preserved.
pub const ALT_SCREEN_ENTER: &[u8] = b"\x1b[?1049h";

/// Exit the alternate screen buffer (`ESC[?1049l`). Restores the
/// user's prior screen contents.
pub const ALT_SCREEN_EXIT: &[u8] = b"\x1b[?1049l";

// =====================================================================
// Cursor visibility and position
// =====================================================================

/// Show the cursor (`ESC[?25h`).
pub const SHOW_CURSOR: &[u8] = b"\x1b[?25h";

/// Hide the cursor (`ESC[?25l`). Typically emitted at TUI startup to
/// prevent cursor flicker during re-rendering.
pub const HIDE_CURSOR: &[u8] = b"\x1b[?25l";

/// Move cursor to (1, 1) home position (`ESC[H`).
pub const CURSOR_HOME: &[u8] = b"\x1b[H";

/// Save cursor position (`ESC7` — DECSC). Paired with [`CURSOR_RESTORE`].
pub const CURSOR_SAVE: &[u8] = b"\x1b7";

/// Restore cursor position (`ESC8` — DECRC). Pairs with [`CURSOR_SAVE`].
pub const CURSOR_RESTORE: &[u8] = b"\x1b8";

// =====================================================================
// Clearing
// =====================================================================

/// Clear entire screen (`ESC[2J`).
pub const CLEAR_SCREEN: &[u8] = b"\x1b[2J";

/// Clear the entire current line (`ESC[2K`).
pub const CLEAR_LINE: &[u8] = b"\x1b[2K";

/// Clear from cursor to end of line (`ESC[K`, same as `ESC[0K`).
pub const CLEAR_TO_EOL: &[u8] = b"\x1b[K";

/// Clear from cursor to end of screen (`ESC[J`, same as `ESC[0J`).
pub const CLEAR_TO_EOS: &[u8] = b"\x1b[J";

// =====================================================================
// SGR (Select Graphic Rendition)
// =====================================================================

/// Reset all attributes and colors (`ESC[0m`).
pub const SGR_RESET: &[u8] = b"\x1b[0m";

/// Bold on (`ESC[1m`).
pub const SGR_BOLD: &[u8] = b"\x1b[1m";

/// Dim / faint on (`ESC[2m`).
pub const SGR_DIM: &[u8] = b"\x1b[2m";

/// Italic on (`ESC[3m`). Not universally supported by every terminal
/// but emitted verbatim to match FASM behavior.
pub const SGR_ITALIC: &[u8] = b"\x1b[3m";

/// Underline on (`ESC[4m`).
pub const SGR_UNDERLINE: &[u8] = b"\x1b[4m";

/// Blink on (`ESC[5m`).
pub const SGR_BLINK: &[u8] = b"\x1b[5m";

/// Reverse / inverse video on (`ESC[7m`).
pub const SGR_REVERSE: &[u8] = b"\x1b[7m";

/// Strikethrough on (`ESC[9m`).
pub const SGR_STRIKETHROUGH: &[u8] = b"\x1b[9m";

/// Bold off (`ESC[22m`). Also disables dim because both share the same
/// off-bit in the SGR model.
pub const SGR_BOLD_OFF: &[u8] = b"\x1b[22m";

/// Underline off (`ESC[24m`).
pub const SGR_UNDERLINE_OFF: &[u8] = b"\x1b[24m";

/// Blink off (`ESC[25m`).
pub const SGR_BLINK_OFF: &[u8] = b"\x1b[25m";

/// Reverse off (`ESC[27m`).
pub const SGR_REVERSE_OFF: &[u8] = b"\x1b[27m";

// =====================================================================
// VT100 ACS (Alternate Character Set) — line drawing
// =====================================================================
//
// When `crate::config::ACS_LINECHARS` is true, the renderer switches
// to the VT100 line-drawing alternate character set by emitting
// [`ACS_ENTER`], sends the bytes below (0x6a..0x78) for box-drawing,
// and emits [`ACS_EXIT`] to return to US-ASCII. When the flag is
// false, the renderer emits the [`UNICODE_*`](UNICODE_HLINE) codepoints
// as UTF-8 instead.

/// Enter ACS (VT100) line-drawing mode (`ESC(0`). Selects the special
/// graphics character set as G0.
pub const ACS_ENTER: &[u8] = b"\x1b(0";

/// Exit ACS line-drawing mode (`ESC(B`). Restores US-ASCII as G0.
pub const ACS_EXIT: &[u8] = b"\x1b(B";

/// Lower-right corner (`j`) in ACS mode — renders as ┘.
pub const ACS_LRCORNER: u8 = b'j';

/// Upper-right corner (`k`) in ACS mode — renders as ┐.
pub const ACS_URCORNER: u8 = b'k';

/// Upper-left corner (`l`) in ACS mode — renders as ┌.
pub const ACS_ULCORNER: u8 = b'l';

/// Lower-left corner (`m`) in ACS mode — renders as └.
pub const ACS_LLCORNER: u8 = b'm';

/// Four-way crossing / plus (`n`) in ACS mode — renders as ┼.
pub const ACS_PLUS: u8 = b'n';

/// Horizontal line (`q`) in ACS mode — renders as ─.
pub const ACS_HLINE: u8 = b'q';

/// Left tee (`t`) in ACS mode — renders as ├.
pub const ACS_LTEE: u8 = b't';

/// Right tee (`u`) in ACS mode — renders as ┤.
pub const ACS_RTEE: u8 = b'u';

/// Top tee (`w`) in ACS mode — renders as ┬.
pub const ACS_TTEE: u8 = b'w';

/// Vertical line (`x`) in ACS mode — renders as │.
pub const ACS_VLINE: u8 = b'x';

/// Bottom tee (`v`) in ACS mode — renders as ┴.
pub const ACS_BTEE: u8 = b'v';

// =====================================================================
// Unicode box-drawing fallback (used when ACS_LINECHARS is false)
// =====================================================================

/// `─` U+2500 BOX DRAWINGS LIGHT HORIZONTAL.
pub const UNICODE_HLINE: char = '─';

/// `│` U+2502 BOX DRAWINGS LIGHT VERTICAL.
pub const UNICODE_VLINE: char = '│';

/// `┌` U+250C BOX DRAWINGS LIGHT DOWN AND RIGHT.
pub const UNICODE_ULCORNER: char = '┌';

/// `┐` U+2510 BOX DRAWINGS LIGHT DOWN AND LEFT.
pub const UNICODE_URCORNER: char = '┐';

/// `└` U+2514 BOX DRAWINGS LIGHT UP AND RIGHT.
pub const UNICODE_LLCORNER: char = '└';

/// `┘` U+2518 BOX DRAWINGS LIGHT UP AND LEFT.
pub const UNICODE_LRCORNER: char = '┘';

/// `┤` U+2524 BOX DRAWINGS LIGHT VERTICAL AND LEFT.
pub const UNICODE_RTEE: char = '┤';

/// `├` U+251C BOX DRAWINGS LIGHT VERTICAL AND RIGHT.
pub const UNICODE_LTEE: char = '├';

/// `┴` U+2534 BOX DRAWINGS LIGHT UP AND HORIZONTAL.
pub const UNICODE_BTEE: char = '┴';

/// `┬` U+252C BOX DRAWINGS LIGHT DOWN AND HORIZONTAL.
pub const UNICODE_TTEE: char = '┬';

/// `┼` U+253C BOX DRAWINGS LIGHT VERTICAL AND HORIZONTAL.
pub const UNICODE_PLUS: char = '┼';

// =====================================================================
// Parametric formatters
// =====================================================================

/// Append the ASCII decimal representation of `n` into `out` without
/// heap allocation.
///
/// Used internally by every parametric formatter (move cursor, 256-color
/// SGR, truecolor SGR). A 10-byte stack buffer is sufficient for every
/// `u32` value (`u32::MAX` = `4_294_967_295` is 10 digits). This deliberately
/// avoids pulling in an `itoa` dependency and avoids the allocation
/// overhead of `format!` / `write!`.
fn push_u32(out: &mut dyn BufMut, n: u32) {
    // Digits are emitted into `buf` right-to-left, then the populated
    // sub-slice `buf[idx..]` is appended to the sink in one call.
    let mut buf = [0u8; 10];
    let mut idx = 10usize;
    let mut v = n;
    if v == 0 {
        out.put_u8(b'0');
        return;
    }
    while v > 0 {
        idx -= 1;
        buf[idx] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    out.put_slice(&buf[idx..]);
}

/// Move cursor to absolute position `(row, col)`. Emits `ESC[<row>;<col>H`.
///
/// Coordinates are 1-based (the terminal convention); callers holding
/// 0-based coordinates must add 1 before calling. The FASM equivalent is
/// `tui_ansi$move_cursor`.
pub fn move_cursor_to(out: &mut dyn BufMut, row: u32, col: u32) {
    out.put_slice(CSI);
    push_u32(out, row);
    out.put_u8(b';');
    push_u32(out, col);
    out.put_u8(b'H');
}

/// Move cursor up `n` rows. Emits `ESC[<n>A`.
pub fn cursor_up(out: &mut dyn BufMut, n: u32) {
    out.put_slice(CSI);
    push_u32(out, n);
    out.put_u8(b'A');
}

/// Move cursor down `n` rows. Emits `ESC[<n>B`.
pub fn cursor_down(out: &mut dyn BufMut, n: u32) {
    out.put_slice(CSI);
    push_u32(out, n);
    out.put_u8(b'B');
}

/// Move cursor forward (right) `n` columns. Emits `ESC[<n>C`.
pub fn cursor_forward(out: &mut dyn BufMut, n: u32) {
    out.put_slice(CSI);
    push_u32(out, n);
    out.put_u8(b'C');
}

/// Move cursor backward (left) `n` columns. Emits `ESC[<n>D`.
pub fn cursor_backward(out: &mut dyn BufMut, n: u32) {
    out.put_slice(CSI);
    push_u32(out, n);
    out.put_u8(b'D');
}

/// Set foreground to 256-color palette index `n`. Emits `ESC[38;5;<n>m`.
pub fn set_fg_256(out: &mut dyn BufMut, n: u8) {
    out.put_slice(b"\x1b[38;5;");
    push_u32(out, u32::from(n));
    out.put_u8(b'm');
}

/// Set background to 256-color palette index `n`. Emits `ESC[48;5;<n>m`.
pub fn set_bg_256(out: &mut dyn BufMut, n: u8) {
    out.put_slice(b"\x1b[48;5;");
    push_u32(out, u32::from(n));
    out.put_u8(b'm');
}

/// Set foreground to 24-bit RGB `(r, g, b)`. Emits `ESC[38;2;<r>;<g>;<b>m`.
pub fn set_fg_rgb(out: &mut dyn BufMut, r: u8, g: u8, b: u8) {
    out.put_slice(b"\x1b[38;2;");
    push_u32(out, u32::from(r));
    out.put_u8(b';');
    push_u32(out, u32::from(g));
    out.put_u8(b';');
    push_u32(out, u32::from(b));
    out.put_u8(b'm');
}

/// Set background to 24-bit RGB `(r, g, b)`. Emits `ESC[48;2;<r>;<g>;<b>m`.
pub fn set_bg_rgb(out: &mut dyn BufMut, r: u8, g: u8, b: u8) {
    out.put_slice(b"\x1b[48;2;");
    push_u32(out, u32::from(r));
    out.put_u8(b';');
    push_u32(out, u32::from(g));
    out.put_u8(b';');
    push_u32(out, u32::from(b));
    out.put_u8(b'm');
}

// =====================================================================
// 24-bit RGB → 256-color palette (FASM `ansi_wci_rgbi` verbatim port)
// =====================================================================

/// Approximate a 24-bit RGB color `(r, g, b)` as an xterm 256-color
/// palette index using the exact arithmetic of the FASM `ansi_wci_rgbi`
/// macro from `tui_ansi.inc`.
///
/// This port is byte-for-byte faithful to the assembly implementation
/// per AAP §0.4.4 ("TUI tables and arithmetic ported verbatim to
/// preserve identical behavior across translations"). The FASM source
/// reads:
///
/// ```text
/// macro ansi_wci_rgbi {
///     if ansi_wcr = ansi_wcg & ansi_wcg = ansi_wcb
///         if ansi_wcr = 0
///             ansi_wci_val = 0xe8                      ; 232
///         else if ansi_wcr = 255
///             ansi_wci_val = 255
///         else
///             ansi_wci_val = (ansi_wcr / 11) + 232
///         end if
///     else
///         ansi_wcr = ansi_wcr / 43
///         ansi_wcg = ansi_wcg / 43
///         ansi_wcb = ansi_wcb / 43
///         ansi_wci_val = ansi_wcb + (ansi_wcg * 6) + (ansi_wcr * 36) + 16
///     end if
/// }
/// ```
///
/// Two branches:
/// - **Grayscale branch** (`r == g == b`):
///   - `0` → `0xe8` (232, base of grayscale ramp)
///   - `255` → `255` (top of grayscale ramp)
///   - otherwise → `(r / 11) + 232` (maps `1..=254` into the 24-step
///     grayscale ramp from `232` upward)
/// - **Color-cube branch** (otherwise): each channel is quantized by
///   integer-divide-by-43 into `0..=5` (since `255 / 43 == 5`), then
///   combined as `b' + 6·g' + 36·r' + 16` to produce a `16..=231`
///   index within the 6×6×6 cube.
///
/// Note that FASM's grayscale branch deliberately returns a value in
/// the cube-cell range (`232` at `r=0`, not `16`) and the ramp top
/// (`255`, not `231`); these choices are preserved verbatim even where
/// they differ from the xterm-suggested quantization, because AAP
/// §0.8.1 mandates byte-identical behavior preservation.
#[must_use]
pub const fn rgb_to_256(r: u8, g: u8, b: u8) -> u8 {
    if r == g && g == b {
        if r == 0 {
            0xe8 // 232 — FASM base of grayscale ramp (matches `ansi_wci_val = 0xe8`)
        } else if r == 255 {
            255 // top of grayscale ramp (matches FASM `ansi_wci_val = 255`)
        } else {
            (r / 11) + 232
        }
    } else {
        let rq = r / 43;
        let gq = g / 43;
        let bq = b / 43;
        bq + (gq * 6) + (rq * 36) + 16
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csi_prefix() {
        assert_eq!(CSI, b"\x1b[");
        assert_eq!(ESC, b"\x1b");
    }

    #[test]
    fn alt_screen_constants() {
        assert_eq!(ALT_SCREEN_ENTER, b"\x1b[?1049h");
        assert_eq!(ALT_SCREEN_EXIT, b"\x1b[?1049l");
    }

    #[test]
    fn sgr_reset_is_zero_m() {
        assert_eq!(SGR_RESET, b"\x1b[0m");
    }

    #[test]
    fn hide_show_cursor_constants() {
        assert_eq!(HIDE_CURSOR, b"\x1b[?25l");
        assert_eq!(SHOW_CURSOR, b"\x1b[?25h");
    }

    #[test]
    fn move_cursor_to_emits_row_col_h() {
        let mut out = Vec::<u8>::new();
        move_cursor_to(&mut out, 1, 1);
        assert_eq!(out, b"\x1b[1;1H");
        out.clear();
        move_cursor_to(&mut out, 24, 80);
        assert_eq!(out, b"\x1b[24;80H");
    }

    #[test]
    fn push_u32_zero_and_digits() {
        let mut out = Vec::<u8>::new();
        push_u32(&mut out, 0);
        assert_eq!(out, b"0");
        out.clear();
        push_u32(&mut out, 123);
        assert_eq!(out, b"123");
        out.clear();
        push_u32(&mut out, 4_294_967_295);
        assert_eq!(out, b"4294967295");
    }

    #[test]
    fn set_fg_256_format() {
        let mut out = Vec::<u8>::new();
        set_fg_256(&mut out, 200);
        assert_eq!(out, b"\x1b[38;5;200m");
    }

    #[test]
    fn set_bg_256_format() {
        let mut out = Vec::<u8>::new();
        set_bg_256(&mut out, 0);
        assert_eq!(out, b"\x1b[48;5;0m");
    }

    #[test]
    fn set_fg_rgb_format() {
        let mut out = Vec::<u8>::new();
        set_fg_rgb(&mut out, 255, 128, 0);
        assert_eq!(out, b"\x1b[38;2;255;128;0m");
    }

    #[test]
    fn set_bg_rgb_format() {
        let mut out = Vec::<u8>::new();
        set_bg_rgb(&mut out, 1, 2, 3);
        assert_eq!(out, b"\x1b[48;2;1;2;3m");
    }

    #[test]
    fn rgb_to_256_black_is_232() {
        // FASM `ansi_wci_rgbi` grayscale branch: r == g == b == 0 → 0xe8 (232).
        // This is the BASE of the 24-step grayscale ramp per the FASM
        // verbatim arithmetic (not the cube-origin 16 of the xterm
        // convention).
        assert_eq!(rgb_to_256(0, 0, 0), 232);
    }

    #[test]
    fn rgb_to_256_white_is_255() {
        // FASM `ansi_wci_rgbi` grayscale branch: r == g == b == 255 → 255.
        // The FASM macro returns the TOP of the grayscale ramp (255)
        // rather than the xterm-convention 231.
        assert_eq!(rgb_to_256(255, 255, 255), 255);
    }

    #[test]
    fn rgb_to_256_pure_red_in_cube() {
        // FASM `ansi_wci_rgbi` color-cube branch: (255,0,0) → r/43=5,
        // g/43=0, b/43=0 → 0 + (0*6) + (5*36) + 16 = 196. The canonical
        // "bright red" cube cell, unchanged between xterm and FASM
        // conventions because the cube arithmetic is identical.
        assert_eq!(rgb_to_256(255, 0, 0), 196);
    }

    #[test]
    fn acs_constants_present() {
        assert_eq!(ACS_ENTER, b"\x1b(0");
        assert_eq!(ACS_EXIT, b"\x1b(B");
        assert_eq!(ACS_HLINE, b'q');
        assert_eq!(ACS_VLINE, b'x');
        assert_eq!(ACS_ULCORNER, b'l');
        assert_eq!(ACS_URCORNER, b'k');
        assert_eq!(ACS_LLCORNER, b'm');
        assert_eq!(ACS_LRCORNER, b'j');
        assert_eq!(ACS_PLUS, b'n');
        assert_eq!(ACS_LTEE, b't');
        assert_eq!(ACS_RTEE, b'u');
        assert_eq!(ACS_TTEE, b'w');
        assert_eq!(ACS_BTEE, b'v');
    }

    #[test]
    fn unicode_box_drawing_chars() {
        assert_eq!(UNICODE_HLINE, '─');
        assert_eq!(UNICODE_VLINE, '│');
        assert_eq!(UNICODE_ULCORNER, '┌');
        assert_eq!(UNICODE_URCORNER, '┐');
        assert_eq!(UNICODE_LLCORNER, '└');
        assert_eq!(UNICODE_LRCORNER, '┘');
        assert_eq!(UNICODE_LTEE, '├');
        assert_eq!(UNICODE_RTEE, '┤');
        assert_eq!(UNICODE_TTEE, '┬');
        assert_eq!(UNICODE_BTEE, '┴');
        assert_eq!(UNICODE_PLUS, '┼');
    }

    #[test]
    fn cursor_up_down_forward_backward() {
        let mut out = Vec::<u8>::new();
        cursor_up(&mut out, 3);
        assert_eq!(out, b"\x1b[3A");
        out.clear();
        cursor_down(&mut out, 5);
        assert_eq!(out, b"\x1b[5B");
        out.clear();
        cursor_forward(&mut out, 7);
        assert_eq!(out, b"\x1b[7C");
        out.clear();
        cursor_backward(&mut out, 1);
        assert_eq!(out, b"\x1b[1D");
    }

    #[test]
    fn clear_constants() {
        assert_eq!(CLEAR_SCREEN, b"\x1b[2J");
        assert_eq!(CLEAR_LINE, b"\x1b[2K");
        assert_eq!(CLEAR_TO_EOL, b"\x1b[K");
        assert_eq!(CLEAR_TO_EOS, b"\x1b[J");
    }

    #[test]
    fn sgr_attribute_constants() {
        assert_eq!(SGR_BOLD, b"\x1b[1m");
        assert_eq!(SGR_DIM, b"\x1b[2m");
        assert_eq!(SGR_ITALIC, b"\x1b[3m");
        assert_eq!(SGR_UNDERLINE, b"\x1b[4m");
        assert_eq!(SGR_BLINK, b"\x1b[5m");
        assert_eq!(SGR_REVERSE, b"\x1b[7m");
        assert_eq!(SGR_STRIKETHROUGH, b"\x1b[9m");
        assert_eq!(SGR_BOLD_OFF, b"\x1b[22m");
        assert_eq!(SGR_UNDERLINE_OFF, b"\x1b[24m");
        assert_eq!(SGR_BLINK_OFF, b"\x1b[25m");
        assert_eq!(SGR_REVERSE_OFF, b"\x1b[27m");
    }

    #[test]
    fn cursor_save_restore_constants() {
        assert_eq!(CURSOR_SAVE, b"\x1b7");
        assert_eq!(CURSOR_RESTORE, b"\x1b8");
        assert_eq!(CURSOR_HOME, b"\x1b[H");
    }

    // ---- FASM-verbatim rgb_to_256 sanity tests (supplemental) ----

    #[test]
    fn rgb_to_256_grayscale_middle_uses_divide_by_11() {
        // FASM: (r / 11) + 232 for r != 0 && r != 255.
        // r=11   → (11/11)+232  = 233.
        // r=22   → (22/11)+232  = 234.
        // r=128  → (128/11)+232 = 11+232 = 243.
        // r=254  → (254/11)+232 = 23+232 = 255.
        assert_eq!(rgb_to_256(11, 11, 11), 233);
        assert_eq!(rgb_to_256(22, 22, 22), 234);
        assert_eq!(rgb_to_256(128, 128, 128), 243);
        assert_eq!(rgb_to_256(254, 254, 254), 255);
    }

    #[test]
    fn rgb_to_256_color_cube_covers_full_range() {
        // FASM cube: b/43 + (g/43)*6 + (r/43)*36 + 16.
        // Min non-grayscale cube index: r=0,g=0,b=43 → 1 + 0 + 0 + 16 = 17.
        // Max cube index: r=255,g=255,b=254 → rq=5, gq=5, bq=5
        //   → 5 + 30 + 180 + 16 = 231.
        // Mid-range: r=128, g=64, b=0 → rq=2, gq=1, bq=0
        //   → 0 + 6 + 72 + 16 = 94.
        assert_eq!(rgb_to_256(0, 0, 43), 17);
        assert_eq!(rgb_to_256(255, 255, 254), 231);
        assert_eq!(rgb_to_256(128, 64, 0), 94);
    }
}
