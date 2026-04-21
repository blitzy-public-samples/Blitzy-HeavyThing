// HeavyThing x86_64 assembly language library — Rust translation.
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

//! Verbatim port of FASM `unicodecase.inc`.
//!
//! This module reproduces the two 256-byte XOR maps (`.toupper_map` and
//! `.tolower_map`) plus the cascaded range-check ladder from the FASM
//! `utf16$upper` / `utf16$lower` functions for the `extendedcase = 0`
//! default declared in `ht_defaults.inc` (line 106). The implementation
//! deliberately preserves the quirky round-trip behaviour of the
//! original tables, which does NOT follow the Unicode Standard's
//! derived-core-properties case folding:
//!
//! * `to_upper('ß')` returns `'ÿ'` (`toupper_map[0xDF] = 0x20`, so
//!   `0xDF XOR 0x20 = 0xFF`). The Unicode rule `ß → SS` is NOT applied.
//! * `to_upper('ÿ')` returns `'ß'` (`toupper_map[0xFF] = 0x20`, so
//!   `0xFF XOR 0x20 = 0xDF`).
//! * `to_lower('ß')` returns `'ß'` unchanged (`tolower_map[0xDF] = 0`).
//! * `to_lower('ÿ')` returns `'ÿ'` unchanged (`tolower_map[0xFF] = 0`).
//!
//! This `ß ↔ ÿ` asymmetry across `to_upper` / `to_lower` is intentional
//! FASM behaviour and is preserved verbatim per AAP §0.4.4 ("case
//! mapping tables ported verbatim from unicodecase.inc") and §0.8.1
//! ("Preserve all observable behaviour").
//!
//! Because FASM emits a single UTF-16 code unit per input code unit,
//! the public case-mapping functions here have signature `char -> char`,
//! not `char -> String`. Callers that require full Unicode case folding
//! (German sharp-s expansion to `SS`, Greek final-sigma handling,
//! Turkish-I dotting, locale-sensitive rules) must bypass this module
//! and use [`char::to_uppercase`] / [`char::to_lowercase`] directly.
//! The `net`, `tls`, `ssh`, and `tui` subsystems do not need those
//! semantics and depend on the FASM-compatible single-codepoint
//! behaviour preserved here.
//!
//! # Variant selected
//!
//! FASM's `unicodecase.inc` defines two variants gated on the
//! build-time constant `extendedcase`:
//!
//! * `extendedcase = 0` (the `ht_defaults.inc` default, line 106):
//!   coarse/medium script-wide offsets plus parity cascades only. Code
//!   points outside the enumerated ranges are returned unchanged.
//! * `extendedcase = 1`: the same ranges plus a binary search through a
//!   165-entry (`utf16$upper`) or 156-entry (`utf16$lower`) table that
//!   covers additional code points such as U+00B5 µ → U+039C Μ and
//!   U+2126 Ω → U+03C9 ω.
//!
//! This Rust port implements the **non-extended variant** because it
//! matches the FASM default build used by the in-scope `sshtalk`,
//! `hnwatch`, and `webserver` binaries. The extended binary-search
//! tables may be added later as a Cargo feature if any downstream
//! caller needs them.
//!
//! # Classification predicates
//!
//! The nine `is_*` classification helpers (`is_upper`, `is_lower`,
//! `is_letter`, `is_digit`, `is_alphanumeric`, `is_whitespace`,
//! `is_control`, `is_ascii`, `is_hexdigit`) delegate to the
//! corresponding `char::is_*` stdlib methods. FASM `unicodecase.inc`
//! does not provide these predicates — they are thin helpers added to
//! keep higher-level code (string parsing, URL parsing, HTTP header
//! parsing) idiomatic.

// ============================================================================
// 256-byte XOR tables — verbatim from FASM `.toupper_map` / `.tolower_map`
// ============================================================================

/// XOR mask for code points `0x00..=0xFF` that yields the uppercase form.
///
/// Derived byte-for-byte from FASM `unicodecase.inc` `.toupper_map`.
/// Non-zero entries occur at exactly 58 positions:
///
/// * `0x61..=0x7A` (26 entries, `a..=z`): XOR `0x20` yields `A..=Z`.
/// * `0xDF..=0xF6` (24 entries, `ß..=ö`): XOR `0x20`. Note the `ß` entry
///   (index 0xDF) preserves the FASM quirk `toupper('ß') = 'ÿ'`.
/// * `0xF8..=0xFF` (8 entries, `ø..=ÿ`): XOR `0x20`. The `ÿ` entry
///   (index 0xFF) preserves the quirk `toupper('ÿ') = 'ß'`.
///
/// All other positions contain `0x00` (identity XOR). Gap at `0xF7`
/// keeps the division sign `÷` unchanged.
const TOUPPER_MAP: [u8; 256] = [
    // 0x00-0x0F
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x10-0x1F
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x20-0x2F  ' '..'/'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x30-0x3F  '0'..'?'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x40-0x4F  '@','A'..'O'   (A..Z already uppercase → XOR 0)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x50-0x5F  'P'..'Z','[','\\',']','^','_'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x60-0x6F  '`','a'..'o'
    0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    // 0x70-0x7F  'p'..'z','{','|','}','~',DEL
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x80-0x8F  C1 controls
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x90-0x9F  C1 controls
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0xA0-0xAF  Latin-1 punctuation / symbols
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0xB0-0xBF  Latin-1 punctuation / symbols
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0xC0-0xCF  Latin-1 uppercase 'À'..'Ï'   (already uppercase → XOR 0)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0xD0-0xDF  'Ð'..'Þ','ß'   — ß XOR 0x20 → ÿ (FASM quirk)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
    // 0xE0-0xEF  'à'..'ï'
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    // 0xF0-0xFF  'ð'..'ö','÷','ø'..'ÿ'   — ÿ XOR 0x20 → ß (FASM quirk)
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
];

/// XOR mask for code points `0x00..=0xFF` that yields the lowercase form.
///
/// Derived byte-for-byte from FASM `unicodecase.inc` `.tolower_map`.
/// Non-zero entries occur at exactly 56 positions:
///
/// * `0x41..=0x5A` (26 entries, `A..=Z`): XOR `0x20` yields `a..=z`.
/// * `0xC0..=0xD6` (23 entries, `À..=Ö`): XOR `0x20`.
/// * `0xD8..=0xDE` (7 entries, `Ø..=Þ`): XOR `0x20`.
///
/// All other positions contain `0x00` (identity XOR). Note the
/// intentional gaps: `0xD7` (`×` multiplication sign), `0xDF` (`ß`),
/// and `0xFF` (`ÿ`) are all identity in this table — the asymmetry
/// with [`TOUPPER_MAP`] is intentional FASM behaviour.
const TOLOWER_MAP: [u8; 256] = [
    // 0x00-0x0F
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x10-0x1F
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x20-0x2F
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x30-0x3F  '0'..'?'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x40-0x4F  '@','A'..'O'
    0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    // 0x50-0x5F  'P'..'Z','[','\\',']','^','_'
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x60-0x6F  '`','a'..'o'   (already lowercase → XOR 0)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x70-0x7F  'p'..'z','{','|','}','~',DEL
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x80-0x8F  C1 controls
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x90-0x9F  C1 controls
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0xA0-0xAF  Latin-1 punctuation / symbols
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0xB0-0xBF  Latin-1 punctuation / symbols
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0xC0-0xCF  'À'..'Ï'
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    // 0xD0-0xDF  'Ð'..'Ö','×','Ø'..'Þ','ß'   — × and ß are identity
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00,
    // 0xE0-0xEF  'à'..'ï'   (already lowercase → XOR 0)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0xF0-0xFF  'ð'..'ÿ'   (already lowercase; ÿ stays as ÿ per FASM asymmetry)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// ============================================================================
// Cascaded range ladder for BMP code points 0x0100..=0xFFFF
// (non-extended variant — matches FASM `extendedcase = 0` default)
// ============================================================================

/// Apply the FASM `utf16$upper` cascaded range ladder to a BMP code point.
///
/// Returns the uppercase mapping for code points covered by one of the
/// enumerated ranges, or the input unchanged for everything else. See
/// the module-level documentation for variant-selection rationale.
fn toupper_cascaded(cp: u32) -> u32 {
    match cp {
        // --- Phase 1: coarse script-wide offsets ---
        0x0450..=0x045F => cp - 0x50, // Cyrillic supplement (lowercase → uppercase)
        0x0561..=0x0586 => cp - 0x30, // Armenian
        0x03B1..=0x03CB => cp - 0x20, // Greek
        0x0430..=0x044F => cp - 0x20, // Cyrillic
        0xFF41..=0xFF5A => cp - 0x20, // Fullwidth Latin
        0x24D0..=0x24E9 => cp - 0x1A, // Circled Latin Small → Circled Latin Capital

        // --- Phase 2: medium offsets ---
        0x2170..=0x217F => cp - 0x10, // Small Roman numerals → Capital
        // Greek extended — four disjoint small-letter ranges, all +8
        0x1F00..=0x1F07 | 0x1F10..=0x1F15 | 0x1F20..=0x1F27 | 0x1F30..=0x1F37 => cp + 0x08,

        // --- Phase 3: Latin parity cascades (sub 1) ---
        // 0x0101..=0x012F: ODD indices are small (Ā/ā pair, capital at even)
        0x0101..=0x012F if cp & 1 == 1 => cp - 1,
        // 0x013A..=0x0148: EVEN indices are small (Ĺ/ĺ parity inversion)
        0x013A..=0x0148 if cp & 1 == 0 => cp - 1,
        // 0x014B..=0x0177: ODD indices are small (Ŋ/ŋ pair)
        0x014B..=0x0177 if cp & 1 == 1 => cp - 1,
        // 0x0201..=0x0233 except 0x0221: ODD indices are small (Ȁ/ȁ pair)
        0x0201..=0x0233 if cp & 1 == 1 && cp != 0x0221 => cp - 1,

        // --- Phase 4: odd-indexed cascaded ranges ---
        0x03D9..=0x03EF if cp & 1 == 1 => cp - 1, // Greek Coptic
        0x0461..=0x04BF if cp & 1 == 1 && cp != 0x0483 && cp != 0x0485 && cp != 0x0487 && cp != 0x0489 => {
            cp - 1
        } // Cyrillic historic letters (gaps are combining marks)
        0x04D1..=0x04F9 if cp & 1 == 1 => cp - 1, // Cyrillic extended
        0x1E01..=0x1E95 if cp & 1 == 1 => cp - 1, // Latin Extended Additional
        0x1EA1..=0x1EF9 if cp & 1 == 1 => cp - 1, // Latin Extended Additional Vietnamese

        _ => cp,
    }
}

/// Apply the FASM `utf16$lower` cascaded range ladder to a BMP code point.
///
/// Mirror of [`toupper_cascaded`] — uses symmetric but independently-defined
/// ranges from `unicodecase.inc`. Note the `+48` Georgian quirk preserved
/// verbatim: FASM's own inline comment asks "should be + 1c60 ? hmmm, why
/// are we doing it different?" but the behaviour is shipped as-is.
fn tolower_cascaded(cp: u32) -> u32 {
    match cp {
        // --- Phase 1: coarse script-wide offsets ---
        // Georgian: FASM uses +48 (0x30) with an inline comment noting
        // "should be + 1c60 ? hmmm, why are we doing it different?".
        // Preserved verbatim per AAP §0.4.4.
        0x10A0..=0x10C5 => cp + 48,
        0x0400..=0x040F => cp + 0x50, // Cyrillic supplement
        0x0531..=0x0556 => cp + 0x30, // Armenian
        0x0391..=0x03AB => cp + 0x20, // Greek
        0x0410..=0x042F => cp + 0x20, // Cyrillic
        0xFF21..=0xFF3A => cp + 0x20, // Fullwidth Latin
        0x24B6..=0x24CF => cp + 0x1A, // Circled Latin Capital → Circled Latin Small

        // --- Phase 2: medium offsets ---
        0x2160..=0x216F => cp + 0x10, // Capital Roman numerals → Small
        // Greek extended — four disjoint capital-letter ranges, all -8
        0x1F08..=0x1F0F | 0x1F18..=0x1F1D | 0x1F28..=0x1F2F | 0x1F38..=0x1F3F => cp - 0x08,

        // --- Phase 3: Latin parity cascades (add 1) ---
        // 0x0100..=0x012E: EVEN indices are capital (Ā/ā pair)
        0x0100..=0x012E if cp & 1 == 0 => cp + 1,
        // 0x0139..=0x0147: ODD indices are capital (Ĺ/ĺ parity inversion)
        0x0139..=0x0147 if cp & 1 == 1 => cp + 1,
        // 0x014A..=0x0176: EVEN indices are capital (Ŋ/ŋ pair)
        0x014A..=0x0176 if cp & 1 == 0 => cp + 1,
        // 0x0200..=0x0232 except 0x0220: EVEN indices are capital (Ȁ/ȁ pair)
        0x0200..=0x0232 if cp & 1 == 0 && cp != 0x0220 => cp + 1,

        // --- Phase 4: even-indexed cascaded ranges ---
        0x03D8..=0x03EE if cp & 1 == 0 => cp + 1, // Greek Coptic
        0x0460..=0x04BE if cp & 1 == 0 && cp != 0x0482 && cp != 0x0484 && cp != 0x0486 && cp != 0x0488 => {
            cp + 1
        } // Cyrillic historic letters (gaps are combining marks)
        0x04D0..=0x04F8 if cp & 1 == 0 => cp + 1, // Cyrillic extended
        0x1E00..=0x1E94 if cp & 1 == 0 => cp + 1, // Latin Extended Additional
        0x1EA0..=0x1EF8 if cp & 1 == 0 => cp + 1, // Latin Extended Additional Vietnamese

        _ => cp,
    }
}

// ============================================================================
// Public case-mapping API
// ============================================================================

/// Return the FASM `utf16$upper` uppercase form of a single `char`.
///
/// Runs the 256-byte XOR [`TOUPPER_MAP`] for code points in `0..=0xFF`,
/// the cascaded range ladder for BMP code points in `0x100..=0xFFFF`,
/// and returns the input unchanged for non-BMP code points (matching
/// the FASM `utf16` word-level addressing — FASM cannot reach
/// supplementary planes).
///
/// This is a single-codepoint-in / single-codepoint-out mapping. It
/// does NOT perform full Unicode case folding; see the module-level
/// documentation for the ß ↔ ÿ quirks that distinguish this port from
/// [`char::to_uppercase`].
///
/// # Examples
///
/// ```
/// use heavything::util::unicodecase::to_upper;
/// assert_eq!(to_upper('a'), 'A');
/// assert_eq!(to_upper('A'), 'A');     // identity
/// assert_eq!(to_upper('α'), 'Α');     // U+03B1 → U+0391 via cascaded range
/// // FASM quirks: ß ↔ ÿ swap across toupper.
/// assert_eq!(to_upper('ß'), 'ÿ');
/// assert_eq!(to_upper('ÿ'), 'ß');
/// ```
#[must_use]
pub fn to_upper(c: char) -> char {
    let cp = c as u32;
    let mapped = if cp <= 0xFF {
        let byte = cp as u8;
        u32::from(byte ^ TOUPPER_MAP[byte as usize])
    } else if cp <= 0xFFFF {
        toupper_cascaded(cp)
    } else {
        cp
    };
    char::from_u32(mapped).unwrap_or(c)
}

/// Return the FASM `utf16$lower` lowercase form of a single `char`.
///
/// Mirror of [`to_upper`] — runs the 256-byte XOR [`TOLOWER_MAP`] for
/// Latin-1, the cascaded ladder for BMP, and returns the input
/// unchanged for non-BMP code points.
///
/// # Examples
///
/// ```
/// use heavything::util::unicodecase::to_lower;
/// assert_eq!(to_lower('A'), 'a');
/// assert_eq!(to_lower('a'), 'a');     // identity
/// assert_eq!(to_lower('Α'), 'α');     // U+0391 → U+03B1 via cascaded range
/// // FASM asymmetry: ß and ÿ are unchanged by tolower.
/// assert_eq!(to_lower('ß'), 'ß');
/// assert_eq!(to_lower('ÿ'), 'ÿ');
/// ```
#[must_use]
pub fn to_lower(c: char) -> char {
    let cp = c as u32;
    let mapped = if cp <= 0xFF {
        let byte = cp as u8;
        u32::from(byte ^ TOLOWER_MAP[byte as usize])
    } else if cp <= 0xFFFF {
        tolower_cascaded(cp)
    } else {
        cp
    };
    char::from_u32(mapped).unwrap_or(c)
}

/// Return the FASM uppercase form of every `char` in `s`.
///
/// Maps each character one-to-one via [`to_upper`]. Does NOT perform
/// full Unicode case folding — the German `ß` becomes `ÿ` (per the
/// FASM `toupper_map` quirk), not `SS`.
#[must_use]
pub fn string_upper(s: &str) -> String {
    s.chars().map(to_upper).collect()
}

/// Return the FASM lowercase form of every `char` in `s`.
///
/// Maps each character one-to-one via [`to_lower`].
#[must_use]
pub fn string_lower(s: &str) -> String {
    s.chars().map(to_lower).collect()
}

/// Compare two strings for equality ignoring case, using the FASM
/// uppercase mapping.
///
/// Streams both inputs through [`to_upper`] without allocating and
/// returns `true` iff the resulting uppercase sequences match exactly.
///
/// # Examples
///
/// ```
/// use heavything::util::unicodecase::eq_ignore_case;
/// assert!(eq_ignore_case("Hello", "HELLO"));
/// assert!(eq_ignore_case("straße", "STRAßE"));
/// // FASM quirk: "straße" and "STRASSE" are NOT equal because the
/// // FASM uppercase of `ß` is `ÿ`, not `SS`.
/// assert!(!eq_ignore_case("straße", "STRASSE"));
/// ```
#[must_use]
pub fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.chars().map(to_upper).eq(b.chars().map(to_upper))
}

// ============================================================================
// Classification predicates (stdlib delegation)
//
// These wrap `char::is_*` methods. FASM's `unicodecase.inc` does not
// expose classification helpers; they are provided here for idiomatic
// Rust callers. The review explicitly accepted this divergence.
// ============================================================================

/// Returns `true` if `c` is an uppercase letter per [`char::is_uppercase`].
#[must_use]
pub fn is_upper(c: char) -> bool {
    c.is_uppercase()
}

/// Returns `true` if `c` is a lowercase letter per [`char::is_lowercase`].
#[must_use]
pub fn is_lower(c: char) -> bool {
    c.is_lowercase()
}

/// Returns `true` if `c` is alphabetic per [`char::is_alphabetic`].
#[must_use]
pub fn is_letter(c: char) -> bool {
    c.is_alphabetic()
}

/// Returns `true` if `c` is a numeric character per [`char::is_numeric`].
#[must_use]
pub fn is_digit(c: char) -> bool {
    c.is_numeric()
}

/// Returns `true` if `c` is alphanumeric per [`char::is_alphanumeric`].
#[must_use]
pub fn is_alphanumeric(c: char) -> bool {
    c.is_alphanumeric()
}

/// Returns `true` if `c` is whitespace per [`char::is_whitespace`].
#[must_use]
pub fn is_whitespace(c: char) -> bool {
    c.is_whitespace()
}

/// Returns `true` if `c` is a control character per [`char::is_control`].
#[must_use]
pub fn is_control(c: char) -> bool {
    c.is_control()
}

/// Returns `true` if `c` is an ASCII character per [`char::is_ascii`].
#[must_use]
pub fn is_ascii(c: char) -> bool {
    c.is_ascii()
}

/// Returns `true` if `c` is an ASCII hexadecimal digit per
/// [`char::is_ascii_hexdigit`].
#[must_use]
pub fn is_hexdigit(c: char) -> bool {
    c.is_ascii_hexdigit()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // XOR table: simple ASCII round-trips (char -> char signature)
    // ------------------------------------------------------------------------

    #[test]
    fn simple_ascii_upper() {
        assert_eq!(to_upper('a'), 'A');
        assert_eq!(to_upper('z'), 'Z');
        assert_eq!(to_upper('A'), 'A');
        assert_eq!(to_upper('Z'), 'Z');
        assert_eq!(to_upper('1'), '1');
        assert_eq!(to_upper('!'), '!');
    }

    #[test]
    fn simple_ascii_lower() {
        assert_eq!(to_lower('A'), 'a');
        assert_eq!(to_lower('Z'), 'z');
        assert_eq!(to_lower('a'), 'a');
        assert_eq!(to_lower('z'), 'z');
        assert_eq!(to_lower('1'), '1');
        assert_eq!(to_lower('!'), '!');
    }

    // ------------------------------------------------------------------------
    // FASM quirks around sharp-s (ß) and y-dieresis (ÿ)
    // ------------------------------------------------------------------------

    #[test]
    fn fasm_sharp_s_upper_maps_to_ydieresis() {
        // TOUPPER_MAP[0xDF] = 0x20, so 0xDF XOR 0x20 = 0xFF ('ÿ').
        assert_eq!(to_upper('ß'), 'ÿ');
    }

    #[test]
    fn fasm_ydieresis_upper_maps_to_sharp_s() {
        // TOUPPER_MAP[0xFF] = 0x20, so 0xFF XOR 0x20 = 0xDF ('ß').
        assert_eq!(to_upper('ÿ'), 'ß');
    }

    #[test]
    fn fasm_sharp_s_lower_is_unchanged() {
        // TOLOWER_MAP[0xDF] = 0x00 — ß stays as ß (asymmetric with TOUPPER_MAP).
        assert_eq!(to_lower('ß'), 'ß');
    }

    #[test]
    fn fasm_ydieresis_lower_is_unchanged() {
        // TOLOWER_MAP[0xFF] = 0x00 — ÿ stays as ÿ.
        assert_eq!(to_lower('ÿ'), 'ÿ');
    }

    #[test]
    fn fasm_sharp_s_roundtrip_is_not_idempotent() {
        // to_lower(to_upper('ß')) == to_lower('ÿ') == 'ÿ' ≠ 'ß'
        assert_eq!(to_lower(to_upper('ß')), 'ÿ');
        // to_upper(to_lower('ß')) == to_upper('ß') == 'ÿ' ≠ 'ß'
        assert_eq!(to_upper(to_lower('ß')), 'ÿ');
    }

    // ------------------------------------------------------------------------
    // Latin-1 XOR coverage — exhaustive verification of every 0x20 index
    // ------------------------------------------------------------------------

    #[test]
    fn latin1_upper_covers_e0_to_f6() {
        // à..ö (U+00E0..=U+00F6) all XOR with 0x20 → À..Ö.
        for cp in 0xE0u32..=0xF6 {
            let c = char::from_u32(cp).unwrap();
            let expected = char::from_u32(cp ^ 0x20).unwrap();
            assert_eq!(to_upper(c), expected, "cp = U+{cp:04X}");
        }
    }

    #[test]
    fn latin1_upper_covers_f8_to_ff() {
        // ø..ÿ (U+00F8..=U+00FF) all XOR with 0x20.
        for cp in 0xF8u32..=0xFF {
            let c = char::from_u32(cp).unwrap();
            let expected = char::from_u32(cp ^ 0x20).unwrap();
            assert_eq!(to_upper(c), expected, "cp = U+{cp:04X}");
        }
    }

    #[test]
    fn latin1_division_sign_is_identity_in_both_tables() {
        // TOUPPER_MAP[0xF7] = 0, so ÷ is unchanged by to_upper.
        assert_eq!(to_upper('÷'), '÷');
        // TOLOWER_MAP[0xD7] = 0, so × is unchanged by to_lower.
        assert_eq!(to_lower('×'), '×');
    }

    #[test]
    fn latin1_lower_covers_c0_to_d6() {
        // À..Ö (U+00C0..=U+00D6) all XOR with 0x20 → à..ö.
        for cp in 0xC0u32..=0xD6 {
            let c = char::from_u32(cp).unwrap();
            let expected = char::from_u32(cp ^ 0x20).unwrap();
            assert_eq!(to_lower(c), expected, "cp = U+{cp:04X}");
        }
    }

    #[test]
    fn latin1_lower_covers_d8_to_de() {
        // Ø..Þ (U+00D8..=U+00DE) all XOR with 0x20.
        for cp in 0xD8u32..=0xDE {
            let c = char::from_u32(cp).unwrap();
            let expected = char::from_u32(cp ^ 0x20).unwrap();
            assert_eq!(to_lower(c), expected, "cp = U+{cp:04X}");
        }
    }

    // ------------------------------------------------------------------------
    // Cascaded ranges: Phase 1 (coarse offsets)
    // ------------------------------------------------------------------------

    #[test]
    fn greek_alpha_round_trip() {
        assert_eq!(to_lower('Α'), 'α'); // U+0391 → U+03B1
        assert_eq!(to_upper('α'), 'Α'); // U+03B1 → U+0391
    }

    #[test]
    fn greek_omega_round_trip() {
        // Ω U+03A9 ↔ ω U+03C9 via coarse +0x20 offset.
        assert_eq!(to_lower('Ω'), 'ω');
        assert_eq!(to_upper('ω'), 'Ω');
    }

    #[test]
    fn cyrillic_ya_round_trip() {
        assert_eq!(to_lower('Я'), 'я'); // U+042F → U+044F
        assert_eq!(to_upper('я'), 'Я'); // U+044F → U+042F
    }

    #[test]
    fn cyrillic_supplement_round_trip() {
        // Ѐ U+0400 ↔ ѐ U+0450 via 0x50 offset.
        let cap = char::from_u32(0x0400).unwrap();
        let low = char::from_u32(0x0450).unwrap();
        assert_eq!(to_lower(cap), low);
        assert_eq!(to_upper(low), cap);
    }

    #[test]
    fn fullwidth_latin_round_trip() {
        // Ａ U+FF21 ↔ ａ U+FF41 via +0x20 offset.
        let big_a = char::from_u32(0xFF21).unwrap();
        let lil_a = char::from_u32(0xFF41).unwrap();
        assert_eq!(to_lower(big_a), lil_a);
        assert_eq!(to_upper(lil_a), big_a);
    }

    #[test]
    fn circled_latin_round_trip() {
        // Ⓐ U+24B6 ↔ ⓐ U+24D0 via +0x1A offset.
        let big = char::from_u32(0x24B6).unwrap();
        let small = char::from_u32(0x24D0).unwrap();
        assert_eq!(to_lower(big), small);
        assert_eq!(to_upper(small), big);
    }

    #[test]
    fn roman_numeral_round_trip() {
        // Ⅰ U+2160 ↔ ⅰ U+2170 via +0x10 offset.
        let big = char::from_u32(0x2160).unwrap();
        let small = char::from_u32(0x2170).unwrap();
        assert_eq!(to_lower(big), small);
        assert_eq!(to_upper(small), big);
    }

    // ------------------------------------------------------------------------
    // Cascaded ranges: Phase 2 (Greek extended +8 / -8)
    // ------------------------------------------------------------------------

    #[test]
    fn greek_extended_offset_8() {
        // U+1F00 ἀ (small) ↔ U+1F08 Ἀ (capital) via +8 offset.
        let small = char::from_u32(0x1F00).unwrap();
        let big = char::from_u32(0x1F08).unwrap();
        assert_eq!(to_upper(small), big);
        assert_eq!(to_lower(big), small);
    }

    #[test]
    fn greek_extended_second_range() {
        // U+1F20 (small) ↔ U+1F28 (capital).
        let small = char::from_u32(0x1F20).unwrap();
        let big = char::from_u32(0x1F28).unwrap();
        assert_eq!(to_upper(small), big);
        assert_eq!(to_lower(big), small);
    }

    // ------------------------------------------------------------------------
    // Cascaded ranges: Phase 3 (Latin parity cascades)
    // ------------------------------------------------------------------------

    #[test]
    fn latin_ext_odd_block_sub_one() {
        // U+0101 ā → U+0100 Ā (ODD is small in this block).
        let lower_a_macron = char::from_u32(0x0101).unwrap();
        let upper_a_macron = char::from_u32(0x0100).unwrap();
        assert_eq!(to_upper(lower_a_macron), upper_a_macron);
        assert_eq!(to_lower(upper_a_macron), lower_a_macron);
    }

    #[test]
    fn latin_ext_parity_inverted_block() {
        // In 0x0139..=0x0148, ODD indices are capital and EVEN indices
        // are small — the opposite of the surrounding blocks.
        // U+0139 Ĺ (capital, ODD) ↔ U+013A ĺ (small, EVEN).
        let cap = char::from_u32(0x0139).unwrap();
        let low = char::from_u32(0x013A).unwrap();
        assert_eq!(to_lower(cap), low);
        assert_eq!(to_upper(low), cap);
    }

    #[test]
    fn latin_ext_gap_0220_and_0221_preserved() {
        // 0x0200..=0x0232 has holes at 0x0220 (tolower skip) and 0x0221
        // (toupper skip) — both preserved as identity in both functions.
        let at_220 = char::from_u32(0x0220).unwrap();
        let at_221 = char::from_u32(0x0221).unwrap();
        assert_eq!(to_upper(at_220), at_220);
        assert_eq!(to_lower(at_220), at_220);
        assert_eq!(to_upper(at_221), at_221);
        assert_eq!(to_lower(at_221), at_221);
    }

    // ------------------------------------------------------------------------
    // Cascaded ranges: Phase 4 (odd/even cascaded ranges with gaps)
    // ------------------------------------------------------------------------

    #[test]
    fn greek_coptic_round_trip() {
        // U+03D8 (capital) ↔ U+03D9 (small) via Phase 4 parity cascade.
        let cap = char::from_u32(0x03D8).unwrap();
        let small = char::from_u32(0x03D9).unwrap();
        assert_eq!(to_upper(small), cap);
        assert_eq!(to_lower(cap), small);
    }

    #[test]
    fn cyrillic_historic_gaps_preserved() {
        // 0x0483..=0x0489 are Cyrillic combining marks that FASM
        // intentionally skips within the 0x0460..=0x04BF cascade.
        for cp in [0x0482u32, 0x0483, 0x0484, 0x0485, 0x0486, 0x0487, 0x0488, 0x0489] {
            let c = char::from_u32(cp).unwrap();
            assert_eq!(to_upper(c), c, "to_upper(U+{cp:04X}) should be identity");
            assert_eq!(to_lower(c), c, "to_lower(U+{cp:04X}) should be identity");
        }
    }

    #[test]
    fn latin_extended_additional_round_trip() {
        // U+1E00 Ḁ (capital) ↔ U+1E01 ḁ (small).
        let cap = char::from_u32(0x1E00).unwrap();
        let small = char::from_u32(0x1E01).unwrap();
        assert_eq!(to_upper(small), cap);
        assert_eq!(to_lower(cap), small);
    }

    #[test]
    fn latin_extended_additional_vietnamese_round_trip() {
        // U+1EA0 Ạ (capital) ↔ U+1EA1 ạ (small).
        let cap = char::from_u32(0x1EA0).unwrap();
        let small = char::from_u32(0x1EA1).unwrap();
        assert_eq!(to_upper(small), cap);
        assert_eq!(to_lower(cap), small);
    }

    #[test]
    fn georgian_plus_forty_eight_quirk() {
        // FASM's Georgian uppercase-to-lowercase uses +48 rather than the
        // technically-correct +0x1C60 ('should be + 1c60 ? hmmm').
        // We preserve the quirk verbatim.
        let cap = char::from_u32(0x10A0).unwrap();
        let quirky = char::from_u32(0x10A0 + 48).unwrap();
        assert_eq!(to_lower(cap), quirky);
    }

    // ------------------------------------------------------------------------
    // Non-BMP handling
    // ------------------------------------------------------------------------

    #[test]
    fn supplementary_plane_unchanged() {
        // FASM utf16 cannot address supplementary planes; our port
        // returns them unchanged (identity mapping for cp > 0xFFFF).
        let c = char::from_u32(0x10400).unwrap(); // Deseret capital
        assert_eq!(to_upper(c), c);
        assert_eq!(to_lower(c), c);
    }

    #[test]
    fn unassigned_bmp_range_unchanged() {
        // A BMP code point outside all cascaded ranges is identity.
        let c = char::from_u32(0x2000).unwrap(); // EN QUAD — not a letter
        assert_eq!(to_upper(c), c);
        assert_eq!(to_lower(c), c);
    }

    // ------------------------------------------------------------------------
    // String and comparison helpers
    // ------------------------------------------------------------------------

    #[test]
    fn string_upper_basic() {
        assert_eq!(string_upper("hello"), "HELLO");
        assert_eq!(string_upper("Hello World"), "HELLO WORLD");
        // FASM quirk: ß uppers to ÿ, not SS.
        assert_eq!(string_upper("straße"), "STRAÿE");
    }

    #[test]
    fn string_lower_basic() {
        assert_eq!(string_lower("HELLO"), "hello");
        assert_eq!(string_lower("STRASSE"), "strasse");
        // ß is unchanged by tolower.
        assert_eq!(string_lower("STRAßE"), "straße");
    }

    #[test]
    fn string_upper_lower_empty() {
        assert_eq!(string_upper(""), "");
        assert_eq!(string_lower(""), "");
    }

    #[test]
    fn eq_ignore_case_ascii() {
        assert!(eq_ignore_case("Hello", "HELLO"));
        assert!(eq_ignore_case("HELLO", "hello"));
        assert!(eq_ignore_case("", ""));
        assert!(!eq_ignore_case("Hello", "World"));
        assert!(!eq_ignore_case("Hello", "Hell"));
        assert!(!eq_ignore_case("Hell", "Hello"));
    }

    #[test]
    fn eq_ignore_case_fasm_sharp_s() {
        // FASM's uppercase of "straße" is "STRAÿE", so "straße" and
        // "STRAßE" ARE equal (both upper to "STRAÿE"), but "straße"
        // and "STRASSE" are NOT equal.
        assert!(eq_ignore_case("straße", "STRAßE"));
        assert!(!eq_ignore_case("straße", "STRASSE"));
    }

    #[test]
    fn eq_ignore_case_greek() {
        // Greek round-trips cleanly via coarse cascaded range.
        assert!(eq_ignore_case("Αβγ", "αΒΓ"));
        assert!(!eq_ignore_case("Αβγ", "ΧΨΩ"));
    }

    // ------------------------------------------------------------------------
    // Classification predicates
    // ------------------------------------------------------------------------

    #[test]
    fn classification_basic() {
        assert!(is_upper('A'));
        assert!(!is_upper('a'));
        assert!(is_lower('a'));
        assert!(!is_lower('A'));
        assert!(is_letter('A'));
        assert!(is_letter('α'));
        assert!(!is_letter('5'));
        assert!(is_digit('5'));
        assert!(!is_digit('A'));
        assert!(is_alphanumeric('Q'));
        assert!(is_alphanumeric('7'));
        assert!(is_whitespace(' '));
        assert!(is_whitespace('\t'));
        assert!(!is_whitespace('A'));
        assert!(is_control('\n'));
        assert!(!is_control('A'));
        assert!(is_ascii('A'));
        assert!(!is_ascii('Ä'));
        assert!(is_hexdigit('0'));
        assert!(is_hexdigit('F'));
        assert!(is_hexdigit('a'));
        assert!(!is_hexdigit('G'));
    }

    #[test]
    fn mixed_case_classification() {
        let s = "Hello, World! 123";
        let upper_count = s.chars().filter(|&c| is_upper(c)).count();
        let lower_count = s.chars().filter(|&c| is_lower(c)).count();
        let digit_count = s.chars().filter(|&c| is_digit(c)).count();
        let space_count = s.chars().filter(|&c| is_whitespace(c)).count();
        assert_eq!(upper_count, 2); // H, W
        assert_eq!(lower_count, 8); // e,l,l,o,o,r,l,d
        assert_eq!(digit_count, 3); // 1, 2, 3
        assert_eq!(space_count, 2); // two spaces
    }

    #[test]
    fn hexdigit_bounds() {
        for c in '0'..='9' {
            assert!(is_hexdigit(c), "'{c}' should be a hex digit");
        }
        for c in 'a'..='f' {
            assert!(is_hexdigit(c), "'{c}' should be a hex digit");
        }
        for c in 'A'..='F' {
            assert!(is_hexdigit(c), "'{c}' should be a hex digit");
        }
        for c in 'g'..='z' {
            assert!(!is_hexdigit(c), "'{c}' should NOT be a hex digit");
        }
        for c in 'G'..='Z' {
            assert!(!is_hexdigit(c), "'{c}' should NOT be a hex digit");
        }
    }

    // ------------------------------------------------------------------------
    // Table invariants (sanity checks — verifies the verbatim port)
    // ------------------------------------------------------------------------

    #[test]
    fn toupper_map_has_58_non_zero_entries() {
        let count = TOUPPER_MAP.iter().filter(|&&b| b != 0).count();
        assert_eq!(count, 58);
    }

    #[test]
    fn tolower_map_has_56_non_zero_entries() {
        let count = TOLOWER_MAP.iter().filter(|&&b| b != 0).count();
        assert_eq!(count, 56);
    }

    #[test]
    fn toupper_map_non_zero_entries_are_all_0x20() {
        for (i, &b) in TOUPPER_MAP.iter().enumerate() {
            if b != 0 {
                assert_eq!(b, 0x20, "TOUPPER_MAP[{i:#04X}] should be 0x20");
            }
        }
    }

    #[test]
    fn tolower_map_non_zero_entries_are_all_0x20() {
        for (i, &b) in TOLOWER_MAP.iter().enumerate() {
            if b != 0 {
                assert_eq!(b, 0x20, "TOLOWER_MAP[{i:#04X}] should be 0x20");
            }
        }
    }

    #[test]
    fn toupper_map_has_0x20_at_verified_indices() {
        // Triple-verified positions from FASM unicodecase.inc (.toupper_map).
        for i in 0x61u8..=0x7A {
            assert_eq!(TOUPPER_MAP[i as usize], 0x20, "TOUPPER_MAP[{i:#04X}]");
        }
        for i in 0xDFu8..=0xF6 {
            assert_eq!(TOUPPER_MAP[i as usize], 0x20, "TOUPPER_MAP[{i:#04X}]");
        }
        for i in 0xF8u8..=0xFF {
            assert_eq!(TOUPPER_MAP[i as usize], 0x20, "TOUPPER_MAP[{i:#04X}]");
        }
        // Verified gaps.
        assert_eq!(TOUPPER_MAP[0xF7], 0x00); // ÷
    }

    #[test]
    fn tolower_map_has_0x20_at_verified_indices() {
        // Triple-verified positions from FASM unicodecase.inc (.tolower_map).
        for i in 0x41u8..=0x5A {
            assert_eq!(TOLOWER_MAP[i as usize], 0x20, "TOLOWER_MAP[{i:#04X}]");
        }
        for i in 0xC0u8..=0xD6 {
            assert_eq!(TOLOWER_MAP[i as usize], 0x20, "TOLOWER_MAP[{i:#04X}]");
        }
        for i in 0xD8u8..=0xDE {
            assert_eq!(TOLOWER_MAP[i as usize], 0x20, "TOLOWER_MAP[{i:#04X}]");
        }
        // Verified gaps: × (0xD7), ß (0xDF), ÿ (0xFF).
        assert_eq!(TOLOWER_MAP[0xD7], 0x00);
        assert_eq!(TOLOWER_MAP[0xDF], 0x00);
        assert_eq!(TOLOWER_MAP[0xFF], 0x00);
    }
}
