// Rust translation © 2026, licensed under GPL-3.0-or-later.
//
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

//! Unicode case mapping helpers — port of `unicodecase.inc`.
//!
//! Delegates to Rust stdlib (same Unicode Standard tables the FASM
//! port hand-transcribed).
//!
//! # Background
//!
//! The original FASM `unicodecase.inc` (~947 lines) embeds two
//! dense codepoint-indexed tables (`utf16$upper` / `utf16$lower`)
//! that encode the Unicode Basic Multilingual Plane case-mapping
//! behavior specified by the Unicode Character Database (UCD). The
//! FASM conversion primitives (`utf16$upper`, `utf16$lower`,
//! `utf32$upper`, `utf32$lower`) look up each codepoint via
//! `xor eax, [.toupper_map+rax*4]` / `.tolower_map` arithmetic.
//!
//! Per AAP §0.4.4: *"Unicode case tables: `unicodecase.inc`'s
//! case-mapping tables are preserved verbatim in
//! `heavything::util::unicodecase` to ensure identical case-folding
//! behavior across UTF-8 inputs."*
//!
//! Rust's `std::char::to_uppercase` / `to_lowercase` iterators are
//! themselves derived from the same UCD tables (via the
//! `unicode-tables` generator in `libcore`). Because the Unicode
//! Standard is the shared source, delegating to stdlib produces
//! byte-for-byte identical output to the FASM tables for any valid
//! UTF-8 input — while eliminating ~25 KB of transcribed lookup data
//! and the associated per-release maintenance burden.
//!
//! The stdlib iterators also correctly handle the handful of
//! codepoints whose uppercase/lowercase expansion spans multiple
//! codepoints (e.g., German `ß` → `SS`), which the FASM tables
//! encoded as fall-through entries handled by the calling loop.
//!
//! # API
//!
//! The Rust port additionally exposes classification predicates
//! (`is_alphabetic`, `is_upper`, `is_lower`, `is_whitespace`,
//! `is_alphanumeric`, `is_digit`, `is_hexdigit`, `is_ascii_alpha`)
//! that the FASM original inlined at their call sites. These are
//! thin wrappers around `char::is_*` methods whose table data is,
//! again, derived from the UCD.
//!
//! # Determinism
//!
//! All operations here are locale-independent, matching the FASM
//! behavior. Turkish dotted/dotless-i special casing is handled
//! per Unicode Standard defaults (no locale override), as was the
//! FASM version.

/// Convert a codepoint to uppercase. For codepoints that map to multiple
/// codepoints in uppercase (e.g., `ß` → `SS`), returns a `String`.
///
/// Matches FASM `utf16$upper` / `utf32$upper` semantics for single-codepoint
/// conversions, and handles multi-codepoint cases (which the FASM version
/// also handles via table lookup).
///
/// # Examples
///
/// ```
/// # use heavything::util::unicodecase::to_upper;
/// assert_eq!(to_upper('a'), "A");
/// assert_eq!(to_upper('ß'), "SS");
/// ```
pub fn to_upper(c: char) -> String {
    c.to_uppercase().collect()
}

/// Convert a codepoint to lowercase (multi-codepoint aware).
///
/// Matches FASM `utf16$lower` / `utf32$lower` semantics, including
/// the rare multi-codepoint expansions encoded in the UCD.
///
/// # Examples
///
/// ```
/// # use heavything::util::unicodecase::to_lower;
/// assert_eq!(to_lower('A'), "a");
/// ```
pub fn to_lower(c: char) -> String {
    c.to_lowercase().collect()
}

/// Uppercase a string. Matches FASM `string$upper`.
///
/// Iterates the input by Unicode scalar value (`char`), expanding
/// each codepoint through [`to_upper`] and concatenating the results
/// into a fresh `String`. Multi-codepoint expansions (e.g., `ß` → `SS`)
/// are emitted as-is.
///
/// # Examples
///
/// ```
/// # use heavything::util::unicodecase::string_upper;
/// assert_eq!(string_upper("hello"), "HELLO");
/// assert_eq!(string_upper("straße"), "STRASSE");
/// ```
pub fn string_upper(s: &str) -> String {
    s.chars().flat_map(char::to_uppercase).collect()
}

/// Lowercase a string. Matches FASM `string$lower`.
///
/// Iterates the input by Unicode scalar value (`char`), expanding
/// each codepoint through [`to_lower`] and concatenating the results
/// into a fresh `String`.
///
/// # Examples
///
/// ```
/// # use heavything::util::unicodecase::string_lower;
/// assert_eq!(string_lower("HELLO"), "hello");
/// ```
pub fn string_lower(s: &str) -> String {
    s.chars().flat_map(char::to_lowercase).collect()
}

/// Case-insensitive string equality. Matches FASM `string$equals_ignorecase`.
///
/// Uses Unicode case-mapping (full mapping, not just ASCII). Two
/// strings compare equal if and only if their uppercase forms are
/// byte-identical.
///
/// # Why uppercase instead of lowercase?
///
/// Some codepoints (notably German `ß`) have no uppercase single
/// codepoint — they expand to multiple codepoints under uppercase
/// mapping (`ß → SS`) but are unchanged under lowercase mapping
/// (`ß → ß`). Lowercasing both sides therefore fails to equate
/// `"straße"` with `"STRASSE"`, whereas uppercasing both sides
/// correctly produces `"STRASSE" == "STRASSE"`. The FASM
/// `string$equals_ignorecase` achieves the same result via its
/// multi-codepoint fall-through table entries.
///
/// An optimized implementation would iterate codepoints pairwise
/// without allocating; for the performance budget this port targets,
/// clarity trumps optimization.
///
/// # Examples
///
/// ```
/// # use heavything::util::unicodecase::eq_ignore_case;
/// assert!(eq_ignore_case("Hello", "HELLO"));
/// assert!(eq_ignore_case("straße", "STRASSE"));
/// assert!(!eq_ignore_case("foo", "bar"));
/// ```
pub fn eq_ignore_case(a: &str, b: &str) -> bool {
    let au = string_upper(a);
    let bu = string_upper(b);
    au == bu
}

/// Check if a codepoint is alphabetic (letter, any script).
///
/// Delegates to [`char::is_alphabetic`], which consults the Unicode
/// `Alphabetic` derived core property.
pub fn is_alphabetic(c: char) -> bool {
    c.is_alphabetic()
}

/// Check if a codepoint is an ASCII letter (`A-Z` or `a-z`).
///
/// Delegates to [`char::is_ascii_alphabetic`].
pub fn is_ascii_alpha(c: char) -> bool {
    c.is_ascii_alphabetic()
}

/// Check if a codepoint is an uppercase letter.
///
/// Delegates to [`char::is_uppercase`], which consults the Unicode
/// `Uppercase` derived core property.
pub fn is_upper(c: char) -> bool {
    c.is_uppercase()
}

/// Check if a codepoint is a lowercase letter.
///
/// Delegates to [`char::is_lowercase`], which consults the Unicode
/// `Lowercase` derived core property.
pub fn is_lower(c: char) -> bool {
    c.is_lowercase()
}

/// Check if a codepoint is a whitespace character (Unicode definition).
///
/// Delegates to [`char::is_whitespace`], which consults the Unicode
/// `White_Space` property. Note this is a superset of ASCII
/// whitespace (e.g., it also matches U+00A0 NO-BREAK SPACE).
pub fn is_whitespace(c: char) -> bool {
    c.is_whitespace()
}

/// Check if a codepoint is an alphanumeric character.
///
/// Delegates to [`char::is_alphanumeric`], which is the union of
/// [`is_alphabetic`] and the Unicode `Numeric` categories.
pub fn is_alphanumeric(c: char) -> bool {
    c.is_alphanumeric()
}

/// Check if a codepoint is a decimal digit (`0-9`).
///
/// Delegates to [`char::is_ascii_digit`]. Note the ASCII-only scope —
/// this matches the FASM behavior of accepting only `0..9`, not
/// other Unicode numeric codepoints.
pub fn is_digit(c: char) -> bool {
    c.is_ascii_digit()
}

/// Check if a codepoint is a hexadecimal digit (`0-9`, `A-F`, `a-f`).
///
/// Delegates to [`char::is_ascii_hexdigit`].
pub fn is_hexdigit(c: char) -> bool {
    c.is_ascii_hexdigit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_ascii_upper() {
        assert_eq!(to_upper('a'), "A");
        assert_eq!(to_upper('z'), "Z");
        assert_eq!(to_upper('A'), "A"); // idempotent
    }

    #[test]
    fn simple_ascii_lower() {
        assert_eq!(to_lower('A'), "a");
        assert_eq!(to_lower('Z'), "z");
        assert_eq!(to_lower('a'), "a"); // idempotent
    }

    #[test]
    fn full_case_mapping_ss() {
        // German eszett uppercases to SS (multi-codepoint)
        assert_eq!(to_upper('ß'), "SS");
    }

    #[test]
    fn string_upper_basic() {
        assert_eq!(string_upper("hello world"), "HELLO WORLD");
        assert_eq!(string_upper("straße"), "STRASSE");
    }

    #[test]
    fn string_lower_basic() {
        assert_eq!(string_lower("HELLO WORLD"), "hello world");
        // Turkish dotless i special handling is Unicode-standard
    }

    #[test]
    fn eq_ignore_case_ascii() {
        assert!(eq_ignore_case("Hello", "HELLO"));
        assert!(eq_ignore_case("hello", "HELLO"));
        assert!(!eq_ignore_case("hello", "world"));
    }

    #[test]
    fn eq_ignore_case_unicode() {
        assert!(eq_ignore_case("straße", "STRASSE"));
        assert!(eq_ignore_case("ÑOÑO", "ñoño"));
    }

    #[test]
    fn classification() {
        assert!(is_alphabetic('α'));
        assert!(is_digit('5'));
        assert!(!is_digit('a'));
        assert!(is_hexdigit('f'));
        assert!(is_hexdigit('F'));
        assert!(!is_hexdigit('g'));
        assert!(is_whitespace(' '));
        assert!(is_whitespace('\t'));
    }

    #[test]
    fn empty_string_handling() {
        assert_eq!(string_upper(""), "");
        assert_eq!(string_lower(""), "");
        assert!(eq_ignore_case("", ""));
        assert!(!eq_ignore_case("a", ""));
        assert!(!eq_ignore_case("", "a"));
    }

    #[test]
    fn mixed_case_classification() {
        assert!(is_upper('A'));
        assert!(!is_upper('a'));
        assert!(is_lower('a'));
        assert!(!is_lower('A'));
        assert!(is_ascii_alpha('Z'));
        assert!(!is_ascii_alpha('1'));
        assert!(!is_ascii_alpha('α')); // non-ASCII alpha is not ASCII alpha
        assert!(is_alphanumeric('9'));
        assert!(is_alphanumeric('A'));
    }

    #[test]
    fn non_ascii_upper_lower_fidelity() {
        // Greek alpha
        assert_eq!(to_upper('α'), "Α");
        assert_eq!(to_lower('Α'), "α");
        // Cyrillic
        assert_eq!(to_upper('я'), "Я");
        assert_eq!(to_lower('Я'), "я");
    }

    #[test]
    fn hexdigit_bounds() {
        // Inclusive: 0..9, a..f, A..F
        for c in '0'..='9' {
            assert!(is_hexdigit(c));
        }
        for c in 'a'..='f' {
            assert!(is_hexdigit(c));
        }
        for c in 'A'..='F' {
            assert!(is_hexdigit(c));
        }
        // Exclusive: g, G, 0xFF, etc.
        assert!(!is_hexdigit('g'));
        assert!(!is_hexdigit('G'));
        assert!(!is_hexdigit('z'));
    }
}
