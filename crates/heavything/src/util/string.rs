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

//! String utilities wrapping Rust `String`/`&str`. Consolidates
//! `string32.inc` (4,550 lines) + `string16.inc` (4,513 lines) from the
//! HeavyThing assembly library into a single idiomatic Rust module.
//!
//! # Historical context (FASM original)
//!
//! The FASM sources implemented a hand-rolled string engine with an
//! 8-byte little-endian length prefix followed by either UTF-32
//! (`string32.inc`) or UTF-16 (`string16.inc`) codepoint arrays. The
//! 4-byte vs. 2-byte stride was selected at build time via the
//! `string_bits = 32 | 16` toggle declared in `ht_defaults.inc`
//! (line 82).
//!
//! Representative FASM entry points:
//!
//! * `string$new` — allocate 8 bytes, zero the length prefix.
//! * `string$copy` — deep-copy `length * stride + 8` bytes via `memcpy`.
//! * `string$reverse` — allocate a fresh buffer of identical size and
//!   swap codepoints from both ends toward the middle.
//! * `string$concat` — compute the combined length, allocate once,
//!   memcpy both source bodies sequentially.
//! * `string$equals`, `string$equalsnocase`, `string$length`,
//!   `string$find`, `string$tolower`, `string$toupper`, `string$split`,
//!   `string$startswith`, `string$endswith`, `string$replace`,
//!   `string$repeat`, etc.
//!
//! # Rust strategy (per AAP §0.5.1.7 and §0.8.9)
//!
//! Per AAP §0.5.1.7, the `string_bits` compile-time toggle is **collapsed
//! to Rust native strings**. Rust's `String`/`&str` are UTF-8 byte
//! sequences which can represent every Unicode scalar value (the same
//! set UTF-16 and UTF-32 encode), so no information is lost. The
//! 8-byte length prefix that the FASM engine managed manually is
//! implicit in Rust's `String` (the smart pointer already tracks
//! `len` + `capacity`).
//!
//! Mapping of FASM entry points to Rust:
//!
//! | FASM                       | Rust                                         |
//! |----------------------------|----------------------------------------------|
//! | `string$new`               | [`String::new`] (via [`new`] here)           |
//! | `string$copy`              | [`str::to_owned`] (via [`copy`] here)        |
//! | `string$reverse`           | [`str::chars`] + [`Iterator::rev`]           |
//! | `string$concat`            | [`String::with_capacity`] + [`String::push_str`] |
//! | `string$equals`            | `a == b`                                     |
//! | `string$equalsnocase`      | [`unicodecase::eq_ignore_case`]              |
//! | `string$length`            | [`str::chars`] + [`Iterator::count`]         |
//! | `string$tolower`           | [`char::to_lowercase`] via flat-map          |
//! | `string$toupper`           | [`char::to_uppercase`] via flat-map          |
//! | `string$find`              | [`str::find`]                                |
//! | `string$startswith`        | [`str::starts_with`]                         |
//! | `string$endswith`          | [`str::ends_with`]                           |
//! | `string$split`             | [`str::split`] collected into `Vec<String>`  |
//! | `string$trim`              | [`str::trim`]                                |
//! | `string$replace`           | [`str::replace`]                             |
//! | `string$repeat`            | [`str::repeat`]                              |
//!
//! # Case folding — intentional divergence
//!
//! Two case-folding layers coexist in the HeavyThing Rust port:
//!
//! * [`to_upper`] / [`to_lower`] in *this* module delegate to
//!   [`char::to_uppercase`] / [`char::to_lowercase`], which implement
//!   the full Unicode Standard derived-core-properties case mapping.
//!   For example, `to_upper("ß")` correctly yields `"SS"` (a single
//!   codepoint expanding to two), matching modern IETF/W3C
//!   expectations.
//! * [`equals_ci`] delegates to [`unicodecase::eq_ignore_case`], which
//!   preserves the **FASM-quirky** case table from `unicodecase.inc`.
//!   The FASM table uses simple XOR-based byte-level folding that
//!   does NOT match the Unicode Standard (e.g., `toupper('ß') = 'ÿ'`).
//!   This quirk is deliberately preserved to keep wire-level
//!   observable behavior (HTTP header matching, SSH authentication,
//!   TUI form input) byte-identical to the assembly baseline — see
//!   AAP §0.8.1 "preserve all observable behavior".
//!
//! This module does **not** handle numeric string formatting (padding,
//! grouping, base conversion with arbitrary width). Those concerns
//! live in [`crate::util::formatter`] and
//! [`crate::util::string_math`]. The simple `parse_*` / `*_to_string`
//! helpers here cover the common integer-conversion paths consumed by
//! the net, tui, and showcase-application layers.

use crate::util::unicodecase;

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// Create a new empty `String`.
///
/// Matches FASM `string$new`, which allocated an 8-byte buffer with a
/// zero length prefix. In Rust this is simply [`String::new`], which
/// allocates no backing storage until the first mutation — a strict
/// improvement over the FASM version which always allocated 8 bytes.
#[must_use]
pub fn new() -> String {
    String::new()
}

/// Create a new `String` from a byte slice.
///
/// If `bytes` contain invalid UTF-8 sequences, the invalid bytes are
/// replaced with the Unicode replacement character (`U+FFFD`) via
/// [`String::from_utf8_lossy`]. This permissive policy matches the
/// FASM engine which accepted arbitrary byte input and round-tripped
/// it through the codepoint array without validation.
#[must_use]
pub fn from_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Deep-copy a string.
///
/// Matches FASM `string$copy`, which allocated a new buffer of
/// `length * stride + 8` bytes and `memcpy`'d the source. In Rust
/// [`str::to_owned`] performs the equivalent heap allocation plus
/// byte copy.
#[must_use]
pub fn copy(s: &str) -> String {
    s.to_owned()
}

/// Reverse a string by code-points.
///
/// Matches FASM `string$reverse`, which operated on UTF-32 (or UTF-16)
/// codepoints. Rust's [`str::chars`] iterator yields Unicode scalar
/// values (equivalent to UTF-32 codepoints for any valid UTF-8 input),
/// so [`Iterator::rev`] + `collect` produces byte-identical output to
/// the FASM implementation for every valid input.
///
/// # Examples
///
/// ```ignore
/// // Internal module — exercised via crate tests.
/// assert_eq!(reverse("hello"), "olleh");
/// assert_eq!(reverse("áëî"), "îëá"); // multi-byte codepoints
/// ```
#[must_use]
pub fn reverse(s: &str) -> String {
    s.chars().rev().collect()
}

/// Concatenate two strings into a newly allocated `String`.
///
/// Matches FASM `string$concat`. Pre-sizes the output via
/// [`String::with_capacity`] to eliminate the intermediate reallocation
/// that a naive `a.to_owned() + b` would incur.
#[must_use]
pub fn concat(a: &str, b: &str) -> String {
    let mut out = String::with_capacity(a.len() + b.len());
    out.push_str(a);
    out.push_str(b);
    out
}

/// Concatenate any number of string slices into a newly allocated
/// `String`.
///
/// Generalises [`concat`] to N-way joins. Pre-sizes the output using
/// the sum of input byte-lengths so only one heap allocation occurs
/// for the whole operation. This is the idiomatic Rust replacement
/// for the FASM pattern of chained `string$concat` calls each of
/// which allocated and discarded intermediate buffers.
#[must_use]
pub fn concat_many(parts: &[&str]) -> String {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = String::with_capacity(total);
    for p in parts {
        out.push_str(p);
    }
    out
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

/// Compare two strings for byte-exact equality.
///
/// Matches FASM `string$equals`. Rust's built-in `==` operator on
/// `&str` already performs a byte-level compare after a length pre-
/// check, exactly as the FASM implementation did with `rep cmpsq`
/// over the codepoint arrays.
#[must_use]
pub fn equals(a: &str, b: &str) -> bool {
    a == b
}

/// Compare two strings for case-insensitive equality using the
/// HeavyThing Unicode case tables.
///
/// Matches FASM `string$equalsnocase`. Delegates to
/// [`unicodecase::eq_ignore_case`], which reproduces the FASM
/// `unicodecase.inc` XOR-based case tables verbatim — including the
/// FASM-quirky behavior that `toupper('ß') = 'ÿ'` (rather than the
/// Unicode Standard `'SS'`). This quirk is preserved to keep HTTP
/// header / SSH username / TUI input matching byte-identical to the
/// assembly baseline.
///
/// If you need Unicode-Standard-compliant case folding, use
/// [`to_upper`] / [`to_lower`] and compare the results.
#[must_use]
pub fn equals_ci(a: &str, b: &str) -> bool {
    unicodecase::eq_ignore_case(a, b)
}

// ---------------------------------------------------------------------------
// Length
// ---------------------------------------------------------------------------

/// Return the length of `s` in **Unicode code-points** (not bytes).
///
/// Matches FASM `string$length`, which returned the codepoint count
/// stored in the 8-byte length prefix. In UTF-8, the codepoint count
/// can be smaller than the byte count because non-ASCII codepoints
/// occupy 2–4 bytes. Use [`length_bytes`] when you need the storage
/// size of the string.
///
/// This is an O(n) operation in the byte length of `s` — it scans
/// the UTF-8 byte sequence to count codepoints. Cache the result
/// when calling in a tight loop.
#[must_use]
pub fn length_cp(s: &str) -> usize {
    s.chars().count()
}

/// Return the length of `s` in UTF-8 bytes.
///
/// Equivalent to [`str::len`] on the underlying `&str`. Constant-time.
/// Use this when allocating output buffers or computing Content-Length
/// style wire-protocol headers; use [`length_cp`] when presenting
/// human-meaningful "character counts" in TUI layouts.
#[must_use]
pub fn length_bytes(s: &str) -> usize {
    s.len()
}

// ---------------------------------------------------------------------------
// Case conversion (full Unicode)
// ---------------------------------------------------------------------------

/// Uppercase a string using **full Unicode case mapping**.
///
/// Uses [`char::to_uppercase`], which implements the Unicode Standard
/// derived-core-properties case mapping — including multi-codepoint
/// expansions such as `'ß'` → `"SS"` and `'ﬁ'` → `"FI"`.
///
/// Note: this intentionally differs from
/// [`unicodecase::to_upper`](crate::util::unicodecase::to_upper),
/// which preserves the FASM-quirky byte-level case table for wire-
/// protocol-compatibility reasons. Use this function when you want
/// modern Unicode-compliant case mapping for display, sorting, or
/// JSON output; use the `unicodecase` routines when you need byte-
/// identical output to the FASM baseline.
#[must_use]
pub fn to_upper(s: &str) -> String {
    s.chars().flat_map(char::to_uppercase).collect()
}

/// Lowercase a string using **full Unicode case mapping**.
///
/// Uses [`char::to_lowercase`], which implements the Unicode Standard
/// derived-core-properties case mapping. See [`to_upper`] for the
/// rationale behind the split between Unicode-Standard folding
/// here versus the FASM-compatible folding in
/// [`crate::util::unicodecase`].
#[must_use]
pub fn to_lower(s: &str) -> String {
    s.chars().flat_map(char::to_lowercase).collect()
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

/// Find the first occurrence of `needle` in `haystack`, returning the
/// **byte offset** of its start or `None`.
///
/// Matches FASM `string$find`. The returned index is a valid byte
/// offset suitable for slicing into `haystack` via `&haystack[idx..]`.
/// Unlike the FASM implementation (which returned a codepoint index),
/// this returns a UTF-8 byte index — the more useful quantity for
/// downstream slicing operations. Call sites that need the codepoint
/// index can compute it as `haystack[..idx].chars().count()`.
#[must_use]
pub fn find(haystack: &str, needle: &str) -> Option<usize> {
    haystack.find(needle)
}

/// Case-insensitive substring search using **full Unicode case
/// folding** (via [`to_lower`]).
///
/// Lowercases both operands and then searches. The returned index is
/// a byte offset into the **lowercased** form of `haystack`, which
/// may differ from a byte offset into the original `haystack` if the
/// string contains codepoints whose lowercase form has a different
/// UTF-8 byte length (e.g., `'İ'` U+0130 = 2 bytes → `'i'` + combining
/// dot U+0307 = 3 bytes). This matches the FASM `string$findnocase`
/// contract, which likewise returned an offset into the folded
/// comparison buffer.
///
/// For HTTP header or URI matching where byte offsets into the
/// original must be exact, prefer pre-lowercasing the input once and
/// tracking offsets explicitly.
#[must_use]
pub fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let haystack_lower = to_lower(haystack);
    let needle_lower = to_lower(needle);
    haystack_lower.find(&needle_lower)
}

/// Check whether `s` starts with the given `prefix`.
///
/// Matches FASM `string$startswith`. Delegates to
/// [`str::starts_with`], which performs a byte-level compare after a
/// length pre-check.
#[must_use]
pub fn starts_with(s: &str, prefix: &str) -> bool {
    s.starts_with(prefix)
}

/// Check whether `s` ends with the given `suffix`.
///
/// Matches FASM `string$endswith`. Delegates to [`str::ends_with`].
#[must_use]
pub fn ends_with(s: &str, suffix: &str) -> bool {
    s.ends_with(suffix)
}

// ---------------------------------------------------------------------------
// Splitting
// ---------------------------------------------------------------------------

/// Split `s` on every occurrence of the separator character `sep`.
///
/// Matches FASM `string$split`. Returns a newly-allocated `Vec` of
/// owned `String`s. Empty slices produced by adjacent separators or
/// by separators at either end are preserved in the output, matching
/// [`str::split`] semantics.
#[must_use]
pub fn split(s: &str, sep: char) -> Vec<String> {
    s.split(sep).map(|part| part.to_owned()).collect()
}

/// Split `s` on every occurrence of the string separator `sep`.
///
/// Matches FASM `string$split_str`. Returns a newly-allocated `Vec`
/// of owned `String`s. `sep` must be non-empty; passing an empty
/// separator yields the degenerate empty-match sequence from
/// [`str::split`].
#[must_use]
pub fn split_str(s: &str, sep: &str) -> Vec<String> {
    s.split(sep).map(|part| part.to_owned()).collect()
}

// ---------------------------------------------------------------------------
// Trimming
// ---------------------------------------------------------------------------

/// Trim leading and trailing whitespace.
///
/// Matches FASM `string$trim`. Delegates to [`str::trim`], which uses
/// the Unicode Standard definition of whitespace
/// (`U+0009`..=`U+000D`, `U+0020`, plus the additional `White_Space`
/// characters). This is a superset of the ASCII whitespace set the
/// FASM `string$trim` recognised, but identical on the ASCII inputs
/// the HeavyThing protocol parsers actually produce.
#[must_use]
pub fn trim(s: &str) -> String {
    s.trim().to_owned()
}

/// Trim leading whitespace only.
///
/// Matches FASM `string$trim_left` (and the reverse-direction variant
/// of `string$trim`). Delegates to [`str::trim_start`].
#[must_use]
pub fn trim_start(s: &str) -> String {
    s.trim_start().to_owned()
}

/// Trim trailing whitespace only.
///
/// Matches FASM `string$trim_right`. Delegates to [`str::trim_end`].
#[must_use]
pub fn trim_end(s: &str) -> String {
    s.trim_end().to_owned()
}

// ---------------------------------------------------------------------------
// Replace / repeat
// ---------------------------------------------------------------------------

/// Replace every occurrence of the substring `from` with `to`.
///
/// Matches FASM `string$replace`. Delegates to [`str::replace`],
/// which scans left-to-right and is non-overlapping: once a match is
/// replaced, scanning resumes at the character after the replacement,
/// not inside it.
#[must_use]
pub fn replace(s: &str, from: &str, to: &str) -> String {
    s.replace(from, to)
}

/// Repeat `s` exactly `n` times end-to-end.
///
/// Matches the FASM `string$repeat` pattern of an alloc-once,
/// memcpy-in-a-loop idiom. Delegates to [`str::repeat`].
#[must_use]
pub fn repeat(s: &str, n: usize) -> String {
    s.repeat(n)
}

// ---------------------------------------------------------------------------
// Integer ↔ String conversion
// ---------------------------------------------------------------------------

/// Parse a decimal `&str` into an `i64`.
///
/// Accepts an optional leading `+` or `-` sign and returns `None` on
/// any parse failure (including overflow, empty string, or non-digit
/// characters after optional surrounding whitespace). Surrounding
/// whitespace is trimmed per the FASM `string$to_int` convention.
#[must_use]
pub fn parse_i64(s: &str) -> Option<i64> {
    s.trim().parse::<i64>().ok()
}

/// Parse a decimal `&str` into a `u64`.
///
/// Returns `None` on any parse failure (empty string, overflow, non-
/// digit characters, or a leading `-`). Surrounding whitespace is
/// trimmed. Unlike [`parse_i64`], a leading `+` is **not** accepted
/// (matching [`u64::from_str`]'s stricter behavior).
#[must_use]
pub fn parse_u64(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok()
}

/// Parse a hexadecimal `&str` into a `u64`.
///
/// Accepts an optional `0x` or `0X` prefix (case-insensitive), then
/// delegates to [`u64::from_str_radix`] with radix 16. Hex digits
/// `a..=f` / `A..=F` are both accepted. Surrounding whitespace is
/// trimmed before the prefix is stripped.
#[must_use]
pub fn parse_hex_u64(s: &str) -> Option<u64> {
    let trimmed = s.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u64::from_str_radix(stripped, 16).ok()
}

/// Format an `i64` as a decimal `String`.
///
/// Negative values get a leading `-`. Matches FASM
/// `string$from_int`'s decimal output. For custom padding / grouping
/// see [`crate::util::formatter`].
#[must_use]
pub fn i64_to_string(n: i64) -> String {
    n.to_string()
}

/// Format a `u64` as a decimal `String`.
///
/// Matches the unsigned variant of FASM `string$from_int`.
#[must_use]
pub fn u64_to_string(n: u64) -> String {
    n.to_string()
}

/// Format a `u64` as a lowercase hexadecimal `String` **without** a
/// `0x` prefix.
///
/// Matches FASM `string$from_hex` default output (lowercase, no
/// prefix). Prepend `"0x"` at the call site if prefixed output is
/// required. For an uppercase form, `format!("{n:X}")` can be used
/// directly at the call site.
#[must_use]
pub fn u64_to_hex(n: u64) -> String {
    format!("{n:x}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    #[test]
    fn empty_string() {
        assert_eq!(new(), "");
        assert_eq!(length_cp(""), 0);
        assert_eq!(length_bytes(""), 0);
    }

    #[test]
    fn from_bytes_roundtrip_ascii() {
        assert_eq!(from_bytes(b"hello"), "hello");
    }

    #[test]
    fn from_bytes_roundtrip_utf8() {
        // "héllo" in UTF-8 is 68 C3 A9 6C 6C 6F.
        let utf8 = b"h\xc3\xa9llo";
        assert_eq!(from_bytes(utf8), "héllo");
    }

    #[test]
    fn from_bytes_lossy_invalid() {
        // 0xFF is never a valid UTF-8 leading byte; it should be
        // replaced with U+FFFD, not propagated as a parse error.
        let invalid = b"ab\xffcd";
        let result = from_bytes(invalid);
        assert!(result.contains('\u{FFFD}'));
        assert!(result.starts_with("ab"));
        assert!(result.ends_with("cd"));
    }

    #[test]
    fn copy_is_deep() {
        let a = String::from("owned");
        let b = copy(&a);
        // Mutating `a` must not affect `b`.
        drop(a);
        assert_eq!(b, "owned");
    }

    // ------------------------------------------------------------------
    // Reverse
    // ------------------------------------------------------------------

    #[test]
    fn reverse_ascii() {
        assert_eq!(reverse("hello"), "olleh");
    }

    #[test]
    fn reverse_unicode() {
        // Multi-byte chars reversed by codepoint.
        assert_eq!(reverse("áëî"), "îëá");
    }

    #[test]
    fn reverse_empty_and_single() {
        assert_eq!(reverse(""), "");
        assert_eq!(reverse("x"), "x");
    }

    #[test]
    fn reverse_is_involutive_for_bmp() {
        // Double-reverse of a BMP-only string yields the original.
        let s = "The quick brown fox";
        assert_eq!(reverse(&reverse(s)), s);
    }

    // ------------------------------------------------------------------
    // Concat
    // ------------------------------------------------------------------

    #[test]
    fn concat_basic() {
        assert_eq!(concat("foo", "bar"), "foobar");
        assert_eq!(concat_many(&["a", "b", "c"]), "abc");
    }

    #[test]
    fn concat_empty() {
        assert_eq!(concat("", ""), "");
        assert_eq!(concat("x", ""), "x");
        assert_eq!(concat("", "y"), "y");
        assert_eq!(concat_many(&[]), "");
        assert_eq!(concat_many(&[""]), "");
    }

    // ------------------------------------------------------------------
    // Equality
    // ------------------------------------------------------------------

    #[test]
    fn equals_basic() {
        assert!(equals("abc", "abc"));
        assert!(!equals("abc", "abd"));
        assert!(!equals("abc", "ab"));
        assert!(!equals("ab", "abc"));
        assert!(equals("", ""));
    }

    #[test]
    fn equals_ci_ascii() {
        assert!(equals_ci("Hello", "HELLO"));
        assert!(equals_ci("hello", "HeLlO"));
        assert!(!equals_ci("hello", "world"));
    }

    // ------------------------------------------------------------------
    // Length
    // ------------------------------------------------------------------

    #[test]
    fn length_cp_vs_bytes() {
        let s = "héllo"; // 'é' (U+00E9) is 2 bytes in UTF-8.
        assert_eq!(length_cp(s), 5);
        assert_eq!(length_bytes(s), 6);
    }

    #[test]
    fn length_cp_4byte_utf8() {
        // U+1F600 GRINNING FACE is a 4-byte UTF-8 sequence but one
        // codepoint.
        let s = "ab\u{1F600}cd";
        assert_eq!(length_cp(s), 5);
        assert_eq!(length_bytes(s), 4 + 4);
    }

    // ------------------------------------------------------------------
    // Case conversion (full Unicode via stdlib)
    // ------------------------------------------------------------------

    #[test]
    fn case_conversion() {
        assert_eq!(to_upper("hello"), "HELLO");
        assert_eq!(to_lower("WORLD"), "world");
        // Full Unicode case folding via stdlib — deliberately
        // different from `unicodecase::to_upper` which preserves
        // the FASM-quirky single-codepoint mapping.
        assert_eq!(to_upper("ß"), "SS");
    }

    #[test]
    fn case_conversion_mixed() {
        assert_eq!(to_upper("MixedCase123"), "MIXEDCASE123");
        assert_eq!(to_lower("MixedCase123"), "mixedcase123");
    }

    #[test]
    fn case_conversion_empty() {
        assert_eq!(to_upper(""), "");
        assert_eq!(to_lower(""), "");
    }

    // ------------------------------------------------------------------
    // Search
    // ------------------------------------------------------------------

    #[test]
    fn find_basic() {
        assert_eq!(find("hello world", "world"), Some(6));
        assert_eq!(find("hello world", "xyz"), None);
        assert_eq!(find("", ""), Some(0));
        assert_eq!(find("abc", ""), Some(0));
    }

    #[test]
    fn find_ci_basic() {
        assert_eq!(find_ci("Hello World", "world"), Some(6));
        assert_eq!(find_ci("Hello World", "WORLD"), Some(6));
        assert_eq!(find_ci("hello", "X"), None);
    }

    #[test]
    fn starts_ends_with() {
        assert!(starts_with("hello world", "hello"));
        assert!(!starts_with("hello world", "world"));
        assert!(ends_with("hello world", "world"));
        assert!(!ends_with("hello world", "hello"));
        assert!(starts_with("abc", ""));
        assert!(ends_with("abc", ""));
    }

    // ------------------------------------------------------------------
    // Split
    // ------------------------------------------------------------------

    #[test]
    fn split_basic() {
        assert_eq!(split("a,b,c", ','), vec!["a", "b", "c"]);
        assert_eq!(split_str("a::b::c", "::"), vec!["a", "b", "c"]);
    }

    #[test]
    fn split_preserves_empties() {
        assert_eq!(split(",,", ','), vec!["", "", ""]);
        assert_eq!(split("", ','), vec![""]);
    }

    #[test]
    fn split_str_multichar_separator() {
        assert_eq!(split_str("foo--bar--baz", "--"), vec!["foo", "bar", "baz"]);
    }

    // ------------------------------------------------------------------
    // Trim
    // ------------------------------------------------------------------

    #[test]
    fn trim_basic() {
        assert_eq!(trim("  hello  "), "hello");
        assert_eq!(trim_start("  hello  "), "hello  ");
        assert_eq!(trim_end("  hello  "), "  hello");
        assert_eq!(trim("\t\n xyz \r\n"), "xyz");
    }

    #[test]
    fn trim_nothing_to_trim() {
        assert_eq!(trim("hello"), "hello");
        assert_eq!(trim(""), "");
    }

    // ------------------------------------------------------------------
    // Replace / repeat
    // ------------------------------------------------------------------

    #[test]
    fn replace_all() {
        assert_eq!(replace("aaa", "a", "bc"), "bcbcbc");
    }

    #[test]
    fn replace_not_found() {
        assert_eq!(replace("hello", "xyz", "abc"), "hello");
    }

    #[test]
    fn replace_overlap_left_to_right() {
        // "aaa" with "aa" -> "a" scans left-to-right non-overlapping:
        // first match at offset 0 replaces "aa", leaving "aa" at
        // offset 1 → then the remaining "a" is untouched.
        // Rust stdlib non-overlapping semantics: "aaaa" + "aa" -> "bb"
        // actually works as "aa" -> "b" + "aa" -> "b" = "bb".
        assert_eq!(replace("aaaa", "aa", "b"), "bb");
    }

    #[test]
    fn repeat_basic() {
        assert_eq!(repeat("ab", 3), "ababab");
        assert_eq!(repeat("x", 0), "");
        assert_eq!(repeat("", 5), "");
    }

    // ------------------------------------------------------------------
    // Integer parsing
    // ------------------------------------------------------------------

    #[test]
    fn parse_numbers() {
        assert_eq!(parse_i64("42"), Some(42));
        assert_eq!(parse_i64("-42"), Some(-42));
        assert_eq!(parse_hex_u64("0xff"), Some(255));
        assert_eq!(parse_hex_u64("FF"), Some(255));
    }

    #[test]
    fn parse_i64_whitespace_tolerant() {
        assert_eq!(parse_i64("   100   "), Some(100));
        assert_eq!(parse_i64("\t-7\n"), Some(-7));
    }

    #[test]
    fn parse_i64_invalid() {
        assert_eq!(parse_i64(""), None);
        assert_eq!(parse_i64("abc"), None);
        assert_eq!(parse_i64("1.5"), None);
        // Overflow.
        assert_eq!(parse_i64("99999999999999999999"), None);
    }

    #[test]
    fn parse_u64_rejects_negative() {
        assert_eq!(parse_u64("-1"), None);
        assert_eq!(parse_u64("0"), Some(0));
        assert_eq!(parse_u64("18446744073709551615"), Some(u64::MAX));
        // MAX + 1 overflows.
        assert_eq!(parse_u64("18446744073709551616"), None);
    }

    #[test]
    fn parse_hex_u64_prefix_variants() {
        assert_eq!(parse_hex_u64("0xDEADBEEF"), Some(0xDEAD_BEEF));
        assert_eq!(parse_hex_u64("0XDEADBEEF"), Some(0xDEAD_BEEF));
        assert_eq!(parse_hex_u64("deadbeef"), Some(0xDEAD_BEEF));
        assert_eq!(parse_hex_u64("  0xff "), Some(0xFF));
        assert_eq!(parse_hex_u64(""), None);
        assert_eq!(parse_hex_u64("0x"), None);
        assert_eq!(parse_hex_u64("xyz"), None);
    }

    // ------------------------------------------------------------------
    // Integer formatting
    // ------------------------------------------------------------------

    #[test]
    fn i64_to_string_basic() {
        assert_eq!(i64_to_string(0), "0");
        assert_eq!(i64_to_string(42), "42");
        assert_eq!(i64_to_string(-42), "-42");
        assert_eq!(i64_to_string(i64::MIN), "-9223372036854775808");
        assert_eq!(i64_to_string(i64::MAX), "9223372036854775807");
    }

    #[test]
    fn u64_to_string_basic() {
        assert_eq!(u64_to_string(0), "0");
        assert_eq!(u64_to_string(u64::MAX), "18446744073709551615");
    }

    #[test]
    fn u64_to_hex_basic() {
        assert_eq!(u64_to_hex(0), "0");
        assert_eq!(u64_to_hex(0xDEAD_BEEF), "deadbeef");
        assert_eq!(u64_to_hex(u64::MAX), "ffffffffffffffff");
    }

    // ------------------------------------------------------------------
    // Roundtrip invariants
    // ------------------------------------------------------------------

    #[test]
    fn parse_format_roundtrip_i64() {
        for &n in &[0_i64, 1, -1, 42, -42, i64::MIN, i64::MAX, 1_000_000] {
            let s = i64_to_string(n);
            assert_eq!(parse_i64(&s), Some(n));
        }
    }

    #[test]
    fn parse_format_roundtrip_u64() {
        for &n in &[0_u64, 1, 42, 255, u64::MAX, 1_000_000] {
            let s = u64_to_string(n);
            assert_eq!(parse_u64(&s), Some(n));
        }
    }

    #[test]
    fn parse_format_roundtrip_hex() {
        for &n in &[0_u64, 1, 0xFF, 0xDEAD_BEEF, u64::MAX] {
            let s = u64_to_hex(n);
            assert_eq!(parse_hex_u64(&s), Some(n));
        }
    }
}
