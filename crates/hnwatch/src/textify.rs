//! ------------------------------------------------------------------------
//! HeavyThing x86_64 assembly language library and showcase programs
//! Copyright © 2015 2 Ton Digital
//! Homepage: <https://2ton.com.au/>
//! Author: Jeff Marrison <jeff@2ton.com.au>
//!
//! This file is part of the HeavyThing library.
//!
//! HeavyThing is free software: you can redistribute it and/or modify
//! it under the terms of the GNU General Public License, or
//! (at your option) any later version.
//!
//! HeavyThing is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU General Public License for more details.
//!
//! You should have received a copy of the GNU General Public License along
//! with the HeavyThing library. If not, see <http://www.gnu.org/licenses/>.
//! ------------------------------------------------------------------------
//!
//! `textify.rs`: Rust port of `hnwatch/textify.inc`.
//!
//! Since the "text" field of the Hacker News Firebase API returns HTML,
//! and the original HeavyThing library author had not transcribed a full
//! XML/XHTML parser into the library, this module is a "brute force, beat
//! it with a hammer" HTML stripper so that the comment viewing page looks
//! a little more sane than otherwise. Only the most common cases are
//! dealt with here.
//!
//! This Rust port preserves the exact transformation order, step count,
//! and behavior of the original assembly implementation per AAP §0.1.1
//! (byte-for-byte equivalent output for equivalent input) and §0.8.2
//! (minimal-change discipline — NO regex, NO external HTML parsers, NO
//! new transformations, NO additional entities/tags).
//!
//! # Public API
//!
//! The module exposes exactly one public function — [`textify`] — which
//! is consumed by `ui::itemupdaterow` and `ui::itemupdate` in the
//! `hnwatch` binary crate per AAP §0.5.1.10.
//!
//! # Safety
//!
//! This module contains NO `unsafe` blocks, NO I/O, NO logging, NO async,
//! and NO third-party crate dependencies (standard-library prelude only).
//! It contributes zero entries to `UNSAFE_AUDIT.md` per Gate 6.

// --- Cleartext constants (preserved verbatim from `textify.inc:205-221`) ---
//
// The FASM `cleartext` macro declares null-terminated ASCII string literals
// in a read-only data segment. The Rust equivalents are module-level
// `const &'static str` items; their byte contents match the assembly
// declarations exactly so that every `str::replace` / `str::find` call
// compares the same sequence of bytes as the corresponding
// `string$replace` / `string$indexof` in the assembly.

/// Paragraph-break open tag — `textify.inc:205` `cleartext .p, '<p>'`.
///
/// Step 1 replaces every occurrence of this tag with [`LF`].
const P_TAG: &str = "<p>";

/// Single-byte line-feed (U+000A) — `textify.inc:206` `cleartext .lf, 10`.
///
/// Substituted for [`P_TAG`] in step 1 to produce a terminal-friendly
/// paragraph break.
const LF: &str = "\n";

/// Hex numeric-entity prefix — `textify.inc:207` `cleartext .xent, '&#x'`.
///
/// Step 2 locates occurrences of this prefix and decodes the following
/// two hex digits plus the closing `;` as a single Latin-1 codepoint.
const XENT: &str = "&#x";

/// Empty replacement string — `textify.inc:208` `cleartext .emptystr, ''`.
///
/// Used as the replacement argument in step 3 to delete code/pre markup
/// sequences without introducing whitespace.
const EMPTY: &str = "";

/// Opening tag pair `<code><pre>` — `textify.inc:209`
/// `cleartext .codepre, '<code><pre>'`. Stripped in step 3.
const CODE_PRE: &str = "<code><pre>";

/// Opening tag pair `<pre><code>` — `textify.inc:210`
/// `cleartext .precode, '<pre><code>'`. Stripped in step 3.
const PRE_CODE: &str = "<pre><code>";

/// Closing tag pair `</code></pre>` — `textify.inc:211`
/// `cleartext .endcodepre, '</code></pre>'`. Stripped in step 3.
const END_CODE_PRE: &str = "</code></pre>";

/// Named entity for `<` — `textify.inc:212` `cleartext .lt, '&lt;'`.
/// Replaced with [`LESS_THAN`] FIRST in step 4 (order-critical).
const LT_ENT: &str = "&lt;";

/// Named entity for `>` — `textify.inc:213` `cleartext .gt, '&gt;'`.
/// Replaced with [`GREATER_THAN`] SECOND in step 4 (order-critical).
const GT_ENT: &str = "&gt;";

/// Named entity for `&` — `textify.inc:214` `cleartext .amp, '&amp;'`.
/// Replaced with [`AMPERSAND`] THIRD in step 4 (order-critical — if
/// decoded earlier, nested entities such as `&amp;lt;` would collapse
/// to `<` instead of the correct `&lt;`).
const AMP_ENT: &str = "&amp;";

/// Named entity for `"` — `textify.inc:215` `cleartext .quot, '&quot;'`.
/// Replaced with [`QUOT_MARK`] FOURTH (and last) in step 4.
const QUOT_ENT: &str = "&quot;";

/// Literal `<` character — `textify.inc:216`
/// `cleartext .lessthan, '<'`.
const LESS_THAN: &str = "<";

/// Literal `>` character — `textify.inc:217`
/// `cleartext .greaterthan, '>'`.
const GREATER_THAN: &str = ">";

/// Literal `&` character — `textify.inc:218`
/// `cleartext .ampersand, '&'`.
const AMPERSAND: &str = "&";

/// Literal `"` character — `textify.inc:219`
/// `cleartext .quotmark, '"'`. Also used as a search pattern in step 5
/// to locate the closing quote of an `<a href="…">` URL.
const QUOT_MARK: &str = "\"";

/// Anchor-tag-with-href open sequence (9 bytes) — `textify.inc:220`
/// `cleartext .ahref, '<a href="'`.
///
/// Step 5 searches for this sequence; positions `idx+8` (the opening
/// quote) and `idx+9` (the first URL byte) are derived from this
/// length. The `idx+10` search origin used for the closing `"` and
/// `</a>` searches matches `textify.inc:162` and `:173`.
const AHREF: &str = "<a href=\"";

/// Anchor-tag close sequence (4 bytes) — `textify.inc:221`
/// `cleartext .ahrefclose, '</a>'`.
///
/// Step 5 searches for this sequence; the trailing `+4` offset applied
/// to `close_a` mirrors `textify.inc:179` `lea edx, [eax+4]` when
/// computing the total length of the `<a href="…">…</a>` substring to
/// excise.
const AHREF_CLOSE: &str = "</a>";

// --- Public API ---------------------------------------------------------

/// HTML-to-plain-text converter for Hacker News story bodies.
///
/// Applies the five transformation steps from `textify.inc` in the
/// original assembly order:
///
/// 1. Replace every `<p>` with `\n` (`textify.inc:38-42`).
/// 2. Decode `&#xNN;` hex numeric entities to their Latin-1 codepoints
///    (`textify.inc:44-89`). The assembly treats the decoded byte as a
///    single-byte UTF-8 input via `string$from_utf8(1 byte)`, producing
///    a string whose codepoint equals the byte value; `u8 as char` in
///    Rust matches this exact behavior. Only codepoints ≤ 0xFF are
///    supported — this is a preserved limitation, not a regression.
/// 3. Strip the code-block open/close sequences `<code><pre>`,
///    `<pre><code>`, and `</code></pre>` (`textify.inc:91-115`).
/// 4. Replace the named entities `&lt;`, `&gt;`, `&amp;`, `&quot;` with
///    their literal characters, **in that exact order**
///    (`textify.inc:117-148`). Reordering would cause double-decoding
///    of nested entities such as `&amp;lt;`.
/// 5. Replace `<a href="URL">text</a>` sequences with just `URL`
///    (`textify.inc:150-199`). Malformed input is passed through
///    gracefully: if a `<a href="` is not followed by a closing `"`
///    or a matching `</a>`, the function bails out of step 5 and
///    returns whatever has been transformed so far (mirrors the
///    `.nohrefs_free` and `.nohrefs` bailout labels at
///    `textify.inc:165` and `:176`).
///
/// # Parameters
///
/// * `input` — an HTML-ish string value as returned by the Hacker News
///   Firebase API in the `text` field of an item JSON payload.
///
/// # Returns
///
/// A freshly-allocated [`String`] with the five transformations applied.
/// Empty-input / plain-text-input is returned unchanged (no allocations
/// are elided, matching the assembly which always produces a new
/// heap-allocated string).
///
/// # Panics
///
/// This function does not panic. All index-based slicing uses
/// [`str::get`] with [`Option`] fall-through; malformed input causes a
/// clean early exit from the affected step, never a panic.
///
/// # Examples
///
/// ```ignore
/// // (Internal module — not part of the public crate API.)
/// let html = "<p>Hello &amp; welcome to \
///             <a href=\"https://2ton.com.au/\">2 Ton</a>!";
/// let text = textify(html);
/// assert_eq!(text, "\nHello & welcome to https://2ton.com.au/!");
/// ```
pub fn textify(input: &str) -> String {
    // ------------------------------------------------------------------
    // Step 1: turn <p> into \n  (textify.inc:38-42)
    //
    // The assembly `string$replace` returns a fresh string with every
    // occurrence replaced; Rust's `str::replace` has identical
    // semantics ("Replaces all matches of a pattern with another
    // string").
    // ------------------------------------------------------------------
    let mut s: String = input.replace(P_TAG, LF);

    // ------------------------------------------------------------------
    // Step 2: remove &#xNN; hex numeric entities  (textify.inc:44-89)
    //
    // The assembly loops:
    //   1. Find "&#x" (indexof). If -1, goto step 3.
    //   2. Extract the next 2 bytes (idx+3..idx+5) and lowercase them.
    //   3. Hex-decode those 2 bytes to a single byte.
    //   4. Convert that byte to a UTF-8 string via
    //      `string$from_utf8(1 byte)`.
    //   5. Extract the full 6-byte sequence "&#xNN;" (idx..idx+6).
    //   6. Replace all occurrences of that 6-byte sequence with the
    //      decoded character.
    //   7. Loop.
    //
    // The assembly assumes EXACTLY 2 hex digits followed by `;` — a
    // preserved limitation. Malformed entities (truncated, non-hex,
    // or missing `;`) cause a clean break out of the loop via the
    // `let-else` / `Option` fall-throughs below; the partially
    // transformed string is returned untouched for that step.
    // ------------------------------------------------------------------
    while let Some(idx) = s.find(XENT) {
        // Extract 2 hex chars at positions idx+3 .. idx+5 inclusive-
        // exclusive. `str::get` returns `None` if the range is out of
        // bounds or not at a UTF-8 boundary — both conditions are
        // treated as "malformed, stop".
        let Some(hex_slice) = s.get(idx + 3..idx + 5) else {
            break;
        };
        // Assembly `string$to_lower_inplace` before `string$hexdecode`
        // (textify.inc:59) ensures the two hex chars are lowercase so
        // both `&#xA0;` and `&#xa0;` decode identically.
        let hex_lower = hex_slice.to_ascii_lowercase();
        // `u8::from_str_radix(_, 16)` fails on non-hex input, which we
        // treat as "malformed entity, stop looping".
        let Ok(byte) = u8::from_str_radix(&hex_lower, 16) else {
            break;
        };
        // Assembly `string$from_utf8` on a single byte produces a
        // UTF-8 string whose codepoint equals the byte value
        // (equivalent to a Latin-1 → Unicode mapping). `u8 as char`
        // in Rust performs the exact same mapping because the Unicode
        // Consortium defined U+0000..U+00FF to coincide with ISO-8859-1.
        let replacement: String = (byte as char).to_string();
        // Build the exact 6-byte sequence "&#xHH;" starting at idx.
        // Using `get` (not slicing) guards against an unterminated
        // entity at end-of-string.
        let Some(target_slice) = s.get(idx..idx + 6) else {
            break;
        };
        let target: String = target_slice.to_string();
        // `string$replace` in the assembly operates on the full string
        // and replaces every occurrence; Rust `str::replace` does the
        // same.
        s = s.replace(&target, &replacement);
    }

    // ------------------------------------------------------------------
    // Step 3: strip code-block markers  (textify.inc:91-115)
    //
    // Three sequential `string$replace` calls with the empty-string
    // replacement target, in the exact assembly order:
    //   <code><pre>
    //   <pre><code>
    //   </code></pre>
    // ------------------------------------------------------------------
    s = s.replace(CODE_PRE, EMPTY);
    s = s.replace(PRE_CODE, EMPTY);
    s = s.replace(END_CODE_PRE, EMPTY);

    // ------------------------------------------------------------------
    // Step 4: replace the common named entities  (textify.inc:117-148)
    //
    // ORDER IS CRITICAL — the assembly decodes `&lt;` first, then
    // `&gt;`, then `&amp;`, then `&quot;`. Reordering would cause
    // double-decoding of nested forms such as `&amp;lt;` (which must
    // remain `&lt;` after the pass, NOT collapse to `<`).
    //
    // SCOPE — by design, EXACTLY FOUR named entities are decoded:
    // `&lt;`, `&gt;`, `&amp;`, `&quot;`. This matches the assembly's
    // `string$replace` call sites at `textify.inc:117-148` precisely;
    // no broader named-entity table (e.g. `&nbsp;`, `&ldquo;`,
    // `&rdquo;`, `&hellip;`, `&mdash;`) is consulted. Any other
    // `&name;` sequence passes through verbatim — this preserves the
    // FASM baseline behavior per AAP §0.1.1 (byte-for-byte output
    // parity) and AAP §0.5.1.10 / §0.8.2 (minimal-change discipline:
    // the Rust port MUST NOT add transformations not present in the
    // assembly). See `test_unsupported_named_entity_passes_through`.
    // ------------------------------------------------------------------
    s = s.replace(LT_ENT, LESS_THAN);
    s = s.replace(GT_ENT, GREATER_THAN);
    s = s.replace(AMP_ENT, AMPERSAND);
    s = s.replace(QUOT_ENT, QUOT_MARK);

    // ------------------------------------------------------------------
    // Step 5: replace <a href="URL">...</a> with just URL
    //                                         (textify.inc:150-199)
    //
    // The assembly:
    //   1. Find "<a href=\"" (indexof). If -1, goto return.
    //   2. Find the closing `"` starting at idx+10 (NOT idx+9 — the
    //      offset is `AHREF.len() + 1` = 9 + 1, which advances ONE
    //      byte PAST the opening `"`). This offset is load-bearing:
    //      it means the search for the closing `"` cannot match the
    //      opening `"` itself even when the URL is empty. Worked
    //      examples:
    //        - `<a href="/">X</a>`  → URL `/` IS extracted (the
    //          closing `"` is at position 10, which is exactly the
    //          search_start, and Rust's `str::find` includes that
    //          starting byte in the search range).
    //        - `<a href="">X</a>` (empty URL) → the search cannot
    //          find a closing `"` at position 10 (that byte is `>`),
    //          so it proceeds to the NEXT `"` in the input. If no
    //          later `"` exists, the algorithm bails cleanly; if a
    //          later `"` exists (e.g. `<a href="">X</a>"more"`), the
    //          algorithm misinterprets the intervening `">X</a>` as
    //          the URL. This is a preserved FASM quirk per AAP §0.1.1
    //          (byte-for-byte output parity). See the tests
    //          `test_empty_url_pathological` and
    //          `test_single_char_url_extracted` for coverage.
    //   3. If the closing `"` is missing, goto `.nohrefs` (bail out).
    //   4. Extract the URL as s[idx+9..close_quote].
    //   5. Find "</a>" starting at idx+10.
    //   6. If `</a>` is missing, goto `.nohrefs_free` (bail out,
    //      releasing the URL — in Rust this is handled by `String`
    //      Drop when the `url` local goes out of scope at the `break`).
    //   7. Extract the full substring s[idx..close_a+4].
    //   8. Replace the full substring with the URL.
    //   9. Loop.
    // ------------------------------------------------------------------
    while let Some(idx) = s.find(AHREF) {
        // `search_start = idx + 10` matches the assembly's
        // `[r12d+10]` literal offset at `textify.inc:162` and `:173`.
        // The +10 (not +9) is a preserved quirk: it advances ONE byte
        // past the opening `"`. A URL of length 1 (e.g. `/`) is still
        // extracted because the closing `"` lands at exactly
        // `search_start` and `str::find` includes that byte. A URL of
        // length 0 cannot be extracted from a self-contained anchor:
        // the search skips the opening+closing `"` pair entirely and
        // either bails (no later `"`) or misinterprets subsequent
        // text as the URL (see the module-level worked examples).
        let search_start = idx + 10;
        // `str::get(search_start..)` returns None when the offset is
        // out of bounds OR not at a UTF-8 boundary (the latter is
        // possible when the URL begins with a multi-byte codepoint
        // whose second byte falls at `search_start`). Both conditions
        // map to the assembly's "bailout" behavior.
        let Some(tail) = s.get(search_start..) else {
            break;
        };
        // First: locate the closing `"`.
        let Some(close_quote_rel) = tail.find(QUOT_MARK) else {
            break;
        };
        let close_quote = search_start + close_quote_rel;
        // Extract the URL: s[idx+9..close_quote]. Using `.get` guards
        // against pathological inputs where `close_quote < idx+9`
        // (the assembly would have undefined behavior here, but Rust's
        // range check returns None and we bail cleanly).
        let Some(url_slice) = s.get(idx + 9..close_quote) else {
            break;
        };
        let url: String = url_slice.to_string();
        // Second: locate the closing `</a>` from the SAME offset
        // (search_start = idx+10) — this is the assembly's behavior
        // per `textify.inc:173`, NOT starting from `close_quote`. We
        // can safely reuse `tail` since `s` has not been mutated yet.
        let Some(close_a_rel) = tail.find(AHREF_CLOSE) else {
            // `.nohrefs_free` path at `textify.inc:197-199` — the
            // assembly releases the URL heap allocation here; Rust's
            // `url: String` is dropped automatically when we break
            // out of this scope, achieving identical cleanup.
            break;
        };
        let close_a = search_start + close_a_rel;
        // Extract the full `<a href="…">…</a>` substring:
        // s[idx..close_a+4]. The +4 accounts for the length of
        // [`AHREF_CLOSE`] and matches `textify.inc:179`
        // `lea edx, [eax+4]`.
        let Some(full_slice) = s.get(idx..close_a + 4) else {
            break;
        };
        let full: String = full_slice.to_string();
        // Replace every occurrence of the full anchor with the URL —
        // matches assembly `string$replace` semantics (replaces all
        // occurrences in one pass).
        s = s.replace(&full, &url);
    }

    // Return the transformed string. `rax = rbx; pop; epilog` at
    // `textify.inc:202-204`.
    s
}

// --- Unit tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Unit tests for the [`textify`] function.
    //!
    //! Each test targets one of the five transformation steps, plus
    //! a small number of edge-case and combined-input scenarios, per
    //! the Validation Checklist in the file-level agent specification
    //! (AAP §0.8.4).

    use super::*;

    #[test]
    fn test_p_tag_replacement() {
        // Step 1: every <p> is replaced with a single \n.
        let input = "Line one<p>Line two<p>Line three";
        let expected = "Line one\nLine two\nLine three";
        assert_eq!(textify(input), expected);
    }

    #[test]
    fn test_hex_entity_decoding() {
        // Step 2: &#x27; → U+0027 (apostrophe), &#xA0; → U+00A0 (NBSP).
        // The Latin-1 → Unicode mapping is preserved exactly: `u8 as
        // char` at codepoint 0xA0 yields the non-breaking space.
        let input = "Smart &#x27; quote and &#xA0; nbsp";
        let expected = "Smart ' quote and \u{A0} nbsp";
        assert_eq!(textify(input), expected);
    }

    #[test]
    fn test_hex_entity_mixed_case() {
        // Step 2: upper-case and lower-case hex digits decode to the
        // same byte (the assembly's `string$to_lower_inplace` step
        // at `textify.inc:59` is preserved by `to_ascii_lowercase`).
        let input_upper = "x&#xA0;y";
        let input_lower = "x&#xa0;y";
        assert_eq!(textify(input_upper), textify(input_lower));
    }

    #[test]
    fn test_code_tag_stripping() {
        // Step 3: <code><pre>, <pre><code>, and </code></pre> are
        // stripped; other content is preserved.
        let input = "<code><pre>let x = 1;</code></pre> is rust";
        let expected = "let x = 1; is rust";
        assert_eq!(textify(input), expected);
    }

    #[test]
    fn test_named_entities() {
        // Step 4: the four entities &lt;, &gt;, &amp;, &quot; decode
        // to their literal characters. The assembly decodes them in
        // exactly that order — this test exercises all four
        // simultaneously.
        let input = "if x &lt; y &amp;&amp; y &gt; 0 then &quot;win&quot;";
        let expected = "if x < y && y > 0 then \"win\"";
        assert_eq!(textify(input), expected);
    }

    #[test]
    fn test_anchor_url_extraction() {
        // Step 5: <a href="URL">text</a> → URL (the anchor text is
        // discarded; only the href value is kept).
        let input = "Click <a href=\"https://example.com\">here</a> now";
        let expected = "Click https://example.com now";
        assert_eq!(textify(input), expected);
    }

    #[test]
    fn test_malformed_anchor_bailout() {
        // Step 5: an `<a href="` without a closing `"` triggers the
        // `.nohrefs` bailout at `textify.inc:165`. The function
        // returns the string with all prior steps applied and step 5
        // cleanly aborted (in this case, no other transformations
        // apply either, so the input is returned unchanged).
        let input = "Broken <a href=\"https://example.com no closing quote";
        assert_eq!(textify(input), input);
    }

    #[test]
    fn test_malformed_anchor_no_close_tag() {
        // Step 5: `<a href="URL"` with a quote but no `</a>` triggers
        // the `.nohrefs_free` bailout at `textify.inc:197-199`. The
        // function returns whatever has been transformed so far —
        // with no prior step applicable, the input passes through
        // unchanged.
        let input = "Broken <a href=\"https://example.com\"> no close tag";
        assert_eq!(textify(input), input);
    }

    #[test]
    fn test_order_of_entity_decoding() {
        // Critical ordering test: step 4 decodes &lt; BEFORE &amp;,
        // so `&amp;lt;` becomes `&lt;` (not `<`). Reordering would
        // produce `<` which is wrong.
        let input = "&amp;lt; should remain as &lt;";
        let expected = "&lt; should remain as <";
        assert_eq!(textify(input), expected);
    }

    #[test]
    fn test_empty_string() {
        // Empty input returns an empty string (all five steps are
        // no-ops on an empty slice).
        assert_eq!(textify(""), "");
    }

    #[test]
    fn test_plain_text_no_html() {
        // No HTML-ish tokens → input is returned unchanged byte-for-
        // byte (all five loops terminate immediately on first
        // iteration).
        let input = "Just plain text with no HTML";
        assert_eq!(textify(input), input);
    }

    #[test]
    fn test_combined() {
        // End-to-end test exercising steps 1, 4, and 5 together.
        let input = "<p>Hello &amp; welcome to <a href=\"https://2ton.com.au/\">2 Ton</a>!";
        let expected = "\nHello & welcome to https://2ton.com.au/!";
        assert_eq!(textify(input), expected);
    }

    #[test]
    fn test_multiple_anchor_extractions() {
        // Step 5's outer loop: multiple anchors in a single input are
        // all extracted, one per loop iteration.
        let input = concat!(
            "See <a href=\"https://a.test/\">A</a> and ",
            "<a href=\"https://b.test/\">B</a>."
        );
        let expected = "See https://a.test/ and https://b.test/.";
        assert_eq!(textify(input), expected);
    }

    #[test]
    fn test_hex_entity_truncated() {
        // Step 2: a truncated `&#x` (no hex digits, no `;`) causes the
        // `s.get(idx+3..idx+5)` call to return None, which breaks the
        // loop cleanly. The truncated prefix is preserved in the
        // output verbatim (no crash, no malformed substitution).
        let input = "nothing to see: &#x";
        assert_eq!(textify(input), input);
    }

    #[test]
    fn test_hex_entity_non_hex_digits() {
        // Step 2: `&#xZZ;` — the two characters after `&#x` are not
        // hex digits. `u8::from_str_radix` returns Err, which breaks
        // the loop cleanly. The malformed entity is preserved as-is
        // (the assembly would likewise fail to decode and leave the
        // text untouched, though via a different code path).
        let input = "bad &#xZZ; entity";
        assert_eq!(textify(input), input);
    }

    #[test]
    fn test_combined_hex_and_code_block() {
        // Steps 2 and 3 together: hex entity decoding occurs BEFORE
        // code-block stripping, matching the assembly's fixed order.
        let input = "<code><pre>&#x27;quoted&#x27;</code></pre>";
        let expected = "'quoted'";
        assert_eq!(textify(input), expected);
    }

    #[test]
    fn test_unsupported_named_entity_passes_through() {
        // Step 4: the assembly decodes EXACTLY four named entities
        // (`&lt;`, `&gt;`, `&amp;`, `&quot;`) at textify.inc:117-148.
        // Any other named entity — e.g. `&nbsp;`, `&ldquo;`,
        // `&rdquo;`, `&hellip;`, `&mdash;` — is NOT decoded. It must
        // pass through verbatim to preserve byte-for-byte FASM output
        // parity per AAP §0.1.1. Adding a broader entity table would
        // violate AAP §0.5.1.10 / §0.8.2 minimal-change discipline.
        let input = "Hello&nbsp;world &mdash; &ldquo;quoted&rdquo;";
        assert_eq!(textify(input), input);
    }

    #[test]
    fn test_hex_entity_target_slice_oob() {
        // Step 2: the input ends exactly after the two hex digits,
        // with NO trailing `;`. The first `s.get(idx+3..idx+5)` call
        // succeeds (two hex chars at positions 10..12 of a 12-byte
        // string), `u8::from_str_radix` succeeds, but then the second
        // `s.get(idx..idx+6)` call at textify.rs step-2 bailout fails
        // because `idx+6 = 13` exceeds the 12-byte length. The let-
        // else branch breaks the loop cleanly and the input passes
        // through unchanged. This exercises the ordering-sensitive
        // bailout that distinguishes `test_hex_entity_truncated` (hex
        // digits absent) from this case (hex digits present but no
        // closing `;` or trailing bytes).
        let input = "prefix &#x41";
        assert_eq!(textify(input), input);
    }

    #[test]
    fn test_empty_url_pathological() {
        // Step 5: an empty URL `<a href="">X</a>` is NOT cleanly
        // extracted because the `search_start = idx + 10` offset
        // skips past both the opening `"` AND the adjacent closing
        // `"`. When a later `"` exists in the input, the algorithm
        // misinterprets the intervening text (including the stray
        // `"` between `</a>` and the next token) as the URL. This
        // is a preserved FASM quirk per AAP §0.1.1 (byte-for-byte
        // output parity) — documented in the Step 5 rustdoc. The
        // Rust port MUST NOT "fix" this behavior, as it would
        // diverge from the assembly baseline.
        //
        // Trace for input `<a href="">X</a>"more"` (22 bytes):
        //   - idx = 0, search_start = 10
        //   - tail = `">X</a>"more"` (positions 10..22)
        //   - tail.find(`"`) = 6 → close_quote = 16
        //   - url_slice = s[9..16] = `">X</a>` (7 bytes incl. lead `"`)
        //   - tail.find(`</a>`) = 2 → close_a = 12
        //   - full_slice = s[0..16] = `<a href="">X</a>`
        //   - replace full_slice with url_slice
        //   - result: `">X</a>"more"` (13 bytes)
        let input = "<a href=\"\">X</a>\"more\"";
        let expected = "\">X</a>\"more\"";
        assert_eq!(textify(input), expected);
    }

    #[test]
    fn test_single_char_url_extracted() {
        // Step 5: a single-character URL (e.g. `/`) IS extracted
        // successfully. The closing `"` lands at exactly
        // `search_start = idx + 10`, and Rust's `str::find` includes
        // that starting byte in the search range. This test
        // empirically confirms the corrected Step 5 rustdoc claim:
        // 1-character URLs work; only 0-character URLs are
        // pathological. See `test_empty_url_pathological` for the
        // 0-character contrast case.
        let input = "Click <a href=\"/\">here</a>.";
        let expected = "Click /.";
        assert_eq!(textify(input), expected);
    }
}
