// HeavyThing Rust port — Base64 (RFC 4648) encode/decode.
//
// Original assembly source:
//   base64_latin1.inc — Copyright © 2015, 2016, 2017, 2018 2 Ton Digital.
//   Homepage: https://2ton.com.au/
//   Author: Jeff Marrison <jeff@2ton.com.au>
//
// This Rust translation is licensed under the GNU General Public License v3.0
// or later, preserving the original upstream license terms.
//
// This file is part of the HeavyThing Rust library.
//
// HeavyThing is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// HeavyThing is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with HeavyThing. If not, see <http://www.gnu.org/licenses/>.

//! Base64 (RFC 4648) encode/decode.
//!
//! Port of the FASM `base64_latin1.inc` module. This implementation
//! wraps the [`base64`] crate and preserves the original assembly
//! behavior, including:
//!
//! * Standard RFC 4648 alphabet (`A–Z a–z 0–9 + /`) with `=` padding.
//! * Optional CRLF line wrapping every 76 characters controlled by
//!   [`config::BASE64_LINEBREAKS`](crate::config::BASE64_LINEBREAKS)
//!   and [`config::BASE64_MAXLINE`](crate::config::BASE64_MAXLINE),
//!   matching the FASM `base64_linebreaks = 1` and
//!   `base64_maxline = 76` defaults from `ht_defaults.inc`.
//! * Whitespace-tolerant decoding via [`decode_tolerant`], which
//!   filters `\r`, `\n`, `\t`, and space before decoding — mirroring
//!   the FASM decoder's whitespace handling (`byte <= 32`).
//!
//! The "latin1" suffix in the FASM name indicated that the encoded
//! output is restricted to ASCII characters (which are latin-1 safe);
//! the Rust API returns idiomatic UTF-8 `String`s which are trivially
//! ASCII-only for base64 output.
//!
//! Consumers include:
//! * `util::privmapped` (ETag generation via SHA-224 base64)
//! * `net::ssh::server` (public-key base64 fields)
//! * `net::http::headers` (HTTP Basic authentication)
//! * `crypto::x509` (PEM certificate encoding)

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;

use crate::config::{BASE64_LINEBREAKS, BASE64_MAXLINE};
use crate::error::UtilError;

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Compute the length of the base64-encoded output for `input_len`
/// raw input bytes.
///
/// Matches the FASM `base64$encode_length` entry point. Returns the
/// number of output bytes **excluding** any CRLF line breaks that
/// [`encode_with_linebreaks`] may insert; callers that need the wrapped
/// length should add the CRLF overhead themselves or call
/// [`encode_with_linebreaks`] and take `.len()` of the result.
///
/// The formula is the standard `ceil(n / 3) * 4`, produced here via
/// [`usize::div_ceil`] for overflow-safe arithmetic.
///
/// # Examples
/// ```ignore
/// // Internal usage inside the heavything crate.
/// assert_eq!(base64::encode_length(0), 0);
/// assert_eq!(base64::encode_length(1), 4);   // "Xg==" shape
/// assert_eq!(base64::encode_length(3), 4);   // no padding
/// assert_eq!(base64::encode_length(4), 8);
/// ```
#[inline]
pub fn encode_length(input_len: usize) -> usize {
    input_len.div_ceil(3) * 4
}

/// Base64-encode `input` using the standard RFC 4648 alphabet with
/// `=` padding. Does **not** insert line breaks.
///
/// For output that honors the project's `BASE64_LINEBREAKS` / `BASE64_MAXLINE`
/// defaults, see [`encode_with_linebreaks`].
#[inline]
pub fn encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// Base64-encode `input` using the standard RFC 4648 alphabet **without**
/// trailing `=` padding.
///
/// Useful for callers that need canonical unpadded base64 such as the
/// `base64url`-style wire format used in some protocols (though this
/// uses the *standard* alphabet, not the URL-safe variant).
#[inline]
pub fn encode_no_pad(input: &[u8]) -> String {
    STANDARD_NO_PAD.encode(input)
}

/// Base64-encode `input`, honoring the compile-time defaults
/// [`BASE64_LINEBREAKS`] and [`BASE64_MAXLINE`].
///
/// When `BASE64_LINEBREAKS` is `true` and `BASE64_MAXLINE > 0`,
/// inserts CRLF (`\r\n`) every `BASE64_MAXLINE` output characters,
/// matching the RFC 2045 / MIME convention and the FASM
/// `base64$encode_latin1` behavior under `base64_linebreaks = 1`.
///
/// When either constant disables wrapping, the result is identical to
/// [`encode`].
pub fn encode_with_linebreaks(input: &[u8]) -> String {
    let raw = STANDARD.encode(input);
    if !BASE64_LINEBREAKS || BASE64_MAXLINE == 0 {
        return raw;
    }
    apply_linebreaks(&raw, BASE64_MAXLINE)
}

/// Insert CRLF (`\r\n`) separators into `encoded` after every `max_line`
/// ASCII characters, returning a new `String`.
///
/// `encoded` is expected to be base64 output (pure ASCII); the function
/// treats it as bytes and assumes each byte is a single column. A
/// `max_line` of `0` disables wrapping (a plain clone is returned).
///
/// Trailing partial lines are *not* terminated with a CRLF — only
/// interior separators are emitted, matching the FASM assembly's
/// behavior where the wrap loop only emits a CRLF before the *next*
/// segment, not after the final one.
///
/// Exposed publicly so that callers (e.g., PEM encoders in
/// `crypto::x509`) can use widths other than [`BASE64_MAXLINE`].
pub fn apply_linebreaks(encoded: &str, max_line: usize) -> String {
    if max_line == 0 || encoded.is_empty() {
        return encoded.to_owned();
    }

    // Pre-compute output capacity: the encoded bytes plus two bytes of
    // CRLF per fully-completed line. Using `len / max_line` may yield
    // one extra CRLF when `len` is an exact multiple, but we emit a
    // separator only *between* segments (not trailing), so the spare
    // capacity just goes unused — still tighter than `String::new()`.
    let crlf_count = encoded.len() / max_line;
    let mut out = String::with_capacity(encoded.len() + crlf_count * 2);

    // base64 output is pure ASCII; operating on `as_bytes()` and using
    // `str::from_utf8` on the slices is safe and avoids character-wise
    // iteration overhead. The `str::from_utf8` call cannot fail because
    // `encoded` is itself a valid `&str` and we split on byte-aligned
    // boundaries of the ASCII subrange.
    let bytes = encoded.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let end = (pos + max_line).min(bytes.len());
        let segment = std::str::from_utf8(&bytes[pos..end]).unwrap_or("");
        out.push_str(segment);
        if end < bytes.len() {
            out.push_str("\r\n");
        }
        pos = end;
    }
    out
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decode standard-alphabet base64 bytes (with padding) into a
/// `Vec<u8>`.
///
/// Matches the FASM `base64$decode_latin1` entry point for strict
/// input. Input must not contain line breaks, whitespace, or other
/// non-alphabet characters; for whitespace-tolerant decoding use
/// [`decode_tolerant`].
///
/// # Errors
/// Returns [`UtilError::Base64`] containing the upstream
/// [`base64::DecodeError`]'s `Display` representation when the input
/// contains invalid characters, has bad padding, or is truncated.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, UtilError> {
    STANDARD
        .decode(input)
        .map_err(|e| UtilError::Base64(e.to_string()))
}

/// Decode standard-alphabet base64 from a `&str`.
///
/// Convenience wrapper around [`decode`] for string inputs.
///
/// # Errors
/// See [`decode`].
#[inline]
pub fn decode_str(input: &str) -> Result<Vec<u8>, UtilError> {
    decode(input.as_bytes())
}

/// Decode standard-alphabet base64, tolerating embedded whitespace.
///
/// Strips the four whitespace characters (`\r`, `\n`, `\t`, ` `) from
/// `input` before decoding. This mirrors the FASM decoder's
/// `byte <= 32` skip-check, which caused it to ignore any ASCII
/// control byte ≤ 0x20 — in practice, the four whitespace characters
/// listed above.
///
/// Intended for input such as MIME-wrapped base64 (CRLF every 76
/// chars) or PEM-style blocks.
///
/// # Errors
/// Returns [`UtilError::Base64`] if, after whitespace stripping, the
/// remaining input is not valid base64.
pub fn decode_tolerant(input: &str) -> Result<Vec<u8>, UtilError> {
    let cleaned: String = input
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\t' | ' '))
        .collect();
    decode_str(&cleaned)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10 encoding test vectors — the canonical reference
    /// points for base64 encoders.
    #[test]
    fn encode_rfc4648_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    /// RFC 4648 §10 decoding test vectors (forward direction verified
    /// above; this tests the inverse path).
    #[test]
    fn decode_rfc4648_vectors() {
        assert_eq!(decode(b"").expect("decode empty"), b"");
        assert_eq!(decode(b"Zg==").expect("decode f"), b"f");
        assert_eq!(decode(b"Zm8=").expect("decode fo"), b"fo");
        assert_eq!(decode(b"Zm9v").expect("decode foo"), b"foo");
        assert_eq!(decode(b"Zm9vYg==").expect("decode foob"), b"foob");
        assert_eq!(decode(b"Zm9vYmE=").expect("decode fooba"), b"fooba");
        assert_eq!(decode(b"Zm9vYmFy").expect("decode foobar"), b"foobar");
    }

    /// Verify `encode_length` matches the actual encoded string length
    /// for every input size from 0 to 100 bytes.
    #[test]
    fn encode_length_matches_actual() {
        for n in 0..=100usize {
            let input = vec![0u8; n];
            let actual = encode(&input);
            assert_eq!(
                encode_length(n),
                actual.len(),
                "encode_length({n}) = {} but encode produced {} bytes",
                encode_length(n),
                actual.len()
            );
        }
    }

    /// Verify CRLF wrapping at the 76-character default width.
    #[test]
    fn apply_linebreaks_76() {
        // Build a 200-char ASCII string (not real base64, but the
        // wrapper operates on bytes and doesn't care about the
        // alphabet).
        let input = "A".repeat(200);
        let wrapped = apply_linebreaks(&input, 76);

        // Must contain at least one CRLF separator.
        assert!(wrapped.contains("\r\n"), "wrapped output missing CRLF");

        // Split on CRLF; first two segments should be exactly 76
        // chars; the third is the remainder (200 - 152 = 48).
        let lines: Vec<&str> = wrapped.split("\r\n").collect();
        assert_eq!(lines.len(), 3, "expected 3 segments, got {}", lines.len());
        assert_eq!(lines[0].len(), 76, "first line length mismatch");
        assert_eq!(lines[1].len(), 76, "second line length mismatch");
        assert_eq!(lines[2].len(), 200 - 76 * 2, "final partial line length mismatch");

        // Total non-CRLF content must equal the original input.
        assert_eq!(wrapped.replace("\r\n", ""), input);
    }

    /// Verify that when `max_line == 0`, wrapping is a no-op.
    #[test]
    fn apply_linebreaks_zero_is_noop() {
        let input = "ABCDEFGHIJKLMNOP";
        assert_eq!(apply_linebreaks(input, 0), input);
    }

    /// Verify that wrapping an empty string yields an empty string
    /// (no spurious CRLF).
    #[test]
    fn apply_linebreaks_empty_is_empty() {
        assert_eq!(apply_linebreaks("", 76), "");
    }

    /// Verify that an input of length exactly equal to `max_line` does
    /// *not* emit a trailing CRLF — the separator is interior-only.
    #[test]
    fn apply_linebreaks_exact_no_trailing() {
        let input = "A".repeat(76);
        let wrapped = apply_linebreaks(&input, 76);
        assert_eq!(wrapped, input, "no separator expected for single full line");
        assert!(!wrapped.ends_with("\r\n"));
    }

    /// Verify that `encode_with_linebreaks` produces wrapped output
    /// honoring the compile-time defaults (`BASE64_LINEBREAKS = true`,
    /// `BASE64_MAXLINE = 76`).
    #[test]
    fn encode_with_linebreaks_wraps_at_default() {
        // 200 raw bytes → 268 base64 characters (ceil(200/3)*4 = 268),
        // which exceeds 76 and must be wrapped into multiple lines.
        let input = vec![0u8; 200];
        let output = encode_with_linebreaks(&input);
        if BASE64_LINEBREAKS && BASE64_MAXLINE > 0 {
            assert!(
                output.contains("\r\n"),
                "expected wrapped output under BASE64_LINEBREAKS=true"
            );
            // First segment must be exactly BASE64_MAXLINE chars.
            let first = output.split("\r\n").next().expect("at least one segment");
            assert_eq!(first.len(), BASE64_MAXLINE);
        } else {
            // If the project ever flips the default, fall back to the
            // unwrapped invariant.
            assert!(!output.contains("\r\n"));
        }
    }

    /// Verify `decode_tolerant` strips embedded whitespace and decodes
    /// correctly.
    #[test]
    fn decode_tolerant_strips_whitespace() {
        // CRLF in the middle
        let with_crlf = "Zm9v\r\nYmFy";
        assert_eq!(decode_tolerant(with_crlf).expect("decode crlf"), b"foobar");

        // LF only
        let with_lf = "Zm9v\nYmFy";
        assert_eq!(decode_tolerant(with_lf).expect("decode lf"), b"foobar");

        // Tabs and spaces scattered
        let with_misc = "Zm\t9v Y mFy";
        assert_eq!(decode_tolerant(with_misc).expect("decode misc"), b"foobar");

        // Leading and trailing whitespace
        let with_ends = "  \r\nZm9vYmFy\r\n  ";
        assert_eq!(decode_tolerant(with_ends).expect("decode ends"), b"foobar");
    }

    /// Verify `decode_str` is a correct thin wrapper over `decode`.
    #[test]
    fn decode_str_wrapper() {
        assert_eq!(decode_str("Zm9vYmFy").expect("decode_str"), b"foobar");
    }

    /// Verify invalid base64 input surfaces as `UtilError::Base64(_)`.
    #[test]
    fn decode_invalid_returns_error() {
        // '!' is not in the RFC 4648 standard alphabet.
        match decode(b"not_base64!") {
            Err(UtilError::Base64(msg)) => {
                assert!(!msg.is_empty(), "error message must be non-empty");
            }
            other => panic!("expected UtilError::Base64, got {other:?}"),
        }

        // Truncated input (too short, invalid padding shape).
        assert!(matches!(decode(b"Z"), Err(UtilError::Base64(_))));

        // Bad padding.
        assert!(matches!(decode(b"Z==="), Err(UtilError::Base64(_))));
    }

    /// Encode → decode full byte-range roundtrip for every byte value
    /// 0..=255 to confirm alphabet coverage and padding handling.
    #[test]
    fn roundtrip_all_bytes() {
        let original: Vec<u8> = (0..=255u8).collect();
        let encoded = encode(&original);
        let decoded = decode_str(&encoded).expect("roundtrip decode");
        assert_eq!(decoded, original);
    }

    /// Encode-with-linebreaks → decode-tolerant roundtrip confirms
    /// the wrapping/unwrapping chain is lossless.
    #[test]
    fn roundtrip_wrapped() {
        let original: Vec<u8> = (0..=255u8).collect();
        let wrapped = encode_with_linebreaks(&original);
        let decoded = decode_tolerant(&wrapped).expect("roundtrip wrapped decode");
        assert_eq!(decoded, original);
    }

    /// Verify `encode_no_pad` strips trailing `=` characters.
    #[test]
    fn encode_no_pad_strips_padding() {
        // "f" encodes to "Zg==" with padding or "Zg" without.
        assert_eq!(encode_no_pad(b"f"), "Zg");
        assert_eq!(encode_no_pad(b"fo"), "Zm8");
        // Three-byte input requires no padding; padded and unpadded
        // outputs match.
        assert_eq!(encode_no_pad(b"foo"), "Zm9v");
        assert_eq!(encode_no_pad(b""), "");
    }
}
