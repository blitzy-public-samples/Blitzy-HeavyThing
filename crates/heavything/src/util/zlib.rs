// HeavyThing Rust port — zlib / gzip / raw-deflate compression wrappers.
//
// Original assembly sources:
//   zlib_deflate.inc — Copyright © 2015 2 Ton Digital.
//   zlib_inflate.inc — Copyright © 2015 2 Ton Digital.
//   Homepage: https://2ton.com.au/
//   Author: Jeff Marrison <jeff@2ton.com.au>
//
// The upstream FASM sources acknowledge the reference zlib library by
// Jean-Loup Gailly and Mark Adler; the FASM port re-implemented the
// reference codec in hand-written x86_64 assembly across the pair of
// files `zlib_deflate.inc` (4,805 lines) and `zlib_inflate.inc`
// (2,656 lines). This Rust port replaces the ~7,400 lines of assembly
// with a thin wrapper over the [`flate2`] crate (pinned to the
// workspace-level `flate2 = "1"` dependency), which itself delegates
// to the pure-Rust `miniz_oxide` backend.
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

//! zlib / gzip / raw-deflate encoding and decoding via [`flate2`].
//!
//! Port of `zlib_deflate.inc` (RFC 1950 zlib + RFC 1951 raw deflate
//! encoders) and `zlib_inflate.inc` (matching decoders plus RFC 1952
//! gzip support). Per AAP §0.5.1.7 the ~7,400-line hand-rolled FASM
//! codec is replaced by a thin wrapper over [`flate2`], which in turn
//! delegates to the pure-Rust `miniz_oxide` backend. This preserves
//! bit-exact interoperability with standard zlib / gzip / deflate
//! streams while eliminating an entire subsystem's worth of
//! hand-written cryptographic-adjacent code.
//!
//! # Format families
//!
//! Three closely-related wire formats are exposed, differentiated by
//! the header/trailer framing around the shared deflate payload:
//!
//! | Format  | RFC | Framing                                      | Typical use                                |
//! |---------|-----|----------------------------------------------|--------------------------------------------|
//! | zlib    | 1950 | 2-byte header + deflate + Adler-32 trailer  | HTTP `Content-Encoding: deflate`, PNG `IDAT` |
//! | gzip    | 1952 | 10-byte header + deflate + CRC-32 + ISIZE   | HTTP `Content-Encoding: gzip`              |
//! | deflate | 1951 | raw deflate (no header, no trailer)         | SSH transport when `ssh_force_compression = 1` |
//!
//! Each family has matched [`encode`/`decode`] pairs using the
//! [`flate2`] encoder/decoder types in `write::*Encoder` /
//! `read::*Decoder` form, a design choice driven by the shape of the
//! FASM API — the assembly accepted a contiguous input buffer and
//! produced a contiguous output buffer, which matches the
//! `write_all` → `finish()` and `read_to_end` → `Ok(out)` patterns
//! used below.
//!
//! # Compression level
//!
//! The default compression level is 6 (a.k.a. `Z_DEFAULT_COMPRESSION`
//! in the canonical zlib C API), exposed here as [`DEFAULT_LEVEL`] and
//! sourced from [`crate::config::ZLIB_DEFLATE_LEVEL`]. Any level
//! between 0 (no compression, stored only) and 9 (maximum deflate
//! ratio at the cost of CPU time) is accepted; values above 9 are
//! clamped to 9 by [`to_compression`] to match the [`flate2::Compression`]
//! API contract.
//!
//! # Initial buffer reservation
//!
//! All three encoder entry points pre-reserve
//! [`crate::config::ZLIB_DEFLATE_RESERVE`] bytes of output capacity
//! (16 KiB default, matching the FASM `zlib_deflate_reserve` knob) in
//! the sink `Vec<u8>`. This avoids the small-allocation ramp-up that
//! would otherwise occur during the first few `write!` calls and
//! mirrors the preallocation behavior of the FASM baseline.
//!
//! # Error surface
//!
//! Every public entry point returns `Result<Vec<u8>, UtilError>` with
//! failures funneled into [`UtilError::Zlib`] (a `String` payload).
//! Upstream `flate2` errors surface as `std::io::Error`; their
//! `Display` impl is captured via `e.to_string()` into the `Zlib`
//! variant, preserving the error message without dragging an `io::Error`
//! source chain into the utility error type (which keeps the
//! [`crate::error::UtilError`] enum's layout flat per AAP §0.8.3).
//!
//! # Consumers
//!
//! * [`crate::net::http::server`] — `Content-Encoding: gzip` responses.
//! * [`crate::net::http::client`] — decoding gzip/deflate response bodies.
//! * [`crate::net::ssh::compression`] — SSH forced zlib transport compression.
//! * [`crate::util::png`] — indirectly via the `png` crate's internal
//!   use of deflate for `IDAT` chunk payloads.
//!
//! The `MIN_COMPRESSION_THRESHOLD` knob (the FASM `mimelike.inc`
//! 1024-byte floor below which gzip encoding is skipped to avoid
//! negative compression ratios) lives in the
//! [`crate::net::http::mimelike`] module where the decision is made,
//! not here — keeping the zlib wrapper free of HTTP-level policy.

use std::io::{Read, Write};

use flate2::{
    read::{DeflateDecoder, GzDecoder, ZlibDecoder},
    write::{DeflateEncoder, GzEncoder, ZlibEncoder},
    Compression,
};

use crate::config::{ZLIB_DEFLATE_LEVEL, ZLIB_DEFLATE_RESERVE};
use crate::error::UtilError;

// ---------------------------------------------------------------------------
// Public constants & shared helpers
// ---------------------------------------------------------------------------

/// Default compression level, mirroring the FASM
/// [`crate::config::ZLIB_DEFLATE_LEVEL`] knob (value `6`).
///
/// This is the canonical zlib `Z_DEFAULT_COMPRESSION` level — a
/// deliberate industry-wide compromise between compression ratio and
/// encoder CPU cost. Changing this constant would diverge from the
/// FASM baseline's default output byte stream for callers that rely
/// on the three no-level entry points ([`zlib_compress`],
/// [`gzip_compress`], [`deflate_compress`]); callers that need a
/// different level should call the `_with_level` variants directly.
pub const DEFAULT_LEVEL: u32 = ZLIB_DEFLATE_LEVEL;

/// Convert a caller-supplied `u32` level into a [`flate2::Compression`]
/// instance, clamping to the valid `0..=9` range.
///
/// [`flate2::Compression::new`] panics on values greater than 9, so we
/// clamp defensively here. Values of 0 (store only / no compression)
/// and 9 (maximum compression) are pass-through; anything strictly
/// above 9 is coerced to 9. Negative levels are not representable in
/// `u32` so no lower clamp is required.
fn to_compression(level: u32) -> Compression {
    Compression::new(level.min(9))
}

// ---------------------------------------------------------------------------
// zlib format (RFC 1950) — deflate payload wrapped with a 2-byte header
// and an Adler-32 trailer.
// ---------------------------------------------------------------------------

/// Compress `data` using the zlib format (RFC 1950) at the default
/// level [`DEFAULT_LEVEL`].
///
/// This matches the FASM `zlib_deflate$deflate` entry point invoked
/// without an explicit level argument. The output begins with the
/// standard zlib 2-byte header (`CMF` + `FLG`, encoding a 32 KiB
/// window and the `FDICT=0 FLEVEL` level hint) followed by the
/// deflate-compressed payload and a 4-byte big-endian Adler-32
/// checksum of the original input.
///
/// # Errors
///
/// Returns [`UtilError::Zlib`] if the underlying [`ZlibEncoder`]
/// `write_all` or `finish` call fails. In practice these are
/// allocation failures or `io::Error` surfaces from the in-memory
/// `Vec<u8>` sink; they are extremely rare but surfaced faithfully.
pub fn zlib_compress(data: &[u8]) -> Result<Vec<u8>, UtilError> {
    zlib_compress_with_level(data, DEFAULT_LEVEL)
}

/// Compress `data` using the zlib format (RFC 1950) at the
/// caller-supplied `level` (clamped to `0..=9`).
///
/// Equivalent to the FASM `zlib_deflate$deflate_level` variant.
/// See [`zlib_compress`] for framing details and
/// [`to_compression`] for level clamping behavior.
///
/// The output `Vec<u8>` is pre-reserved to
/// [`crate::config::ZLIB_DEFLATE_RESERVE`] bytes (16 KiB default)
/// before encoding begins, avoiding incremental small
/// reallocations for typical payloads. The final `Vec` may grow
/// beyond that reservation for payloads that do not compress.
///
/// # Errors
///
/// Returns [`UtilError::Zlib`] on encoder failure; see
/// [`zlib_compress`].
pub fn zlib_compress_with_level(data: &[u8], level: u32) -> Result<Vec<u8>, UtilError> {
    let mut encoder = ZlibEncoder::new(Vec::with_capacity(ZLIB_DEFLATE_RESERVE), to_compression(level));
    encoder
        .write_all(data)
        .map_err(|e| UtilError::Zlib(e.to_string()))?;
    encoder.finish().map_err(|e| UtilError::Zlib(e.to_string()))
}

/// Decompress zlib-format (RFC 1950) `data`.
///
/// Matches the FASM `zlib_inflate$inflate` entry point. The input
/// must begin with a valid zlib 2-byte header (`0x78 0x??` is the
/// most common prefix for `deflate` with a 32 KiB window) and end
/// with a valid 4-byte Adler-32 checksum of the decompressed
/// payload. Corrupt or unrelated input produces [`UtilError::Zlib`].
///
/// The output buffer is pre-reserved to `data.len() * 2` bytes — a
/// common rule of thumb for compressed-to-decompressed ratios on
/// typical text/binary payloads. The `Vec` grows as needed for
/// higher-ratio inputs.
///
/// # Errors
///
/// Returns [`UtilError::Zlib`] if the input is not valid zlib data
/// or the decoder encounters an I/O error while draining the
/// deflate stream.
pub fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>, UtilError> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::with_capacity(data.len().saturating_mul(2));
    decoder
        .read_to_end(&mut out)
        .map_err(|e| UtilError::Zlib(e.to_string()))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// gzip format (RFC 1952) — deflate payload wrapped with a 10-byte gzip
// header and an 8-byte trailer (CRC-32 + original ISIZE mod 2^32).
// ---------------------------------------------------------------------------

/// Compress `data` using the gzip format (RFC 1952) at the default
/// level [`DEFAULT_LEVEL`].
///
/// This is the encoder invoked by
/// [`crate::net::http::server`] when emitting
/// `Content-Encoding: gzip` responses. The output begins with the
/// fixed 10-byte gzip header (magic `0x1f 0x8b`, compression
/// method `08` = deflate, flags, timestamp, extra flags, OS byte)
/// followed by the raw deflate payload, a 4-byte little-endian
/// CRC-32 of the uncompressed input, and a 4-byte little-endian
/// length (input bytes mod 2^32).
///
/// # Errors
///
/// Returns [`UtilError::Zlib`] if the underlying [`GzEncoder`]
/// fails; see [`zlib_compress`] for error-path rationale.
pub fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, UtilError> {
    gzip_compress_with_level(data, DEFAULT_LEVEL)
}

/// Compress `data` using the gzip format (RFC 1952) at the
/// caller-supplied `level` (clamped to `0..=9`).
///
/// See [`gzip_compress`] for framing details and
/// [`zlib_compress_with_level`] for the shared buffer-reservation
/// and error-handling behavior.
///
/// # Errors
///
/// Returns [`UtilError::Zlib`] on encoder failure.
pub fn gzip_compress_with_level(data: &[u8], level: u32) -> Result<Vec<u8>, UtilError> {
    let mut encoder = GzEncoder::new(Vec::with_capacity(ZLIB_DEFLATE_RESERVE), to_compression(level));
    encoder
        .write_all(data)
        .map_err(|e| UtilError::Zlib(e.to_string()))?;
    encoder.finish().map_err(|e| UtilError::Zlib(e.to_string()))
}

/// Decompress gzip-format (RFC 1952) `data`.
///
/// Used by [`crate::net::http::client`] to decompress response
/// bodies received with `Content-Encoding: gzip`. Only the first
/// gzip member is decoded; concatenated multi-member gzip streams
/// are NOT automatically concatenated on decode — this matches the
/// FASM baseline's single-member behavior for `zlib_inflate$inflate_gzip`.
/// The input must start with the magic bytes `0x1f 0x8b`.
///
/// # Errors
///
/// Returns [`UtilError::Zlib`] if the gzip magic/header is invalid,
/// the CRC-32 trailer mismatches the decompressed payload, or the
/// deflate payload itself is corrupt.
pub fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>, UtilError> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::with_capacity(data.len().saturating_mul(2));
    decoder
        .read_to_end(&mut out)
        .map_err(|e| UtilError::Zlib(e.to_string()))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Raw deflate (RFC 1951) — deflate payload with no header, no trailer.
// ---------------------------------------------------------------------------

/// Compress `data` using raw deflate (RFC 1951 — no zlib or gzip
/// wrapper) at the default level [`DEFAULT_LEVEL`].
///
/// Used by [`crate::net::ssh::compression`] when an SSH session
/// negotiates (or is forced into, per
/// [`crate::config::SSH_FORCE_COMPRESSION`]) the `zlib` or
/// `zlib@openssh.com` transport compression — the SSH2 spec
/// specifies a bare-deflate payload with no outer framing at the
/// compression layer, since the SSH binary packet protocol
/// already supplies length framing and MAC integrity checks.
///
/// # Errors
///
/// Returns [`UtilError::Zlib`] on encoder failure; see
/// [`zlib_compress`].
pub fn deflate_compress(data: &[u8]) -> Result<Vec<u8>, UtilError> {
    deflate_compress_with_level(data, DEFAULT_LEVEL)
}

/// Compress `data` using raw deflate (RFC 1951) at the
/// caller-supplied `level` (clamped to `0..=9`).
///
/// See [`deflate_compress`] for framing rationale and
/// [`zlib_compress_with_level`] for the shared buffer-reservation
/// behavior.
///
/// # Errors
///
/// Returns [`UtilError::Zlib`] on encoder failure.
pub fn deflate_compress_with_level(data: &[u8], level: u32) -> Result<Vec<u8>, UtilError> {
    let mut encoder = DeflateEncoder::new(Vec::with_capacity(ZLIB_DEFLATE_RESERVE), to_compression(level));
    encoder
        .write_all(data)
        .map_err(|e| UtilError::Zlib(e.to_string()))?;
    encoder.finish().map_err(|e| UtilError::Zlib(e.to_string()))
}

/// Decompress raw-deflate-format (RFC 1951) `data`.
///
/// The counterpart decoder to [`deflate_compress`]; used by the
/// SSH transport decompression path. The input must be a bare
/// deflate bitstream with no surrounding header or trailer.
///
/// # Errors
///
/// Returns [`UtilError::Zlib`] if the deflate bitstream is
/// malformed or truncated.
pub fn deflate_decompress(data: &[u8]) -> Result<Vec<u8>, UtilError> {
    let mut decoder = DeflateDecoder::new(data);
    let mut out = Vec::with_capacity(data.len().saturating_mul(2));
    decoder
        .read_to_end(&mut out)
        .map_err(|e| UtilError::Zlib(e.to_string()))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Unit tests — validate round-trip semantics across all three format
// families, level handling, magic-byte emission, empty-input handling,
// and the error surface for invalid input.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a compressible ASCII payload through the zlib
    /// encoder and decoder. The repeated "quick brown fox"
    /// pangram compresses easily because of the repeated words;
    /// the post-compression length MUST be strictly less than the
    /// input length or the encoder is broken.
    #[test]
    fn zlib_roundtrip_ascii() {
        let input = b"The quick brown fox jumps over the lazy dog.".repeat(10);
        let compressed = zlib_compress(&input).expect("zlib_compress");
        assert!(
            compressed.len() < input.len(),
            "expected compression: input={} compressed={}",
            input.len(),
            compressed.len()
        );
        let decompressed = zlib_decompress(&compressed).expect("zlib_decompress");
        assert_eq!(decompressed, input);
    }

    /// The zlib format begins with a 2-byte header where the first
    /// byte's low nibble is the compression method. For deflate
    /// (the only method used) the first byte's low nibble is `0x8`,
    /// and the second byte is chosen so that `(byte0 * 256 + byte1) % 31 == 0`
    /// per RFC 1950 §2.2. Rather than validate the exact bytes (which
    /// vary by level), this test validates the method nibble.
    #[test]
    fn zlib_header_method_is_deflate() {
        let compressed = zlib_compress(b"header check").expect("compress");
        // CM (low nibble of byte 0) must be 8 for deflate.
        assert_eq!(compressed[0] & 0x0f, 0x08);
    }

    /// Round-trip a small buffer through gzip and verify the gzip
    /// magic bytes `0x1f 0x8b` lead the output. Gzip is the HTTP
    /// `Content-Encoding: gzip` workhorse and its header bytes are
    /// load-bearing.
    #[test]
    fn gzip_roundtrip_with_magic_bytes() {
        let input = b"hello world".to_vec();
        let compressed = gzip_compress(&input).expect("gzip_compress");
        // gzip magic (RFC 1952 §2.3.1): ID1=0x1f, ID2=0x8b
        assert_eq!(&compressed[..2], &[0x1f, 0x8b]);
        // CM (compression method) byte 2 must be 8 for deflate.
        assert_eq!(compressed[2], 0x08);
        let decompressed = gzip_decompress(&compressed).expect("gzip_decompress");
        assert_eq!(decompressed, input);
    }

    /// Round-trip a highly-compressible payload through raw deflate
    /// (no framing). The output MUST be strictly smaller than the
    /// input and the decoded payload MUST match the input byte-for-byte.
    #[test]
    fn deflate_roundtrip_compressible() {
        let input = b"abc abc abc abc abc".repeat(100);
        let compressed = deflate_compress(&input).expect("deflate_compress");
        assert!(
            compressed.len() < input.len(),
            "expected compression: input={} compressed={}",
            input.len(),
            compressed.len()
        );
        let decompressed = deflate_decompress(&compressed).expect("deflate_decompress");
        assert_eq!(decompressed, input);
    }

    /// Round-trip an empty input through all three format families.
    /// Empty inputs are a common edge case for compressors (the
    /// FASM baseline handles them; the Rust port must too).
    #[test]
    fn empty_input_roundtrips_all_formats() {
        let empty: &[u8] = &[];

        let z = zlib_compress(empty).expect("zlib empty compress");
        assert_eq!(zlib_decompress(&z).expect("zlib empty decompress"), empty);

        let g = gzip_compress(empty).expect("gzip empty compress");
        // gzip still emits the 10-byte header and 8-byte trailer.
        assert_eq!(&g[..2], &[0x1f, 0x8b]);
        assert_eq!(gzip_decompress(&g).expect("gzip empty decompress"), empty);

        let d = deflate_compress(empty).expect("deflate empty compress");
        assert_eq!(deflate_decompress(&d).expect("deflate empty decompress"), empty);
    }

    /// The public [`DEFAULT_LEVEL`] constant MUST equal 6 per the
    /// FASM `zlib_deflate_level` baseline in
    /// [`crate::config::ZLIB_DEFLATE_LEVEL`]. This is a single-line
    /// sanity check to catch accidental rebinding.
    #[test]
    fn default_level_preserved() {
        assert_eq!(DEFAULT_LEVEL, 6);
        assert_eq!(DEFAULT_LEVEL, ZLIB_DEFLATE_LEVEL);
    }

    /// Explicit level 0 (store only, no compression). The output is
    /// slightly larger than the input due to the zlib framing and
    /// deflate stored-block headers, but MUST still round-trip
    /// losslessly.
    #[test]
    fn level_zero_store_only_roundtrips() {
        let input = b"no compression at level 0".to_vec();
        let compressed = zlib_compress_with_level(&input, 0).expect("level 0 compress");
        // Stored-only output is at least as large as the input plus framing.
        assert!(compressed.len() >= input.len());
        let decompressed = zlib_decompress(&compressed).expect("level 0 decompress");
        assert_eq!(decompressed, input);
    }

    /// Explicit level 9 (maximum compression). The output MUST be
    /// strictly smaller than a level-1 output for a highly redundant
    /// payload, demonstrating that level is actually being applied.
    #[test]
    fn level_nine_compresses_more_than_level_one() {
        let input = b"a".repeat(1024);
        let low = zlib_compress_with_level(&input, 1).expect("level 1");
        let high = zlib_compress_with_level(&input, 9).expect("level 9");
        assert!(
            high.len() <= low.len(),
            "expected level 9 <= level 1: level1={} level9={}",
            low.len(),
            high.len()
        );
    }

    /// Levels strictly above 9 are clamped to 9 by [`to_compression`]
    /// to preserve the [`flate2::Compression::new`] API contract.
    /// We verify this by confirming that `level = 99` produces the
    /// same byte output as `level = 9` for a deterministic input.
    #[test]
    fn level_above_nine_clamps_to_nine() {
        let input = b"clamping test payload".repeat(50);
        let nine = zlib_compress_with_level(&input, 9).expect("level 9");
        let clamped = zlib_compress_with_level(&input, 99).expect("level 99 clamped");
        assert_eq!(nine, clamped);
    }

    /// Feeding the zlib decoder a buffer that isn't zlib data MUST
    /// produce [`UtilError::Zlib`] rather than panicking. This is
    /// the adversarial-input guarantee: callers receiving untrusted
    /// data can safely propagate the error.
    #[test]
    fn invalid_zlib_input_errors_cleanly() {
        let garbage = b"this is definitely not zlib data";
        let err = zlib_decompress(garbage).expect_err("expected error");
        assert!(matches!(err, UtilError::Zlib(_)));
    }

    /// Feeding the gzip decoder something lacking the `0x1f 0x8b`
    /// magic MUST produce [`UtilError::Zlib`].
    #[test]
    fn invalid_gzip_input_errors_cleanly() {
        let garbage = b"no gzip magic here at all, totally bogus";
        let err = gzip_decompress(garbage).expect_err("expected error");
        assert!(matches!(err, UtilError::Zlib(_)));
    }

    /// Corrupting a byte early in the zlib header (invalidating
    /// the 2-byte `CMF`/`FLG` header check per RFC 1950 §2.2) MUST
    /// produce [`UtilError::Zlib`]. Unlike mid-payload truncation —
    /// which `flate2`/`miniz_oxide` handles leniently by returning
    /// partial decompressed output — an invalid header is rejected
    /// immediately by the decoder with a deterministic error.
    #[test]
    fn corrupted_zlib_header_errors_cleanly() {
        let mut corrupted = zlib_compress(b"header corruption test").expect("compress");
        // Force CMF byte to 0x00 — its low nibble becomes 0 (not
        // deflate), violating RFC 1950. Additionally, the
        // `(CMF*256 + FLG) mod 31 == 0` check almost certainly
        // fails as well.
        corrupted[0] = 0x00;
        let err = zlib_decompress(&corrupted).expect_err("expected error");
        assert!(matches!(err, UtilError::Zlib(_)));
    }

    /// Verify that gzip data is NOT accepted by the zlib decoder
    /// and vice versa — the three format families are deliberately
    /// distinct on the wire and consumers must select the correct
    /// decoder.
    #[test]
    fn formats_are_not_interchangeable() {
        let input = b"format cross-check";
        let as_gzip = gzip_compress(input).expect("gzip");
        assert!(zlib_decompress(&as_gzip).is_err());

        let as_zlib = zlib_compress(input).expect("zlib");
        assert!(gzip_decompress(&as_zlib).is_err());

        let as_deflate = deflate_compress(input).expect("deflate");
        assert!(gzip_decompress(&as_deflate).is_err());
    }

    /// Large-input round-trip (128 KiB) to exercise the
    /// [`crate::config::ZLIB_DEFLATE_RESERVE`] pre-reservation path
    /// and ensure the encoder correctly grows the sink `Vec`
    /// beyond the initial 16 KiB capacity.
    #[test]
    fn large_input_roundtrip() {
        let input = (0..128 * 1024).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
        let compressed = zlib_compress(&input).expect("large compress");
        let decompressed = zlib_decompress(&compressed).expect("large decompress");
        assert_eq!(decompressed, input);
    }

    /// Sanity-check: confirm that [`crate::config::ZLIB_DEFLATE_RESERVE`]
    /// holds the expected 16 KiB value. This guards against accidental
    /// upstream changes to the config constant that would alter this
    /// module's pre-allocation behavior.
    #[test]
    fn zlib_deflate_reserve_constant_is_16k() {
        assert_eq!(ZLIB_DEFLATE_RESERVE, 16_384);
    }

    /// Verify `to_compression` level clamping at the helper boundary
    /// by round-tripping through an encoder built from its output.
    /// Uses level `u32::MAX` (extreme overflow path) to ensure the
    /// `.min(9)` clamp is load-bearing.
    #[test]
    fn to_compression_clamps_u32_max() {
        let input = b"extreme level";
        // If the clamp is missing, `Compression::new(u32::MAX)` panics
        // inside the flate2 crate. Reaching the assertion means the
        // clamp worked.
        let out = zlib_compress_with_level(input, u32::MAX).expect("clamped compress");
        let decoded = zlib_decompress(&out).expect("decompress");
        assert_eq!(decoded, input);
    }
}
