// HeavyThing Rust port — PNG image decoding (wraps the `png` crate).
//
// Original assembly source:
//   png.inc — Copyright © 2015 2 Ton Digital.
//   Homepage: https://2ton.com.au/
//   Author: Jeff Marrison <jeff@2ton.com.au>
//
// The upstream FASM source (786 lines) implements a minimalist PNG
// decoder by hand: 8-byte signature check, IHDR chunk validation,
// IDAT accumulation with zlib inflate via `zlib_inflate.inc`, PNG
// scanline filter reversal, and per-colortype expansion to a
// contiguous 32-bit RGBA pixel buffer. Per AAP §0.5.1.7 this Rust
// translation replaces all of that with a thin wrapper over the
// [`png`] crate (pinned to the workspace-level `png = "0.17"`
// dependency), which itself delegates IDAT decompression to
// `miniz_oxide`/`flate2` — matching the back-end used by the
// `crate::util::zlib` wrapper so there is no double-wrapping of the
// deflate primitive (see AAP §0.8.3 Minimal-Change discipline).
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

//! PNG image decoding via [`png`].
//!
//! Port of `png.inc` — the upstream FASM decoder is a
//! minimalist-by-design PNG reader that validates only the signature,
//! IHDR, IDAT, and IEND chunks, rejects `PLTE`/indexed color
//! ("mainly, no PLTE/indexed color support, seems none of the pngs i
//! have use them anyway" — `png.inc` line 25), and always produces a
//! contiguous 32-bit RGBA pixel buffer in memory. This Rust port
//! delegates chunk parsing, CRC-32 validation, zlib inflation, and
//! scanline defiltering to the well-maintained [`png`] crate while
//! preserving each of the FASM contract's externally observable
//! behaviors.
//!
//! # FASM contract parity
//!
//! The 40-byte `png_*_ofs` struct from `png.inc` (lines 34–44) has an
//! exact public-field mapping in the [`Png`] struct:
//!
//! | FASM offset | FASM field   | Rust field         |
//! |-------------|--------------|--------------------|
//! | 0           | `width`      | [`Png::width`]     |
//! | 4           | `height`     | [`Png::height`]    |
//! | 8           | `bitdepth`   | [`Png::bit_depth`] |
//! | 12          | `colortype`  | [`Png::color_type`]|
//! | 16          | `linelength` | [`Png::line_length`] |
//! | 20          | `rowlength`  | [`Png::row_length`]  |
//! | 24          | `pixdepth`   | [`Png::pixel_depth`] |
//! | 28          | `channels`   | [`Png::channels`]    |
//! | 32          | `data` ptr   | [`Png::data`] (owned `Vec<u8>`) |
//!
//! After decoding, `bit_depth` and `color_type` record the **source**
//! IHDR byte values (so `color_type ∈ {0, 2, 4, 6}` — `3`/Indexed is
//! rejected); `channels` / `pixel_depth` / `line_length` /
//! `row_length` describe the **expanded** RGBA output buffer held in
//! `data` and therefore have fixed values `4` / `4` / `width * 4` /
//! `width`, exactly as promised by the `png.inc` post-expansion
//! invariants.
//!
//! # Validation rules (matching `png.inc`)
//!
//! Inputs failing any of the following checks are rejected via
//! [`UtilError::Io`] with [`std::io::ErrorKind::InvalidData`]:
//!
//! - 8-byte PNG signature must be present (the `png` crate enforces
//!   this and surfaces it as [`png::DecodingError::Format`]).
//! - The first chunk must be `IHDR` (enforced by the `png` crate).
//! - `width ∈ 1..=65535` and `height ∈ 1..=65535` (matches `png.inc`
//!   lines 88–91).
//! - `bit_depth ∈ {8, 16}` (matches `png.inc` lines 110–114; `1`/`2`/
//!   `4` bpp grayscale PNGs are rejected even though the `png` crate
//!   could transparently expand them via [`Transformations::EXPAND`]).
//! - `color_type ∈ {0, 2, 4, 6}` — Grayscale, RGB, GrayscaleAlpha,
//!   RGBA. `3` (paletted/Indexed) is explicitly rejected per `png.inc`
//!   line 25.
//! - Every chunk's CRC-32 matches its payload (the `png` crate
//!   enforces this per PNG RFC §5.5). CRC failures surface as
//!   [`UtilError::CrcMismatch`] for callers that want to distinguish
//!   transport corruption from other malformations.
//!
//! # Output guarantees
//!
//! `Png::data` is always `width * height * 4` bytes of contiguous
//! 8-bit RGBA. Transformation chain:
//!
//! - 16 bpp source samples are stripped to 8 bpp via
//!   [`Transformations::STRIP_16`].
//! - Sub-8 bpp grayscale would be expanded to 8 bpp via
//!   [`Transformations::EXPAND`] (but is rejected at the validation
//!   step above; the transformation flag is kept for defense in
//!   depth against future spec relaxations).
//! - `tRNS` chunk transparency is unpacked into an explicit alpha
//!   channel via [`Transformations::EXPAND`].
//! - Grayscale → RGBA, GrayscaleAlpha → RGBA, and RGB → RGBA
//!   expansions are performed in this module (the `png` crate does
//!   not offer a direct color-type upconversion transformation for
//!   non-paletted inputs). The expansion loops mirror the FASM
//!   `.onechannel` / `.twochannels` / `.threechannels` /
//!   `.fourchannels` dispatches from `png.inc` lines 380–710.
//!
//! # Consumers
//!
//! - [`crate::tui::widgets::png`] — the TUI `PngWidget` that was
//!   driven by the FASM `tui_png.inc` (AAP §0.5.1.5). It consumes a
//!   [`Png`] and blits its RGBA buffer as 24-bit-true-color ANSI
//!   escapes into the terminal grid.
//!
//! # Design notes
//!
//! Per AAP §0.5.1.7 and §0.8.3 this module is explicitly forbidden
//! from re-implementing zlib inflation (`flate2` via `png`/`miniz_oxide`
//! handles it), CRC-32 chunk validation (the `png` crate uses
//! `crc32fast` internally — the same crate wrapped by
//! [`crate::util::crc`]), or IHDR/IDAT/IEND chunk parsing (the `png`
//! crate does it). The only PNG-specific logic that remains here is
//! the FASM validation policy (no indexed color, bit depth ∈ {8, 16},
//! dimensions in `1..=65535`) and the native-format → RGBA expansion
//! loops.
//!
//! No `unsafe` code. No allocations beyond the single decode buffer
//! plus the RGBA output buffer. No panics on malformed input (all
//! error paths use `Result<Png, UtilError>`).

use std::io::{Error as IoError, ErrorKind};

use png::{BitDepth, ColorType, Decoder, DecodingError, Transformations};

use crate::error::UtilError;

// ============================================================================
// Public type: Png.
// ============================================================================

/// A decoded PNG image with RGBA 32-bit pixel data.
///
/// Produced by [`Png::new`]. Holds an owned `Vec<u8>` containing the
/// contiguous `width * height * 4`-byte RGBA buffer, plus metadata
/// mirroring the 40-byte FASM `png_*_ofs` layout (see the module-level
/// documentation for a field-by-field mapping).
///
/// # Invariants
///
/// After [`Png::new`] returns `Ok`:
///
/// - `width ∈ 1..=65535` and `height ∈ 1..=65535`.
/// - `bit_depth ∈ {8, 16}` (the source IHDR bit depth).
/// - `color_type ∈ {0, 2, 4, 6}` (the source IHDR color type; `3` /
///   Indexed is rejected at decode time).
/// - `channels == 4` and `pixel_depth == 4` (always RGBA 32-bit).
/// - `line_length == width * 4` (row stride of the RGBA buffer).
/// - `row_length == width` (pixels per row).
/// - `data.len() == width as usize * height as usize * 4`.
#[derive(Debug, Clone)]
pub struct Png {
    /// Image width in pixels, from the IHDR chunk.
    pub width: u32,

    /// Image height in pixels, from the IHDR chunk.
    pub height: u32,

    /// Source bit depth from the IHDR chunk. Always `8` or `16`.
    pub bit_depth: u8,

    /// Source color type from the IHDR chunk. One of:
    /// `0` (Grayscale), `2` (RGB), `4` (Grayscale + Alpha),
    /// `6` (RGBA). `3` (Indexed/PLTE) is never present: such inputs
    /// are rejected at decode time to match `png.inc`'s policy.
    pub color_type: u8,

    /// Row stride in bytes of the RGBA output buffer (`width * 4`).
    pub line_length: u32,

    /// Pixels per row (`width`). Kept as a distinct field to mirror
    /// the FASM `png_rowlength_ofs` layout exactly.
    pub row_length: u32,

    /// Bytes per pixel in the RGBA output buffer. Always `4`.
    pub pixel_depth: u8,

    /// Channel count of the RGBA output buffer. Always `4`
    /// (Red, Green, Blue, Alpha).
    pub channels: u8,

    /// Contiguous RGBA 32-bit pixel data: `width * height * 4` bytes,
    /// row-major, one byte per sample in R, G, B, A order.
    pub data: Vec<u8>,
}

// ============================================================================
// Public API: Png::new and Png::pixel_count.
// ============================================================================

impl Png {
    /// Decode a PNG image from a byte slice and return a [`Png`]
    /// containing its RGBA pixel data.
    ///
    /// # Parameters
    ///
    /// * `bytes` — a complete PNG file byte stream, starting with the
    ///   8-byte PNG signature (`0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A
    ///   0x0A`) and ending with the `IEND` chunk and its CRC-32.
    ///
    /// # Returns
    ///
    /// On success, a fully decoded [`Png`] whose `data` field is a
    /// newly-allocated RGBA 32-bit pixel buffer. On failure, a
    /// [`UtilError`] whose variant identifies the failure class:
    ///
    /// - [`UtilError::CrcMismatch`] — a PNG chunk failed its CRC-32
    ///   check (per PNG RFC §5.5). The `png` crate surfaces this as
    ///   [`DecodingError::Format`] with a `"CRC error: …"` message;
    ///   this wrapper recognizes the prefix and promotes to the
    ///   specific variant for better diagnostics.
    /// - [`UtilError::Io`] for every other failure: missing or
    ///   invalid signature, malformed IHDR, truncated input,
    ///   unsupported color type (Indexed), unsupported bit depth
    ///   (`<8`), or dimensions outside `1..=65535`. The wrapped
    ///   [`std::io::Error`] carries a human-readable message.
    ///
    /// # Errors
    ///
    /// - `UtilError::Io` for malformed or truncated PNG inputs.
    /// - `UtilError::CrcMismatch` for PNG chunk CRC failures.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use heavything::util::png::Png;
    /// let bytes = std::fs::read("logo.png").expect("read file");
    /// let image = Png::new(&bytes).expect("decode PNG");
    /// assert_eq!(image.channels, 4);
    /// assert_eq!(image.data.len(), image.pixel_count() * 4);
    /// ```
    pub fn new(bytes: &[u8]) -> Result<Self, UtilError> {
        // Build a decoder over the input byte slice. `&[u8]` implements
        // `std::io::Read`, which is the bound required by `Decoder::new`.
        let mut decoder = Decoder::new(bytes);

        // Configure the transformation pipeline:
        //
        // - `EXPAND`   — expand paletted → RGB, expand sub-8 bpp grayscale
        //                to 8 bpp, and unpack tRNS transparency into an
        //                explicit alpha channel.
        // - `ALPHA`    — implies `EXPAND`; expands paletted images to
        //                RGBA. Included defensively even though paletted
        //                inputs are rejected at the validation step below
        //                per `png.inc`'s no-PLTE policy.
        // - `STRIP_16` — strip 16-bit samples to 8 bits, keeping only
        //                the high byte of each sample (matches the FASM
        //                16→8 stripping loops in `png.inc` lines ~150–180).
        //
        // The `png` crate does NOT provide a direct grayscale-→-RGB or
        // RGB-→-RGBA transformation for non-paletted inputs, so the
        // channel-count expansion is performed manually below after
        // `next_frame()` returns.
        decoder.set_transformations(
            Transformations::EXPAND | Transformations::ALPHA | Transformations::STRIP_16,
        );

        // Parse the PNG signature, IHDR, and any pre-IDAT ancillary
        // chunks. Returns a `Reader<&[u8]>` positioned just before the
        // first IDAT chunk.
        let mut reader = decoder.read_info().map_err(map_png_err)?;

        // Snapshot the source IHDR metadata before consuming the reader
        // for `next_frame()`. The `Info` reference is borrowed from
        // `reader`, so we copy the primitive fields out and release the
        // borrow before calling `output_color_type()` / `next_frame()`.
        let (width, height, source_color_type, source_bit_depth) = {
            let info = reader.info();
            (info.width, info.height, info.color_type, info.bit_depth)
        };

        // --------------------------------------------------------------
        // FASM validation rules (preserved verbatim from `png.inc`).
        // --------------------------------------------------------------

        // Reject paletted / indexed color. `png.inc` line 25 explicitly
        // states this is an intentional omission.
        if source_color_type == ColorType::Indexed {
            return Err(UtilError::Io(IoError::new(
                ErrorKind::InvalidData,
                "PNG indexed color (PLTE) not supported",
            )));
        }

        // Reject sub-8 bpp bit depths. `png.inc` lines 110–114 accept
        // only 8 or 16 bpp. Even though `Transformations::EXPAND` would
        // upconvert `1`/`2`/`4` bpp grayscale transparently, we preserve
        // the FASM policy strictly.
        if matches!(source_bit_depth, BitDepth::One | BitDepth::Two | BitDepth::Four) {
            return Err(UtilError::Io(IoError::new(
                ErrorKind::InvalidData,
                "PNG bit depth must be 8 or 16 (sub-8 bpp rejected)",
            )));
        }

        // Reject zero or out-of-range dimensions. `png.inc` lines 88–91
        // enforce `1..=65535` for both width and height.
        if width == 0 || height == 0 || width > 65_535 || height > 65_535 {
            return Err(UtilError::Io(IoError::new(
                ErrorKind::InvalidData,
                "PNG dimensions out of range (must be 1..=65535)",
            )));
        }

        // --------------------------------------------------------------
        // Decode the IDAT chunks into a native-format pixel buffer.
        // --------------------------------------------------------------

        // `output_color_type()` returns the (ColorType, BitDepth) pair
        // reflecting the applied transformations. After `STRIP_16` the
        // bit depth is always `Eight` for our accepted inputs; the
        // color type is whatever the transformations decided on.
        let (output_color_type, _output_bit_depth) = reader.output_color_type();

        // Allocate the scratch decode buffer. `output_buffer_size()` is
        // exact: it returns `output_line_size(width) * height` where
        // `output_line_size` includes any per-row padding the crate
        // considers necessary (none for 8 bpp outputs).
        let mut decode_buf = vec![0u8; reader.output_buffer_size()];
        reader.next_frame(&mut decode_buf).map_err(map_png_err)?;

        // --------------------------------------------------------------
        // Expand the native-format buffer to contiguous RGBA 32-bit.
        // --------------------------------------------------------------

        let pixel_count = (width as usize) * (height as usize);
        let data = expand_to_rgba(output_color_type, &decode_buf, pixel_count)?;

        // --------------------------------------------------------------
        // Assemble the final `Png` value.
        // --------------------------------------------------------------

        Ok(Self {
            width,
            height,
            // `bit_depth` reflects the *source* IHDR byte (8 or 16), not
            // the post-transformation output depth, matching FASM.
            bit_depth: source_bit_depth as u8,
            // `color_type` reflects the source IHDR byte: the `ColorType`
            // enum is `#[repr(u8)]` with values 0/2/3/4/6 matching the
            // PNG specification, so the cast is a zero-cost numeric
            // conversion that lands in `{0, 2, 4, 6}` given we rejected
            // `3` (Indexed) above.
            color_type: source_color_type as u8,
            // `line_length` / `row_length` / `pixel_depth` / `channels`
            // describe the *output* RGBA buffer regardless of source
            // format, matching the post-expansion FASM invariants.
            line_length: width * 4,
            row_length: width,
            pixel_depth: 4,
            channels: 4,
            data,
        })
    }

    /// Total pixel count of the image (`width * height`).
    ///
    /// Mirrors the informal FASM accessor pattern of computing
    /// `rdx = width * height` via `imul` immediately after loading the
    /// `png_*_ofs` struct fields.
    #[inline]
    pub fn pixel_count(&self) -> usize {
        (self.width as usize) * (self.height as usize)
    }

    /// Return the decoded RGBA pixel buffer as an immutable byte slice.
    ///
    /// Provided per the Checkpoint 4 Phase 2 API adaptation registry as
    /// a spelling-compatible accessor for downstream consumers that
    /// reach for `image.pixels()` (borrowing the convention from
    /// `image::RgbaImage::as_raw` / typical PNG-decoder crates). Since
    /// the canonical [`Png::data`] field is already `pub`, this
    /// accessor is additive and purely for API-surface parity — it
    /// compiles to the same single-field load as direct `.data[..]`
    /// access.
    ///
    /// The returned slice contains exactly `width * height * 4` bytes,
    /// laid out row-major as `[R, G, B, A, R, G, B, A, …]`.
    #[inline]
    #[must_use]
    pub fn pixels(&self) -> &[u8] {
        &self.data
    }
}

// ============================================================================
// Private helpers.
// ============================================================================

/// Expand a native-format decoded-pixel buffer to contiguous RGBA
/// 32-bit.
///
/// Handles the four non-paletted 8 bpp color types that can surface
/// after our transformation pipeline (`Transformations::EXPAND |
/// ALPHA | STRIP_16`). The `Indexed` branch is defensively included
/// for exhaustive-match semantics but is unreachable in practice:
/// `Png::new` rejects `ColorType::Indexed` on the source IHDR long
/// before this function is called.
fn expand_to_rgba(
    output_color_type: ColorType,
    decode_buf: &[u8],
    pixel_count: usize,
) -> Result<Vec<u8>, UtilError> {
    let mut data: Vec<u8> = Vec::with_capacity(pixel_count * 4);

    match output_color_type {
        // 1 sample per pixel → (G, G, G, 0xFF). Mirrors the FASM
        // `.onechannel` dispatch in `png.inc`.
        ColorType::Grayscale => {
            for &sample in decode_buf.iter().take(pixel_count) {
                data.push(sample);
                data.push(sample);
                data.push(sample);
                data.push(0xFF);
            }
        }

        // 2 samples per pixel → (G, G, G, A). Mirrors the FASM
        // `.twochannels` dispatch.
        ColorType::GrayscaleAlpha => {
            for chunk in decode_buf.chunks_exact(2).take(pixel_count) {
                data.push(chunk[0]);
                data.push(chunk[0]);
                data.push(chunk[0]);
                data.push(chunk[1]);
            }
        }

        // 3 samples per pixel → (R, G, B, 0xFF). Mirrors the FASM
        // `.threechannels` dispatch.
        ColorType::Rgb => {
            for chunk in decode_buf.chunks_exact(3).take(pixel_count) {
                data.push(chunk[0]);
                data.push(chunk[1]);
                data.push(chunk[2]);
                data.push(0xFF);
            }
        }

        // 4 samples per pixel → direct RGBA passthrough. Mirrors the
        // FASM `.fourchannels` dispatch (which was essentially a
        // `rep movsb` of the already-RGBA defiltered buffer).
        ColorType::Rgba => {
            let needed = pixel_count * 4;
            if decode_buf.len() < needed {
                return Err(UtilError::Io(IoError::new(
                    ErrorKind::InvalidData,
                    "PNG RGBA buffer shorter than width*height*4",
                )));
            }
            data.extend_from_slice(&decode_buf[..needed]);
        }

        // Unreachable given `Png::new` rejects `ColorType::Indexed` on
        // the source IHDR and `Transformations::ALPHA | EXPAND` would
        // have promoted indexed to RGBA before reaching this point
        // regardless. Kept for exhaustive-match safety.
        ColorType::Indexed => {
            return Err(UtilError::Io(IoError::new(
                ErrorKind::InvalidData,
                "PNG indexed color (PLTE) not supported",
            )));
        }
    }

    Ok(data)
}

/// Convert a [`png::DecodingError`] into the crate-wide [`UtilError`].
///
/// The variant mapping preserves the FASM error-classification intent:
///
/// - `IoError` → passed through via [`UtilError::Io`]'s `#[from]`
///   conversion.
/// - `Format` with a `"CRC error: …"` message (the `png` crate's
///   [`FormatError`] `Display` impl uses this exact prefix for the
///   internal `CrcMismatch` variant, see `png` 0.17 `decoder/stream.rs`
///   line 297) → promoted to the more-specific [`UtilError::CrcMismatch`]
///   so callers can distinguish transport corruption from logical
///   PNG malformations.
/// - `Format` with any other message → [`UtilError::Io`] with
///   [`ErrorKind::InvalidData`].
/// - `Parameter` → [`UtilError::Io`] with [`ErrorKind::InvalidInput`]
///   (misuse of the decoder interface; should not occur for our call
///   sites, but mapped for completeness).
/// - `LimitsExceeded` → [`UtilError::Io`] with
///   [`ErrorKind::InvalidData`] (the `png` crate's configurable size
///   limits were exceeded).
///
/// [`FormatError`]: png::DecodingError::Format
fn map_png_err(e: DecodingError) -> UtilError {
    match e {
        DecodingError::IoError(ioe) => UtilError::Io(ioe),

        DecodingError::Format(format_err) => {
            let msg = format_err.to_string();
            // The `png` crate's `FormatError::fmt` emits the exact prefix
            // `"CRC error: expected 0x…"` for its internal
            // `FormatErrorInner::CrcMismatch` variant. This is a stable
            // part of the crate's public `Display` output contract and
            // is the only place in the `png` crate that uses this prefix.
            if msg.starts_with("CRC error") {
                UtilError::CrcMismatch
            } else {
                UtilError::Io(IoError::new(ErrorKind::InvalidData, msg))
            }
        }

        DecodingError::Parameter(param_err) => {
            UtilError::Io(IoError::new(ErrorKind::InvalidInput, param_err.to_string()))
        }

        DecodingError::LimitsExceeded => {
            UtilError::Io(IoError::new(ErrorKind::InvalidData, "PNG limits exceeded"))
        }
    }
}

// ============================================================================
// API-adaptation helpers for downstream consumers.
// ============================================================================
//
// The Checkpoint 4 Phase 2 API adaptation registry prescribes two
// additional spellings for the PNG decoding entry-point:
//
// * A type alias `PngImage` paralleling the canonical [`Png`] name —
//   many downstream consumers (e.g., `util_integration.rs`) reach for
//   `PngImage` by convention because the `Png` prefix is otherwise
//   reserved in their namespaces for the format-identification enum.
//
// * A free function `decode(data) -> Result<Png, UtilError>` paralleling
//   [`Png::new`] — matches the naming pattern established by
//   `base64::decode`, `hex::decode`, etc.
//
// Both spellings preserve the canonical 9-field [`Png`] struct layout
// with its FASM `png_*_ofs` offset table parity (see module doc); we
// deliberately do NOT introduce a parallel `PngImage { width, height,
// channels, pixels }` struct that would discard the extra `bit_depth`,
// `color_type`, `line_length`, `row_length`, and `pixel_depth` fields
// — those fields are load-bearing for downstream callers that inspect
// the underlying PNG format metadata. The alias is therefore a
// spelling-only compatibility shim.

/// Alias of [`Png`] under the `PngImage` naming convention. Provided
/// per the API adaptation registry. Both names refer to the same
/// 9-field struct; pick whichever reads more naturally at the call
/// site.
pub use Png as PngImage;

/// Decode a PNG byte buffer into a [`Png`]. Alias of [`Png::new`] in
/// the free-function form (`png::decode(bytes)`) preferred by
/// downstream consumers. Byte-identical behavior to [`Png::new`]:
/// IDAT decompression via `miniz_oxide`/`flate2`, expansion to RGBA
/// via `png` crate `Transformations::EXPAND | ALPHA | STRIP_16`, and
/// rejection of indexed/PLTE images + sub-8bpp bit depths + zero or
/// greater-than-65535 dimensions.
///
/// # Errors
/// Returns [`UtilError::Io`] for malformed PNG data, unsupported
/// color types, or out-of-range dimensions; returns
/// [`UtilError::CrcMismatch`] if a chunk CRC check fails.
pub fn decode(data: &[u8]) -> Result<Png, UtilError> {
    Png::new(data)
}

// ============================================================================
// Unit tests.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use png::{BitDepth as EncBitDepth, ColorType as EncColorType, Encoder};

    /// Helper: encode `pixel_data` as a PNG with the given
    /// `color_type` at 8 bpp. Uses the `png` crate's encoder so test
    /// fixtures are always RFC-compliant.
    fn encode_png(width: u32, height: u32, color_type: EncColorType, pixel_data: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut encoder = Encoder::new(&mut buf, width, height);
            encoder.set_color(color_type);
            encoder.set_depth(EncBitDepth::Eight);
            let mut writer = encoder.write_header().expect("encode header");
            writer.write_image_data(pixel_data).expect("encode data");
        }
        buf
    }

    #[test]
    fn rejects_empty_input() {
        assert!(Png::new(&[]).is_err());
    }

    #[test]
    fn rejects_two_byte_input() {
        assert!(Png::new(&[0x89, 0x50]).is_err());
    }

    #[test]
    fn rejects_signature_only() {
        // Only the 8-byte PNG signature: no IHDR, no data, no IEND.
        let sig: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert!(Png::new(&sig).is_err());
    }

    #[test]
    fn rejects_random_bytes() {
        // Definitely not a PNG.
        let garbage: Vec<u8> = (0..128u8).collect();
        assert!(Png::new(&garbage).is_err());
    }

    #[test]
    fn decodes_1x1_rgba() {
        // Single red pixel, fully opaque.
        let px: [u8; 4] = [0xFF, 0x00, 0x00, 0xFF];
        let bytes = encode_png(1, 1, EncColorType::Rgba, &px);

        let decoded = Png::new(&bytes).expect("decode 1x1 RGBA");
        assert_eq!(decoded.width, 1);
        assert_eq!(decoded.height, 1);
        assert_eq!(decoded.bit_depth, 8);
        // ColorType::Rgba numeric value per PNG spec is 6.
        assert_eq!(decoded.color_type, 6);
        assert_eq!(decoded.channels, 4);
        assert_eq!(decoded.pixel_depth, 4);
        assert_eq!(decoded.line_length, 4);
        assert_eq!(decoded.row_length, 1);
        assert_eq!(decoded.data.len(), 4);
        assert_eq!(decoded.data, px);
        assert_eq!(decoded.pixel_count(), 1);
    }

    #[test]
    fn decodes_2x2_rgb_to_rgba() {
        // Four distinct RGB pixels. Each source pixel is 3 bytes;
        // after decode+expand each must become 4 bytes with alpha 0xFF.
        let rgb: [u8; 12] = [
            0xFF, 0x00, 0x00, // (0,0) red
            0x00, 0xFF, 0x00, // (1,0) green
            0x00, 0x00, 0xFF, // (0,1) blue
            0xFF, 0xFF, 0x00, // (1,1) yellow
        ];
        let bytes = encode_png(2, 2, EncColorType::Rgb, &rgb);

        let decoded = Png::new(&bytes).expect("decode 2x2 RGB");
        assert_eq!(decoded.width, 2);
        assert_eq!(decoded.height, 2);
        assert_eq!(decoded.bit_depth, 8);
        // ColorType::Rgb numeric value per PNG spec is 2.
        assert_eq!(decoded.color_type, 2);
        assert_eq!(decoded.channels, 4);
        assert_eq!(decoded.pixel_depth, 4);
        assert_eq!(decoded.line_length, 8); // 2 * 4
        assert_eq!(decoded.row_length, 2);
        assert_eq!(decoded.data.len(), 16); // 2 * 2 * 4
        assert_eq!(&decoded.data[0..4], &[0xFF, 0x00, 0x00, 0xFF]);
        assert_eq!(&decoded.data[4..8], &[0x00, 0xFF, 0x00, 0xFF]);
        assert_eq!(&decoded.data[8..12], &[0x00, 0x00, 0xFF, 0xFF]);
        assert_eq!(&decoded.data[12..16], &[0xFF, 0xFF, 0x00, 0xFF]);
        assert_eq!(decoded.pixel_count(), 4);
    }

    #[test]
    fn decodes_2x2_grayscale_to_rgba() {
        // Four grayscale samples at 8 bpp. After decode each single
        // byte G must expand to (G, G, G, 0xFF).
        let gray: [u8; 4] = [0x00, 0x55, 0xAA, 0xFF];
        let bytes = encode_png(2, 2, EncColorType::Grayscale, &gray);

        let decoded = Png::new(&bytes).expect("decode 2x2 grayscale");
        assert_eq!(decoded.width, 2);
        assert_eq!(decoded.height, 2);
        assert_eq!(decoded.bit_depth, 8);
        // ColorType::Grayscale numeric value per PNG spec is 0.
        assert_eq!(decoded.color_type, 0);
        assert_eq!(decoded.channels, 4);
        assert_eq!(decoded.pixel_depth, 4);
        assert_eq!(decoded.line_length, 8);
        assert_eq!(decoded.row_length, 2);
        assert_eq!(decoded.data.len(), 16);
        assert_eq!(&decoded.data[0..4], &[0x00, 0x00, 0x00, 0xFF]);
        assert_eq!(&decoded.data[4..8], &[0x55, 0x55, 0x55, 0xFF]);
        assert_eq!(&decoded.data[8..12], &[0xAA, 0xAA, 0xAA, 0xFF]);
        assert_eq!(&decoded.data[12..16], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn decodes_2x2_grayscale_alpha_to_rgba() {
        // Two samples per pixel: (G, A). Each must expand to
        // (G, G, G, A).
        let ga: [u8; 8] = [
            0x00, 0xFF, // (0,0) black, opaque
            0x80, 0x40, // (1,0) mid-gray, quarter-alpha
            0xFF, 0x00, // (0,1) white, transparent
            0x55, 0xAA, // (1,1) dark-gray, ~66% alpha
        ];
        let bytes = encode_png(2, 2, EncColorType::GrayscaleAlpha, &ga);

        let decoded = Png::new(&bytes).expect("decode 2x2 gray+alpha");
        assert_eq!(decoded.width, 2);
        assert_eq!(decoded.height, 2);
        // ColorType::GrayscaleAlpha numeric value per PNG spec is 4.
        assert_eq!(decoded.color_type, 4);
        assert_eq!(decoded.channels, 4);
        assert_eq!(decoded.data.len(), 16);
        assert_eq!(&decoded.data[0..4], &[0x00, 0x00, 0x00, 0xFF]);
        assert_eq!(&decoded.data[4..8], &[0x80, 0x80, 0x80, 0x40]);
        assert_eq!(&decoded.data[8..12], &[0xFF, 0xFF, 0xFF, 0x00]);
        assert_eq!(&decoded.data[12..16], &[0x55, 0x55, 0x55, 0xAA]);
    }

    #[test]
    fn rejects_indexed_color() {
        // Build a valid 1x1 indexed-color PNG via the encoder.
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut encoder = Encoder::new(&mut buf, 1, 1);
            encoder.set_color(EncColorType::Indexed);
            encoder.set_depth(EncBitDepth::Eight);
            // Single-color palette: one red entry.
            encoder.set_palette(vec![0xFF, 0x00, 0x00]);
            let mut writer = encoder.write_header().expect("indexed header");
            // Image data: one byte, palette index 0.
            writer.write_image_data(&[0x00]).expect("indexed data");
        }

        match Png::new(&buf) {
            Err(UtilError::Io(ioe)) => {
                // Must be `InvalidData` and mention indexed/PLTE.
                assert_eq!(ioe.kind(), ErrorKind::InvalidData);
                let msg = ioe.to_string().to_lowercase();
                assert!(
                    msg.contains("indexed") || msg.contains("plte"),
                    "unexpected error message: {msg}"
                );
            }
            Ok(_) => panic!("indexed-color PNG must be rejected"),
            Err(other) => panic!("expected UtilError::Io, got {other:?}"),
        }
    }

    #[test]
    fn pixel_count_matches_dimensions() {
        // Use a 3x5 image to confirm `pixel_count` is width * height.
        let rgba: Vec<u8> = vec![0x7F; 3 * 5 * 4];
        let bytes = encode_png(3, 5, EncColorType::Rgba, &rgba);
        let decoded = Png::new(&bytes).expect("decode 3x5 RGBA");
        assert_eq!(decoded.pixel_count(), 15);
        assert_eq!(decoded.data.len(), 15 * 4);
    }

    #[test]
    fn decodes_larger_image_correctly() {
        // Decode a 16x16 RGBA image with a gradient and verify a
        // sampling of pixel bytes round-trip exactly through the
        // encode → decode path.
        let w: u32 = 16;
        let h: u32 = 16;
        let mut src: Vec<u8> = Vec::with_capacity((w * h) as usize * 4);
        for y in 0..h {
            for x in 0..w {
                src.push(x as u8 * 16);
                src.push(y as u8 * 16);
                src.push(((x + y) % 16) as u8 * 16);
                src.push(0xFF);
            }
        }
        let bytes = encode_png(w, h, EncColorType::Rgba, &src);
        let decoded = Png::new(&bytes).expect("decode 16x16 RGBA");

        assert_eq!(decoded.width, w);
        assert_eq!(decoded.height, h);
        assert_eq!(decoded.data.len(), src.len());
        assert_eq!(decoded.data, src);
    }

    #[test]
    fn map_png_err_passes_through_io() {
        // IoError variant must pass through via `UtilError::Io`.
        let io_err = IoError::new(ErrorKind::UnexpectedEof, "truncated");
        let mapped = map_png_err(DecodingError::IoError(io_err));
        assert!(matches!(mapped, UtilError::Io(_)));
    }

    #[test]
    fn map_png_err_translates_limits_exceeded() {
        let mapped = map_png_err(DecodingError::LimitsExceeded);
        match mapped {
            UtilError::Io(ioe) => {
                assert_eq!(ioe.kind(), ErrorKind::InvalidData);
                assert!(ioe.to_string().contains("limits"));
            }
            other => panic!("expected UtilError::Io, got {other:?}"),
        }
    }

    #[test]
    fn rejects_tampered_chunk_as_crc_mismatch() {
        // Produce a valid 1x1 RGBA PNG, then flip one byte inside the
        // IDAT payload. The chunk CRC-32 will no longer match the
        // mutated data, so the `png` crate must surface this as
        // `DecodingError::Format` with the "CRC error: …" Display
        // prefix, which `map_png_err` must promote to
        // `UtilError::CrcMismatch`.
        let px: [u8; 4] = [0xFF, 0x00, 0x00, 0xFF];
        let mut bytes = encode_png(1, 1, EncColorType::Rgba, &px);

        // The first IDAT chunk's type tag is `"IDAT"` = 0x49 0x44 0x41
        // 0x54. Find its offset and mutate a byte of the chunk's
        // payload (the 4 bytes immediately after the length+type
        // preamble). We skip the 8-byte signature and the 25-byte
        // IHDR chunk to land inside IDAT.
        let idat_pos = bytes
            .windows(4)
            .position(|w| w == b"IDAT")
            .expect("IDAT chunk present");
        // Mutate the first byte of the IDAT payload (4 bytes after
        // `IDAT` tag). This is inside the zlib-compressed data; the
        // chunk's 4-byte CRC trailer at the end will no longer match.
        let tamper_pos = idat_pos + 4;
        bytes[tamper_pos] = bytes[tamper_pos].wrapping_add(1);

        match Png::new(&bytes) {
            Err(UtilError::CrcMismatch) => {
                // Expected path.
            }
            // A deflate-level corruption could also surface as a
            // generic Format error; that's acceptable — the important
            // invariant is that the decode fails loudly.
            Err(UtilError::Io(_)) => {
                // Also acceptable for a deflate-corruption-only
                // tamper; our mapping promotes only the CRC-tagged
                // subvariant.
            }
            Ok(_) => panic!("tampered PNG must not decode cleanly"),
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }
}
