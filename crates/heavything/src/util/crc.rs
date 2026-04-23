// HeavyThing Rust port — CRC-32 IEEE 802.3 (gzip/PNG polynomial).
//
// Original assembly source:
//   crc.inc — Copyright © 2015 2 Ton Digital.
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

//! CRC-32 IEEE 802.3 (gzip/PNG polynomial `0xEDB88320`).
//!
//! Port of the FASM `crc.inc` module. The upstream FASM implementation
//! uses a 16-byte-at-a-time table-based CRC-32 kernel; this Rust port
//! wraps the [`crc32fast`] crate, which uses the same polynomial
//! (`0xEDB88320`, the reflected form of the IEEE 802.3 / gzip / PNG
//! polynomial) and, when available, SSE2 + PCLMULQDQ SIMD acceleration
//! on `x86_64`. The externally observable output — the 32-bit CRC value
//! for any given byte sequence — is byte-for-byte identical to the FASM
//! implementation and to standard test vectors.
//!
//! # FASM API parity
//!
//! The FASM export `crc$32(accum, buffer, length) -> new_accum` maps
//! directly to [`crc32`], which accepts an initial accumulator, a byte
//! slice, and returns the updated accumulator. Pass `0` as the initial
//! accumulator for a new computation; pass the previous return value on
//! subsequent calls to extend incrementally.
//!
//! For ergonomic one-shot CRC calculation, use [`crc32_oneshot`].
//! For incremental streaming (e.g. inside an I/O chain where the CRC
//! is updated on each chunk), use the [`Crc32`] struct.
//!
//! # Consumers
//!
//! * `util::zlib` — gzip footer (RFC 1952 §2.3) CRC-32 of the
//!   uncompressed payload.
//! * `util::png` — PNG chunk CRC-32 per PNG specification §5.5
//!   (the `png` crate validates these internally, so direct usage is
//!   limited to custom chunk handling).
//!
//! # Design notes
//!
//! * The FASM comment at `crc.inc:24` explicitly notes that this is
//!   **not** the CRC-32C polynomial exposed by the SSE4.2 `crc32`
//!   instruction — that polynomial (`0x82F63B78`) is used by iSCSI and
//!   Castagnoli. Gzip, PNG, and Ethernet all use IEEE 802.3
//!   (`0xEDB88320`), which is what [`crc32fast`] implements.
//! * The standard check value is `crc32(0, b"123456789") == 0xCBF43926`.
//!   This is universal across every IEEE 802.3 CRC-32 implementation;
//!   if the test fails, the build is broken.

use crc32fast::Hasher;

// ---------------------------------------------------------------------------
// Free functions — FASM-parity API
// ---------------------------------------------------------------------------

/// Compute or update a CRC-32 accumulator over a byte buffer.
///
/// Matches FASM `crc$32(accum, buffer, length) -> new_accum` semantics
/// for incremental computation:
///
/// * Pass `0` as the initial accumulator on the first call.
/// * Pass the previous return value on subsequent calls to extend.
///
/// Uses polynomial `0xEDB88320` (IEEE 802.3 / gzip / PNG).
///
/// # Examples
///
/// One-shot:
///
/// ```
/// use heavything::util::crc::crc32;
/// assert_eq!(crc32(0, b"123456789"), 0xCBF43926);
/// ```
///
/// Incremental (split across chunks yields the same result):
///
/// ```
/// use heavything::util::crc::crc32;
/// let a = crc32(0, b"1234");
/// let b = crc32(a, b"56789");
/// assert_eq!(b, 0xCBF43926);
/// ```
#[inline]
pub fn crc32(accum: u32, buffer: &[u8]) -> u32 {
    // `crc32fast`'s Hasher uses the same polynomial and initial/final XOR
    // convention as the IEEE 802.3 / gzip / PNG standard, so seeding it
    // with `accum` reproduces the FASM "running accumulator" pattern.
    let mut hasher = Hasher::new_with_initial(accum);
    hasher.update(buffer);
    hasher.finalize()
}

/// Compute the CRC-32 of a byte buffer from scratch (initial accumulator 0).
///
/// Convenience shim over [`crc32`] for the common case where there is no
/// prior accumulator to extend.
///
/// # Examples
///
/// ```
/// use heavything::util::crc::crc32_oneshot;
/// assert_eq!(crc32_oneshot(b"123456789"), 0xCBF43926);
/// assert_eq!(crc32_oneshot(b""), 0);
/// ```
#[inline]
pub fn crc32_oneshot(buffer: &[u8]) -> u32 {
    crc32(0, buffer)
}

// ---------------------------------------------------------------------------
// Streaming CRC-32 computer
// ---------------------------------------------------------------------------

/// Streaming CRC-32 computer.
///
/// Use when bytes must be fed incrementally without carrying an
/// intermediate accumulator by hand. Mirrors a common FASM pattern where
/// an `io` chain layer updates a running CRC on each chunk of data
/// passing through (e.g. gzip payload hashing during deflate output or
/// PNG chunk serialisation).
///
/// # Examples
///
/// ```
/// use heavything::util::crc::Crc32;
/// let mut crc = Crc32::new();
/// crc.update(b"123");
/// crc.update(b"456");
/// crc.update(b"789");
/// assert_eq!(crc.finalize(), 0xCBF43926);
/// ```
#[derive(Clone)]
pub struct Crc32 {
    hasher: Hasher,
}

impl Crc32 {
    /// Create a new CRC-32 computer with initial accumulator `0`.
    #[inline]
    pub fn new() -> Self {
        Self {
            hasher: Hasher::new(),
        }
    }

    /// Create a new CRC-32 computer seeded with the given accumulator.
    ///
    /// Useful for resuming a previously persisted computation — e.g. when
    /// a large payload's CRC was computed so far and stored in an I/O
    /// chain's per-connection state, and further chunks must extend it.
    #[inline]
    pub fn new_with_accum(accum: u32) -> Self {
        Self {
            hasher: Hasher::new_with_initial(accum),
        }
    }

    /// Extend the accumulator with a byte slice.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and return the CRC-32 value. Consumes the computer.
    #[inline]
    pub fn finalize(self) -> u32 {
        self.hasher.finalize()
    }

    /// Peek at the current accumulator without consuming the computer.
    ///
    /// `crc32fast::Hasher` does not expose a peek primitive directly; we
    /// clone the internal state and finalize the clone. For the streaming
    /// use-case where peek is called rarely (e.g. progress reporting or
    /// mid-stream validation), the clone cost is acceptable.
    #[inline]
    pub fn peek(&self) -> u32 {
        self.hasher.clone().finalize()
    }
}

impl Default for Crc32 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests — CRC-32 IEEE 802.3 known-answer vectors and API behavior
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The empty input produces accumulator 0 when started from 0.
    #[test]
    fn empty_input() {
        assert_eq!(crc32_oneshot(&[]), 0);
        assert_eq!(crc32(0, &[]), 0);
    }

    /// IEEE 802.3 known-answer vectors. These are universal across every
    /// conforming CRC-32 implementation; any divergence signals a
    /// fundamentally broken polynomial or initial/final XOR convention.
    #[test]
    fn known_vectors() {
        // The canonical check value per CRC-32 IEEE 802.3.
        assert_eq!(crc32_oneshot(b"123456789"), 0xCBF43926);
        // Single-byte vectors.
        assert_eq!(crc32_oneshot(b"a"), 0xE8B7BE43);
        // Empty-input identity.
        assert_eq!(crc32_oneshot(b""), 0);
    }

    /// Incremental updates (split the input into two chunks) must agree
    /// with a one-shot computation over the full input.
    #[test]
    fn incremental_equals_oneshot() {
        let full: &[u8] = b"The quick brown fox jumps over the lazy dog";
        let (a, b) = full.split_at(20);
        let oneshot = crc32_oneshot(full);
        let accum1 = crc32(0, a);
        let accum2 = crc32(accum1, b);
        assert_eq!(oneshot, accum2);
    }

    /// Repeated `update()` calls on the streaming `Crc32` must produce
    /// the same result as the one-shot free function.
    #[test]
    fn streaming_api() {
        let mut crc = Crc32::new();
        crc.update(b"123");
        crc.update(b"456");
        crc.update(b"789");
        assert_eq!(crc.finalize(), 0xCBF43926);
    }

    /// `peek()` must not consume the computer; further updates (even
    /// empty ones) must remain valid afterward and `finalize()` must
    /// yield the same value `peek()` returned when no additional bytes
    /// were fed in between.
    #[test]
    fn peek_does_not_consume() {
        let mut crc = Crc32::new();
        crc.update(b"123456789");
        let peeked = crc.peek();
        // Feed an empty slice; this must leave the accumulator unchanged.
        crc.update(&[]);
        let final_val = crc.finalize();
        assert_eq!(peeked, final_val);
        assert_eq!(final_val, 0xCBF43926);
    }

    /// Constructing a fresh `Crc32` with a prior accumulator via
    /// `new_with_accum` must allow seamless extension of the computation.
    #[test]
    fn resume_with_accum() {
        let accum = crc32_oneshot(b"123");
        let mut crc = Crc32::new_with_accum(accum);
        crc.update(b"456789");
        assert_eq!(crc.finalize(), 0xCBF43926);
    }

    /// `Default::default()` must be equivalent to `Crc32::new()`.
    #[test]
    fn default_equals_new() {
        let a = Crc32::default();
        let b = Crc32::new();
        assert_eq!(a.peek(), b.peek());
        assert_eq!(a.finalize(), 0);
    }

    /// `Clone` preserves state: cloning mid-stream and continuing on each
    /// branch independently yields identical finalizations when fed the
    /// same remainder. Validates the `#[derive(Clone)]` on `Crc32`.
    #[test]
    fn clone_preserves_state() {
        let mut crc_a = Crc32::new();
        crc_a.update(b"1234");
        let mut crc_b = crc_a.clone();
        crc_a.update(b"56789");
        crc_b.update(b"56789");
        assert_eq!(crc_a.finalize(), 0xCBF43926);
        assert_eq!(crc_b.finalize(), 0xCBF43926);
    }

    /// Two distinct inputs of identical length must generally produce
    /// different CRCs (weak collision-sensitivity check — CRC-32 is not
    /// cryptographic, but trivially distinct inputs should not collide).
    #[test]
    fn distinct_inputs_produce_distinct_crcs() {
        assert_ne!(crc32_oneshot(b"abc"), crc32_oneshot(b"abd"));
        assert_ne!(crc32_oneshot(b"123456789"), crc32_oneshot(b"987654321"));
    }

    /// Large input (16 KiB of zeros) — exercises the SIMD fast path on
    /// `x86_64` builds and confirms the accumulator stays self-consistent
    /// across the table/SIMD boundary inside `crc32fast`.
    #[test]
    fn large_zero_buffer() {
        const N: usize = 16 * 1024;
        let zeros = vec![0u8; N];
        let oneshot = crc32_oneshot(&zeros);
        // Split-then-rejoin must match.
        let (a, b) = zeros.split_at(N / 2);
        let split = crc32(crc32(0, a), b);
        assert_eq!(oneshot, split);
        // CRC of N zero bytes is deterministic and non-zero for N > 0.
        assert_ne!(oneshot, 0);
    }
}
