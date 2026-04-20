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

//! MD5 hash function (RFC 1321).
//! Port of `md5.inc` (531 lines).
//!
//! # ⚠️ Security Warning
//!
//! **MD5 is cryptographically broken** for any use that requires
//! collision resistance. Public collision attacks were demonstrated in
//! 2004 (Wang et al.), chosen-prefix collisions in 2008 (Stevens), and
//! have since been mass-produced — a chosen-prefix collision can be
//! generated on commodity hardware in minutes. MD5 offers no collision
//! resistance in any adversarial setting, and its preimage resistance
//! is also weakened (theoretical 2^123.4 attack, Sasaki 2009).
//!
//! This module is provided **only for legacy protocol interoperability**
//! where the wire format mandates MD5:
//!
//! * TLS 1.0 / 1.1 PRF (RFC 2246 / RFC 4346) — PRF's MD5 half XORed
//!   with SHA-1 half provides only indirect security; TLS 1.0/1.1 are
//!   themselves deprecated (RFC 8996).
//! * HTTP Digest Authentication (RFC 7616) — MD5 is the default
//!   algorithm; SHA-256 is preferred but legacy servers still require
//!   MD5 for interop.
//! * NTLM / NT password hash (Windows legacy authentication).
//!
//! **For any new cryptographic application, use
//! [`crate::crypto::sha2`] (SHA-256 / SHA-512) instead.**
//!
//! # Historical Context (FASM original)
//!
//! The FASM `md5.inc` (531 lines) is a hand-translated port of Marc
//! Bevand's public-domain MD5 implementation (attribution preserved in
//! the source header at `md5.inc` line 24). It exports six public
//! symbols:
//!
//! * `md5$new`       (`md5.inc` line 31)  — allocate + initialize a
//!   128-byte state block (`md5_state_size = 128`) via `heap$alloc`.
//! * `md5$init`      (`md5.inc` line 47)  — zero the state, write the
//!   initial hash IV `0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476`
//!   (RFC 1321 §3.3, `md5.inc` line 79).
//! * `md5$update`    (`md5.inc` line 86)  — feed message bytes into the
//!   state, calling `md5$transform` for every full 64-byte block.
//! * `md5$transform` (`md5.inc` line 161) — single-block compression:
//!   four rounds of 16 operations each (`F`, `G`, `H`, `I` nonlinear
//!   functions) with rotate-left by round-specific amounts.
//! * `md5$final`     (`md5.inc` line 370) — append `0x80` padding,
//!   zero-fill to 56 bytes mod 64, append little-endian 64-bit
//!   bitcount, run final `md5$transform`, then **auto-reinitialize**
//!   the state (`md5.inc` line 461 — `call md5$init`) so callers can
//!   immediately reuse it.
//! * `md5$mgf1`      (`md5.inc` line 482) — RFC 2437 / RFC 8017 Mask
//!   Generation Function 1 over MD5. Produces `mask_len` bytes from a
//!   seed via `H(seed || BE32(counter))` concatenation.
//!
//! # Rust Strategy (per AAP §0.5.1.3 and §0.8.3)
//!
//! Per AAP §0.6.1 this module wraps the RustCrypto `md-5 = "0.10"`
//! crate. That crate contains the same Marc Bevand algorithm family
//! (constant-time, no lookup tables) compiled to idiomatic Rust with
//! byte-identical output. We therefore do **not** re-implement the
//! transform; we expose a thin safe API that preserves the FASM public
//! contract:
//!
//! 1. One-shot digest: [`md5()`] — takes a slice, returns `[u8; 16]`.
//!    Corresponds to FASM's common idiom of `md5$new` → `md5$update` →
//!    `md5$final` in a single call.
//! 2. Stateful hashing: [`Md5`] — wraps [`md5::Md5`] with methods
//!    ([`Md5::new`], [`Md5::default`], [`Md5::reset`], [`Md5::update`],
//!    [`Md5::finalize`], [`Md5::clone`]) mirroring the FASM API shape.
//!    The stateful form is required by [`crate::crypto::hmac`] for
//!    HMAC-MD5 (used in TLS 1.0 / 1.1 PRF and HTTP digest auth).
//! 3. MGF1: [`md5_mgf1`] — RFC 8017 §B.2.1 mask generation, computes
//!    `mask_len` bytes by concatenating `MD5(seed || BE32(counter))`.
//!
//! # Byte-for-Byte Parity with FASM
//!
//! Every output of this module is byte-identical to the FASM assembly
//! output for identical input. Both implementations trace back to the
//! same Marc Bevand reference algorithm and produce RFC 1321 test
//! vectors exactly. Verified in the `tests` module against RFC 1321
//! §A.5 vectors and against multi-block inputs that exercise the
//! buffer-flush boundary.
//!
//! # No `unsafe`, no FFI
//!
//! This module contains zero `unsafe` blocks and performs no FFI. All
//! operations delegate to the safe [`mod@md5`] crate API. Per AAP §0.7.4
//! this contributes **0** sites to the `UNSAFE_AUDIT.md` inventory.

use md5::{Digest, Md5 as Md5Core};

// ============================================================================
// Constants
// ============================================================================

/// MD5 produces a 128-bit (16-byte) digest.
///
/// Matches RFC 1321 §3.3 and the FASM implied digest-size constant
/// (state-block layout stores the 4 × u32 hash register at offset
/// `sha_stateptr_ofs`).
pub const MD5_OUTPUT_SIZE: usize = 16;

/// MD5 processes messages in 512-bit (64-byte) blocks.
///
/// Matches RFC 1321 §3.4 and the FASM `md5$transform` chunk size
/// (`md5.inc` line 161, all 16 round operations consume 4 message
/// words = 64 bytes per call).
pub const MD5_BLOCK_SIZE: usize = 64;

// ============================================================================
// One-shot digest
// ============================================================================

/// Compute the MD5 digest of `data` and return the 16-byte result.
///
/// This is the one-shot path — equivalent to creating an [`Md5`],
/// feeding `data`, and finalizing in a single call. Internally delegates
/// to [`Digest::digest`] on the `md-5` crate's `Md5` type (AAP §0.6.1
/// external import).
///
/// # ⚠️ Security
///
/// See the [module-level warning](self). Do not use MD5 for any new
/// security-sensitive application.
///
/// # Examples
///
/// ```
/// use heavything::crypto::md5::md5;
/// // RFC 1321 test vector: MD5("") = d41d8cd98f00b204e9800998ecf8427e
/// assert_eq!(
///     md5(b""),
///     [0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
///      0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e],
/// );
/// ```
#[must_use]
pub fn md5(data: &[u8]) -> [u8; MD5_OUTPUT_SIZE] {
    // `Md5Core::digest` returns `GenericArray<u8, U16>`; `.into()`
    // uses the `From<GenericArray<u8, U16>> for [u8; 16]` impl
    // provided by `generic-array 0.14` for fixed sizes. Zero-cost at
    // `opt-level = 3`.
    Md5Core::digest(data).into()
}

// ============================================================================
// Stateful hasher
// ============================================================================

/// MD5 hasher — equivalent to the FASM `md5$new`-allocated state block.
///
/// Wraps [`md5::Md5`]. Use this type when you need to hash data across
/// multiple calls ([`Self::update`]) before producing the final digest
/// ([`Self::finalize`]). For simple one-shot hashing use the free
/// [`md5()`] function.
///
/// The [`Clone`] implementation duplicates the full internal state and
/// is used by [`crate::crypto::hmac`] to split the "ipad" and "opad"
/// inner/outer state for HMAC-MD5 precomputation (the standard
/// optimization from RFC 2104 §4).
///
/// # ⚠️ Security
///
/// See the [module-level warning](self). MD5 is broken for collision
/// resistance; this type exists only for legacy protocol support.
///
/// # Examples
///
/// ```
/// use heavything::crypto::md5::Md5;
/// let mut hasher = Md5::new();
/// hasher.update(b"abc");
/// let digest = hasher.finalize();
/// assert_eq!(
///     digest,
///     [0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
///      0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72],
/// );
/// ```
#[derive(Clone, Default)]
pub struct Md5 {
    /// Wrapped RustCrypto hasher holding the MD5 state (4 × u32 chain
    /// variables + 64-byte block buffer + 64-bit bit-counter).
    /// Corresponds to the 128-byte block allocated by FASM `md5$new`
    /// (`md5_state_size = 128`, `md5.inc` line 26).
    ctx: Md5Core,
}

impl Md5 {
    /// Construct a fresh MD5 hasher initialized with the RFC 1321
    /// initial hash value `0x67452301, 0xefcdab89, 0x98badcfe,
    /// 0x10325476` and a zero bit-counter.
    ///
    /// Equivalent to FASM `md5$new` + `md5$init` (`md5.inc` lines 31
    /// and 47). The `md-5` crate's `Digest::new` performs the
    /// initialization inline within the returned struct — no heap
    /// allocation occurs (the FASM heap-alloc call was an artifact of
    /// the assembly memory model and is unnecessary in Rust where the
    /// state lives on the stack or inside an owning container).
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self { ctx: Md5Core::new() }
    }

    /// Reset this hasher to its initial state, discarding any
    /// previously-fed data.
    ///
    /// Equivalent to re-calling [`Self::new`] but operates in-place on
    /// this instance without allocating a new `Md5`. The FASM
    /// equivalent is `md5$init` on an existing state block.
    ///
    /// Mirrors the auto-reset behavior of FASM `md5$final` (`md5.inc`
    /// line 461): after a `finalize()`-equivalent call the FASM code
    /// implicitly reinitialized the state. In Rust, `finalize` consumes
    /// `self` to statically prevent use-after-finalize bugs, so callers
    /// who want to reuse the hasher must either `clone()` before
    /// finalize or `reset()` after any point in the hash stream.
    #[inline]
    pub fn reset(&mut self) {
        // Overwrite with a fresh hasher rather than calling
        // `Digest::reset` (which would require an extra `use
        // md5::digest::Reset`). Semantically equivalent, one line
        // fewer of trait scaffolding.
        self.ctx = Md5Core::new();
    }

    /// Feed `data` into the hasher.
    ///
    /// Equivalent to FASM `md5$update` (`md5.inc` line 86). May be
    /// called any number of times; the total message hashed is the
    /// concatenation of every `update` argument in order.
    ///
    /// # Performance
    ///
    /// Internally buffers partial blocks and calls `md5$transform` for
    /// every full 64-byte chunk — matches the FASM streaming behavior.
    /// For a single `update` call with a multiple-of-64-byte slice no
    /// buffering overhead is incurred.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        // `Digest::update` on `md5::Md5` in crate v0.10 accepts
        // `impl AsRef<[u8]>`; a `&[u8]` satisfies that bound directly.
        // Method resolution is unambiguous because only `Digest` is
        // imported at module level, not the lower-level `Update`
        // trait whose method has the same name.
        self.ctx.update(data);
    }

    /// Consume this hasher and return the final 16-byte digest.
    ///
    /// Equivalent to FASM `md5$final` (`md5.inc` line 370): appends
    /// the `0x80` padding byte, zero-fills to 56 bytes mod 64,
    /// appends the little-endian 64-bit bit-count, runs the final
    /// `md5$transform`, and extracts the 4 chain variables as 16
    /// little-endian bytes.
    ///
    /// # Difference from FASM
    ///
    /// The FASM variant auto-reinitializes the state after finalizing
    /// (line 461). The Rust variant consumes `self` (moves out), which
    /// statically prevents the same bug that the FASM auto-reinit was
    /// working around: accidentally finalizing the same state twice
    /// and getting inconsistent output. Callers who want to reuse a
    /// hasher should [`Clone`] it before finalizing, or construct a
    /// new one.
    #[inline]
    #[must_use]
    pub fn finalize(self) -> [u8; MD5_OUTPUT_SIZE] {
        // `Digest::finalize` returns `GenericArray<u8, U16>`;
        // `.into()` converts to `[u8; 16]` via the fixed-size `From`
        // impl in `generic-array 0.14`. Zero-cost at `opt-level = 3`.
        self.ctx.finalize().into()
    }
}

// ============================================================================
// MGF1 mask generation (RFC 8017 Appendix B.2.1)
// ============================================================================

/// RFC 8017 Mask Generation Function 1 (MGF1) over MD5.
///
/// Produces `mask_len` bytes of output by concatenating
/// `MD5(seed || BE32(counter))` for `counter = 0, 1, 2, …` and
/// truncating to exactly `mask_len` bytes. Matches FASM `md5$mgf1`
/// (`md5.inc` line 482) byte-for-byte.
///
/// # Parameters
///
/// * `seed` — the "mgfSeed" input octet string (any length, including
///   zero).
/// * `mask_len` — desired output length in bytes. `0` returns an empty
///   `Vec`. RFC 8017 states the maximum `mask_len` is
///   `2^32 × hLen = 2^32 × 16 = 64 GiB`; in practice callers request
///   at most a few hundred bytes (e.g., RSA-OAEP/PSS salt + DB
///   length).
///
/// # Returns
///
/// A `Vec<u8>` of exactly `mask_len` bytes.
///
/// # Algorithm
///
/// ```text
/// T = ""
/// for counter in 0 .. ceil(mask_len / 16):
///     C = BE32(counter)                   // I2OSP(counter, 4)
///     T = T || MD5(seed || C)
/// return T[0 .. mask_len]
/// ```
///
/// This exactly mirrors the FASM loop at `md5.inc` lines 489–530:
///
/// 1. `md5$update(state, seed, seed_len)`
/// 2. byte-swap counter to big-endian, `md5$update(state, BE_counter, 4)`
/// 3. `md5$final(state, digest, 0)`  (auto-reinits state)
/// 4. copy `min(16, remaining)` bytes to output, increment counter
///
/// # ⚠️ Security
///
/// MGF1-MD5 is almost never used in modern cryptography — RSA-OAEP
/// and RSA-PSS (the primary MGF1 consumers) migrated to SHA-256 long
/// ago. This function is provided solely for FASM API parity with
/// legacy code paths that referenced `md5$mgf1`. For new applications
/// use [`crate::crypto::sha2`]-based MGF1 or alternative KDFs.
///
/// # Examples
///
/// ```
/// use heavything::crypto::md5::md5_mgf1;
/// let mask = md5_mgf1(b"seed", 32);
/// assert_eq!(mask.len(), 32);
/// // Same seed + mask_len is deterministic:
/// assert_eq!(mask, md5_mgf1(b"seed", 32));
/// ```
#[must_use]
pub fn md5_mgf1(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(mask_len);
    // RFC 8017 step 3 counter. `u32` per I2OSP(counter, 4). The loop
    // exits well before overflow — for MD5's 16-byte block, reaching
    // `u32::MAX` would require a 64 GiB `mask_len`, far beyond any
    // realistic call site. `wrapping_add` below keeps this a total
    // function without tripping debug overflow-checks (AAP §0.8.3
    // "no panic in library code paths").
    let mut counter: u32 = 0;
    while output.len() < mask_len {
        // H(seed || I2OSP(counter, 4)) — RFC 8017 §B.2.1 step 3b.
        let mut hasher = Md5Core::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        // Append either a full 16-byte block or just the remainder
        // needed to reach `mask_len` — whichever is smaller. The
        // FASM implementation does the same min-copy at `md5.inc`
        // line 520.
        let remaining = mask_len - output.len();
        let take = remaining.min(MD5_OUTPUT_SIZE);
        output.extend_from_slice(&digest[..take]);
        counter = counter.wrapping_add(1);
    }
    output
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a 32-character hex string into a `[u8; 16]`. Test-only
    /// helper — panics on malformed input (a bug in the test itself,
    /// acceptable per AAP §0.8.4 "Tests and benchmarks may use
    /// `unwrap()`").
    #[allow(clippy::unwrap_used)]
    fn hex16(hex: &str) -> [u8; 16] {
        assert_eq!(hex.len(), 32, "expected 32 hex chars, got {}", hex.len());
        let mut out = [0u8; 16];
        for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let s = std::str::from_utf8(chunk).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    // ---------------------------------------------------------------------
    // RFC 1321 Section A.5 — "Test suite" reference vectors
    // ---------------------------------------------------------------------

    #[test]
    fn rfc1321_empty_string() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(md5(b""), hex16("d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn rfc1321_single_a() {
        // MD5("a") = 0cc175b9c0f1b6a831c399e269772661
        assert_eq!(md5(b"a"), hex16("0cc175b9c0f1b6a831c399e269772661"));
    }

    #[test]
    fn rfc1321_abc() {
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        assert_eq!(md5(b"abc"), hex16("900150983cd24fb0d6963f7d28e17f72"));
    }

    #[test]
    fn rfc1321_message_digest() {
        // MD5("message digest") = f96b697d7cb7938d525a2f31aaf161d0
        assert_eq!(md5(b"message digest"), hex16("f96b697d7cb7938d525a2f31aaf161d0"));
    }

    #[test]
    fn rfc1321_lower_alphabet() {
        // MD5("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
        assert_eq!(
            md5(b"abcdefghijklmnopqrstuvwxyz"),
            hex16("c3fcd3d76192e4007dfb496cca67e13b")
        );
    }

    #[test]
    fn rfc1321_alphanumeric() {
        // MD5("ABC...XYZabc...xyz012...789") = d174ab98d277d9f5a5611c2c9f419d9f
        assert_eq!(
            md5(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            hex16("d174ab98d277d9f5a5611c2c9f419d9f")
        );
    }

    #[test]
    fn rfc1321_eight_digit_groups() {
        // MD5("12345678901234567890…") — 80 bytes, exercises multi-block path.
        // Expected: 57edf4a22be3c955ac49da2e2107b67a (RFC 1321 §A.5).
        assert_eq!(
            md5(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
            hex16("57edf4a22be3c955ac49da2e2107b67a")
        );
    }

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

    #[test]
    fn constants_match_spec() {
        assert_eq!(MD5_OUTPUT_SIZE, 16);
        assert_eq!(MD5_BLOCK_SIZE, 64);
    }

    // ---------------------------------------------------------------------
    // Stateful hasher API (`Md5` struct)
    // ---------------------------------------------------------------------

    #[test]
    fn stateful_single_update_matches_oneshot() {
        let mut hasher = Md5::new();
        hasher.update(b"abc");
        assert_eq!(hasher.finalize(), md5(b"abc"));
    }

    #[test]
    fn stateful_incremental_matches_oneshot() {
        let mut h = Md5::new();
        h.update(b"abc");
        h.update(b"def");
        h.update(b"ghij");
        assert_eq!(h.finalize(), md5(b"abcdefghij"));
    }

    #[test]
    fn stateful_default_is_empty_state() {
        // `Md5::default()` must produce the same digest as `Md5::new()`
        // on empty input — the RFC 1321 zero-length vector.
        let h = Md5::default();
        assert_eq!(h.finalize(), md5(b""));
    }

    #[test]
    fn reset_restores_initial_state() {
        let mut h = Md5::new();
        h.update(b"some garbage we want to discard");
        h.reset();
        h.update(b"abc");
        assert_eq!(h.finalize(), md5(b"abc"));
    }

    #[test]
    fn reset_after_partial_block() {
        // Reset must clear both the compressed state and the buffered
        // partial-block bytes (critical for correctness — a naive
        // reset that only clears the state register would leave
        // stale buffer bytes and produce wrong digests).
        let mut h = Md5::new();
        h.update(b"x"); // single byte lives in buffer, not yet transformed
        h.reset();
        h.update(b"abc");
        assert_eq!(h.finalize(), md5(b"abc"));
    }

    #[test]
    fn clone_is_independent() {
        // This is the HMAC precompute pattern: one hasher absorbs the
        // shared ipad prefix, then is cloned so the inner and outer
        // hashes can diverge without restarting the prefix.
        let mut h1 = Md5::new();
        h1.update(b"shared-prefix");
        let mut h2 = h1.clone();
        h1.update(b"-path-A");
        h2.update(b"-path-B");
        assert_eq!(h1.finalize(), md5(b"shared-prefix-path-A"));
        assert_eq!(h2.finalize(), md5(b"shared-prefix-path-B"));
    }

    #[test]
    fn clone_preserves_partial_buffer() {
        // Cloning must copy the partial-block buffer too, not just
        // the compressed state.
        let mut h1 = Md5::new();
        h1.update(b"x"); // < 64 bytes → lives in buffer
        let mut h2 = h1.clone();
        h1.update(b"yz");
        h2.update(b"YZ");
        assert_eq!(h1.finalize(), md5(b"xyz"));
        assert_eq!(h2.finalize(), md5(b"xYZ"));
    }

    // ---------------------------------------------------------------------
    // Multi-block input (exercises the 64-byte-buffer boundary)
    // ---------------------------------------------------------------------

    #[test]
    fn multi_block_input_1000_bytes() {
        // 1000 = 15 full 64-byte blocks + 40-byte tail.
        let data = vec![0x61u8; 1000];
        let mut h = Md5::new();
        h.update(&data);
        assert_eq!(h.finalize(), md5(&data));
    }

    #[test]
    fn exactly_one_block() {
        // 64 bytes exactly — boundary condition that used to trip up
        // hand-rolled implementations missing the final-empty-block
        // case in the FASM padding.
        let data = vec![0x42u8; 64];
        let mut h = Md5::new();
        h.update(&data);
        let digest = h.finalize();
        assert_eq!(digest, md5(&data));
    }

    #[test]
    fn length_requires_second_padding_block() {
        // 56 bytes — the padding byte + 8-byte length would exceed
        // the first block's remaining 8 bytes, forcing a second
        // padding block. This is the `md5.inc` lines 400–417
        // `dosecondtolast` code path.
        let data = vec![0x55u8; 56];
        let mut h = Md5::new();
        h.update(&data);
        assert_eq!(h.finalize(), md5(&data));
    }

    // ---------------------------------------------------------------------
    // MGF1 (RFC 8017 §B.2.1)
    // ---------------------------------------------------------------------

    #[test]
    fn mgf1_zero_length_returns_empty() {
        assert!(md5_mgf1(b"any seed here", 0).is_empty());
    }

    #[test]
    fn mgf1_single_full_block() {
        // mask_len == 16 → exactly one MD5 iteration: MD5(seed || BE32(0)).
        let mask = md5_mgf1(b"foo", 16);
        assert_eq!(mask.len(), 16);
        let mut expected = Md5::new();
        expected.update(b"foo");
        expected.update(&0u32.to_be_bytes());
        assert_eq!(mask[..], expected.finalize()[..]);
    }

    #[test]
    fn mgf1_partial_block_truncation() {
        // mask_len < 16 → one MD5 call, output truncated to mask_len.
        let mask = md5_mgf1(b"seed", 8);
        assert_eq!(mask.len(), 8);
        let full = md5_mgf1(b"seed", 16);
        assert_eq!(mask, full[..8]);
    }

    #[test]
    fn mgf1_multi_block() {
        // mask_len == 40 → 3 MD5 calls (16 + 16 + 8 bytes).
        let mask = md5_mgf1(b"abc", 40);
        assert_eq!(mask.len(), 40);
        // First 16 bytes = MD5("abc" || BE32(0)).
        let mut h0 = Md5::new();
        h0.update(b"abc");
        h0.update(&0u32.to_be_bytes());
        assert_eq!(mask[..16], h0.finalize()[..]);
        // Next 16 bytes = MD5("abc" || BE32(1)).
        let mut h1 = Md5::new();
        h1.update(b"abc");
        h1.update(&1u32.to_be_bytes());
        assert_eq!(mask[16..32], h1.finalize()[..]);
        // Last 8 bytes = first 8 bytes of MD5("abc" || BE32(2)).
        let mut h2 = Md5::new();
        h2.update(b"abc");
        h2.update(&2u32.to_be_bytes());
        assert_eq!(mask[32..40], h2.finalize()[..8]);
    }

    #[test]
    fn mgf1_mask_len_exact_block_multiple() {
        // mask_len == 32 → exactly 2 MD5 blocks, no truncation.
        let mask = md5_mgf1(b"exact", 32);
        assert_eq!(mask.len(), 32);
    }

    #[test]
    fn mgf1_is_deterministic() {
        assert_eq!(md5_mgf1(b"det", 24), md5_mgf1(b"det", 24));
        assert_eq!(md5_mgf1(b"", 32), md5_mgf1(b"", 32));
    }

    #[test]
    fn mgf1_varies_with_seed() {
        assert_ne!(md5_mgf1(b"seed1", 16), md5_mgf1(b"seed2", 16));
    }

    #[test]
    fn mgf1_varies_with_mask_len() {
        // Extending the mask should extend, not regenerate, the output.
        let short = md5_mgf1(b"abc", 16);
        let long = md5_mgf1(b"abc", 32);
        assert_eq!(long.len(), 32);
        assert_eq!(short[..], long[..16]);
    }

    #[test]
    fn mgf1_empty_seed_is_valid() {
        // RFC 8017 allows zero-length seed.
        let mask = md5_mgf1(b"", 16);
        assert_eq!(mask.len(), 16);
        // Should equal MD5(BE32(0)) = MD5([0, 0, 0, 0]).
        let mut h = Md5::new();
        h.update(&0u32.to_be_bytes());
        assert_eq!(mask[..], h.finalize()[..]);
    }

    // ---------------------------------------------------------------------
    // Sanity: type is Send + Sync (required by tokio async contexts)
    // ---------------------------------------------------------------------

    #[test]
    fn md5_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Md5>();
    }
}
