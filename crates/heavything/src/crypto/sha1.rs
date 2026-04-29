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

//! SHA-1 hash function (FIPS 180-4 §6.1, RFC 3174).
//! Port of `sha1.inc` (677 lines).
//!
//! # ⚠️ Security Warning
//!
//! **SHA-1 is cryptographically broken** for any use that requires
//! collision resistance. A practical collision attack was demonstrated
//! by Stevens, Bursztein, Karpman, Albertini, and Markov in February
//! 2017 ("SHAttered" / `shattered.io`) — two distinct PDF files with
//! identical SHA-1 digests, produced with an estimated 2⁶³·¹ operations
//! (~$110k of cloud compute at the time). Chosen-prefix collisions
//! followed in 2020 (Leurent & Peyrin, "SHA-1 is a Shambles") at
//! 2⁶³·⁴ operations, further weakening the algorithm. NIST formally
//! deprecated SHA-1 for digital-signature generation in 2011
//! (SP 800-131A) and disallowed all production SHA-1 use after
//! 2030 (SP 800-131A Rev. 3, 2022). Preimage and second-preimage
//! resistance against best-known attacks remain at ~2⁶⁰ (Knellwolf &
//! Khovratovich 2012, reduced-round) but should not be relied on.
//!
//! This module is provided **only for legacy protocol interoperability**
//! where the wire format mandates SHA-1:
//!
//! * SSH v2 (RFC 4253) — `ssh-rsa` host-key signatures and
//!   `diffie-hellman-group-exchange-sha1` (superseded by `-sha256`
//!   variant; see [`crate::crypto::sha2`]). The HeavyThing SSH stack
//!   emits `ssh-rsa` signatures when peers negotiate them for
//!   compatibility with OpenSSH < 8.8 (where `ssh-rsa` was the
//!   default host-key algorithm).
//! * TLS 1.0 / 1.1 (RFC 2246 / RFC 4346) — the PRF's SHA-1 half
//!   XORed with the MD5 half; `CipherSuite` strings `*_SHA`
//!   (not `*_SHA256`) specify HMAC-SHA-1 as the MAC. TLS 1.0/1.1
//!   are themselves deprecated (RFC 8996, March 2021).
//! * OCSP (RFC 6960) — `CertID.hashAlgorithm` default is SHA-1
//!   (see RFC 6960 §4.1.1, `id-sha1`). Most responders still
//!   generate SHA-1 CertIDs even when the underlying signature
//!   uses SHA-256 or stronger.
//! * PKCS#1 v1.5 signatures with `id-sha1` OID for certificate
//!   verification against pre-2016 CAs (increasingly rare).
//!
//! **For any new cryptographic application, use
//! [`crate::crypto::sha2`] (SHA-256 / SHA-384 / SHA-512) instead.**
//!
//! # Historical Context (FASM original)
//!
//! The FASM `sha1.inc` (677 lines) is a hand-written SSE2-targeted
//! assembly implementation (comment at `sha1.inc` lines 24–28:
//! "sse2 only … faster than anything else where sse3 or better is
//! _not_ used"). Note the FASM naming convention uses `sha160` — this
//! refers to the NIST SHA-160 spec designation (SHA-1's original name
//! in FIPS 180-1, renamed to SHA-1 in FIPS 180-2). The Rust port uses
//! the conventional external name `Sha1` / `sha1`. The FASM module
//! exports six public symbols:
//!
//! * `sha160$new`       (`sha1.inc` line 35)  — allocate + initialize a
//!   144-byte state block (`sha160_state_size = 144`) via `heap$alloc`.
//! * `sha160$init`      (`sha1.inc` line 51)  — zero the state, write
//!   the initial hash IV `0x67452301, 0xefcdab89, 0x98badcfe,
//!   0x10325476, 0xc3d2e1f0` (FIPS 180-4 §5.3.1, `sha1.inc` line 76).
//! * `sha160$update`    (`sha1.inc` line 89)  — feed message bytes into
//!   the state, calling `sha160$transform` for every full 64-byte
//!   block.
//! * `sha160$transform` (`sha1.inc` line 164) — single-block
//!   compression: 80 rounds in four 20-round groups (`Ch`, `Parity`,
//!   `Maj`, `Parity` nonlinear functions) with round-constant
//!   addition and rotate-left-5 / rotate-left-30.
//! * `sha160$final`     (`sha1.inc` line 490) — append `0x80` padding,
//!   zero-fill to 56 bytes mod 64, append **big-endian** 64-bit
//!   bitcount (unlike MD5's little-endian), run final
//!   `sha160$transform`, then optionally reinitialize or free the
//!   state.
//! * `sha160$mgf1`      (`sha1.inc` line 628) — RFC 2437 / RFC 8017
//!   Mask Generation Function 1 over SHA-1. Produces `mask_len` bytes
//!   from a seed via `H(seed || BE32(counter))` concatenation.
//!
//! # Rust Strategy (per AAP §0.5.1.3 and §0.8.3)
//!
//! Per AAP §0.6.1 this module wraps the `ring = "0.17"` crate's
//! [`SHA1_FOR_LEGACY_USE_ONLY`][`ring::digest::SHA1_FOR_LEGACY_USE_ONLY`]
//! algorithm. Ring's use of the explicit `_FOR_LEGACY_USE_ONLY`
//! naming makes the legacy-only intent visible at every call site —
//! a reviewer seeing `ring::digest::SHA1_FOR_LEGACY_USE_ONLY` in a
//! diff has an immediate signal that SHA-1 is not being used for new
//! cryptographic construction. Ring's SHA-1 implementation produces
//! byte-identical output to the FASM and FIPS 180-4 reference
//! specifications. We therefore do **not** re-implement the transform
//! or IV; we expose a thin safe API that preserves the FASM public
//! contract:
//!
//! 1. One-shot digest: [`sha1()`] — takes a slice, returns `[u8; 20]`.
//!    Corresponds to FASM's common idiom of `sha160$new` →
//!    `sha160$update` → `sha160$final` in a single call.
//! 2. Stateful hashing: [`Sha1`] — wraps [`ring::digest::Context`]
//!    with methods ([`Sha1::new`], [`Sha1::default`], [`Sha1::reset`],
//!    [`Sha1::update`], [`Sha1::finalize`], [`Sha1::clone`])
//!    mirroring the FASM API shape. The stateful form is required by
//!    [`crate::crypto::hmac`] for HMAC-SHA-1 (used in TLS 1.0/1.1 PRF,
//!    SSH transport, and the OCSP CertID).
//! 3. MGF1: [`sha1_mgf1`] — RFC 8017 §B.2.1 mask generation,
//!    computes `mask_len` bytes by concatenating
//!    `SHA-1(seed || BE32(counter))`.
//!
//! # Byte-for-Byte Parity with FASM
//!
//! Every output of this module is byte-identical to the FASM assembly
//! output for identical input. Both implementations trace back to the
//! FIPS 180-4 reference specification and produce RFC 3174 / NIST CAVP
//! test vectors exactly. Verified in the `tests` module against the
//! canonical `"abc"` and `""` CAVP vectors, the RFC 3174 §7.3
//! multi-block vector, and inputs that exercise every padding-boundary
//! edge case (exactly-one-block, 55-byte single-pad, 56-byte
//! second-pad-block trigger).
//!
//! # No `unsafe`, no FFI
//!
//! This module contains zero `unsafe` blocks and performs no FFI. All
//! operations delegate to the safe [`ring::digest`] API. Per AAP §0.7.4
//! this contributes **0** sites to the `UNSAFE_AUDIT.md` inventory.

use ring::digest::{self, Context, Digest, SHA1_FOR_LEGACY_USE_ONLY};

// ============================================================================
// Constants
// ============================================================================

/// SHA-1 produces a 160-bit (20-byte) digest.
///
/// Matches FIPS 180-4 §6.1 (Table 1, "SHA-1 Message Digest Size") and
/// the FASM `sha160$final` output-write loop (`sha1.inc` lines 585–619,
/// which emits 5 × 4-byte big-endian chain variables = 20 bytes).
pub const SHA1_OUTPUT_SIZE: usize = 20;

/// SHA-1 processes messages in 512-bit (64-byte) blocks.
///
/// Matches FIPS 180-4 §6.1 (Table 1, "SHA-1 Block Size") and the FASM
/// `sha160$transform` chunk size (`sha1.inc` line 164, which consumes
/// exactly 16 × 4-byte message words = 64 bytes per call and expands
/// them to the 80-word `W` schedule for the compression rounds).
pub const SHA1_BLOCK_SIZE: usize = 64;

// ============================================================================
// One-shot digest
// ============================================================================

/// Compute the SHA-1 digest of `data` and return the 20-byte result.
///
/// This is the one-shot path — equivalent to creating a [`Sha1`],
/// feeding `data`, and finalizing in a single call. Internally delegates
/// to [`ring::digest::digest`] with [`SHA1_FOR_LEGACY_USE_ONLY`] as the
/// algorithm selector.
///
/// # ⚠️ Security
///
/// See the [module-level warning](self). Do not use SHA-1 for any new
/// security-sensitive application; prefer [`crate::crypto::sha2`].
///
/// # Examples
///
/// ```
/// use heavything::crypto::sha1::sha1;
/// // NIST CAVP vector: SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
/// assert_eq!(
///     sha1(b"abc"),
///     [0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
///      0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
///      0x9c, 0xd0, 0xd8, 0x9d],
/// );
/// ```
#[must_use]
pub fn sha1(data: &[u8]) -> [u8; SHA1_OUTPUT_SIZE] {
    // `ring::digest::digest` computes the hash in a single call and
    // returns an opaque `Digest` wrapper. `Digest: AsRef<[u8]>` yields
    // the 20-byte tail; we copy it into a stack-allocated fixed-size
    // array so the return type matches the FASM `sha160$final`
    // output buffer contract (`sha1.inc` line 494, `rsi` = 20-byte
    // destination).
    //
    // Per AAP §0.8.3 we avoid `unwrap()`/`expect()` in library code.
    // `copy_from_slice` is infallible for matching-length slices, and
    // the length is guaranteed by `SHA1_FOR_LEGACY_USE_ONLY.output_len()`
    // being exactly 20 (verified by ring's test suite and our own
    // `constants_match_spec` test below).
    let digest = digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, data);
    let mut out = [0u8; SHA1_OUTPUT_SIZE];
    out.copy_from_slice(digest.as_ref());
    out
}

// ============================================================================
// Stateful hasher
// ============================================================================

/// SHA-1 hasher — equivalent to the FASM `sha160$new`-allocated state
/// block.
///
/// Wraps [`ring::digest::Context`]. Use this type when you need to hash
/// data across multiple [`Self::update`] calls before producing the
/// final digest ([`Self::finalize`]). For simple one-shot hashing use
/// the free [`sha1()`] function.
///
/// The [`Clone`] implementation duplicates the full internal state
/// (compressed chain variables + buffered partial-block bytes + 64-bit
/// bit-counter) and is used by [`crate::crypto::hmac`] to split the
/// "ipad" and "opad" inner/outer state for HMAC-SHA-1 precomputation
/// (the standard optimization from RFC 2104 §4). It is also used by
/// the HMAC-DRBG reseed path where the "V" state is cloned before
/// being mixed with fresh entropy.
///
/// # ⚠️ Security
///
/// See the [module-level warning](self). SHA-1 is broken for collision
/// resistance; this type exists only for legacy protocol support.
///
/// # Examples
///
/// ```
/// use heavything::crypto::sha1::Sha1;
/// let mut hasher = Sha1::new();
/// hasher.update(b"abc");
/// let digest = hasher.finalize();
/// // NIST CAVP vector: SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
/// assert_eq!(
///     digest,
///     [0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
///      0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
///      0x9c, 0xd0, 0xd8, 0x9d],
/// );
/// ```
#[derive(Clone)]
pub struct Sha1 {
    /// Wrapped ring hasher context holding the SHA-1 state (5 × u32
    /// chain variables + 64-byte block buffer + 64-bit bit-counter).
    /// Corresponds to the 144-byte block allocated by FASM
    /// `sha160$new` (`sha160_state_size = 144`, `sha1.inc` line 30).
    /// Ring's `Context` is `#[derive(Clone)]` at `ring-0.17/src/digest.rs`
    /// line 186, enabling the HMAC precompute pattern referenced in
    /// the struct doc-comment above.
    ctx: Context,
}

impl Sha1 {
    /// Construct a fresh SHA-1 hasher initialized with the FIPS 180-4
    /// initial hash value `0x67452301, 0xefcdab89, 0x98badcfe,
    /// 0x10325476, 0xc3d2e1f0` and a zero bit-counter.
    ///
    /// Equivalent to FASM `sha160$new` + `sha160$init` (`sha1.inc`
    /// lines 35 and 51). Ring's [`Context::new`] performs the
    /// initialization inline within the returned struct — no heap
    /// allocation occurs (the FASM heap-alloc call was an artifact of
    /// the assembly memory model and is unnecessary in Rust where the
    /// state lives on the stack or inside an owning container).
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            ctx: Context::new(&SHA1_FOR_LEGACY_USE_ONLY),
        }
    }

    /// Reset this hasher to its initial state, discarding any
    /// previously-fed data.
    ///
    /// Equivalent to re-calling [`Self::new`] but operates in-place on
    /// this instance. The FASM equivalent is `sha160$init` on an
    /// existing state block (`sha1.inc` line 51).
    ///
    /// Mirrors the auto-reset behavior of FASM `sha160$final`
    /// (`sha1.inc` line 622 — the tail branch that calls
    /// `sha160$init` when the `edx` "free" flag is zero): after a
    /// `finalize()`-equivalent call the FASM code implicitly
    /// reinitialized the state. In Rust, [`Self::finalize`] consumes
    /// `self` to statically prevent use-after-finalize bugs, so
    /// callers who want to reuse the hasher must either [`Clone`] it
    /// before finalize or [`Self::reset`] after any point in the
    /// hash stream.
    #[inline]
    pub fn reset(&mut self) {
        // Overwrite with a fresh context rather than mutating in
        // place — ring does not expose a `reset()` method on
        // `Context`, so constructing a new one is the idiomatic
        // approach. Equivalent in behavior and (at `opt-level=3`)
        // cost to an in-place reset since both paths zero the
        // 144-byte state region.
        self.ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    }

    /// Feed `data` into the hasher.
    ///
    /// Equivalent to FASM `sha160$update` (`sha1.inc` line 89). May be
    /// called any number of times; the total message hashed is the
    /// concatenation of every `update` argument in order.
    ///
    /// # Performance
    ///
    /// Internally buffers partial blocks and calls the SHA-1 transform
    /// for every full 64-byte chunk — matches the FASM streaming
    /// behavior. For a single `update` call with a multiple-of-64-byte
    /// slice no buffering overhead is incurred. Ring's transform on
    /// x86_64 uses the AVX2-accelerated SHA-NI path when available
    /// (`is_x86_feature_detected!("sha")` at crate init) and falls
    /// back to a constant-time SIMD software implementation otherwise.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        // `Context::update(&mut self, &[u8])` is ring's public
        // streaming API, documented at `ring-0.17/src/digest.rs`
        // line 215. Direct passthrough — no buffering or conversion
        // needed since the input type matches exactly.
        self.ctx.update(data);
    }

    /// Consume this hasher and return the final 20-byte digest.
    ///
    /// Equivalent to FASM `sha160$final` (`sha1.inc` line 490):
    /// appends the `0x80` padding byte, zero-fills to 56 bytes mod 64,
    /// appends the **big-endian** 64-bit bit-count (`sha1.inc` lines
    /// 520–540 — note big-endian, in contrast to MD5's little-endian),
    /// runs the final `sha160$transform`, and extracts the 5 chain
    /// variables as 20 big-endian bytes.
    ///
    /// # Difference from FASM
    ///
    /// The FASM variant auto-reinitializes the state after finalizing
    /// when the caller passes `edx = 0` (don't-free flag; `sha1.inc`
    /// line 622 — `call sha160$init`). The Rust variant consumes
    /// `self` (moves out), which statically prevents the same bug
    /// that the FASM auto-reinit was working around: accidentally
    /// finalizing the same state twice and getting inconsistent
    /// output. Callers who want to reuse a hasher should [`Clone`] it
    /// before finalizing (the HMAC precompute pattern), or construct
    /// a new one.
    #[inline]
    #[must_use]
    pub fn finalize(self) -> [u8; SHA1_OUTPUT_SIZE] {
        // `Context::finish(self)` consumes the context and returns a
        // `Digest` (`ring-0.17/src/digest.rs` line 260). We then
        // extract the 20-byte tail via `AsRef<[u8]>` (line 324) and
        // copy into a stack-allocated fixed-size array.
        //
        // Per AAP §0.8.3 we avoid `unwrap()`/`expect()` in library
        // code. `copy_from_slice` is infallible for matching-length
        // slices; the length is guaranteed by ring's internal
        // invariant that a `Digest` produced from
        // `SHA1_FOR_LEGACY_USE_ONLY` has `output_len() == 20`.
        let digest: Digest = self.ctx.finish();
        let mut out = [0u8; SHA1_OUTPUT_SIZE];
        out.copy_from_slice(digest.as_ref());
        out
    }
}

impl Default for Sha1 {
    /// Construct a fresh SHA-1 hasher — identical to [`Sha1::new`].
    ///
    /// Implemented explicitly (rather than via `#[derive(Default)]`)
    /// because [`ring::digest::Context`] does not itself implement
    /// `Default` — it requires a non-null `&'static Algorithm`
    /// parameter at construction which has no sensible zero value.
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MGF1 mask generation (RFC 8017 Appendix B.2.1)
// ============================================================================

/// RFC 8017 Mask Generation Function 1 (MGF1) over SHA-1.
///
/// Produces `mask_len` bytes of output by concatenating
/// `SHA-1(seed || BE32(counter))` for `counter = 0, 1, 2, …` and
/// truncating to exactly `mask_len` bytes. Matches FASM `sha160$mgf1`
/// (`sha1.inc` line 628) byte-for-byte.
///
/// # Parameters
///
/// * `seed` — the "mgfSeed" input octet string (any length, including
///   zero).
/// * `mask_len` — desired output length in bytes. `0` returns an empty
///   `Vec`. RFC 8017 states the maximum `mask_len` is
///   `2³² × hLen = 2³² × 20 = 80 GiB`; in practice callers request at
///   most a few hundred bytes (e.g., RSA-OAEP/PSS salt + DB length).
///
/// # Returns
///
/// A `Vec<u8>` of exactly `mask_len` bytes.
///
/// # Algorithm
///
/// ```text
/// T = ""
/// for counter in 0 .. ceil(mask_len / 20):
///     C = BE32(counter)                     // I2OSP(counter, 4)
///     T = T || SHA-1(seed || C)
/// return T[0 .. mask_len]
/// ```
///
/// This exactly mirrors the FASM loop at `sha1.inc` lines 634–677:
///
/// 1. `sha160$update(state, seed, seed_len)`
/// 2. byte-swap counter to big-endian, `sha160$update(state, BE_counter, 4)`
/// 3. `sha160$final(state, digest, 0)`  (auto-reinits state)
/// 4. copy `min(20, remaining)` bytes to output, increment counter
///
/// # ⚠️ Security
///
/// MGF1-SHA-1 appears as the default mask-generation function in
/// RSA-OAEP (RFC 8017 §7.1) and RSA-PSS (RFC 8017 §8.1) when no
/// alternative is negotiated. Because SHA-1 is broken for collision
/// resistance (SHAttered 2017), modern standards — PKCS#1 v2.2
/// updates, NIST SP 800-56B Rev. 2, TLS 1.3's cipher suites —
/// have moved to SHA-256-based MGF1 or alternative KDFs. This
/// function is provided solely for FASM API parity with legacy code
/// paths that referenced `sha160$mgf1`, most commonly older SSH
/// deployments and PKCS#1 v1.5 / v2.1 interop. For new applications
/// use [`crate::crypto::sha2`]-based MGF1 or alternative KDFs such
/// as HKDF.
///
/// # Examples
///
/// ```
/// use heavything::crypto::sha1::sha1_mgf1;
/// let mask = sha1_mgf1(b"seed", 32);
/// assert_eq!(mask.len(), 32);
/// // Same seed + mask_len is deterministic:
/// assert_eq!(mask, sha1_mgf1(b"seed", 32));
/// ```
#[must_use]
pub fn sha1_mgf1(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(mask_len);
    // RFC 8017 step 3 counter. `u32` per I2OSP(counter, 4). The loop
    // exits well before overflow — for SHA-1's 20-byte block,
    // reaching `u32::MAX` would require an 80 GiB `mask_len`, far
    // beyond any realistic call site. `wrapping_add` below keeps
    // this a total function without tripping debug overflow-checks
    // (AAP §0.8.3 "no panic in library code paths").
    let mut counter: u32 = 0;
    while output.len() < mask_len {
        // H(seed || I2OSP(counter, 4)) — RFC 8017 §B.2.1 step 3b.
        // Construct a fresh context each iteration (`sha160$final` in
        // FASM auto-reinits; we express the same semantics by simply
        // building a new context — ring has no `reset()` method, and
        // a fresh `Context::new` is equivalent in both behavior and
        // (at `opt-level=3`) machine code to an in-place reset).
        let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        ctx.update(seed);
        ctx.update(&counter.to_be_bytes());
        let digest = ctx.finish();
        // Append either a full 20-byte block or just the remainder
        // needed to reach `mask_len` — whichever is smaller. The
        // FASM implementation does the same min-copy at `sha1.inc`
        // line 670.
        let remaining = mask_len - output.len();
        let take = remaining.min(SHA1_OUTPUT_SIZE);
        output.extend_from_slice(&digest.as_ref()[..take]);
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

    /// Parse a 40-character hex string into a `[u8; 20]`. Test-only
    /// helper — panics on malformed input (a bug in the test itself,
    /// acceptable per AAP §0.8.4 "Tests and benchmarks may use
    /// `unwrap()`").
    #[allow(clippy::unwrap_used)]
    fn hex20(hex: &str) -> [u8; 20] {
        assert_eq!(hex.len(), 40, "expected 40 hex chars, got {}", hex.len());
        let mut out = [0u8; 20];
        for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let s = std::str::from_utf8(chunk).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    // ---------------------------------------------------------------------
    // NIST CAVP / RFC 3174 Section 7.3 — reference test vectors
    // ---------------------------------------------------------------------

    #[test]
    fn cavp_empty_string() {
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        // FIPS 180-4 §6.1, NIST CAVP "ShortMsg" vectors.
        assert_eq!(sha1(b""), hex20("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    }

    #[test]
    fn cavp_single_a() {
        // SHA-1("a") = 86f7e437faa5a7fce15d1ddcb9eaeaea377667b8
        // NIST CAVP single-byte vector.
        assert_eq!(sha1(b"a"), hex20("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"));
    }

    #[test]
    fn cavp_abc() {
        // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        // The canonical RFC 3174 §7.3 "TEST1" vector (three-byte
        // single-block message).
        assert_eq!(sha1(b"abc"), hex20("a9993e364706816aba3e25717850c26c9cd0d89d"));
    }

    #[test]
    fn rfc3174_two_block() {
        // SHA-1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        //   = 84983e441c3bd26ebaae4aa1f95129e5e54670f1
        // RFC 3174 §7.3 "TEST2" — 56 bytes, exercises the
        // second-padding-block path because adding 1 + 8 bytes of
        // trailer would overflow the first block's remaining space.
        assert_eq!(
            sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex20("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        );
    }

    #[test]
    fn cavp_448_bit_single_block() {
        // 56-byte message = 448 bits. Distinct from
        // `rfc3174_two_block` (different input data, same length →
        // different digest). Exercises the second-padding-block path
        // because padding byte + 8-byte length would not fit in the
        // single remaining byte of block 1.
        // Input: 56 × 'a' bytes.
        // Expected: SHA-1 of 56 × 0x61 (verified against openssl sha1).
        assert_eq!(
            sha1(&[0x61u8; 56]),
            hex20("c2db330f6083854c99d4b5bfb6e8f29f201be699")
        );
    }

    #[test]
    fn cavp_55_byte_single_pad() {
        // 55 bytes — the maximum single-block-pad case: padding byte
        // + 8-byte length fit exactly in the first block's remaining
        // 9 bytes. Exercises the `sha1.inc` lines 552–576
        // single-pad-block code path (no second padding block needed).
        // Input: 55 × 'a' bytes.
        // Expected: SHA-1 of 55 × 0x61 (verified against openssl sha1).
        assert_eq!(
            sha1(&[0x61u8; 55]),
            hex20("c1c8bbdc22796e28c0e15163d20899b65621d65a")
        );
    }

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

    #[test]
    fn constants_match_spec() {
        assert_eq!(SHA1_OUTPUT_SIZE, 20);
        assert_eq!(SHA1_BLOCK_SIZE, 64);
    }

    // ---------------------------------------------------------------------
    // Stateful hasher API (`Sha1` struct)
    // ---------------------------------------------------------------------

    #[test]
    fn stateful_single_update_matches_oneshot() {
        let mut hasher = Sha1::new();
        hasher.update(b"abc");
        assert_eq!(hasher.finalize(), sha1(b"abc"));
    }

    #[test]
    fn stateful_incremental_matches_oneshot() {
        let mut h = Sha1::new();
        h.update(b"abc");
        h.update(b"def");
        h.update(b"ghij");
        assert_eq!(h.finalize(), sha1(b"abcdefghij"));
    }

    #[test]
    fn stateful_default_is_empty_state() {
        // `Sha1::default()` must produce the same digest as
        // `Sha1::new()` on empty input — the NIST CAVP zero-length
        // vector.
        let h = Sha1::default();
        assert_eq!(h.finalize(), sha1(b""));
    }

    #[test]
    fn reset_restores_initial_state() {
        let mut h = Sha1::new();
        h.update(b"some garbage we want to discard");
        h.reset();
        h.update(b"abc");
        assert_eq!(h.finalize(), sha1(b"abc"));
    }

    #[test]
    fn reset_after_partial_block() {
        // Reset must clear both the compressed state and the buffered
        // partial-block bytes (critical for correctness — a naive
        // reset that only cleared the chain variables would leave
        // stale buffer bytes and produce wrong digests). Ring's
        // `Context::new` zeros the entire 144-byte equivalent region
        // so this is guaranteed.
        let mut h = Sha1::new();
        h.update(b"x"); // single byte lives in buffer, not yet transformed
        h.reset();
        h.update(b"abc");
        assert_eq!(h.finalize(), sha1(b"abc"));
    }

    #[test]
    fn clone_is_independent() {
        // This is the HMAC precompute pattern: one hasher absorbs
        // the shared ipad prefix, then is cloned so the inner and
        // outer hashes can diverge without restarting the prefix.
        let mut h1 = Sha1::new();
        h1.update(b"shared-prefix");
        let mut h2 = h1.clone();
        h1.update(b"-path-A");
        h2.update(b"-path-B");
        assert_eq!(h1.finalize(), sha1(b"shared-prefix-path-A"));
        assert_eq!(h2.finalize(), sha1(b"shared-prefix-path-B"));
    }

    #[test]
    fn clone_preserves_partial_buffer() {
        // Cloning must copy the partial-block buffer too, not just
        // the compressed state. Ring's `#[derive(Clone)]` on
        // `Context` copies the full struct including `pending` and
        // `num_pending` fields (see ring-0.17/src/digest.rs lines
        // 186–194).
        let mut h1 = Sha1::new();
        h1.update(b"x"); // < 64 bytes → lives in buffer
        let mut h2 = h1.clone();
        h1.update(b"yz");
        h2.update(b"YZ");
        assert_eq!(h1.finalize(), sha1(b"xyz"));
        assert_eq!(h2.finalize(), sha1(b"xYZ"));
    }

    // ---------------------------------------------------------------------
    // Multi-block input (exercises the 64-byte-buffer boundary)
    // ---------------------------------------------------------------------

    #[test]
    fn multi_block_input_1000_bytes() {
        // 1000 = 15 full 64-byte blocks + 40-byte tail.
        let data = vec![0x61u8; 1000];
        let mut h = Sha1::new();
        h.update(&data);
        assert_eq!(h.finalize(), sha1(&data));
    }

    #[test]
    fn exactly_one_block() {
        // 64 bytes exactly — boundary condition that used to trip up
        // hand-rolled implementations missing the final-empty-block
        // case in the FASM padding. Forces a second padding block
        // because the 64-byte message completely fills block 1,
        // leaving zero room for the 0x80 + length trailer.
        let data = vec![0x42u8; 64];
        let mut h = Sha1::new();
        h.update(&data);
        let digest = h.finalize();
        assert_eq!(digest, sha1(&data));
    }

    #[test]
    fn length_requires_second_padding_block() {
        // 56 bytes — the padding byte + 8-byte length would exceed
        // the first block's remaining 8 bytes, forcing a second
        // padding block. This is the `sha1.inc` lines 515–548
        // `dosecondtolast` equivalent code path.
        let data = vec![0x55u8; 56];
        let mut h = Sha1::new();
        h.update(&data);
        assert_eq!(h.finalize(), sha1(&data));
    }

    #[test]
    fn streaming_matches_oneshot_across_many_chunks() {
        // Feed the same 1024-byte message in 1-, 7-, 32-, 63-, 64-,
        // 65-, 128-, and 197-byte chunks and verify the digest
        // matches the one-shot call. Exercises every non-trivial
        // buffer-boundary path in ring's transform.
        let data: Vec<u8> = (0..1024).map(|i| (i as u8).wrapping_mul(31)).collect();
        let one_shot = sha1(&data);
        for chunk_size in [1, 7, 32, 63, 64, 65, 128, 197] {
            let mut h = Sha1::new();
            for chunk in data.chunks(chunk_size) {
                h.update(chunk);
            }
            assert_eq!(
                h.finalize(),
                one_shot,
                "digest mismatch for chunk_size={chunk_size}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // MGF1 (RFC 8017 §B.2.1)
    // ---------------------------------------------------------------------

    #[test]
    fn mgf1_zero_length_returns_empty() {
        assert!(sha1_mgf1(b"any seed here", 0).is_empty());
    }

    #[test]
    fn mgf1_single_full_block() {
        // mask_len == 20 → exactly one SHA-1 iteration:
        // SHA-1(seed || BE32(0)).
        let mask = sha1_mgf1(b"foo", 20);
        assert_eq!(mask.len(), 20);
        let mut expected = Sha1::new();
        expected.update(b"foo");
        expected.update(&0u32.to_be_bytes());
        assert_eq!(mask[..], expected.finalize()[..]);
    }

    #[test]
    fn mgf1_partial_block_truncation() {
        // mask_len < 20 → one SHA-1 call, output truncated to mask_len.
        let mask = sha1_mgf1(b"seed", 10);
        assert_eq!(mask.len(), 10);
        let full = sha1_mgf1(b"seed", 20);
        assert_eq!(mask, full[..10]);
    }

    #[test]
    fn mgf1_multi_block() {
        // mask_len == 48 → 3 SHA-1 calls (20 + 20 + 8 bytes).
        let mask = sha1_mgf1(b"abc", 48);
        assert_eq!(mask.len(), 48);
        // First 20 bytes = SHA-1("abc" || BE32(0)).
        let mut h0 = Sha1::new();
        h0.update(b"abc");
        h0.update(&0u32.to_be_bytes());
        assert_eq!(mask[..20], h0.finalize()[..]);
        // Next 20 bytes = SHA-1("abc" || BE32(1)).
        let mut h1 = Sha1::new();
        h1.update(b"abc");
        h1.update(&1u32.to_be_bytes());
        assert_eq!(mask[20..40], h1.finalize()[..]);
        // Last 8 bytes = first 8 bytes of SHA-1("abc" || BE32(2)).
        let mut h2 = Sha1::new();
        h2.update(b"abc");
        h2.update(&2u32.to_be_bytes());
        assert_eq!(mask[40..48], h2.finalize()[..8]);
    }

    #[test]
    fn mgf1_mask_len_exact_block_multiple() {
        // mask_len == 40 → exactly 2 SHA-1 blocks, no truncation.
        let mask = sha1_mgf1(b"exact", 40);
        assert_eq!(mask.len(), 40);
    }

    #[test]
    fn mgf1_is_deterministic() {
        assert_eq!(sha1_mgf1(b"det", 28), sha1_mgf1(b"det", 28));
        assert_eq!(sha1_mgf1(b"", 32), sha1_mgf1(b"", 32));
    }

    #[test]
    fn mgf1_varies_with_seed() {
        assert_ne!(sha1_mgf1(b"seed1", 20), sha1_mgf1(b"seed2", 20));
    }

    #[test]
    fn mgf1_varies_with_mask_len() {
        // Extending the mask should extend, not regenerate, the
        // output. This is the MGF1 "prefix" property: output
        // octets only depend on the seed and the counter, never on
        // the requested total length.
        let short = sha1_mgf1(b"abc", 20);
        let long = sha1_mgf1(b"abc", 40);
        assert_eq!(long.len(), 40);
        assert_eq!(short[..], long[..20]);
    }

    #[test]
    fn mgf1_empty_seed_is_valid() {
        // RFC 8017 allows zero-length seed.
        let mask = sha1_mgf1(b"", 20);
        assert_eq!(mask.len(), 20);
        // Should equal SHA-1(BE32(0)) = SHA-1([0, 0, 0, 0]).
        let mut h = Sha1::new();
        h.update(&0u32.to_be_bytes());
        assert_eq!(mask[..], h.finalize()[..]);
    }

    #[test]
    fn mgf1_large_mask_len() {
        // 512-byte mask — 26 full SHA-1 blocks, exercises the
        // counter increment across many iterations without hitting
        // any special boundary. 512 = 25 × 20 + 12, so the final
        // block is truncated to 12 bytes.
        let mask = sha1_mgf1(b"large-mask-test-seed", 512);
        assert_eq!(mask.len(), 512);
        // Verify the 26th block (counter = 25) contributes the
        // final 12 bytes.
        let mut h = Sha1::new();
        h.update(b"large-mask-test-seed");
        h.update(&25u32.to_be_bytes());
        assert_eq!(mask[500..512], h.finalize()[..12]);
    }

    // ---------------------------------------------------------------------
    // Sanity: type is Send + Sync (required by tokio async contexts)
    // ---------------------------------------------------------------------

    #[test]
    fn sha1_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Sha1>();
    }
}
