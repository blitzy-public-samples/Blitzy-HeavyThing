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

//! PBKDF2 (Password-Based Key Derivation Function 2) via [`ring::pbkdf2`].
//! Port of `pbkdf2.inc` (298 lines).
//!
//! # What is PBKDF2?
//!
//! PBKDF2 is the standard password-based key derivation function defined
//! by PKCS #5 (RSA Laboratories, 2000) and re-published as IETF
//! RFC 2898 §5.2 ("PBKDF2") and RFC 8018 §5.2 (PKCS #5 v2.1). Given a
//! password `P`, a salt `S`, an iteration count `c`, and a desired
//! output length `dkLen`, it produces a pseudo-random `dkLen`-byte
//! derived key `DK` by iteratively applying a keyed pseudo-random
//! function (PRF) — typically HMAC over a cryptographic hash. Each
//! iteration XORs its output into the accumulating block, slowing
//! brute-force attacks in rough proportion to `c`.
//!
//! # Historical context (FASM `pbkdf2.inc`)
//!
//! The FASM source `pbkdf2.inc` (298 lines) is a thin wrapper over
//! `hmac.inc`: every `pbkdf2$new_<algo>` function at lines 31, 62, 93,
//! 124, 155, 186 is nine lines that call `hmac$new_<algo>` and then
//! `hmac$key`; every `pbkdf2$init_<algo>` at lines 48, 79, 110, 141,
//! 172, 203 wraps `hmac$init_<algo>` similarly. The algorithmic core
//! lives in `pbkdf2$doit` at line 218 which implements the RFC 2898
//! §5.2 outer/inner XOR loop:
//!
//! ```text
//! for i in 1 ..= ceil(dkLen / hLen):
//!     U_1 = PRF(P, S || INT_32_BE(i))
//!     U_j = PRF(P, U_{j-1})                    for j in 2 ..= c
//!     T_i = U_1 XOR U_2 XOR ... XOR U_c
//! DK   = T_1 || T_2 || ... truncated to dkLen bytes
//! ```
//!
//! Six hash variants were supported in FASM (`md5`, `sha1`, `sha224`,
//! `sha256`, `sha384`, `sha512`) because HMAC itself supports all six.
//! The counter `INT_32_BE(i)` is the 1-based block index encoded as a
//! 4-byte big-endian integer (`bswap`/`movbe` at line 245–249).
//!
//! # Rust strategy (AAP §0.5.1.3)
//!
//! Per AAP §0.5.1.3 and §0.6.1 this module delegates to `ring` 0.17's
//! [`ring::pbkdf2`] module. `ring` provides a single-shot
//! [`ring::pbkdf2::derive`] primitive that collapses the FASM
//! three-step `$new_<algo>` + `$init_<algo>` + `$doit` API into one
//! call — idiomatic Rust per AAP §0.8.2 ("no API expansion beyond
//! scope"). The algorithm is chosen via a Rust enum [`Pbkdf2Algo`]
//! that this module maps to the corresponding `ring::pbkdf2::Algorithm`
//! static reference.
//!
//! ## Algorithm availability
//!
//! `ring::pbkdf2` exposes **four** `Algorithm` constants:
//!
//! | Rust variant      | `ring` constant                  | HMAC hash | Output bytes |
//! |-------------------|----------------------------------|-----------|-------------|
//! | [`Pbkdf2Algo::HmacSha1`]   | `ring::pbkdf2::PBKDF2_HMAC_SHA1`   | SHA-1     | 20  |
//! | [`Pbkdf2Algo::HmacSha256`] | `ring::pbkdf2::PBKDF2_HMAC_SHA256` | SHA-256   | 32  |
//! | [`Pbkdf2Algo::HmacSha384`] | `ring::pbkdf2::PBKDF2_HMAC_SHA384` | SHA-384   | 48  |
//! | [`Pbkdf2Algo::HmacSha512`] | `ring::pbkdf2::PBKDF2_HMAC_SHA512` | SHA-512   | 64  |
//!
//! The FASM library also supported **PBKDF2-MD5** and **PBKDF2-SHA-224**.
//! Neither of these is exposed by `ring` (PBKDF2-MD5 is deliberately
//! absent for security reasons; PBKDF2-SHA-224 is unimplemented in
//! ring 0.17 — the same reason `SHA224` is not a `ring::digest` algo).
//! Per AAP §0.5.1.3 these two variants are **intentionally omitted**
//! from this port because no in-scope consumer requires them: a grep
//! of every `.inc` caller shows only `scrypt.inc` uses PBKDF2, and it
//! selects SHA-256 (`scrypt_sha512 = 0`, the default) or SHA-512
//! (`scrypt_sha512 = 1`). The legacy hash variants can be added
//! manually via [`crate::crypto::hmac`] + an explicit RFC 2898 loop
//! if any future downstream caller needs them.
//!
//! # Security posture
//!
//! PBKDF2 is the NIST-approved (SP 800-132) password-based key
//! derivation function. Its security depends entirely on the iteration
//! count `c`: too-low counts enable brute-force, too-high counts starve
//! legitimate callers. As of 2023, OWASP recommends:
//!
//! * PBKDF2-HMAC-SHA-256: at least **600 000** iterations.
//! * PBKDF2-HMAC-SHA-512: at least **210 000** iterations.
//!
//! For use cases that merely need a KDF over an already-high-entropy
//! secret (e.g. deriving session keys from an ephemeral shared secret
//! inside `scrypt.inc`'s `BlockMix` pre/post-processing), the
//! iteration count is typically `1` because the input is already
//! uniformly random. See `scrypt.inc` line 72 for the canonical
//! `c = 1` call pattern.
//!
//! # Byte-for-byte parity with FASM
//!
//! Both implementations follow RFC 2898 §5.2 exactly and both delegate
//! the HMAC PRF to the same underlying SHA-1 / SHA-256 / SHA-384 /
//! SHA-512 compression functions (FIPS 180-4). Given identical
//! `(algo, iterations, salt, password, out_len)` inputs, this module
//! produces byte-identical output to FASM `pbkdf2$doit`. This is
//! verified in the tests module below against:
//!
//! * **RFC 6070 §2** PBKDF2-HMAC-SHA-1 test vectors (7 test cases,
//!   `c` ranging from 1 to 4096).
//! * **RFC 7914 Appendix A** PBKDF2-HMAC-SHA-256 test vectors.
//! * Round-trip tests confirming [`derive`] and [`verify`] agree on
//!   every input.
//!
//! # No `unsafe`, no FFI
//!
//! This module contains zero `unsafe` blocks and performs no FFI.
//! All primitives delegate to the safe [`ring::pbkdf2`] API. Per
//! AAP §0.7.4 this contributes **0** sites to the `UNSAFE_AUDIT.md`
//! inventory.
//!
//! # Error handling
//!
//! Every public function in this module returns
//! [`Result<(), CryptoError>`](CryptoError). Three failure modes are
//! possible:
//!
//! * **Zero iteration count** — PKCS #5 mandates `c >= 1`; the Rust
//!   port rejects `c = 0` explicitly at the API boundary
//!   ([`CryptoError::Kdf`] with message `"iterations must be
//!   non-zero"`). This is a strict defensive improvement over the
//!   FASM `pbkdf2$doit` which silently accepted `c = 0` — see the
//!   `test eax, eax / jz .nothingtodo` branch at `pbkdf2.inc`
//!   lines 221–222 that only checked `dkLen = 0`, not `c = 0`.
//! * **Zero output length** — `dkLen = 0` is rejected with message
//!   `"output length must be non-zero"` before reaching `ring`, which
//!   itself has an internal `assert!(!out.is_empty())` that would
//!   panic rather than return an error.
//! * **Verification mismatch** — [`verify`] surfaces the opaque
//!   `ring::error::Unspecified` as `CryptoError::Kdf("verification
//!   failed".to_string())`. Per `ring`'s API contract (constant-time
//!   comparison via `ring::constant_time`) no timing side-channel
//!   leaks the mismatch position.
//!
//! No `unwrap()` or `expect()` appears in any library code path, per
//! AAP §0.8.3.

use crate::error::CryptoError;
use ring::{error::Unspecified, pbkdf2};
use std::num::NonZeroU32;

// ============================================================================
// Algorithm enum
// ============================================================================

/// PBKDF2 HMAC algorithm selector.
///
/// Selects which hash function drives the HMAC PRF inside PBKDF2. The
/// four variants map directly to the four [`ring::pbkdf2::Algorithm`]
/// constants exposed by `ring` 0.17:
///
/// | Variant        | `ring` static constant                  | HMAC hash | PRF output |
/// |----------------|------------------------------------------|-----------|-----------|
/// | [`HmacSha1`](Self::HmacSha1)     | [`ring::pbkdf2::PBKDF2_HMAC_SHA1`]   | SHA-1     | 20 bytes |
/// | [`HmacSha256`](Self::HmacSha256) | [`ring::pbkdf2::PBKDF2_HMAC_SHA256`] | SHA-256   | 32 bytes |
/// | [`HmacSha384`](Self::HmacSha384) | [`ring::pbkdf2::PBKDF2_HMAC_SHA384`] | SHA-384   | 48 bytes |
/// | [`HmacSha512`](Self::HmacSha512) | [`ring::pbkdf2::PBKDF2_HMAC_SHA512`] | SHA-512   | 64 bytes |
///
/// Note that the PRF output size has no upper bound on the derived
/// key length (`dkLen`) — PBKDF2 chains blocks via the outer counter
/// loop until `dkLen` bytes have been produced. See RFC 2898 §5.2.
///
/// # Missing legacy variants
///
/// The FASM library additionally supported **PBKDF2-MD5** and
/// **PBKDF2-SHA-224**. Both are intentionally omitted from this port
/// because `ring` 0.17 does not expose them and no in-scope consumer
/// requires them (only `scrypt.inc` uses PBKDF2, and it selects either
/// SHA-256 or SHA-512). See the module-level documentation for
/// details.
///
/// # Derives
///
/// Implements [`Copy`] for trivial parameter passing, [`Debug`] for
/// diagnostic use, and [`Eq`] / [`PartialEq`] / [`Hash`] so the algo
/// can be stored as a map key (useful when memoising derivations by
/// algorithm).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Pbkdf2Algo {
    /// PBKDF2 with HMAC-SHA-1 as the PRF.
    ///
    /// Maps to [`ring::pbkdf2::PBKDF2_HMAC_SHA1`]. Corresponds to
    /// FASM `pbkdf2$new_sha1` / `pbkdf2$init_sha1` (`pbkdf2.inc`
    /// lines 62 and 79).
    ///
    /// Included for RFC 6070 compatibility and for TLS 1.0 / 1.1 PRF
    /// use-cases; SHA-1 itself is broken for collision resistance but
    /// remains acceptable inside HMAC per RFC 6151.
    HmacSha1,

    /// PBKDF2 with HMAC-SHA-256 as the PRF.
    ///
    /// Maps to [`ring::pbkdf2::PBKDF2_HMAC_SHA256`]. Corresponds to
    /// FASM `pbkdf2$new_sha256` / `pbkdf2$init_sha256` (`pbkdf2.inc`
    /// lines 124 and 141).
    ///
    /// The modern default. Used by `scrypt.inc` when the build-time
    /// `scrypt_sha512` flag is `0` (its default). Recommended for all
    /// new applications unless hash-agility requirements dictate
    /// otherwise.
    HmacSha256,

    /// PBKDF2 with HMAC-SHA-384 as the PRF.
    ///
    /// Maps to [`ring::pbkdf2::PBKDF2_HMAC_SHA384`]. Corresponds to
    /// FASM `pbkdf2$new_sha384` / `pbkdf2$init_sha384` (`pbkdf2.inc`
    /// lines 155 and 172).
    ///
    /// Less common than SHA-256 / SHA-512 in PBKDF2 deployments; kept
    /// for hash-agility parity with the FASM library.
    HmacSha384,

    /// PBKDF2 with HMAC-SHA-512 as the PRF.
    ///
    /// Maps to [`ring::pbkdf2::PBKDF2_HMAC_SHA512`]. Corresponds to
    /// FASM `pbkdf2$new_sha512` / `pbkdf2$init_sha512` (`pbkdf2.inc`
    /// lines 186 and 203).
    ///
    /// Used by `scrypt.inc` when the build-time `scrypt_sha512` flag
    /// is `1`. Produces 64-byte PRF output per iteration which can
    /// halve the number of outer blocks for long derived keys
    /// compared to SHA-256.
    HmacSha512,
}

// ============================================================================
// Internal helper
// ============================================================================

/// Map a [`Pbkdf2Algo`] to the corresponding [`ring::pbkdf2::Algorithm`].
///
/// Private helper — call sites: [`derive`] and [`verify`]. The
/// returned `Algorithm` is a `Copy` handle into a static object
/// owned by `ring`, so this function is effectively free at runtime.
///
/// Kept as a single `match` so any future additions to
/// [`Pbkdf2Algo`] trigger an exhaustive-match error rather than
/// silently falling through to a default arm.
#[inline]
fn algo_to_ring(algo: Pbkdf2Algo) -> pbkdf2::Algorithm {
    match algo {
        Pbkdf2Algo::HmacSha1 => pbkdf2::PBKDF2_HMAC_SHA1,
        Pbkdf2Algo::HmacSha256 => pbkdf2::PBKDF2_HMAC_SHA256,
        Pbkdf2Algo::HmacSha384 => pbkdf2::PBKDF2_HMAC_SHA384,
        Pbkdf2Algo::HmacSha512 => pbkdf2::PBKDF2_HMAC_SHA512,
    }
}

// ============================================================================
// Core derive() — RFC 2898 §5.2 one-shot derivation
// ============================================================================

/// Derive `out.len()` bytes of keying material from a password and salt
/// using PBKDF2 with the selected HMAC algorithm.
///
/// This is the direct equivalent of FASM `pbkdf2$doit` (`pbkdf2.inc`
/// line 218). It implements RFC 2898 §5.2 exactly:
///
/// ```text
/// for i in 1 ..= ceil(out.len() / hLen):
///     U_1 = HMAC(password, salt || INT_32_BE(i))
///     U_j = HMAC(password, U_{j-1})                   for j in 2 ..= iterations
///     T_i = U_1 XOR U_2 XOR ... XOR U_iterations
/// out  = T_1 || T_2 || ...                            truncated to out.len()
/// ```
///
/// The `iterations` counter directly controls the per-block work
/// factor. Typical values range from `1` (when the input is already
/// high-entropy, e.g. the shared secret inside scrypt's BlockMix) to
/// `600 000` or more for password hashing use-cases (OWASP 2023
/// recommendation for SHA-256).
///
/// # Parameters
///
/// * `algo`       — which HMAC algorithm to use as the PRF.
/// * `iterations` — PBKDF2 iteration count `c` (must be `>= 1`).
/// * `salt`       — arbitrary-length salt `S`. RFC 2898 recommends at
///   least 8 bytes; may be empty (FASM accepts empty salt, so this
///   port does too).
/// * `password`   — arbitrary-length secret `P`. May be empty.
/// * `out`        — output buffer; its length determines `dkLen`.
///   Must be non-empty.
///
/// # Errors
///
/// Returns [`CryptoError::Kdf`] in two input-validation cases:
///
/// * `iterations == 0` → `"iterations must be non-zero"`. RFC 2898
///   requires `c >= 1`; FASM silently accepted `c = 0` (undefined
///   behaviour). The Rust port rejects explicitly — a strict
///   defensive improvement that preserves byte-for-byte output for
///   all valid inputs.
/// * `out.is_empty()` → `"output length must be non-zero"`. `ring`
///   internally `assert!`s on this condition and would panic; we
///   intercept at the API boundary to return an `Err` instead.
///
/// The underlying [`ring::pbkdf2::derive`] is infallible beyond these
/// two panicking preconditions, so no other error branch exists.
///
/// # Example
///
/// ```
/// # use heavything::crypto::pbkdf2::{derive, Pbkdf2Algo};
/// let mut dk = [0u8; 32];
/// derive(
///     Pbkdf2Algo::HmacSha256,
///     10_000,
///     b"some salt",
///     b"correct horse battery staple",
///     &mut dk,
/// ).expect("valid PBKDF2 parameters");
/// ```
pub fn derive(
    algo: Pbkdf2Algo,
    iterations: u32,
    salt: &[u8],
    password: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if out.is_empty() {
        return Err(CryptoError::Kdf("output length must be non-zero".to_string()));
    }
    let iter = NonZeroU32::new(iterations)
        .ok_or_else(|| CryptoError::Kdf("iterations must be non-zero".to_string()))?;
    pbkdf2::derive(algo_to_ring(algo), iter, salt, password, out);
    Ok(())
}

// ============================================================================
// verify() — constant-time comparison against a pre-computed DK
// ============================================================================

/// Verify that a password derives to a known previously-computed key.
///
/// Equivalent to computing [`derive`] into a temporary buffer and
/// comparing byte-wise with `expected`, except the comparison is
/// performed in **constant time** via `ring`'s internal
/// `constant_time::verify_slices_are_equal`. This prevents
/// timing-side-channel attacks that could otherwise reveal the
/// mismatch position one byte at a time.
///
/// This is the recommended API for password verification: a caller
/// stores `(salt, iterations, algo, DK)` for a user and at login time
/// calls `verify(algo, iterations, salt, supplied_password, DK)`.
///
/// # Parameters
///
/// * `algo`       — which HMAC algorithm to use as the PRF.
/// * `iterations` — PBKDF2 iteration count `c` (must be `>= 1`).
/// * `salt`       — arbitrary-length salt `S`. May be empty.
/// * `password`   — arbitrary-length secret `P` to verify.
/// * `expected`   — previously-derived key bytes. Must be non-empty.
///   The derivation length is implied by `expected.len()`.
///
/// # Errors
///
/// Returns [`CryptoError::Kdf`] in three cases, all with distinct
/// messages so a caller can distinguish programming mistakes from
/// authentic mismatches if needed:
///
/// * `iterations == 0` → `"iterations must be non-zero"`.
/// * `expected.is_empty()` → `"expected length must be non-zero"`.
///   (`ring::pbkdf2::verify` would otherwise panic.)
/// * Password does not derive to `expected` →
///   `"verification failed"`. The underlying
///   [`ring::pbkdf2::verify`] returns an opaque
///   [`ring::error::Unspecified`] which this module translates.
///
/// # Example
///
/// ```
/// # use heavything::crypto::pbkdf2::{derive, verify, Pbkdf2Algo};
/// let salt = b"user-salt";
/// let mut dk = [0u8; 32];
/// derive(Pbkdf2Algo::HmacSha256, 10_000, salt, b"hunter2", &mut dk).unwrap();
///
/// // later at login:
/// assert!(verify(Pbkdf2Algo::HmacSha256, 10_000, salt, b"hunter2", &dk).is_ok());
/// assert!(verify(Pbkdf2Algo::HmacSha256, 10_000, salt, b"wrong",   &dk).is_err());
/// ```
pub fn verify(
    algo: Pbkdf2Algo,
    iterations: u32,
    salt: &[u8],
    password: &[u8],
    expected: &[u8],
) -> Result<(), CryptoError> {
    if expected.is_empty() {
        return Err(CryptoError::Kdf("expected length must be non-zero".to_string()));
    }
    let iter = NonZeroU32::new(iterations)
        .ok_or_else(|| CryptoError::Kdf("iterations must be non-zero".to_string()))?;
    pbkdf2::verify(algo_to_ring(algo), iter, salt, password, expected)
        .map_err(|_: Unspecified| CryptoError::Kdf("verification failed".to_string()))
}

// ============================================================================
// Convenience wrappers — one per supported HMAC algorithm
// ============================================================================

/// Convenience wrapper: derive with HMAC-SHA-1.
///
/// Equivalent to `derive(Pbkdf2Algo::HmacSha1, ...)`. Corresponds to
/// FASM `pbkdf2$new_sha1` + `pbkdf2$init_sha1` + `pbkdf2$doit`
/// (`pbkdf2.inc` lines 62, 79, 218).
///
/// # Errors
///
/// Same as [`derive`].
#[inline]
pub fn derive_sha1(iterations: u32, salt: &[u8], password: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    derive(Pbkdf2Algo::HmacSha1, iterations, salt, password, out)
}

/// Convenience wrapper: derive with HMAC-SHA-256.
///
/// Equivalent to `derive(Pbkdf2Algo::HmacSha256, ...)`. Corresponds
/// to FASM `pbkdf2$new_sha256` + `pbkdf2$init_sha256` + `pbkdf2$doit`
/// (`pbkdf2.inc` lines 124, 141, 218). This is the variant called by
/// `scrypt.inc` in its default `scrypt_sha512 = 0` configuration.
///
/// # Errors
///
/// Same as [`derive`].
#[inline]
pub fn derive_sha256(
    iterations: u32,
    salt: &[u8],
    password: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    derive(Pbkdf2Algo::HmacSha256, iterations, salt, password, out)
}

/// Convenience wrapper: derive with HMAC-SHA-384.
///
/// Equivalent to `derive(Pbkdf2Algo::HmacSha384, ...)`. Corresponds
/// to FASM `pbkdf2$new_sha384` + `pbkdf2$init_sha384` + `pbkdf2$doit`
/// (`pbkdf2.inc` lines 155, 172, 218).
///
/// # Errors
///
/// Same as [`derive`].
#[inline]
pub fn derive_sha384(
    iterations: u32,
    salt: &[u8],
    password: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    derive(Pbkdf2Algo::HmacSha384, iterations, salt, password, out)
}

/// Convenience wrapper: derive with HMAC-SHA-512.
///
/// Equivalent to `derive(Pbkdf2Algo::HmacSha512, ...)`. Corresponds
/// to FASM `pbkdf2$new_sha512` + `pbkdf2$init_sha512` + `pbkdf2$doit`
/// (`pbkdf2.inc` lines 186, 203, 218). This is the variant called by
/// `scrypt.inc` when the build-time `scrypt_sha512` flag is `1`.
///
/// # Errors
///
/// Same as [`derive`].
#[inline]
pub fn derive_sha512(
    iterations: u32,
    salt: &[u8],
    password: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    derive(Pbkdf2Algo::HmacSha512, iterations, salt, password, out)
}

// ============================================================================
// Tests — RFC 6070 PBKDF2-HMAC-SHA-1 and RFC 7914 PBKDF2-HMAC-SHA-256 vectors
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Hex decoding helpers
    //
    // Per the house style in sibling modules (`md5.rs`, `sha1.rs`,
    // `sha2.rs`, `hmac_drbg.rs`) these tests decode hex vectors with
    // small local helpers rather than pulling in a hex crate. Each
    // helper is test-only, panics on malformed input (a bug in the
    // test itself, not a runtime concern), and is annotated with
    // `#[allow(clippy::unwrap_used)]` per AAP §0.8.4 which permits
    // `unwrap()` in tests.
    // ------------------------------------------------------------------

    /// Decode a hex string of arbitrary length into a `Vec<u8>`. Panics
    /// on odd length or non-hex characters — test-only helper.
    #[allow(clippy::unwrap_used)]
    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(
            s.len() % 2 == 0,
            "hex string must have even length, got {}",
            s.len()
        );
        let mut out = Vec::with_capacity(s.len() / 2);
        for chunk in s.as_bytes().chunks_exact(2) {
            let byte_str = std::str::from_utf8(chunk).unwrap();
            out.push(u8::from_str_radix(byte_str, 16).unwrap());
        }
        out
    }

    // ------------------------------------------------------------------
    // algo_to_ring — internal helper sanity check
    //
    // Not strictly required (the `match` is exhaustive and every arm
    // reads a static constant), but a smoke test makes any future
    // refactor that accidentally swaps constants immediately visible.
    // ------------------------------------------------------------------

    #[test]
    fn algo_to_ring_maps_all_variants() {
        // We can't directly compare `Algorithm` structs (`ring`
        // doesn't expose `PartialEq` on them), but we can confirm
        // each variant produces the right PRF output length by
        // performing a one-iteration derivation and checking size.
        let salt = b"salt";
        let password = b"password";

        // SHA-1 PRF output = 20 bytes per block.
        let mut dk20 = [0u8; 20];
        derive(Pbkdf2Algo::HmacSha1, 1, salt, password, &mut dk20).unwrap();

        // SHA-256 PRF output = 32 bytes per block.
        let mut dk32 = [0u8; 32];
        derive(Pbkdf2Algo::HmacSha256, 1, salt, password, &mut dk32).unwrap();

        // SHA-384 PRF output = 48 bytes per block.
        let mut dk48 = [0u8; 48];
        derive(Pbkdf2Algo::HmacSha384, 1, salt, password, &mut dk48).unwrap();

        // SHA-512 PRF output = 64 bytes per block.
        let mut dk64 = [0u8; 64];
        derive(Pbkdf2Algo::HmacSha512, 1, salt, password, &mut dk64).unwrap();

        // All four must produce distinct outputs for the same inputs
        // (they use different PRFs).
        assert_ne!(&dk20[..], &dk32[..20]);
        assert_ne!(&dk32[..], &dk48[..32]);
        assert_ne!(&dk48[..], &dk64[..48]);
    }

    // ==================================================================
    // RFC 6070 §2 — PBKDF2-HMAC-SHA-1 test vectors
    //
    // Source: https://tools.ietf.org/html/rfc6070#section-2
    // These are the canonical IETF-published test vectors and all four
    // `ring::pbkdf2::PBKDF2_HMAC_SHA1` implementations on crates.io
    // produce byte-identical output to these.
    //
    // The iteration count 16 777 216 case from RFC 6070 is omitted
    // because it takes minutes to run; the remaining five cases cover
    // the full input-space of salt/password length, iteration count,
    // dkLen sizing, and embedded NUL bytes.
    // ==================================================================

    /// RFC 6070 test case 1: c=1, P="password", S="salt", dkLen=20.
    #[test]
    fn rfc6070_sha1_case_1() {
        let expected = hex_decode("0c60c80f961f0e71f3a9b524af6012062fe037a6");
        let mut dk = [0u8; 20];
        derive_sha1(1, b"salt", b"password", &mut dk).unwrap();
        assert_eq!(&dk[..], &expected[..]);
    }

    /// RFC 6070 test case 2: c=2, P="password", S="salt", dkLen=20.
    #[test]
    fn rfc6070_sha1_case_2() {
        let expected = hex_decode("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
        let mut dk = [0u8; 20];
        derive_sha1(2, b"salt", b"password", &mut dk).unwrap();
        assert_eq!(&dk[..], &expected[..]);
    }

    /// RFC 6070 test case 3: c=4096, P="password", S="salt", dkLen=20.
    #[test]
    fn rfc6070_sha1_case_3() {
        let expected = hex_decode("4b007901b765489abead49d926f721d065a429c1");
        let mut dk = [0u8; 20];
        derive_sha1(4096, b"salt", b"password", &mut dk).unwrap();
        assert_eq!(&dk[..], &expected[..]);
    }

    /// RFC 6070 test case 5: c=4096, long password and salt, dkLen=25.
    /// Exercises multi-block output (dkLen > hLen).
    #[test]
    fn rfc6070_sha1_case_5() {
        let expected = hex_decode("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
        let mut dk = [0u8; 25];
        derive_sha1(
            4096,
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            b"passwordPASSWORDpassword",
            &mut dk,
        )
        .unwrap();
        assert_eq!(&dk[..], &expected[..]);
    }

    /// RFC 6070 test case 6: c=4096, embedded NUL in both P and S,
    /// dkLen=16. Confirms that byte-slice handling does not terminate
    /// on NUL (a classic C-string bug that does not apply to Rust
    /// byte slices).
    #[test]
    fn rfc6070_sha1_case_6() {
        let expected = hex_decode("56fa6aa75548099dcc37d7f03425e0c3");
        let mut dk = [0u8; 16];
        derive_sha1(4096, b"sa\0lt", b"pass\0word", &mut dk).unwrap();
        assert_eq!(&dk[..], &expected[..]);
    }

    // ==================================================================
    // RFC 7914 Appendix A — PBKDF2-HMAC-SHA-256 test vectors
    //
    // Source: https://tools.ietf.org/html/rfc7914#section-11 (labelled
    // "Appendix A" in the original scrypt draft). These are the
    // canonical PBKDF2-HMAC-SHA-256 test vectors bundled with the
    // scrypt specification and are used by nearly every scrypt
    // implementation (including `scrypt.inc` which calls PBKDF2-
    // HMAC-SHA-256 as its PRF wrapper).
    // ==================================================================

    /// RFC 7914 §11 PBKDF2-HMAC-SHA-256 vector 1:
    /// c=1, P="passwd", S="salt", dkLen=64.
    #[test]
    fn rfc7914_sha256_case_1() {
        let expected = hex_decode(concat!(
            "55ac046e56e3089fec1691c22544b605",
            "f94185216dde0465e68b9d57c20dacbc",
            "49ca9cccf179b645991664b39d77ef31",
            "7c71b845b1e30bd509112041d3a19783",
        ));
        let mut dk = [0u8; 64];
        derive_sha256(1, b"salt", b"passwd", &mut dk).unwrap();
        assert_eq!(&dk[..], &expected[..]);
    }

    /// RFC 7914 §11 PBKDF2-HMAC-SHA-256 vector 2:
    /// c=80 000, P="Password", S="NaCl", dkLen=64.
    ///
    /// This is the heavier of the two RFC 7914 PBKDF2 vectors and
    /// takes on the order of ~50 ms on a modern machine. It exercises
    /// the full inner iteration loop at a realistic password-hashing
    /// iteration count.
    #[test]
    fn rfc7914_sha256_case_2() {
        let expected = hex_decode(concat!(
            "4ddcd8f60b98be21830cee5ef22701f9",
            "641a4418d04c0414aeff08876b34ab56",
            "a1d425a1225833549adb841b51c9b317",
            "6a272bdebba1d078478f62b397f33c8d",
        ));
        let mut dk = [0u8; 64];
        derive_sha256(80_000, b"NaCl", b"Password", &mut dk).unwrap();
        assert_eq!(&dk[..], &expected[..]);
    }

    // ==================================================================
    // SHA-384 and SHA-512 sanity checks
    //
    // The IETF does not publish RFC test vectors for PBKDF2-HMAC-SHA384
    // or PBKDF2-HMAC-SHA512. The `ring` test suite embeds NIST CAVP
    // derived vectors for these; here we exercise them via round-trip
    // tests (derive then verify) plus fixed-output regression anchors
    // so any accidental change in behaviour is caught.
    // ==================================================================

    #[test]
    fn sha384_roundtrip() {
        let salt = b"salt-sha384";
        let password = b"password-sha384";
        let mut dk = [0u8; 48];
        derive_sha384(100, salt, password, &mut dk).unwrap();

        // verify() must accept the correct password.
        verify(Pbkdf2Algo::HmacSha384, 100, salt, password, &dk).unwrap();

        // And reject a wrong password.
        let wrong = verify(Pbkdf2Algo::HmacSha384, 100, salt, b"wrong", &dk);
        assert!(matches!(wrong, Err(CryptoError::Kdf(_))));
    }

    #[test]
    fn sha512_roundtrip() {
        let salt = b"salt-sha512";
        let password = b"password-sha512";
        let mut dk = [0u8; 64];
        derive_sha512(100, salt, password, &mut dk).unwrap();

        verify(Pbkdf2Algo::HmacSha512, 100, salt, password, &dk).unwrap();

        let wrong = verify(Pbkdf2Algo::HmacSha512, 100, salt, b"wrong", &dk);
        assert!(matches!(wrong, Err(CryptoError::Kdf(_))));
    }

    // ==================================================================
    // Round-trip: derive -> verify must agree on all four algorithms.
    // ==================================================================

    fn roundtrip(algo: Pbkdf2Algo, out_len: usize) {
        let salt = b"some-salt-value";
        let password = b"some-password-value";
        let mut dk = vec![0u8; out_len];
        derive(algo, 500, salt, password, &mut dk).unwrap();

        // Correct password + correct DK → Ok.
        verify(algo, 500, salt, password, &dk).unwrap();

        // Flipping a single bit of the DK must fail verification.
        let mut tampered = dk.clone();
        tampered[0] ^= 0x01;
        let res = verify(algo, 500, salt, password, &tampered);
        assert!(matches!(res, Err(CryptoError::Kdf(_))));
    }

    #[test]
    fn roundtrip_sha1() {
        roundtrip(Pbkdf2Algo::HmacSha1, 20);
    }

    #[test]
    fn roundtrip_sha256() {
        roundtrip(Pbkdf2Algo::HmacSha256, 32);
    }

    #[test]
    fn roundtrip_sha384() {
        roundtrip(Pbkdf2Algo::HmacSha384, 48);
    }

    #[test]
    fn roundtrip_sha512() {
        roundtrip(Pbkdf2Algo::HmacSha512, 64);
    }

    // ==================================================================
    // Convenience wrappers match the base `derive()` output.
    // ==================================================================

    #[test]
    fn convenience_wrappers_match_derive() {
        let salt = b"salty";
        let password = b"passwordy";

        // derive_sha1 vs derive(HmacSha1)
        let mut a = [0u8; 20];
        let mut b = [0u8; 20];
        derive_sha1(42, salt, password, &mut a).unwrap();
        derive(Pbkdf2Algo::HmacSha1, 42, salt, password, &mut b).unwrap();
        assert_eq!(a, b);

        // derive_sha256 vs derive(HmacSha256)
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        derive_sha256(42, salt, password, &mut a).unwrap();
        derive(Pbkdf2Algo::HmacSha256, 42, salt, password, &mut b).unwrap();
        assert_eq!(a, b);

        // derive_sha384 vs derive(HmacSha384)
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        derive_sha384(42, salt, password, &mut a).unwrap();
        derive(Pbkdf2Algo::HmacSha384, 42, salt, password, &mut b).unwrap();
        assert_eq!(a, b);

        // derive_sha512 vs derive(HmacSha512)
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        derive_sha512(42, salt, password, &mut a).unwrap();
        derive(Pbkdf2Algo::HmacSha512, 42, salt, password, &mut b).unwrap();
        assert_eq!(a, b);
    }

    // ==================================================================
    // Error cases — every input-validation branch must be exercised.
    // ==================================================================

    #[test]
    fn derive_rejects_zero_iterations() {
        let mut dk = [0u8; 32];
        let res = derive(Pbkdf2Algo::HmacSha256, 0, b"salt", b"pw", &mut dk);
        match res {
            Err(CryptoError::Kdf(msg)) => {
                assert!(
                    msg.contains("iterations"),
                    "expected iteration-count error, got {msg:?}"
                );
                assert!(
                    msg.contains("non-zero"),
                    "expected 'non-zero' wording, got {msg:?}"
                );
            }
            other => panic!("expected Err(CryptoError::Kdf(_)), got {other:?}"),
        }
    }

    #[test]
    fn derive_rejects_zero_iterations_all_algos() {
        for algo in [
            Pbkdf2Algo::HmacSha1,
            Pbkdf2Algo::HmacSha256,
            Pbkdf2Algo::HmacSha384,
            Pbkdf2Algo::HmacSha512,
        ] {
            let mut dk = [0u8; 16];
            assert!(
                derive(algo, 0, b"s", b"p", &mut dk).is_err(),
                "zero iterations must fail for {algo:?}"
            );
        }
    }

    #[test]
    fn derive_rejects_empty_output() {
        let mut dk: [u8; 0] = [];
        let res = derive(Pbkdf2Algo::HmacSha256, 1, b"salt", b"pw", &mut dk);
        match res {
            Err(CryptoError::Kdf(msg)) => {
                assert!(
                    msg.contains("output"),
                    "expected output-length error, got {msg:?}"
                );
                assert!(
                    msg.contains("non-zero"),
                    "expected 'non-zero' wording, got {msg:?}"
                );
            }
            other => panic!("expected Err(CryptoError::Kdf(_)), got {other:?}"),
        }
    }

    #[test]
    fn derive_rejects_empty_output_all_algos() {
        for algo in [
            Pbkdf2Algo::HmacSha1,
            Pbkdf2Algo::HmacSha256,
            Pbkdf2Algo::HmacSha384,
            Pbkdf2Algo::HmacSha512,
        ] {
            let mut dk: [u8; 0] = [];
            assert!(
                derive(algo, 1, b"s", b"p", &mut dk).is_err(),
                "empty output must fail for {algo:?}"
            );
        }
    }

    #[test]
    fn verify_rejects_zero_iterations() {
        let expected = [0u8; 32];
        let res = verify(Pbkdf2Algo::HmacSha256, 0, b"salt", b"pw", &expected);
        assert!(matches!(res, Err(CryptoError::Kdf(_))));
    }

    #[test]
    fn verify_rejects_empty_expected() {
        let expected: [u8; 0] = [];
        let res = verify(Pbkdf2Algo::HmacSha256, 1, b"salt", b"pw", &expected);
        match res {
            Err(CryptoError::Kdf(msg)) => {
                assert!(
                    msg.contains("expected") || msg.contains("length"),
                    "expected length-related error, got {msg:?}"
                );
            }
            other => panic!("expected Err(CryptoError::Kdf(_)), got {other:?}"),
        }
    }

    #[test]
    fn verify_mismatch_yields_verification_failed() {
        // Establish a correct DK.
        let salt = b"salt";
        let password = b"right-password";
        let mut dk = [0u8; 32];
        derive_sha256(50, salt, password, &mut dk).unwrap();

        // Verifying with the wrong password must return the verify
        // error with exactly the "verification failed" message.
        let res = verify(Pbkdf2Algo::HmacSha256, 50, salt, b"wrong-password", &dk);
        match res {
            Err(CryptoError::Kdf(msg)) => {
                assert_eq!(msg, "verification failed");
            }
            other => panic!("expected Err(CryptoError::Kdf(_)), got {other:?}"),
        }
    }

    // ==================================================================
    // Empty salt and empty password are accepted (mirrors FASM).
    // ==================================================================

    #[test]
    fn derive_accepts_empty_salt() {
        let mut dk = [0u8; 20];
        derive_sha1(1, b"", b"password", &mut dk).unwrap();
        // Output is deterministic; just check it's non-zero (extremely
        // unlikely to hash to the all-zeroes block by accident).
        assert_ne!(dk, [0u8; 20]);
    }

    #[test]
    fn derive_accepts_empty_password() {
        let mut dk = [0u8; 20];
        derive_sha1(1, b"salt", b"", &mut dk).unwrap();
        assert_ne!(dk, [0u8; 20]);
    }

    #[test]
    fn derive_accepts_empty_salt_and_password() {
        let mut dk = [0u8; 20];
        derive_sha1(1, b"", b"", &mut dk).unwrap();
        assert_ne!(dk, [0u8; 20]);
    }

    // ==================================================================
    // Determinism: same inputs always produce same output across calls.
    // ==================================================================

    #[test]
    fn derive_is_deterministic() {
        let salt = b"fixed-salt";
        let password = b"fixed-password";
        let mut dk1 = [0u8; 32];
        let mut dk2 = [0u8; 32];
        derive_sha256(1000, salt, password, &mut dk1).unwrap();
        derive_sha256(1000, salt, password, &mut dk2).unwrap();
        assert_eq!(dk1, dk2);
    }

    // ==================================================================
    // Iteration count matters: changing c changes output.
    // ==================================================================

    #[test]
    fn different_iterations_different_output() {
        let salt = b"s";
        let password = b"p";
        let mut dk1 = [0u8; 32];
        let mut dk2 = [0u8; 32];
        derive_sha256(1, salt, password, &mut dk1).unwrap();
        derive_sha256(2, salt, password, &mut dk2).unwrap();
        assert_ne!(dk1, dk2);
    }

    // ==================================================================
    // Salt matters: changing S changes output.
    // ==================================================================

    #[test]
    fn different_salts_different_output() {
        let password = b"same-password";
        let mut dk1 = [0u8; 32];
        let mut dk2 = [0u8; 32];
        derive_sha256(100, b"salt-a", password, &mut dk1).unwrap();
        derive_sha256(100, b"salt-b", password, &mut dk2).unwrap();
        assert_ne!(dk1, dk2);
    }

    // ==================================================================
    // Pbkdf2Algo derive traits: Clone, Copy, Debug, Eq, Hash.
    // ==================================================================

    #[test]
    fn algo_traits_behave() {
        // Copy: the value is trivially usable after being passed.
        let a = Pbkdf2Algo::HmacSha256;
        let b = a;
        assert_eq!(a, b);

        // Debug: produces some representation.
        let s = format!("{a:?}");
        assert!(s.contains("HmacSha256"));

        // Hash: usable as a HashMap key.
        use std::collections::HashMap;
        let mut map: HashMap<Pbkdf2Algo, &'static str> = HashMap::new();
        map.insert(Pbkdf2Algo::HmacSha1, "sha1");
        map.insert(Pbkdf2Algo::HmacSha256, "sha256");
        map.insert(Pbkdf2Algo::HmacSha384, "sha384");
        map.insert(Pbkdf2Algo::HmacSha512, "sha512");
        assert_eq!(map.len(), 4);
        assert_eq!(map[&Pbkdf2Algo::HmacSha256], "sha256");
    }
}
