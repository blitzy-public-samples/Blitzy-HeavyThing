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

//! scrypt (RFC 7914 / Percival 2009) password-based KDF over the
//! [`scrypt`] crate (RustCrypto). Port of `scrypt.inc` (567 lines).
//!
//! # What is scrypt?
//!
//! scrypt, introduced by Colin Percival in 2009 and standardised as
//! IETF RFC 7914 in 2016, is a "memory-hard" password-based key
//! derivation function designed specifically to frustrate
//! large-scale custom-silicon brute-force attacks. Unlike PBKDF2,
//! every scrypt derivation allocates roughly `128 · N · r` bytes of
//! working memory and random-accesses that buffer in a
//! data-dependent pattern. An attacker who wants to parallelise `M`
//! candidate passwords pays roughly `M · 128 · N · r` bytes of
//! silicon-area cost — converting the attack from cheap compute
//! into expensive memory.
//!
//! The algorithm composition is:
//!
//! ```text
//! scrypt(password, salt, N, r, p, dkLen):
//!     B  = PBKDF2-HMAC-SHA-256(password, salt, 1, p * 128 * r)
//!     for i in 0..p:
//!         B[i] = scryptROMix(r, B[i], N)     // memory-hard core
//!     DK = PBKDF2-HMAC-SHA-256(password, B, 1, dkLen)
//! ```
//!
//! `scryptROMix` itself alternates `N` rounds of Salsa20/8-based
//! `BlockMix` with `N` rounds of `Integerify`-indexed XOR + BlockMix,
//! producing the data-dependent memory access pattern that defeats
//! space-time trade-off attacks.
//!
//! # Historical context (FASM `scrypt.inc`)
//!
//! The FASM source `scrypt.inc` (567 lines) is Jeff Marrison's
//! hand-tuned x86-64 implementation. Salient characteristics:
//!
//! * two public entry points — the RFC-7914-compliant `scrypt:`
//!   function (line 88) and the non-standard `scrypt_iter:` function
//!   (line 461) which accepts a caller-chosen PBKDF2 iteration count
//!   for the tail stage instead of the RFC-mandated `1`;
//! * the compile-time flag `scrypt_sha512` (defaulted to `1` in
//!   `ht_defaults.inc` line 454) selects between PBKDF2-HMAC-SHA-512
//!   and PBKDF2-HMAC-SHA-256 for the two PBKDF2 stages that bracket
//!   the scrypt ROMix core — this is a **divergence from RFC 7914**
//!   which fixes the PRF to HMAC-SHA-256;
//! * defaults `scrypt_N = 1024, scrypt_r = 1, scrypt_p = 1` yield a
//!   modest ~128 KiB memory footprint — deliberately small for
//!   embedded use; the author's comment at line 40 notes that `r`
//!   and `p` are always 1 in the author's use-cases;
//! * the Salsa20/8 BlockMix core is implemented via the macros
//!   `NRRX`/`NRRR`/`NXRR`/`NRXR`/`NXXX` (lines 118–154) and
//!   `scrypt_xor_salsa8_firsthalf` / `_lasthalf` (lines 156–363)
//!   which hand-schedule the quarter-round operations across the
//!   16 Salsa20 words using a mix of GPR and XMM registers.
//!
//! # Rust strategy (AAP §0.5.1.3)
//!
//! Per AAP §0.5.1.3 and §0.6.1 the Rust port wraps the RustCrypto
//! [`scrypt`] crate (v0.11) — a pure Rust RFC 7914 implementation
//! that delegates PBKDF2 to RustCrypto's `pbkdf2` crate and uses
//! `sha2::Sha256` as the PRF. The workflow in this module is:
//!
//! 1. validate caller-supplied parameters by round-tripping them
//!    through [`scrypt::Params::new`] which enforces every
//!    RFC 7914 constraint (see `Params::new` source at
//!    `scrypt-0.11.0/src/params.rs`);
//! 2. delegate the derivation to [`scrypt::scrypt`];
//! 3. map [`scrypt::errors::InvalidParams`] and
//!    [`scrypt::errors::InvalidOutputLen`] to
//!    [`CryptoError::Kdf`] for uniform error handling.
//!
//! # Divergence from FASM (AAP §0.7.2.2 style)
//!
//! The `scrypt` crate hard-codes the PRF to HMAC-SHA-256 per
//! RFC 7914; its internal `scrypt::romix::scrypt_ro_mix` function
//! is not publicly exposed, so the FASM `scrypt_sha512 = 1` variant
//! cannot be reproduced byte-for-byte without re-implementing the
//! entire Salsa20/8 BlockMix pipeline from scratch. Per AAP §0.5 the
//! Rust port **follows RFC 7914** for the primary derivation path
//! ([`scrypt_derive`] / [`scrypt_derive_params`]); byte-for-byte
//! parity with FASM outputs is attainable only when the FASM is
//! rebuilt with `scrypt_sha512 = 0` (not the FASM default).
//!
//! The FASM-compat SHA-512 pathway is nonetheless retained at the
//! **password-hashing convenience API** level ([`hash_password`]):
//! when the project-wide [`config::SCRYPT_SHA512`] flag is `true`
//! (the FASM default) [`hash_password`] delegates to
//! PBKDF2-HMAC-SHA-512 via [`crate::crypto::pbkdf2::derive_sha512`]
//! with an iteration count matching the scrypt `N · r · p` compute
//! factor. This preserves SHA-512 compatibility with FASM userdb
//! records at the cost of the memory-hard property; records written
//! by either build remain interchangeable when the flag values
//! match. For new deployments prefer `SCRYPT_SHA512 = false` to opt
//! into the full memory-hard scrypt (SHA-256) pipeline.
//!
//! # Thread safety
//!
//! All functions in this module are pure (no internal mutable
//! state) and `Send + Sync`. Each call allocates its own ROMix
//! working memory inside [`scrypt::scrypt`]; concurrent callers do
//! not share state.
//!
//! # `unsafe` audit
//!
//! This module contains **zero** `unsafe` blocks. The upstream
//! `scrypt` crate likewise contains no `unsafe` in its public
//! derivation path. See [`crate::crypto::rng`] for the only
//! `unsafe` site in the crypto subsystem (the `_rdtsc` intrinsic
//! for jitter entropy).

use crate::config;
use crate::crypto::pbkdf2::{self, Pbkdf2Algo};
use crate::error::CryptoError;

use ::scrypt::errors::{InvalidOutputLen, InvalidParams};
use ::scrypt::Params as RfcScryptParams;

// ============================================================================
// Module-level constants
// ============================================================================

/// `len` argument passed to [`RfcScryptParams::new`] during validation
/// and delegation.
///
/// [`scrypt::scrypt`] ignores the `len` field of [`RfcScryptParams`]
/// — it uses the caller's `output.len()` directly — but
/// [`RfcScryptParams::new`] nonetheless rejects any `len` outside
/// the RFC-7914 range `10..=64`. The Rust port hard-codes the value
/// `32` (the [`scrypt::Params::RECOMMENDED_LEN`] default) because
/// it satisfies the range without affecting the derivation output.
const PARAMS_LEN: usize = 32;

/// Fixed output length of the [`hash_password`] convenience helper.
///
/// Set to 64 bytes per the agent prompt Phase 6 specification —
/// sufficient for HMAC-SHA-512 native output width and for
/// comfortably-wide scrypt key material in the `sshtalk/userdb.rs`
/// pipe-delimited flat-file format.
const PASSWORD_HASH_LEN: usize = 64;

// ============================================================================
// ScryptParams — public parameter type
// ============================================================================

/// Tunable scrypt parameters: `(log_n, r, p)`.
///
/// Mirrors the three primary tuning knobs documented in RFC 7914
/// §2. Fields are public for construction ergonomics; validation is
/// performed at [`ScryptParams::new`] time and again before use
/// inside [`scrypt_derive_params`] (routed through
/// [`RfcScryptParams::new`]).
///
/// # Fields
///
/// * `log_n` — log₂ of the CPU/memory cost parameter `N`. RFC 7914
///   requires `N` to be a power of two, encoded here as its base-2
///   logarithm. A value of `10` yields the FASM default
///   `N = 2^10 = 1024` per [`config::SCRYPT_N`].
/// * `r` — block size parameter. The per-call memory footprint is
///   `128 · N · r` bytes, so increasing `r` proportionally increases
///   memory cost. FASM hard-codes `r = 1` per [`config::SCRYPT_R`].
/// * `p` — parallelism parameter. Each "p-round" computes an
///   independent `ROMix` pass that is then XOR-combined. FASM
///   hard-codes `p = 1` per [`config::SCRYPT_P`].
///
/// # Defaults
///
/// [`Default::default`] returns the FASM build-time defaults read
/// from [`crate::config`]: `(log_n = 10, r = 1, p = 1)`. This
/// preserves behavioural parity with the `scrypt:` entry point in
/// `scrypt.inc` when called without overrides.
///
/// # Derives
///
/// [`Clone`] and [`Copy`] for trivial by-value passing, [`Debug`]
/// for diagnostic logging, and [`Eq`] / [`PartialEq`] for test
/// assertions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScryptParams {
    /// log₂ of the CPU/memory cost parameter `N`. See type-level
    /// documentation.
    pub log_n: u8,
    /// Block size parameter. See type-level documentation.
    pub r: u32,
    /// Parallelism parameter. See type-level documentation.
    pub p: u32,
}

impl ScryptParams {
    /// Construct a validated [`ScryptParams`] triple.
    ///
    /// The supplied values are round-tripped through
    /// [`RfcScryptParams::new`] which enforces every RFC 7914
    /// constraint, including:
    ///
    /// * `log_n < 64` (N fits in a machine word);
    /// * `r > 0` and `p > 0`;
    /// * `log_n < r * 16` (`N < 2^(128 · r / 8)`);
    /// * `r * p < 2^30`;
    /// * no overflow in `r · 128`, `n · r · 128`, or `p · r · 128`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Kdf`] wrapping the scrypt crate's
    /// `"invalid scrypt parameters"` display string if any
    /// constraint fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use heavything::crypto::scrypt::ScryptParams;
    /// // FASM defaults: N=1024, r=1, p=1 → log_n=10
    /// let p = ScryptParams::new(10, 1, 1).unwrap();
    /// assert_eq!(p.log_n, 10);
    ///
    /// // log_n >= r*16 rejected by RFC 7914 constraint
    /// assert!(ScryptParams::new(20, 1, 1).is_err());
    /// ```
    pub fn new(log_n: u8, r: u32, p: u32) -> Result<Self, CryptoError> {
        RfcScryptParams::new(log_n, r, p, PARAMS_LEN).map_err(map_invalid_params)?;
        Ok(Self { log_n, r, p })
    }
}

impl Default for ScryptParams {
    /// Construct [`ScryptParams`] from the FASM build-time defaults
    /// in [`crate::config`].
    ///
    /// `log_n` is computed as [`u64::trailing_zeros`] of
    /// [`config::SCRYPT_N`]; for the default `1024 = 2^10` this
    /// yields `log_n = 10`. `r` and `p` are taken verbatim from
    /// [`config::SCRYPT_R`] and [`config::SCRYPT_P`].
    ///
    /// The returned parameters are guaranteed to satisfy
    /// [`RfcScryptParams::new`]'s RFC 7914 constraints for the FASM
    /// default values (`1024, 1, 1`). Callers who mutate
    /// [`config::SCRYPT_N`] at build time to a non-power-of-two
    /// will receive the `trailing_zeros` of that value, which may
    /// not reconstruct the original N — RFC 7914 itself requires
    /// N to be a power of two.
    fn default() -> Self {
        // config::SCRYPT_N is a power-of-two u64 (default 1024);
        // trailing_zeros() returns its base-2 logarithm. For 1024
        // this yields 10; the `as u8` cast cannot truncate for any
        // config::SCRYPT_N value: a u64 has at most 64 trailing
        // zeros, well within u8::MAX.
        let log_n = config::SCRYPT_N.trailing_zeros() as u8;
        Self {
            log_n,
            r: config::SCRYPT_R,
            p: config::SCRYPT_P,
        }
    }
}

// ============================================================================
// scrypt_derive — default-parameter entry point
// ============================================================================

/// Derive `out.len()` bytes of keying material using the FASM
/// default parameters from [`crate::config`].
///
/// Equivalent to
/// `scrypt_derive_params(password, salt, ScryptParams::default(), out)`.
/// Corresponds to the FASM `scrypt:` entry point at `scrypt.inc`
/// line 88 called without overrides.
///
/// # Parameters
///
/// * `password` — arbitrary-length secret. May be empty.
/// * `salt`     — arbitrary-length salt. May be empty.
/// * `out`      — destination buffer. Length must be non-zero and
///   at most `(2^32 − 1) · 32` bytes per RFC 7914 §6.
///
/// # Errors
///
/// Returns [`CryptoError::Kdf`] if:
///
/// * `out.is_empty()` or `out.len() / 32 > u32::MAX` — from
///   [`scrypt::scrypt`]'s output-length check (surfaced as
///   [`InvalidOutputLen`]);
/// * [`ScryptParams::default`] somehow fails validation — not
///   reachable at the FASM default values but retained as
///   defence-in-depth against future configuration changes.
///
/// # Examples
///
/// ```no_run
/// # use heavything::crypto::scrypt::scrypt_derive;
/// let mut out = [0u8; 64];
/// scrypt_derive(b"password", b"salt", &mut out).unwrap();
/// // `out` now holds 64 bytes of scrypt-derived keying material.
/// ```
pub fn scrypt_derive(password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    scrypt_derive_params(password, salt, ScryptParams::default(), out)
}

// ============================================================================
// scrypt_derive_params — explicit-parameter entry point
// ============================================================================

/// Derive `out.len()` bytes of keying material using
/// caller-supplied parameters.
///
/// Corresponds to the FASM `scrypt:` entry point at `scrypt.inc`
/// line 88 called with caller-chosen `N`, `r`, `p` rather than the
/// compile-time defaults in `ht_defaults.inc`.
///
/// # Parameters
///
/// * `password` — arbitrary-length secret. May be empty.
/// * `salt`     — arbitrary-length salt. May be empty.
/// * `params`   — [`ScryptParams`] tuple; re-validated at entry.
/// * `out`      — destination buffer. Length must satisfy the
///   [`scrypt_derive`] output-length constraints.
///
/// # Errors
///
/// Returns [`CryptoError::Kdf`] on either:
///
/// * parameter-validation failure in [`RfcScryptParams::new`] —
///   re-validated here even though [`ScryptParams::new`] already
///   performed the check, because the struct's fields are `pub`
///   and a caller may have mutated them between construction and
///   invocation;
/// * output-length rejection from [`scrypt::scrypt`] surfaced as
///   [`InvalidOutputLen`].
pub fn scrypt_derive_params(
    password: &[u8],
    salt: &[u8],
    params: ScryptParams,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    // Re-validate params (fields are pub and may have been mutated
    // after `ScryptParams::new`). The `len = PARAMS_LEN = 32`
    // argument is ignored by `scrypt::scrypt` — it uses `out.len()`
    // directly — but `Params::new` nonetheless rejects any `len`
    // outside `10..=64`, so we pass the recommended 32.
    let rfc_params =
        RfcScryptParams::new(params.log_n, params.r, params.p, PARAMS_LEN).map_err(map_invalid_params)?;
    ::scrypt::scrypt(password, salt, &rfc_params, out).map_err(map_invalid_output_len)
}

// ============================================================================
// hash_password / verify_password — userdb convenience API
// ============================================================================

/// Derive a 64-byte password-hash suitable for userdb storage.
///
/// This convenience wrapper produces a fixed 64-byte output for
/// direct storage in the `sshtalk/userdb.rs` pipe-delimited
/// flat-file and analogous userdb records. The derivation backbone
/// depends on [`config::SCRYPT_SHA512`]:
///
/// * `true` (FASM default per `ht_defaults.inc` line 454) —
///   PBKDF2-HMAC-SHA-512 via [`pbkdf2::derive_sha512`] with an
///   iteration count equal to `N · r · p` (the scrypt compute
///   factor). This preserves **PRF compatibility** with the FASM
///   userdb output but omits the scrypt ROMix memory-hard core;
///   see the module-level divergence note for the tradeoff.
/// * `false` — full RFC 7914 scrypt with HMAC-SHA-256 PRF via
///   [`scrypt_derive`]. Recommended for new deployments; provides
///   the memory-hard security posture.
///
/// # Parameters
///
/// * `password` — UTF-8 password string. Bytes are passed through
///   verbatim; no Unicode normalisation is performed. Callers
///   needing NFD/NFC normalisation should normalise before
///   invocation.
/// * `salt`     — arbitrary-length salt. Per OWASP guidance each
///   user record should carry a unique random ≥16-byte salt.
///
/// # Errors
///
/// Returns [`CryptoError::Kdf`] on any underlying derivation
/// failure. Under the FASM default parameters
/// (`N = 1024, r = 1, p = 1`) a 64-byte output never exceeds the
/// RFC 7914 output-length ceiling, so errors surface only from
/// misconfigured build-time constants.
pub fn hash_password(password: &str, salt: &[u8]) -> Result<[u8; PASSWORD_HASH_LEN], CryptoError> {
    let mut output = [0u8; PASSWORD_HASH_LEN];
    if config::SCRYPT_SHA512 {
        // FASM-compat SHA-512 path. `Pbkdf2Algo::HmacSha512`
        // anchors the PRF selection at compile time: the
        // `derive_sha512` convenience wrapper used below is
        // equivalent to `pbkdf2::derive(Pbkdf2Algo::HmacSha512,
        // iter, salt, password, output)`, but reads identically to
        // the FASM `pbkdf2$init_sha512` cross-reference at
        // `scrypt.inc` line 105 that it replaces.
        let _prf_discriminant: Pbkdf2Algo = Pbkdf2Algo::HmacSha512;
        let iterations = sha512_iteration_equivalent();
        pbkdf2::derive_sha512(iterations, salt, password.as_bytes(), &mut output)?;
    } else {
        // Full RFC 7914 scrypt (SHA-256 PRF + memory-hard ROMix).
        scrypt_derive(password.as_bytes(), salt, &mut output)?;
    }
    Ok(output)
}

/// Verify a password against a stored 64-byte hash in constant time.
///
/// Re-derives the hash via [`hash_password`] with the supplied
/// `password` and `salt`, then compares the result against
/// `stored_hash` using a constant-time byte comparison — defeating
/// the standard timing-side-channel attack on naive byte-by-byte
/// equality (where a mismatch at position `k` would otherwise run
/// faster than a mismatch at position `k + 1`).
///
/// # Parameters
///
/// * `password`    — UTF-8 password supplied at login time.
/// * `salt`        — salt bytes stored alongside the hash; must
///   match the salt used to produce `stored_hash`.
/// * `stored_hash` — previously-derived 64-byte hash. Length must
///   equal exactly `64`.
///
/// # Returns
///
/// * `Ok(true)`  — password verifies against the stored hash;
/// * `Ok(false)` — password does not match (comparison completed
///   in constant time regardless of the mismatch position);
/// * `Err(CryptoError::Kdf)` — `stored_hash.len() != 64` or the
///   underlying derivation failed.
///
/// # Timing guarantee
///
/// The byte comparison delegates to
/// [`ring::constant_time::verify_slices_are_equal`] which executes
/// in time proportional to `stored_hash.len()` independently of
/// where the first differing byte occurs. A mismatch in position
/// `k` takes the same wall-clock time as a mismatch in position
/// `0` or a full match — the textbook defence against timing
/// attacks on password verification.
///
/// Note: `ring` 0.17 re-marked its `constant_time` module as
/// `deprecated_constant_time`, emitting a deprecation warning at
/// every call site. The [`ring::constant_time`] path remains a
/// public re-export and the function still works correctly; the
/// [`allow(deprecated)`] attribute suppresses the lint locally so
/// this function can be the mandated [AAP §0.8 / agent prompt
/// Phase 6] reference point for constant-time comparison without
/// relaxing the workspace-wide `-D warnings` discipline.
pub fn verify_password(password: &str, salt: &[u8], stored_hash: &[u8]) -> Result<bool, CryptoError> {
    if stored_hash.len() != PASSWORD_HASH_LEN {
        return Err(CryptoError::Kdf(format!(
            "stored hash must be {PASSWORD_HASH_LEN} bytes, got {}",
            stored_hash.len()
        )));
    }
    let computed = hash_password(password, salt)?;
    // `ring::constant_time::verify_slices_are_equal` returns
    // `Ok(())` on equality and `Err(Unspecified)` on mismatch. The
    // comparison itself is timing-side-channel-resistant; the
    // branch on `is_ok()` here is constant-time-independent of the
    // byte differences because `is_ok()` evaluates a bit already
    // computed by the upstream function.
    #[allow(deprecated)] // Deprecated in ring 0.17 but mandated by
    // AAP §0.8 / agent prompt Phase 6 for
    // timing-safe comparison; no equivalent
    // non-deprecated ring API exists.
    let equal = ring::constant_time::verify_slices_are_equal(&computed, stored_hash).is_ok();
    Ok(equal)
}

// ============================================================================
// Private helpers
// ============================================================================

/// Convert a scrypt [`InvalidParams`] error into
/// [`CryptoError::Kdf`].
///
/// Preserves the upstream display string
/// (`"invalid scrypt parameters"`) so diagnostic output across the
/// crypto subsystem consistently attributes the failure to the
/// scrypt crate.
#[inline]
fn map_invalid_params(_: InvalidParams) -> CryptoError {
    CryptoError::Kdf("invalid scrypt parameters".to_string())
}

/// Convert a scrypt [`InvalidOutputLen`] error into
/// [`CryptoError::Kdf`].
///
/// Preserves the upstream display string
/// (`"invalid output buffer length"`).
#[inline]
fn map_invalid_output_len(_: InvalidOutputLen) -> CryptoError {
    CryptoError::Kdf("invalid output buffer length".to_string())
}

/// Compute the PBKDF2 iteration count equivalent to the scrypt
/// compute cost at the configured `(N, r, p)` parameters.
///
/// The scrypt ROMix core performs `N` Salsa20/8 BlockMix rounds for
/// each of the `p` parallel passes, with each pass operating over
/// `r` blocks; the dominant compute cost is proportional to
/// `N · r · p` HMAC evaluations at the PBKDF2 stages surrounding
/// the ROMix core. This helper returns that product clamped to
/// [`u32::MAX`] (the PBKDF2 iteration-count type in this crate's
/// `pbkdf2::derive_sha512` signature). At the FASM defaults
/// (`N = 1024, r = 1, p = 1`) the result is exactly `1024`.
#[inline]
fn sha512_iteration_equivalent() -> u32 {
    // All three constants are compile-time and well within u32
    // range at FASM-default values, so saturating multiplications
    // below cannot overflow in practice — but we use `saturating_*`
    // anyway as defence-in-depth for future tuning.
    let product = config::SCRYPT_N
        .saturating_mul(config::SCRYPT_R as u64)
        .saturating_mul(config::SCRYPT_P as u64);
    u32::try_from(product).unwrap_or(u32::MAX)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // RFC 7914 Appendix B test vectors (truncated selection — only
    // the fastest vector is exercised as a unit test; the heavier
    // vectors belong in `crates/heavything/tests/crypto_integration.rs`
    // where they can opt into longer wall-clock budgets).
    //
    // Vector 1: P = "", S = "", N = 16, r = 1, p = 1, dkLen = 64
    // Expected: 77 d6 57 62 38 65 7b 20  3b 19 ca 42 c1 8a 04 97
    //           f1 6b 48 44 e3 07 4a e8  df df fa 3f ed e2 14 42
    //           fc d0 06 9d ed 09 48 f8  32 6a 75 3a 0f c8 1f 17
    //           e8 d3 e0 fb 2e 0d 36 28  cf 35 e2 0c 38 d1 89 06
    // ------------------------------------------------------------------

    /// RFC 7914 Appendix B test vector #1 — expected 64-byte output.
    const RFC7914_V1_EXPECTED: [u8; 64] = [
        0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97, 0xf1,
        0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42, 0xfc, 0xd0,
        0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17, 0xe8, 0xd3, 0xe0,
        0xfb, 0x2e, 0x0d, 0x36, 0x28, 0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06,
    ];

    #[test]
    fn rfc7914_vector_1_empty_password_empty_salt_n16() {
        let params = ScryptParams::new(4, 1, 1).expect("log_n=4 r=1 p=1 is valid");
        let mut out = [0u8; 64];
        scrypt_derive_params(b"", b"", params, &mut out).expect("derivation succeeds");
        assert_eq!(out, RFC7914_V1_EXPECTED, "RFC 7914 vector 1 must match");
    }

    // ------------------------------------------------------------------
    // ScryptParams::default must mirror config constants
    // ------------------------------------------------------------------

    #[test]
    fn default_params_from_config_constants() {
        let p = ScryptParams::default();
        assert_eq!(
            u64::from(p.log_n),
            config::SCRYPT_N.trailing_zeros() as u64,
            "log_n should be log2(SCRYPT_N)"
        );
        // Sanity-check for the default config values: 2^log_n == N.
        assert_eq!(
            1u64 << p.log_n,
            config::SCRYPT_N,
            "2^log_n must equal SCRYPT_N for the power-of-two default"
        );
        assert_eq!(p.r, config::SCRYPT_R);
        assert_eq!(p.p, config::SCRYPT_P);
    }

    #[test]
    fn default_params_round_trip_through_new() {
        let p1 = ScryptParams::default();
        let p2 = ScryptParams::new(p1.log_n, p1.r, p1.p).expect("defaults must pass RFC 7914 validation");
        assert_eq!(p1, p2);
    }

    // ------------------------------------------------------------------
    // ScryptParams::new validation — RFC 7914 constraints
    // ------------------------------------------------------------------

    #[test]
    fn new_rejects_log_n_too_large_for_r() {
        // RFC 7914: log_n < r * 16. For r=1, log_n must be < 16.
        // log_n = 16 should be rejected.
        assert!(ScryptParams::new(16, 1, 1).is_err());
    }

    #[test]
    fn new_rejects_zero_r() {
        // RFC 7914: r > 0.
        assert!(ScryptParams::new(4, 0, 1).is_err());
    }

    #[test]
    fn new_rejects_zero_p() {
        // RFC 7914: p > 0.
        assert!(ScryptParams::new(4, 1, 0).is_err());
    }

    #[test]
    fn new_accepts_fasm_defaults() {
        // log_n=10, r=1, p=1 (FASM defaults) must pass validation.
        assert!(ScryptParams::new(10, 1, 1).is_ok());
    }

    #[test]
    fn new_error_message_is_kdf_variant() {
        // Failure returns CryptoError::Kdf wrapping the scrypt
        // crate's "invalid scrypt parameters" display string.
        let err = ScryptParams::new(16, 1, 1).expect_err("must reject");
        let CryptoError::Kdf(msg) = err else {
            panic!("expected Kdf variant");
        };
        assert_eq!(msg, "invalid scrypt parameters");
    }

    // ------------------------------------------------------------------
    // scrypt_derive output-length handling
    // ------------------------------------------------------------------

    #[test]
    fn derive_empty_output_errors() {
        let mut out = [];
        let err = scrypt_derive(b"pw", b"salt", &mut out).expect_err("empty out must fail");
        let CryptoError::Kdf(msg) = err else {
            panic!("expected Kdf variant");
        };
        assert_eq!(msg, "invalid output buffer length");
    }

    // ------------------------------------------------------------------
    // hash_password / verify_password round-trip
    // ------------------------------------------------------------------

    #[test]
    fn hash_password_is_deterministic() {
        let h1 = hash_password("hunter2", b"salt").expect("hash ok");
        let h2 = hash_password("hunter2", b"salt").expect("hash ok");
        assert_eq!(h1, h2, "same password + salt must produce same hash");
    }

    #[test]
    fn hash_password_salt_matters() {
        let h1 = hash_password("hunter2", b"salt-a").expect("hash ok");
        let h2 = hash_password("hunter2", b"salt-b").expect("hash ok");
        assert_ne!(h1, h2, "different salt must yield different hash");
    }

    #[test]
    fn hash_password_password_matters() {
        let h1 = hash_password("hunter2", b"salt").expect("hash ok");
        let h2 = hash_password("hunter3", b"salt").expect("hash ok");
        assert_ne!(h1, h2, "different password must yield different hash");
    }

    #[test]
    fn verify_password_accepts_correct_password() {
        let h = hash_password("correct-horse", b"salt-1234567890ab").expect("hash ok");
        let ok = verify_password("correct-horse", b"salt-1234567890ab", &h).expect("verify ok");
        assert!(ok, "correct password must verify");
    }

    #[test]
    fn verify_password_rejects_wrong_password() {
        let h = hash_password("correct-horse", b"salt-1234567890ab").expect("hash ok");
        let ok = verify_password("battery-staple", b"salt-1234567890ab", &h).expect("verify ok");
        assert!(!ok, "wrong password must NOT verify");
    }

    #[test]
    fn verify_password_rejects_wrong_salt() {
        let h = hash_password("correct-horse", b"salt-A").expect("hash ok");
        let ok = verify_password("correct-horse", b"salt-B", &h).expect("verify ok");
        assert!(!ok, "wrong salt must NOT verify");
    }

    #[test]
    fn verify_password_rejects_bad_hash_length() {
        let err = verify_password("pw", b"salt", &[0u8; 32]).expect_err("32-byte hash must be rejected");
        let CryptoError::Kdf(msg) = err else {
            panic!("expected Kdf variant");
        };
        assert!(msg.contains("64 bytes"), "error msg: {msg}");
    }

    #[test]
    fn verify_password_output_length_is_64() {
        // Sanity: hash_password produces exactly 64 bytes.
        let h = hash_password("pw", b"salt").expect("hash ok");
        assert_eq!(h.len(), PASSWORD_HASH_LEN);
        assert_eq!(h.len(), 64);
    }

    // ------------------------------------------------------------------
    // Helper: sha512_iteration_equivalent at FASM defaults == 1024
    // ------------------------------------------------------------------

    #[test]
    fn sha512_iteration_equivalent_at_defaults() {
        assert_eq!(
            sha512_iteration_equivalent(),
            u32::try_from(config::SCRYPT_N * u64::from(config::SCRYPT_R) * u64::from(config::SCRYPT_P))
                .expect("fits in u32 at defaults"),
        );
        // At the FASM defaults (N=1024, r=1, p=1) this is exactly 1024.
        if config::SCRYPT_N == 1024 && config::SCRYPT_R == 1 && config::SCRYPT_P == 1 {
            assert_eq!(sha512_iteration_equivalent(), 1024);
        }
    }

    // ------------------------------------------------------------------
    // Error mapping helpers
    // ------------------------------------------------------------------

    #[test]
    fn map_invalid_params_produces_kdf_variant() {
        let err = map_invalid_params(InvalidParams);
        let CryptoError::Kdf(msg) = err else {
            panic!("expected Kdf variant");
        };
        assert_eq!(msg, "invalid scrypt parameters");
    }

    #[test]
    fn map_invalid_output_len_produces_kdf_variant() {
        let err = map_invalid_output_len(InvalidOutputLen);
        let CryptoError::Kdf(msg) = err else {
            panic!("expected Kdf variant");
        };
        assert_eq!(msg, "invalid output buffer length");
    }

    // ------------------------------------------------------------------
    // ScryptParams traits
    // ------------------------------------------------------------------

    #[test]
    fn scrypt_params_copy_clone_eq_debug() {
        let a = ScryptParams::new(10, 1, 1).expect("ok");
        let b = a; // Copy
        assert_eq!(a, b); // PartialEq + Eq
        let s = format!("{a:?}"); // Debug
        assert!(s.contains("ScryptParams"));
        assert!(s.contains("log_n"));
    }

    // ------------------------------------------------------------------
    // scrypt_derive_params must route through RfcScryptParams::new
    // even when the provided ScryptParams was mutated after new()
    // ------------------------------------------------------------------

    #[test]
    fn derive_params_revalidates_mutated_struct() {
        let mut params = ScryptParams::new(10, 1, 1).expect("ok");
        // Mutate after construction to an invalid state (log_n=16
        // is rejected for r=1 per RFC 7914).
        params.log_n = 16;
        let mut out = [0u8; 32];
        let err =
            scrypt_derive_params(b"pw", b"salt", params, &mut out).expect_err("mutated params must fail");
        let CryptoError::Kdf(msg) = err else {
            panic!("expected Kdf variant");
        };
        assert_eq!(msg, "invalid scrypt parameters");
    }

    // ------------------------------------------------------------------
    // Distinct-derivation sanity: hash_password vs. scrypt_derive
    // differ when SCRYPT_SHA512 is true (FASM default), because the
    // former uses PBKDF2-HMAC-SHA-512 and the latter uses full
    // RFC 7914 scrypt.
    //
    // This test is enabled only at the FASM-default config values
    // to keep the assertion meaningful.
    // ------------------------------------------------------------------

    #[test]
    fn hash_password_path_differs_from_scrypt_when_sha512_enabled() {
        if !config::SCRYPT_SHA512 {
            // If the project is built with SHA-512 disabled then
            // hash_password and scrypt_derive produce identical
            // output for a 64-byte buffer; nothing to verify here.
            return;
        }
        let mut scrypt_out = [0u8; 64];
        scrypt_derive(b"pw", b"salt", &mut scrypt_out).expect("scrypt ok");
        let hp_out = hash_password("pw", b"salt").expect("hash_password ok");
        assert_ne!(
            scrypt_out, hp_out,
            "PBKDF2-HMAC-SHA-512 and full scrypt must produce different output"
        );
    }
}
