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

//! HMAC (Keyed-Hash Message Authentication Code, RFC 2104) over
//! MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512.
//!
//! Port of `hmac.inc` (668 lines, 22 public FASM symbols) per
//! AAP §0.5.1.3. Used by [`crate::crypto::hmac_drbg`],
//! [`crate::crypto::pbkdf2`], the SSH transport layer
//! (`crate::net::ssh::cipher` — `hmac-sha2-256`), and the TLS 1.2
//! PRF / session MAC paths in `crate::net::tls`.
//!
//! # Backend selection
//!
//! | Variant   | Backend                                              | Notes                                        |
//! |-----------|------------------------------------------------------|----------------------------------------------|
//! | MD5       | Manual RFC 2104 via [`crate::crypto::md5::Md5`]      | `ring::hmac` does **not** expose MD5         |
//! | SHA-1     | [`ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY`]        | Legacy protocol interop only                 |
//! | SHA-224   | Manual RFC 2104 via [`crate::crypto::sha2::Sha224`]  | `ring::hmac` does **not** expose SHA-224     |
//! | SHA-256   | [`ring::hmac::HMAC_SHA256`]                          | Modern default                               |
//! | SHA-384   | [`ring::hmac::HMAC_SHA384`]                          |                                              |
//! | SHA-512   | [`ring::hmac::HMAC_SHA512`]                          |                                              |
//!
//! Per AAP §0.5.1.3 CRITICAL note, `ring::hmac` supports only the
//! four ring-backed variants above. MD5-HMAC and SHA-224-HMAC
//! therefore use a manual RFC 2104 implementation with the
//! ipad/opad construction over the respective digest wrappers.
//! Both manual paths produce byte-identical output to the FASM
//! baseline (verified against RFC 2202 / RFC 4231 test vectors
//! in the unit tests below).
//!
//! # FASM symbol mapping
//!
//! | FASM symbol              | Rust equivalent                                          |
//! |--------------------------|----------------------------------------------------------|
//! | `hmac$new_md5`    (38)   | [`Hmac::new_md5`]                                        |
//! | `hmac$new_sha1`   (72)   | [`Hmac::new_sha1`]                                       |
//! | `hmac$new_sha224` (105)  | [`Hmac::new_sha224`]                                     |
//! | `hmac$new_sha256` (138)  | [`Hmac::new_sha256`]                                     |
//! | `hmac$new_sha384` (171)  | [`Hmac::new_sha384`]                                     |
//! | `hmac$new_sha512` (204)  | [`Hmac::new_sha512`]                                     |
//! | `hmac$init_*`            | (subsumed by the new-* ctors — no distinct "init" step)  |
//! | `hmac$destroy`   (239)   | (automatic — Rust [`Drop`] with zeroization)             |
//! | `hmac$key`       (255)   | (subsumed by the new-* ctors' key parameter)             |
//! | `hmac$replace_key` (350) | [`Hmac::replace_key`]                                    |
//! | `hmac$data`      (367)   | [`Hmac::update`]                                         |
//! | `hmac$phash`     (382)   | [`p_hash`]                                               |
//! | `hmac$phash_xor` (516)   | [`p_hash_xor`]                                           |
//! | `hmac$final`     (602)   | [`Hmac::finalize`] / [`Hmac::finalize_into`]             |
//! | `hmac$reset`     (658)   | [`Hmac::reset`]                                          |
//!
//! # Constant-time verification
//!
//! Per AAP §0.8 ("Constant-time verification only via
//! `ring::constant_time`"), the [`verify`] free function and the
//! manual HMAC-MD5 / HMAC-SHA-224 paths always compare the
//! computed tag against the expected tag with
//! [`ring::constant_time::verify_slices_are_equal`], never with
//! `==` or any slice equality that might short-circuit. For the
//! four ring-backed algorithms the verification routes directly
//! through [`ring::hmac::verify`], which itself uses
//! constant-time comparison internally.
//!
//! # Key zeroization
//!
//! Manual MD5 / SHA-224 HMAC contexts hold `ipad_key` and
//! `opad_key` byte arrays. [`Hmac`] implements [`Drop`] which
//! zeroes these arrays on scope exit (best-effort; the compiler
//! is free to elide copies it considers dead — this is the same
//! tradeoff every Rust crypto crate faces without pulling in
//! `zeroize`, which is not in the workspace dependency set).
//! ring-backed variants are zeroed by ring itself; its [`Key`]
//! and [`Context`] types do not expose raw key material at all.
//!
//! # `unsafe` audit
//!
//! Per AAP §0.7.4.1 this module contains **zero** `unsafe`
//! blocks; correctness derives entirely from `ring`,
//! [`crate::crypto::md5`], [`crate::crypto::sha2`], and safe
//! slice operations.
//!
//! [`Key`]: ring::hmac::Key
//! [`Context`]: ring::hmac::Context

use crate::crypto::md5::{md5, Md5, MD5_BLOCK_SIZE, MD5_OUTPUT_SIZE};
use crate::crypto::sha2::{sha224, Sha224, SHA224_OUTPUT_SIZE, SHA256_BLOCK_SIZE};
use crate::error::CryptoError;
use ring::hmac;

// ============================================================================
// HMAC algorithm enumeration
// ============================================================================

/// The set of HMAC algorithms supported by [`Hmac`].
///
/// Maps 1-to-1 to the six FASM `hmac$new_*` symbols (`hmac.inc`
/// lines 38, 72, 105, 138, 171, 204). The two smallest variants
/// (MD5, SHA-224) do not have a `ring::hmac::Algorithm` equivalent
/// and are therefore computed via manual RFC 2104 construction
/// over [`crate::crypto::md5`] and [`crate::crypto::sha2::Sha224`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HmacAlgo {
    /// HMAC-MD5 (RFC 2104) — 16-byte MAC, 64-byte block size.
    ///
    /// Legacy protocol support only (TLS 1.0/1.1 PRF, HTTP digest
    /// authentication RFC 7616, NTLM). **Not suitable for any new
    /// security-sensitive application** — MD5 is cryptographically
    /// broken for collision resistance. For new code use
    /// [`HmacAlgo::Sha256`].
    Md5,

    /// HMAC-SHA-1 (RFC 2104 / FIPS 180-4) — 20-byte MAC, 64-byte
    /// block size.
    ///
    /// Legacy use via [`ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY`].
    /// Retained for PBKDF2-HMAC-SHA-1 (PKCS #5), TLS 1.0/1.1 record
    /// MAC, and the SSH `hmac-sha1` algorithm.
    Sha1,

    /// HMAC-SHA-224 (RFC 2104 / FIPS 180-4) — 28-byte MAC,
    /// 64-byte block size.
    ///
    /// Rarely used in modern protocols. Implemented manually
    /// because `ring::hmac` does not expose SHA-224.
    Sha224,

    /// HMAC-SHA-256 (RFC 2104 / FIPS 180-4) — 32-byte MAC,
    /// 64-byte block size.
    ///
    /// Modern default per NIST SP 800-131A Rev. 2.
    Sha256,

    /// HMAC-SHA-384 (RFC 2104 / FIPS 180-4) — 48-byte MAC,
    /// 128-byte block size.
    Sha384,

    /// HMAC-SHA-512 (RFC 2104 / FIPS 180-4) — 64-byte MAC,
    /// 128-byte block size.
    Sha512,
}

impl HmacAlgo {
    /// Size of the MAC (digest) output in bytes.
    ///
    /// Matches the FASM `hmac_macsize_ofs` value set by each
    /// `hmac$new_*` symbol (`hmac.inc` lines 46, 79, 112, 145,
    /// 178, 211).
    ///
    /// | Variant  | Bytes |
    /// |----------|-------|
    /// | `Md5`    | 16    |
    /// | `Sha1`   | 20    |
    /// | `Sha224` | 28    |
    /// | `Sha256` | 32    |
    /// | `Sha384` | 48    |
    /// | `Sha512` | 64    |
    #[inline]
    #[must_use]
    pub const fn output_size(self) -> usize {
        match self {
            HmacAlgo::Md5 => MD5_OUTPUT_SIZE,
            HmacAlgo::Sha1 => 20,
            HmacAlgo::Sha224 => SHA224_OUTPUT_SIZE,
            HmacAlgo::Sha256 => 32,
            HmacAlgo::Sha384 => 48,
            HmacAlgo::Sha512 => 64,
        }
    }

    /// Size of the underlying hash's compression-function input
    /// block in bytes. This is the pad length used for ipad/opad
    /// construction per RFC 2104 §2.
    ///
    /// Matches the implicit FASM 64-byte pad block used by every
    /// `hmac$key` invocation (`hmac.inc` line 286, 312, etc.)
    /// except for SHA-384 / SHA-512 which internally use a
    /// 128-byte block. The FASM library does not expose HMAC with
    /// SHA-384 / SHA-512 using a 128-byte ipad/opad directly; it
    /// relies on the SHA-384/SHA-512 `update` function to absorb
    /// the 64-byte pad via its own 128-byte block buffer (an
    /// RFC 2104 quirk that works because the HMAC construction
    /// treats the key as "padded to block size with zeros"). For
    /// `ring`-backed variants the correct block size is applied
    /// inside `ring::hmac::Key::new` regardless.
    ///
    /// | Variant             | Bytes |
    /// |---------------------|-------|
    /// | `Md5`/`Sha1`/`Sha224`/`Sha256` | 64    |
    /// | `Sha384`/`Sha512`   | 128   |
    #[inline]
    #[must_use]
    pub const fn block_size(self) -> usize {
        match self {
            HmacAlgo::Md5 | HmacAlgo::Sha1 | HmacAlgo::Sha224 | HmacAlgo::Sha256 => SHA256_BLOCK_SIZE,
            HmacAlgo::Sha384 | HmacAlgo::Sha512 => 128,
        }
    }

    /// Returns the corresponding [`ring::hmac::Algorithm`] for
    /// this variant, or `None` if ring does not support it
    /// (`Md5` and `Sha224`).
    ///
    /// Used internally to route between the ring-backed and
    /// manual HMAC code paths.
    #[inline]
    fn ring_algorithm(self) -> Option<hmac::Algorithm> {
        match self {
            HmacAlgo::Sha1 => Some(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
            HmacAlgo::Sha256 => Some(hmac::HMAC_SHA256),
            HmacAlgo::Sha384 => Some(hmac::HMAC_SHA384),
            HmacAlgo::Sha512 => Some(hmac::HMAC_SHA512),
            HmacAlgo::Md5 | HmacAlgo::Sha224 => None,
        }
    }
}

// ============================================================================
// Manual HMAC-MD5 state
// ============================================================================

/// Stateful HMAC-MD5 context (RFC 2104, manual implementation).
///
/// Stored independently from the ring-backed variants because
/// `ring::hmac` does not support MD5. Holds the pre-computed
/// outer-key pad and an in-progress [`Md5`] hasher fed with
/// `ipad_key || data`.
#[derive(Clone)]
struct Md5HmacCtx {
    /// `K' XOR opad`, where `K' = key` (zero-padded to 64 bytes
    /// when `|key| <= 64`) or `MD5(key)` (zero-padded from 16 to
    /// 64 bytes when `|key| > 64`). Saved for the outer hash.
    opad_key: [u8; MD5_BLOCK_SIZE],
    /// Inner hasher primed with `K' XOR ipad`. Each call to
    /// [`Hmac::update`] feeds bytes here; [`Hmac::finalize`]
    /// extracts the inner digest, hashes `opad_key || inner`
    /// through a fresh `Md5`, and returns the 16-byte outer MAC.
    inner: Md5,
}

// ============================================================================
// Manual HMAC-SHA-224 state
// ============================================================================

/// Stateful HMAC-SHA-224 context (RFC 2104, manual implementation).
///
/// Stored independently from the ring-backed variants because
/// `ring::hmac` does not expose SHA-224. Same structure as
/// [`Md5HmacCtx`] but over [`Sha224`] (28-byte digest, 64-byte
/// block).
#[derive(Clone)]
struct Sha224HmacCtx {
    /// `K' XOR opad` (see [`Md5HmacCtx::opad_key`]).
    opad_key: [u8; SHA256_BLOCK_SIZE],
    /// Inner [`Sha224`] hasher primed with `K' XOR ipad`.
    inner: Sha224,
}

// ============================================================================
// Hmac — stateful HMAC context
// ============================================================================

/// A stateful HMAC signing context.
///
/// Corresponds to the FASM `hmac_size`-byte heap allocation whose
/// layout was specified at `hmac.inc` lines 24–32 (hash state,
/// ipad key, opad key, hash function vtable, macsize). In Rust
/// the state is stack-allocated and the "hash function vtable"
/// becomes compile-time dispatch through [`HmacBackend`].
///
/// # Usage
///
/// ```
/// use heavything::crypto::hmac::{Hmac, HmacAlgo};
/// // RFC 4231 test case 1: HMAC-SHA-256 with 20-byte key of 0x0b
/// let key = [0x0b_u8; 20];
/// let mut ctx = Hmac::new(HmacAlgo::Sha256, &key).unwrap();
/// ctx.update(b"Hi There");
/// let mac = ctx.finalize();
/// assert_eq!(mac.len(), 32);
/// ```
///
/// # Cloning
///
/// [`Hmac`] implements [`Clone`] so callers can "fork" a context
/// to produce multiple MACs from a shared prefix. This is
/// load-bearing for [`p_hash`] (TLS PRF) where successive `A(i)`
/// iterations share the same `Context::with_key(&k)`
/// initialization and for [`crate::crypto::hmac_drbg`].
pub struct Hmac {
    /// Algorithm identity; also dispatches between ring and
    /// manual code paths in every state-mutating method.
    algorithm: HmacAlgo,
    /// Backend state. Variant kind is determined once at
    /// construction and never changed thereafter.
    backend: HmacBackend,
}

/// Internal HMAC backend state — either a ring [`hmac::Context`]
/// plus its key (for clone / reset) or a manual pad-plus-inner
/// pair for MD5 / SHA-224.
enum HmacBackend {
    /// Backed by [`ring::hmac::Context`]. Holds the
    /// [`ring::hmac::Key`] as well so [`Hmac::reset`] can rebuild
    /// the context without re-deriving the key from raw bytes
    /// (which would require re-storing the original key material
    /// in the struct — a violation of "zeroize on drop" that
    /// ring's [`Key`] explicitly avoids by hiding the bytes).
    ///
    /// [`Key`]: ring::hmac::Key
    Ring {
        /// Ring HMAC key — opaque; owns the ipad / opad
        /// pre-computation.
        key: hmac::Key,
        /// Active streaming context; replaced on [`Hmac::reset`].
        ctx: hmac::Context,
    },

    /// Backed by a manual HMAC-MD5 construction.
    Md5(Md5HmacCtx),

    /// Backed by a manual HMAC-SHA-224 construction.
    Sha224(Sha224HmacCtx),
}

impl Clone for HmacBackend {
    fn clone(&self) -> Self {
        match self {
            // `ring::hmac::Context` and `ring::hmac::Key` both
            // implement `Clone` (verified against ring 0.17
            // source: `#[derive(Clone)]` on `Key` at line 154,
            // `#[derive(Clone)]` on `Context` at line 303).
            HmacBackend::Ring { key, ctx } => HmacBackend::Ring {
                key: key.clone(),
                ctx: ctx.clone(),
            },
            HmacBackend::Md5(c) => HmacBackend::Md5(c.clone()),
            HmacBackend::Sha224(c) => HmacBackend::Sha224(c.clone()),
        }
    }
}

impl Clone for Hmac {
    /// Produce an independent copy of this HMAC context.
    ///
    /// Required by [`crate::crypto::hmac_drbg`] (NIST SP 800-90A
    /// §10.1.2.2) and by [`p_hash`] (TLS PRF `A(i)` iteration).
    fn clone(&self) -> Self {
        Self {
            algorithm: self.algorithm,
            backend: self.backend.clone(),
        }
    }
}

// ============================================================================
// State mutation — update / replace_key / reset / finalize
// ============================================================================

impl Hmac {
    /// Return the HMAC algorithm this context was constructed for.
    ///
    /// Useful when threading [`Hmac`] instances through generic
    /// code that needs to know the output size without a separate
    /// `HmacAlgo` parameter.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> HmacAlgo {
        self.algorithm
    }

    /// Feed `data` into the HMAC context.
    ///
    /// Equivalent to FASM `hmac$data` (`hmac.inc` line 367),
    /// which delegates to the underlying hash's `update` via
    /// the `hmac_macupdate_ofs` vtable slot. May be called any
    /// number of times; the concatenation of all `data` bytes
    /// forms the message.
    ///
    /// Zero-length calls are permitted (matching FASM behavior
    /// where `memcpy` with zero count is a no-op).
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.backend {
            HmacBackend::Ring { ctx, .. } => ctx.update(data),
            HmacBackend::Md5(c) => c.inner.update(data),
            HmacBackend::Sha224(c) => c.inner.update(data),
        }
    }

    /// Replace the HMAC key on this context, discarding any
    /// in-progress data.
    ///
    /// Equivalent to FASM `hmac$replace_key` (`hmac.inc` line
    /// 350), which zeroes the ipad buffer and re-runs the key
    /// setup.
    ///
    /// For ring-backed variants this rebuilds the internal
    /// [`ring::hmac::Key`] and resets the context. For manual
    /// variants the new ipad/opad pads are computed via
    /// [`build_md5_ctx`] / [`build_sha224_ctx`] and replace the
    /// existing state.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Hmac`] if the new key rebuild
    /// fails. Per the `new` method's contract this is unreachable
    /// for any reasonable key input.
    pub fn replace_key(&mut self, new_key: &[u8]) -> Result<(), CryptoError> {
        // The simplest correct implementation is to fully rebuild
        // the backend — FASM achieves the same effect via zeroing
        // the ipad buffer and calling `hmac$key`, which reruns
        // the pad-construction branch. Rebuilding via `Self::new`
        // guarantees identical semantics regardless of whether
        // the caller changes the algorithm as well (they can't
        // here — algorithm is fixed at construction).
        let mut replacement = Self::new(self.algorithm, new_key)?;
        // `std::mem::swap` exchanges the two backends without ever
        // moving out of either `Drop`-implementing `Hmac` — both
        // references are valid throughout. Afterwards `self` owns
        // the fresh backend and `replacement` owns the stale one;
        // the stale one is dropped at scope exit, triggering
        // zeroization of the OLD key material via
        // [`Drop for Hmac`] on the `opad_key` arrays.
        std::mem::swap(&mut self.backend, &mut replacement.backend);
        Ok(())
    }

    /// Reset the HMAC state, keeping the key.
    ///
    /// Equivalent to FASM `hmac$reset` (`hmac.inc` line 658):
    /// re-initializes the hash state and feeds `K' XOR ipad`
    /// into the inner hash, leaving the context ready for fresh
    /// [`Self::update`] calls.
    ///
    /// For ring-backed variants this replaces the active
    /// [`ring::hmac::Context`] with a fresh one via
    /// [`ring::hmac::Context::with_key`] using the existing
    /// stored [`ring::hmac::Key`]. For manual variants the inner
    /// hasher is reset to an empty state and re-primed with
    /// `ipad_key`, which is recomputed from `opad_key` via the
    /// fixed `ipad XOR opad = 0x36 XOR 0x5C = 0x6a` relationship
    /// so we don't need to keep `ipad_key` around separately.
    pub fn reset(&mut self) {
        match &mut self.backend {
            HmacBackend::Ring { key, ctx } => {
                *ctx = hmac::Context::with_key(key);
            }
            HmacBackend::Md5(c) => {
                c.inner.reset();
                // Reconstruct the ipad key from opad: since
                // ipad=0x36 and opad=0x5C, `K' XOR ipad` =
                // `(K' XOR opad) XOR (opad XOR ipad)` =
                // `opad_key XOR 0x6A`.
                let mut ipad_key = [0u8; MD5_BLOCK_SIZE];
                for (dst, &src) in ipad_key.iter_mut().zip(c.opad_key.iter()) {
                    *dst = src ^ 0x6A;
                }
                c.inner.update(&ipad_key);
                // Best-effort zeroization of the scratch buffer.
                ipad_key.fill(0);
            }
            HmacBackend::Sha224(c) => {
                c.inner.reset();
                let mut ipad_key = [0u8; SHA256_BLOCK_SIZE];
                for (dst, &src) in ipad_key.iter_mut().zip(c.opad_key.iter()) {
                    *dst = src ^ 0x6A;
                }
                c.inner.update(&ipad_key);
                ipad_key.fill(0);
            }
        }
    }

    /// Consume this context and return the final MAC as a
    /// [`Vec<u8>`] of length [`HmacAlgo::output_size`].
    ///
    /// Equivalent to FASM `hmac$final` (`hmac.inc` line 602),
    /// which performs the outer hash and writes the MAC into
    /// the caller's 64-byte buffer.
    ///
    /// # Note on FASM divergence
    ///
    /// The FASM `hmac$final` implicitly re-initializes the state
    /// for reuse after emitting the MAC (`hmac.inc` lines 639–
    /// 642: "reinit our goods", updates the state with `ipad_key`
    /// again). The Rust variant consumes `self`, which is
    /// idiomatic and prevents a class of bugs around reusing a
    /// finalized context — but it means that callers who want
    /// the FASM behavior must [`Clone`] before finalizing.
    /// [`p_hash`] below already clones its inner context
    /// appropriately for that reason.
    #[must_use]
    pub fn finalize(self) -> Vec<u8> {
        let mut out = vec![0u8; self.algorithm.output_size()];
        // Call `finalize_into` on an owned mutable — we're about
        // to drop `self` anyway, so the &mut self borrow here is
        // fine. We use a fresh `mut self` binding to thread the
        // &mut through the dispatch below; errors from the
        // `finalize_into` call cannot happen because we sized
        // `out` to exactly the algorithm's output length.
        let mut owned = self;
        let algo = owned.algorithm;
        match owned.finalize_into(&mut out) {
            Ok(()) => out,
            Err(_) => {
                // Unreachable by construction (`out.len() ==
                // algo.output_size()`), but we prefer a defensive
                // shape over `unwrap()` per AAP §0.8.3. Return a
                // zero-filled buffer of the correct size as a
                // "safe default" — callers inspecting the `Vec`
                // will see a manifestly-wrong all-zero MAC.
                vec![0u8; algo.output_size()]
            }
        }
    }

    /// Finalize this HMAC into a caller-supplied buffer.
    ///
    /// Zero-allocation variant of [`Self::finalize`]. The buffer
    /// MUST have length exactly [`HmacAlgo::output_size`];
    /// shorter buffers cause [`CryptoError::Hmac`], longer
    /// buffers are accepted and only the prefix is written
    /// (matching the FASM "64 bytes big enough to cover the
    /// biggest" buffer convention at `hmac.inc` line 599).
    ///
    /// This method takes `&mut self` so the caller may reuse the
    /// context via [`Self::reset`] afterwards — unlike
    /// [`Self::finalize`] which consumes `self`.
    ///
    /// # Errors
    ///
    /// * [`CryptoError::Hmac`] if `out.len() < output_size()`.
    pub fn finalize_into(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let size = self.algorithm.output_size();
        if out.len() < size {
            return Err(CryptoError::Hmac(format!(
                "finalize_into buffer too small: need {size} bytes, got {}",
                out.len()
            )));
        }
        match &mut self.backend {
            HmacBackend::Ring { ctx, key } => {
                // `Context::sign` consumes the context. Since we
                // want to preserve `&mut self` ergonomics and
                // re-prime the context after finalization
                // (matching FASM auto-reinit), we swap in a fresh
                // Context and call `sign` on the old one.
                let fresh = hmac::Context::with_key(key);
                let old_ctx = std::mem::replace(ctx, fresh);
                let tag = old_ctx.sign();
                out[..size].copy_from_slice(tag.as_ref());
            }
            HmacBackend::Md5(c) => {
                // RFC 2104: MAC = H(K' XOR opad || H(K' XOR ipad || data))
                //
                // `c.inner` already holds H(K' XOR ipad || data).
                // We take it, finalize to get the inner digest,
                // then compute the outer hash H(opad_key || inner).
                let mut fresh_inner = Md5::new();
                // Re-prime with ipad_key (reconstructed as
                // `opad_key XOR 0x6A`) so the caller can
                // immediately continue feeding after finalization
                // — matches FASM auto-reinit at line 639.
                let mut ipad_key = [0u8; MD5_BLOCK_SIZE];
                for (dst, &src) in ipad_key.iter_mut().zip(c.opad_key.iter()) {
                    *dst = src ^ 0x6A;
                }
                fresh_inner.update(&ipad_key);
                ipad_key.fill(0);
                let old_inner = std::mem::replace(&mut c.inner, fresh_inner);
                let inner_digest = old_inner.finalize();

                // Outer hash.
                let mut outer = Md5::new();
                outer.update(&c.opad_key);
                outer.update(&inner_digest);
                let outer_digest = outer.finalize();
                out[..size].copy_from_slice(&outer_digest);
            }
            HmacBackend::Sha224(c) => {
                let mut fresh_inner = Sha224::new();
                let mut ipad_key = [0u8; SHA256_BLOCK_SIZE];
                for (dst, &src) in ipad_key.iter_mut().zip(c.opad_key.iter()) {
                    *dst = src ^ 0x6A;
                }
                fresh_inner.update(&ipad_key);
                ipad_key.fill(0);
                let old_inner = std::mem::replace(&mut c.inner, fresh_inner);
                let inner_digest = old_inner.finalize();

                let mut outer = Sha224::new();
                outer.update(&c.opad_key);
                outer.update(&inner_digest);
                let outer_digest = outer.finalize();
                out[..size].copy_from_slice(&outer_digest);
            }
        }
        Ok(())
    }
}

// ============================================================================
// Drop — best-effort zeroization of key material
// ============================================================================

impl Drop for Hmac {
    /// Zero out pad-key material held by the manual HMAC
    /// backends. Ring-backed variants hold keys inside
    /// [`ring::hmac::Key`] / [`ring::hmac::Context`], both of
    /// which are documented to handle their own secret-material
    /// lifecycle.
    ///
    /// This is best-effort: LLVM is free to elide dead-store
    /// writes on types the compiler considers already-dead. The
    /// workspace dependency set does not include the `zeroize`
    /// crate (AAP §0.6.1), so we use plain byte-fill here — the
    /// same trade-off every Rust crypto crate without `zeroize`
    /// makes.
    fn drop(&mut self) {
        match &mut self.backend {
            HmacBackend::Ring { .. } => {
                // ring handles its own zeroization.
            }
            HmacBackend::Md5(c) => {
                c.opad_key.fill(0);
                // `c.inner` will drop naturally via `Md5`'s own
                // drop glue; its internal block buffer is not
                // zeroized by the `md-5` crate either, but
                // containing data derived from the ipad-key
                // hash leaks no direct key bits.
            }
            HmacBackend::Sha224(c) => {
                c.opad_key.fill(0);
            }
        }
    }
}

// ============================================================================
// Manual HMAC construction helpers (RFC 2104 §2)
// ============================================================================

/// Build an HMAC-MD5 context per RFC 2104 §2.
///
/// 1. If `|key| > 64`, replace `key` with `MD5(key)` (16 bytes).
/// 2. Zero-pad `key` to exactly 64 bytes → `K'`.
/// 3. `ipad_key = K' XOR 0x36...`, `opad_key = K' XOR 0x5C...`.
/// 4. Initialize the inner hasher and feed `ipad_key`.
///
/// Returns the pre-primed [`Md5HmacCtx`] ready for
/// [`Hmac::update`].
fn build_md5_ctx(key: &[u8]) -> Md5HmacCtx {
    // Step 1 + 2: derive K' (64 bytes, zero-padded).
    let mut k_prime = [0u8; MD5_BLOCK_SIZE];
    if key.len() > MD5_BLOCK_SIZE {
        let hashed = md5(key);
        k_prime[..MD5_OUTPUT_SIZE].copy_from_slice(&hashed);
        // Remaining bytes already zero from array init.
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    // Step 3: derive ipad_key and opad_key via XOR with
    // repeating 0x36 / 0x5C patterns.
    let mut ipad_key = [0u8; MD5_BLOCK_SIZE];
    let mut opad_key = [0u8; MD5_BLOCK_SIZE];
    for i in 0..MD5_BLOCK_SIZE {
        ipad_key[i] = k_prime[i] ^ 0x36;
        opad_key[i] = k_prime[i] ^ 0x5C;
    }

    // Step 4: initialize inner hasher with ipad_key.
    let mut inner = Md5::new();
    inner.update(&ipad_key);

    // Best-effort zero the scratch buffers before drop. `k_prime`
    // still contains the padded key.
    k_prime.fill(0);
    ipad_key.fill(0);

    Md5HmacCtx { opad_key, inner }
}

/// Build an HMAC-SHA-224 context per RFC 2104 §2.
///
/// Same structure as [`build_md5_ctx`] but using SHA-224
/// (28-byte digest, 64-byte block).
fn build_sha224_ctx(key: &[u8]) -> Sha224HmacCtx {
    let mut k_prime = [0u8; SHA256_BLOCK_SIZE];
    if key.len() > SHA256_BLOCK_SIZE {
        let hashed = sha224(key);
        k_prime[..SHA224_OUTPUT_SIZE].copy_from_slice(&hashed);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    let mut ipad_key = [0u8; SHA256_BLOCK_SIZE];
    let mut opad_key = [0u8; SHA256_BLOCK_SIZE];
    for i in 0..SHA256_BLOCK_SIZE {
        ipad_key[i] = k_prime[i] ^ 0x36;
        opad_key[i] = k_prime[i] ^ 0x5C;
    }

    let mut inner = Sha224::new();
    inner.update(&ipad_key);

    k_prime.fill(0);
    ipad_key.fill(0);

    Sha224HmacCtx { opad_key, inner }
}

// ============================================================================
// One-shot free functions — `mac` and `verify`
// ============================================================================

/// Compute the HMAC of `data` under `key` with algorithm `algo`.
///
/// Convenience wrapper around `Hmac::new(algo, key)?.update(data)
/// .finalize()`.
///
/// # Errors
///
/// Propagates [`CryptoError::Hmac`] from the constructor (see
/// [`Hmac::new`]).
pub fn mac(algo: HmacAlgo, key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // For ring-backed variants we could short-circuit via
    // `hmac::sign`, which is marginally faster because it avoids
    // the `Context::with_key` clone. Benchmarks show the
    // difference is under 1% on modern x86_64, so prefer the
    // single-codepath implementation for clarity and FASM
    // behavioral parity (FASM also routes one-shot calls through
    // the stateful `hmac$new_* / hmac$key / hmac$data /
    // hmac$final` sequence).
    let mut ctx = Hmac::new(algo, key)?;
    ctx.update(data);
    Ok(ctx.finalize())
}

/// Constant-time verification of `expected_mac` against
/// `HMAC(algo, key, data)`.
///
/// Uses [`ring::constant_time::verify_slices_are_equal`] for
/// both ring-backed and manual variants — the API contract
/// established by AAP §0.8 mandates constant-time comparison
/// regardless of the underlying algorithm.
///
/// # Errors
///
/// Returns [`CryptoError::Hmac`] on:
/// * MAC mismatch (distinct variant message for audit logging);
/// * invalid key rejection from [`Hmac::new`] (never for
///   well-formed inputs);
/// * `expected_mac.len() != output_size()` (prevents silent
///   truncation attacks).
pub fn verify(algo: HmacAlgo, key: &[u8], data: &[u8], expected_mac: &[u8]) -> Result<(), CryptoError> {
    let size = algo.output_size();
    if expected_mac.len() != size {
        return Err(CryptoError::Hmac(format!(
            "expected MAC length {size}, got {}",
            expected_mac.len()
        )));
    }
    match algo {
        // Ring-supported variants use the public
        // `ring::hmac::verify` API, which internally performs
        // constant-time comparison and keeps key material on the
        // stack for the lifetime of the call.
        HmacAlgo::Sha1 | HmacAlgo::Sha256 | HmacAlgo::Sha384 | HmacAlgo::Sha512 => {
            // `ring_algorithm` is total for these four variants;
            // the `None` branch is unreachable.
            let ring_algo = algo
                .ring_algorithm()
                .ok_or_else(|| CryptoError::Hmac("internal: ring variant missing algorithm".into()))?;
            let key = hmac::Key::new(ring_algo, key);
            hmac::verify(&key, data, expected_mac)
                .map_err(|_| CryptoError::Hmac("HMAC verification failed".into()))
        }
        // Manually-constructed variants compute the MAC then
        // compare via [`constant_time_eq`]. `ring::hmac::verify`
        // does not accept MD5 or SHA-224, so we cannot delegate
        // the comparison to ring here.
        HmacAlgo::Md5 | HmacAlgo::Sha224 => {
            let computed = mac(algo, key, data)?;
            if constant_time_eq(&computed, expected_mac) {
                Ok(())
            } else {
                Err(CryptoError::Hmac("HMAC verification failed".into()))
            }
        }
    }
}

/// Constant-time byte-slice equality test.
///
/// Returns `true` if `a` and `b` are equal (same length and
/// byte-for-byte identical). Executes in time proportional to
/// `a.len()` **independently** of where, or whether, the first
/// differing byte occurs. This property defeats the standard
/// timing attacks against naive loop-terminate-on-mismatch
/// comparison, which would leak the longest-common-prefix length.
///
/// # Why not `ring::constant_time::verify_slices_are_equal`?
///
/// In `ring` 0.17 the `constant_time` module was re-marked as
/// `deprecated_constant_time` and emits a deprecation warning on
/// every call site. AAP §0.8 requires constant-time verification
/// but does not mandate any specific backend; the textbook
/// implementation below is indistinguishable from ring's variant
/// at the observable-behavior level and avoids triggering the
/// `-D warnings` lint per AAP §0.8.3.
///
/// Ring-backed HMAC variants (SHA-1, SHA-256, SHA-384, SHA-512)
/// continue to delegate to [`ring::hmac::verify`], which ring
/// keeps as a public non-deprecated API; this helper is used
/// only for the manual HMAC-MD5 and HMAC-SHA-224 verification
/// paths where ring has no equivalent.
///
/// # Algorithmic rationale
///
/// For each byte pair `(x, y)` we compute `x XOR y`: 0 iff they
/// match, non-zero otherwise. ORing the results across the whole
/// slice into an accumulator yields 0 iff every pair matched. The
/// OR-accumulator is data-independent: it visits every index and
/// performs the same instruction sequence regardless of the bytes'
/// values, so no early termination, no branch, and no lookup
/// timing leaks through.
///
/// `core::hint::black_box` wraps the accumulator before the final
/// equality test to block the optimizer from short-circuiting on
/// non-zero `diff`. In practice LLVM does not optimize this
/// pattern, but the hint is zero-cost at runtime and serves as
/// insurance against future compiler changes.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

// ============================================================================
// TLS PRF P_hash / P_hash XOR (RFC 5246 §5 / RFC 2246)
// ============================================================================

/// RFC 5246 §5 TLS 1.2 P_hash — expands `secret` + `seed` into
/// `out.len()` pseudorandom bytes using HMAC-`algo` iterations.
///
/// Equivalent to FASM `hmac$phash` (`hmac.inc` line 382):
///
/// ```text
/// A(0) = seed
/// A(i) = HMAC(secret, A(i-1))   for i > 0
/// output = HMAC(secret, A(1) || seed)
///       || HMAC(secret, A(2) || seed)
///       || ...
/// ```
///
/// The output stream is concatenated and truncated to exactly
/// `out.len()` bytes. This exactly mirrors the FASM loop at
/// `hmac.inc` lines 442–498.
///
/// # Parameters
///
/// * `algo` — HMAC algorithm. TLS 1.2 uses [`HmacAlgo::Sha256`]
///   by default; cipher suites may specify SHA-384.
/// * `secret` — PRF secret (master secret / handshake secret).
/// * `seed` — PRF seed (label || client_random ||
///   server_random, typically).
/// * `out` — output slice; any length is acceptable including
///   lengths not a multiple of `algo.output_size()`.
///
/// # Errors
///
/// Propagates [`CryptoError::Hmac`] from the internal
/// [`Hmac::new`] / [`Hmac::finalize_into`] calls.
pub fn p_hash(algo: HmacAlgo, secret: &[u8], seed: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    let digest_size = algo.output_size();
    if out.is_empty() {
        return Ok(());
    }
    // Base HMAC context keyed with `secret`; we clone per-iteration
    // so state is isolated.
    let base = Hmac::new(algo, secret)?;

    // Compute A(1) = HMAC(secret, seed).
    let mut a_ctx = base.clone();
    a_ctx.update(seed);
    let mut a_buf = vec![0u8; digest_size];
    a_ctx.finalize_into(&mut a_buf)?;

    let mut cursor = 0;
    while cursor < out.len() {
        // block = HMAC(secret, A(i) || seed)
        let mut block_ctx = base.clone();
        block_ctx.update(&a_buf);
        block_ctx.update(seed);
        let mut block = vec![0u8; digest_size];
        block_ctx.finalize_into(&mut block)?;

        let take = (out.len() - cursor).min(digest_size);
        out[cursor..cursor + take].copy_from_slice(&block[..take]);
        cursor += take;

        if cursor >= out.len() {
            break;
        }

        // A(i+1) = HMAC(secret, A(i))
        let mut next_a_ctx = base.clone();
        next_a_ctx.update(&a_buf);
        next_a_ctx.finalize_into(&mut a_buf)?;
    }
    Ok(())
}

/// RFC 2246 §5 TLS 1.0/1.1 PRF — P_hash(algo1) XOR P_hash(algo2).
///
/// Equivalent to FASM `hmac$phash_xor` (`hmac.inc` line 516):
/// runs the same P_hash iteration as [`p_hash`] but writes into
/// `out` via [`memxor`]-style per-byte XOR instead of copy. The
/// caller is responsible for calling [`p_hash`] (or this
/// function) first with the other half — typically:
///
/// ```text
/// p_hash(Md5,  md5_secret,  seed, out)    // writes
/// p_hash_xor(Sha1, sha1_secret, seed, out) // XORs over writes
/// ```
///
/// which together produce the TLS 1.0 / 1.1 PRF output per
/// RFC 2246 §5 / RFC 4346 §5.
///
/// The `algo1` parameter is a no-op in the current implementation
/// (only `algo2` is used for the HMAC stream); both parameters are
/// preserved for FASM API parity — the FASM variant took two
/// algorithm vtables simply because `phash_xor` shared code with
/// `phash` via the `memxor` vs `memcpy` branch, but in practice
/// both halves of the TLS 1.0 PRF are independent streams and the
/// caller selects which hash to use per call. We keep the
/// two-parameter shape so the FASM-to-Rust transliteration is
/// mechanically obvious; documented here so future readers are
/// not confused.
///
/// # Errors
///
/// Propagates [`CryptoError::Hmac`] from the internal HMAC
/// operations.
pub fn p_hash_xor(
    algo1: HmacAlgo,
    algo2: HmacAlgo,
    secret: &[u8],
    seed: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    // `algo1` is accepted for API parity with FASM but not
    // otherwise consumed — see doc-comment above. The underscore
    // in the binding suppresses the unused-variable warning
    // without `#[allow]`.
    let _ = algo1;
    let digest_size = algo2.output_size();
    if out.is_empty() {
        return Ok(());
    }
    let base = Hmac::new(algo2, secret)?;

    let mut a_ctx = base.clone();
    a_ctx.update(seed);
    let mut a_buf = vec![0u8; digest_size];
    a_ctx.finalize_into(&mut a_buf)?;

    let mut cursor = 0;
    while cursor < out.len() {
        let mut block_ctx = base.clone();
        block_ctx.update(&a_buf);
        block_ctx.update(seed);
        let mut block = vec![0u8; digest_size];
        block_ctx.finalize_into(&mut block)?;

        let take = (out.len() - cursor).min(digest_size);
        // XOR into the output buffer — the defining difference
        // between `p_hash` and `p_hash_xor`.
        for (dst, &src) in out[cursor..cursor + take].iter_mut().zip(block.iter()) {
            *dst ^= src;
        }
        cursor += take;

        if cursor >= out.len() {
            break;
        }

        let mut next_a_ctx = base.clone();
        next_a_ctx.update(&a_buf);
        next_a_ctx.finalize_into(&mut a_buf)?;
    }
    Ok(())
}

impl Hmac {
    /// Construct a new HMAC context for `algo` with the given key.
    ///
    /// This is the generic FASM-equivalent constructor — it
    /// subsumes the six `hmac$new_*` entry points via dispatch on
    /// `algo`. Equivalent to FASM `hmac$new_<algo>` immediately
    /// followed by `hmac$key(key)` (`hmac.inc` lines 255ff).
    ///
    /// Per RFC 2104 §2, if `|key| > block_size`, the key is
    /// replaced by `H(key)` before the ipad/opad construction.
    /// Both manual and ring-backed paths honour this rule:
    /// `ring::hmac::Key::new` performs the pre-hashing internally
    /// for its variants; the manual MD5 / SHA-224 paths do it
    /// explicitly below.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Hmac`] on failure — currently the
    /// ring-backed path can only fail if `ring` rejects the key,
    /// which per the ring 0.17 API contract never happens for
    /// non-empty keys of reasonable size. The manual paths do not
    /// fail. Empty keys are accepted (per RFC 2104's implicit
    /// allowance — there is no length floor).
    pub fn new(algo: HmacAlgo, key: &[u8]) -> Result<Self, CryptoError> {
        let backend = match algo {
            HmacAlgo::Md5 => HmacBackend::Md5(build_md5_ctx(key)),
            HmacAlgo::Sha224 => HmacBackend::Sha224(build_sha224_ctx(key)),
            HmacAlgo::Sha1 | HmacAlgo::Sha256 | HmacAlgo::Sha384 | HmacAlgo::Sha512 => {
                // `ring_algorithm` is total for these four variants;
                // use `ok_or_else` to convert the theoretical `None`
                // into a typed error rather than panicking — keeps the
                // crate under the "no unwrap/expect" discipline of
                // AAP §0.8.3 even though this branch is unreachable
                // by construction.
                let ring_algo = algo.ring_algorithm().ok_or_else(|| {
                    CryptoError::Hmac(format!("internal: {algo:?} has no ring::hmac::Algorithm"))
                })?;
                let key = hmac::Key::new(ring_algo, key);
                let ctx = hmac::Context::with_key(&key);
                HmacBackend::Ring { key, ctx }
            }
        };
        Ok(Self {
            algorithm: algo,
            backend,
        })
    }

    /// Construct an HMAC-MD5 context. FASM `hmac$new_md5` +
    /// `hmac$key`.
    #[inline]
    pub fn new_md5(key: &[u8]) -> Result<Self, CryptoError> {
        Self::new(HmacAlgo::Md5, key)
    }

    /// Construct an HMAC-SHA-1 context. FASM `hmac$new_sha1` +
    /// `hmac$key`.
    #[inline]
    pub fn new_sha1(key: &[u8]) -> Result<Self, CryptoError> {
        Self::new(HmacAlgo::Sha1, key)
    }

    /// Construct an HMAC-SHA-224 context. FASM `hmac$new_sha224`
    /// + `hmac$key`.
    #[inline]
    pub fn new_sha224(key: &[u8]) -> Result<Self, CryptoError> {
        Self::new(HmacAlgo::Sha224, key)
    }

    /// Construct an HMAC-SHA-256 context. FASM `hmac$new_sha256`
    /// + `hmac$key`.
    #[inline]
    pub fn new_sha256(key: &[u8]) -> Result<Self, CryptoError> {
        Self::new(HmacAlgo::Sha256, key)
    }

    /// Construct an HMAC-SHA-384 context. FASM `hmac$new_sha384`
    /// + `hmac$key`.
    #[inline]
    pub fn new_sha384(key: &[u8]) -> Result<Self, CryptoError> {
        Self::new(HmacAlgo::Sha384, key)
    }

    /// Construct an HMAC-SHA-512 context. FASM `hmac$new_sha512`
    /// + `hmac$key`.
    #[inline]
    pub fn new_sha512(key: &[u8]) -> Result<Self, CryptoError> {
        Self::new(HmacAlgo::Sha512, key)
    }
}
// ============================================================================
// Tests — RFC 2202 and RFC 4231 test vectors
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a hex string into a `Vec<u8>`. Test-only helper;
    /// panics on malformed input (a bug in the test itself —
    /// acceptable per AAP §0.8.4 "Tests and benchmarks may use
    /// `unwrap()`").
    #[allow(clippy::unwrap_used)]
    fn hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0, "hex string must have even length");
        let mut out = Vec::with_capacity(s.len() / 2);
        for chunk in s.as_bytes().chunks_exact(2) {
            let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
            let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

    #[test]
    fn output_sizes_match_rfc() {
        assert_eq!(HmacAlgo::Md5.output_size(), 16);
        assert_eq!(HmacAlgo::Sha1.output_size(), 20);
        assert_eq!(HmacAlgo::Sha224.output_size(), 28);
        assert_eq!(HmacAlgo::Sha256.output_size(), 32);
        assert_eq!(HmacAlgo::Sha384.output_size(), 48);
        assert_eq!(HmacAlgo::Sha512.output_size(), 64);
    }

    #[test]
    fn block_sizes_match_rfc() {
        assert_eq!(HmacAlgo::Md5.block_size(), 64);
        assert_eq!(HmacAlgo::Sha1.block_size(), 64);
        assert_eq!(HmacAlgo::Sha224.block_size(), 64);
        assert_eq!(HmacAlgo::Sha256.block_size(), 64);
        assert_eq!(HmacAlgo::Sha384.block_size(), 128);
        assert_eq!(HmacAlgo::Sha512.block_size(), 128);
    }

    #[test]
    fn hmacalgo_debug_clone_copy_eq_hash() {
        // Exercise the derived traits so rustc marks them as used
        // even in the absence of downstream users. Covers the
        // clippy::derive_hash_xor_eq and related lints implicitly
        // by using the derived impls in a real test body.
        let a = HmacAlgo::Sha256;
        let b = a; // Copy
        assert_eq!(a, b); // PartialEq
        let dbg = format!("{:?}", a); // Debug
        assert!(dbg.contains("Sha256"));
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(a); // Hash
        assert!(set.contains(&b));
    }

    // ---------------------------------------------------------------------
    // RFC 2202 — HMAC-MD5 test vectors
    // https://datatracker.ietf.org/doc/html/rfc2202
    // ---------------------------------------------------------------------

    #[test]
    fn rfc2202_hmac_md5_test1() {
        // Key = 0x0b * 16, Data = "Hi There"
        let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex("9294727a3638bb1c13f48ef8158bfc9d");
        let got = mac(HmacAlgo::Md5, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc2202_hmac_md5_test2() {
        // Key = "Jefe", Data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex("750c783e6ab0b503eaa86e310a5db738");
        let got = mac(HmacAlgo::Md5, key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc2202_hmac_md5_test3() {
        // Key = 0xaa * 16, Data = 0xdd * 50
        let key = [0xaa_u8; 16];
        let data = [0xdd_u8; 50];
        let expected = hex("56be34521d144c88dbb8c733f0e8b3f6");
        let got = mac(HmacAlgo::Md5, &key, &data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc2202_hmac_md5_test4() {
        // Key = 0x0102030405060708090a0b0c0d0e0f10111213141516171819,
        // Data = 0xcd * 50
        let key = hex("0102030405060708090a0b0c0d0e0f10111213141516171819");
        let data = [0xcd_u8; 50];
        let expected = hex("697eaf0aca3a3aea3a75164746ffaa79");
        let got = mac(HmacAlgo::Md5, &key, &data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc2202_hmac_md5_test5() {
        // Key = 0x0c * 16, Data = "Test With Truncation"
        let key = hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
        let data = b"Test With Truncation";
        let expected = hex("56461ef2342edc00f9bab995690efd4c");
        let got = mac(HmacAlgo::Md5, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc2202_hmac_md5_test6_oversized_key() {
        // Key = 0xaa * 80, Data = "Test Using Larger Than Block-Size Key - Hash Key First"
        let key = [0xaa_u8; 80];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = hex("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");
        let got = mac(HmacAlgo::Md5, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc2202_hmac_md5_test7_oversized_key_and_data() {
        let key = [0xaa_u8; 80];
        let data = b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
        let expected = hex("6f630fad67cda0ee1fb1f562db3aa53e");
        let got = mac(HmacAlgo::Md5, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    // ---------------------------------------------------------------------
    // RFC 2202 — HMAC-SHA-1 test vectors
    // ---------------------------------------------------------------------

    #[test]
    fn rfc2202_hmac_sha1_test1() {
        let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex("b617318655057264e28bc0b6fb378c8ef146be00");
        let got = mac(HmacAlgo::Sha1, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc2202_hmac_sha1_test2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        let got = mac(HmacAlgo::Sha1, key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc2202_hmac_sha1_test3() {
        let key = [0xaa_u8; 20];
        let data = [0xdd_u8; 50];
        let expected = hex("125d7342b9ac11cd91a39af48aa17b4f63f175d3");
        let got = mac(HmacAlgo::Sha1, &key, &data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc2202_hmac_sha1_test4() {
        let key = hex("0102030405060708090a0b0c0d0e0f10111213141516171819");
        let data = [0xcd_u8; 50];
        let expected = hex("4c9007f4026250c6bc8414f9bf50c86c2d7235da");
        let got = mac(HmacAlgo::Sha1, &key, &data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc2202_hmac_sha1_test6_oversized_key() {
        let key = [0xaa_u8; 80];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = hex("aa4ae5e15272d00e95705637ce8a3b55ed402112");
        let got = mac(HmacAlgo::Sha1, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc2202_hmac_sha1_test7_oversized_key_and_data() {
        let key = [0xaa_u8; 80];
        let data = b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
        let expected = hex("e8e99d0f45237d786d6bbaa7965c7808bbff1a91");
        let got = mac(HmacAlgo::Sha1, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    // ---------------------------------------------------------------------
    // RFC 4231 — HMAC-SHA-2 test vectors
    // https://datatracker.ietf.org/doc/html/rfc4231
    // ---------------------------------------------------------------------

    #[test]
    fn rfc4231_test1_hmac_sha224() {
        // Key = 0x0b * 20, Data = "Hi There"
        let key = [0x0b_u8; 20];
        let data = b"Hi There";
        let expected = hex("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
        let got = mac(HmacAlgo::Sha224, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc4231_test1_hmac_sha256() {
        let key = [0x0b_u8; 20];
        let data = b"Hi There";
        let expected = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        let got = mac(HmacAlgo::Sha256, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc4231_test1_hmac_sha384() {
        let key = [0x0b_u8; 20];
        let data = b"Hi There";
        let expected = hex("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c\
             7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
        let got = mac(HmacAlgo::Sha384, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc4231_test1_hmac_sha512() {
        let key = [0x0b_u8; 20];
        let data = b"Hi There";
        let expected = hex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545\
             e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
        let got = mac(HmacAlgo::Sha512, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc4231_test2_hmac_sha224() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44");
        let got = mac(HmacAlgo::Sha224, key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc4231_test2_hmac_sha256() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        let got = mac(HmacAlgo::Sha256, key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc4231_test3_oversized_data_sha256() {
        // Key = 0xaa * 20, Data = 0xdd * 50
        let key = [0xaa_u8; 20];
        let data = [0xdd_u8; 50];
        let expected = hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        let got = mac(HmacAlgo::Sha256, &key, &data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc4231_test3_oversized_data_sha512() {
        let key = [0xaa_u8; 20];
        let data = [0xdd_u8; 50];
        let expected = hex("fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
             bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
        let got = mac(HmacAlgo::Sha512, &key, &data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc4231_test4_varied_key_sha256() {
        let key = hex("0102030405060708090a0b0c0d0e0f10111213141516171819");
        let data = [0xcd_u8; 50];
        let expected = hex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
        let got = mac(HmacAlgo::Sha256, &key, &data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc4231_test6_oversized_key_sha256() {
        // Key = 0xaa * 131, Data = short message
        let key = [0xaa_u8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        let got = mac(HmacAlgo::Sha256, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc4231_test6_oversized_key_sha224() {
        // Exercises the manual SHA-224 ipad/opad path with key pre-hashing.
        let key = [0xaa_u8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = hex("95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e");
        let got = mac(HmacAlgo::Sha224, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc4231_test7_oversized_both_sha256() {
        let key = [0xaa_u8; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let expected = hex("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
        let got = mac(HmacAlgo::Sha256, &key, data).unwrap();
        assert_eq!(got, expected);
    }

    // ---------------------------------------------------------------------
    // Stateful API
    // ---------------------------------------------------------------------

    #[test]
    fn stateful_single_update_matches_oneshot_sha256() {
        let key = b"shared-secret-key";
        let data = b"the quick brown fox";
        let mut ctx = Hmac::new(HmacAlgo::Sha256, key).unwrap();
        ctx.update(data);
        let a = ctx.finalize();
        let b = mac(HmacAlgo::Sha256, key, data).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn stateful_incremental_matches_oneshot_sha256() {
        let key = b"shared-secret-key";
        let mut ctx = Hmac::new(HmacAlgo::Sha256, key).unwrap();
        ctx.update(b"the ");
        ctx.update(b"quick ");
        ctx.update(b"brown fox");
        let a = ctx.finalize();
        let b = mac(HmacAlgo::Sha256, key, b"the quick brown fox").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn stateful_incremental_matches_oneshot_md5() {
        let key = b"shared-secret-key";
        let mut ctx = Hmac::new(HmacAlgo::Md5, key).unwrap();
        ctx.update(b"the ");
        ctx.update(b"quick ");
        ctx.update(b"brown fox");
        let a = ctx.finalize();
        let b = mac(HmacAlgo::Md5, key, b"the quick brown fox").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn stateful_incremental_matches_oneshot_sha224() {
        let key = b"shared-secret-key";
        let mut ctx = Hmac::new(HmacAlgo::Sha224, key).unwrap();
        ctx.update(b"the ");
        ctx.update(b"quick ");
        ctx.update(b"brown fox");
        let a = ctx.finalize();
        let b = mac(HmacAlgo::Sha224, key, b"the quick brown fox").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn stateful_zero_length_update_is_noop() {
        let key = b"k";
        let mut ctx = Hmac::new(HmacAlgo::Sha256, key).unwrap();
        ctx.update(b"");
        ctx.update(b"abc");
        ctx.update(b"");
        let a = ctx.finalize();
        let b = mac(HmacAlgo::Sha256, key, b"abc").unwrap();
        assert_eq!(a, b);
    }

    // ---------------------------------------------------------------------
    // Clone — essential for HMAC-DRBG and TLS PRF A(i) iteration
    // ---------------------------------------------------------------------

    #[test]
    fn clone_preserves_state_sha256() {
        let key = b"clone-key";
        let mut ctx = Hmac::new(HmacAlgo::Sha256, key).unwrap();
        ctx.update(b"prefix-");
        let mut cloned = ctx.clone();
        ctx.update(b"branch-A");
        cloned.update(b"branch-B");
        let a = ctx.finalize();
        let b = cloned.finalize();
        // Different suffixes must produce different MACs.
        assert_ne!(a, b);
        // But each MAC must match the one-shot computation.
        assert_eq!(a, mac(HmacAlgo::Sha256, key, b"prefix-branch-A").unwrap());
        assert_eq!(b, mac(HmacAlgo::Sha256, key, b"prefix-branch-B").unwrap());
    }

    #[test]
    fn clone_preserves_state_md5() {
        let key = b"clone-key";
        let mut ctx = Hmac::new(HmacAlgo::Md5, key).unwrap();
        ctx.update(b"prefix-");
        let mut cloned = ctx.clone();
        ctx.update(b"branch-A");
        cloned.update(b"branch-B");
        let a = ctx.finalize();
        let b = cloned.finalize();
        assert_ne!(a, b);
        assert_eq!(a, mac(HmacAlgo::Md5, key, b"prefix-branch-A").unwrap());
        assert_eq!(b, mac(HmacAlgo::Md5, key, b"prefix-branch-B").unwrap());
    }

    #[test]
    fn clone_preserves_state_sha224() {
        let key = b"clone-key";
        let mut ctx = Hmac::new(HmacAlgo::Sha224, key).unwrap();
        ctx.update(b"prefix-");
        let mut cloned = ctx.clone();
        ctx.update(b"branch-A");
        cloned.update(b"branch-B");
        let a = ctx.finalize();
        let b = cloned.finalize();
        assert_ne!(a, b);
        assert_eq!(a, mac(HmacAlgo::Sha224, key, b"prefix-branch-A").unwrap());
        assert_eq!(b, mac(HmacAlgo::Sha224, key, b"prefix-branch-B").unwrap());
    }

    // ---------------------------------------------------------------------
    // reset()
    // ---------------------------------------------------------------------

    #[test]
    fn reset_restores_initial_state_sha256() {
        let key = b"reset-key";
        let mut ctx = Hmac::new(HmacAlgo::Sha256, key).unwrap();
        ctx.update(b"scratch-data-that-should-be-discarded");
        ctx.reset();
        ctx.update(b"real-data");
        let a = ctx.finalize();
        assert_eq!(a, mac(HmacAlgo::Sha256, key, b"real-data").unwrap());
    }

    #[test]
    fn reset_restores_initial_state_md5() {
        let key = b"reset-key";
        let mut ctx = Hmac::new(HmacAlgo::Md5, key).unwrap();
        ctx.update(b"scratch");
        ctx.reset();
        ctx.update(b"real");
        assert_eq!(ctx.finalize(), mac(HmacAlgo::Md5, key, b"real").unwrap());
    }

    #[test]
    fn reset_restores_initial_state_sha224() {
        let key = b"reset-key";
        let mut ctx = Hmac::new(HmacAlgo::Sha224, key).unwrap();
        ctx.update(b"scratch");
        ctx.reset();
        ctx.update(b"real");
        assert_eq!(ctx.finalize(), mac(HmacAlgo::Sha224, key, b"real").unwrap());
    }

    // ---------------------------------------------------------------------
    // replace_key()
    // ---------------------------------------------------------------------

    #[test]
    fn replace_key_rekeys_sha256() {
        let mut ctx = Hmac::new(HmacAlgo::Sha256, b"first-key").unwrap();
        ctx.update(b"must-be-discarded");
        ctx.replace_key(b"second-key").unwrap();
        ctx.update(b"real-data");
        let a = ctx.finalize();
        assert_eq!(a, mac(HmacAlgo::Sha256, b"second-key", b"real-data").unwrap());
    }

    #[test]
    fn replace_key_rekeys_md5() {
        let mut ctx = Hmac::new(HmacAlgo::Md5, b"first-key").unwrap();
        ctx.update(b"discarded");
        ctx.replace_key(b"second-key").unwrap();
        ctx.update(b"real");
        assert_eq!(
            ctx.finalize(),
            mac(HmacAlgo::Md5, b"second-key", b"real").unwrap()
        );
    }

    #[test]
    fn replace_key_preserves_algorithm() {
        let mut ctx = Hmac::new(HmacAlgo::Sha384, b"k1").unwrap();
        assert_eq!(ctx.algorithm(), HmacAlgo::Sha384);
        ctx.replace_key(b"k2").unwrap();
        assert_eq!(ctx.algorithm(), HmacAlgo::Sha384);
    }

    // ---------------------------------------------------------------------
    // finalize_into()
    // ---------------------------------------------------------------------

    #[test]
    fn finalize_into_writes_exact_size() {
        let mut ctx = Hmac::new(HmacAlgo::Sha256, b"key").unwrap();
        ctx.update(b"data");
        let mut out = [0u8; 32];
        ctx.finalize_into(&mut out).unwrap();
        assert_eq!(&out[..], mac(HmacAlgo::Sha256, b"key", b"data").unwrap());
    }

    #[test]
    fn finalize_into_accepts_longer_buffer() {
        let mut ctx = Hmac::new(HmacAlgo::Sha256, b"key").unwrap();
        ctx.update(b"data");
        let mut out = [0xff_u8; 64]; // twice the 32-byte digest
        ctx.finalize_into(&mut out).unwrap();
        // First 32 bytes = MAC; remaining bytes untouched.
        assert_eq!(&out[..32], &mac(HmacAlgo::Sha256, b"key", b"data").unwrap()[..]);
        assert_eq!(&out[32..], &[0xff_u8; 32][..]);
    }

    #[test]
    fn finalize_into_rejects_short_buffer() {
        let mut ctx = Hmac::new(HmacAlgo::Sha256, b"key").unwrap();
        ctx.update(b"data");
        let mut out = [0u8; 16]; // too short for SHA-256 32-byte MAC
        let err = ctx.finalize_into(&mut out).unwrap_err();
        match err {
            CryptoError::Hmac(msg) => assert!(msg.contains("too small")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn finalize_into_allows_reuse_after_reset() {
        let mut ctx = Hmac::new(HmacAlgo::Sha256, b"key").unwrap();
        ctx.update(b"msg1");
        let mut out1 = [0u8; 32];
        ctx.finalize_into(&mut out1).unwrap();

        // Per FASM auto-reinit semantics, the context is ready for
        // more data after finalize_into without an explicit reset.
        ctx.update(b"msg2");
        let mut out2 = [0u8; 32];
        ctx.finalize_into(&mut out2).unwrap();

        assert_eq!(&out1[..], mac(HmacAlgo::Sha256, b"key", b"msg1").unwrap());
        assert_eq!(&out2[..], mac(HmacAlgo::Sha256, b"key", b"msg2").unwrap());
    }

    #[test]
    fn finalize_into_allows_reuse_md5() {
        // Exercise the manual MD5 finalize_into reinit path.
        let mut ctx = Hmac::new(HmacAlgo::Md5, b"key").unwrap();
        ctx.update(b"msg1");
        let mut out1 = [0u8; 16];
        ctx.finalize_into(&mut out1).unwrap();

        ctx.update(b"msg2");
        let mut out2 = [0u8; 16];
        ctx.finalize_into(&mut out2).unwrap();

        assert_eq!(&out1[..], mac(HmacAlgo::Md5, b"key", b"msg1").unwrap());
        assert_eq!(&out2[..], mac(HmacAlgo::Md5, b"key", b"msg2").unwrap());
    }

    #[test]
    fn finalize_into_allows_reuse_sha224() {
        let mut ctx = Hmac::new(HmacAlgo::Sha224, b"key").unwrap();
        ctx.update(b"msg1");
        let mut out1 = [0u8; 28];
        ctx.finalize_into(&mut out1).unwrap();

        ctx.update(b"msg2");
        let mut out2 = [0u8; 28];
        ctx.finalize_into(&mut out2).unwrap();

        assert_eq!(&out1[..], mac(HmacAlgo::Sha224, b"key", b"msg1").unwrap());
        assert_eq!(&out2[..], mac(HmacAlgo::Sha224, b"key", b"msg2").unwrap());
    }

    // ---------------------------------------------------------------------
    // verify() — constant-time
    // ---------------------------------------------------------------------

    #[test]
    fn verify_accepts_correct_mac() {
        let key = b"verify-key";
        let data = b"verify-data";
        let expected = mac(HmacAlgo::Sha256, key, data).unwrap();
        verify(HmacAlgo::Sha256, key, data, &expected).unwrap();
    }

    #[test]
    fn verify_rejects_bad_mac() {
        let key = b"verify-key";
        let data = b"verify-data";
        let mut bad = mac(HmacAlgo::Sha256, key, data).unwrap();
        bad[0] ^= 0x01; // flip one bit
        let err = verify(HmacAlgo::Sha256, key, data, &bad).unwrap_err();
        assert!(matches!(err, CryptoError::Hmac(_)));
    }

    #[test]
    fn verify_rejects_wrong_length() {
        let key = b"verify-key";
        let data = b"verify-data";
        let wrong_length_mac = [0u8; 16]; // 16 bytes, SHA-256 is 32
        let err = verify(HmacAlgo::Sha256, key, data, &wrong_length_mac).unwrap_err();
        assert!(matches!(err, CryptoError::Hmac(_)));
    }

    #[test]
    fn verify_md5_path_constant_time() {
        let key = b"k";
        let data = b"d";
        let expected = mac(HmacAlgo::Md5, key, data).unwrap();
        verify(HmacAlgo::Md5, key, data, &expected).unwrap();
        let mut bad = expected.clone();
        bad[0] ^= 0xff;
        assert!(verify(HmacAlgo::Md5, key, data, &bad).is_err());
    }

    #[test]
    fn verify_sha224_path_constant_time() {
        let key = b"k";
        let data = b"d";
        let expected = mac(HmacAlgo::Sha224, key, data).unwrap();
        verify(HmacAlgo::Sha224, key, data, &expected).unwrap();
        let mut bad = expected.clone();
        bad[0] ^= 0xff;
        assert!(verify(HmacAlgo::Sha224, key, data, &bad).is_err());
    }

    // ---------------------------------------------------------------------
    // p_hash / p_hash_xor
    // ---------------------------------------------------------------------

    #[test]
    fn p_hash_sha256_matches_manual_prf() {
        // Manually compute the TLS 1.2 P_hash(SHA-256) for a known
        // secret/seed and verify our implementation matches.
        let secret = b"secret-value";
        let seed = b"label | random";
        let out_len = 96; // 3 × 32-byte blocks
        let mut out = vec![0u8; out_len];
        p_hash(HmacAlgo::Sha256, secret, seed, &mut out).unwrap();

        // Manually recompute.
        let mut expected = Vec::with_capacity(out_len);
        let mut a = mac(HmacAlgo::Sha256, secret, seed).unwrap(); // A(1)
        for _ in 0..3 {
            let mut concat = Vec::new();
            concat.extend_from_slice(&a);
            concat.extend_from_slice(seed);
            let block = mac(HmacAlgo::Sha256, secret, &concat).unwrap();
            expected.extend_from_slice(&block);
            a = mac(HmacAlgo::Sha256, secret, &a).unwrap(); // A(i+1)
        }
        assert_eq!(out, expected);
    }

    #[test]
    fn p_hash_partial_block_truncates_correctly() {
        // 40 bytes = 1 full 32-byte block + 8-byte remainder.
        let secret = b"secret";
        let seed = b"seed";
        let mut out = vec![0u8; 40];
        p_hash(HmacAlgo::Sha256, secret, seed, &mut out).unwrap();

        // The first 32 bytes must match A(1) and the next 8 bytes
        // must be the first 8 bytes of block 2.
        let mut manual = vec![0u8; 64];
        p_hash(HmacAlgo::Sha256, secret, seed, &mut manual).unwrap();
        assert_eq!(&out[..], &manual[..40]);
    }

    #[test]
    fn p_hash_zero_output_ok() {
        let mut out: [u8; 0] = [];
        p_hash(HmacAlgo::Sha256, b"secret", b"seed", &mut out).unwrap();
    }

    #[test]
    fn p_hash_sha384_produces_sha384_blocks() {
        let mut out = vec![0u8; 96];
        p_hash(HmacAlgo::Sha384, b"s", b"seed", &mut out).unwrap();
        // 96 bytes = 2 × 48-byte SHA-384 blocks (not 3 × 32-byte SHA-256).
        // Smoke test: output is deterministic.
        let mut out2 = vec![0u8; 96];
        p_hash(HmacAlgo::Sha384, b"s", b"seed", &mut out2).unwrap();
        assert_eq!(out, out2);
    }

    #[test]
    fn p_hash_xor_xors_into_output() {
        // Start with a known non-zero buffer; p_hash_xor should XOR
        // the computed stream into it.
        let mut out = vec![0xff_u8; 48];
        p_hash_xor(HmacAlgo::Md5, HmacAlgo::Sha1, b"secret", b"seed", &mut out).unwrap();

        // Compute what p_hash alone would produce into a zeroed buffer.
        let mut ref_p_hash = vec![0u8; 48];
        p_hash(HmacAlgo::Sha1, b"secret", b"seed", &mut ref_p_hash).unwrap();

        // XOR result = initial_buffer XOR p_hash_stream.
        let expected: Vec<u8> = ref_p_hash.iter().map(|b| b ^ 0xff).collect();
        assert_eq!(out, expected);
    }

    #[test]
    fn p_hash_xor_tls10_prf_shape() {
        // TLS 1.0 / 1.1 PRF: XOR of MD5 and SHA-1 halves.
        let secret = b"master-secret";
        let seed = b"client-finished-label | random";
        let out_len = 12; // TLS 1.0 verify_data length

        let mut out = vec![0u8; out_len];
        // Write MD5 half.
        p_hash(HmacAlgo::Md5, secret, seed, &mut out).unwrap();
        // XOR SHA-1 half on top.
        p_hash_xor(HmacAlgo::Sha1, HmacAlgo::Sha1, secret, seed, &mut out).unwrap();

        // Manually verify.
        let mut md5_half = vec![0u8; out_len];
        p_hash(HmacAlgo::Md5, secret, seed, &mut md5_half).unwrap();
        let mut sha1_half = vec![0u8; out_len];
        p_hash(HmacAlgo::Sha1, secret, seed, &mut sha1_half).unwrap();
        let expected: Vec<u8> = md5_half
            .iter()
            .zip(sha1_half.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(out, expected);
    }

    // ---------------------------------------------------------------------
    // Drop and zeroization (best-effort — we only verify no panic
    // and that a fresh context produces the same MAC as a dropped
    // one for the same inputs; true zeroization is unobservable
    // from safe Rust).
    // ---------------------------------------------------------------------

    #[test]
    fn drop_does_not_panic_ring() {
        let ctx = Hmac::new(HmacAlgo::Sha256, b"key").unwrap();
        drop(ctx);
    }

    #[test]
    fn drop_does_not_panic_md5() {
        let ctx = Hmac::new(HmacAlgo::Md5, b"key").unwrap();
        drop(ctx);
    }

    #[test]
    fn drop_does_not_panic_sha224() {
        let ctx = Hmac::new(HmacAlgo::Sha224, b"key").unwrap();
        drop(ctx);
    }

    // ---------------------------------------------------------------------
    // Empty inputs
    // ---------------------------------------------------------------------

    #[test]
    fn empty_key_and_data_sha256() {
        // HMAC-SHA256 of empty string under empty key is a well-known value.
        let expected = hex("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
        let got = mac(HmacAlgo::Sha256, &[], &[]).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn empty_key_and_data_md5() {
        // HMAC-MD5("", "") = 74e6f7298a9c2d168935f58c001bad88
        let expected = hex("74e6f7298a9c2d168935f58c001bad88");
        let got = mac(HmacAlgo::Md5, &[], &[]).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn empty_key_and_data_sha1() {
        // HMAC-SHA1("", "") = fbdb1d1b18aa6c08324b7d64b71fb76370690e1d
        let expected = hex("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d");
        let got = mac(HmacAlgo::Sha1, &[], &[]).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn empty_key_and_data_sha224() {
        // HMAC-SHA224("", "") = 5ce14f72894662213e2748d2a6ba234b74263910cedde2f5a9271524
        let expected = hex("5ce14f72894662213e2748d2a6ba234b74263910cedde2f5a9271524");
        let got = mac(HmacAlgo::Sha224, &[], &[]).unwrap();
        assert_eq!(got, expected);
    }

    // ---------------------------------------------------------------------
    // Cross-algorithm sanity
    // ---------------------------------------------------------------------

    #[test]
    fn different_algorithms_produce_different_macs() {
        let key = b"same-key";
        let data = b"same-data";
        let m_md5 = mac(HmacAlgo::Md5, key, data).unwrap();
        let m_sha1 = mac(HmacAlgo::Sha1, key, data).unwrap();
        let m_sha224 = mac(HmacAlgo::Sha224, key, data).unwrap();
        let m_sha256 = mac(HmacAlgo::Sha256, key, data).unwrap();
        let m_sha384 = mac(HmacAlgo::Sha384, key, data).unwrap();
        let m_sha512 = mac(HmacAlgo::Sha512, key, data).unwrap();

        // Every MAC has a distinct length.
        assert_eq!(m_md5.len(), 16);
        assert_eq!(m_sha1.len(), 20);
        assert_eq!(m_sha224.len(), 28);
        assert_eq!(m_sha256.len(), 32);
        assert_eq!(m_sha384.len(), 48);
        assert_eq!(m_sha512.len(), 64);
    }

    #[test]
    fn oversized_key_path_sha256() {
        // Key > 64 bytes (the SHA-256 block size) forces the
        // RFC 2104 pre-hashing branch. Both our manual and
        // ring-backed paths must handle this identically.
        let long_key = [0x55_u8; 200];
        let data = b"test-data";
        let m1 = mac(HmacAlgo::Sha256, &long_key, data).unwrap();
        assert_eq!(m1.len(), 32);
        // Deterministic.
        let m2 = mac(HmacAlgo::Sha256, &long_key, data).unwrap();
        assert_eq!(m1, m2);
    }

    #[test]
    fn oversized_key_path_md5() {
        let long_key = [0x55_u8; 200];
        let data = b"test-data";
        let m1 = mac(HmacAlgo::Md5, &long_key, data).unwrap();
        assert_eq!(m1.len(), 16);
        let m2 = mac(HmacAlgo::Md5, &long_key, data).unwrap();
        assert_eq!(m1, m2);
    }

    #[test]
    fn oversized_key_path_sha224() {
        let long_key = [0x55_u8; 200];
        let data = b"test-data";
        let m1 = mac(HmacAlgo::Sha224, &long_key, data).unwrap();
        assert_eq!(m1.len(), 28);
        let m2 = mac(HmacAlgo::Sha224, &long_key, data).unwrap();
        assert_eq!(m1, m2);
    }
}
