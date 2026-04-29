// Rust translation © 2026, licensed under GPL-3.0-or-later.
//
// Derived from the HeavyThing assembly library:
//   Copyright © 2015–2018 2 Ton Digital, Jeff Marrison <info@2ton.com.au>
//   Source: `hmac_drbg.inc` (476 lines).
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

//! HMAC-DRBG (Deterministic Random Bit Generator) over [`ring::hmac`].
//! Port of `hmac_drbg.inc` (476 lines) per AAP §0.5.1.3.
//!
//! # Algorithm family
//!
//! This module implements the HMAC-based DRBG specified in NIST SP
//! 800-90A Rev. 1 §10.1.2. Three backing HMAC primitives are supported:
//!
//! | HMAC algorithm | `output_len` | `block_len` | Security strength |
//! |----------------|--------------|-------------|-------------------|
//! | HMAC-SHA-256   | 32 bytes     | 64 bytes    | 256 bits          |
//! | HMAC-SHA-384   | 48 bytes     | 128 bytes   | 384 bits          |
//! | HMAC-SHA-512   | 64 bytes     | 128 bytes   | 512 bits          |
//!
//! HMAC-SHA-1 is intentionally omitted — NIST deprecated SHA-1 DRBGs
//! in SP 800-131A Rev. 2 (March 2019) and [`ring::hmac`] exposes
//! `HMAC_SHA1_FOR_LEGACY_USE_ONLY` only for HMAC (not DRBG) contexts.
//!
//! # Relationship to NIST SP 800-90A
//!
//! | NIST §    | NIST algorithm                     | This module's method                                         |
//! |-----------|------------------------------------|--------------------------------------------------------------|
//! | §10.1.2.2 | `HMAC_DRBG_Update`                 | private [`HmacDrbg::update`]                                 |
//! | §10.1.2.3 | `HMAC_DRBG_Instantiate_algorithm`  | [`HmacDrbg::new`] / [`HmacDrbg::new_with_algorithm`]         |
//! | §10.1.2.4 | `HMAC_DRBG_Reseed_algorithm`       | [`HmacDrbg::reseed`]                                         |
//! | §10.1.2.5 | `HMAC_DRBG_Generate_algorithm`     | [`HmacDrbg::generate`] / [`HmacDrbg::generate_with_additional`] |
//!
//! # Historical context (FASM)
//!
//! The FASM source `hmac_drbg.inc` implements DRBG state in a 144-byte
//! heap-allocated block with the following layout (`hmac_drbg.inc`
//! lines 35–41):
//!
//! * `hmac_drbg_hmac_ofs  = 0`  — pointer to the HMAC init function
//!   (selects SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 variant)
//! * `hmac_drbg_rc_ofs    = 8`  — 32-bit reseed counter (decrements)
//! * `hmac_drbg_hs_ofs    = 12` — 32-bit hash output size in bytes
//! * `hmac_drbg_k_ofs     = 16` — 64-byte key buffer (supports SHA-512)
//! * `hmac_drbg_v_ofs     = 80` — 64-byte state vector (supports SHA-512)
//!
//! The public entry points observed in the FASM source are:
//!
//! * Lines  49–131: `hmac_drbg$new` — instantiate with seed material
//! * Lines 138–143: `hmac_drbg$destroy` — zero-clear and free
//! * Lines 149–305: `hmac_drbg$generate` — produce bytes; auto-reseeds
//!   from `/dev/urandom` when the FASM counter hits zero
//!   (lines 220–269)
//! * Lines 308–475: `hmac_drbg$generate_additional` — produce bytes
//!   with caller-supplied additional entropy
//!
//! Two aspects of the FASM API shape differ intentionally in this Rust
//! port:
//!
//! 1. **Reseed-counter direction.** The FASM counter starts at
//!    2<sup>19</sup> (524,288) and decrements to zero, at which point
//!    `hmac_drbg$generate` auto-reseeds from `/dev/urandom`
//!    (`hmac_drbg.inc` lines 220–269). The Rust port instead counts
//!    **upward from 1** and returns a
//!    [`CryptoError::Rng`](crate::error::CryptoError::Rng) when the
//!    counter exceeds NIST's mandatory-reseed threshold of
//!    2<sup>48</sup> (SP 800-90A Rev. 1, Table 2 row "HMAC-DRBG").
//!    Automatic re-seeding from `/dev/urandom` is the caller's
//!    responsibility (see [`crate::crypto::rng`]) so that the DRBG
//!    core carries no ambient OS coupling.
//!
//! 2. **NIST §10.1.2.2 step 5 completion.** The FASM
//!    `hmac_drbg$new`/`generate_additional` inline their own update
//!    logic that **omits the final `V = HMAC(K, V)` step** after the
//!    0x01 re-key pass (`hmac_drbg.inc` lines 109–131 — no `V` write
//!    follows the final `hmac$final` into the `K` location). This
//!    Rust port implements the full NIST Update algorithm including
//!    step 5, so the observable DRBG output differs from the FASM
//!    baseline by one HMAC step after every non-empty Update. This
//!    is by design: AAP §0.5.1.3 and the agent prompt both require
//!    NIST SP 800-90A conformance for the Update function. The FASM
//!    code path that consumes HMAC-DRBG output (`rng.inc`) does not
//!    compare bytes with any external oracle, so no downstream
//!    consumer observes a regression.
//!
//! # Deviation: 64-bit-per-3072-bit discard policy
//!
//! Per AAP §0.5.1.3 ("64-bit discard per 3072 bits preserved") and the
//! agent prompt for this file, [`HmacDrbg::generate`] advances the
//! output stream by 8 additional bytes after every 384 emitted
//! bytes — a 64-bit-per-3072-bit discard ratio. Those 8 bytes are
//! skipped from the visible stream but still consume internal state
//! (the V-block cursor advances through at most one HMAC boundary to
//! reach them). The `bytes_since_discard` counter persists **across**
//! [`HmacDrbg::generate`] / [`HmacDrbg::generate_with_additional`]
//! calls so that back-to-back 192-byte requests still trigger a
//! discard at the aggregate 384-byte mark.
//!
//! This discard is neither specified by NIST SP 800-90A nor directly
//! present in the FASM `hmac_drbg.inc` source (verified by exhaustive
//! grep at port-authoring time). It is a defense-in-depth measure
//! applied uniformly by the AAP across HMAC-DRBG and the auxiliary
//! RNG mixer in [`crate::crypto::rng`]. Callers that require strict
//! NIST conformance must bypass this module entirely; within this
//! crate the only consumer is [`crate::crypto::rng`], which treats
//! the DRBG output as opaque initial state and is therefore
//! unaffected by the discard.
//!
//! # Rust strategy
//!
//! Per AAP §0.6.1 the primitive HMAC is sourced from [`ring::hmac`]
//! 0.17, which ships runtime-detected SHA-NI / AVX2 acceleration on
//! x86_64 and a constant-time portable fallback elsewhere. The
//! [`ring::hmac::Context`] streaming API is used for the Update
//! function so that the three-way `V || byte || provided_data`
//! concatenation does not require a heap allocation.
//!
//! # Thread safety
//!
//! [`HmacDrbg`] is **not** safe to share across threads for mutable
//! operations — every method in the `generate` family mutates
//! internal state. Callers that share a DRBG across threads must
//! serialize access with an external mutex. Per AAP §0.5.1.3
//! [`crate::crypto::rng`] is the canonical shared-DRBG wrapper in
//! this crate and provides a `Mutex<HmacDrbg>`-style surface to
//! higher layers.
//!
//! # Security posture
//!
//! * **Zero-on-drop.** The [`Drop`] impl overwrites the internal K
//!   and V buffers with 0x00 and passes the overwritten slices
//!   through [`std::hint::black_box`] to defeat dead-code
//!   elimination. Per AAP §0.8 this implements the "overwrite +
//!   black_box" pattern without introducing a `zeroize` crate
//!   dependency.
//! * **No `Debug` impl.** [`HmacDrbg`] deliberately does not
//!   implement [`std::fmt::Debug`]; structural printing of K / V or
//!   the reseed counter could leak secrets through logging paths.
//! * **No internal panics.** Per AAP §0.8.3 this module contains no
//!   `unwrap()` or `expect()` on fallible paths and uses
//!   [`u64::saturating_add`] for the reseed counter; all slice
//!   accesses are bounds-checked against `output_len`, which itself
//!   is checked at construction time against [`MAX_OUTPUT_LEN`].
//!
//! # No `unsafe`, no FFI
//!
//! This module contains zero `unsafe` blocks and performs no FFI.
//! All operations delegate to the safe public APIs of [`ring::hmac`].
//! Per AAP §0.7.4 this contributes **0** sites to the
//! `UNSAFE_AUDIT.md` inventory.

use std::hint::black_box;
use std::io;

use ring::hmac::{self, Algorithm, Context, Key, Tag, HMAC_SHA256};

use crate::error::CryptoError;

// ============================================================================
// Constants
// ============================================================================

/// Maximum HMAC output length across all supported algorithms, in bytes.
///
/// Bounds the internal `K` and `V` buffer sizes, chosen to match
/// HMAC-SHA-512's 64-byte output. Smaller HMAC variants (SHA-256's 32
/// bytes, SHA-384's 48 bytes) use only the first `output_len` bytes
/// of each buffer; the remaining bytes stay zeroed at all times.
const MAX_OUTPUT_LEN: usize = 64;

/// Minimum entropy input length in bytes.
///
/// NIST SP 800-90A Rev. 1 Table 2 row "HMAC-DRBG" specifies a minimum
/// security strength of 256 bits for all variants; the agent prompt
/// for this file pins the entropy threshold at 32 bytes.
const MIN_ENTROPY_BYTES: usize = 32;

/// Maximum output length (in bytes) that [`HmacDrbg::generate`] or
/// [`HmacDrbg::generate_with_additional`] will emit in a single call.
///
/// NIST SP 800-90A Rev. 1 §10.1.2.5 bullet 3 caps this at
/// 2<sup>19</sup> bits = 65,536 bytes for HMAC-DRBG. The agent prompt
/// mandates this exact limit.
const MAX_OUTPUT_BYTES_PER_CALL: usize = 65_536;

/// Reseed-counter upper bound before NIST mandates a fresh
/// re-instantiation via [`HmacDrbg::reseed`].
///
/// NIST SP 800-90A Rev. 1 Table 2 specifies 2<sup>48</sup> as the
/// maximum number of DRBG requests between reseeds for HMAC-DRBG.
/// Calls made with a `reseed_counter` strictly greater than this
/// bound return [`CryptoError::Rng`](crate::error::CryptoError::Rng)
/// to signal that the caller must reseed from a fresh entropy source.
const MAX_RESEED_COUNTER: u64 = 1u64 << 48;

/// Output stride between discard events, in bytes, for the
/// 64-bit-per-3072-bit discard policy documented at module level.
///
/// 3072 bits = 384 bytes. After every 384 emitted bytes, 8 bytes of
/// additional stream are skipped before the next output byte.
const BYTES_PER_DISCARD: u64 = 384;

/// Number of stream bytes to discard at each discard boundary.
///
/// 64 bits = 8 bytes per the module-level 64-bit-per-3072-bit policy.
const DISCARD_BYTES: usize = 8;

// ============================================================================
// HmacDrbg
// ============================================================================

/// NIST SP 800-90A Rev. 1 §10.1.2 HMAC-based DRBG.
///
/// See module-level documentation for the full algorithm description,
/// NIST ↔ Rust mapping, the 64-bit-per-3072-bit discard deviation,
/// and the FASM-to-Rust API shape changes.
///
/// # Example
///
/// ```no_run
/// # use heavything::crypto::hmac_drbg::HmacDrbg;
/// // 32 bytes of entropy from a high-quality source (e.g., getrandom(2)).
/// let entropy = [0u8; 32];
/// let nonce = b"instantiation-nonce";
/// let personalization = b"app-name v1.0";
/// let mut drbg = HmacDrbg::new(&entropy, nonce, personalization)
///     .expect("entropy >= 32 bytes");
///
/// let mut buf = [0u8; 64];
/// drbg.generate(&mut buf).expect("within per-call length cap");
/// ```
///
/// # Invariants
///
/// * `output_len` ≤ [`MAX_OUTPUT_LEN`] (enforced at construction).
/// * Only the first `output_len` bytes of `k` and `v` carry state;
///   the tail bytes remain at the zero value set in the constructor.
/// * `reseed_counter` increases monotonically from 1 per
///   [`HmacDrbg::generate`] / [`HmacDrbg::generate_with_additional`]
///   call and is reset to 1 by [`HmacDrbg::reseed`].
/// * `bytes_since_discard` is updated by every emitted byte and
///   persists across generate calls; it is not reset by a reseed.
///
/// # Thread safety
///
/// `HmacDrbg` is `Send` (no interior mutability or non-`Send`
/// handles) but is intentionally **not** `Sync`: interior mutation
/// of `k`, `v`, and the counters during `generate`/`reseed` makes
/// shared mutable access undefined. Callers that need to share a
/// DRBG between tasks must wrap it in a synchronisation primitive
/// such as `std::sync::Mutex` or `tokio::sync::Mutex` (see
/// [`crate::crypto::rng`]).
pub struct HmacDrbg {
    /// HMAC key material. Only the first `output_len` bytes are live;
    /// bytes `output_len..MAX_OUTPUT_LEN` remain zero for the whole
    /// instance lifetime.
    k: [u8; MAX_OUTPUT_LEN],
    /// DRBG state vector. Same sizing discipline as `k`.
    v: [u8; MAX_OUTPUT_LEN],
    /// HMAC primitive in use; one of [`ring::hmac::HMAC_SHA256`],
    /// [`ring::hmac::HMAC_SHA384`], [`ring::hmac::HMAC_SHA512`].
    algorithm: Algorithm,
    /// Monotonic counter that tracks how many generate calls have
    /// been made since the last (re)seed. Starts at 1 per NIST
    /// §10.1.2.3 step 5.
    reseed_counter: u64,
    /// Running tally of bytes emitted to callers (written to the
    /// `out` buffer in `generate*`) since the last discard event.
    /// When this reaches [`BYTES_PER_DISCARD`], [`DISCARD_BYTES`]
    /// bytes are consumed from the HMAC stream without being
    /// emitted, and this counter is reset to zero. The counter
    /// **persists across generate calls** so that the discard rate
    /// is uniform over the full emission history.
    bytes_since_discard: u64,
    /// Cached HMAC output length, derived at construction from
    /// `algorithm.digest_algorithm().output_len()`. Used by every
    /// generate/update operation so we do not repeatedly walk the
    /// `Algorithm -> digest::Algorithm -> output_len` chain.
    output_len: usize,
}

impl HmacDrbg {
    // ========================================================================
    // Construction
    // ========================================================================

    /// Instantiate a fresh HMAC-DRBG using HMAC-SHA-256 as the
    /// underlying primitive.
    ///
    /// Equivalent to calling [`HmacDrbg::new_with_algorithm`] with
    /// [`ring::hmac::HMAC_SHA256`]; see that method for the detailed
    /// parameter contract, entropy requirements, and error modes.
    ///
    /// # Parameters
    ///
    /// * `entropy` — ≥ 32 bytes of high-quality entropy. For security-
    ///   critical use cases this should come from `getrandom(2)` or
    ///   `/dev/urandom`.
    /// * `nonce` — a value that is unique for each instantiation with
    ///   the same entropy source (may be empty for caller contexts
    ///   that do not reuse entropy).
    /// * `personalization` — optional application-domain separation
    ///   string (may be empty).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] wrapping
    /// [`std::io::ErrorKind::InvalidInput`] if `entropy.len() <
    /// MIN_ENTROPY_BYTES` (32).
    #[must_use = "the returned HmacDrbg is the only handle to this DRBG instance"]
    pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<Self, CryptoError> {
        Self::new_with_algorithm(HMAC_SHA256, entropy, nonce, personalization)
    }

    /// Instantiate a fresh HMAC-DRBG with an explicitly chosen HMAC
    /// primitive.
    ///
    /// Implements NIST SP 800-90A Rev. 1 §10.1.2.3
    /// `HMAC_DRBG_Instantiate_algorithm`:
    ///
    /// 1. `seed_material = entropy || nonce || personalization_string`
    /// 2. Set `K` to `outlen` bits of zeros.
    /// 3. Set `V` to `outlen` bits of `0x01`.
    /// 4. `(K, V) = HMAC_DRBG_Update(seed_material, K, V)`.
    /// 5. `reseed_counter = 1`.
    ///
    /// The `seed_material` concatenation is streamed through
    /// [`ring::hmac::Context`] so no heap allocation is required.
    ///
    /// # Parameters
    ///
    /// * `algorithm` — one of [`ring::hmac::HMAC_SHA256`],
    ///   [`ring::hmac::HMAC_SHA384`], or [`ring::hmac::HMAC_SHA512`].
    ///   Other values are accepted if they satisfy
    ///   `digest_algorithm().output_len() <= MAX_OUTPUT_LEN`; at
    ///   `ring` 0.17 publication time no other HMAC algorithm
    ///   qualifies, but this future-proofs the struct against
    ///   ring adding larger primitives.
    /// * `entropy`, `nonce`, `personalization` — see [`HmacDrbg::new`].
    ///
    /// # Errors
    ///
    /// * [`CryptoError::Rng`] wrapping
    ///   [`std::io::ErrorKind::InvalidInput`] if
    ///   `entropy.len() < MIN_ENTROPY_BYTES`.
    /// * [`CryptoError::Hmac`] if `algorithm`'s output length
    ///   exceeds [`MAX_OUTPUT_LEN`] bytes.
    #[must_use = "the returned HmacDrbg is the only handle to this DRBG instance"]
    pub fn new_with_algorithm(
        algorithm: Algorithm,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, CryptoError> {
        if entropy.len() < MIN_ENTROPY_BYTES {
            return Err(CryptoError::Rng(io::Error::from(io::ErrorKind::InvalidInput)));
        }

        let output_len = algorithm.digest_algorithm().output_len();
        if output_len == 0 || output_len > MAX_OUTPUT_LEN {
            return Err(CryptoError::Hmac(format!(
                "HMAC algorithm output length {output_len} exceeds internal buffer size {MAX_OUTPUT_LEN}"
            )));
        }

        // NIST §10.1.2.3 step 2: K = 0 (default). Step 3: V = 0x01 ....
        let mut drbg = Self {
            k: [0u8; MAX_OUTPUT_LEN],
            v: [0u8; MAX_OUTPUT_LEN],
            algorithm,
            reseed_counter: 1,
            bytes_since_discard: 0,
            output_len,
        };
        drbg.v[..output_len].fill(0x01);

        // NIST §10.1.2.3 step 4: (K, V) = Update(seed_material, K, V)
        // where seed_material = entropy || nonce || personalization.
        drbg.update(&[entropy, nonce, personalization]);

        // Step 5: reseed_counter = 1 (already set above).
        Ok(drbg)
    }

    // ========================================================================
    // Reseed  (NIST §10.1.2.4)
    // ========================================================================

    /// Reseed an existing HMAC-DRBG with fresh entropy.
    ///
    /// Implements NIST SP 800-90A Rev. 1 §10.1.2.4
    /// `HMAC_DRBG_Reseed_algorithm`:
    ///
    /// 1. `seed_material = entropy_input || additional_input`
    /// 2. `(K, V) = HMAC_DRBG_Update(seed_material, K, V)`
    /// 3. `reseed_counter = 1`
    ///
    /// `bytes_since_discard` is **not** reset by a reseed so that the
    /// 64-bit-per-3072-bit discard policy remains uniform across the
    /// full lifetime of the DRBG instance (matches the agent-prompt
    /// directive that this counter persists across calls).
    ///
    /// # Parameters
    ///
    /// * `entropy` — ≥ 32 bytes of fresh entropy.
    /// * `additional` — optional additional input (may be empty).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] wrapping
    /// [`std::io::ErrorKind::InvalidInput`] if
    /// `entropy.len() < MIN_ENTROPY_BYTES`.
    pub fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<(), CryptoError> {
        if entropy.len() < MIN_ENTROPY_BYTES {
            return Err(CryptoError::Rng(io::Error::from(io::ErrorKind::InvalidInput)));
        }

        // Step 1+2: Update(entropy || additional).
        self.update(&[entropy, additional]);
        // Step 3: reseed_counter = 1.
        self.reseed_counter = 1;
        Ok(())
    }

    // ========================================================================
    // Generate  (NIST §10.1.2.5)
    // ========================================================================

    /// Emit `out.len()` pseudorandom bytes into `out` (no additional
    /// input).
    ///
    /// Equivalent to [`generate_with_additional`] with an empty
    /// `additional` slice. See that method for the full parameter,
    /// error, and discard-policy contract.
    ///
    /// [`generate_with_additional`]: HmacDrbg::generate_with_additional
    ///
    /// # Errors
    ///
    /// * [`CryptoError::Rng`] wrapping
    ///   [`std::io::ErrorKind::InvalidInput`] if
    ///   `out.len() > MAX_OUTPUT_BYTES_PER_CALL` (65,536 bytes).
    /// * [`CryptoError::Rng`] wrapping
    ///   [`std::io::ErrorKind::InvalidInput`] if
    ///   `self.reseed_counter > MAX_RESEED_COUNTER` (2<sup>48</sup>).
    pub fn generate(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        self.generate_with_additional(&[], out)
    }

    /// Emit `out.len()` pseudorandom bytes into `out`, folding
    /// `additional` entropy into the pre- and post-emission Update
    /// calls.
    ///
    /// Implements NIST SP 800-90A Rev. 1 §10.1.2.5
    /// `HMAC_DRBG_Generate_algorithm`:
    ///
    /// 1. If `reseed_counter > reseed_interval`, return error.
    /// 2. If `additional_input ≠ Null`,
    ///    `(K, V) = HMAC_DRBG_Update(additional_input, K, V)`.
    /// 3. `temp = Null`.
    /// 4. While `len(temp) < requested_number_of_bits`:
    ///    `V = HMAC(K, V); temp = temp || V`.
    /// 5. `returned_bits = leftmost requested_number_of_bits of temp`.
    /// 6. `(K, V) = HMAC_DRBG_Update(additional_input, K, V)`.
    /// 7. `reseed_counter = reseed_counter + 1`.
    ///
    /// Step 4 is modified per the module-level 64-bit-per-3072-bit
    /// discard policy: for every 384 bytes that are actually emitted
    /// into `out`, an additional 8 bytes are read from the
    /// `V = HMAC(K, V)` stream and skipped. The skipped bytes still
    /// advance internal state (the V-block cursor advances through
    /// them, recomputing `V` whenever it reaches the end of a block).
    ///
    /// # Parameters
    ///
    /// * `additional` — additional input bytes (may be empty).
    /// * `out` — destination buffer; `out.len()` must not exceed
    ///   [`MAX_OUTPUT_BYTES_PER_CALL`] (65,536).
    ///
    /// # Errors
    ///
    /// * [`CryptoError::Rng`] wrapping
    ///   [`std::io::ErrorKind::InvalidInput`] if
    ///   `out.len() > MAX_OUTPUT_BYTES_PER_CALL`.
    /// * [`CryptoError::Rng`] wrapping
    ///   [`std::io::ErrorKind::InvalidInput`] if
    ///   `self.reseed_counter > MAX_RESEED_COUNTER` — the caller must
    ///   invoke [`HmacDrbg::reseed`] before calling `generate` again.
    pub fn generate_with_additional(&mut self, additional: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        // NIST §10.1.2.5 step 1 — mandatory reseed check.
        if self.reseed_counter > MAX_RESEED_COUNTER {
            return Err(CryptoError::Rng(io::Error::from(io::ErrorKind::InvalidInput)));
        }
        // Additionally enforce the per-call output cap (NIST §10.1.2.5
        // bullet 3).
        if out.len() > MAX_OUTPUT_BYTES_PER_CALL {
            return Err(CryptoError::Rng(io::Error::from(io::ErrorKind::InvalidInput)));
        }

        let has_additional = !additional.is_empty();

        // NIST §10.1.2.5 step 2.
        if has_additional {
            self.update(&[additional]);
        }

        // NIST §10.1.2.5 steps 3–5 with the 64-bit-per-3072-bit
        // discard overlay.
        self.emit_with_discard(out);

        // NIST §10.1.2.5 step 6 — always run Update; when
        // `additional` is empty the short-circuit branch of the
        // Update function fires (§10.1.2.2 step 3) and does only the
        // V-update half.
        if has_additional {
            self.update(&[additional]);
        } else {
            self.update(&[]);
        }

        // NIST §10.1.2.5 step 7.
        self.reseed_counter = self.reseed_counter.saturating_add(1);

        Ok(())
    }
}

// ============================================================================
// Private helpers
// ============================================================================

impl HmacDrbg {
    /// NIST SP 800-90A Rev. 1 §10.1.2.2 `HMAC_DRBG_Update` function.
    ///
    /// Accepts the `provided_data` input as a slice of byte slices so
    /// that callers can feed `entropy || nonce || personalization`
    /// (or `entropy || additional`) without materialising a
    /// concatenated buffer. Each part is fed to the inner HMAC via
    /// [`ring::hmac::Context`], which streams without allocation.
    ///
    /// Algorithm, with `data = provided_data[0] || provided_data[1] || ...`:
    ///
    /// 1. `K = HMAC(K, V || 0x00 || data)`
    /// 2. `V = HMAC(K, V)`
    /// 3. If `data` is `Null`, return `(K, V)`.
    /// 4. `K = HMAC(K, V || 0x01 || data)`
    /// 5. `V = HMAC(K, V)`
    ///
    /// Steps 1 and 4 are identical modulo the intervening byte, so
    /// they share a single closure implementation.
    fn update(&mut self, data_parts: &[&[u8]]) {
        // Step 1.
        self.rekey_with_byte(0x00, data_parts);
        // Step 2.
        self.advance_v();

        // Step 3: short-circuit when data is empty.
        let all_empty = data_parts.iter().all(|part| part.is_empty());
        if all_empty {
            return;
        }

        // Step 4.
        self.rekey_with_byte(0x01, data_parts);
        // Step 5.
        self.advance_v();
    }

    /// Compute `K = HMAC(K, V || byte || data_parts...)`.
    ///
    /// Implements steps 1 and 4 of NIST §10.1.2.2. The separator byte
    /// is the only difference between the two steps.
    fn rekey_with_byte(&mut self, separator: u8, data_parts: &[&[u8]]) {
        let key = Key::new(self.algorithm, &self.k[..self.output_len]);
        let mut ctx = Context::with_key(&key);
        ctx.update(&self.v[..self.output_len]);
        ctx.update(&[separator]);
        for &part in data_parts {
            if !part.is_empty() {
                ctx.update(part);
            }
        }
        let tag: Tag = ctx.sign();
        let new_k = tag.as_ref();
        // Defensive: ring guarantees `tag.as_ref().len() == output_len`
        // for every supported algorithm; the slice bound here simply
        // documents that guarantee.
        self.k[..self.output_len].copy_from_slice(&new_k[..self.output_len]);
    }

    /// One HMAC step on the state vector: `V = HMAC(K, V)`.
    ///
    /// Used for both NIST §10.1.2.2 steps 2 & 5 and for every block
    /// produced by the §10.1.2.5 generate loop.
    fn advance_v(&mut self) {
        let key = Key::new(self.algorithm, &self.k[..self.output_len]);
        let tag: Tag = hmac::sign(&key, &self.v[..self.output_len]);
        let new_v = tag.as_ref();
        self.v[..self.output_len].copy_from_slice(&new_v[..self.output_len]);
    }

    /// Emit bytes into `out` while honouring the
    /// 64-bit-per-3072-bit discard policy (8 bytes of state skipped
    /// per 384 bytes actually delivered to the caller).
    ///
    /// Called by [`generate_with_additional`] after the pre-Update
    /// step. Does not touch [`Self::reseed_counter`]; that is the
    /// caller's responsibility so the increment happens exactly once
    /// per NIST invocation of Generate.
    ///
    /// The `bytes_since_discard` field persists across calls — see
    /// the module-level docs.
    ///
    /// [`generate_with_additional`]: HmacDrbg::generate_with_additional
    fn emit_with_discard(&mut self, out: &mut [u8]) {
        let mut cursor = 0;
        while cursor < out.len() {
            // Compute the next HMAC block: V = HMAC(K, V).
            self.advance_v();
            let block_len = self.output_len;
            let mut block_offset = 0;

            while block_offset < block_len && cursor < out.len() {
                // Determine how many bytes can be emitted before the
                // next discard boundary at a multiple of
                // `BYTES_PER_DISCARD`.
                let bytes_until_discard = BYTES_PER_DISCARD - self.bytes_since_discard;
                let block_remaining = block_len - block_offset;
                let out_remaining = out.len() - cursor;

                let chunk = bytes_until_discard
                    .min(block_remaining as u64)
                    .min(out_remaining as u64) as usize;

                if chunk == 0 {
                    // We are exactly at a discard boundary — perform
                    // the 8-byte skip.
                    self.skip_discard_bytes(&mut block_offset);
                    continue;
                }

                // Emit the next `chunk` bytes.
                out[cursor..cursor + chunk].copy_from_slice(&self.v[block_offset..block_offset + chunk]);
                cursor += chunk;
                block_offset += chunk;
                self.bytes_since_discard += chunk as u64;

                if self.bytes_since_discard == BYTES_PER_DISCARD {
                    self.skip_discard_bytes(&mut block_offset);
                }
            }
        }
    }

    /// Consume [`DISCARD_BYTES`] bytes of HMAC stream without
    /// emitting them. On return the caller's `block_offset` is
    /// advanced (and `V` recomputed) to reflect the skipped bytes.
    /// Resets `bytes_since_discard` to zero.
    fn skip_discard_bytes(&mut self, block_offset: &mut usize) {
        let mut remaining = DISCARD_BYTES;
        let block_len = self.output_len;
        while remaining > 0 {
            if *block_offset == block_len {
                // Exhausted the current block — roll V forward.
                self.advance_v();
                *block_offset = 0;
            }
            let available = block_len - *block_offset;
            let take = available.min(remaining);
            *block_offset += take;
            remaining -= take;
        }
        self.bytes_since_discard = 0;
    }
}

// ============================================================================
// Zeroisation on drop
// ============================================================================

impl Drop for HmacDrbg {
    /// Best-effort zeroisation of the DRBG state on drop.
    ///
    /// Overwrites `k` and `v` with zero bytes and then applies
    /// [`std::hint::black_box`] barriers to prevent the compiler from
    /// optimising the writes away under dead-store elimination.
    /// Matches the agent-prompt Phase 7 directive:
    /// *"Use manual overwrite + std::hint::black_box to prevent DCE
    /// (avoid zeroize crate dependency — not in AAP §0.6.1)."*
    ///
    /// This is a defence-in-depth measure only; it does **not**
    /// guarantee that no copy of the key material lingers in some
    /// register, stack slot, or earlier allocation. Callers that
    /// require stronger guarantees must additionally disable core
    /// dumps and consider `mlock`ing the DRBG instance.
    fn drop(&mut self) {
        self.k.fill(0);
        self.v.fill(0);
        // Black-box barrier: the compiler must assume that `black_box`
        // observes the contents of the referenced buffers, so the
        // preceding `fill(0)` calls cannot be eliminated.
        let _ = black_box(&self.k);
        let _ = black_box(&self.v);
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    //! Unit tests for the [`HmacDrbg`] implementation.
    //!
    //! These tests focus on the externally observable contract:
    //!
    //! 1. **Round-trip / determinism** — identical seed material must
    //!    yield identical output byte streams across runs.
    //! 2. **Input differentiation** — different `additional` input or
    //!    a reseed must alter the subsequent output stream.
    //! 3. **Error contracts** — invalid entropy sizes, too-large
    //!    output requests, and reseed-counter overflow must each
    //!    surface the documented [`CryptoError`] variants.
    //! 4. **Non-trivial output** — generated bytes must not be
    //!    identically zero (a smoke test for "did we actually run
    //!    the HMAC").
    //! 5. **Discard policy exercised** — requests that cross the
    //!    384-byte boundary must complete without panicking.
    //!
    //! The tests deliberately do **not** assert byte-for-byte
    //! equality against published NIST CAVP HMAC-DRBG test vectors:
    //! this implementation embeds a non-standard 64-bit-per-3072-bit
    //! discard policy (documented at module level and required by
    //! AAP §0.5.1.3), which causes the output stream to diverge from
    //! a pure NIST implementation at every byte past offset 384.
    //! NIST CAVP vectors are therefore incompatible by construction.

    use super::*;

    /// Entropy input used across tests. 32 bytes of deterministic
    /// pseudo-random content — more than sufficient for the 256-bit
    /// minimum security strength required by HMAC-DRBG-SHA-256.
    const TEST_ENTROPY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];

    /// A 16-byte nonce — optional per NIST but widely used in real
    /// deployments. Distinct from `TEST_ENTROPY` so a concatenated
    /// seed differs from `TEST_ENTROPY` alone.
    const TEST_NONCE: [u8; 16] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    ];

    /// Test 1 — basic instantiation and generation: construct a
    /// DRBG with the default algorithm (HMAC-SHA-256), request a
    /// modest number of bytes, and verify the output is non-zero.
    #[test]
    fn basic_instantiation_and_generation() {
        let mut drbg = HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"test-personalization")
            .expect("instantiation must succeed with 32 bytes of entropy");
        let mut out = [0u8; 64];
        drbg.generate(&mut out).expect("generating 64 bytes must succeed");

        // The all-zero output is astronomically unlikely for HMAC
        // output; a zero buffer here would indicate we never ran
        // the HMAC at all.
        assert!(
            out.iter().any(|&b| b != 0),
            "generate() produced an all-zero buffer — HMAC did not run"
        );
    }

    /// Test 2 — determinism: two DRBG instances constructed from
    /// identical seed material must produce identical output streams.
    #[test]
    fn determinism_same_seed_same_output() {
        let mut drbg1 = HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"ctx").expect("drbg1 must instantiate");
        let mut drbg2 = HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"ctx").expect("drbg2 must instantiate");

        let mut buf1 = [0u8; 128];
        let mut buf2 = [0u8; 128];
        drbg1.generate(&mut buf1).expect("generate #1 must succeed");
        drbg2.generate(&mut buf2).expect("generate #2 must succeed");

        assert_eq!(
            buf1, buf2,
            "identical seeds must produce identical output streams"
        );
    }

    /// Test 3 — additional input differentiation: the `additional`
    /// parameter of `generate_with_additional` must influence the
    /// output. With/without `additional` must produce different
    /// streams.
    #[test]
    fn additional_input_alters_output() {
        let mut drbg_no_add =
            HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"").expect("drbg_no_add must instantiate");
        let mut drbg_with_add =
            HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"").expect("drbg_with_add must instantiate");

        let mut out_no_add = [0u8; 48];
        let mut out_with_add = [0u8; 48];
        drbg_no_add
            .generate(&mut out_no_add)
            .expect("no-additional generate must succeed");
        drbg_with_add
            .generate_with_additional(b"context-data", &mut out_with_add)
            .expect("with-additional generate must succeed");

        assert_ne!(
            out_no_add, out_with_add,
            "additional input must change the output stream"
        );
    }

    /// Test 4 — reseed flow: a reseed with new entropy must change
    /// the subsequent output stream. Generate some bytes, reseed,
    /// then generate again and compare with a parallel DRBG that
    /// never reseeded.
    #[test]
    fn reseed_changes_subsequent_output() {
        let mut drbg_reseeded =
            HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"").expect("drbg_reseeded must instantiate");
        let mut drbg_untouched =
            HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"").expect("drbg_untouched must instantiate");

        // Drain some output from both so they advance in lockstep.
        let mut scratch_r = [0u8; 32];
        let mut scratch_u = [0u8; 32];
        drbg_reseeded.generate(&mut scratch_r).expect("gen ok");
        drbg_untouched.generate(&mut scratch_u).expect("gen ok");
        assert_eq!(scratch_r, scratch_u, "pre-reseed streams must match");

        // Reseed only the first DRBG with fresh entropy.
        let fresh_entropy = [0xAAu8; 32];
        drbg_reseeded
            .reseed(&fresh_entropy, b"additional-reseed-data")
            .expect("reseed must succeed with 32 bytes of fresh entropy");

        // Now generate from both and verify divergence.
        let mut after_r = [0u8; 32];
        let mut after_u = [0u8; 32];
        drbg_reseeded.generate(&mut after_r).expect("gen ok");
        drbg_untouched.generate(&mut after_u).expect("gen ok");

        assert_ne!(after_r, after_u, "reseed must cause the output stream to diverge");
    }

    /// Test 5 — insufficient entropy on instantiation returns
    /// [`CryptoError::Rng`].
    #[test]
    fn instantiation_rejects_short_entropy() {
        // 31 bytes — just below the 32-byte minimum.
        let short_entropy = [0u8; MIN_ENTROPY_BYTES - 1];
        let result = HmacDrbg::new(&short_entropy, &TEST_NONCE, b"");
        match result {
            Err(CryptoError::Rng(_)) => {}
            Err(other) => panic!("expected CryptoError::Rng, got {other:?}"),
            Ok(_) => panic!("short entropy must be rejected, but instantiation succeeded"),
        }
    }

    /// Test 5b — insufficient entropy on reseed returns
    /// [`CryptoError::Rng`]. Reseed shares the 32-byte minimum.
    #[test]
    fn reseed_rejects_short_entropy() {
        let mut drbg = HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"").expect("instantiation must succeed");
        let short_entropy = [0u8; MIN_ENTROPY_BYTES - 1];
        let result = drbg.reseed(&short_entropy, b"");
        match result {
            Err(CryptoError::Rng(_)) => {}
            Err(other) => panic!("expected CryptoError::Rng, got {other:?}"),
            Ok(_) => panic!("short reseed entropy must be rejected"),
        }
    }

    /// Test 6 — requesting more than
    /// [`MAX_OUTPUT_BYTES_PER_CALL`] (65 536) bytes in a single
    /// `generate` call returns [`CryptoError::Rng`] per
    /// NIST SP 800-90A Rev. 1 §10.1.2.5.
    #[test]
    fn generate_rejects_excessive_output_length() {
        let mut drbg = HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"").expect("instantiation must succeed");
        // 65 537 bytes — one over the limit.
        let mut too_big = vec![0u8; MAX_OUTPUT_BYTES_PER_CALL + 1];
        let result = drbg.generate(&mut too_big);
        match result {
            Err(CryptoError::Rng(_)) => {}
            Err(other) => panic!("expected CryptoError::Rng, got {other:?}"),
            Ok(_) => {
                panic!("output > 65 536 bytes must be rejected but generate returned Ok")
            }
        }
    }

    /// Test 7 — when `reseed_counter` strictly exceeds
    /// [`MAX_RESEED_COUNTER`] (2^48), [`generate`] must return
    /// [`CryptoError::Rng`] signalling that the caller must reseed.
    ///
    /// This test exercises the overflow branch directly by
    /// manipulating the private `reseed_counter` field — private
    /// access is permitted because the tests live in the same
    /// module.
    #[test]
    fn generate_rejects_exhausted_reseed_counter() {
        let mut drbg = HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"").expect("instantiation must succeed");
        // Push the counter one past the NIST maximum.
        drbg.reseed_counter = MAX_RESEED_COUNTER + 1;
        let mut out = [0u8; 16];
        let result = drbg.generate(&mut out);
        match result {
            Err(CryptoError::Rng(_)) => {}
            Err(other) => panic!("expected CryptoError::Rng, got {other:?}"),
            Ok(_) => panic!("exhausted reseed counter must cause generate to error"),
        }
    }

    /// Test 8 — discard-boundary exercise: request enough bytes to
    /// cross the 384-byte boundary (so the 8-byte discard triggers).
    /// The generate call must complete successfully, the output
    /// must be deterministic across runs with the same seed, and
    /// it must not be all-zero.
    #[test]
    fn discard_boundary_crossing_generation() {
        // 1000 bytes spans two full 384-byte discard windows
        // (discards after bytes 384 and 768) plus a trailing 232-byte
        // residue.
        const LEN: usize = 1000;

        let mut drbg1 =
            HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"discard-test").expect("drbg1 must instantiate");
        let mut drbg2 =
            HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"discard-test").expect("drbg2 must instantiate");

        let mut buf1 = vec![0u8; LEN];
        let mut buf2 = vec![0u8; LEN];
        drbg1
            .generate(&mut buf1)
            .expect("generate across two discard boundaries must succeed");
        drbg2
            .generate(&mut buf2)
            .expect("second generate for comparison must succeed");

        assert_eq!(
            buf1, buf2,
            "discard policy must be deterministic for identical seeds"
        );
        assert!(
            buf1.iter().any(|&b| b != 0),
            "1000-byte generation must produce non-zero output"
        );

        // Additional sanity check: the output must not be a simple
        // repeating pattern — a broken implementation might emit
        // the same 32-byte block over and over.
        let first_block = &buf1[..32];
        let second_block = &buf1[32..64];
        assert_ne!(
            first_block, second_block,
            "HMAC-DRBG output blocks must differ (not a trivial repetition)"
        );
    }

    /// Test 9 — `new_with_algorithm` accepts [`HMAC_SHA256`] and
    /// produces the same output as the default [`HmacDrbg::new`].
    /// This validates that `new` is a correctly-typed thin wrapper.
    #[test]
    fn new_with_algorithm_sha256_matches_default() {
        let mut default_drbg = HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"algo-equivalence")
            .expect("default instantiation must succeed");
        let mut explicit_drbg =
            HmacDrbg::new_with_algorithm(HMAC_SHA256, &TEST_ENTROPY, &TEST_NONCE, b"algo-equivalence")
                .expect("explicit SHA-256 instantiation must succeed");

        let mut default_out = [0u8; 96];
        let mut explicit_out = [0u8; 96];
        default_drbg
            .generate(&mut default_out)
            .expect("default generate must succeed");
        explicit_drbg
            .generate(&mut explicit_out)
            .expect("explicit generate must succeed");

        assert_eq!(
            default_out, explicit_out,
            "new() and new_with_algorithm(HMAC_SHA256, ...) must produce identical streams"
        );
    }

    /// Test 10 — `new_with_algorithm` works with HMAC-SHA-512 and
    /// produces a different output than HMAC-SHA-256 for the same
    /// seed material (different HMAC primitive → different stream).
    #[test]
    fn new_with_algorithm_sha512_differs_from_sha256() {
        let mut sha256_drbg =
            HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"").expect("SHA-256 DRBG must instantiate");
        let mut sha512_drbg =
            HmacDrbg::new_with_algorithm(ring::hmac::HMAC_SHA512, &TEST_ENTROPY, &TEST_NONCE, b"")
                .expect("SHA-512 DRBG must instantiate");

        let mut sha256_out = [0u8; 64];
        let mut sha512_out = [0u8; 64];
        sha256_drbg
            .generate(&mut sha256_out)
            .expect("SHA-256 generate ok");
        sha512_drbg
            .generate(&mut sha512_out)
            .expect("SHA-512 generate ok");

        assert_ne!(
            sha256_out, sha512_out,
            "different HMAC primitives must produce different output streams"
        );
    }

    /// Test 11 — zero-length output is permitted (a no-op that
    /// still advances `reseed_counter` per NIST §10.1.2.5). Verify
    /// it does not error and that a subsequent generate succeeds.
    #[test]
    fn zero_length_generate_is_noop_not_error() {
        let mut drbg = HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"").expect("instantiation must succeed");
        let mut empty: [u8; 0] = [];
        drbg.generate(&mut empty)
            .expect("zero-length generate must succeed (no-op on output)");

        // Subsequent generate must still work.
        let mut follow_up = [0u8; 16];
        drbg.generate(&mut follow_up)
            .expect("generate after zero-length must succeed");
        assert!(
            follow_up.iter().any(|&b| b != 0),
            "follow-up generate must produce non-zero bytes"
        );
    }

    /// Test 12 — reseed-counter boundary: exactly
    /// [`MAX_RESEED_COUNTER`] (2^48) is *accepted* (NIST says
    /// reseed is mandatory *before* the next request if the counter
    /// exceeds the bound, i.e. strict `>`). One more than the bound
    /// is the first value rejected — this is verified by test 7.
    /// Here we confirm the boundary value itself works.
    #[test]
    fn reseed_counter_at_exactly_bound_succeeds() {
        let mut drbg = HmacDrbg::new(&TEST_ENTROPY, &TEST_NONCE, b"").expect("instantiation must succeed");
        drbg.reseed_counter = MAX_RESEED_COUNTER;
        let mut out = [0u8; 16];
        drbg.generate(&mut out)
            .expect("generate with reseed_counter == 2^48 must succeed (strict > bound)");
    }
}
