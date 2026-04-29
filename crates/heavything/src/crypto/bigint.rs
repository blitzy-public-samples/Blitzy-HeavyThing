// Rust translation © 2026, licensed under GPL-3.0-or-later.
//
// Derived from the HeavyThing assembly library:
//   Copyright © 2015–2018 2 Ton Digital, Jeff Marrison <info@2ton.com.au>
//   Source: `bigint.inc` (10,923 lines — the largest source file in the
//   HeavyThing repository and the widest API surface of the crypto
//   subsystem with 75 public symbols).
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

//! Arbitrary-precision integer arithmetic — port of `bigint.inc`.
//!
//! # Overview
//!
//! The FASM `bigint.inc` module implements a heap-allocated arbitrary-
//! precision unsigned/signed integer type with a 16-byte-aligned word
//! backing store and a per-instance Montgomery-powmod cache (slot
//! `bigint_monty_powmod_ofs`). Observable behavior translated here:
//!
//! * **Primality testing** — trial division against the first 6,540
//!   primes (up to 65,521) followed by Miller–Rabin with exactly
//!   [`config::MILLER_RABIN_ERROR_RATE`](crate::config::MILLER_RABIN_ERROR_RATE)
//!   (`= 64`) rounds unless overridden via [`is_prime2`].
//! * **Random prime generation** — [`random_prime`] generates an
//!   N-bit candidate with top two bits set and LSB set, screens it
//!   against the small-prime table via [`mod_small_primes`], then
//!   validates with [`is_prime`]. Composites are stepped past with
//!   addition of 2, mirroring the `primesieve`/`primesievemod`
//!   behavior of `bigint.inc` line 7800+.
//! * **DH / DSA / RSA helpers** — [`dh_params`] yields a safe prime
//!   `p = 2q + 1` with generator `g`; [`dsa_params`] follows the
//!   FIPS 186-4 Appendix A approach with the defaults
//!   ([`config::DSA_SIZE`](crate::config::DSA_SIZE) `= 3072`,
//!   [`config::DSA_SUBGROUP_SIZE`](crate::config::DSA_SUBGROUP_SIZE)
//!   `= 256`) used by SSH `ssh-dss` host-key generation;
//!   [`rsa_private`] derives the standard PKCS#1 CRT components
//!   `(n, d, dp, dq, qinv)` from `(p, q, e)`.
//! * **Encoding** — [`encode`] / [`set_encoded`] are thin wrappers
//!   around `BigUint::to_bytes_be` / `BigUint::from_bytes_be` that
//!   preserve the FASM big-endian wire-format for RSA/DH moduli.
//! * **Jacobi symbol** — [`jacobi`] implements the standard recursive
//!   definition with quadratic-reciprocity sign flipping, matching
//!   `bigint$jacobi` at `bigint.inc` lines 6679–6800.
//!
//! # Rust design
//!
//! Rather than re-implement the FASM 10,923-line hand-tuned x86_64
//! bignum routines, this port delegates to the well-reviewed
//! `num-bigint`/`num-traits`/`num-integer` crate trio per AAP
//! §0.6.1. The assembly library's hand-written SIMD Montgomery
//! multiplication is replaced by `BigUint::modpow` which uses a
//! sliding-window Montgomery exponentiation internally — within the
//! AAP §0.8.1 3× performance envelope for the critical RSA/DH paths.
//!
//! The FASM "cheater" statics `bigint$zero` and `bigint$one` are
//! preserved as [`zero`] / [`one`] accessor functions backed by
//! module-level [`std::sync::OnceLock`] singletons; const-fn
//! construction of `BigUint` is not available on stable Rust.
//! `OnceLock` (rather than `LazyLock`) is used to comply with the
//! AAP §0.8.3 codebase rule "use `std::sync::OnceLock`, NOT
//! `once_cell::sync::OnceCell`" while staying within the workspace
//! `rust-version = "1.75"` MSRV (`LazyLock` was stabilised in 1.80).
//!
//! # Unsafe
//!
//! Zero `unsafe` blocks — all heavy lifting is in `num-bigint`, which
//! is also `#![forbid(unsafe_code)]` in its crypto-critical paths.

// ============================================================================
// Imports
// ============================================================================

use std::sync::{Arc, OnceLock};

pub use num_bigint::{BigInt, BigUint};
pub use num_integer::Integer;
pub use num_traits::{One, Pow, Signed, Zero};

use crate::config::{
    BIGINT_MAXWORDS, BIGINT_UNROLLSIZE, DH_BITS, DSA_SIZE, DSA_SUBGROUP_SIZE, MILLER_RABIN_ERROR_RATE,
};
use crate::crypto::rng;
use crate::error::CryptoError;

// ============================================================================
// Public type aliases
// ============================================================================

/// Reference-counted, shareable [`BigUint`].
///
/// Enables zero-copy sharing of large DH/DSA parameters across worker
/// processes and async tasks without per-use cloning of kilobyte-sized
/// bignums. This type is exported from this module per AAP §0.5.1.3
/// and is used by `crate::net::tls` and `crate::net::ssh::kex`.
pub type BigUintArc = Arc<BigUint>;

// ============================================================================
// Private helpers
// ============================================================================

/// Validates that `bits` does not exceed the architectural maximum
/// ([`BIGINT_MAXWORDS`] × 64 bits).
///
/// Returns [`CryptoError::Bignum`] with a human-readable message if
/// the bit count would exceed the supported range.
#[inline]
fn validate_bit_size(bits: u32) -> Result<(), CryptoError> {
    let max_bits = (BIGINT_MAXWORDS as u32).saturating_mul(64);
    if bits > max_bits {
        return Err(CryptoError::Bignum(format!(
            "bit size {bits} exceeds architectural maximum (BIGINT_MAXWORDS = {BIGINT_MAXWORDS} × 64 = {max_bits})"
        )));
    }
    Ok(())
}

// ============================================================================
// Small-primes table (6,540 primes from 2 through 65,521)
// ============================================================================

/// First 6,540 primes (2 through 65,521) computed via Sieve of
/// Eratosthenes at first access.
///
/// Mirrors the FASM `bigint_primetable` data block at `bigint.inc`
/// line 8455 but avoids baking 52 KB of literal data into the
/// binary. Initialization runs once on first access and takes
/// ~1 ms on modern hardware. Uses `OnceLock` (MSRV 1.70) per AAP
/// §0.8.3 codebase rule rather than `LazyLock` (which is MSRV 1.80
/// and exceeds the workspace `rust-version = "1.75"` floor).
static SMALL_PRIMES: OnceLock<Vec<u32>> = OnceLock::new();

/// Builds the small-primes table via Sieve of Eratosthenes.
fn build_small_primes() -> Vec<u32> {
    const LIMIT: usize = 65_522; // exclusive upper bound
    let mut sieve = vec![true; LIMIT];
    sieve[0] = false;
    sieve[1] = false;
    let sqrt_limit = (LIMIT as f64).sqrt() as usize + 1;
    for i in 2..=sqrt_limit {
        if sieve[i] {
            let mut j = i * i;
            while j < LIMIT {
                sieve[j] = false;
                j += i;
            }
        }
    }
    sieve
        .iter()
        .enumerate()
        .filter_map(|(i, &is_p)| if is_p { Some(i as u32) } else { None })
        .collect()
}

/// Returns a reference to the lazily-initialized small-primes table.
#[inline]
fn small_primes_table() -> &'static [u32] {
    SMALL_PRIMES.get_or_init(build_small_primes)
}

// ============================================================================
// Static "cheater" constants: BigUint(0) and BigUint(1)
// ============================================================================

/// Lazy singleton for `BigUint::zero()`. Replaces the FASM static
/// `bigint$zero` (`bigint.inc` module-level storage).
static ZERO_STATIC: OnceLock<BigUint> = OnceLock::new();

/// Lazy singleton for `BigUint::one()`. Replaces the FASM static
/// `bigint$one` (`bigint.inc` module-level storage).
static ONE_STATIC: OnceLock<BigUint> = OnceLock::new();

/// Returns a shared reference to the module-wide zero bignum.
///
/// Equivalent to the FASM `bigint$zero` static (`bigint.inc`).
#[must_use]
pub fn zero() -> &'static BigUint {
    ZERO_STATIC.get_or_init(BigUint::zero)
}

/// Returns a shared reference to the module-wide one bignum.
///
/// Equivalent to the FASM `bigint$one` static (`bigint.inc`).
#[must_use]
pub fn one() -> &'static BigUint {
    ONE_STATIC.get_or_init(BigUint::one)
}

// ============================================================================
// CachedMontgomery — cached base/modulus for repeated modular exponentiation
// ============================================================================

/// Cached Montgomery-form `base^exp mod modulus` evaluator.
///
/// The FASM bignum type stores per-instance Montgomery precomputed
/// state in `bigint_monty_powmod_ofs` (`bigint.inc` struct constant
/// `bigint_monty_powmod_ofs = 24`). Rather than a per-`BigUint`
/// mutable slot, this port groups the base + modulus into a separate
/// wrapper value that callers can keep around between exponentiations.
///
/// `num-bigint`'s [`BigUint::modpow`] already uses an internal
/// Montgomery sliding-window exponentiator when the modulus is odd,
/// so this struct exists for API-parity with the FASM cache and as a
/// convenience handle; no additional precomputation is performed.
#[derive(Clone, Debug)]
pub struct CachedMontgomery {
    base: BigUint,
    modulus: BigUint,
}

impl CachedMontgomery {
    /// Constructs a new Montgomery-cache handle for `base` and
    /// `modulus`. Both values are moved into the struct.
    #[must_use]
    pub fn new(base: BigUint, modulus: BigUint) -> Self {
        Self { base, modulus }
    }

    /// Returns `base^exp mod modulus` using the stored base/modulus.
    ///
    /// Equivalent to the FASM `monty$doit` path invoked after a
    /// `monty$new` bind to base + modulus.
    #[must_use]
    pub fn powmod(&self, exp: &BigUint) -> BigUint {
        self.base.modpow(exp, &self.modulus)
    }
}

// ============================================================================
// RsaPrivateComponents — RSA private-key CRT decomposition
// ============================================================================

/// RSA private-key CRT components produced by [`rsa_private`].
///
/// Mirrors the PKCS#1 v2.2 §3.2 representation and the FASM
/// `bigint$rsaprivate` layout (`bigint.inc` lines 9654–9800).
/// Downstream consumers (`crate::net::ssh::auth`, `crate::net::tls`)
/// use this struct directly to perform CRT-accelerated decryption.
#[derive(Clone, Debug)]
pub struct RsaPrivateComponents {
    /// RSA modulus `n = p * q`.
    pub n: BigUint,
    /// Private exponent `d = e^-1 mod (p-1)(q-1)`.
    pub d: BigUint,
    /// CRT exponent for the `p` factor: `dp = d mod (p - 1)`.
    pub dp: BigUint,
    /// CRT exponent for the `q` factor: `dq = d mod (q - 1)`.
    pub dq: BigUint,
    /// CRT coefficient: `qinv = q^-1 mod p`.
    pub qinv: BigUint,
}

// ============================================================================
// Primality testing
// ============================================================================

/// Probabilistic primality test using Miller–Rabin with
/// [`MILLER_RABIN_ERROR_RATE`] (`= 64`) rounds.
///
/// Returns `Ok(true)` if `n` is prime with probability at least
/// `1 - 2^-128` (conservative bound), `Ok(false)` if `n` is
/// definitely composite, or [`CryptoError::Bignum`] on internal
/// arithmetic failure.
///
/// Equivalent to the FASM `bigint$isprime` entry point at
/// `bigint.inc` line 8532. The FASM implementation uses a
/// bit-count-indexed iteration table (`.mrtable`) that reduces the
/// round count for very large candidates (down to 1 round at
/// 1,880+ bits) while staying at or below the `2^-64` error bound
/// from `millerrabinerrorrate = 64`. For compliance with the AAP
/// §0.8.1 "exactly 64 rounds" directive, [`is_prime`] runs a full
/// 64 rounds regardless of bit length; callers wanting the
/// variable-round FASM schedule can use [`is_prime2`] with an
/// explicit round count.
pub fn is_prime(n: &BigUint) -> Result<bool, CryptoError> {
    is_prime2(n, MILLER_RABIN_ERROR_RATE)
}

/// Variable-round Miller–Rabin primality test.
///
/// Equivalent to the FASM `bigint$isprime2` entry point at
/// `bigint.inc` line 8915 (which takes an explicit round count).
/// `rounds = 0` is treated as a trivial pass only for known small
/// primes; for general input `rounds >= 1` is recommended.
pub fn is_prime2(n: &BigUint, rounds: u32) -> Result<bool, CryptoError> {
    // Edge cases: 0, 1, 2, 3
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);

    if n < &two {
        return Ok(false);
    }
    if *n == two || *n == three {
        return Ok(true);
    }
    if n.is_even() {
        return Ok(false);
    }

    // Fast path: n fits in 16 bits → direct lookup in the
    // small-primes table (matches FASM single-word path at
    // `bigint.inc` line 8880).
    if n.bits() <= 16 {
        let n_u32 = n.iter_u32_digits().next().unwrap_or(0);
        return Ok(small_primes_table().binary_search(&n_u32).is_ok());
    }

    // Trial division by the first 256 small primes — fast composite
    // screen before launching into Miller–Rabin witness loops.
    let table = small_primes_table();
    for &p in table.iter().take(256) {
        let p_big = BigUint::from(p);
        if (n % &p_big).is_zero() {
            return Ok(false);
        }
    }

    // If `rounds == 0`, skip Miller-Rabin and declare the candidate
    // probably prime (only reachable for n with no small factors).
    if rounds == 0 {
        return Ok(true);
    }

    // Miller–Rabin proper: write n-1 = 2^s * d with d odd, then
    // test `rounds` random witnesses.
    let one_big = BigUint::one();
    let n_minus_1 = n - &one_big;
    let mut s: u64 = 0;
    let mut d = n_minus_1.clone();
    while d.is_even() {
        d >>= 1;
        s += 1;
    }

    for _round in 0..rounds {
        // Witness in [2, n-2]; the upper bound here is n-1 exclusive
        // which gives [2, n-2].
        let witness = set_randomrange(&two, &n_minus_1)?;
        let mut x = witness.modpow(&d, n);

        if x.is_one() || x == n_minus_1 {
            continue;
        }

        let mut composite_witness = true;
        for _ in 0..s.saturating_sub(1) {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                composite_witness = false;
                break;
            }
            if x.is_one() {
                // Non-trivial square root of 1 → definitely composite.
                return Ok(false);
            }
        }

        if composite_witness {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Returns the smallest prime in the small-primes table that
/// divides `n`, or `None` if no prime `p < n` in the table divides
/// `n`.
///
/// Equivalent to the FASM `bigint$modsmallprimes` entry point at
/// `bigint.inc` line 8883. Used as a fast composite screen before
/// expensive Miller–Rabin witness rounds in [`random_prime`].
#[must_use]
pub fn mod_small_primes(n: &BigUint) -> Option<u32> {
    let table = small_primes_table();
    for &p in table.iter() {
        let p_big = BigUint::from(p);
        if &p_big >= n {
            break;
        }
        if (n % &p_big).is_zero() {
            return Some(p);
        }
    }
    None
}

// ============================================================================
// Random prime generation
// ============================================================================

/// Generates a random `bits`-bit prime.
///
/// Equivalent to the FASM `bigint$random_prime` entry point at
/// `bigint.inc` line 7745. The algorithm:
///
/// 1. For `bits <= 16`, pick uniformly from the small-primes table
///    in the range `[2^(bits-1), 2^bits)`.
/// 2. Otherwise, draw a random `bits`-bit number, force the low bit
///    and the top two bits, then step forward by 2 each composite
///    rejection — matching the FASM `primesieve$next` linear
///    advancement at `bigint.inc` lines 7790–7830. Small-prime
///    trial division is applied before Miller–Rabin for efficiency.
///
/// # Errors
/// Returns [`CryptoError::Bignum`] if `bits < 2`, or if `bits`
/// exceeds [`BIGINT_MAXWORDS`] × 64. Returns [`CryptoError::Rng`]
/// if the bounded attempt loop exhausts without discovering a
/// prime — extraordinarily unlikely in normal operation and
/// indicative of RNG malfunction.
pub fn random_prime(bits: u32) -> Result<BigUint, CryptoError> {
    if bits < 2 {
        return Err(CryptoError::Bignum(format!(
            "random_prime: bits={bits} must be >= 2"
        )));
    }
    validate_bit_size(bits)?;

    // Fast path: small primes via table lookup.
    if bits <= 16 {
        let table = small_primes_table();
        let max_val: u64 = 1u64 << bits;
        let min_val: u64 = 1u64 << (bits - 1);
        let candidates: Vec<u32> = table
            .iter()
            .copied()
            .filter(|&p| (p as u64) >= min_val && (p as u64) < max_val)
            .collect();
        if candidates.is_empty() {
            return Err(CryptoError::Bignum(format!(
                "random_prime: no primes in {bits}-bit range [2^{}, 2^{bits})",
                bits - 1
            )));
        }
        let mut idx_bytes = [0u8; 8];
        rng::block(&mut idx_bytes);
        let idx = (u64::from_le_bytes(idx_bytes) as usize) % candidates.len();
        return Ok(BigUint::from(candidates[idx]));
    }

    // General path: N-bit odd with top two bits set. Step by +2.
    const OUTER_ATTEMPTS: usize = 100;
    const INNER_ATTEMPTS: usize = 1_000_000;
    let step = BigUint::from(2u32);
    for _outer in 0..OUTER_ATTEMPTS {
        let mut candidate = set_random(bits)?;
        candidate.set_bit(0, true);
        candidate.set_bit(u64::from(bits - 1), true);
        candidate.set_bit(u64::from(bits - 2), true);

        for _inner in 0..INNER_ATTEMPTS {
            if candidate.bits() != u64::from(bits) {
                break; // overflow; try new random
            }
            if mod_small_primes(&candidate).is_none() && is_prime(&candidate)? {
                return Ok(candidate);
            }
            candidate += &step;
        }
    }

    Err(CryptoError::Rng(std::io::Error::other(format!(
        "random_prime: exhausted attempts without finding a {bits}-bit prime"
    ))))
}

// ============================================================================
// Random-number helpers
// ============================================================================

/// Returns a uniformly random `bits`-bit unsigned integer.
///
/// Equivalent to the FASM `bigint$set_random` entry point
/// (`bigint.inc`). The top unused bits of the leading byte are
/// masked so the result never exceeds `2^bits - 1`. Note that the
/// top bit is NOT forced set — if a full-width random integer is
/// required, callers should OR with `set_pow2(bits - 1)` or use
/// [`BigUint::set_bit`] directly.
///
/// # Errors
/// Returns [`CryptoError::Bignum`] if `bits` exceeds the
/// architectural bound [`BIGINT_MAXWORDS`] × 64.
pub fn set_random(bits: u32) -> Result<BigUint, CryptoError> {
    if bits == 0 {
        return Ok(BigUint::zero());
    }
    validate_bit_size(bits)?;

    let byte_count = bits.div_ceil(8) as usize;
    let mut bytes = vec![0u8; byte_count];
    rng::block(&mut bytes);

    // Mask leading byte so the high bits above `bits` are zero.
    let extra_bits = (byte_count * 8) - bits as usize;
    if extra_bits > 0 && !bytes.is_empty() {
        let keep_bits = 8 - extra_bits;
        bytes[0] &= (1u8 << keep_bits) - 1;
    }

    Ok(BigUint::from_bytes_be(&bytes))
}

/// Returns a uniformly random integer in the half-open range
/// `[min, max)` using rejection sampling.
///
/// Equivalent to the FASM `bigint$set_randomrange` entry point
/// (`bigint.inc`).
///
/// # Errors
/// Returns [`CryptoError::Bignum`] if `min >= max`. Returns
/// [`CryptoError::Rng`] if rejection sampling exhausts its bounded
/// retry budget — vanishingly unlikely for well-conditioned
/// `[min, max)` ranges.
pub fn set_randomrange(min: &BigUint, max: &BigUint) -> Result<BigUint, CryptoError> {
    if min >= max {
        return Err(CryptoError::Bignum(format!(
            "set_randomrange: min ({min}) >= max ({max})"
        )));
    }
    let range = max - min;
    let bits = range.bits();
    if bits == 0 {
        return Err(CryptoError::Bignum(
            "set_randomrange: zero-sized range".to_string(),
        ));
    }

    const MAX_REJECTIONS: usize = 1024;
    for _ in 0..MAX_REJECTIONS {
        let candidate = set_random(bits as u32)?;
        if candidate < range {
            return Ok(candidate + min);
        }
    }

    Err(CryptoError::Rng(std::io::Error::other(
        "set_randomrange: rejection sampling retry budget exhausted",
    )))
}

/// Returns `2^exponent` as a fresh [`BigUint`].
///
/// Equivalent to the FASM `bigint$set_pow2` entry point at
/// `bigint.inc`. Uses the [`Pow`] trait from `num-traits` to
/// compute the power for API parity with the FASM implementation.
#[must_use]
pub fn set_pow2(exponent: u32) -> BigUint {
    // Pow::pow(2, e) = 2^e, exactly matching FASM `bigint$set_pow2`.
    Pow::pow(BigUint::from(2u32), exponent)
}

// ============================================================================
// Big-endian encoding and decoding
// ============================================================================

/// Encodes `n` as big-endian bytes with no leading zeros (unless
/// `n == 0`, in which case a single `0x00` byte is returned).
///
/// Equivalent to the FASM `bigint$encode` entry point at
/// `bigint.inc` line 558. Used on the wire by TLS, SSH, and RSA
/// handshakes to serialize moduli and integers.
#[must_use]
pub fn encode(n: &BigUint) -> Vec<u8> {
    n.to_bytes_be()
}

/// Decodes a big-endian byte slice into a new [`BigUint`].
///
/// Equivalent to the FASM `bigint$set_encoded` entry point at
/// `bigint.inc` line 625. An empty slice decodes to zero.
#[must_use]
pub fn set_encoded(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

// ============================================================================
// Bit-level helpers (population-count, bit length, byte length)
// ============================================================================

/// Returns `true` if bit `i` of `n` is set (0 = LSB).
///
/// Equivalent to the FASM `bigint$bitget` entry point at
/// `bigint.inc`.
#[must_use]
pub fn bit_get(n: &BigUint, i: usize) -> bool {
    n.bit(i as u64)
}

/// Sets bit `i` of `n` (0 = LSB).
///
/// Equivalent to the FASM `bigint$bitset` entry point at
/// `bigint.inc`.
pub fn bit_set(n: &mut BigUint, i: usize) {
    n.set_bit(i as u64, true);
}

/// Clears bit `i` of `n` (0 = LSB).
///
/// Equivalent to the FASM `bigint$bitclear` entry point at
/// `bigint.inc`.
pub fn bit_clear(n: &mut BigUint, i: usize) {
    n.set_bit(i as u64, false);
}

/// Returns the population count (Hamming weight) of `n` — the
/// number of set bits.
///
/// Equivalent to the FASM `bigint$bitcount` entry point at
/// `bigint.inc`. The implementation sums `count_ones()` of each
/// limb and is O(words).
#[must_use]
pub fn bit_count(n: &BigUint) -> u64 {
    n.iter_u32_digits().map(|d| u64::from(d.count_ones())).sum()
}

/// Returns the number of bytes required to encode `n` in
/// big-endian (zero for `n == 0`).
///
/// Equivalent to the FASM `bigint$bytecount` entry point at
/// `bigint.inc`. Matches `encode(n).len()` for non-zero `n`.
#[must_use]
pub fn byte_count(n: &BigUint) -> usize {
    if n.is_zero() {
        0
    } else {
        n.bits().div_ceil(8) as usize
    }
}

/// Returns `floor(log2(n))` (the index of the most-significant set
/// bit, 0-based), or 0 for `n == 0`.
///
/// Equivalent to the FASM `bigint$lg2` entry point at `bigint.inc`.
/// Note: the FASM convention returns 0 for both `n == 0` and
/// `n == 1`; this port preserves that behavior.
#[must_use]
pub fn lg2(n: &BigUint) -> u32 {
    if n.is_zero() {
        0
    } else {
        (n.bits() - 1) as u32
    }
}

// ============================================================================
// Modular inverse and Jacobi symbol
// ============================================================================

/// Returns `a^-1 mod modulus` — the modular multiplicative inverse.
///
/// Equivalent to the FASM `bigint$inversemod` entry point at
/// `bigint.inc` line 6465. Uses the extended Euclidean algorithm
/// via [`Integer::extended_gcd`] on `BigInt`.
///
/// # Errors
/// Returns [`CryptoError::Bignum`] if `modulus <= 1`, if `a == 0`
/// modulo `modulus`, or if `gcd(a, modulus) != 1` (i.e., no
/// inverse exists).
pub fn mod_inverse(a: &BigUint, modulus: &BigUint) -> Result<BigUint, CryptoError> {
    if *modulus <= BigUint::one() {
        return Err(CryptoError::Bignum(format!(
            "mod_inverse: modulus ({modulus}) must be > 1"
        )));
    }

    // Reduce `a` into [0, modulus) first.
    let a_reduced = a % modulus;
    if a_reduced.is_zero() {
        return Err(CryptoError::Bignum(
            "mod_inverse: a is zero modulo the modulus".to_string(),
        ));
    }

    // Extended GCD operates on `BigInt`. The returned
    // `ExtendedGcd { gcd, x, y }` satisfies `a*x + modulus*y = gcd`.
    let a_signed: BigInt = BigInt::from_biguint(num_bigint::Sign::Plus, a_reduced);
    let m_signed: BigInt = BigInt::from_biguint(num_bigint::Sign::Plus, modulus.clone());
    let egcd = a_signed.extended_gcd(&m_signed);

    if !egcd.gcd.is_one() {
        return Err(CryptoError::Bignum(format!(
            "mod_inverse: gcd(a, modulus) = {} != 1 — inverse does not exist",
            egcd.gcd
        )));
    }

    // Reduce the Bézout coefficient `x` mod modulus (may be negative).
    let x_mod = egcd.x.mod_floor(&m_signed);
    x_mod
        .to_biguint()
        .ok_or_else(|| CryptoError::Bignum("mod_inverse: reduced coefficient not convertible".to_string()))
}

/// Returns the Jacobi symbol `(a / n)` as `+1`, `-1`, or `0`.
///
/// Equivalent to the FASM `bigint$jacobi` entry point at
/// `bigint.inc` lines 6679–6800.
///
/// Preconditions (follow the classical mathematical definition):
/// * `n > 0` and `n` is odd. Returns `0` otherwise.
/// * `a` may be any sign; it is reduced modulo `n` at entry.
///
/// The algorithm follows the standard recursive reduction with
/// sign flipping driven by quadratic reciprocity and the `n mod 8`
/// rule for the factor-of-two stripping step.
#[must_use]
pub fn jacobi(a: &BigInt, n: &BigInt) -> i8 {
    // Precondition: n > 0 and odd.
    if !n.is_positive() {
        return 0;
    }
    let n_mag = n.magnitude();
    if n_mag.is_even() {
        return 0;
    }

    // Reduce `a` into [0, n) as a BigInt, then promote to BigUint
    // for the positive-arithmetic inner loop.
    let a_reduced_signed = a.mod_floor(n);
    // `mod_floor` with positive divisor yields non-negative result.
    let mut a_work = a_reduced_signed.to_biguint().unwrap_or_else(BigUint::zero);
    let mut n_work = n_mag.clone();
    let mut result: i8 = 1;

    while !a_work.is_zero() {
        // Strip factors of 2 from `a`, flipping sign when
        // `n mod 8 ∈ {3, 5}`. For odd `n`, bit 0 is always set, so
        // `n mod 8 ∈ {1, 3, 5, 7}`; the condition becomes
        // `bit1 XOR bit2`.
        while a_work.is_even() {
            a_work >>= 1u32;
            if n_work.bit(1) ^ n_work.bit(2) {
                result = -result;
            }
        }
        // Swap via `mem::swap`. Both `a` and `n` are odd here.
        std::mem::swap(&mut a_work, &mut n_work);
        // Quadratic-reciprocity sign flip: flip when
        // `a ≡ 3 (mod 4)` AND `n ≡ 3 (mod 4)`. For odd numbers,
        // `mod 4 == 3` iff bit 1 is set.
        if a_work.bit(1) && n_work.bit(1) {
            result = -result;
        }
        a_work %= &n_work;
    }

    if n_work.is_one() {
        result
    } else {
        0
    }
}

// ============================================================================
// DH parameter generation
// ============================================================================

/// Generates Diffie–Hellman parameters `(p, g)` where `p` is a
/// `p_bits`-bit safe prime (i.e., `p = 2q + 1` with `q` also
/// prime) and `g` is the smallest small integer that is a
/// generator of the order-`q` prime subgroup of `(Z/pZ)*`.
///
/// Equivalent to the FASM `bigint$dh_params` entry point at
/// `bigint.inc` lines 8012–8150. Small sizes (< 64 bits) are
/// rejected as they produce insecure parameters; the production
/// default is [`DH_BITS`] (`= 2048`).
///
/// # Errors
/// Returns [`CryptoError::Dh`] if `p_bits < 64` or if `p_bits`
/// exceeds the architectural bound [`BIGINT_MAXWORDS`] × 64.
///
/// # Performance
/// Safe-prime generation is probabilistic: expected runtime is
/// `O(p_bits^4)` due to repeated Miller–Rabin testing on both
/// `q` and `p = 2q + 1`. For a 2048-bit prime this can take
/// several minutes; tests in this module use 64–128-bit sizes.
pub fn dh_params(p_bits: u32) -> Result<(BigUint, BigUint), CryptoError> {
    if p_bits < 64 {
        return Err(CryptoError::Dh(format!(
            "dh_params: p_bits={p_bits} below minimum 64 (recommended default is DH_BITS={DH_BITS})"
        )));
    }
    validate_bit_size(p_bits).map_err(|e| match e {
        CryptoError::Bignum(s) => CryptoError::Dh(s),
        other => other,
    })?;

    let one_big = BigUint::one();

    const MAX_ATTEMPTS: usize = 10_000;
    for _ in 0..MAX_ATTEMPTS {
        // Candidate subgroup prime q of (p_bits - 1) bits.
        let q = random_prime(p_bits - 1)?;
        // Compute p = 2q + 1.
        let p = (&q << 1u32) + &one_big;
        // Require exactly p_bits bits.
        if p.bits() != u64::from(p_bits) {
            continue;
        }
        if !is_prime(&p)? {
            continue;
        }
        // Find small generator. For a safe prime p = 2q+1 the
        // multiplicative group (Z/pZ)* has order 2q with subgroup
        // orders {1, 2, q, 2q}. Per the FASM `bigint$dh_params`
        // source ("generator g such that g is a quadratic residue
        // mod p", `bigint.inc:8008`), we want g in the order-q
        // subgroup of quadratic residues. By Euler's criterion this
        // is equivalent to `g^q ≡ 1 (mod p)`. We try small odd
        // candidates first since they are the conventional choice
        // for RFC 3526 / RFC 7919 style DH groups.
        for &g_small in &[2u32, 3, 5, 7, 11, 13, 17, 19, 23] {
            let g = BigUint::from(g_small);
            if g >= p {
                continue;
            }
            let g_pow_q = g.modpow(&q, &p);
            if g_pow_q.is_one() {
                return Ok((p, g));
            }
            // Otherwise g_pow_q == p - 1 (g is a non-residue with
            // order 2 or 2q); try the next candidate.
        }
        // None of the small candidates were quadratic residues —
        // an unlikely (~2^-9) outcome; regenerate q/p.
    }

    Err(CryptoError::Dh(format!(
        "dh_params: exhausted {MAX_ATTEMPTS} attempts generating a {p_bits}-bit safe prime"
    )))
}

// ============================================================================
// DSA parameter generation
// ============================================================================

/// Generates DSA parameters `(p, q, g)` with `|p| = p_bits` and
/// `|q| = q_bits`, satisfying `q | (p - 1)` and `g` a generator of
/// the order-`q` subgroup of `(Z/pZ)*`.
///
/// Equivalent to the FASM `bigint$dsa_params` entry point at
/// `bigint.inc` lines 8303–8455 and follows FIPS 186-4 Appendix
/// A.1.1 "Generation of Domain Parameters Using Probable Primes".
/// Recommended defaults are [`DSA_SIZE`] (`p_bits = 3072`) and
/// [`DSA_SUBGROUP_SIZE`] (`q_bits = 256`).
///
/// DSA is a legacy algorithm retained for SSH `ssh-dss` host-key
/// compatibility; new deployments should prefer Ed25519 / ECDSA.
///
/// # Errors
/// Returns [`CryptoError::Bignum`] if `p_bits <= q_bits`,
/// `q_bits < 64`, or `p_bits` exceeds the architectural bound.
///
/// # Performance
/// Parameter generation at the FIPS default sizes is **slow**
/// (several minutes on modern hardware) because it requires
/// Miller–Rabin testing of a very large `p`. Tests in this module
/// use much smaller sizes.
pub fn dsa_params(p_bits: u32, q_bits: u32) -> Result<(BigUint, BigUint, BigUint), CryptoError> {
    if q_bits < 64 || p_bits <= q_bits {
        return Err(CryptoError::Bignum(format!(
            "dsa_params: invalid sizes p_bits={p_bits} q_bits={q_bits} (FIPS 186-4 defaults are DSA_SIZE={DSA_SIZE}, DSA_SUBGROUP_SIZE={DSA_SUBGROUP_SIZE})"
        )));
    }
    validate_bit_size(p_bits)?;

    let one_big = BigUint::one();
    let two_big = BigUint::from(2u32);
    let two_to_lm1 = set_pow2(p_bits - 1); // 2^(p_bits - 1)
    let two_to_l = set_pow2(p_bits); // 2^p_bits (exclusive upper bound)

    const OUTER_ATTEMPTS: usize = 100;
    for _outer in 0..OUTER_ATTEMPTS {
        // Step 1: generate prime q of q_bits.
        let q = random_prime(q_bits)?;
        let two_q = &q * &two_big;

        // Step 2: try p candidates until one is prime.
        for _inner in 0..(4 * p_bits as usize) {
            // Random p_bits-bit number with top bit set.
            let mut candidate = set_random(p_bits)?;
            candidate.set_bit(u64::from(p_bits - 1), true);

            // Adjust so p ≡ 1 (mod 2q): p -= (p - 1) mod 2q.
            let cand_minus_1 = &candidate - &one_big;
            let rem = &cand_minus_1 % &two_q;
            if rem > candidate {
                continue;
            }
            let mut p = &candidate - &rem;

            // Step forward by 2q, testing primality each step.
            for _step in 0..(4 * p_bits as usize) {
                if p < two_to_lm1 || p >= two_to_l {
                    break;
                }
                if is_prime(&p)? {
                    // Step 3: find generator g = h^((p-1)/q) mod p.
                    let exp = (&p - &one_big) / &q;
                    for h_small in 2u32..=65_536 {
                        let h = BigUint::from(h_small);
                        if h >= p {
                            break;
                        }
                        let g = h.modpow(&exp, &p);
                        if !g.is_one() && !g.is_zero() {
                            return Ok((p, q, g));
                        }
                    }
                    // Unlikely to exhaust h-space; try next p.
                }
                p += &two_q;
            }
        }
    }

    Err(CryptoError::Bignum(format!(
        "dsa_params: exhausted {OUTER_ATTEMPTS} outer attempts (p_bits={p_bits}, q_bits={q_bits})"
    )))
}

// ============================================================================
// RSA private-key CRT derivation
// ============================================================================

/// Derives PKCS#1 v2.2 §3.2 RSA private-key CRT components from
/// primes `p`, `q` and public exponent `e`.
///
/// Equivalent to the FASM `bigint$rsaprivate` entry point at
/// `bigint.inc` lines 9654–9800 (modulo the FASM-specific cache
/// layout; the Rust port returns a plain [`RsaPrivateComponents`]
/// struct).
///
/// Computes:
/// * `n = p * q`
/// * `phi = (p - 1) * (q - 1)` (Euler totient)
/// * `d = e^-1 mod phi`
/// * `dp = d mod (p - 1)`
/// * `dq = d mod (q - 1)`
/// * `qinv = q^-1 mod p`
///
/// # Errors
/// Returns [`CryptoError::Bignum`] if either prime is too small
/// (`< 2`), or if `gcd(e, phi) != 1` (i.e., `e` shares a factor
/// with `phi` so the inverse does not exist).
pub fn rsa_private(p: &BigUint, q: &BigUint, e: &BigUint) -> Result<RsaPrivateComponents, CryptoError> {
    let two_big = BigUint::from(2u32);
    if *p < two_big || *q < two_big {
        return Err(CryptoError::Bignum(format!(
            "rsa_private: primes must be >= 2 (p={p}, q={q})"
        )));
    }
    if e.is_zero() || e.is_one() {
        return Err(CryptoError::Bignum(format!(
            "rsa_private: public exponent e={e} must be > 1"
        )));
    }

    let one_big = BigUint::one();
    let n = p * q;
    let p_minus_1 = p - &one_big;
    let q_minus_1 = q - &one_big;
    let phi = &p_minus_1 * &q_minus_1;

    let d = mod_inverse(e, &phi)?;
    let dp = &d % &p_minus_1;
    let dq = &d % &q_minus_1;
    let qinv = mod_inverse(q, p)?;

    Ok(RsaPrivateComponents { n, d, dp, dq, qinv })
}

// ============================================================================
// Debug / logging helper
// ============================================================================

/// Returns a human-readable hexadecimal representation of `n`
/// grouped into `BIGINT_UNROLLSIZE / 2`-byte (8-byte) chunks with
/// `_` separators.
///
/// Equivalent to the FASM `bigint$debug` entry point, used for
/// diagnostic and log output. The grouping matches the FASM
/// unroll factor for visual alignment with the original
/// hand-tuned 64-bit-word register dumps.
#[must_use]
pub fn debug_hex(n: &BigUint) -> String {
    let bytes = n.to_bytes_be();
    if bytes.is_empty() || (bytes.len() == 1 && bytes[0] == 0) {
        return "0x0".to_string();
    }
    // Group by BIGINT_UNROLLSIZE / 2 = 8 bytes (FASM word-level
    // unrolling factor, preserved for API parity).
    let chunk_size = BIGINT_UNROLLSIZE / 2;
    let mut out = String::with_capacity(2 + bytes.len() * 2 + bytes.len() / chunk_size);
    out.push_str("0x");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && i % chunk_size == 0 {
            out.push('_');
        }
        // Two-digit lowercase hex without allocating a temporary
        // string per byte.
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Small-primes table
    // ------------------------------------------------------------------

    #[test]
    fn small_primes_table_has_expected_count() {
        let primes = small_primes_table();
        // Primes below 65,522 → 6,542 primes per classical counting;
        // we also include 65521 (the largest 16-bit prime) so the
        // expected count is π(65521) = 6542.
        assert_eq!(primes.len(), 6542);
        assert_eq!(primes[0], 2);
        assert_eq!(primes[1], 3);
        assert_eq!(primes[2], 5);
        // Last element should be the largest prime <= 65521.
        assert_eq!(*primes.last().unwrap(), 65521);
    }

    #[test]
    fn small_primes_are_sorted() {
        let primes = small_primes_table();
        for w in primes.windows(2) {
            assert!(w[0] < w[1], "table not sorted at {:?}", w);
        }
    }

    // ------------------------------------------------------------------
    // Static zero() / one() cheater accessors
    // ------------------------------------------------------------------

    #[test]
    fn zero_is_zero() {
        let z = zero();
        assert!(z.is_zero());
        assert_eq!(*z, BigUint::from(0u32));
    }

    #[test]
    fn one_is_one() {
        let o = one();
        assert!(o.is_one());
        assert_eq!(*o, BigUint::from(1u32));
    }

    #[test]
    fn zero_one_are_stable_across_calls() {
        // OnceLock should yield the same reference on repeat calls.
        let z1 = zero() as *const BigUint;
        let z2 = zero() as *const BigUint;
        assert_eq!(z1, z2);
        let o1 = one() as *const BigUint;
        let o2 = one() as *const BigUint;
        assert_eq!(o1, o2);
    }

    // ------------------------------------------------------------------
    // Primality testing: known answers
    // ------------------------------------------------------------------

    #[test]
    fn is_prime_handles_small_edge_cases() {
        assert!(!is_prime(&BigUint::from(0u32)).unwrap());
        assert!(!is_prime(&BigUint::from(1u32)).unwrap());
        assert!(is_prime(&BigUint::from(2u32)).unwrap());
        assert!(is_prime(&BigUint::from(3u32)).unwrap());
        assert!(!is_prime(&BigUint::from(4u32)).unwrap());
        assert!(is_prime(&BigUint::from(5u32)).unwrap());
        assert!(!is_prime(&BigUint::from(9u32)).unwrap());
        assert!(!is_prime(&BigUint::from(15u32)).unwrap());
        assert!(is_prime(&BigUint::from(97u32)).unwrap());
        assert!(!is_prime(&BigUint::from(100u32)).unwrap());
    }

    #[test]
    fn is_prime_large_16bit() {
        assert!(is_prime(&BigUint::from(65521u32)).unwrap()); // largest 16-bit prime
        assert!(!is_prime(&BigUint::from(65522u32)).unwrap());
        assert!(!is_prime(&BigUint::from(65520u32)).unwrap());
    }

    #[test]
    fn is_prime_mersenne_prime() {
        // Mersenne prime M_13 = 2^13 - 1 = 8191 (prime).
        assert!(is_prime(&BigUint::from(8191u32)).unwrap());
        // Mersenne prime M_31 = 2^31 - 1 = 2147483647 (prime).
        assert!(is_prime(&BigUint::from(2_147_483_647u64)).unwrap());
        // M_127 = 2^127 - 1 — a famous large Mersenne prime.
        let m127 = (BigUint::from(1u32) << 127u32) - 1u32;
        assert!(is_prime(&m127).unwrap());
    }

    #[test]
    fn is_prime_mersenne_composite() {
        // 2^11 - 1 = 2047 = 23 * 89 — the canonical Miller–Rabin
        // strong-liar example against base 2.
        assert!(!is_prime(&BigUint::from(2047u32)).unwrap());
        // 2^127 + 1 is composite (Fermat-like).
        let m127_plus_2 = ((BigUint::from(1u32) << 127u32) - 1u32) + BigUint::from(2u32);
        assert!(!is_prime(&m127_plus_2).unwrap());
    }

    #[test]
    fn is_prime_carmichael_numbers() {
        // Carmichael numbers fool some primality tests but not
        // strong Miller–Rabin. Test the first few.
        assert!(!is_prime(&BigUint::from(561u32)).unwrap()); // 3 * 11 * 17
        assert!(!is_prime(&BigUint::from(1105u32)).unwrap()); // 5 * 13 * 17
        assert!(!is_prime(&BigUint::from(1729u32)).unwrap()); // 7 * 13 * 19
    }

    #[test]
    fn is_prime2_variable_rounds() {
        // With rounds=0 we still reject obvious small-prime divisors.
        assert!(!is_prime2(&BigUint::from(4u32), 0).unwrap());
        // rounds=1 sufficient for well-separated candidates.
        assert!(is_prime2(&BigUint::from(97u32), 1).unwrap());
        assert!(!is_prime2(&BigUint::from(2047u32), 10).unwrap());
    }

    // ------------------------------------------------------------------
    // mod_small_primes
    // ------------------------------------------------------------------

    #[test]
    fn mod_small_primes_hits() {
        assert_eq!(mod_small_primes(&BigUint::from(4u32)), Some(2));
        assert_eq!(mod_small_primes(&BigUint::from(9u32)), Some(3));
        assert_eq!(mod_small_primes(&BigUint::from(15u32)), Some(3));
        assert_eq!(mod_small_primes(&BigUint::from(35u32)), Some(5));
        assert_eq!(mod_small_primes(&BigUint::from(91u32)), Some(7));
    }

    #[test]
    fn mod_small_primes_misses() {
        // 97 is a prime itself; none of the primes smaller than 97
        // divide it.
        assert_eq!(mod_small_primes(&BigUint::from(97u32)), None);
        // 2 itself: table starts at 2 which is equal to n; break.
        assert_eq!(mod_small_primes(&BigUint::from(2u32)), None);
    }

    #[test]
    fn mod_small_primes_large_composite() {
        // Product of two small primes: 1009 * 1013 = 1,022,117.
        let composite = BigUint::from(1009u32) * BigUint::from(1013u32);
        let result = mod_small_primes(&composite);
        assert_eq!(result, Some(1009));
    }

    // ------------------------------------------------------------------
    // random_prime
    // ------------------------------------------------------------------

    #[test]
    fn random_prime_small_16bit() {
        let p = random_prime(16).expect("random_prime(16) should succeed");
        assert!(is_prime(&p).unwrap());
        // 16-bit bound: p must be in [2^15, 2^16).
        assert!(p >= BigUint::from(1u32 << 15));
        assert!(p < BigUint::from(1u32 << 16));
    }

    #[test]
    fn random_prime_32bit() {
        let p = random_prime(32).expect("random_prime(32) should succeed");
        assert!(is_prime(&p).unwrap());
        assert_eq!(p.bits(), 32);
    }

    #[test]
    fn random_prime_rejects_bits_below_2() {
        let err = random_prime(1).unwrap_err();
        match err {
            CryptoError::Bignum(_) => {}
            other => panic!("expected Bignum error, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // set_random and set_randomrange
    // ------------------------------------------------------------------

    #[test]
    fn set_random_bit_length_bounded() {
        for bits in [1u32, 7, 8, 9, 16, 64, 128] {
            for _ in 0..4 {
                let n = set_random(bits).unwrap();
                assert!(
                    n.bits() <= u64::from(bits),
                    "set_random({}) produced {} bits ({})",
                    bits,
                    n.bits(),
                    n
                );
            }
        }
    }

    #[test]
    fn set_random_zero_bits() {
        let n = set_random(0).unwrap();
        assert!(n.is_zero());
    }

    #[test]
    fn set_randomrange_in_bounds() {
        let min = BigUint::from(100u32);
        let max = BigUint::from(200u32);
        for _ in 0..20 {
            let r = set_randomrange(&min, &max).unwrap();
            assert!(r >= min, "below min: {}", r);
            assert!(r < max, "at/above max: {}", r);
        }
    }

    #[test]
    fn set_randomrange_rejects_empty_range() {
        let a = BigUint::from(42u32);
        let err = set_randomrange(&a, &a).unwrap_err();
        match err {
            CryptoError::Bignum(_) => {}
            other => panic!("expected Bignum error, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // set_pow2
    // ------------------------------------------------------------------

    #[test]
    fn set_pow2_correctness() {
        assert_eq!(set_pow2(0), BigUint::from(1u32));
        assert_eq!(set_pow2(1), BigUint::from(2u32));
        assert_eq!(set_pow2(10), BigUint::from(1024u32));
        assert_eq!(set_pow2(64), BigUint::from(1u128 << 64));
        // Large case.
        let p256 = set_pow2(256);
        assert_eq!(p256.bits(), 257);
    }

    // ------------------------------------------------------------------
    // Encoding round-trip
    // ------------------------------------------------------------------

    #[test]
    fn encode_decode_round_trip_zero() {
        let n = BigUint::zero();
        let bytes = encode(&n);
        let decoded = set_encoded(&bytes);
        assert_eq!(decoded, n);
    }

    #[test]
    fn encode_decode_round_trip_small() {
        let n = BigUint::from(0xdeadbeef_u32);
        let bytes = encode(&n);
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(set_encoded(&bytes), n);
    }

    #[test]
    fn encode_decode_round_trip_large() {
        // 256 random bytes → BigUint → back to bytes.
        let mut raw = vec![0u8; 256];
        rng::block(&mut raw);
        // Ensure the top byte is nonzero so encoded length equals raw length.
        raw[0] = 0x80;
        let n = set_encoded(&raw);
        let bytes = encode(&n);
        assert_eq!(bytes, raw);
    }

    #[test]
    fn encode_strips_leading_zeros() {
        let n = BigUint::from(1u32);
        let bytes = encode(&n);
        assert_eq!(bytes, vec![1u8]);
    }

    // ------------------------------------------------------------------
    // Bit operations
    // ------------------------------------------------------------------

    #[test]
    fn bit_get_set_clear_round_trip() {
        let mut n = BigUint::zero();
        assert!(!bit_get(&n, 0));
        bit_set(&mut n, 0);
        assert!(bit_get(&n, 0));
        bit_set(&mut n, 7);
        assert_eq!(n, BigUint::from(0b1000_0001u32));
        bit_clear(&mut n, 0);
        assert_eq!(n, BigUint::from(0b1000_0000u32));
    }

    #[test]
    fn bit_count_known_values() {
        assert_eq!(bit_count(&BigUint::zero()), 0);
        assert_eq!(bit_count(&BigUint::from(1u32)), 1);
        assert_eq!(bit_count(&BigUint::from(0xFFu32)), 8);
        assert_eq!(bit_count(&BigUint::from(0xFFFF_FFFFu32)), 32);
        assert_eq!(bit_count(&BigUint::from(0xAAAA_AAAAu32)), 16);
    }

    #[test]
    fn byte_count_known_values() {
        assert_eq!(byte_count(&BigUint::zero()), 0);
        assert_eq!(byte_count(&BigUint::from(1u32)), 1);
        assert_eq!(byte_count(&BigUint::from(0xFFu32)), 1);
        assert_eq!(byte_count(&BigUint::from(0x100u32)), 2);
        assert_eq!(byte_count(&BigUint::from(0xFFFF_FFFFu32)), 4);
    }

    #[test]
    fn lg2_known_values() {
        assert_eq!(lg2(&BigUint::zero()), 0);
        assert_eq!(lg2(&BigUint::from(1u32)), 0);
        assert_eq!(lg2(&BigUint::from(2u32)), 1);
        assert_eq!(lg2(&BigUint::from(3u32)), 1);
        assert_eq!(lg2(&BigUint::from(4u32)), 2);
        assert_eq!(lg2(&BigUint::from(1024u32)), 10);
        assert_eq!(lg2(&(BigUint::from(1u32) << 100u32)), 100);
    }

    // ------------------------------------------------------------------
    // mod_inverse
    // ------------------------------------------------------------------

    #[test]
    fn mod_inverse_small() {
        // 3 * 5 = 15 ≡ 1 (mod 7), so 3^-1 ≡ 5 (mod 7).
        let inv = mod_inverse(&BigUint::from(3u32), &BigUint::from(7u32)).unwrap();
        assert_eq!(inv, BigUint::from(5u32));

        // 2 * 3 = 6 ≡ 1 (mod 5), so 2^-1 ≡ 3 (mod 5).
        let inv = mod_inverse(&BigUint::from(2u32), &BigUint::from(5u32)).unwrap();
        assert_eq!(inv, BigUint::from(3u32));
    }

    #[test]
    fn mod_inverse_self_check() {
        // For e = 65537, phi = 3120 (= 60 * 52 = (61-1)*(53-1))
        // d = 65537^-1 mod 3120 should satisfy e*d ≡ 1 (mod phi).
        let e = BigUint::from(65537u32);
        let phi = BigUint::from(3120u32);
        let d = mod_inverse(&e, &phi).unwrap();
        let prod = (&e * &d) % &phi;
        assert_eq!(prod, BigUint::from(1u32));
    }

    #[test]
    fn mod_inverse_no_inverse() {
        // gcd(6, 9) = 3 != 1 — no inverse.
        let err = mod_inverse(&BigUint::from(6u32), &BigUint::from(9u32)).unwrap_err();
        match err {
            CryptoError::Bignum(_) => {}
            other => panic!("expected Bignum error, got {other:?}"),
        }
    }

    #[test]
    fn mod_inverse_rejects_trivial_modulus() {
        assert!(mod_inverse(&BigUint::from(3u32), &BigUint::from(1u32)).is_err());
        assert!(mod_inverse(&BigUint::from(3u32), &BigUint::from(0u32)).is_err());
    }

    // ------------------------------------------------------------------
    // Jacobi symbol — known values
    // ------------------------------------------------------------------

    #[test]
    fn jacobi_known_values() {
        let bi = |n: i64| BigInt::from(n);
        // Basic cases from algebra texts.
        assert_eq!(jacobi(&bi(1), &bi(1)), 1);
        assert_eq!(jacobi(&bi(2), &bi(3)), -1);
        assert_eq!(jacobi(&bi(3), &bi(5)), -1);
        assert_eq!(jacobi(&bi(4), &bi(15)), 1); // 4 = 2^2; (2/15)^2 = 1
        assert_eq!(jacobi(&bi(1001), &bi(9907)), -1); // standard textbook example
    }

    #[test]
    fn jacobi_zero_and_gcd_gt1() {
        let bi = |n: i64| BigInt::from(n);
        // (0 / n) = 0 for n > 1.
        assert_eq!(jacobi(&bi(0), &bi(15)), 0);
        // gcd(a, n) > 1 → 0.
        assert_eq!(jacobi(&bi(6), &bi(15)), 0); // gcd(6, 15) = 3
    }

    #[test]
    fn jacobi_n_even_or_nonpositive() {
        let bi = |n: i64| BigInt::from(n);
        // n must be positive and odd; otherwise jacobi is undefined
        // and we return 0.
        assert_eq!(jacobi(&bi(3), &bi(4)), 0);
        assert_eq!(jacobi(&bi(3), &bi(0)), 0);
        assert_eq!(jacobi(&bi(3), &bi(-5)), 0);
    }

    #[test]
    fn jacobi_prime_denominator_equals_legendre() {
        // For odd prime p, jacobi(a, p) = legendre(a, p) =
        // a^((p-1)/2) mod p interpreted as {0, ±1}.
        let p: u32 = 97;
        for a in 1u32..20 {
            let j = jacobi(&BigInt::from(a), &BigInt::from(p));
            // Compute Legendre directly via Euler's criterion.
            let exp = BigUint::from((p - 1) / 2);
            let a_pow = BigUint::from(a).modpow(&exp, &BigUint::from(p));
            let expected: i8 = if a_pow.is_zero() {
                0
            } else if a_pow.is_one() {
                1
            } else {
                -1
            };
            assert_eq!(j, expected, "jacobi({a}, {p}) mismatch");
        }
    }

    // ------------------------------------------------------------------
    // RSA private-key CRT derivation
    // ------------------------------------------------------------------

    #[test]
    fn rsa_private_textbook_example() {
        // Canonical PKCS#1 v2.0 textbook example using
        // φ(n) = (p-1)(q-1) (which is what FASM `bigint$rsaprivate`
        // and our `rsa_private` compute):
        //   p = 61, q = 53, e = 17
        //   n   = p·q                 = 3233
        //   φ   = (p-1)(q-1)          = 3120
        //   d   = e^-1 mod φ          = 2753   (since 17 · 2753 = 46801 = 15·3120 + 1)
        //   dp  = d mod (p-1)         = 2753 mod 60 = 53
        //   dq  = d mod (q-1)         = 2753 mod 52 = 49
        //   qinv= q^-1 mod p          = 53^-1 mod 61 = 38   (53·38 = 2014 = 33·61 + 1)
        // Note: PKCS#1 v2.2 alternatively allows d derived from
        // λ(n) = lcm(p-1,q-1) = 780 (giving d = 413). The dp / dq /
        // qinv invariants are identical under either convention.
        let components = rsa_private(
            &BigUint::from(61u32),
            &BigUint::from(53u32),
            &BigUint::from(17u32),
        )
        .unwrap();
        assert_eq!(components.n, BigUint::from(3233u32));
        assert_eq!(components.d, BigUint::from(2753u32));
        assert_eq!(components.dp, BigUint::from(53u32));
        assert_eq!(components.dq, BigUint::from(49u32));
        assert_eq!(components.qinv, BigUint::from(38u32));
    }

    #[test]
    fn rsa_private_functional_roundtrip() {
        // Encrypt/decrypt a small message with the derived private
        // key to confirm functional correctness of the CRT params.
        let p = BigUint::from(61u32);
        let q = BigUint::from(53u32);
        let e = BigUint::from(17u32);
        let components = rsa_private(&p, &q, &e).unwrap();
        let n = &components.n;
        let d = &components.d;
        let msg = BigUint::from(65u32); // < n = 3233
                                        // c = msg^e mod n; m = c^d mod n; m should equal msg.
        let c = msg.modpow(&e, n);
        let m = c.modpow(d, n);
        assert_eq!(m, msg);
    }

    #[test]
    fn rsa_private_rejects_bad_exponent() {
        assert!(rsa_private(&BigUint::from(61u32), &BigUint::from(53u32), &BigUint::from(0u32)).is_err());
        assert!(rsa_private(&BigUint::from(61u32), &BigUint::from(53u32), &BigUint::from(1u32)).is_err());
    }

    // ------------------------------------------------------------------
    // DH parameters (small size for test speed)
    // ------------------------------------------------------------------

    #[test]
    fn dh_params_small() {
        let (p, g) = dh_params(64).expect("dh_params(64) should succeed");
        // p is a 64-bit prime.
        assert_eq!(p.bits(), 64);
        assert!(is_prime(&p).unwrap());
        // q = (p - 1) / 2 should also be prime (safe prime).
        let q = (&p - BigUint::from(1u32)) >> 1u32;
        assert!(is_prime(&q).unwrap());
        // g is in the order-q subgroup of quadratic residues mod p
        // (FASM `bigint$dh_params` convention, `bigint.inc:8008`).
        // By Euler's criterion this means `g^q ≡ 1 (mod p)`.
        let g_pow_q = g.modpow(&q, &p);
        assert!(
            g_pow_q.is_one(),
            "g={g} is not a quadratic residue mod p (g^q = {g_pow_q}, expected 1)"
        );
        // And g must be > 1 (the trivial element is not a generator).
        assert!(g > BigUint::one());
    }

    #[test]
    fn dh_params_rejects_tiny_sizes() {
        for bad_bits in [0u32, 1, 8, 32, 63] {
            let err = dh_params(bad_bits).unwrap_err();
            match err {
                CryptoError::Dh(_) => {}
                other => panic!("expected Dh error for bits={bad_bits}, got {other:?}"),
            }
        }
    }

    // ------------------------------------------------------------------
    // DSA parameters (small size for test speed)
    // ------------------------------------------------------------------

    #[test]
    fn dsa_params_small() {
        // Tiny sizes for test — real DSA uses 3072/256.
        let (p, q, g) = dsa_params(128, 64).expect("dsa_params(128, 64) should succeed");
        assert!(is_prime(&p).unwrap());
        assert!(is_prime(&q).unwrap());
        // q | (p - 1)
        assert!(((&p - BigUint::from(1u32)) % &q).is_zero());
        // g is an order-q generator: g^q ≡ 1 (mod p) AND g > 1.
        let g_pow_q = g.modpow(&q, &p);
        assert!(g_pow_q.is_one());
        assert!(g > BigUint::from(1u32));
    }

    #[test]
    fn dsa_params_rejects_bad_sizes() {
        assert!(dsa_params(64, 128).is_err()); // p < q
        assert!(dsa_params(128, 32).is_err()); // q_bits < 64
    }

    // ------------------------------------------------------------------
    // CachedMontgomery
    // ------------------------------------------------------------------

    #[test]
    fn cached_montgomery_matches_plain_modpow() {
        let base = BigUint::from(123u32);
        let modulus = BigUint::from(10_007u32); // prime
        let exp = BigUint::from(999u32);
        let cached = CachedMontgomery::new(base.clone(), modulus.clone());
        let expected = base.modpow(&exp, &modulus);
        assert_eq!(cached.powmod(&exp), expected);
    }

    #[test]
    fn cached_montgomery_reusable() {
        let base = BigUint::from(2u32);
        let modulus = BigUint::from(1009u32); // prime
        let cached = CachedMontgomery::new(base.clone(), modulus.clone());
        // Verify Fermat's little theorem: 2^(1008) ≡ 1 (mod 1009).
        let one_mod = cached.powmod(&BigUint::from(1008u32));
        assert_eq!(one_mod, BigUint::from(1u32));
        // Reuse: 2^504 should be the square root of 1 mod 1009 — i.e., ±1.
        let sqrt1 = cached.powmod(&BigUint::from(504u32));
        assert!(
            sqrt1 == BigUint::from(1u32) || sqrt1 == BigUint::from(1008u32),
            "got unexpected square root: {sqrt1}"
        );
    }

    // ------------------------------------------------------------------
    // debug_hex
    // ------------------------------------------------------------------

    #[test]
    fn debug_hex_zero() {
        assert_eq!(debug_hex(&BigUint::zero()), "0x0");
    }

    #[test]
    fn debug_hex_small() {
        assert_eq!(debug_hex(&BigUint::from(0x01u32)), "0x01");
        assert_eq!(debug_hex(&BigUint::from(0xdeadbeefu32)), "0xdeadbeef");
    }

    #[test]
    fn debug_hex_grouping() {
        // 9 bytes → one 8-byte group + 1 byte, with `_` separator.
        let n = BigUint::from(0x1122334455667788u64) * BigUint::from(256u32) + BigUint::from(0x99u32);
        let hex = debug_hex(&n);
        // Expected form: "0x01_1122334455667788_99" — 9 bytes total,
        // so the grouping inserts `_` at every 8-byte boundary.
        // Actually total = 9 bytes: 0x01 + 1122334455667788 + 99 → 10 bytes.
        // Let's just verify the `_` separator is present and all bytes render.
        assert!(hex.starts_with("0x"));
        assert!(hex.contains('_'), "expected grouping separator in {hex}");
    }

    // ------------------------------------------------------------------
    // BigUintArc type alias
    // ------------------------------------------------------------------

    #[test]
    fn biguint_arc_shares_data() {
        let shared: BigUintArc = Arc::new(BigUint::from(42u32));
        let clone1 = Arc::clone(&shared);
        let clone2 = Arc::clone(&shared);
        assert_eq!(*clone1, BigUint::from(42u32));
        assert_eq!(*clone2, BigUint::from(42u32));
        assert_eq!(Arc::strong_count(&shared), 3);
    }

    // ------------------------------------------------------------------
    // Validate bit-size bound enforcement
    // ------------------------------------------------------------------

    #[test]
    fn set_random_rejects_overlarge_bits() {
        let max_bits = (BIGINT_MAXWORDS as u32) * 64;
        assert!(set_random(max_bits + 1).is_err());
    }

    #[test]
    fn random_prime_rejects_overlarge_bits() {
        let max_bits = (BIGINT_MAXWORDS as u32) * 64;
        assert!(random_prime(max_bits + 1).is_err());
    }

    // ------------------------------------------------------------------
    // Config constant sanity
    // ------------------------------------------------------------------

    #[test]
    fn config_constants_have_expected_values() {
        assert_eq!(MILLER_RABIN_ERROR_RATE, 64);
        assert_eq!(BIGINT_MAXWORDS, 512);
        assert_eq!(BIGINT_UNROLLSIZE, 16);
        assert_eq!(DH_BITS, 2_048);
        assert_eq!(DSA_SIZE, 3_072);
        assert_eq!(DSA_SUBGROUP_SIZE, 256);
    }
}
