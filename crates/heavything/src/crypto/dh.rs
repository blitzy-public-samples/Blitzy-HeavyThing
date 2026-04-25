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

//! Diffie–Hellman parameter types used by SSH
//! `diffie-hellman-group-exchange-sha256` key exchange (RFC 4419).
//! Port of `dh_groups.inc` (44 lines).
//!
//! # Scope
//!
//! Per AAP §0.3.2.2 and §0.5.1.3, this module deliberately omits the
//! large hand-generated DH safe-prime pools from
//! `dh_pool_{2k,3k,4k,6k,8k,16k}.inc` for two reasons:
//!
//! 1. **TLS no longer uses classical DHE.** `rustls` (the AAP-mandated
//!    TLS implementation) supports only ECDHE in TLS 1.2 and TLS 1.3,
//!    so the assembly's classical-DH safe-prime pools have no caller
//!    in the Rust port's TLS subsystem.
//! 2. **SSH uses well-known groups.** OpenSSH 8.x+ negotiates
//!    `diffie-hellman-group-exchange-sha256` with peers using the
//!    pre-computed RFC 3526 MODP groups (Group 14 = 2048 bit,
//!    Group 15 = 3072 bit, Group 16 = 4096 bit). All three are
//!    encoded statically in [`groups`] as compile-time byte arrays.
//!
//! # FASM origin
//!
//! `dh_groups.inc` defined small generators (`dhg2 = 2`, `dhg3 = 3`,
//! and so on as data structures with embedded primes). `dh_pool.inc`
//! commented the safe-prime pool architecture and selected one of six
//! conditional includes based on the FASM compile-time `dh_bits`
//! setting (2048 / 3072 / 4096 / 6144 / 8192 / 16384). The Rust port
//! collapses both files into this single module: small generator
//! constants live in [`groups::DHG2_G`] through [`groups::DHG7_G`],
//! and primes live in [`groups::group14_prime`] through
//! [`groups::group16_prime`].
//!
//! # Public API
//!
//! * [`DhParams`] — DH domain parameters `(p, g)` shared between two
//!   communicating parties.
//! * [`DhKeypair`] — private exponent + public value for one party.
//!   Its [`Debug`] implementation **redacts the private exponent** so
//!   accidental logging cannot leak key material.
//! * [`generate_keypair`] — produces a fresh `(private, public)`
//!   keypair using [`crate::crypto::rng::block`] for randomness.
//! * [`shared_secret`] — combines a peer's public value with our
//!   private exponent to derive the raw shared secret bytes
//!   (caller is responsible for any wire-format wrapping such as
//!   the SSH `mpint` encoding from RFC 4253 §5).
//! * [`select_gex_group`] — picks the best RFC 3526 group for an
//!   incoming RFC 4419 group-exchange request `(min, want, max)`.
//!
//! # Performance
//!
//! Each prime is decoded once from a `const` byte array via
//! [`BigUint::from_bytes_be`] and cached in an [`OnceLock`]. Subsequent
//! callers pay a single 256-byte (Group 14), 384-byte (Group 15), or
//! 512-byte (Group 16) `BigUint::clone` per access.
//! [`generate_keypair`]'s dominant cost is the modular exponentiation
//! `g^x mod p`; [`BigUint::modpow`] uses sliding-window Montgomery
//! exponentiation internally per AAP §0.8.1's 3× envelope.
//!
//! # Thread safety
//!
//! All public types are `Send + Sync` because `BigUint`, `Arc`, and
//! `&'static [u8]` are. The cached primes use [`OnceLock`] per the
//! AAP §0.8.3 rule "use `std::sync::OnceLock`, not
//! `once_cell::sync::OnceCell`".
//!
//! # `unsafe` audit
//!
//! Zero `unsafe` blocks. All heavy lifting is in `num-bigint` (which
//! is `#![forbid(unsafe_code)]` in its public API) and the safe
//! `BigUint::from_bytes_be` / `BigUint::modpow` / `BigUint::to_bytes_be`
//! entry points.

// ============================================================================
// Imports
// ============================================================================

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::sync::{Arc, OnceLock};

use num_traits::{One, Zero};

use crate::config::{DH_BITS, DH_PRIVATEKEY_SIZE};
use crate::crypto::bigint::BigUint;
use crate::crypto::rng;
use crate::error::CryptoError;

// ============================================================================
// Compile-time hex → byte-array decoder
// ============================================================================
//
// We decode the RFC 3526 prime hex literals at compile time so the
// runtime path uses only the infallible `BigUint::from_bytes_be`,
// avoiding any `unwrap()` or `expect()` in production code (per AAP
// §0.8.3). A panic inside a `const fn` is a compile-time error if
// reached during `const` evaluation, so an invalid hex literal would
// fail the build, not the runtime.

/// Decode a single ASCII hex character to its 4-bit value.
///
/// Triggers a compile-time panic on invalid input. This is logically
/// equivalent to a `static_assert` and is unreachable for the
/// hard-coded RFC 3526 hex literals defined in [`groups`].
const fn decode_hex_byte(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("decode_hex_byte: invalid hexadecimal character"),
    }
}

/// Decode an even-length ASCII hex string to a fixed-size byte array.
///
/// Triggers a compile-time panic if `hex.len() != N * 2`. Used by
/// [`groups`] to derive the 256-, 384-, and 512-byte big-endian
/// representations of the RFC 3526 primes.
const fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = hex.as_bytes();
    if bytes.len() != N * 2 {
        panic!("decode_hex: hex string length must equal 2 × N");
    }
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        let hi = decode_hex_byte(bytes[2 * i]);
        let lo = decode_hex_byte(bytes[2 * i + 1]);
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    out
}

// ============================================================================
// `groups` submodule — small generators + RFC 3526 MODP primes
// ============================================================================

/// Well-known DH generators and pre-computed RFC 3526 MODP primes.
///
/// The four generator constants ([`DHG2_G`] – [`DHG7_G`]) preserve the
/// small-generator data structures from the assembly source's
/// `dh_groups.inc` (`dhg2`, `dhg3`, `dhg5`, `dhg7`). The three
/// `groupNN_prime` functions return the safe primes from RFC 3526
/// Sections 3, 4, and 5 — these replace the hand-generated safe-prime
/// pools in `dh_pool_{2k,3k,4k}.inc` per AAP §0.3.2.2 and provide
/// interoperability with OpenSSH's `diffie-hellman-group-exchange-sha256`
/// negotiation.
pub mod groups {
    use super::{decode_hex, BigUint, OnceLock};

    /// Small DH generator `g = 2`.
    ///
    /// Mirrors the FASM `dhg2` data structure at `dh_groups.inc:29`.
    /// Used as the default generator for RFC 3526 Groups 14 / 15 / 16
    /// and for the runtime-generated safe primes from
    /// [`crate::crypto::bigint::dh_params`].
    pub const DHG2_G: u32 = 2;

    /// Small DH generator `g = 3`.
    ///
    /// Mirrors the FASM `dhg3` data structure at `dh_groups.inc:39`.
    /// Used by `crate::crypto::bigint::dh_params` as a fallback when
    /// `g = 2` is not a quadratic residue modulo a freshly generated
    /// safe prime.
    pub const DHG3_G: u32 = 3;

    /// Small DH generator `g = 5`.
    ///
    /// Mirrors the FASM `dhg5` data structure family in `dh_groups.inc`.
    /// Tertiary fallback after [`DHG2_G`] and [`DHG3_G`] for safe-prime
    /// quadratic-residue search.
    pub const DHG5_G: u32 = 5;

    /// Small DH generator `g = 7`.
    ///
    /// Mirrors the FASM `dhg7` data structure family in `dh_groups.inc`.
    /// Quaternary fallback used by safe-prime quadratic-residue search.
    pub const DHG7_G: u32 = 7;

    // ------------------------------------------------------------------
    // RFC 3526 Section 3 — 2048-bit MODP Group 14
    // ------------------------------------------------------------------
    //
    // p = 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
    // generator g = 2 (assigned id 14)
    //
    // The hex literal below is the verbatim concatenation of the
    // 8-character blocks from RFC 3526 §3 (lines 17–28 of the published
    // RFC). Each line in the `concat!` invocation contributes 64 hex
    // characters = 32 bytes; total 8 × 64 = 512 hex characters = 256
    // bytes = 2048 bits.

    const GROUP14_HEX: &str = concat!(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    );

    /// Compile-time-decoded big-endian byte representation of Group 14's `p`.
    const GROUP14_BYTES: [u8; 256] = decode_hex::<256>(GROUP14_HEX);

    /// RFC 3526 §3 — 2048-bit MODP Group 14 safe prime.
    ///
    /// The bytes are decoded once at first call and cached in an
    /// [`OnceLock`]; subsequent calls clone the cached `BigUint`.
    /// This is the default DH group used by the SSH KEX subsystem
    /// when an incoming `diffie-hellman-group-exchange-sha256`
    /// request ranges over 2048 bits (the OpenSSH default).
    #[must_use]
    pub fn group14_prime() -> BigUint {
        static CACHED: OnceLock<BigUint> = OnceLock::new();
        CACHED
            .get_or_init(|| BigUint::from_bytes_be(&GROUP14_BYTES))
            .clone()
    }

    // ------------------------------------------------------------------
    // RFC 3526 Section 4 — 3072-bit MODP Group 15
    // ------------------------------------------------------------------
    //
    // p = 2^3072 - 2^3008 - 1 + 2^64 * { [2^2942 pi] + 1690314 }
    // generator g = 2 (assigned id 15)
    //
    // 12 × 64 = 768 hex characters = 384 bytes = 3072 bits.

    const GROUP15_HEX: &str = concat!(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
        "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
        "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
        "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
        "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    );

    /// Compile-time-decoded big-endian byte representation of Group 15's `p`.
    const GROUP15_BYTES: [u8; 384] = decode_hex::<384>(GROUP15_HEX);

    /// RFC 3526 §4 — 3072-bit MODP Group 15 safe prime.
    ///
    /// Returned when an SSH peer's `diffie-hellman-group-exchange-sha256`
    /// request `(min, want, max)` ranges over 3072 bits and 2048 is
    /// below `min` or unsuitable. Cached on first access in an
    /// [`OnceLock`].
    #[must_use]
    pub fn group15_prime() -> BigUint {
        static CACHED: OnceLock<BigUint> = OnceLock::new();
        CACHED
            .get_or_init(|| BigUint::from_bytes_be(&GROUP15_BYTES))
            .clone()
    }

    // ------------------------------------------------------------------
    // RFC 3526 Section 5 — 4096-bit MODP Group 16
    // ------------------------------------------------------------------
    //
    // p = 2^4096 - 2^4032 - 1 + 2^64 * { [2^3966 pi] + 240904 }
    // generator g = 2 (assigned id 16)
    //
    // 16 × 64 = 1024 hex characters = 512 bytes = 4096 bits.

    const GROUP16_HEX: &str = concat!(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
        "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
        "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
        "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
        "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
        "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8",
        "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
        "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
        "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
    );

    /// Compile-time-decoded big-endian byte representation of Group 16's `p`.
    const GROUP16_BYTES: [u8; 512] = decode_hex::<512>(GROUP16_HEX);

    /// RFC 3526 §5 — 4096-bit MODP Group 16 safe prime.
    ///
    /// Returned when an SSH peer's `diffie-hellman-group-exchange-sha256`
    /// request `(min, want, max)` ranges over 4096 bits — the maximum
    /// strength offered by the in-scope RFC 3526 set. Cached on first
    /// access in an [`OnceLock`].
    #[must_use]
    pub fn group16_prime() -> BigUint {
        static CACHED: OnceLock<BigUint> = OnceLock::new();
        CACHED
            .get_or_init(|| BigUint::from_bytes_be(&GROUP16_BYTES))
            .clone()
    }
}

// ============================================================================
// `DhParams` — DH domain parameters
// ============================================================================

/// Diffie–Hellman domain parameters: a safe prime `p` and a generator
/// `g` of a sufficiently large subgroup of (Z/pZ)\*.
///
/// Both parties in a DH exchange agree on the same `(p, g)` pair
/// (typically negotiated via SSH RFC 4419 group exchange or pulled
/// from one of the static [`groups`] entries). Sharing of a single
/// parameter set across many keypairs is the common case, which is
/// why [`DhKeypair`] stores its parameters behind an [`Arc`] rather
/// than by value.
///
/// `Clone` is implemented because `BigUint::clone` is cheap enough
/// (a refcount bump on the underlying `Vec<u64>`) and because the
/// shared-Arc pattern in [`DhKeypair`] occasionally needs to fork
/// a parameter set during testing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhParams {
    /// Safe prime modulus. Must be `>= 2^DH_BITS` for security.
    pub p: BigUint,
    /// Generator of a large subgroup of (Z/pZ)\*. For all RFC 3526
    /// MODP groups this is the small integer `2`; for runtime-generated
    /// safe primes from `crate::crypto::bigint::dh_params` it can be
    /// any of the small generators `2`, `3`, `5`, `7`.
    pub g: BigUint,
}

// ============================================================================
// `DhKeypair` — private + public DH key pair
// ============================================================================

/// A Diffie–Hellman private + public key pair tied to a specific
/// parameter set.
///
/// `params` is held behind an [`Arc`] so that multiple keypairs
/// (one per session, for instance) can share a single
/// [`groups::group14_prime`] without each keypair owning a separate
/// 256-byte allocation.
///
/// **Security note.** The [`Debug`] implementation deliberately
/// **redacts** the `private` exponent (it prints `"<redacted>"`) so
/// that accidental `dbg!`, `tracing::debug!`, or panic backtraces do
/// not leak the long-term key. The `PartialEq` derive is intentionally
/// **omitted** so two keypairs cannot be compared via `==` (which would
/// route through the private exponent). Callers that genuinely need
/// equality for testing must compare `private` and `public` fields
/// explicitly.
pub struct DhKeypair {
    /// Shared DH parameters. Multiple keypairs commonly share a single
    /// `Arc` to the same [`DhParams`] instance.
    pub params: Arc<DhParams>,
    /// Private exponent `x` such that `public = g^x mod p`. Treated as
    /// long-term key material — never printed by [`Debug`].
    pub private: BigUint,
    /// Public value `g^private mod p`. Sent on the wire to the peer.
    pub public: BigUint,
}

impl Debug for DhKeypair {
    /// Redacts `private` to prevent accidental key exposure in logs.
    ///
    /// Output is structurally identical to the auto-derived `Debug` for
    /// every field except `private`, which is replaced with the
    /// literal string `"<redacted>"`. AAP §0.7 / Phase 7 requirement.
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("DhKeypair")
            .field("params", &self.params)
            .field("private", &"<redacted>")
            .field("public", &self.public)
            .finish()
    }
}

// ============================================================================
// Private helper: validate peer public value range [2, p-2]
// ============================================================================

/// Verify that `peer_public ∈ [2, p-2]` per RFC 2631 §2.1.5.
///
/// This is the small-subgroup-attack mitigation: rejecting `0`, `1`,
/// and `p-1` ensures the resulting shared secret is in the correct
/// large prime-order subgroup. Returns [`CryptoError::Dh`] with a
/// caller-friendly message on rejection.
///
/// (A full subgroup-membership test `peer_public^q mod p == 1` is
/// not performed because `q` is not part of the [`DhParams`] for
/// classical safe-prime DH; the SSH KEX protocol elsewhere binds the
/// shared secret into the exchange hash, which provides the same
/// security guarantee.)
fn check_peer_public_range(p: &BigUint, peer_public: &BigUint) -> Result<(), CryptoError> {
    // Guard 1: peer_public != 0
    if peer_public.is_zero() {
        return Err(CryptoError::Dh(
            "peer DH public value is zero (small-subgroup attack)".to_string(),
        ));
    }
    // Guard 2: peer_public != 1
    if peer_public.is_one() {
        return Err(CryptoError::Dh(
            "peer DH public value is one (small-subgroup attack)".to_string(),
        ));
    }
    // Guard 3: peer_public < p (i.e. it is a valid residue mod p)
    if peer_public >= p {
        return Err(CryptoError::Dh(
            "peer DH public value is >= p (out of range)".to_string(),
        ));
    }
    // Guard 4: peer_public != p - 1.
    // Compute (p - 1) and compare. `p` is a safe prime ≥ 2048 bits, so
    // this subtraction is cheap and never underflows.
    let p_minus_one: BigUint = p - BigUint::one();
    if *peer_public == p_minus_one {
        return Err(CryptoError::Dh(
            "peer DH public value is p - 1 (small-subgroup attack)".to_string(),
        ));
    }
    Ok(())
}

// ============================================================================
// `generate_keypair` — fresh ephemeral keypair
// ============================================================================

/// Generate a fresh Diffie–Hellman keypair under the supplied parameters.
///
/// The private exponent is drawn from
/// [`crate::crypto::rng::block`] (HMAC-DRBG seeded from `/dev/urandom`)
/// and is exactly [`crate::config::DH_PRIVATEKEY_SIZE`] bits long
/// (256 bits by default per AAP §0.6 / `ht_defaults.inc`). The public
/// value is computed as `g^private mod p` via `num-bigint`'s
/// sliding-window Montgomery exponentiation
/// ([`BigUint::modpow`]).
///
/// # Errors
///
/// Returns [`CryptoError::Dh`] if the requested private-key size
/// is degenerate (`< 2` bits) or if the resulting public value is
/// unexpectedly `0` or `1`. The public-value sanity check guards
/// against pathological [`DhParams`] (for instance `g = 0` or
/// `g = 1` which a malicious caller could construct).
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use heavything::crypto::dh::{generate_keypair, groups, DhParams};
///
/// let params = Arc::new(DhParams {
///     p: groups::group14_prime(),
///     g: heavything::crypto::bigint::BigUint::from(groups::DHG2_G),
/// });
/// let kp = generate_keypair(params).unwrap();
/// // kp.public is now g^kp.private mod p, ready to send on the wire.
/// ```
pub fn generate_keypair(params: Arc<DhParams>) -> Result<DhKeypair, CryptoError> {
    // Sanity-check the requested private-exponent size. Anything below
    // 2 bits cannot represent a value in [2, p-2] for any reasonable
    // prime, so we reject early with a descriptive message.
    if DH_PRIVATEKEY_SIZE < 2 {
        return Err(CryptoError::Dh(format!(
            "DH_PRIVATEKEY_SIZE = {DH_PRIVATEKEY_SIZE} is too small \
             (must be >= 2 bits)"
        )));
    }

    // Allocate a byte buffer large enough to hold DH_PRIVATEKEY_SIZE
    // bits, then trim the high-order byte's surplus bits so the
    // resulting BigUint has exactly DH_PRIVATEKEY_SIZE significant
    // bits. This mirrors the masking pattern from
    // `bigint::set_random` and matches the FASM `bigint$set_random`
    // contract in `bigint.inc`.
    let byte_count = DH_PRIVATEKEY_SIZE.div_ceil(8);
    let mut bytes = vec![0u8; byte_count];

    // Draw cryptographic randomness. `rng::block` cannot fail at the
    // type level (its signature is `fn block(out: &mut [u8])`); any
    // initialization failure was reported via `rng::init` at startup.
    rng::block(&mut bytes);

    // Mask off the top bits that are beyond DH_PRIVATEKEY_SIZE. For
    // example, when DH_PRIVATEKEY_SIZE = 256 (the default), byte_count
    // is 32 and extra_bits is 0, so this branch is a no-op. For
    // non-byte-aligned sizes (e.g. 250 bits) we clear the surplus 6
    // high bits in `bytes[0]` so the resulting integer is exactly
    // `DH_PRIVATEKEY_SIZE` bits.
    let extra_bits = (byte_count * 8) - DH_PRIVATEKEY_SIZE;
    if extra_bits > 0 && !bytes.is_empty() {
        let keep_bits = 8 - extra_bits;
        bytes[0] &= (1u8 << keep_bits) - 1;
    }

    // Force the most-significant bit of the buffer to 1 so the
    // resulting private exponent has *exactly* DH_PRIVATEKEY_SIZE
    // significant bits (avoiding the case where the top bytes happen
    // to be zero, which would yield a smaller exponent and weaker key).
    if !bytes.is_empty() {
        let top_bit_position_within_byte = (DH_PRIVATEKEY_SIZE - 1) % 8;
        let top_byte_index = if extra_bits == 0 {
            0
        } else {
            // After masking, the first byte holds the top bits. Top
            // bit lives in `bytes[0]` either way; we just need the
            // correct bit-within-byte.
            0
        };
        bytes[top_byte_index] |= 1u8 << top_bit_position_within_byte;
    }

    // Convert byte buffer to BigUint (infallible).
    let private = BigUint::from_bytes_be(&bytes);

    // Compute public = g^private mod p. modpow on num-bigint is
    // sliding-window Montgomery exponentiation; for a 2048-bit
    // modulus and 256-bit exponent it completes in a few milliseconds.
    let public = params.g.modpow(&private, &params.p);

    // Sanity-check: if g was pathological (g = 0 or g = 1) the
    // resulting public value collapses to 0 or 1, which would betray
    // the private exponent or fail validation on the peer side.
    if public.is_zero() || public.is_one() {
        return Err(CryptoError::Dh(
            "computed DH public value is 0 or 1 (degenerate parameters)".to_string(),
        ));
    }

    Ok(DhKeypair {
        params,
        private,
        public,
    })
}

// ============================================================================
// `shared_secret` — derive raw shared secret bytes
// ============================================================================

/// Combine our private exponent with the peer's public value to
/// derive the raw DH shared secret `s = peer_public^private mod p`.
///
/// The return value is the **big-endian byte encoding** of `s`,
/// stripped of leading zeros (matching `BigUint::to_bytes_be`'s
/// natural output). Callers that need the SSH `mpint` wire format
/// (RFC 4253 §5: a 4-byte big-endian length followed by the bytes,
/// with a leading `0x00` prepended whenever the high bit of the first
/// byte is set) must perform that wrapping themselves — typically in
/// `crate::net::ssh::kex`.
///
/// # Errors
///
/// Returns [`CryptoError::Dh`] if `their_public` fails the
/// RFC 2631 `[2, p-2]` range check (i.e. the peer sent `0`, `1`,
/// `p-1`, or a value `>= p`). This guards against the small-subgroup
/// confinement attack and against malicious peers sending
/// out-of-range values to weaken the resulting secret.
///
/// # Example
///
/// ```ignore
/// // Two parties Alice and Bob share parameters; they exchange
/// // public values and derive the same shared secret.
/// let alice_secret = shared_secret(&alice_keypair, &bob_keypair.public)?;
/// let bob_secret   = shared_secret(&bob_keypair,   &alice_keypair.public)?;
/// assert_eq!(alice_secret, bob_secret);
/// ```
pub fn shared_secret(my_keypair: &DhKeypair, their_public: &BigUint) -> Result<Vec<u8>, CryptoError> {
    // Validate peer public value range per RFC 2631.
    check_peer_public_range(&my_keypair.params.p, their_public)?;

    // Compute s = their_public^my_private mod p. Same modpow
    // implementation as generate_keypair — for matching parameters
    // (p, g) this yields the identical shared secret on both sides.
    let secret = their_public.modpow(&my_keypair.private, &my_keypair.params.p);

    // A shared secret of 0 or 1 should never occur for valid params
    // and a valid peer key, but guard anyway. (For safe primes where
    // `p` has order `(p-1)/2` and `g` is a quadratic residue, the
    // result lies in the prime-order subgroup, so `s == 0` is
    // impossible and `s == 1` only happens when `their_public == 1`
    // — already rejected above.)
    if secret.is_zero() || secret.is_one() {
        return Err(CryptoError::Dh(
            "DH shared secret is 0 or 1 (degenerate exchange)".to_string(),
        ));
    }

    Ok(secret.to_bytes_be())
}

// ============================================================================
// `select_gex_group` — RFC 4419 group-exchange group selection
// ============================================================================

/// Select the most appropriate RFC 3526 MODP group for an SSH
/// `diffie-hellman-group-exchange-sha256` request `(min, want, max)`.
///
/// Per RFC 4419 §3, the client sends three bit-length hints: a minimum
/// acceptable size (`min`), a preferred size (`want`), and a maximum
/// acceptable size (`max`). The server picks any group whose modulus
/// size lies in `[min, max]`, preferring one as close to `want` as
/// possible.
///
/// This implementation considers exactly the three RFC 3526 groups
/// supplied by [`groups::group14_prime`] (2048 bit),
/// [`groups::group15_prime`] (3072 bit), and
/// [`groups::group16_prime`] (4096 bit). It picks the group whose
/// bit size lies in `[min, max]` and is closest to `want` (ties
/// broken by preferring the smaller group, since smaller groups
/// finish KEX faster and the client clearly accepts that size).
///
/// If `want` is `0` (a sentinel some clients use), it is replaced
/// by [`crate::config::DH_BITS`] (2048).
///
/// # Errors
///
/// Returns [`CryptoError::Dh`] if no RFC 3526 group fits the
/// `[min, max]` window (e.g. the client requests `min = 8192` bits,
/// which exceeds the maximum offered group of 4096 bits).
///
/// All returned [`DhParams`] use generator `g = 2`
/// ([`groups::DHG2_G`]) per RFC 3526.
pub fn select_gex_group(min: u32, want: u32, max: u32) -> Result<DhParams, CryptoError> {
    // Replace sentinel `want = 0` with the configured default.
    let want_resolved = if want == 0 { DH_BITS as u32 } else { want };

    // Sanity-check the request: min must be <= max.
    if min > max {
        return Err(CryptoError::Dh(format!(
            "RFC 4419 group exchange: min={min} exceeds max={max}"
        )));
    }

    // The candidate set: (size_bits, prime-loader closure).
    // Listed smallest-first so ties prefer the smaller group.
    let candidates: [(u32, fn() -> BigUint); 3] = [
        (2048, groups::group14_prime),
        (3072, groups::group15_prime),
        (4096, groups::group16_prime),
    ];

    // Score each candidate that lies within [min, max] by its
    // distance from want_resolved; pick the lowest-distance candidate
    // with smallest size as the tie-breaker.
    let mut best: Option<(u32, fn() -> BigUint, u32)> = None;
    for (size, loader) in candidates {
        if size < min || size > max {
            continue;
        }
        let distance = size.abs_diff(want_resolved);
        match best {
            None => best = Some((size, loader, distance)),
            Some((_, _, prev_distance)) if distance < prev_distance => {
                best = Some((size, loader, distance));
            }
            _ => { /* current candidate is no better */ }
        }
    }

    let (_chosen_size, loader, _) = best.ok_or_else(|| {
        CryptoError::Dh(format!(
            "RFC 4419 group exchange: no built-in MODP group fits \
             min={min} want={want_resolved} max={max}"
        ))
    })?;

    Ok(DhParams {
        p: loader(),
        g: BigUint::from(groups::DHG2_G),
    })
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// RFC 3526 §3 says Group 14's prime is exactly 2048 bits.
    #[test]
    fn group14_is_2048_bits() {
        let p = groups::group14_prime();
        assert_eq!(p.bits(), 2048, "Group 14 must be exactly 2048 bits");
    }

    /// RFC 3526 §4 says Group 15's prime is exactly 3072 bits.
    #[test]
    fn group15_is_3072_bits() {
        let p = groups::group15_prime();
        assert_eq!(p.bits(), 3072, "Group 15 must be exactly 3072 bits");
    }

    /// RFC 3526 §5 says Group 16's prime is exactly 4096 bits.
    #[test]
    fn group16_is_4096_bits() {
        let p = groups::group16_prime();
        assert_eq!(p.bits(), 4096, "Group 16 must be exactly 4096 bits");
    }

    /// All three groups share the same 1536-bit prefix and 64-bit
    /// suffix `FFFFFFFFFFFFFFFF`. Spot-check that the high bytes are
    /// `0xFF` (consistent with `2^N - small`) for each group.
    #[test]
    fn group_primes_have_expected_high_bytes() {
        for prime_fn in [
            groups::group14_prime,
            groups::group15_prime,
            groups::group16_prime,
        ] {
            let p = prime_fn();
            let bytes = p.to_bytes_be();
            assert_eq!(bytes[0], 0xFF, "high byte of safe prime must be 0xFF");
            assert_eq!(bytes[1], 0xFF, "second byte of safe prime must be 0xFF");
            assert_eq!(
                bytes[bytes.len() - 1],
                0xFF,
                "low byte of safe prime must be 0xFF"
            );
        }
    }

    /// `groups::group14_prime` returns the same value on repeated
    /// calls (verifies `OnceLock` caching behaves like a stable
    /// constant).
    #[test]
    fn group14_is_idempotent() {
        let p1 = groups::group14_prime();
        let p2 = groups::group14_prime();
        assert_eq!(p1, p2);
    }

    /// Two-party key agreement: Alice and Bob each compute a shared
    /// secret on RFC 3526 Group 14 and they must match (the cardinal
    /// DH correctness property).
    #[test]
    fn group14_two_party_agreement() {
        // Initialize RNG before drawing private keys.
        rng::init().expect("rng::init must succeed in test environment");

        let params = Arc::new(DhParams {
            p: groups::group14_prime(),
            g: BigUint::from(groups::DHG2_G),
        });
        let alice = generate_keypair(Arc::clone(&params)).unwrap();
        let bob = generate_keypair(Arc::clone(&params)).unwrap();

        let alice_secret = shared_secret(&alice, &bob.public).unwrap();
        let bob_secret = shared_secret(&bob, &alice.public).unwrap();

        assert_eq!(
            alice_secret, bob_secret,
            "DH shared secrets must match between Alice and Bob"
        );
        assert!(!alice_secret.is_empty(), "DH shared secret must be non-empty");
    }

    /// Same correctness property on Group 15 (3072-bit). Slightly
    /// slower test but exercises a different prime.
    #[test]
    fn group15_two_party_agreement() {
        rng::init().expect("rng::init must succeed in test environment");

        let params = Arc::new(DhParams {
            p: groups::group15_prime(),
            g: BigUint::from(groups::DHG2_G),
        });
        let alice = generate_keypair(Arc::clone(&params)).unwrap();
        let bob = generate_keypair(Arc::clone(&params)).unwrap();

        let alice_secret = shared_secret(&alice, &bob.public).unwrap();
        let bob_secret = shared_secret(&bob, &alice.public).unwrap();

        assert_eq!(alice_secret, bob_secret);
    }

    /// `shared_secret` must reject `their_public == 0`.
    #[test]
    fn shared_secret_rejects_zero_peer_public() {
        rng::init().expect("rng::init must succeed in test environment");

        let params = Arc::new(DhParams {
            p: groups::group14_prime(),
            g: BigUint::from(groups::DHG2_G),
        });
        let alice = generate_keypair(Arc::clone(&params)).unwrap();
        let zero = BigUint::from(0u32);
        let result = shared_secret(&alice, &zero);
        assert!(matches!(result, Err(CryptoError::Dh(_))));
    }

    /// `shared_secret` must reject `their_public == 1`.
    #[test]
    fn shared_secret_rejects_one_peer_public() {
        rng::init().expect("rng::init must succeed in test environment");

        let params = Arc::new(DhParams {
            p: groups::group14_prime(),
            g: BigUint::from(groups::DHG2_G),
        });
        let alice = generate_keypair(Arc::clone(&params)).unwrap();
        let one = BigUint::from(1u32);
        let result = shared_secret(&alice, &one);
        assert!(matches!(result, Err(CryptoError::Dh(_))));
    }

    /// `shared_secret` must reject `their_public == p - 1`.
    #[test]
    fn shared_secret_rejects_p_minus_one() {
        rng::init().expect("rng::init must succeed in test environment");

        let p = groups::group14_prime();
        let p_minus_one = &p - BigUint::one();
        let params = Arc::new(DhParams {
            p,
            g: BigUint::from(groups::DHG2_G),
        });
        let alice = generate_keypair(Arc::clone(&params)).unwrap();
        let result = shared_secret(&alice, &p_minus_one);
        assert!(matches!(result, Err(CryptoError::Dh(_))));
    }

    /// `shared_secret` must reject `their_public >= p`.
    #[test]
    fn shared_secret_rejects_out_of_range_peer_public() {
        rng::init().expect("rng::init must succeed in test environment");

        let p = groups::group14_prime();
        let params = Arc::new(DhParams {
            p: p.clone(),
            g: BigUint::from(groups::DHG2_G),
        });
        let alice = generate_keypair(Arc::clone(&params)).unwrap();
        let too_big = &p + BigUint::one();
        let result = shared_secret(&alice, &too_big);
        assert!(matches!(result, Err(CryptoError::Dh(_))));
    }

    /// `generate_keypair` produces public values strictly between
    /// `1` and `p - 1` (i.e. valid residues that the peer will accept).
    #[test]
    fn generate_keypair_public_in_range() {
        rng::init().expect("rng::init must succeed in test environment");

        let params = Arc::new(DhParams {
            p: groups::group14_prime(),
            g: BigUint::from(groups::DHG2_G),
        });
        let kp = generate_keypair(Arc::clone(&params)).unwrap();

        assert!(!kp.public.is_zero());
        assert!(!kp.public.is_one());
        assert!(kp.public < params.p);
        assert!(kp.public != &params.p - BigUint::one());
    }

    /// `generate_keypair` private exponents have exactly
    /// `DH_PRIVATEKEY_SIZE` significant bits (the high bit is forced
    /// on by the masking pass).
    #[test]
    fn generate_keypair_private_has_expected_bits() {
        rng::init().expect("rng::init must succeed in test environment");

        let params = Arc::new(DhParams {
            p: groups::group14_prime(),
            g: BigUint::from(groups::DHG2_G),
        });
        let kp = generate_keypair(Arc::clone(&params)).unwrap();

        assert_eq!(
            kp.private.bits() as usize,
            DH_PRIVATEKEY_SIZE,
            "private exponent must have exactly DH_PRIVATEKEY_SIZE bits"
        );
    }

    /// Two consecutive calls to `generate_keypair` produce different
    /// private exponents (sanity check that the RNG isn't stuck).
    #[test]
    fn generate_keypair_produces_unique_keys() {
        rng::init().expect("rng::init must succeed in test environment");

        let params = Arc::new(DhParams {
            p: groups::group14_prime(),
            g: BigUint::from(groups::DHG2_G),
        });
        let kp1 = generate_keypair(Arc::clone(&params)).unwrap();
        let kp2 = generate_keypair(Arc::clone(&params)).unwrap();

        assert_ne!(kp1.private, kp2.private, "private exponents must differ");
        assert_ne!(kp1.public, kp2.public, "public values must differ");
    }

    /// `Debug` for [`DhKeypair`] redacts the private exponent.
    #[test]
    fn debug_redacts_private_key() {
        let params = Arc::new(DhParams {
            p: BigUint::from(23u32),
            g: BigUint::from(5u32),
        });
        let kp = DhKeypair {
            params,
            private: BigUint::from(0xDEAD_BEEF_u64),
            public: BigUint::from(7u32),
        };
        let dbg = format!("{kp:?}");
        assert!(
            dbg.contains("<redacted>"),
            "Debug output must contain '<redacted>'"
        );
        assert!(
            !dbg.contains("3735928559") && !dbg.contains("DEADBEEF"),
            "Debug output must not contain the private value"
        );
    }

    /// `select_gex_group(1024, 2048, 3072)` selects Group 14 (2048 bit).
    #[test]
    fn select_gex_picks_2048_when_want_is_2048() {
        let params = select_gex_group(1024, 2048, 3072).unwrap();
        assert_eq!(params.p, groups::group14_prime());
        assert_eq!(params.g, BigUint::from(groups::DHG2_G));
    }

    /// `select_gex_group(2048, 3072, 4096)` selects Group 15 (3072 bit).
    #[test]
    fn select_gex_picks_3072_when_want_is_3072() {
        let params = select_gex_group(2048, 3072, 4096).unwrap();
        assert_eq!(params.p, groups::group15_prime());
    }

    /// `select_gex_group(2048, 4096, 8192)` selects Group 16 (4096 bit).
    #[test]
    fn select_gex_picks_4096_when_want_is_4096() {
        let params = select_gex_group(2048, 4096, 8192).unwrap();
        assert_eq!(params.p, groups::group16_prime());
    }

    /// `want = 0` falls through to the configured default `DH_BITS`.
    #[test]
    fn select_gex_zero_want_falls_back_to_default() {
        let params = select_gex_group(1024, 0, 8192).unwrap();
        // Default DH_BITS is 2048, so Group 14 should be picked.
        assert_eq!(params.p, groups::group14_prime());
    }

    /// `min > max` is rejected.
    #[test]
    fn select_gex_rejects_inverted_range() {
        let result = select_gex_group(8192, 4096, 1024);
        assert!(matches!(result, Err(CryptoError::Dh(_))));
    }

    /// No RFC 3526 group fits a `[min=8193, max=16384]` request.
    #[test]
    fn select_gex_rejects_unsatisfiable_range() {
        let result = select_gex_group(8193, 16384, 16384);
        assert!(matches!(result, Err(CryptoError::Dh(_))));
    }

    /// `select_gex_group(1024, 1024, 1024)` is unsatisfiable since
    /// our smallest group is 2048 bits.
    #[test]
    fn select_gex_rejects_too_small_range() {
        let result = select_gex_group(1024, 1024, 1024);
        assert!(matches!(result, Err(CryptoError::Dh(_))));
    }

    /// Closest-to-want tie-breaking: `(min=2048, want=2560, max=3072)`
    /// has Group 14 (distance 512) and Group 15 (distance 512). The
    /// implementation prefers the smaller-and-equal-distance group.
    #[test]
    fn select_gex_ties_prefer_smaller_group() {
        let params = select_gex_group(2048, 2560, 3072).unwrap();
        assert_eq!(params.p, groups::group14_prime());
    }

    /// All four `groups::DHG*_G` constants match the FASM
    /// `dh_groups.inc` data structures.
    #[test]
    fn small_generator_constants_match_fasm() {
        assert_eq!(groups::DHG2_G, 2);
        assert_eq!(groups::DHG3_G, 3);
        assert_eq!(groups::DHG5_G, 5);
        assert_eq!(groups::DHG7_G, 7);
    }

    /// `DhParams` derives `Clone`, `Debug`, `PartialEq`, `Eq`.
    #[test]
    fn dh_params_implements_required_traits() {
        let p1 = DhParams {
            p: BigUint::from(23u32),
            g: BigUint::from(5u32),
        };
        let p2 = p1.clone();
        assert_eq!(p1, p2);
        let _ = format!("{p1:?}"); // ensure Debug compiles
    }
}
