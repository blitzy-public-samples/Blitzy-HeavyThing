// Rust translation © 2026, licensed under GPL-3.0-or-later.
//
// Derived from the HeavyThing assembly library:
//   Copyright © 2015–2018 2 Ton Digital, Jeff Marrison <info@2ton.com.au>
//   Source: `aes.inc` (1,423 lines).
//
// Algorithm attribution chain (preserved from `aes.inc` lines 22–37):
//   "aes128/aes192/aes256 goodies, based on public domain implementation
//    from Wei Dai" — Wei Dai's Crypto++ AES contribution is in the public
//    domain. The FASM file additionally implements Wei Dai's timing
//    countermeasures for the non-AES-NI fallback path. In the Rust port
//    these timing countermeasures come "for free" because the RustCrypto
//    `aes` crate is a constant-time implementation by design (fixsliced
//    bitsliced code path on the soft fallback, AES-NI intrinsics on
//    hardware that supports them).
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

//! AES block-cipher wrappers — port of `aes.inc` (1,423 lines).
//!
//! # Overview
//!
//! AEAD (GCM) modes are delegated to [`ring::aead`]. Raw AES-CBC
//! (required by the SSH transport per AAP §0.1.1 and §0.6.1) uses the
//! [`aes`] and [`cbc`] crates from the RustCrypto project because
//! `ring` does NOT expose raw AES-CBC (AAP §0.6.1 explicitly notes
//! this gap). Single-block AES-ECB is also exposed for the few
//! protocol-construction sites (e.g., AES-CFB synthesis from raw ECB
//! used by some TLS tooling) per AAP §0.5.1.3.
//!
//! Runtime AES-NI detection happens via [`crate::cpu::features`]
//! and is reported through the [`aesni_available`] helper. Per AAP
//! §0.1.1 ("CPU feature detection must be runtime, not compile-time,
//! to preserve graceful degradation"), the choice between hardware
//! and software code paths is **never** made via
//! `#[cfg(target_feature = "aes")]`. Both [`ring`] and [`aes`] crates
//! perform their own internal `std::is_x86_feature_detected!("aes")`
//! dispatch at runtime, so this module's role is purely to wrap them
//! and report the host's AES-NI capability for diagnostic and
//! benchmark output (`BENCHMARK_REPORT.md` per AAP §0.8.5).
//!
//! # FASM-to-Rust mapping
//!
//! The FASM source has the following high-level structure:
//!
//! | FASM symbol            | `aes.inc` lines | Rust replacement                         |
//! |------------------------|-----------------|------------------------------------------|
//! | `aes$tls`              | 45–50           | Direct functions; no vtable preserved    |
//! | `aes$Se` / `aes$Sd`    | 65–98           | Encapsulated by `aes` crate's S-boxes    |
//! | `aes$Te` / `aes$Td`    | 100–243         | Encapsulated by `aes` crate's T-tables   |
//! | `aes$init_common`      | 246–268         | `Aes*Cbc::new_*` constructors            |
//! | `aes$init_encrypt`     | 611–672         | `Aes*Cbc::new_encrypt` constructors      |
//! | `aes$init_decrypt`     | 675–971         | `Aes*Cbc::new_decrypt` constructors      |
//! | `aes$encrypt`          | 974–1196        | `cbc::Encryptor::encrypt_blocks_mut`     |
//! | `aes$decrypt`          | 1199–1422       | `cbc::Decryptor::decrypt_blocks_mut`     |
//! | `has_AESNI` flag       | 261, 621, 982   | `cpu::features().has_aesni` (reporting)  |
//!
//! The FASM `aes$tls` 4-method vtable (`init_encrypt`, `encrypt`,
//! `init_decrypt`, `decrypt`) is **not** preserved as a struct because
//! Rust callers (in `crate::net::ssh::cipher`) interact with the CBC
//! state directly through the typed `Aes128Cbc` / `Aes192Cbc` /
//! `Aes256Cbc` structs returned by the `aes*_cbc_new_*` constructor
//! functions.
//!
//! # CBC state semantics
//!
//! The FASM `aes$encrypt` / `aes$decrypt` are **stateless single-block**
//! primitives — the assembly's `webserver`/`ssh` higher layers manage
//! the IV chain explicitly. The Rust port intentionally moves IV
//! chaining into the [`Aes128Cbc`] / [`Aes192Cbc`] / [`Aes256Cbc`]
//! structs so that callers can use the idiomatic
//! [`encrypt_blocks`](Aes128Cbc::encrypt_blocks) /
//! [`decrypt_blocks`](Aes128Cbc::decrypt_blocks) methods to process a
//! sequence of blocks in one call without re-deriving the chaining
//! state. The wire-level output is byte-identical: encrypting `N`
//! 16-byte blocks in a single `encrypt_blocks` call produces the same
//! ciphertext as `N` separate FASM `aes$encrypt` calls with manual
//! IV chaining.
//!
//! No PKCS#7 (or any other) padding is performed at this layer —
//! callers are responsible for ensuring `in_out.len() % 16 == 0`.
//! This matches SSH's wire-format semantics where SSH does its own
//! length framing (RFC 4253 §6.1) and adds its own random padding;
//! adding PKCS#7 here would cause SSH packet desynchronisation.
//!
//! # Key sizes
//!
//! | Variant       | Key bytes | Round count | FASM `aes_rounds_ofs` value |
//! |---------------|-----------|-------------|-----------------------------|
//! | AES-128       | 16        | 10          | 10 (`aes.inc` line 257)     |
//! | AES-192       | 24        | 12          | 12                          |
//! | AES-256       | 32        | 14          | 14                          |
//!
//! Block size is always 128 bits (16 bytes) per FIPS 197 §2.2.
//! [`BLOCK_SIZE`] re-exports this value at the module level so callers
//! can write `aes::BLOCK_SIZE` rather than the longer
//! `Aes256Cbc::BLOCK_SIZE`.
//!
//! # AEAD (AES-256-GCM)
//!
//! [`aes256_gcm_seal`] and [`aes256_gcm_open`] expose AES-256-GCM via
//! [`ring::aead`]. AES-256-GCM is the AEAD used by:
//!
//! * The TLS session-cache encryption path
//!   (`tls_server_encryptcache = 1` default per AAP §0.7.2.4 and the
//!   FASM `tls.inc` lines ~3500–3600). The session cache stores
//!   `(SessionId, EncryptedSessionState)` pairs in `mappedheap` and
//!   uses AES-256-GCM with a key rotated per process startup. When
//!   [`aes256_gcm_seal`] is invoked from the session cache, the
//!   nonce is freshly generated via [`crate::crypto::rng::block`]
//!   for every entry (12 bytes, never reused).
//! * Future TLS 1.3 additions where `rustls` requires
//!   AES-256-GCM as a cipher suite (handled internally by `rustls`
//!   itself; this module is not on the TLS data path).
//!
//! **Nonce reuse is catastrophic** for GCM (it leaks the
//! authentication subkey). Both [`aes256_gcm_seal`] and
//! [`aes256_gcm_open`] take the nonce by value as a `[u8; 12]`;
//! callers MUST guarantee uniqueness. The recommended idiom is to
//! generate the nonce via [`crate::crypto::rng::block`] (12 random
//! bytes; collision probability after `n` operations is ≤ `n²/2¹⁰⁰`
//! per the birthday bound, so safe for ≤ 2⁴⁸ operations under one
//! key). The convenience helper [`aes256_gcm_seal_random_nonce`]
//! provides this idiom out of the box.
//!
//! # `unsafe` audit
//!
//! Per AAP §0.7.4.1 ("AES-NI intrinsics: 0 sites"), this module
//! contributes **zero** `unsafe` blocks to `UNSAFE_AUDIT.md`. Both
//! `ring` and the `aes`/`cbc` crates expose safe-only public APIs.
//!
//! # Memory zeroization
//!
//! Round-key state stored inside [`Aes128Cbc`], [`Aes192Cbc`], and
//! [`Aes256Cbc`] is **not** zeroed on drop. The `aes`/`cbc` crates'
//! `zeroize` cargo feature is not enabled because the `zeroize`
//! crate is not in the workspace dependency inventory per AAP
//! §0.6.1. Reaching into the wrapped state to zero memory directly
//! would require an `unsafe` block, which violates the
//! "0 `unsafe` sites" budget for this module. The OS-level page
//! reuse policy and stack reuse semantics are therefore the only
//! line of defense against memory-disclosure attacks. Wei Dai's
//! original timing-side-channel countermeasures (the assembly's
//! threat model) are preserved in full by the `aes` crate's
//! constant-time implementation. Callers requiring stricter
//! memory-disclosure protection should propose adding `zeroize` to
//! the workspace dependency inventory in a follow-up change.
//!
//! # Performance
//!
//! AAP §0.8.1 mandates that AES-128-CBC throughput stay within 3× of
//! the FASM baseline. On AES-NI-enabled hosts (every server-grade
//! Intel CPU since Westmere 2010 and AMD CPU since Bulldozer 2011),
//! both `ring` and `aes` route to the hardware AES-NI intrinsics and
//! achieve roughly 1 GiB/s/core for AES-128-CBC, comfortably within
//! the 3× envelope. On hosts without AES-NI, the `aes` crate
//! fallback uses fixslicing (constant-time bitslicing) which is
//! slower than the FASM Wei Dai T-table path but still meets the
//! envelope for all practical inputs. See `BENCHMARK_REPORT.md` per
//! AAP §0.8.5 for measured numbers.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::error::Unspecified;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};

use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use crate::cpu;
use crate::crypto::rng;
use crate::error::CryptoError;

// ============================================================================
// Constants
// ============================================================================

/// AES block size in bytes (128 bits / 16 bytes).
///
/// Matches FIPS 197 §2.2 and the FASM block-size convention (every
/// `aes$encrypt`/`aes$decrypt` call in `aes.inc` operates on 16
/// bytes pointed to by `rsi`). Re-exported at the module level for
/// shorthand access.
pub const BLOCK_SIZE: usize = 16;

/// AES-128 key length in bytes (128 bits / 16 bytes).
///
/// Matches FASM `edx == 16` argument to `aes$init_common`
/// (`aes.inc` lines 248, 251–257) which produces the 10-round key
/// schedule via `(16/4)+6 = 10`.
pub const AES128_KEY_SIZE: usize = 16;

/// AES-192 key length in bytes (192 bits / 24 bytes).
///
/// Matches FASM `edx == 24` argument to `aes$init_common`
/// (`aes.inc` lines 248, 251–257) which produces the 12-round key
/// schedule via `(24/4)+6 = 12`.
pub const AES192_KEY_SIZE: usize = 24;

/// AES-256 key length in bytes (256 bits / 32 bytes).
///
/// Matches FASM `edx == 32` argument to `aes$init_common`
/// (`aes.inc` lines 248, 251–257) which produces the 14-round key
/// schedule via `(32/4)+6 = 14`.
pub const AES256_KEY_SIZE: usize = 32;

/// AES-GCM nonce length in bytes (96 bits / 12 bytes).
///
/// NIST SP 800-38D §5.2.1.1 specifies that GCM nonces SHOULD be
/// 96 bits long; `ring::aead::AES_256_GCM` requires exactly 12
/// bytes via [`Nonce::assume_unique_for_key`].
pub const GCM_NONCE_SIZE: usize = 12;

/// AES-GCM authentication-tag length in bytes (128 bits / 16 bytes).
///
/// NIST SP 800-38D §5.2.1.2 — `ring`'s `seal_in_place_append_tag`
/// always appends a full 16-byte tag.
pub const GCM_TAG_SIZE: usize = 16;

// ============================================================================
// AesKeySize enum
// ============================================================================

/// Variant tag identifying the AES key length at runtime.
///
/// Used by [`aes_ecb_encrypt_block`] to dispatch between the three
/// `aes` crate types (`aes::Aes128`, `aes::Aes192`, `aes::Aes256`)
/// without exposing them in the public API. Mirrors the FASM
/// `edx == 16|24|32` argument to `aes$init_common`
/// (`aes.inc` lines 248, 254–257) which is the only piece of
/// runtime-selected dispatch in the assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AesKeySize {
    /// AES-128 — 16-byte (128-bit) key, 10 rounds.
    Aes128,
    /// AES-192 — 24-byte (192-bit) key, 12 rounds.
    Aes192,
    /// AES-256 — 32-byte (256-bit) key, 14 rounds.
    Aes256,
}

impl AesKeySize {
    /// Number of bytes in the key for this variant.
    ///
    /// Matches the FASM `aes$init_common` `edx` length argument
    /// (`aes.inc` line 248): 16 for AES-128, 24 for AES-192, 32 for
    /// AES-256.
    #[must_use]
    pub const fn key_bytes(self) -> usize {
        match self {
            AesKeySize::Aes128 => AES128_KEY_SIZE,
            AesKeySize::Aes192 => AES192_KEY_SIZE,
            AesKeySize::Aes256 => AES256_KEY_SIZE,
        }
    }

    /// Number of AES rounds for this variant.
    ///
    /// Matches the FASM `aes_rounds_ofs` value computed by
    /// `aes$init_common` (`aes.inc` lines 254–257): 10 for AES-128,
    /// 12 for AES-192, 14 for AES-256. Provided for parity with the
    /// FASM API surface even though Rust callers do not need the
    /// round count directly (it is internal to the `aes` crate).
    #[must_use]
    pub const fn rounds(self) -> u32 {
        match self {
            AesKeySize::Aes128 => 10,
            AesKeySize::Aes192 => 12,
            AesKeySize::Aes256 => 14,
        }
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Iterate `in_out` in 16-byte chunks and call `f` on each chunk
/// represented as `&mut GenericArray<u8, U16>`.
///
/// The cipher trait's `encrypt_block_mut` / `decrypt_block_mut`
/// methods take `&mut Block<Self>` (which for AES is
/// `GenericArray<u8, U16>`); `chunks_exact_mut(16)` plus
/// `GenericArray::from_mut_slice` give us this safely without any
/// `unsafe` block. Per AAP §0.7.4.1 this module contributes zero
/// `unsafe` sites.
///
/// The caller must have already validated that
/// `in_out.len() % 16 == 0`; if a partial chunk remains it is
/// ignored (matching the FASM "process exactly N×16 bytes" contract).
#[inline]
fn for_each_block_mut<F>(in_out: &mut [u8], mut f: F)
where
    F: FnMut(&mut GenericArray<u8, aes::cipher::consts::U16>),
{
    for chunk in in_out.chunks_exact_mut(BLOCK_SIZE) {
        let block = GenericArray::from_mut_slice(chunk);
        f(block);
    }
}

// ============================================================================
// AES-128 CBC
// ============================================================================

/// AES-128 in Cipher Block Chaining (CBC) mode.
///
/// Wraps either a [`cbc::Encryptor<aes::Aes128>`] or a
/// [`cbc::Decryptor<aes::Aes128>`] depending on which constructor
/// was called. The IV chain is maintained internally across
/// successive calls to [`encrypt_blocks`](Self::encrypt_blocks) /
/// [`decrypt_blocks`](Self::decrypt_blocks) — callers can stream
/// blocks through the same instance without re-supplying the IV.
///
/// **No padding** is applied; input lengths must be a multiple of
/// [`BLOCK_SIZE`] (16 bytes). This matches the FASM
/// `aes$encrypt`/`aes$decrypt` semantics (`aes.inc` lines 974–1422)
/// which operate on a single 16-byte block per call and leave
/// padding/length-framing to the SSH/TLS protocol layers.
pub struct Aes128Cbc {
    inner: Aes128CbcInner,
}

enum Aes128CbcInner {
    Encrypt(cbc::Encryptor<Aes128>),
    Decrypt(cbc::Decryptor<Aes128>),
}

impl Aes128Cbc {
    /// Key length in bytes for AES-128 (16 bytes).
    pub const KEY_SIZE: usize = AES128_KEY_SIZE;

    /// Block size in bytes (16 bytes; identical for all AES variants).
    pub const BLOCK_SIZE: usize = BLOCK_SIZE;

    /// Encrypt `in_out` in place. The slice length **must** be a
    /// multiple of [`BLOCK_SIZE`] (16 bytes); callers are responsible
    /// for any padding the higher protocol requires (SSH does its
    /// own length framing per RFC 4253 §6.1; TLS records are
    /// 16-byte aligned by construction in TLS 1.2 CBC mode).
    ///
    /// Returns [`CryptoError::Aes`] if `in_out.len() % 16 != 0` or
    /// if this instance was constructed for decryption rather than
    /// encryption.
    ///
    /// # FASM correspondence
    ///
    /// Reproduces `aes$encrypt` (`aes.inc` lines 974–1196) for an
    /// arbitrary-length input. The FASM version is single-block;
    /// the Rust version processes `n` blocks in a tight loop driven
    /// by [`cbc::cipher::BlockEncryptMut::encrypt_block_mut`].
    pub fn encrypt_blocks(&mut self, in_out: &mut [u8]) -> Result<(), CryptoError> {
        if in_out.len() % BLOCK_SIZE != 0 {
            return Err(CryptoError::Aes(format!(
                "AES-128-CBC encrypt: input length {} is not a multiple of {}",
                in_out.len(),
                BLOCK_SIZE
            )));
        }
        match &mut self.inner {
            Aes128CbcInner::Encrypt(enc) => {
                for_each_block_mut(in_out, |block| enc.encrypt_block_mut(block));
                Ok(())
            }
            Aes128CbcInner::Decrypt(_) => Err(CryptoError::Aes(
                "AES-128-CBC: instance constructed for decryption; encrypt_blocks called".into(),
            )),
        }
    }

    /// Decrypt `in_out` in place. The slice length **must** be a
    /// multiple of [`BLOCK_SIZE`] (16 bytes). Returns
    /// [`CryptoError::Aes`] otherwise or if this instance was
    /// constructed for encryption.
    ///
    /// # FASM correspondence
    ///
    /// Reproduces `aes$decrypt` (`aes.inc` lines 1199–1422) for an
    /// arbitrary-length input.
    pub fn decrypt_blocks(&mut self, in_out: &mut [u8]) -> Result<(), CryptoError> {
        if in_out.len() % BLOCK_SIZE != 0 {
            return Err(CryptoError::Aes(format!(
                "AES-128-CBC decrypt: input length {} is not a multiple of {}",
                in_out.len(),
                BLOCK_SIZE
            )));
        }
        match &mut self.inner {
            Aes128CbcInner::Decrypt(dec) => {
                for_each_block_mut(in_out, |block| dec.decrypt_block_mut(block));
                Ok(())
            }
            Aes128CbcInner::Encrypt(_) => Err(CryptoError::Aes(
                "AES-128-CBC: instance constructed for encryption; decrypt_blocks called".into(),
            )),
        }
    }
}

// No `Drop` impl for [`Aes128Cbc`]: the `aes`/`cbc` crates expose
// only safe APIs and do not guarantee zeroization on drop (the
// `zeroize` cargo feature is not enabled — `zeroize` is not in the
// dependency inventory per AAP §0.6.1). Reaching into the wrapped
// `cbc::Encryptor`/`cbc::Decryptor` to zero round-key state would
// require an `unsafe` block, which violates this module's
// "0 `unsafe` sites" budget per AAP §0.7.4.1 and the agent prompt.
// Round-key memory is therefore released by the standard library's
// default destructor without explicit zeroization. Callers requiring
// memory-disclosure protection should add the `zeroize` crate as a
// follow-up dependency change. Wei Dai's timing-side-channel
// countermeasures (the original `aes.inc` threat model) are
// preserved in full by the `aes` crate's constant-time
// implementation.

// ============================================================================
// AES-192 CBC
// ============================================================================

/// AES-192 in CBC mode. See [`Aes128Cbc`] for the contract; only the
/// key length (24 bytes) and round count (12) differ.
pub struct Aes192Cbc {
    inner: Aes192CbcInner,
}

enum Aes192CbcInner {
    Encrypt(cbc::Encryptor<Aes192>),
    Decrypt(cbc::Decryptor<Aes192>),
}

impl Aes192Cbc {
    /// Key length in bytes for AES-192 (24 bytes).
    pub const KEY_SIZE: usize = AES192_KEY_SIZE;

    /// Block size in bytes (16 bytes; identical for all AES variants).
    pub const BLOCK_SIZE: usize = BLOCK_SIZE;

    /// Encrypt `in_out` in place. See [`Aes128Cbc::encrypt_blocks`].
    pub fn encrypt_blocks(&mut self, in_out: &mut [u8]) -> Result<(), CryptoError> {
        if in_out.len() % BLOCK_SIZE != 0 {
            return Err(CryptoError::Aes(format!(
                "AES-192-CBC encrypt: input length {} is not a multiple of {}",
                in_out.len(),
                BLOCK_SIZE
            )));
        }
        match &mut self.inner {
            Aes192CbcInner::Encrypt(enc) => {
                for_each_block_mut(in_out, |block| enc.encrypt_block_mut(block));
                Ok(())
            }
            Aes192CbcInner::Decrypt(_) => Err(CryptoError::Aes(
                "AES-192-CBC: instance constructed for decryption; encrypt_blocks called".into(),
            )),
        }
    }

    /// Decrypt `in_out` in place. See [`Aes128Cbc::decrypt_blocks`].
    pub fn decrypt_blocks(&mut self, in_out: &mut [u8]) -> Result<(), CryptoError> {
        if in_out.len() % BLOCK_SIZE != 0 {
            return Err(CryptoError::Aes(format!(
                "AES-192-CBC decrypt: input length {} is not a multiple of {}",
                in_out.len(),
                BLOCK_SIZE
            )));
        }
        match &mut self.inner {
            Aes192CbcInner::Decrypt(dec) => {
                for_each_block_mut(in_out, |block| dec.decrypt_block_mut(block));
                Ok(())
            }
            Aes192CbcInner::Encrypt(_) => Err(CryptoError::Aes(
                "AES-192-CBC: instance constructed for encryption; decrypt_blocks called".into(),
            )),
        }
    }
}

// No `Drop` impl for [`Aes192Cbc`] — see [`Aes128Cbc`] commentary.

// ============================================================================
// AES-256 CBC
// ============================================================================

/// AES-256 in CBC mode. See [`Aes128Cbc`] for the contract; only the
/// key length (32 bytes) and round count (14) differ.
///
/// This variant is REQUIRED by the SSH `aes256-cbc` transport per
/// AAP §0.1.1; it is the workhorse of `crate::net::ssh::cipher`.
pub struct Aes256Cbc {
    inner: Aes256CbcInner,
}

enum Aes256CbcInner {
    Encrypt(cbc::Encryptor<Aes256>),
    Decrypt(cbc::Decryptor<Aes256>),
}

impl Aes256Cbc {
    /// Key length in bytes for AES-256 (32 bytes).
    pub const KEY_SIZE: usize = AES256_KEY_SIZE;

    /// Block size in bytes (16 bytes; identical for all AES variants).
    pub const BLOCK_SIZE: usize = BLOCK_SIZE;

    /// Encrypt `in_out` in place. See [`Aes128Cbc::encrypt_blocks`].
    pub fn encrypt_blocks(&mut self, in_out: &mut [u8]) -> Result<(), CryptoError> {
        if in_out.len() % BLOCK_SIZE != 0 {
            return Err(CryptoError::Aes(format!(
                "AES-256-CBC encrypt: input length {} is not a multiple of {}",
                in_out.len(),
                BLOCK_SIZE
            )));
        }
        match &mut self.inner {
            Aes256CbcInner::Encrypt(enc) => {
                for_each_block_mut(in_out, |block| enc.encrypt_block_mut(block));
                Ok(())
            }
            Aes256CbcInner::Decrypt(_) => Err(CryptoError::Aes(
                "AES-256-CBC: instance constructed for decryption; encrypt_blocks called".into(),
            )),
        }
    }

    /// Decrypt `in_out` in place. See [`Aes128Cbc::decrypt_blocks`].
    pub fn decrypt_blocks(&mut self, in_out: &mut [u8]) -> Result<(), CryptoError> {
        if in_out.len() % BLOCK_SIZE != 0 {
            return Err(CryptoError::Aes(format!(
                "AES-256-CBC decrypt: input length {} is not a multiple of {}",
                in_out.len(),
                BLOCK_SIZE
            )));
        }
        match &mut self.inner {
            Aes256CbcInner::Decrypt(dec) => {
                for_each_block_mut(in_out, |block| dec.decrypt_block_mut(block));
                Ok(())
            }
            Aes256CbcInner::Encrypt(_) => Err(CryptoError::Aes(
                "AES-256-CBC: instance constructed for encryption; decrypt_blocks called".into(),
            )),
        }
    }
}

// No `Drop` impl for [`Aes256Cbc`] — see [`Aes128Cbc`] commentary.

// ============================================================================
// Constructor functions for CBC variants
// ============================================================================

/// Construct an AES-128-CBC encryptor with the given 16-byte key
/// and 16-byte IV.
///
/// Mirrors the FASM `aes$init_encrypt` with `edx == 16`
/// (`aes.inc` lines 611–672). The Rust version is infallible for
/// the type-checked 16-byte slices but returns `Result` for API
/// uniformity with [`aes_ecb_encrypt_block`] (which has runtime
/// length validation).
///
/// # Errors
///
/// Currently never returns `Err`; the `Result` return type is
/// preserved for forward compatibility (e.g., if FIPS-mode key
/// validation is added in a later release).
pub fn aes128_cbc_new_encrypt(
    key: &[u8; AES128_KEY_SIZE],
    iv: &[u8; BLOCK_SIZE],
) -> Result<Aes128Cbc, CryptoError> {
    let key_ga: &GenericArray<u8, _> = GenericArray::from_slice(key);
    let iv_ga: &GenericArray<u8, _> = GenericArray::from_slice(iv);
    let enc = cbc::Encryptor::<Aes128>::new(key_ga, iv_ga);
    Ok(Aes128Cbc {
        inner: Aes128CbcInner::Encrypt(enc),
    })
}

/// Construct an AES-128-CBC decryptor. See [`aes128_cbc_new_encrypt`].
///
/// # Errors
///
/// Currently never returns `Err`; the `Result` return type is
/// preserved for forward compatibility.
pub fn aes128_cbc_new_decrypt(
    key: &[u8; AES128_KEY_SIZE],
    iv: &[u8; BLOCK_SIZE],
) -> Result<Aes128Cbc, CryptoError> {
    let key_ga: &GenericArray<u8, _> = GenericArray::from_slice(key);
    let iv_ga: &GenericArray<u8, _> = GenericArray::from_slice(iv);
    let dec = cbc::Decryptor::<Aes128>::new(key_ga, iv_ga);
    Ok(Aes128Cbc {
        inner: Aes128CbcInner::Decrypt(dec),
    })
}

/// Construct an AES-192-CBC encryptor with the given 24-byte key
/// and 16-byte IV.
///
/// Mirrors the FASM `aes$init_encrypt` with `edx == 24`
/// (`aes.inc` lines 611–672). AES-192 is rarely deployed in modern
/// protocols (SSH and TLS prefer AES-128 / AES-256), but the FASM
/// library supported it via the same code path so we expose it
/// here for parity. Callers needing 24-byte keys (e.g., legacy
/// IPSEC profiles) can use this constructor.
///
/// # Errors
///
/// Currently never returns `Err`.
pub fn aes192_cbc_new_encrypt(
    key: &[u8; AES192_KEY_SIZE],
    iv: &[u8; BLOCK_SIZE],
) -> Result<Aes192Cbc, CryptoError> {
    let key_ga: &GenericArray<u8, _> = GenericArray::from_slice(key);
    let iv_ga: &GenericArray<u8, _> = GenericArray::from_slice(iv);
    let enc = cbc::Encryptor::<Aes192>::new(key_ga, iv_ga);
    Ok(Aes192Cbc {
        inner: Aes192CbcInner::Encrypt(enc),
    })
}

/// Construct an AES-192-CBC decryptor. See [`aes192_cbc_new_encrypt`].
///
/// # Errors
///
/// Currently never returns `Err`.
pub fn aes192_cbc_new_decrypt(
    key: &[u8; AES192_KEY_SIZE],
    iv: &[u8; BLOCK_SIZE],
) -> Result<Aes192Cbc, CryptoError> {
    let key_ga: &GenericArray<u8, _> = GenericArray::from_slice(key);
    let iv_ga: &GenericArray<u8, _> = GenericArray::from_slice(iv);
    let dec = cbc::Decryptor::<Aes192>::new(key_ga, iv_ga);
    Ok(Aes192Cbc {
        inner: Aes192CbcInner::Decrypt(dec),
    })
}

/// Construct an AES-256-CBC encryptor with the given 32-byte key
/// and 16-byte IV.
///
/// Mirrors the FASM `aes$init_encrypt` with `edx == 32`
/// (`aes.inc` lines 611–672). Used by `crate::net::ssh::cipher` to
/// initialise the SSH `aes256-cbc` transport encryption state per
/// RFC 4253 §6.3.
///
/// # Errors
///
/// Currently never returns `Err`.
pub fn aes256_cbc_new_encrypt(
    key: &[u8; AES256_KEY_SIZE],
    iv: &[u8; BLOCK_SIZE],
) -> Result<Aes256Cbc, CryptoError> {
    let key_ga: &GenericArray<u8, _> = GenericArray::from_slice(key);
    let iv_ga: &GenericArray<u8, _> = GenericArray::from_slice(iv);
    let enc = cbc::Encryptor::<Aes256>::new(key_ga, iv_ga);
    Ok(Aes256Cbc {
        inner: Aes256CbcInner::Encrypt(enc),
    })
}

/// Construct an AES-256-CBC decryptor with the given 32-byte key
/// and 16-byte IV.
///
/// Mirrors the FASM `aes$init_decrypt` with `edx == 32`
/// (`aes.inc` lines 675–971). Used by `crate::net::ssh::cipher` to
/// initialise the SSH `aes256-cbc` transport decryption state.
///
/// # Errors
///
/// Currently never returns `Err`.
pub fn aes256_cbc_new_decrypt(
    key: &[u8; AES256_KEY_SIZE],
    iv: &[u8; BLOCK_SIZE],
) -> Result<Aes256Cbc, CryptoError> {
    let key_ga: &GenericArray<u8, _> = GenericArray::from_slice(key);
    let iv_ga: &GenericArray<u8, _> = GenericArray::from_slice(iv);
    let dec = cbc::Decryptor::<Aes256>::new(key_ga, iv_ga);
    Ok(Aes256Cbc {
        inner: Aes256CbcInner::Decrypt(dec),
    })
}

// ============================================================================
// AES-256-GCM (AEAD)
// ============================================================================

/// Encrypt `plaintext` with AES-256-GCM and return
/// `ciphertext || tag` (a `Vec<u8>` of length
/// `plaintext.len() + 16`).
///
/// The 16-byte authentication tag is appended to the ciphertext per
/// the standard `seal_in_place_append_tag` convention used by
/// `ring::aead`. Callers wishing to transmit the tag separately can
/// split the last 16 bytes off the returned vector.
///
/// # Parameters
///
/// * `key` — 32-byte AES-256 key. Reuse across calls is safe so long
///   as nonces are unique. The TLS session-cache path rotates this
///   key on every process startup per AAP §0.7.2.4.
/// * `nonce` — 12-byte initial value. **MUST be unique** for every
///   `(key, nonce)` pair; reuse leaks the GCM authentication
///   subkey. Use [`crate::crypto::rng::block`] to generate fresh
///   nonces or use [`aes256_gcm_seal_random_nonce`] for a built-in
///   random-nonce wrapper.
/// * `aad` — Additional Authenticated Data. Authenticated but not
///   encrypted. The same `aad` must be supplied to
///   [`aes256_gcm_open`] at decrypt time.
/// * `plaintext` — message to encrypt; any length.
///
/// # Errors
///
/// Returns [`CryptoError::Aes`] if `key.len() != 32` (cannot occur
/// at the type level — `&[u8; 32]` enforces it) or if `ring`'s
/// internal GCM state machine returns `Unspecified` (which `ring`
/// does only on programmer error such as a >2³⁹-bit AAD or
/// plaintext, both impossible for in-memory `&[u8]` inputs).
///
/// # FASM correspondence
///
/// AES-GCM is **not** implemented in `aes.inc`; the FASM TLS code
/// path uses CBC suites only (per the assembly's "no GCM, GCM
/// commented 138-143" disposition documented in AAP §0.7.2.1). This
/// function is a Rust-only addition needed for the TLS session
/// cache encryption (`tls_server_encryptcache = 1` per AAP
/// §0.7.2.4), where the FASM library used a custom AES-256-CBC +
/// HMAC-SHA-256 construction — the Rust port replaces that with
/// AEAD-via-AES-GCM, a strictly more conservative choice (single
/// authenticated primitive, no MAC-then-encrypt vs. encrypt-then-MAC
/// ambiguity).
pub fn aes256_gcm_seal(
    key: &[u8; AES256_KEY_SIZE],
    nonce: &[u8; GCM_NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_: Unspecified| CryptoError::Aes("AES-256-GCM seal: invalid key length".into()))?;
    let key = LessSafeKey::new(unbound);
    let nonce_obj = Nonce::assume_unique_for_key(*nonce);

    // Allocate the output buffer with capacity for the tag.
    let mut buf = Vec::with_capacity(plaintext.len() + GCM_TAG_SIZE);
    buf.extend_from_slice(plaintext);

    key.seal_in_place_append_tag(nonce_obj, Aad::from(aad), &mut buf)
        .map_err(|_: Unspecified| CryptoError::Aes("AES-256-GCM seal: encryption failed".into()))?;
    Ok(buf)
}

/// Decrypt `ciphertext` (which carries a trailing 16-byte tag) with
/// AES-256-GCM and return the plaintext.
///
/// `ciphertext` MUST have been produced by [`aes256_gcm_seal`] (or
/// any other AES-256-GCM implementation that uses the same
/// `tag-suffix` convention) with the same `key`, `nonce`, and `aad`.
///
/// # Parameters
///
/// * `key` — 32-byte AES-256 key.
/// * `nonce` — 12-byte initial value (must match seal-time value).
/// * `aad` — Additional Authenticated Data (must match seal-time
///   value).
/// * `ciphertext` — encrypted bytes followed by a 16-byte
///   authentication tag (so `ciphertext.len() >= 16`).
///
/// # Errors
///
/// Returns [`CryptoError::Aes`] if the authentication tag does not
/// verify (tampering, wrong key, wrong nonce, or wrong AAD), or if
/// `ciphertext.len() < 16`.
///
/// # Security
///
/// Tag verification is performed in **constant time** by `ring`;
/// callers do not need additional timing-safe comparisons.
pub fn aes256_gcm_open(
    key: &[u8; AES256_KEY_SIZE],
    nonce: &[u8; GCM_NONCE_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < GCM_TAG_SIZE {
        return Err(CryptoError::Aes(format!(
            "AES-256-GCM open: ciphertext length {} too short for {}-byte tag",
            ciphertext.len(),
            GCM_TAG_SIZE
        )));
    }
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_: Unspecified| CryptoError::Aes("AES-256-GCM open: invalid key length".into()))?;
    let key = LessSafeKey::new(unbound);
    let nonce_obj = Nonce::assume_unique_for_key(*nonce);

    // ring's `open_in_place` requires &mut [u8] and returns the
    // plaintext slice (which is a prefix of the input). Allocate a
    // mutable copy.
    let mut buf = ciphertext.to_vec();
    let pt_len = {
        let pt = key
            .open_in_place(nonce_obj, Aad::from(aad), &mut buf)
            .map_err(|_: Unspecified| CryptoError::Aes("AES-256-GCM open: tag verification failed".into()))?;
        pt.len()
    };
    buf.truncate(pt_len);
    Ok(buf)
}

/// Convenience wrapper around [`aes256_gcm_seal`] that generates a
/// fresh 12-byte nonce via [`crate::crypto::rng::block`] and
/// returns `(nonce, ciphertext_with_tag)`.
///
/// This is the recommended idiom for TLS session-cache encryption
/// (AAP §0.7.2.4) and any other site that does not have an external
/// nonce source: callers persist `(nonce, ct)` and pass `nonce`
/// back to [`aes256_gcm_open`] at decrypt time.
///
/// # Errors
///
/// Returns whatever [`aes256_gcm_seal`] returns. Nonce generation
/// itself is infallible (the RNG is initialised in `crate::lib::init`
/// Stage 9 and re-seeds on demand per AAP §0.5.1.3).
pub fn aes256_gcm_seal_random_nonce(
    key: &[u8; AES256_KEY_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; GCM_NONCE_SIZE], Vec<u8>), CryptoError> {
    let mut nonce = [0u8; GCM_NONCE_SIZE];
    rng::block(&mut nonce);
    let ct = aes256_gcm_seal(key, &nonce, aad, plaintext)?;
    Ok((nonce, ct))
}

// ============================================================================
// Single-block ECB (for protocol construction only)
// ============================================================================

/// Encrypt a single 16-byte block with raw AES-ECB.
///
/// **Warning**: ECB mode is insecure for general multi-block data —
/// identical plaintext blocks produce identical ciphertext blocks,
/// leaking pattern information. This function is provided **only**
/// for protocol-construction sites that need a raw block primitive
/// (e.g., AES-CFB synthesis from raw ECB used by some legacy TLS
/// constructions). New code should use [`aes256_cbc_new_encrypt`]
/// or [`aes256_gcm_seal`] instead.
///
/// # Parameters
///
/// * `key_size` — variant tag selecting AES-128/192/256.
/// * `key` — key bytes; length MUST equal `key_size.key_bytes()`.
/// * `block` — 16-byte block, encrypted in place.
///
/// # Errors
///
/// Returns [`CryptoError::Aes`] if `key.len() != key_size.key_bytes()`.
///
/// # FASM correspondence
///
/// Reproduces the single-block contract of `aes$encrypt`
/// (`aes.inc` line 977: "two arguments: rdi == aes object,
/// rsi == ptr to block to encrypt in place") combined with a fresh
/// `aes$init_encrypt` per call. This is intentionally inefficient
/// for repeated use — callers that need multi-block ECB or any
/// chained mode should use the [`Aes128Cbc`] / [`Aes256Cbc`]
/// constructors which amortise the key schedule across blocks.
pub fn aes_ecb_encrypt_block(
    key_size: AesKeySize,
    key: &[u8],
    block: &mut [u8; BLOCK_SIZE],
) -> Result<(), CryptoError> {
    if key.len() != key_size.key_bytes() {
        return Err(CryptoError::Aes(format!(
            "AES ECB encrypt: key length {} does not match {:?} expected {}",
            key.len(),
            key_size,
            key_size.key_bytes()
        )));
    }
    let block_ga: &mut GenericArray<u8, _> = GenericArray::from_mut_slice(block);
    match key_size {
        AesKeySize::Aes128 => {
            let key_ga: &GenericArray<u8, _> = GenericArray::from_slice(key);
            let cipher = Aes128::new(key_ga);
            cipher.encrypt_block(block_ga);
        }
        AesKeySize::Aes192 => {
            let key_ga: &GenericArray<u8, _> = GenericArray::from_slice(key);
            let cipher = Aes192::new(key_ga);
            cipher.encrypt_block(block_ga);
        }
        AesKeySize::Aes256 => {
            let key_ga: &GenericArray<u8, _> = GenericArray::from_slice(key);
            let cipher = Aes256::new(key_ga);
            cipher.encrypt_block(block_ga);
        }
    }
    Ok(())
}

// ============================================================================
// AES-NI runtime detection
// ============================================================================

/// Returns `true` if the CPU exposes AES-NI hardware acceleration.
///
/// This is a thin wrapper over [`crate::cpu::features`]`().has_aesni`
/// and is provided **for diagnostic and benchmark reporting only**.
/// Per AAP §0.1.1 ("CPU feature detection must be runtime, not
/// compile-time"), the underlying [`ring`] and [`aes`] crates each
/// perform their own internal `std::is_x86_feature_detected!("aes")`
/// dispatch — this module does not gate any code path on the result.
///
/// The FASM source (`aes.inc` lines 261, 621, 982, 1207) used the
/// process-wide `has_AESNI` flag to pick between the AES-NI
/// intrinsic path and the Wei Dai T-table fallback. The Rust
/// equivalent of that flag lives in [`crate::cpu::features`]; this
/// helper makes the value visible to e.g. the `BENCHMARK_REPORT.md`
/// runner so it can label measurements with the host's AES-NI
/// status.
#[must_use]
pub fn aesni_available() -> bool {
    cpu::features().has_aesni
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // FIPS 197 / NIST SP 800-38A test vectors
    // ------------------------------------------------------------------

    /// FIPS 197 Appendix C.1 — AES-128 ECB single-block test vector.
    /// Plaintext: 00112233 44556677 8899aabb ccddeeff
    /// Key:       00010203 04050607 08090a0b 0c0d0e0f
    /// Cipher:    69c4e0d8 6a7b0430 d8cdb780 70b4c55a
    #[test]
    fn aes128_ecb_fips197_vector() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let mut block: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];
        aes_ecb_encrypt_block(AesKeySize::Aes128, &key, &mut block).expect("encrypt OK");
        assert_eq!(block, expected);
    }

    /// FIPS 197 Appendix C.2 — AES-192 ECB single-block test vector.
    /// Plaintext: 00112233 44556677 8899aabb ccddeeff
    /// Key:       00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617
    /// Cipher:    dda97ca4 864cdfe0 6eaf70a0 ec0d7191
    #[test]
    fn aes192_ecb_fips197_vector() {
        let key: [u8; 24] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let mut block: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
        ];
        aes_ecb_encrypt_block(AesKeySize::Aes192, &key, &mut block).expect("encrypt OK");
        assert_eq!(block, expected);
    }

    /// FIPS 197 Appendix C.3 — AES-256 ECB single-block test vector.
    /// Plaintext: 00112233 44556677 8899aabb ccddeeff
    /// Key:       00010203 04050607 08090a0b 0c0d0e0f
    ///            10111213 14151617 18191a1b 1c1d1e1f
    /// Cipher:    8ea2b7ca 516745bf eafc4990 4b496089
    #[test]
    fn aes256_ecb_fips197_vector() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let mut block: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];
        aes_ecb_encrypt_block(AesKeySize::Aes256, &key, &mut block).expect("encrypt OK");
        assert_eq!(block, expected);
    }

    /// NIST SP 800-38A Appendix F.2.1 — CBC-AES128.Encrypt.
    ///
    /// Key: 2b7e151628aed2a6abf7158809cf4f3c
    /// IV:  000102030405060708090a0b0c0d0e0f
    /// Plaintext (4 blocks):
    ///   6bc1bee22e409f96e93d7e117393172a
    ///   ae2d8a571e03ac9c9eb76fac45af8e51
    ///   30c81c46a35ce411e5fbc1191a0a52ef
    ///   f69f2445df4f9b17ad2b417be66c3710
    /// Ciphertext:
    ///   7649abac8119b246cee98e9b12e9197d
    ///   5086cb9b507219ee95db113a917678b2
    ///   73bed6b8e3c1743b7116e69e22229516
    ///   3ff1caa1681fac09120eca307586e1a7
    #[test]
    fn aes128_cbc_nist_sp800_38a_vector() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let plaintext: [u8; 64] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let expected_ct: [u8; 64] = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
            0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
            0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
            0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        ];

        // Encrypt
        let mut buf = plaintext;
        let mut enc = aes128_cbc_new_encrypt(&key, &iv).expect("init enc");
        enc.encrypt_blocks(&mut buf).expect("encrypt OK");
        assert_eq!(buf, expected_ct, "AES-128-CBC ciphertext mismatch");

        // Decrypt
        let mut dec = aes128_cbc_new_decrypt(&key, &iv).expect("init dec");
        dec.decrypt_blocks(&mut buf).expect("decrypt OK");
        assert_eq!(buf, plaintext, "AES-128-CBC round-trip mismatch");
    }

    /// NIST SP 800-38A Appendix F.2.5 — CBC-AES256.Encrypt.
    ///
    /// Key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    /// IV:  000102030405060708090a0b0c0d0e0f
    /// Plaintext (4 blocks): same as AES-128 test
    /// Ciphertext:
    ///   f58c4c04d6e5f1ba779eabfb5f7bfbd6
    ///   9cfc4e967edb808d679f777bc6702c7d
    ///   39f23369a9d9bacfa530e26304231461
    ///   b2eb05e2c39be9fcda6c19078c6a9d1b
    #[test]
    fn aes256_cbc_nist_sp800_38a_vector() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let plaintext: [u8; 64] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let expected_ct: [u8; 64] = [
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
            0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
            0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
            0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b,
        ];

        // Encrypt
        let mut buf = plaintext;
        let mut enc = aes256_cbc_new_encrypt(&key, &iv).expect("init enc");
        enc.encrypt_blocks(&mut buf).expect("encrypt OK");
        assert_eq!(buf, expected_ct, "AES-256-CBC ciphertext mismatch");

        // Decrypt
        let mut dec = aes256_cbc_new_decrypt(&key, &iv).expect("init dec");
        dec.decrypt_blocks(&mut buf).expect("decrypt OK");
        assert_eq!(buf, plaintext, "AES-256-CBC round-trip mismatch");
    }

    /// Streaming-CBC test: encrypt 4 blocks one at a time and verify
    /// the IV chaining is preserved across calls. The result must
    /// match a single-shot encrypt of the same 4 blocks.
    #[test]
    fn aes256_cbc_streaming_matches_one_shot() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];
        let plaintext: [u8; 64] = [0x55u8; 64];

        // One-shot reference
        let mut one_shot = plaintext;
        let mut enc1 = aes256_cbc_new_encrypt(&key, &iv).expect("init enc1");
        enc1.encrypt_blocks(&mut one_shot).expect("one-shot enc");

        // Streamed: 4 separate encrypt_blocks calls
        let mut streamed = plaintext;
        let mut enc2 = aes256_cbc_new_encrypt(&key, &iv).expect("init enc2");
        for chunk in streamed.chunks_mut(BLOCK_SIZE) {
            enc2.encrypt_blocks(chunk).expect("streamed enc");
        }

        assert_eq!(one_shot, streamed, "streaming CBC must match one-shot");
    }

    /// Reject non-block-aligned input lengths.
    #[test]
    fn aes256_cbc_rejects_partial_block() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let mut buf = [0u8; 17]; // Not a multiple of 16
        let mut enc = aes256_cbc_new_encrypt(&key, &iv).expect("init enc");
        let err = enc.encrypt_blocks(&mut buf).expect_err("must reject");
        match err {
            CryptoError::Aes(_) => (),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
    }

    /// Reject decrypt-on-encryptor and encrypt-on-decryptor.
    #[test]
    fn aes256_cbc_rejects_wrong_direction() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let mut buf = [0u8; 16];

        let mut enc = aes256_cbc_new_encrypt(&key, &iv).expect("init enc");
        let err = enc
            .decrypt_blocks(&mut buf)
            .expect_err("must reject decrypt on enc");
        match err {
            CryptoError::Aes(msg) => assert!(msg.contains("encryption")),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }

        let mut dec = aes256_cbc_new_decrypt(&key, &iv).expect("init dec");
        let err = dec
            .encrypt_blocks(&mut buf)
            .expect_err("must reject encrypt on dec");
        match err {
            CryptoError::Aes(msg) => assert!(msg.contains("decryption")),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // AES-256-GCM round-trip and tamper detection
    // ------------------------------------------------------------------

    /// AES-256-GCM seal/open round-trip with non-empty AAD.
    #[test]
    fn aes256_gcm_round_trip() {
        let key = [0xaau8; 32];
        let nonce = [0xbbu8; 12];
        let aad = b"associated data for GCM";
        let plaintext = b"the quick brown fox jumps over the lazy dog";

        let ct = aes256_gcm_seal(&key, &nonce, aad, plaintext).expect("seal OK");
        assert_eq!(ct.len(), plaintext.len() + GCM_TAG_SIZE);

        let pt = aes256_gcm_open(&key, &nonce, aad, &ct).expect("open OK");
        assert_eq!(pt, plaintext);
    }

    /// AES-256-GCM seal/open with empty AAD.
    #[test]
    fn aes256_gcm_round_trip_empty_aad() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"hello, world";

        let ct = aes256_gcm_seal(&key, &nonce, &[], plaintext).expect("seal OK");
        let pt = aes256_gcm_open(&key, &nonce, &[], &ct).expect("open OK");
        assert_eq!(pt, plaintext);
    }

    /// AES-256-GCM seal/open with empty plaintext (just authenticate AAD).
    #[test]
    fn aes256_gcm_empty_plaintext() {
        let key = [0u8; 32];
        let nonce = [1u8; 12];
        let aad = b"only AAD";

        let ct = aes256_gcm_seal(&key, &nonce, aad, &[]).expect("seal OK");
        assert_eq!(ct.len(), GCM_TAG_SIZE);

        let pt = aes256_gcm_open(&key, &nonce, aad, &ct).expect("open OK");
        assert!(pt.is_empty());
    }

    /// Tampered ciphertext must fail to authenticate.
    #[test]
    fn aes256_gcm_tampered_ciphertext_fails() {
        let key = [0xaau8; 32];
        let nonce = [0xbbu8; 12];
        let aad = b"";
        let plaintext = b"sixteen bytes pl";

        let mut ct = aes256_gcm_seal(&key, &nonce, aad, plaintext).expect("seal OK");
        ct[0] ^= 0x01; // flip a bit in the ciphertext
        let err = aes256_gcm_open(&key, &nonce, aad, &ct).expect_err("must fail");
        match err {
            CryptoError::Aes(_) => (),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
    }

    /// Tampered AAD must fail to authenticate.
    #[test]
    fn aes256_gcm_tampered_aad_fails() {
        let key = [0xaau8; 32];
        let nonce = [0xbbu8; 12];
        let plaintext = b"some plaintext";

        let ct = aes256_gcm_seal(&key, &nonce, b"original aad", plaintext).expect("seal OK");
        let err = aes256_gcm_open(&key, &nonce, b"tampered aad", &ct).expect_err("must fail");
        match err {
            CryptoError::Aes(_) => (),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
    }

    /// Wrong nonce must fail to authenticate.
    #[test]
    fn aes256_gcm_wrong_nonce_fails() {
        let key = [0xaau8; 32];
        let plaintext = b"some plaintext";

        let ct = aes256_gcm_seal(&key, &[0xbbu8; 12], b"aad", plaintext).expect("seal OK");
        let err = aes256_gcm_open(&key, &[0xccu8; 12], b"aad", &ct).expect_err("must fail");
        match err {
            CryptoError::Aes(_) => (),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
    }

    /// Truncated ciphertext (shorter than tag) must fail clearly.
    #[test]
    fn aes256_gcm_truncated_ciphertext_fails() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let too_short = [0u8; 4]; // less than 16-byte tag
        let err = aes256_gcm_open(&key, &nonce, &[], &too_short).expect_err("must fail");
        match err {
            CryptoError::Aes(msg) => assert!(msg.contains("too short")),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
    }

    /// Random-nonce convenience helper round-trips correctly.
    #[test]
    fn aes256_gcm_random_nonce_round_trip() {
        // Initialize the RNG (idempotent: harmless if init was already done).
        rng::init().expect("RNG init");

        let key = [0x55u8; 32];
        let aad = b"convenience-helper test";
        let plaintext = b"some payload";

        let (nonce, ct) = aes256_gcm_seal_random_nonce(&key, aad, plaintext).expect("seal_random_nonce OK");
        let pt = aes256_gcm_open(&key, &nonce, aad, &ct).expect("open OK");
        assert_eq!(pt, plaintext);

        // Re-running yields a fresh nonce (statistically — collision
        // probability ≈ 2⁻⁹⁶).
        let (nonce2, _) = aes256_gcm_seal_random_nonce(&key, aad, plaintext).expect("seal_random_nonce OK");
        assert_ne!(nonce, nonce2, "two random nonces must differ (overwhelmingly)");
    }

    // ------------------------------------------------------------------
    // AesKeySize introspection
    // ------------------------------------------------------------------

    #[test]
    fn aes_key_size_key_bytes() {
        assert_eq!(AesKeySize::Aes128.key_bytes(), 16);
        assert_eq!(AesKeySize::Aes192.key_bytes(), 24);
        assert_eq!(AesKeySize::Aes256.key_bytes(), 32);
    }

    #[test]
    fn aes_key_size_rounds() {
        assert_eq!(AesKeySize::Aes128.rounds(), 10);
        assert_eq!(AesKeySize::Aes192.rounds(), 12);
        assert_eq!(AesKeySize::Aes256.rounds(), 14);
    }

    /// `aes_ecb_encrypt_block` rejects key length mismatch.
    #[test]
    fn aes_ecb_rejects_key_length_mismatch() {
        let key = [0u8; 24]; // 24 bytes
        let mut block = [0u8; 16];
        let err = aes_ecb_encrypt_block(AesKeySize::Aes256, &key, &mut block).expect_err("must reject");
        match err {
            CryptoError::Aes(msg) => assert!(msg.contains("key length")),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // AES-NI runtime detection
    // ------------------------------------------------------------------

    /// `aesni_available` returns the same value as
    /// `cpu::features().has_aesni` and is callable.
    #[test]
    fn aesni_available_matches_cpu_features() {
        assert_eq!(aesni_available(), cpu::features().has_aesni);
    }

    // ------------------------------------------------------------------
    // Constants / re-exports
    // ------------------------------------------------------------------

    #[test]
    fn block_size_constants_are_consistent() {
        assert_eq!(BLOCK_SIZE, 16);
        assert_eq!(Aes128Cbc::BLOCK_SIZE, 16);
        assert_eq!(Aes192Cbc::BLOCK_SIZE, 16);
        assert_eq!(Aes256Cbc::BLOCK_SIZE, 16);
        assert_eq!(Aes128Cbc::KEY_SIZE, 16);
        assert_eq!(Aes192Cbc::KEY_SIZE, 24);
        assert_eq!(Aes256Cbc::KEY_SIZE, 32);
    }

    #[test]
    fn nonce_and_tag_size_constants() {
        assert_eq!(GCM_NONCE_SIZE, 12);
        assert_eq!(GCM_TAG_SIZE, 16);
    }

    // ------------------------------------------------------------------
    // AES-192 CBC smoke test
    // ------------------------------------------------------------------

    /// AES-192-CBC round-trip via the public constructors.
    #[test]
    fn aes192_cbc_round_trip() {
        let key: [u8; 24] = [0x10u8; 24];
        let iv: [u8; 16] = [0x20u8; 16];
        let plaintext: [u8; 32] = [0x55u8; 32];

        let mut buf = plaintext;
        let mut enc = aes192_cbc_new_encrypt(&key, &iv).expect("init enc");
        enc.encrypt_blocks(&mut buf).expect("encrypt OK");
        assert_ne!(buf, plaintext, "ciphertext should differ from plaintext");

        let mut dec = aes192_cbc_new_decrypt(&key, &iv).expect("init dec");
        dec.decrypt_blocks(&mut buf).expect("decrypt OK");
        assert_eq!(buf, plaintext, "round-trip should restore plaintext");
    }

    /// AES-192-CBC direction-mismatch rejection.
    #[test]
    fn aes192_cbc_rejects_wrong_direction() {
        let key = [0u8; 24];
        let iv = [0u8; 16];
        let mut buf = [0u8; 16];

        let mut enc = aes192_cbc_new_encrypt(&key, &iv).expect("init enc");
        let err = enc.decrypt_blocks(&mut buf).expect_err("must reject");
        match err {
            CryptoError::Aes(msg) => assert!(msg.contains("encryption")),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }

        let mut dec = aes192_cbc_new_decrypt(&key, &iv).expect("init dec");
        let err = dec.encrypt_blocks(&mut buf).expect_err("must reject");
        match err {
            CryptoError::Aes(msg) => assert!(msg.contains("decryption")),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
    }

    /// AES-128-CBC direction-mismatch rejection.
    #[test]
    fn aes128_cbc_rejects_wrong_direction() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let mut buf = [0u8; 16];

        let mut enc = aes128_cbc_new_encrypt(&key, &iv).expect("init enc");
        let err = enc.decrypt_blocks(&mut buf).expect_err("must reject");
        match err {
            CryptoError::Aes(msg) => assert!(msg.contains("encryption")),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }

        let mut dec = aes128_cbc_new_decrypt(&key, &iv).expect("init dec");
        let err = dec.encrypt_blocks(&mut buf).expect_err("must reject");
        match err {
            CryptoError::Aes(msg) => assert!(msg.contains("decryption")),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
    }

    /// AES-128-CBC partial-block rejection.
    #[test]
    fn aes128_cbc_rejects_partial_block() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let mut buf = [0u8; 17];
        let mut enc = aes128_cbc_new_encrypt(&key, &iv).expect("init enc");
        let err = enc.encrypt_blocks(&mut buf).expect_err("must reject");
        match err {
            CryptoError::Aes(_) => (),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
        let mut dec = aes128_cbc_new_decrypt(&key, &iv).expect("init dec");
        let err = dec.decrypt_blocks(&mut buf).expect_err("must reject");
        match err {
            CryptoError::Aes(_) => (),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
    }

    /// AES-192-CBC partial-block rejection.
    #[test]
    fn aes192_cbc_rejects_partial_block() {
        let key = [0u8; 24];
        let iv = [0u8; 16];
        let mut buf = [0u8; 17];
        let mut enc = aes192_cbc_new_encrypt(&key, &iv).expect("init enc");
        let err = enc.encrypt_blocks(&mut buf).expect_err("must reject");
        match err {
            CryptoError::Aes(_) => (),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
        let mut dec = aes192_cbc_new_decrypt(&key, &iv).expect("init dec");
        let err = dec.decrypt_blocks(&mut buf).expect_err("must reject");
        match err {
            CryptoError::Aes(_) => (),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
    }

    /// AES-256-CBC partial-block on decrypt rejection (covers the
    /// decrypt-side branch of the length check).
    #[test]
    fn aes256_cbc_rejects_partial_block_on_decrypt() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let mut buf = [0u8; 17];
        let mut dec = aes256_cbc_new_decrypt(&key, &iv).expect("init dec");
        let err = dec.decrypt_blocks(&mut buf).expect_err("must reject");
        match err {
            CryptoError::Aes(_) => (),
            other => panic!("expected CryptoError::Aes, got {other:?}"),
        }
    }
}
