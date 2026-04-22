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

//! Cryptographic subsystem — aggregator module for primitives and algorithms.
//!
//! This subsystem translates the fifteen crypto `.inc` assembly files
//! (`aes.inc`, `sha1.inc`, `sha2.inc`, `md5.inc`, `hmac.inc`,
//! `hmac_drbg.inc`, `pbkdf2.inc`, `scrypt.inc`, `bigint.inc`,
//! `dh_groups.inc`, `dh_pool.inc`, `rng.inc`, `X509.inc`, plus the
//! out-of-scope `htcrypt.inc`/`htxts.inc` stubs) into idiomatic Rust
//! wrappers over `ring`, the RustCrypto `aes`/`cbc` crates, `md-5`,
//! `scrypt`, `num-bigint`, and `webpki` per AAP §0.5.1.3 and §0.6.1.
//!
//! # Submodules present
//!
//! * [`md5`] — MD5 hash wrapper (legacy protocol support only);
//!   port of `md5.inc`.
//! * [`sha1`] — SHA-1 hash wrapper (legacy, via
//!   `ring::digest::SHA1_FOR_LEGACY_USE_ONLY`); port of `sha1.inc`.
//! * [`sha2`] — SHA-256 and SHA-512 hash wrappers over
//!   `ring::digest`; port of `sha2.inc`.
//! * [`hmac_drbg`] — NIST SP 800-90A HMAC-DRBG over `ring::hmac`,
//!   with 64-bit-per-3072-bit discard policy preserved per
//!   AAP §0.5.1.3; port of `hmac_drbg.inc`.
//! * [`pbkdf2`] — PBKDF2 (PKCS #5 v2.0 / RFC 8018 §5.2) key
//!   derivation over `ring::pbkdf2`, supporting HMAC-SHA-1,
//!   HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 per AAP §0.5.1.3;
//!   port of `pbkdf2.inc`.
//!
//! Additional crypto submodules (`aes`, `hmac`, `scrypt`, `bigint`,
//! `dh`, `x509`, `rng`) are scheduled in subsequent translation
//! phases per AAP §0.5.1.3 and are not yet wired here. The
//! aggregator exposes only the submodules that exist as source
//! files today so that `cargo check` succeeds on the currently
//! committed sub-set.
//!
//! # Error handling
//!
//! All fallible crypto APIs surface the crate-wide
//! [`CryptoError`](crate::error::CryptoError) enum (see
//! [`crate::error`]). Every variant pairs a machine-readable
//! discriminator with a short diagnostic string — see
//! [`CryptoError::Hmac`](crate::error::CryptoError::Hmac) and
//! [`CryptoError::Rng`](crate::error::CryptoError::Rng) for the two
//! variants used by this subsystem today.
//!
//! # Thread safety
//!
//! Hash and HMAC primitives are pure functions and naturally
//! thread-safe. Stateful primitives — notably
//! [`hmac_drbg::HmacDrbg`] — are `Send` but not `Sync`: callers that
//! need to share an instance must wrap it in `std::sync::Mutex` or
//! `tokio::sync::Mutex`.
//!
//! # `unsafe` audit
//!
//! Per AAP §0.7.4.1 this subsystem contains **zero** `unsafe` blocks;
//! correctness derives entirely from `ring`, the RustCrypto stack, and
//! the safe `Vec`/slice APIs.

/// MD5 hash wrapper — port of `md5.inc`.
pub mod md5;

/// SHA-1 hash wrapper (legacy use only) — port of `sha1.inc`.
pub mod sha1;

/// SHA-256 / SHA-512 hash wrappers — port of `sha2.inc`.
pub mod sha2;

/// NIST SP 800-90A HMAC-DRBG — port of `hmac_drbg.inc`.
pub mod hmac_drbg;

/// PBKDF2 (PKCS #5 v2.0 / RFC 8018 §5.2) key derivation — port of
/// `pbkdf2.inc`.
pub mod pbkdf2;

// Flat re-export of the primary DRBG type so consumers can write
// `use heavything::crypto::HmacDrbg;` rather than the longer
// `use heavything::crypto::hmac_drbg::HmacDrbg;` path. The hash
// wrappers intentionally stay submodule-qualified because each
// hash function lives in a different module (`md5::Md5`,
// `sha1::Sha1`, `sha2::Sha256`, `sha2::Sha512`) and a flat re-export
// would lose that discrimination.
pub use hmac_drbg::HmacDrbg;
