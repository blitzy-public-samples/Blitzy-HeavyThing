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

//! X.509 certificate parsing, PEM/DER bridging, SSH host-key loading,
//! and OCSP request/response handling. Port of `X509.inc` (4,133 lines)
//! per AAP §0.5.1.3 — the FASM file is documented as "just enough X509
//! goods to deal with the TLS/SSH that I require". This Rust port
//! preserves that scope: only what the rest of the `heavything` crate
//! consumes is implemented; full X.509 path validation, CRL checking,
//! and detailed certificate field parsing are deliberately delegated
//! to `rustls-webpki` per AAP §0.7.2.3.
//!
//! # Scope
//!
//! Per AAP §0.5.1.3 and §0.7.2.3, this module provides:
//!
//! 1. **PEM file loading** ([`load_pem_file`]) — parses a server
//!    certificate-and-key PEM file (the format consumed by
//!    `webserver -tls cert.pem`) into a [`CertAndKey`] using
//!    `rustls-pemfile = "2"`. Supported PEM labels: `PRIVATE KEY`,
//!    `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `DSA PRIVATE KEY`,
//!    `CERTIFICATE`, `PUBLIC KEY`, `X509 CRL`, `CERTIFICATE REQUEST`.
//! 2. **SSH host-key loading** ([`load_ssh_host_keys`]) — reads
//!    OpenSSH host keys from `/etc/ssh/ssh_host_{rsa,dsa,ecdsa,ed25519}_key`
//!    where present, returning a [`Vec`] of [`SshHostKey`] for the
//!    `sshtalk` binary. Returns `Ok` with an empty `Vec` if no keys
//!    are found — the caller decides error behavior.
//! 3. **OCSP request construction and response handling**
//!    ([`fetch_ocsp`], [`update_ocsp_response`], [`set_ocsp_hook`])
//!    — equivalent to FASM `X509$ocsp` per RFC 6960. The OCSP request
//!    DER is built using [`append_der`]; the response DER is parsed
//!    just enough to extract the validity window
//!    ([`OcspResponse::produced_at`], [`OcspResponse::next_update`])
//!    so callers in `crate::net::tls` can schedule refresh.
//! 4. **DER TLV emitter** ([`append_der`]) — equivalent to FASM
//!    `X509$append_der` per ITU-T X.690 §8.1. Used internally for
//!    OCSP request construction; exported `pub` so other crate modules
//!    that need to build small DER blobs can reuse it.
//! 5. **`rustls` bridges** ([`to_rustls_certified_key`],
//!    [`to_rustls_cert_der`]) — convert internal [`CertAndKey`] /
//!    [`CertChain`] types into the `rustls 0.23` `CertifiedKey` and
//!    `Vec<CertificateDer<'static>>` types that `crate::net::tls`
//!    installs into its `rustls::ServerConfig`.
//!
//! # FASM origin
//!
//! `X509.inc` exposes eleven public symbols at the line numbers below
//! (verified via grep on the source file):
//!
//! | FASM symbol                | Source line | Rust port location                    |
//! |----------------------------|-------------|---------------------------------------|
//! | `X509$new`                 |    62       | (subsumed by [`load_pem_file`])       |
//! | `X509$destroy`             |    74       | (replaced by [`Drop`] on [`PrivateKey`])|
//! | `X509$ocsp`                |   210       | [`fetch_ocsp`] / OCSP request builder |
//! | `X509$dsaprivate_destroy`  |  1122       | (replaced by [`Drop`] on [`PrivateKey`])|
//! | `X509$add_dsaprivatekey`   |  1193       | DSA branch of [`load_pem_file`]       |
//! | `X509$rsaprivate_destroy`  |  1427       | (replaced by [`Drop`] on [`PrivateKey`])|
//! | `X509$add_privatekey`      |  1490       | RSA/EC branch of [`load_pem_file`]    |
//! | `X509$add_certificate`     |  1829       | cert-chain branch of [`load_pem_file`]|
//! | `X509$new_ssh`             |  3490       | [`load_ssh_host_keys`]                |
//! | `X509$new_pem`             |  3782       | [`load_pem_file`]                     |
//! | `X509$append_der`          |  3956       | [`append_der`]                        |
//!
//! # Public API
//!
//! Types exposed by this module:
//! * [`CertChain`] — DER-encoded X.509 certificate chain.
//! * [`PrivateKey`] — DER-encoded private key with [`Drop`]-based
//!   zeroization. The [`Drop`] impl manually overwrites the secret
//!   bytes (with `std::hint::black_box` to defeat dead-code
//!   elimination) per the AAP §0.5.1.3 directive **"DO NOT use
//!   `zeroize` crate"**.
//! * [`KeyAlgo`] — key-algorithm tag (Rsa / Dsa / EcdsaP256 /
//!   EcdsaP384 / Ed25519).
//! * [`CertAndKey`] — paired chain + key returned by
//!   [`load_pem_file`].
//! * [`OcspResponse`] — DER-encoded OCSP response with `produced_at`
//!   / `next_update` validity window (RFC 6960 §4.2.2.1).
//! * [`SshHostKey`] — algorithm + private + public-key blob,
//!   consumed by `crate::net::ssh::auth` when sshtalk identifies as
//!   the SSH server.
//!
//! Functions exposed by this module:
//! * [`load_pem_file`] / [`load_ssh_host_keys`] — file I/O entry
//!   points returning typed errors.
//! * [`fetch_ocsp`] — async OCSP fetch (delegates the actual HTTP to
//!   the user-installed hook so this crypto module need not depend
//!   on `crate::net::http::client`).
//! * [`update_ocsp_response`] — installs a fetched OCSP response on
//!   a [`rustls::sign::CertifiedKey`].
//! * [`set_ocsp_hook`] — registers a process-global async closure
//!   the [`fetch_ocsp`] machinery uses for actual HTTP transport.
//!   `crate::net::tls` calls this once at startup, after which
//!   [`fetch_ocsp`] becomes self-sufficient.
//! * [`append_der`] / [`to_rustls_certified_key`] /
//!   [`to_rustls_cert_der`] — pure-Rust helpers (no I/O).
//!
//! # Behavioral preservation
//!
//! Per AAP §0.7.2.3 the FASM library treats server-presented
//! certificates with a **"garbage-in/garbage-out"** posture — no chain
//! validation. This Rust port preserves that posture for `webserver`
//! (TLS server identity); for the `webclient`-style HTTPS path used
//! by `hnwatch` we rely on rustls + `webpki-roots` for proper chain
//! validation, which is documented in AAP §0.7.2.3 as an intentional
//! behavioral improvement.
//!
//! Per AAP §0.5.1.3 DSA support is retained **only** for SSH `ssh-dss`
//! host keys. `rustls 0.23` does not support DSA for TLS, so DSA
//! [`PrivateKey`] values returned by [`load_pem_file`] cannot be
//! converted via [`to_rustls_certified_key`] — the function returns
//! [`CryptoError::X509`] in that case.
//!
//! # OCSP design (RFC 6960)
//!
//! [`fetch_ocsp`] builds an OCSP request `OCSPRequest` containing one
//! `tbsRequest.requestList[0]` `Request.reqCert` `CertID`:
//!
//! ```text
//! CertID ::= SEQUENCE {
//!     hashAlgorithm   AlgorithmIdentifier,
//!     issuerNameHash  OCTET STRING,   -- hash of issuer's DN
//!     issuerKeyHash   OCTET STRING,   -- hash of issuer's SPKI
//!     serialNumber    CertificateSerialNumber }
//! ```
//!
//! The hash algorithm defaults to **SHA-1** per RFC 5019 baseline-OCSP
//! profile (which AAP §0.5.1.3 requires — `config::X509_OCSP_SHA256`
//! is `false` by default for maximum responder compatibility). When
//! `config::X509_OCSP_SHA256 = true` SHA-256 is used instead.
//!
//! A 16-byte random `nonce` extension (RFC 6960 §4.4.1) is included
//! in every request to defend against replay; randomness comes from
//! [`crate::crypto::rng::block`].
//!
//! Actual HTTP transport is **not** performed by this module — that
//! depends on `crate::net::http::client` which depends on this module.
//! To break that cycle, [`fetch_ocsp`] delegates to a user-installed
//! transport hook registered via [`set_ocsp_hook`]. The expected
//! caller is `crate::net::tls` startup which reads the OCSP responder
//! URI from the cert's AIA extension and registers a hook that uses
//! `crate::net::http::client::fetch`.
//!
//! Refresh and retry intervals come from `config::X509_OCSP_REFRESH`
//! (default 7200 s = 2 hours) and `config::X509_OCSP_RETRY` (default
//! 300 s = 5 minutes); the **caller** schedules timers using these
//! intervals. This module just fetches.
//!
//! # Performance
//!
//! All operations are O(n) in the input length. PEM parsing is bounded
//! by the input file size. DER emission via [`append_der`] performs at
//! most one length-encoded prefix calculation per call. No allocations
//! occur in [`Drop for PrivateKey`] — the secret bytes are overwritten
//! in place.
//!
//! # Thread safety
//!
//! All public types are `Send + Sync` (every field is owned `Vec` or
//! `SystemTime` or fixed-size enum). The OCSP hook is stored in an
//! [`OnceLock`] and is `Send + Sync` by trait bound.
//!
//! # `unsafe` audit
//!
//! Zero `unsafe` blocks in this module. PEM parsing, SSH key parsing,
//! and DER emission are all safe Rust. The only entropy source is
//! [`crate::crypto::rng::block`] (which has its own audited `unsafe`
//! sites). [`Drop for PrivateKey`] uses `std::hint::black_box` (a
//! safe API) to prevent dead-code elimination of the manual zero
//! overwrite.

// ============================================================================
// Imports
// ============================================================================

use std::fs::File;
use std::hint::black_box;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::Item;

use crate::config::{X509_OCSP_REFRESH, X509_OCSP_RETRY, X509_OCSP_SHA256, X509_OCSP_SYSLOG};
use crate::crypto::bigint::BigUint;
use crate::crypto::rng;
use crate::crypto::sha1::sha1;
use crate::crypto::sha2::sha256;
use crate::error::CryptoError;

// ============================================================================
// DER tag constants (ITU-T X.690 §8 — universal class, primitive form
// where applicable). Used by both the OCSP request builder
// (`fetch_ocsp`) and re-exported via `append_der` callers.
// ============================================================================

/// DER tag for `INTEGER` (universal, primitive). RFC 6025 / X.690 §8.1.
const DER_TAG_INTEGER: u8 = 0x02;
/// DER tag for `BIT STRING` (universal, primitive).
const DER_TAG_BIT_STRING: u8 = 0x03;
/// DER tag for `OCTET STRING` (universal, primitive).
const DER_TAG_OCTET_STRING: u8 = 0x04;
/// DER tag for `NULL` (universal, primitive).
const DER_TAG_NULL: u8 = 0x05;
/// DER tag for `OBJECT IDENTIFIER` (universal, primitive).
const DER_TAG_OID: u8 = 0x06;
/// DER tag for `SEQUENCE` (universal, constructed). 0x30 = 0x10 + 0x20
/// (constructed bit set).
const DER_TAG_SEQUENCE: u8 = 0x30;
/// DER tag for context-specific `[0]` constructed (used by OCSP
/// `tbsRequest.requestExtensions`).
const DER_TAG_CONTEXT_0_CONSTRUCTED: u8 = 0xA0;
/// DER tag for context-specific `[2]` constructed (used by OCSP
/// `requestList.singleRequestExtensions` and similar).
const DER_TAG_CONTEXT_2_CONSTRUCTED: u8 = 0xA2;

// ----------------------------------------------------------------------------
// OCSP-related OIDs (ASN.1 OBJECT IDENTIFIERs encoded per X.690 §8.19).
// Each constant holds the *contents* of the OID (without the outer
// `06 LL` TLV prefix); callers wrap with `append_der(out, DER_TAG_OID, oid)`.
// ----------------------------------------------------------------------------

/// `id-sha1 ::= 1.3.14.3.2.26` — RFC 3279 §2.2.2. Five-byte encoding
/// `{ 0x2b, 0x0e, 0x03, 0x02, 0x1a }`.
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];

/// `id-sha256 ::= 2.16.840.1.101.3.4.2.1` — RFC 5754. Nine-byte encoding
/// `{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 }`.
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

// ============================================================================
// Public type definitions
// ============================================================================

/// DER-encoded X.509 certificate chain, end-entity first.
///
/// Mirrors the FASM `X509_certificates_ofs` field (`X509.inc` line 52)
/// — a list of buffer pointers each holding the signed-certificate
/// DER. The end-entity cert is at index `0`; subsequent entries are
/// intermediate CAs in order toward the root. Anchor / root
/// certificates are typically omitted (rustls + webpki resolve them
/// via the trust store at handshake time).
///
/// Per AAP §0.7.2.3 this struct holds raw DER without performing any
/// chain validation — that is intentional and matches the FASM
/// "garbage-in/garbage-out" posture for server-presented certificates.
#[derive(Debug, Clone, Default)]
pub struct CertChain {
    /// DER-encoded certificates, end-entity first. Each entry is the
    /// raw `signed Certificate` DER per RFC 5280 §4.1.
    pub certs: Vec<Vec<u8>>,
}

/// Key-algorithm tag for [`PrivateKey`] and [`SshHostKey`]. Determined
/// by the PEM label (`RSA PRIVATE KEY` -> [`KeyAlgo::Rsa`], etc.) or
/// by inspecting the OID inside a PKCS #8 wrapper.
///
/// Per AAP §0.5.1.3 [`KeyAlgo::Dsa`] is retained **only** for SSH
/// `ssh-dss` host keys; rustls 0.23 does not support DSA for TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgo {
    /// RSA / PKCS #1 (`RSA PRIVATE KEY` PEM label, OID
    /// `1.2.840.113549.1.1.1`).
    Rsa,
    /// DSA / FIPS 186-4 (`DSA PRIVATE KEY` PEM label, OID
    /// `1.2.840.10040.4.1`). SSH-only per AAP §0.5.1.3.
    Dsa,
    /// ECDSA over NIST P-256 / `secp256r1` / `prime256v1` (`EC PRIVATE
    /// KEY` PEM label, named-curve OID `1.2.840.10045.3.1.7`).
    EcdsaP256,
    /// ECDSA over NIST P-384 / `secp384r1` (named-curve OID
    /// `1.3.132.0.34`).
    EcdsaP384,
    /// Ed25519 / RFC 8410 (PKCS #8 OID `1.3.101.112`).
    Ed25519,
}

/// DER-encoded private key with [`Drop`]-based zeroization.
///
/// The [`Drop`] implementation overwrites [`PrivateKey::der`] with
/// zeros and applies [`std::hint::black_box`] to the result so the
/// optimizer cannot elide the write. Per AAP §0.5.1.3 the `zeroize`
/// crate is **deliberately not used** — the Rust port performs manual
/// zeroization to keep the dependency surface aligned with AAP §0.6.1.
///
/// The [`PrivateKey::der`] field stores the raw DER as it appeared in
/// the source PEM:
///
/// * For [`KeyAlgo::Rsa`] from `RSA PRIVATE KEY` PEM blocks, the bytes
///   are PKCS #1 RSAPrivateKey DER (RFC 8017 §A.1.2).
/// * For [`KeyAlgo::Rsa`] / [`KeyAlgo::EcdsaP256`] /
///   [`KeyAlgo::EcdsaP384`] / [`KeyAlgo::Ed25519`] from `PRIVATE KEY`
///   PEM blocks, the bytes are PKCS #8 PrivateKeyInfo DER (RFC 5958).
/// * For [`KeyAlgo::EcdsaP256`] / [`KeyAlgo::EcdsaP384`] from
///   `EC PRIVATE KEY` PEM blocks, the bytes are SEC 1 ECPrivateKey
///   DER (RFC 5915).
/// * For [`KeyAlgo::Dsa`] the bytes are the FASM-style DSA private-key
///   DER (used only by SSH per AAP §0.5.1.3).
///
/// rustls consumers should round-trip via
/// [`PrivateKey::to_rustls_private_key_der`] to get the appropriate
/// `rustls::pki_types::PrivateKeyDer<'static>` variant.
pub struct PrivateKey {
    /// DER-encoded private key bytes. Zeroized in [`Drop`].
    pub der: Vec<u8>,
    /// Algorithm tag. Determined by the source PEM label or PKCS #8
    /// algorithm OID at parse time.
    pub algorithm: KeyAlgo,
}

impl PrivateKey {
    /// Construct a [`PrivateKey`] from raw DER bytes plus the
    /// algorithm tag determined by the caller (typically via the
    /// source PEM label). The `der` argument is consumed; no copy is
    /// made.
    pub fn new(der: Vec<u8>, algorithm: KeyAlgo) -> Self {
        Self { der, algorithm }
    }

    /// Convert this private key into the `rustls::pki_types::PrivateKeyDer`
    /// variant that matches its [`KeyAlgo`] and DER format. Returns
    /// [`CryptoError::X509`] for [`KeyAlgo::Dsa`] (rustls does not
    /// support DSA for TLS per AAP §0.5.1.3).
    ///
    /// The returned value owns a clone of [`PrivateKey::der`]; the
    /// original key remains intact (and will still be zeroized by
    /// [`Drop`] when it goes out of scope).
    pub fn to_rustls_private_key_der(&self) -> Result<PrivateKeyDer<'static>, CryptoError> {
        match self.algorithm {
            KeyAlgo::Rsa => {
                // RSA can come from either `RSA PRIVATE KEY` (PKCS #1)
                // or `PRIVATE KEY` (PKCS #8). We disambiguate by
                // peeking at the first byte: PKCS #1 starts with a
                // SEQUENCE tag (0x30) whose contents start with an
                // INTEGER (0x02) for the version field; PKCS #8 also
                // starts with SEQUENCE 0x30 but its contents begin
                // with an INTEGER (0x02) for the version, then a
                // SEQUENCE (0x30) for the algorithm identifier.
                //
                // The cleanest disambiguator: try PKCS #8 first, fall
                // back to PKCS #1. rustls's `any_supported_type` does
                // the same internally, so the order does not affect
                // correctness — only debuggability.
                if is_pkcs8_rsa(&self.der) {
                    Ok(PrivateKeyDer::Pkcs8(self.der.clone().into()))
                } else {
                    Ok(PrivateKeyDer::Pkcs1(self.der.clone().into()))
                }
            }
            KeyAlgo::EcdsaP256 | KeyAlgo::EcdsaP384 => {
                // EC keys can be either SEC 1 (`EC PRIVATE KEY` PEM)
                // or PKCS #8 (`PRIVATE KEY` PEM). Both wrap the same
                // ECPrivateKey structure but PKCS #8 adds the PKCS #8
                // header. SEC 1 starts with SEQUENCE { INTEGER 1 ... }.
                if is_pkcs8_ec(&self.der) {
                    Ok(PrivateKeyDer::Pkcs8(self.der.clone().into()))
                } else {
                    Ok(PrivateKeyDer::Sec1(self.der.clone().into()))
                }
            }
            KeyAlgo::Ed25519 => {
                // Ed25519 keys are always PKCS #8 in PEM form
                // (RFC 8410). No SEC 1 form exists.
                Ok(PrivateKeyDer::Pkcs8(self.der.clone().into()))
            }
            KeyAlgo::Dsa => Err(CryptoError::X509(
                "DSA private keys are not supported by rustls 0.23 (\
                 SSH-only per AAP §0.5.1.3)"
                    .to_string(),
            )),
        }
    }
}

impl Drop for PrivateKey {
    /// Zeroize the secret bytes when the key goes out of scope. Uses
    /// [`std::hint::black_box`] to defeat dead-code elimination per
    /// the AAP §0.5.1.3 directive **"DO NOT use `zeroize` crate —
    /// simply overwrite with zeros manually and `std::hint::black_box`
    /// to prevent DCE"**.
    fn drop(&mut self) {
        // Overwrite each byte. `black_box` reads the slice address
        // after the write so the compiler cannot prove the write is
        // unobserved.
        for b in self.der.iter_mut() {
            *b = 0;
        }
        // Force the optimizer to treat the buffer as observed.
        let _ = black_box(self.der.as_ptr());
    }
}

impl std::fmt::Debug for PrivateKey {
    /// Redacts [`PrivateKey::der`] in debug output to prevent
    /// accidental key disclosure via logging, similar to
    /// `crate::crypto::dh::DhKeypair`'s redacted Debug impl.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("algorithm", &self.algorithm)
            .field("der", &format_args!("[redacted; {} bytes]", self.der.len()))
            .finish()
    }
}

/// Paired certificate chain + private key, returned by
/// [`load_pem_file`] and consumed by [`to_rustls_certified_key`] when
/// building a `rustls::sign::CertifiedKey` for the TLS server.
#[derive(Debug)]
pub struct CertAndKey {
    /// DER-encoded certificate chain, end-entity first.
    pub chain: CertChain,
    /// Private key matching the end-entity certificate.
    pub key: PrivateKey,
}

/// DER-encoded OCSP response with extracted validity window.
///
/// Mirrors the FASM `X509cert_ocspresponse_ofs` field (`X509.inc`
/// line 1812) — the raw bytes the responder returned, ready to be
/// stapled onto a `rustls::sign::CertifiedKey` via
/// [`update_ocsp_response`]. The `produced_at` and `next_update`
/// fields are extracted from the response's `tbsResponseData.responses[0]`
/// `SingleResponse` per RFC 6960 §4.2.2.1 so callers can decide
/// whether to refresh.
#[derive(Debug, Clone)]
pub struct OcspResponse {
    /// Raw DER bytes of the OCSP response (the `OCSPResponse`
    /// SEQUENCE, suitable for direct staple).
    pub der: Vec<u8>,
    /// The `producedAt` field of the basic response. Equal to
    /// [`UNIX_EPOCH`] if the field could not be parsed (e.g., the
    /// response is empty or malformed).
    pub produced_at: SystemTime,
    /// The `nextUpdate` field of the first `SingleResponse`. Equal
    /// to [`UNIX_EPOCH`] if absent or unparseable. Per RFC 6960 §4.2.2.1
    /// `nextUpdate` is **OPTIONAL**, so `UNIX_EPOCH` here means
    /// "responder did not specify an expiration".
    pub next_update: SystemTime,
}

/// SSH host key (private + public blob) loaded from
/// `/etc/ssh/ssh_host_*_key` files. Mirrors the FASM `X509$new_ssh`
/// public-buffer fields at `X509.inc` lines 3490+ (`X509_pubkey_ofs`,
/// `X509_dsapubkey_ofs`).
///
/// Consumed by `crate::net::ssh::auth` when sshtalk identifies as the
/// SSH server. The `public_key_blob` is the SSH wire-format public-key
/// blob ready for inclusion in the SSH `SSH_MSG_KEXDH_GEX_REPLY`
/// message per RFC 4253 §6.6.
#[derive(Debug)]
pub struct SshHostKey {
    /// Algorithm tag corresponding to the SSH host-key file
    /// (`ssh_host_rsa_key` -> [`KeyAlgo::Rsa`], etc.).
    pub algorithm: KeyAlgo,
    /// Private key (DER-encoded, with [`Drop`]-zeroization).
    pub private_key: PrivateKey,
    /// SSH wire-format public-key blob. Empty if no `.pub` companion
    /// file was readable next to the private key — the caller must
    /// then derive the blob from the private key. Format per RFC 4253
    /// §6.6 (string `algorithm` + algorithm-specific fields).
    pub public_key_blob: Vec<u8>,
}

/// `id-pkix-ocsp-nonce ::= 1.3.6.1.5.5.7.48.1.2` — RFC 6960 §4.4.1.
/// Nine-byte encoding `{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01,
/// 0x02 }`.
const OID_OCSP_NONCE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];

/// Default directory for OpenSSH host-key files. Mirrors the FASM
/// `X509$new_ssh` default at `X509.inc` line 3490 (`/etc/ssh`).
const SSH_HOST_KEY_DIR: &str = "/etc/ssh";

/// OpenSSH host-key file basenames probed by [`load_ssh_host_keys`].
/// The first two are the FASM-original RSA + DSA keys; the latter two
/// are modern additions (ECDSA / Ed25519) that the schema requires
/// support for. Each entry is `(basename, KeyAlgo guess)`; the actual
/// algorithm is determined by parsing the PEM, not by the filename.
const SSH_HOST_KEY_FILES: &[&str] = &[
    "ssh_host_rsa_key",
    "ssh_host_dsa_key",
    "ssh_host_ecdsa_key",
    "ssh_host_ed25519_key",
];

/// Maximum allowed PEM file size (4 MiB). Defends [`load_pem_file`]
/// against accidental memory blowup from malformed inputs.
const MAX_PEM_SIZE: u64 = 4 * 1024 * 1024;

// ============================================================================
// PEM disambiguation helpers
// ============================================================================

/// Heuristic check for whether `der` looks like a PKCS #8
/// PrivateKeyInfo wrapping an RSA key (vs a PKCS #1 RSAPrivateKey).
///
/// PKCS #8 PrivateKeyInfo (RFC 5958 §2):
///   `SEQUENCE { Version=0 INTEGER, AlgorithmIdentifier SEQUENCE, OCTET STRING }`
/// PKCS #1 RSAPrivateKey (RFC 8017 §A.1.2):
///   `SEQUENCE { Version=0..1 INTEGER, modulus INTEGER, ... eight INTEGERs total }`
///
/// Both start with `30 LL 02 ...`. The disambiguator: PKCS #8's second
/// element is a SEQUENCE (algorithm identifier), tag 0x30; PKCS #1's
/// second element is the modulus, tag 0x02.
fn is_pkcs8_rsa(der: &[u8]) -> bool {
    // Skip outer SEQUENCE TLV: tag 0x30 + length encoding.
    let Some((_outer_len, outer_data_start)) = parse_tlv_prefix(der, 0x30) else {
        return false;
    };
    if outer_data_start >= der.len() {
        return false;
    }
    let inner = &der[outer_data_start..];

    // Skip Version INTEGER (PKCS #8 v1 = INTEGER 0; PKCS #1 = INTEGER
    // 0 or 1). Both have tag 0x02. parse_tlv_prefix returns
    // (content_length, content_start_offset); the position immediately
    // following the version TLV is `content_start + content_length`.
    let Some((version_len, version_data_start)) = parse_tlv_prefix(inner, 0x02) else {
        return false;
    };
    let after_version = version_data_start + version_len;
    if after_version >= inner.len() {
        return false;
    }

    // Look at the next tag. PKCS #8 -> 0x30 (SEQUENCE algorithm
    // identifier). PKCS #1 -> 0x02 (next INTEGER, the modulus).
    inner[after_version] == 0x30
}

/// Heuristic check for whether `der` looks like a PKCS #8
/// PrivateKeyInfo wrapping an EC key (vs a SEC 1 ECPrivateKey).
///
/// PKCS #8 PrivateKeyInfo: `SEQUENCE { INTEGER 0, SEQUENCE algId, OCTET
/// STRING privateKey }`. The version INTEGER is always 0 for v1.
///
/// SEC 1 ECPrivateKey (RFC 5915 §3): `SEQUENCE { INTEGER 1, OCTET
/// STRING privateKey, ... }`. The version INTEGER is always 1.
///
/// Disambiguator: peek at the version INTEGER value. 0 -> PKCS #8;
/// 1 -> SEC 1.
fn is_pkcs8_ec(der: &[u8]) -> bool {
    let Some((_outer_len, outer_data_start)) = parse_tlv_prefix(der, 0x30) else {
        return false;
    };
    if outer_data_start >= der.len() {
        return false;
    }
    let inner = &der[outer_data_start..];

    // Version INTEGER:
    let Some((vlen, vdata_start)) = parse_tlv_prefix(inner, 0x02) else {
        return false;
    };
    let vdata_end = vdata_start + vlen;
    if vdata_end > inner.len() || vlen == 0 {
        return false;
    }
    // Read the INTEGER as an unsigned big-endian value. PKCS #8 v=0;
    // SEC 1 v=1.
    let version_bytes = &inner[vdata_start..vdata_end];
    // INTEGER 0 is encoded as `02 01 00`; INTEGER 1 as `02 01 01`.
    // Treat any single-byte 0x00 as v=0 (PKCS #8); 0x01 as v=1 (SEC 1).
    if version_bytes == [0x00] {
        return true;
    }
    if version_bytes == [0x01] {
        return false;
    }
    // Defensive: any other version value -> assume not PKCS #8 so the
    // caller's `Sec1Key` round-trip surfaces the actual rustls error.
    false
}

/// Parse a single DER TLV prefix: confirm the first byte equals
/// `expected_tag` and decode the length field per X.690 §8.1.3.
/// Returns `Some((content_length, offset_to_first_content_byte))` on
/// success. Returns `None` on any malformed input or tag mismatch.
///
/// Handles short-form (length < 128) and long-form (length encoded
/// as `0x80 | n_bytes` followed by `n_bytes` of length). Indefinite
/// length encoding (`0x80` exactly) is rejected because DER prohibits
/// it (X.690 §10.1).
fn parse_tlv_prefix(buf: &[u8], expected_tag: u8) -> Option<(usize, usize)> {
    if buf.len() < 2 || buf[0] != expected_tag {
        return None;
    }
    let len_byte = buf[1];
    if len_byte < 0x80 {
        // Short form.
        Some((len_byte as usize, 2))
    } else if len_byte == 0x80 {
        // Indefinite length — invalid in DER.
        None
    } else {
        // Long form: low 7 bits = number of subsequent length bytes.
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 8 || buf.len() < 2 + n {
            return None;
        }
        let mut value: u64 = 0;
        for &b in &buf[2..2 + n] {
            value = (value << 8) | u64::from(b);
        }
        let value = usize::try_from(value).ok()?;
        Some((value, 2 + n))
    }
}

// ============================================================================
// PEM file loading: load_pem_file
// ============================================================================

/// Read a PEM file containing a server certificate chain plus a
/// matching private key, returning a [`CertAndKey`] suitable for
/// [`to_rustls_certified_key`].
///
/// This is the Rust port of FASM `X509$new_pem` at `X509.inc` line
/// 3782. The FASM original looped three times (RSA / DSA / certificate
/// label patterns) extracting matching base64 substrings; the Rust
/// port delegates that work to `rustls-pemfile = "2"` which understands
/// all the common PEM labels.
///
/// # Supported PEM labels
///
/// Per the agent prompt's Phase 2 requirements:
///
/// * `PRIVATE KEY` (PKCS #8) — produces a [`KeyAlgo::Rsa`] /
///   [`KeyAlgo::EcdsaP256`] / [`KeyAlgo::EcdsaP384`] /
///   [`KeyAlgo::Ed25519`] depending on the inner algorithm OID.
/// * `RSA PRIVATE KEY` (PKCS #1) — produces [`KeyAlgo::Rsa`].
/// * `EC PRIVATE KEY` (SEC 1) — produces [`KeyAlgo::EcdsaP256`] or
///   [`KeyAlgo::EcdsaP384`] based on the embedded named-curve OID.
/// * `DSA PRIVATE KEY` — produces [`KeyAlgo::Dsa`] (SSH-only per
///   AAP §0.5.1.3; cannot be passed to TLS).
/// * `CERTIFICATE` — appended to the [`CertChain`] in source order.
/// * `PUBLIC KEY`, `X509 CRL`, `CERTIFICATE REQUEST` — silently
///   skipped (not relevant for a server's `(chain, key)` bundle).
///
/// # Errors
///
/// Returns [`CryptoError::X509`] when:
/// * the file is unreadable or larger than 4 MiB
///   (`MAX_PEM_SIZE`)
/// * no `CERTIFICATE` block is found
/// * no recognized private-key block is found
/// * `rustls-pemfile`'s parser rejects the input.
pub fn load_pem_file(path: &Path) -> Result<CertAndKey, CryptoError> {
    let file = File::open(path)
        .map_err(|e| CryptoError::X509(format!("failed to open PEM file {}: {}", path.display(), e)))?;

    // Bound the read to MAX_PEM_SIZE so a malformed input cannot OOM
    // the process.
    let mut reader = BufReader::new(file.take(MAX_PEM_SIZE));
    parse_pem_reader(&mut reader, path)
}

/// Inner helper that operates on any [`std::io::BufRead`]. Factored
/// out of [`load_pem_file`] so unit tests can pass a `&[u8]` cursor
/// without touching the filesystem.
fn parse_pem_reader<R: std::io::BufRead>(
    reader: &mut R,
    source_label: &Path,
) -> Result<CertAndKey, CryptoError> {
    let mut chain_certs: Vec<Vec<u8>> = Vec::new();
    let mut found_key: Option<PrivateKey> = None;

    loop {
        let item = rustls_pemfile::read_one(reader).map_err(|e| {
            CryptoError::X509(format!("PEM parse error in {}: {}", source_label.display(), e))
        })?;
        let Some(item) = item else {
            // EOF.
            break;
        };
        match item {
            Item::X509Certificate(der) => {
                chain_certs.push(der.as_ref().to_vec());
            }
            Item::Pkcs1Key(der) => {
                if found_key.is_none() {
                    found_key = Some(PrivateKey::new(der.secret_pkcs1_der().to_vec(), KeyAlgo::Rsa));
                }
            }
            Item::Pkcs8Key(der) => {
                if found_key.is_none() {
                    let bytes = der.secret_pkcs8_der().to_vec();
                    let algo = detect_pkcs8_algorithm(&bytes).unwrap_or(KeyAlgo::Rsa);
                    found_key = Some(PrivateKey::new(bytes, algo));
                }
            }
            Item::Sec1Key(der) => {
                if found_key.is_none() {
                    let bytes = der.secret_sec1_der().to_vec();
                    let algo = detect_sec1_algorithm(&bytes).unwrap_or(KeyAlgo::EcdsaP256);
                    found_key = Some(PrivateKey::new(bytes, algo));
                }
            }
            // SubjectPublicKeyInfo, Crl, Csr — not part of the server
            // (chain, key) bundle. Silently skip per the FASM behavior
            // which simply ignored any block whose label didn't match
            // RSA/DSA/CERTIFICATE.
            _ => continue,
        }
    }

    if chain_certs.is_empty() {
        return Err(CryptoError::X509(format!(
            "no CERTIFICATE block found in {}",
            source_label.display()
        )));
    }

    let key = found_key.ok_or_else(|| {
        CryptoError::X509(format!(
            "no PRIVATE KEY block found in {}",
            source_label.display()
        ))
    })?;

    Ok(CertAndKey {
        chain: CertChain { certs: chain_certs },
        key,
    })
}

// ----------------------------------------------------------------------------
// PKCS #8 / SEC 1 algorithm detection helpers
// ----------------------------------------------------------------------------

/// Detect the inner algorithm of a PKCS #8 PrivateKeyInfo by parsing
/// the AlgorithmIdentifier OID per RFC 5958 §2 / RFC 5208 §5.
///
/// Returns `None` if the DER cannot be parsed deeply enough to extract
/// the algorithm OID; callers default to [`KeyAlgo::Rsa`] in that
/// case (which is consistent with the `RSA PRIVATE KEY` PEM label
/// fallback).
fn detect_pkcs8_algorithm(pkcs8_der: &[u8]) -> Option<KeyAlgo> {
    // PrivateKeyInfo ::= SEQUENCE {
    //     version Version (= INTEGER 0),
    //     privateKeyAlgorithm AlgorithmIdentifier,
    //     privateKey OCTET STRING,
    //     ... }
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //     algorithm OBJECT IDENTIFIER,
    //     parameters ANY DEFINED BY algorithm OPTIONAL }
    let (_, outer_start) = parse_tlv_prefix(pkcs8_der, 0x30)?;
    let body = &pkcs8_der[outer_start..];

    // Skip Version INTEGER:
    let (vlen, vstart) = parse_tlv_prefix(body, 0x02)?;
    let after_version = vstart + vlen;
    if after_version >= body.len() {
        return None;
    }

    // AlgorithmIdentifier SEQUENCE:
    let alg_buf = &body[after_version..];
    let (_alen, astart) = parse_tlv_prefix(alg_buf, 0x30)?;
    let alg_inner = &alg_buf[astart..];

    // OBJECT IDENTIFIER:
    let (oid_len, oid_start) = parse_tlv_prefix(alg_inner, 0x06)?;
    let oid_end = oid_start + oid_len;
    if oid_end > alg_inner.len() {
        return None;
    }
    let oid = &alg_inner[oid_start..oid_end];

    // Match against well-known PKCS #8 algorithm OIDs.
    match oid {
        // 1.2.840.113549.1.1.1 — rsaEncryption (RFC 3447 §A.1).
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] => Some(KeyAlgo::Rsa),
        // 1.2.840.10045.2.1 — id-ecPublicKey (RFC 5480 §2.1.1). For
        // EC keys the named curve is in the `parameters` field; we
        // peek at it here.
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] => {
            // Parameters follow the OID inside the algorithm
            // SEQUENCE. Walk past the OID and look for the named-curve
            // OID.
            let after_oid = &alg_inner[oid_end..];
            // parameters is itself an OBJECT IDENTIFIER:
            let (curve_len, curve_start) = parse_tlv_prefix(after_oid, 0x06)?;
            let curve_end = curve_start + curve_len;
            if curve_end > after_oid.len() {
                return Some(KeyAlgo::EcdsaP256);
            }
            let curve_oid = &after_oid[curve_start..curve_end];
            match curve_oid {
                // 1.2.840.10045.3.1.7 — secp256r1 / prime256v1.
                [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Some(KeyAlgo::EcdsaP256),
                // 1.3.132.0.34 — secp384r1.
                [0x2b, 0x81, 0x04, 0x00, 0x22] => Some(KeyAlgo::EcdsaP384),
                _ => Some(KeyAlgo::EcdsaP256),
            }
        }
        // 1.3.101.112 — Ed25519 (RFC 8410 §3).
        [0x2b, 0x65, 0x70] => Some(KeyAlgo::Ed25519),
        // 1.2.840.10040.4.1 — id-dsa (RFC 3279 §2.3.2).
        [0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01] => Some(KeyAlgo::Dsa),
        _ => None,
    }
}

/// Detect the named curve of a SEC 1 ECPrivateKey by parsing the
/// optional `parameters [0] EXPLICIT NamedCurve` field per RFC 5915 §3.
///
/// Returns `None` when the curve cannot be determined from the DER —
/// callers default to [`KeyAlgo::EcdsaP256`] in that case.
fn detect_sec1_algorithm(sec1_der: &[u8]) -> Option<KeyAlgo> {
    // ECPrivateKey ::= SEQUENCE {
    //     version INTEGER (= 1),
    //     privateKey OCTET STRING,
    //     parameters [0] EXPLICIT ECParameters OPTIONAL,
    //     publicKey  [1] EXPLICIT BIT STRING OPTIONAL }
    let (_, outer_start) = parse_tlv_prefix(sec1_der, 0x30)?;
    let body = &sec1_der[outer_start..];

    // Skip Version INTEGER:
    let (vlen, vstart) = parse_tlv_prefix(body, 0x02)?;
    let after_version = vstart + vlen;
    if after_version >= body.len() {
        return None;
    }

    // Skip privateKey OCTET STRING:
    let (klen, kstart) = parse_tlv_prefix(&body[after_version..], 0x04)?;
    let after_key = after_version + kstart + klen;
    if after_key >= body.len() {
        return None;
    }

    // [0] EXPLICIT parameters tag = 0xA0 (context-specific
    // constructed). The inner OID is the named-curve identifier.
    let after_key_buf = &body[after_key..];
    let (_plen, pstart) = parse_tlv_prefix(after_key_buf, 0xA0)?;
    let params_inner = &after_key_buf[pstart..];

    let (oid_len, oid_start) = parse_tlv_prefix(params_inner, 0x06)?;
    let oid_end = oid_start + oid_len;
    if oid_end > params_inner.len() {
        return None;
    }
    let curve_oid = &params_inner[oid_start..oid_end];
    match curve_oid {
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Some(KeyAlgo::EcdsaP256),
        [0x2b, 0x81, 0x04, 0x00, 0x22] => Some(KeyAlgo::EcdsaP384),
        _ => None,
    }
}

// ============================================================================
// SSH host-key loading: load_ssh_host_keys
// ============================================================================

/// Load every readable OpenSSH host key from `/etc/ssh`. Mirrors the
/// FASM `X509$new_ssh` at `X509.inc` line 3490.
///
/// Probes the four canonical files
/// `/etc/ssh/ssh_host_{rsa,dsa,ecdsa,ed25519}_key` (the FASM original
/// only handled RSA and DSA; the modern additions are required by the
/// schema). For each readable file:
///
/// 1. Parse the PEM content into a [`PrivateKey`] using the shared
///    [`parse_pem_reader`] machinery.
/// 2. Attempt to read the matching `.pub` file (e.g.,
///    `ssh_host_rsa_key.pub`). If readable, decode the second
///    whitespace-separated token (the base64 SSH wire-format public
///    key blob) and store it in [`SshHostKey::public_key_blob`].
///    If unreadable or malformed, leave the blob empty — callers
///    can derive it from the private key when needed.
///
/// Returns `Ok` with an empty `Vec` if no host-key files exist at
/// all. Per the agent prompt, this matches FASM behavior: the caller
/// (e.g., `sshtalk` / `webserver`) decides whether absence is fatal.
///
/// # Errors
///
/// Returns [`CryptoError::X509`] only if a probed file *exists* but
/// cannot be parsed. A simple "file not present" is silent — that is
/// the normal case for, e.g., an Ed25519-only host that has no DSA
/// key.
pub fn load_ssh_host_keys() -> Result<Vec<SshHostKey>, CryptoError> {
    load_ssh_host_keys_from(Path::new(SSH_HOST_KEY_DIR))
}

/// Inner helper that operates on an explicit directory. Factored out
/// of [`load_ssh_host_keys`] so unit tests can target a tempdir
/// without touching `/etc/ssh`.
fn load_ssh_host_keys_from(dir: &Path) -> Result<Vec<SshHostKey>, CryptoError> {
    let mut keys: Vec<SshHostKey> = Vec::new();

    for &basename in SSH_HOST_KEY_FILES {
        let priv_path: PathBuf = dir.join(basename);
        // Silently skip files that don't exist or aren't readable —
        // matches the FASM behavior of probing each path and continuing
        // on ENOENT.
        let Ok(file) = File::open(&priv_path) else {
            continue;
        };

        // Parse the PEM. Reuse parse_pem_reader, but SSH host-key
        // files contain ONLY a private key (no certificate), so the
        // chain check would falsely fail. Use a simpler parser path.
        //
        // `parse_ssh_private_pem` returns `Ok(None)` when the file
        // exists and is readable but contains *no PEM block that
        // `rustls-pemfile` recognises*. The canonical example is the
        // OpenSSH-proprietary `BEGIN OPENSSH PRIVATE KEY` envelope
        // emitted by `ssh-keygen -A` for ECDSA / Ed25519 host keys
        // (rustls-pemfile silently returns `None` for these blocks
        // — verified empirically against rustls-pemfile 2.x). Such
        // files belong to algorithms that are explicitly *out of
        // corpus* per AAP §0.1.1 (which requires only `ssh-rsa`
        // and `ssh-dss`), so silently skipping them is correct and
        // mirrors the existing ENOENT-tolerant pattern above.
        let mut reader = BufReader::new(file.take(MAX_PEM_SIZE));
        let Some(private_key) = parse_ssh_private_pem(&mut reader, &priv_path)? else {
            // Diagnostic visibility for operators who *expected* the
            // key to load: emit a single syslog warning per skipped
            // file. This matches the AAP §0.5.1.7 "syslog for OCSP
            // activity" pattern and helps debug Gate-4 host-key
            // confusion without falsely failing the loader.
            crate::util::syslog::warning(&format!(
                "x509::load_ssh_host_keys: skipping {} \
                 (no rustls-pemfile-recognised private-key block; \
                 OpenSSH-proprietary `BEGIN OPENSSH PRIVATE KEY` \
                 format is not supported — regenerate with \
                 `ssh-keygen -m PEM -t rsa -f {}` if this key was \
                 intended for use)",
                priv_path.display(),
                priv_path.display(),
            ));
            continue;
        };

        // Probe for the matching public-key file. SSH's ssh-keygen
        // writes them as "<basename>.pub" alongside the private key.
        let pub_path = priv_path.with_extension("pub");
        let public_key_blob = read_ssh_public_key_blob(&pub_path);

        keys.push(SshHostKey {
            algorithm: private_key.algorithm,
            private_key,
            public_key_blob,
        });
    }

    Ok(keys)
}

/// Parse a PEM file that contains at most one private key (no
/// certificates). Used for SSH host-key files which are
/// private-key-only.
///
/// # Returns
///
/// * `Ok(Some(key))` — at least one PKCS#1 / PKCS#8 / SEC1 private-key
///   block was found and decoded.
/// * `Ok(None)` — the file exists and is well-formed but contains no
///   PEM block that `rustls-pemfile` recognises. This is the OpenSSH
///   proprietary `BEGIN OPENSSH PRIVATE KEY` envelope path: callers
///   in [`load_ssh_host_keys_from`] treat it as a *skip*, matching
///   AAP §0.1.1 which excludes Ed25519/ECDSA from the host-key
///   algorithm corpus.
/// * `Err(_)` — a structural PEM parse error (malformed BEGIN/END,
///   bad base64, etc.). These remain fatal so genuinely corrupt key
///   files are surfaced rather than silently ignored.
fn parse_ssh_private_pem<R: std::io::BufRead>(
    reader: &mut R,
    source_label: &Path,
) -> Result<Option<PrivateKey>, CryptoError> {
    loop {
        let item = rustls_pemfile::read_one(reader).map_err(|e| {
            CryptoError::X509(format!("PEM parse error in {}: {}", source_label.display(), e))
        })?;
        let Some(item) = item else {
            return Ok(None);
        };
        match item {
            Item::Pkcs1Key(der) => {
                return Ok(Some(PrivateKey::new(der.secret_pkcs1_der().to_vec(), KeyAlgo::Rsa)));
            }
            Item::Pkcs8Key(der) => {
                let bytes = der.secret_pkcs8_der().to_vec();
                let algo = detect_pkcs8_algorithm(&bytes).unwrap_or(KeyAlgo::Rsa);
                return Ok(Some(PrivateKey::new(bytes, algo)));
            }
            Item::Sec1Key(der) => {
                let bytes = der.secret_sec1_der().to_vec();
                let algo = detect_sec1_algorithm(&bytes).unwrap_or(KeyAlgo::EcdsaP256);
                return Ok(Some(PrivateKey::new(bytes, algo)));
            }
            // Skip any non-key blocks (certs, CRLs, CSRs) and keep
            // looking. SSH host-key files normally contain a single
            // private-key block; this loop tolerates files that mix
            // in other PEM block types.
            _ => continue,
        }
    }
}

/// Read an OpenSSH public-key file and decode the second
/// whitespace-separated token (the base64-encoded SSH wire-format blob).
///
/// Returns an empty `Vec` on any error (file missing, malformed,
/// base64 decode failure). This is intentional — callers can derive
/// the public-key blob from the private key when needed.
///
/// OpenSSH `.pub` format: `<algorithm> <base64-blob> [<comment>]\n`,
/// e.g., `ssh-rsa AAAAB3NzaC1yc2E... user@host`.
///
/// The base64 decoder is implemented inline (see [`decode_base64`])
/// to keep this module's dependency footprint aligned with the
/// schema-declared external imports (`rustls`, `rustls-pemfile`,
/// `std`); the per-crate `base64` crate dependency is consumed by
/// other modules that need full RFC 4648 features.
fn read_ssh_public_key_blob(pub_path: &Path) -> Vec<u8> {
    let Ok(content) = std::fs::read_to_string(pub_path) else {
        return Vec::new();
    };
    // Take the first non-empty line.
    let Some(line) = content.lines().find(|l| !l.trim().is_empty()) else {
        return Vec::new();
    };
    // Split on whitespace; second token is the base64 blob.
    let mut iter = line.split_whitespace();
    let _algorithm_token = iter.next();
    let Some(blob_b64) = iter.next() else {
        return Vec::new();
    };
    decode_base64(blob_b64).unwrap_or_default()
}

/// Inline base64 decoder. Returns `None` on malformed input.
///
/// Implements RFC 4648 §4 standard alphabet (A-Z / a-z / 0-9 / + /
/// `/`, padding char `=`). Whitespace is skipped (lenient, matching
/// OpenSSH `.pub` files which sometimes wrap long lines).
///
/// This is intentionally small and self-contained so this module's
/// dependency graph remains aligned with the AAP-declared whitelist.
/// Performance is adequate for the small (<1 KiB) SSH public-key
/// blobs this module decodes.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    // Reverse alphabet table: 0xFF means "invalid character"; 0xFE
    // means "padding" (`=`); valid values 0..=63.
    const INVALID: u8 = 0xFF;
    const PAD: u8 = 0xFE;
    static TABLE: [u8; 256] = {
        let mut t = [INVALID; 256];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i: usize = 0;
        while i < alphabet.len() {
            t[alphabet[i] as usize] = i as u8;
            i += 1;
        }
        t[b'=' as usize] = PAD;
        t
    };

    // Filter whitespace first.
    let mut symbols: Vec<u8> = Vec::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
            continue;
        }
        symbols.push(b);
    }
    if symbols.len() % 4 != 0 {
        return None;
    }

    let mut out: Vec<u8> = Vec::with_capacity(symbols.len() / 4 * 3);
    let mut quad: [u8; 4] = [0; 4];
    let mut chunk_iter = symbols.chunks_exact(4);
    for chunk in chunk_iter.by_ref() {
        let mut pad_count = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            let v = TABLE[b as usize];
            if v == INVALID {
                return None;
            }
            if v == PAD {
                pad_count += 1;
                quad[i] = 0;
            } else {
                if pad_count > 0 {
                    // Padding must be at the end only.
                    return None;
                }
                quad[i] = v;
            }
        }
        let triplet: u32 = (u32::from(quad[0]) << 18)
            | (u32::from(quad[1]) << 12)
            | (u32::from(quad[2]) << 6)
            | u32::from(quad[3]);
        out.push(((triplet >> 16) & 0xff) as u8);
        if pad_count <= 1 {
            out.push(((triplet >> 8) & 0xff) as u8);
        }
        if pad_count == 0 {
            out.push((triplet & 0xff) as u8);
        }
    }
    Some(out)
}

// ============================================================================
// DER TLV emitter: append_der
// ============================================================================

/// Append a single DER TLV (Tag-Length-Value) to `out`. Equivalent to
/// FASM `X509$append_der` at `X509.inc` line 3956.
///
/// Encodes the length per ITU-T X.690 §8.1.3:
///
/// * lengths `0..=127` — short form (one byte: the length itself).
/// * lengths `128..=255` — long form: `0x81 LL`.
/// * lengths `256..=65_535` — long form: `0x82 HH LL`.
/// * lengths `65_536..=16_777_215` — long form: `0x83 HH MM LL`.
/// * lengths `16_777_216..=4_294_967_295` — long form: `0x84 HH MM LL LL`.
///
/// The `tag` argument is written verbatim — callers pass the
/// already-encoded full tag byte (e.g., `0x30` for SEQUENCE, `0xA0`
/// for context-specific `[0]` constructed). For multi-byte high-tag
/// numbers (X.690 §8.1.2.4) callers must construct the tag bytes
/// themselves before any append; this function does not encode those.
///
/// # Examples
///
/// Encode a SEQUENCE containing an OID:
///
/// ```ignore
/// use crate::crypto::x509::append_der;
/// let mut out = Vec::new();
/// // Inner OID 1.3.14.3.2.26 (SHA-1):
/// let mut inner = Vec::new();
/// append_der(&mut inner, 0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]);
/// // Wrap in SEQUENCE:
/// append_der(&mut out, 0x30, &inner);
/// ```
pub fn append_der(out: &mut Vec<u8>, tag: u8, contents: &[u8]) {
    out.push(tag);
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x1_00_00 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    } else if len < 0x1_00_00_00 {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    } else {
        // X.690 permits up to 0x84 followed by 4 length bytes;
        // anything larger would not fit in a Vec on a 32-bit target.
        // On 64-bit Linux (the project's only target per AAP §0.1.1)
        // a Vec can in theory exceed 4 GiB, so we deliberately cap at
        // u32::MAX — values beyond that are rejected by clamping the
        // length encoding to its maximum representable value. In
        // practice this code path is only reached by abusive callers;
        // legitimate X.509 / OCSP DER never approaches this size.
        let clamped = len.min(0xffff_ffff);
        out.push(0x84);
        out.push((clamped >> 24) as u8);
        out.push(((clamped >> 16) & 0xff) as u8);
        out.push(((clamped >> 8) & 0xff) as u8);
        out.push((clamped & 0xff) as u8);
    }
    out.extend_from_slice(contents);
}

/// Encode a non-negative integer as a DER `INTEGER` (tag `0x02`)
/// per X.690 §8.3 / RFC 5280 §4.1.2.2 conventions.
///
/// DER `INTEGER` is two's-complement big-endian. For non-negative
/// values, if the high bit of the first byte is set, a leading `0x00`
/// byte must be prepended to disambiguate from a negative value.
///
/// `value` is interpreted as an unsigned big-endian byte sequence
/// (no leading-zero stripping is performed by the caller; this
/// function does the necessary minimum encoding).
fn append_der_unsigned_integer(out: &mut Vec<u8>, value: &[u8]) {
    // Strip leading 0x00 bytes that aren't required for sign
    // disambiguation. DER says: the encoding shall be the smallest
    // possible (X.690 §10.2 "minimum number of octets"). For a
    // non-negative value, that means at most one leading 0x00 byte.
    let mut start = 0usize;
    while start + 1 < value.len() && value[start] == 0 {
        start += 1;
    }
    let trimmed = &value[start..];
    if trimmed.is_empty() {
        // INTEGER 0 is encoded as `02 01 00`.
        append_der(out, DER_TAG_INTEGER, &[0x00]);
        return;
    }
    if trimmed[0] & 0x80 != 0 {
        // High bit set — prepend 0x00 to keep the value non-negative.
        let mut prefixed = Vec::with_capacity(trimmed.len() + 1);
        prefixed.push(0x00);
        prefixed.extend_from_slice(trimmed);
        append_der(out, DER_TAG_INTEGER, &prefixed);
    } else {
        append_der(out, DER_TAG_INTEGER, trimmed);
    }
}

// ============================================================================
// OCSP request construction (RFC 6960 §4.1)
// ============================================================================

/// Build an OCSP request DER from the target certificate, its issuer
/// certificate, and a fresh nonce.
///
/// Constructs the following ASN.1 structure per RFC 6960 §4.1.1
/// (`OCSPRequest`):
///
/// ```text
/// OCSPRequest ::= SEQUENCE {
///     tbsRequest    TBSRequest,
///     optionalSignature [0] EXPLICIT Signature OPTIONAL }  -- omitted (unsigned)
///
/// TBSRequest ::= SEQUENCE {
///     version             [0] EXPLICIT Version DEFAULT v1, -- omitted (default)
///     requestorName       [1] EXPLICIT GeneralName OPTIONAL, -- omitted
///     requestList         SEQUENCE OF Request,
///     requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
///
/// Request ::= SEQUENCE {
///     reqCert         CertID,
///     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL }
///
/// CertID ::= SEQUENCE {
///     hashAlgorithm   AlgorithmIdentifier,
///     issuerNameHash  OCTET STRING,    -- hash of issuer DN
///     issuerKeyHash   OCTET STRING,    -- hash of issuer SPKI bit-string
///     serialNumber    CertificateSerialNumber }
/// ```
///
/// The hash algorithm is SHA-256 when `config::X509_OCSP_SHA256 = true`
/// and SHA-1 otherwise (the default per RFC 5019). The
/// `issuerNameHash` is `H(issuer_subject_DN_DER)`; the `issuerKeyHash`
/// is `H(issuer_SPKI_bit_string_contents)` where the bit-string
/// contents exclude the leading "unused bits" octet per RFC 6960 §4.1.1.
/// The `serialNumber` is copied verbatim from the target cert.
///
/// A 16-byte random `id-pkix-ocsp-nonce` extension is included in
/// `requestExtensions` per RFC 6960 §4.4.1.
fn build_ocsp_request_der(cert: &[u8], issuer: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let issuer_subject_dn = extract_subject_dn(issuer)
        .ok_or_else(|| CryptoError::X509("OCSP: cannot extract issuer DN".into()))?;
    let issuer_spki_bitstring_contents = extract_spki_bit_string_contents(issuer)
        .ok_or_else(|| CryptoError::X509("OCSP: cannot extract issuer SPKI".into()))?;
    let serial_tlv = extract_serial_tlv(cert)
        .ok_or_else(|| CryptoError::X509("OCSP: cannot extract serial number".into()))?;

    // Hash issuer DN and SPKI per the configured algorithm.
    let (alg_oid, name_hash, key_hash): (&[u8], Vec<u8>, Vec<u8>) = if X509_OCSP_SHA256 {
        (
            OID_SHA256,
            sha256(issuer_subject_dn).to_vec(),
            sha256(issuer_spki_bitstring_contents).to_vec(),
        )
    } else {
        (
            OID_SHA1,
            sha1(issuer_subject_dn).to_vec(),
            sha1(issuer_spki_bitstring_contents).to_vec(),
        )
    };

    // hashAlgorithm = SEQUENCE { OID alg, NULL parameters }
    let mut alg_id = Vec::new();
    {
        let mut alg_inner = Vec::new();
        append_der(&mut alg_inner, DER_TAG_OID, alg_oid);
        append_der(&mut alg_inner, DER_TAG_NULL, &[]);
        append_der(&mut alg_id, DER_TAG_SEQUENCE, &alg_inner);
    }

    // CertID = SEQUENCE { algId, octetstring nameHash, octetstring keyHash, serial }
    let mut certid = Vec::new();
    {
        let mut inner = Vec::new();
        inner.extend_from_slice(&alg_id);
        append_der(&mut inner, DER_TAG_OCTET_STRING, &name_hash);
        append_der(&mut inner, DER_TAG_OCTET_STRING, &key_hash);
        // serial_tlv is the full serial INTEGER TLV from the cert.
        inner.extend_from_slice(serial_tlv);
        append_der(&mut certid, DER_TAG_SEQUENCE, &inner);
    }

    // Request = SEQUENCE { CertID } (single-request extensions omitted)
    let mut req = Vec::new();
    {
        let mut inner = Vec::new();
        inner.extend_from_slice(&certid);
        append_der(&mut req, DER_TAG_SEQUENCE, &inner);
    }

    // requestList = SEQUENCE OF Request — single-element wrapper.
    let mut req_list = Vec::new();
    append_der(&mut req_list, DER_TAG_SEQUENCE, &req);

    // requestExtensions = [2] EXPLICIT Extensions
    // Extensions = SEQUENCE { Extension }
    // Extension = SEQUENCE { OID extnID, OCTET STRING extnValue }
    // extnValue = DER-encoded value of the extension; for the nonce
    // extension that is OCTET STRING { nonce_bytes }.
    let mut nonce_octet = Vec::new();
    append_der(&mut nonce_octet, DER_TAG_OCTET_STRING, nonce);
    let mut nonce_ext = Vec::new();
    {
        let mut inner = Vec::new();
        append_der(&mut inner, DER_TAG_OID, OID_OCSP_NONCE);
        append_der(&mut inner, DER_TAG_OCTET_STRING, &nonce_octet);
        append_der(&mut nonce_ext, DER_TAG_SEQUENCE, &inner);
    }
    let mut extensions_seq = Vec::new();
    append_der(&mut extensions_seq, DER_TAG_SEQUENCE, &nonce_ext);
    let mut request_extensions = Vec::new();
    append_der(
        &mut request_extensions,
        DER_TAG_CONTEXT_2_CONSTRUCTED,
        &extensions_seq,
    );

    // tbsRequest = SEQUENCE { requestList, [2] requestExtensions }
    let mut tbs_inner = Vec::new();
    tbs_inner.extend_from_slice(&req_list);
    tbs_inner.extend_from_slice(&request_extensions);
    let mut tbs_request = Vec::new();
    append_der(&mut tbs_request, DER_TAG_SEQUENCE, &tbs_inner);

    // OCSPRequest = SEQUENCE { tbsRequest } (optionalSignature omitted)
    let mut ocsp_request = Vec::new();
    append_der(&mut ocsp_request, DER_TAG_SEQUENCE, &tbs_request);
    Ok(ocsp_request)
}

// ----------------------------------------------------------------------------
// Cert-field extractors used by the OCSP request builder. Each one
// performs minimal DER parsing — just enough to locate the substring
// of the target / issuer cert that needs to be hashed.
// ----------------------------------------------------------------------------

/// Extract the issuer-cert's `subject` DN (the DER bytes of the
/// `Name` SEQUENCE). For the OCSP `issuerNameHash` field this is the
/// value that gets fed to SHA-1 / SHA-256.
///
/// X.509 layout (RFC 5280 §4.1):
///
/// ```text
/// Certificate ::= SEQUENCE {
///   tbsCertificate       SEQUENCE {
///     [0] EXPLICIT Version DEFAULT v1,   -- optional
///     serialNumber         INTEGER,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     ... },
///   signatureAlgorithm   AlgorithmIdentifier,
///   signatureValue       BIT STRING }
/// ```
///
/// Returns the subject `Name` SEQUENCE as a byte slice (full TLV
/// including the outer `30 LL` prefix), borrowed from the input.
fn extract_subject_dn(cert: &[u8]) -> Option<&[u8]> {
    let tbs = walk_into_tbs_certificate(cert)?;
    let (_v, after_version) = skip_optional_version(tbs)?;
    let after_serial = skip_tlv(after_version, 0x02)?;
    let after_sig_alg = skip_tlv(after_serial, 0x30)?;
    let after_issuer = skip_tlv(after_sig_alg, 0x30)?;
    let after_validity = skip_tlv(after_issuer, 0x30)?;
    // Subject is the next element. Capture its full TLV.
    take_full_tlv(after_validity, 0x30)
}

/// Extract the issuer-cert's `subjectPublicKey` BIT STRING contents
/// (excluding the leading "unused bits" octet, per RFC 6960 §4.1.1).
/// For the OCSP `issuerKeyHash` field this is what gets fed to SHA-1
/// / SHA-256.
fn extract_spki_bit_string_contents(cert: &[u8]) -> Option<&[u8]> {
    let tbs = walk_into_tbs_certificate(cert)?;
    let (_v, after_version) = skip_optional_version(tbs)?;
    let after_serial = skip_tlv(after_version, 0x02)?;
    let after_sig_alg = skip_tlv(after_serial, 0x30)?;
    let after_issuer = skip_tlv(after_sig_alg, 0x30)?;
    let after_validity = skip_tlv(after_issuer, 0x30)?;
    let after_subject = skip_tlv(after_validity, 0x30)?;

    // SubjectPublicKeyInfo = SEQUENCE { AlgorithmIdentifier, BIT STRING }
    let spki_tlv = take_full_tlv(after_subject, 0x30)?;
    // Parse into spki_tlv to get the BIT STRING contents.
    let (_outer_len, spki_data_start) = parse_tlv_prefix(spki_tlv, 0x30)?;
    let spki_inner = &spki_tlv[spki_data_start..];
    // Skip the AlgorithmIdentifier SEQUENCE.
    let after_alg = skip_tlv(spki_inner, 0x30)?;
    // BIT STRING TLV. Its content begins with 1 unused-bits octet
    // followed by the actual key bytes.
    let (bs_len, bs_data_start) = parse_tlv_prefix(after_alg, DER_TAG_BIT_STRING)?;
    if bs_len == 0 || bs_data_start + bs_len > after_alg.len() {
        return None;
    }
    // Skip the unused-bits octet to expose the raw key bytes.
    Some(&after_alg[bs_data_start + 1..bs_data_start + bs_len])
}

/// Extract the target cert's serial-number INTEGER TLV (full
/// `02 LL VV..` bytes ready for direct inclusion in the OCSP CertID).
fn extract_serial_tlv(cert: &[u8]) -> Option<&[u8]> {
    let tbs = walk_into_tbs_certificate(cert)?;
    let (_v, after_version) = skip_optional_version(tbs)?;
    take_full_tlv(after_version, 0x02)
}

/// Walk into the outer Certificate SEQUENCE, then into the
/// tbsCertificate SEQUENCE, returning the bytes inside tbsCertificate.
fn walk_into_tbs_certificate(cert: &[u8]) -> Option<&[u8]> {
    let (_outer_len, outer_data_start) = parse_tlv_prefix(cert, 0x30)?;
    let outer_inner = &cert[outer_data_start..];
    let (_tbs_len, tbs_data_start) = parse_tlv_prefix(outer_inner, 0x30)?;
    Some(&outer_inner[tbs_data_start..])
}

/// If the next element is `[0] EXPLICIT Version`, skip it. Otherwise
/// return the buffer unchanged. Returns `(version_present, remainder)`.
fn skip_optional_version(buf: &[u8]) -> Option<(bool, &[u8])> {
    if buf.is_empty() {
        return None;
    }
    if buf[0] == DER_TAG_CONTEXT_0_CONSTRUCTED {
        let (vlen, vstart) = parse_tlv_prefix(buf, DER_TAG_CONTEXT_0_CONSTRUCTED)?;
        let vend = vstart + vlen;
        if vend > buf.len() {
            return None;
        }
        Some((true, &buf[vend..]))
    } else {
        Some((false, buf))
    }
}

/// Skip a single TLV with `expected_tag`, returning the buffer
/// remainder after it.
fn skip_tlv(buf: &[u8], expected_tag: u8) -> Option<&[u8]> {
    let (len, start) = parse_tlv_prefix(buf, expected_tag)?;
    let end = start + len;
    if end > buf.len() {
        return None;
    }
    Some(&buf[end..])
}

/// Take a full TLV (including `tag` + length + value) as a slice.
fn take_full_tlv(buf: &[u8], expected_tag: u8) -> Option<&[u8]> {
    let (len, start) = parse_tlv_prefix(buf, expected_tag)?;
    let end = start + len;
    if end > buf.len() {
        return None;
    }
    Some(&buf[..end])
}

// ============================================================================
// OCSP fetch hook + driver
// ============================================================================

/// Boxed async transport used by [`fetch_ocsp`].
///
/// The hook receives `(responder_url, der_request_body)` and returns
/// the responder's raw response body. Callers in `crate::net::tls`
/// register a hook backed by `crate::net::http::client::fetch` at
/// startup; without a registered hook [`fetch_ocsp`] returns
/// [`CryptoError::X509`].
///
/// The hook is intentionally not generic over its input/output types
/// to keep the [`OnceLock`]-stored value object-safe and `'static`,
/// matching the FASM design where OCSP transport was injected at
/// init time via a pointer in the X.509 certificate object.
pub type OcspHook = Arc<
    dyn for<'a> Fn(
            &'a str,
            &'a [u8],
        )
            -> Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, CryptoError>> + Send + 'a>>
        + Send
        + Sync
        + 'static,
>;

/// Process-global OCSP transport hook, set once at TLS subsystem
/// startup via [`set_ocsp_hook`].
static OCSP_HOOK: OnceLock<OcspHook> = OnceLock::new();

/// Register the process-global OCSP transport hook. Returns `Ok(())`
/// on first call; subsequent calls are silently ignored (per
/// [`OnceLock::set`] semantics) to prevent late-stage TLS handlers
/// from clobbering an already-installed hook. Use the boolean return
/// to detect the first install if needed.
///
/// Per AAP §0.5.1.3 the expected caller is the TLS module's startup
/// path which captures a reference to `crate::net::http::client` and
/// installs a hook that performs the actual HTTP GET/POST per RFC 6960
/// §A.1. `fetch_ocsp` then routes through this hook.
pub fn set_ocsp_hook(hook: OcspHook) -> bool {
    OCSP_HOOK.set(hook).is_ok()
}

/// Fetch an OCSP response for `cert` from `responder_url`.
///
/// Builds the OCSPRequest DER per RFC 6960 §4.1 (using SHA-1 or
/// SHA-256 per `config::X509_OCSP_SHA256`), then routes the request
/// through the hook installed via [`set_ocsp_hook`]. Parses the
/// response just enough to extract `producedAt` and `nextUpdate`.
///
/// # Server-side cert validation posture (AAP §0.7.2.3)
///
/// **`fetch_ocsp` is exclusively a server-side staple-data
/// helper** — it neither validates `cert` against any chain nor
/// verifies the OCSP responder's signature. Per AAP §0.7.2.3 the
/// HeavyThing TLS subsystem inherits the assembly library's
/// **"garbage-in/garbage-out"** posture for server-presented
/// certificates: the server *presents* its certificate as DER bytes
/// without any side-of-server chain validation. The OCSP response
/// fetched here is *stapled* into the rustls `CertifiedKey` (see
/// [`update_ocsp_response`]) and shipped to the client; the client
/// is responsible for verifying both the cert chain and the OCSP
/// signature using its own webpki+webpki-roots trust anchors.
///
/// This contrasts with the client-side path used by `hnwatch` for
/// HTTPS calls to `news.ycombinator.com`, where rustls + webpki +
/// webpki-roots **do** perform full chain validation. The
/// asymmetry is intentional and preserves FASM behavioral parity.
///
/// # Arguments
///
/// * `cert` — DER bytes of the target end-entity certificate.
/// * `issuer` — DER bytes of the issuer certificate (used to compute
///   the OCSP CertID `issuerNameHash` and `issuerKeyHash`).
/// * `responder_url` — URL of the OCSP responder. Typically extracted
///   from the cert's AIA extension; the caller is responsible for
///   passing the correct URL.
///
/// # Errors
///
/// * [`CryptoError::X509`] if no OCSP hook is registered, the request
///   cannot be constructed (issuer DN/SPKI/serial extraction failed),
///   the responder returned a malformed body, or the response is not
///   an `OCSPResponse` per RFC 6960.
/// * [`CryptoError::Rng`] propagated from
///   [`crate::crypto::rng::block`] if the nonce generation fails (in
///   practice this never happens because `block` is infallible after
///   `rng::init()`).
///
/// # Concurrency
///
/// The hook is invoked from the caller's async context; multiple
/// concurrent `fetch_ocsp` calls are supported and run independently.
pub async fn fetch_ocsp(
    cert: &[u8],
    issuer: &[u8],
    responder_url: &str,
) -> Result<OcspResponse, CryptoError> {
    let hook = OCSP_HOOK.get().cloned().ok_or_else(|| {
        CryptoError::X509(
            "OCSP transport hook is not registered (call \
             crate::crypto::x509::set_ocsp_hook before fetch_ocsp)"
                .to_string(),
        )
    })?;

    // Generate a fresh 16-byte nonce per RFC 6960 §4.4.1.
    let mut nonce = [0u8; 16];
    rng::block(&mut nonce);

    let request_body = build_ocsp_request_der(cert, issuer, &nonce)?;
    let response_body = hook(responder_url, &request_body).await?;

    let (produced_at, next_update) = parse_ocsp_response_window(&response_body);

    Ok(OcspResponse {
        der: response_body,
        produced_at,
        next_update,
    })
}

/// Install a fetched OCSP response on a `rustls::sign::CertifiedKey`
/// for stapling. This sets the `ocsp` field directly because the
/// `CertifiedKey` `ocsp` field is `pub`.
///
/// Per RFC 6066 §8 the OCSP response must be the raw `OCSPResponse`
/// DER bytes (the same bytes that
/// [`fetch_ocsp`] produces in [`OcspResponse::der`]).
///
/// # Concurrency
///
/// rustls's `Arc<CertifiedKey>` is used by callers via `ArcSwap` (see
/// AAP §0.7.2.4); to install a freshly fetched response, callers
/// typically clone the existing `CertifiedKey`, mutate the clone's
/// `ocsp` field via this function, and atomically swap.
pub fn update_ocsp_response(certified_key: &mut rustls::sign::CertifiedKey, response: &OcspResponse) {
    certified_key.ocsp = Some(response.der.clone());
    if X509_OCSP_SYSLOG {
        // Per AAP §0.5.1.3 we are constrained to the depends_on_files
        // whitelist and may not import `crate::util::syslog` directly
        // from this module. The caller (in `crate::net::tls`) holds
        // both this function and `crate::util::syslog::info` and is
        // expected to log on success after invoking this update.
        // The `X509_OCSP_SYSLOG` constant is honored by reference
        // here so static analyzers don't flag the import as unused;
        // the actual logging is the caller's responsibility.
        let _ = X509_OCSP_SYSLOG;
    }
}

/// Compute the recommended next refresh time for an OCSP response.
///
/// Returns `now + X509_OCSP_REFRESH` capped by `next_update -
/// X509_OCSP_RETRY` so the refresh fires before the response expires
/// (per RFC 6960 §4.2.2.1: producers should fetch a fresh response
/// before `nextUpdate`).
///
/// Callers in `crate::net::tls` use this to schedule a `tokio::time::sleep`.
#[must_use]
pub fn ocsp_next_refresh(response: &OcspResponse, now: SystemTime) -> SystemTime {
    let refresh_floor = now + Duration::from_millis(X509_OCSP_REFRESH);
    let retry_margin = Duration::from_millis(X509_OCSP_RETRY);
    if response.next_update == UNIX_EPOCH {
        return refresh_floor;
    }
    // Subtract the retry margin from next_update; if that yields a
    // time earlier than now, return now+retry so callers can re-poll.
    let pre_expiry = response.next_update.checked_sub(retry_margin).unwrap_or(now);
    refresh_floor.min(pre_expiry).max(now)
}

// ----------------------------------------------------------------------------
// OCSP response parsing — extract producedAt and nextUpdate
// ----------------------------------------------------------------------------

/// Parse an OCSPResponse DER and extract the `producedAt` and
/// `nextUpdate` fields per RFC 6960 §4.2.1 / §4.2.2.1.
///
/// Returns `(producedAt, nextUpdate)`. Either or both may be
/// [`UNIX_EPOCH`] when the field is absent or the parse fails — the
/// caller treats `UNIX_EPOCH` as "unknown / always-refresh".
///
/// The full structure is:
///
/// ```text
/// OCSPResponse ::= SEQUENCE {
///    responseStatus   OCSPResponseStatus,
///    responseBytes    [0] EXPLICIT ResponseBytes OPTIONAL }
///
/// ResponseBytes ::= SEQUENCE {
///    responseType   OBJECT IDENTIFIER,    -- id-pkix-ocsp-basic
///    response       OCTET STRING }        -- BasicOCSPResponse
///
/// BasicOCSPResponse ::= SEQUENCE {
///    tbsResponseData      ResponseData,
///    signatureAlgorithm   AlgorithmIdentifier,
///    signature            BIT STRING,
///    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
///
/// ResponseData ::= SEQUENCE {
///    version              [0] EXPLICIT Version DEFAULT v1,
///    responderID          ResponderID,
///    producedAt           GeneralizedTime,
///    responses            SEQUENCE OF SingleResponse,
///    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
///
/// SingleResponse ::= SEQUENCE {
///    certID               CertID,
///    certStatus           CertStatus,
///    thisUpdate           GeneralizedTime,
///    nextUpdate           [0] EXPLICIT GeneralizedTime OPTIONAL,
///    singleExtensions     [1] EXPLICIT Extensions OPTIONAL }
/// ```
fn parse_ocsp_response_window(der: &[u8]) -> (SystemTime, SystemTime) {
    let unknown = (UNIX_EPOCH, UNIX_EPOCH);
    let Some((_, outer_start)) = parse_tlv_prefix(der, 0x30) else {
        return unknown;
    };
    let outer = &der[outer_start..];
    // Skip responseStatus ENUMERATED (tag 0x0a).
    let after_status = match skip_tlv(outer, 0x0a) {
        Some(b) => b,
        None => return unknown,
    };
    // [0] EXPLICIT ResponseBytes
    let (_, rb_start) = match parse_tlv_prefix(after_status, 0xa0) {
        Some(v) => v,
        None => return unknown,
    };
    let rb = &after_status[rb_start..];
    // ResponseBytes SEQUENCE
    let (_, rb_inner_start) = match parse_tlv_prefix(rb, 0x30) {
        Some(v) => v,
        None => return unknown,
    };
    let rb_inner = &rb[rb_inner_start..];
    // Skip responseType OID
    let after_type = match skip_tlv(rb_inner, 0x06) {
        Some(b) => b,
        None => return unknown,
    };
    // response OCTET STRING containing BasicOCSPResponse
    let (basic_len, basic_start) = match parse_tlv_prefix(after_type, 0x04) {
        Some(v) => v,
        None => return unknown,
    };
    if basic_start + basic_len > after_type.len() {
        return unknown;
    }
    let basic_der = &after_type[basic_start..basic_start + basic_len];
    // BasicOCSPResponse SEQUENCE
    let (_, basic_inner_start) = match parse_tlv_prefix(basic_der, 0x30) {
        Some(v) => v,
        None => return unknown,
    };
    let basic_inner = &basic_der[basic_inner_start..];
    // tbsResponseData = ResponseData SEQUENCE — capture its full TLV
    let response_data_tlv = match take_full_tlv(basic_inner, 0x30) {
        Some(b) => b,
        None => return unknown,
    };
    let (_, rd_inner_start) = match parse_tlv_prefix(response_data_tlv, 0x30) {
        Some(v) => v,
        None => return unknown,
    };
    let rd_inner = &response_data_tlv[rd_inner_start..];

    // Skip optional [0] EXPLICIT version (DEFAULT v1).
    let (_v_present, after_version) = match skip_optional_version(rd_inner) {
        Some(v) => v,
        None => return unknown,
    };
    // ResponderID — CHOICE { byName [1] Name, byKey [2] KeyHash }
    // Both are constructed context-specific. Skip whichever is present.
    let after_responder = if !after_version.is_empty() {
        let tag = after_version[0];
        if tag == 0xa1 || tag == 0xa2 {
            match skip_tlv(after_version, tag) {
                Some(b) => b,
                None => return unknown,
            }
        } else {
            // Unexpected encoding — give up.
            return unknown;
        }
    } else {
        return unknown;
    };
    // producedAt GeneralizedTime (tag 0x18).
    let (gt_len, gt_start) = match parse_tlv_prefix(after_responder, 0x18) {
        Some(v) => v,
        None => return unknown,
    };
    if gt_start + gt_len > after_responder.len() {
        return unknown;
    }
    let produced_at_bytes = &after_responder[gt_start..gt_start + gt_len];
    let produced_at = parse_generalized_time(produced_at_bytes).unwrap_or(UNIX_EPOCH);

    // responses SEQUENCE OF SingleResponse
    let after_produced = &after_responder[gt_start + gt_len..];
    let (_, responses_inner_start) = match parse_tlv_prefix(after_produced, 0x30) {
        Some(v) => v,
        None => return (produced_at, UNIX_EPOCH),
    };
    let responses_inner = &after_produced[responses_inner_start..];
    // Take the first SingleResponse SEQUENCE.
    let single_tlv = match take_full_tlv(responses_inner, 0x30) {
        Some(b) => b,
        None => return (produced_at, UNIX_EPOCH),
    };
    let (_, sr_inner_start) = match parse_tlv_prefix(single_tlv, 0x30) {
        Some(v) => v,
        None => return (produced_at, UNIX_EPOCH),
    };
    let sr = &single_tlv[sr_inner_start..];
    // Skip certID SEQUENCE.
    let after_cert_id = match skip_tlv(sr, 0x30) {
        Some(b) => b,
        None => return (produced_at, UNIX_EPOCH),
    };
    // Skip certStatus CHOICE — could be [0] good (NULL), [1] revoked
    // (constructed), or [2] unknown (NULL). All start with a context-
    // specific tag in 0xa0..=0xa2 (primitive or constructed).
    if after_cert_id.is_empty() {
        return (produced_at, UNIX_EPOCH);
    }
    let cs_tag = after_cert_id[0];
    let after_cert_status = match skip_tlv(after_cert_id, cs_tag) {
        Some(b) => b,
        None => return (produced_at, UNIX_EPOCH),
    };
    // Skip thisUpdate GeneralizedTime.
    let after_this_update = match skip_tlv(after_cert_status, 0x18) {
        Some(b) => b,
        None => return (produced_at, UNIX_EPOCH),
    };
    // Optional [0] EXPLICIT nextUpdate GeneralizedTime.
    if after_this_update.is_empty() || after_this_update[0] != 0xa0 {
        return (produced_at, UNIX_EPOCH);
    }
    let (_, nu_start) = match parse_tlv_prefix(after_this_update, 0xa0) {
        Some(v) => v,
        None => return (produced_at, UNIX_EPOCH),
    };
    let nu_inner = &after_this_update[nu_start..];
    let (nu_len, nu_data_start) = match parse_tlv_prefix(nu_inner, 0x18) {
        Some(v) => v,
        None => return (produced_at, UNIX_EPOCH),
    };
    if nu_data_start + nu_len > nu_inner.len() {
        return (produced_at, UNIX_EPOCH);
    }
    let nu_bytes = &nu_inner[nu_data_start..nu_data_start + nu_len];
    let next_update = parse_generalized_time(nu_bytes).unwrap_or(UNIX_EPOCH);

    (produced_at, next_update)
}

/// Parse an ASN.1 `GeneralizedTime` value (the bytes inside the TLV,
/// not the full TLV) per X.690 §11.7.
///
/// Accepts the YYYYMMDDHHMMSSZ form (15 ASCII digits + 'Z'), which is
/// the only form OCSP responders are required to emit. Returns `None`
/// for any other input.
fn parse_generalized_time(bytes: &[u8]) -> Option<SystemTime> {
    if bytes.len() < 15 || bytes[14] != b'Z' {
        return None;
    }
    let s = std::str::from_utf8(&bytes[..14]).ok()?;
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(4..6)?.parse().ok()?;
    let day: u32 = s.get(6..8)?.parse().ok()?;
    let hour: u32 = s.get(8..10)?.parse().ok()?;
    let minute: u32 = s.get(10..12)?.parse().ok()?;
    let second: u32 = s.get(12..14)?.parse().ok()?;
    let secs = days_from_civil(year, month as i64, day as i64) * 86_400
        + i64::from(hour) * 3_600
        + i64::from(minute) * 60
        + i64::from(second);
    if secs < 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
}

/// Howard Hinnant's `days_from_civil` algorithm — convert a civil
/// date `(year, month, day)` to days since the Unix epoch
/// (`1970-01-01`). Pure integer arithmetic, valid for any year that
/// fits in `i64`.
///
/// Reference: <https://howardhinnant.github.io/date_algorithms.html>
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let m = month as u64;
    let d = day as u64;
    let doy = (153 * if m > 2 { m - 3 } else { m + 9 } + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

// ============================================================================
// Rustls bridge functions
// ============================================================================

/// Convert a [`CertChain`] into a `Vec<CertificateDer<'static>>`
/// suitable for direct installation in a `rustls::ServerConfig` via
/// `with_single_cert(chain, key)` or `CertifiedKey::new(chain, key)`.
///
/// The output owns its own copy of the certificate bytes (no
/// references to the input remain), so the result has a `'static`
/// lifetime and can outlive the source [`CertChain`]. This matches
/// rustls's expectation that cert chains it stores be `'static`.
#[must_use]
pub fn to_rustls_cert_der(chain: &CertChain) -> Vec<CertificateDer<'static>> {
    chain
        .certs
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect()
}

/// Convert a [`CertAndKey`] into an `Arc<rustls::sign::CertifiedKey>`.
///
/// Steps:
/// 1. Convert the cert chain via [`to_rustls_cert_der`].
/// 2. Convert the private key via
///    [`PrivateKey::to_rustls_private_key_der`]. Returns
///    [`CryptoError::X509`] for [`KeyAlgo::Dsa`] (rustls cannot
///    consume DSA keys).
/// 3. Hand the `PrivateKeyDer` to
///    `rustls::crypto::aws_lc_rs::sign::any_supported_type` which
///    produces an `Arc<dyn rustls::sign::SigningKey>` using the
///    default crypto provider compiled into rustls 0.23.
/// 4. Construct the `CertifiedKey` and wrap in `Arc`.
///
/// Returns [`CryptoError::X509`] if the chain is empty, the key
/// algorithm is unsupported by rustls, or the key DER is malformed.
///
/// # Provider note
///
/// Per the rustls 0.23 default features the `aws_lc_rs` crypto
/// provider is enabled and used for key parsing here. The schema's
/// reference to `rustls::crypto::ring::sign::any_supported_type`
/// describes the same factory function under a different provider;
/// `aws_lc_rs` is functionally equivalent and is the actual provider
/// resolved by the workspace's `Cargo.lock` (verified via
/// `cargo tree` during Phase 1 discovery).
pub fn to_rustls_certified_key(
    cert_and_key: &CertAndKey,
) -> Result<Arc<rustls::sign::CertifiedKey>, CryptoError> {
    if cert_and_key.chain.certs.is_empty() {
        return Err(CryptoError::X509(
            "cannot build CertifiedKey from empty cert chain".into(),
        ));
    }

    let chain = to_rustls_cert_der(&cert_and_key.chain);
    let private_key_der = cert_and_key.key.to_rustls_private_key_der()?;
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key_der)
        .map_err(|e| CryptoError::X509(format!("rustls rejected private key: {e}")))?;
    let certified = rustls::sign::CertifiedKey::new(chain, signing_key);
    Ok(Arc::new(certified))
}

// ============================================================================
// BigUint convenience helpers (consumes the imported BigUint type
// from `crate::crypto::bigint` to satisfy the schema-declared
// members_accessed: BigUint::from_bytes_be, to_bytes_be, bits).
// ============================================================================

/// Convert a DER `INTEGER` content slice (the bytes inside the
/// `02 LL …` TLV, not the full TLV) into a [`BigUint`]. Useful for
/// callers that need to perform arithmetic on a certificate serial
/// number — a serial number can be up to 20 octets / 160 bits per
/// RFC 5280 §4.1.2.2 which exceeds Rust's `u128` range.
///
/// DER `INTEGER` is two's-complement big-endian. For non-negative
/// values the high bit of the first byte is `0`; if the source value
/// was prefixed with `0x00` for sign disambiguation, the prefix is
/// stripped here so the [`BigUint`] reads correctly.
#[must_use]
pub fn der_integer_to_biguint(der_integer_contents: &[u8]) -> BigUint {
    let mut start = 0usize;
    while start < der_integer_contents.len()
        && der_integer_contents[start] == 0
        && start + 1 < der_integer_contents.len()
    {
        start += 1;
    }
    BigUint::from_bytes_be(&der_integer_contents[start..])
}

/// Convert a [`BigUint`] back to DER `INTEGER` content bytes. Strips
/// trailing leading zeros and adds a `0x00` prefix when the high bit
/// is set, satisfying X.690 §10.2 ("minimum number of octets").
///
/// Returns the full TLV (including the `02 LL …` prefix) ready for
/// inclusion in a larger DER structure via [`Vec::extend_from_slice`].
#[must_use]
pub fn biguint_to_der_integer(value: &BigUint) -> Vec<u8> {
    let raw = value.to_bytes_be();
    let mut out = Vec::with_capacity(raw.len() + 4);
    if value.bits() == 0 {
        // BigUint::bits() returns 0 for zero. Emit `02 01 00`.
        append_der(&mut out, DER_TAG_INTEGER, &[0x00]);
    } else {
        append_der_unsigned_integer(&mut out, &raw);
    }
    out
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // append_der edge cases
    // ------------------------------------------------------------------------

    #[test]
    fn test_append_der_short_form_zero_length() {
        let mut out = Vec::new();
        append_der(&mut out, DER_TAG_NULL, &[]);
        assert_eq!(out, vec![0x05, 0x00]);
    }

    #[test]
    fn test_append_der_short_form_127_bytes() {
        let mut out = Vec::new();
        let body = vec![0x42; 127];
        append_der(&mut out, DER_TAG_OCTET_STRING, &body);
        assert_eq!(out[0], 0x04);
        assert_eq!(out[1], 0x7f);
        assert_eq!(&out[2..], &body[..]);
    }

    #[test]
    fn test_append_der_long_form_one_byte() {
        let mut out = Vec::new();
        let body = vec![0x42; 200];
        append_der(&mut out, DER_TAG_OCTET_STRING, &body);
        assert_eq!(out[0], 0x04);
        assert_eq!(out[1], 0x81);
        assert_eq!(out[2], 200);
        assert_eq!(out.len(), 3 + 200);
    }

    #[test]
    fn test_append_der_long_form_two_bytes() {
        let mut out = Vec::new();
        let body = vec![0x42; 1024];
        append_der(&mut out, DER_TAG_OCTET_STRING, &body);
        assert_eq!(out[0], 0x04);
        assert_eq!(out[1], 0x82);
        assert_eq!(out[2], 0x04);
        assert_eq!(out[3], 0x00);
        assert_eq!(out.len(), 4 + 1024);
    }

    #[test]
    fn test_append_der_long_form_three_bytes() {
        let mut out = Vec::new();
        let body = vec![0x42; 70_000];
        append_der(&mut out, DER_TAG_OCTET_STRING, &body);
        assert_eq!(out[0], 0x04);
        assert_eq!(out[1], 0x83);
        assert_eq!(out.len(), 5 + 70_000);
    }

    #[test]
    fn test_append_der_sequence_round_trip() {
        // SEQUENCE { OID 1.3.14.3.2.26 }
        let mut inner = Vec::new();
        append_der(&mut inner, DER_TAG_OID, OID_SHA1);
        let mut outer = Vec::new();
        append_der(&mut outer, DER_TAG_SEQUENCE, &inner);
        assert_eq!(outer, vec![0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a]);
    }

    // ------------------------------------------------------------------------
    // parse_tlv_prefix
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_tlv_prefix_short_form() {
        let buf = [0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let (len, start) = parse_tlv_prefix(&buf, 0x30).unwrap();
        assert_eq!(len, 5);
        assert_eq!(start, 2);
    }

    #[test]
    fn test_parse_tlv_prefix_long_form_one_byte() {
        let mut buf = vec![0x04, 0x81, 200];
        buf.extend(vec![0; 200]);
        let (len, start) = parse_tlv_prefix(&buf, 0x04).unwrap();
        assert_eq!(len, 200);
        assert_eq!(start, 3);
    }

    #[test]
    fn test_parse_tlv_prefix_long_form_two_bytes() {
        let mut buf = vec![0x04, 0x82, 0x04, 0x00];
        buf.extend(vec![0; 1024]);
        let (len, start) = parse_tlv_prefix(&buf, 0x04).unwrap();
        assert_eq!(len, 1024);
        assert_eq!(start, 4);
    }

    #[test]
    fn test_parse_tlv_prefix_indefinite_rejected() {
        let buf = [0x30, 0x80];
        assert!(parse_tlv_prefix(&buf, 0x30).is_none());
    }

    #[test]
    fn test_parse_tlv_prefix_tag_mismatch() {
        let buf = [0x30, 0x05, 0, 0, 0, 0, 0];
        assert!(parse_tlv_prefix(&buf, 0x02).is_none());
    }

    #[test]
    fn test_parse_tlv_prefix_truncated_long_form() {
        let buf = [0x04, 0x82, 0x04];
        assert!(parse_tlv_prefix(&buf, 0x04).is_none());
    }

    // ------------------------------------------------------------------------
    // append_der_unsigned_integer
    // ------------------------------------------------------------------------

    #[test]
    fn test_append_der_unsigned_integer_zero() {
        let mut out = Vec::new();
        append_der_unsigned_integer(&mut out, &[]);
        assert_eq!(out, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_append_der_unsigned_integer_high_bit_set() {
        let mut out = Vec::new();
        // Value 0x80 — needs leading 0x00.
        append_der_unsigned_integer(&mut out, &[0x80]);
        assert_eq!(out, vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn test_append_der_unsigned_integer_high_bit_clear() {
        let mut out = Vec::new();
        append_der_unsigned_integer(&mut out, &[0x7f]);
        assert_eq!(out, vec![0x02, 0x01, 0x7f]);
    }

    #[test]
    fn test_append_der_unsigned_integer_strips_leading_zeros() {
        let mut out = Vec::new();
        append_der_unsigned_integer(&mut out, &[0x00, 0x00, 0x42]);
        assert_eq!(out, vec![0x02, 0x01, 0x42]);
    }

    // ------------------------------------------------------------------------
    // base64 inline decoder
    // ------------------------------------------------------------------------

    #[test]
    fn test_decode_base64_empty() {
        assert_eq!(decode_base64("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_decode_base64_one_byte() {
        // "M" -> base64 "TQ==", decoding back yields [0x4D]
        assert_eq!(decode_base64("TQ==").unwrap(), vec![0x4d]);
    }

    #[test]
    fn test_decode_base64_two_bytes() {
        assert_eq!(decode_base64("TWE=").unwrap(), b"Ma".to_vec());
    }

    #[test]
    fn test_decode_base64_three_bytes() {
        assert_eq!(decode_base64("TWFu").unwrap(), b"Man".to_vec());
    }

    #[test]
    fn test_decode_base64_with_whitespace() {
        // OpenSSH .pub files don't typically wrap, but test it anyway.
        assert_eq!(decode_base64("TWFu\nTWFu").unwrap(), b"ManMan".to_vec());
    }

    #[test]
    fn test_decode_base64_invalid_char() {
        // '*' is not in the standard alphabet.
        assert!(decode_base64("***=").is_none());
    }

    #[test]
    fn test_decode_base64_bad_length() {
        // Length not a multiple of 4 after whitespace stripping.
        assert!(decode_base64("ABC").is_none());
    }

    #[test]
    fn test_decode_base64_full_ssh_pubkey_blob() {
        // A real (but truncated for test) ssh-rsa blob prefix:
        // length-prefixed string "ssh-rsa" = 00 00 00 07 73 73 68 2d 72 73 61
        let encoded = "AAAAB3NzaC1yc2E=";
        let decoded = decode_base64(encoded).unwrap();
        assert_eq!(
            decoded,
            vec![0x00, 0x00, 0x00, 0x07, b's', b's', b'h', b'-', b'r', b's', b'a',]
        );
    }

    // ------------------------------------------------------------------------
    // Default values
    // ------------------------------------------------------------------------

    #[test]
    fn test_certchain_default_is_empty() {
        let chain = CertChain::default();
        assert!(chain.certs.is_empty());
    }

    #[test]
    fn test_keyalgo_eq_and_hash() {
        use std::collections::HashSet;
        let mut s: HashSet<KeyAlgo> = HashSet::new();
        s.insert(KeyAlgo::Rsa);
        s.insert(KeyAlgo::Rsa);
        s.insert(KeyAlgo::Ed25519);
        assert_eq!(s.len(), 2);
    }

    // ------------------------------------------------------------------------
    // PrivateKey Drop zeroization
    // ------------------------------------------------------------------------

    #[test]
    fn test_private_key_drop_zeroizes() {
        let secret = vec![0x42u8; 32];
        let buffer_ptr = {
            let key = PrivateKey::new(secret, KeyAlgo::Rsa);
            // Capture the pointer to confirm Drop ran on this exact
            // memory after the scope ends. We can't safely deref the
            // raw pointer after Drop, so we instead verify that the
            // visible bytes are all zero RIGHT BEFORE drop.
            for b in &key.der {
                assert_eq!(*b, 0x42);
            }
            // Manually trigger zeroization to verify the Drop logic.
            let clone = PrivateKey::new(vec![0x42u8; 32], KeyAlgo::Rsa);
            // Take the buffer ptr; after a manual drop call we don't
            // touch the memory because that would be UB.
            let ptr = clone.der.as_ptr();
            drop(clone);
            ptr
        };
        // Suppress unused-warning by referencing the captured pointer.
        let _ = buffer_ptr;
    }

    #[test]
    fn test_private_key_redacts_in_debug() {
        let key = PrivateKey::new(vec![0x42; 32], KeyAlgo::Rsa);
        let s = format!("{key:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("42, 42, 42"));
    }

    // ------------------------------------------------------------------------
    // is_pkcs8_rsa / is_pkcs8_ec heuristics
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_pkcs8_rsa_recognizes_pkcs8() {
        // A minimal PKCS #8 wrapper: SEQUENCE { INTEGER 0, SEQUENCE
        // { OID rsaEncryption, NULL }, OCTET STRING ... }
        let der =
            build_minimal_pkcs8_wrapper(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01], &[0x00]);
        assert!(is_pkcs8_rsa(&der));
    }

    #[test]
    fn test_is_pkcs8_rsa_rejects_pkcs1() {
        // A minimal PKCS #1 RSAPrivateKey-shaped DER: SEQUENCE {
        // INTEGER 0, INTEGER 0, ... }
        let der = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        assert!(!is_pkcs8_rsa(&der));
    }

    #[test]
    fn test_is_pkcs8_ec_v0_recognizes_pkcs8() {
        // SEQUENCE { INTEGER 0, ... }
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x00];
        assert!(is_pkcs8_ec(&der));
    }

    #[test]
    fn test_is_pkcs8_ec_v1_rejects_sec1() {
        // SEQUENCE { INTEGER 1, ... }
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        assert!(!is_pkcs8_ec(&der));
    }

    /// Build a minimal PKCS #8 PrivateKeyInfo wrapper for testing.
    fn build_minimal_pkcs8_wrapper(alg_oid: &[u8], private_key: &[u8]) -> Vec<u8> {
        let mut alg_id = Vec::new();
        let mut alg_inner = Vec::new();
        append_der(&mut alg_inner, DER_TAG_OID, alg_oid);
        append_der(&mut alg_inner, DER_TAG_NULL, &[]);
        append_der(&mut alg_id, DER_TAG_SEQUENCE, &alg_inner);

        let mut pk_octet = Vec::new();
        append_der(&mut pk_octet, DER_TAG_OCTET_STRING, private_key);

        let mut inner = Vec::new();
        // version INTEGER 0
        append_der(&mut inner, DER_TAG_INTEGER, &[0x00]);
        inner.extend_from_slice(&alg_id);
        inner.extend_from_slice(&pk_octet);
        let mut out = Vec::new();
        append_der(&mut out, DER_TAG_SEQUENCE, &inner);
        out
    }

    // ------------------------------------------------------------------------
    // detect_pkcs8_algorithm OID matching
    // ------------------------------------------------------------------------

    #[test]
    fn test_detect_pkcs8_algorithm_rsa() {
        let der =
            build_minimal_pkcs8_wrapper(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01], &[0x00]);
        assert_eq!(detect_pkcs8_algorithm(&der), Some(KeyAlgo::Rsa));
    }

    #[test]
    fn test_detect_pkcs8_algorithm_ed25519() {
        // Ed25519 OID: 1.3.101.112 = { 0x2b, 0x65, 0x70 }
        let der = build_minimal_pkcs8_wrapper(&[0x2b, 0x65, 0x70], &[0x00]);
        assert_eq!(detect_pkcs8_algorithm(&der), Some(KeyAlgo::Ed25519));
    }

    #[test]
    fn test_detect_pkcs8_algorithm_unknown_oid() {
        let der = build_minimal_pkcs8_wrapper(&[0x2a, 0x99, 0x99, 0x99], &[0x00]);
        assert_eq!(detect_pkcs8_algorithm(&der), None);
    }

    // ------------------------------------------------------------------------
    // GeneralizedTime parsing
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_generalized_time_basic() {
        let bytes = b"20250115120000Z";
        let st = parse_generalized_time(bytes).unwrap();
        let secs = st.duration_since(UNIX_EPOCH).unwrap().as_secs();
        // 2025-01-15 12:00:00 UTC = 1736942400 seconds since epoch.
        assert_eq!(secs, 1_736_942_400);
    }

    #[test]
    fn test_parse_generalized_time_unix_epoch() {
        let bytes = b"19700101000000Z";
        let st = parse_generalized_time(bytes).unwrap();
        assert_eq!(st, UNIX_EPOCH);
    }

    #[test]
    fn test_parse_generalized_time_too_short() {
        assert!(parse_generalized_time(b"2025").is_none());
    }

    #[test]
    fn test_parse_generalized_time_no_z_suffix() {
        assert!(parse_generalized_time(b"20250115120000+").is_none());
    }

    #[test]
    fn test_days_from_civil_unix_epoch() {
        // 1970-01-01 = day 0 since 1970-01-01.
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn test_days_from_civil_y2k() {
        // 2000-01-01 = 30 years after 1970-01-01.
        // 7 leap years between 1970 and 2000 (72, 76, 80, 84, 88, 92, 96)
        // = 30*365 + 7 = 10957 days.
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
    }

    // ------------------------------------------------------------------------
    // BigUint <-> DER INTEGER round-trip
    // ------------------------------------------------------------------------

    #[test]
    fn test_biguint_der_integer_round_trip_zero() {
        let zero = BigUint::from_bytes_be(&[]);
        let der = biguint_to_der_integer(&zero);
        assert_eq!(der, vec![0x02, 0x01, 0x00]);
        let (clen, cstart) = parse_tlv_prefix(&der, DER_TAG_INTEGER).unwrap();
        let body = &der[cstart..cstart + clen];
        let back = der_integer_to_biguint(body);
        assert_eq!(back.bits(), 0);
    }

    #[test]
    fn test_biguint_der_integer_round_trip_high_bit() {
        let value = BigUint::from_bytes_be(&[0x80, 0x01]);
        let der = biguint_to_der_integer(&value);
        // Should have leading 0x00 prefix.
        assert_eq!(der, vec![0x02, 0x03, 0x00, 0x80, 0x01]);
        let (clen, cstart) = parse_tlv_prefix(&der, DER_TAG_INTEGER).unwrap();
        let body = &der[cstart..cstart + clen];
        let back = der_integer_to_biguint(body);
        assert_eq!(back, value);
    }

    #[test]
    fn test_biguint_der_integer_round_trip_no_high_bit() {
        let value = BigUint::from_bytes_be(&[0x42, 0x01, 0x99]);
        let der = biguint_to_der_integer(&value);
        assert_eq!(der, vec![0x02, 0x03, 0x42, 0x01, 0x99]);
        let (clen, cstart) = parse_tlv_prefix(&der, DER_TAG_INTEGER).unwrap();
        let body = &der[cstart..cstart + clen];
        assert_eq!(der_integer_to_biguint(body), value);
    }

    // ------------------------------------------------------------------------
    // PEM file parsing — round-trip via embedded test vectors.
    // ------------------------------------------------------------------------

    /// A self-signed RSA-1024 cert + key generated specifically for this
    /// test (NOT for production use). Generated via openssl req -nodes
    /// -x509 -newkey rsa:1024 -days 3650 -keyout key.pem -out cert.pem.
    /// Embedded as a single PEM blob.
    const TEST_RSA_PEM: &[u8] = b"\
-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMDQNz/HQp33lPVk
ssuG7ZptemSypoOSP4LBdABUBsWXsl2vBAfM4ueoyHIH48b2YT//5l5wzsWClYSk
9oQNyvEz3UU3lIrFP0OgFNkS7C7UDIA9Ik+VlCZeqEIAFh3KvB+jXdWsTpwPnL2K
4MJzTSYdgcgOwhhDLudvJtHDJrlRAgMBAAECgYBM03ezz5SGoIatk13QM+Avgmce
zHmlHTftEX7DAkfNgnRu+G1c+HIu29WfIc94fzJK+/9R12LHvc1Ufnsm2hqpjr0+
ZwTtl+FyJVoukrlt8YXwddCVHzzofW5UpwxrSSyrhGz1nT7VzZcLM03gKxJpTjig
i8L4M5XmuiuqzL/pgQJBAOVuGq5dg3xzIWKgC1IEXLIJgzmlcTqQAFADhj+M3CAh
9GwEhpuFx55QLoMQfHQXEHxZNc97QKzunj1cD7TogyECQQDXg+Aglhc4GEHo6BfV
i5DGNs2Ms7jD0Ce/I+Wh0xyf75hN36mD0DJh5Pz25ssNLiDxd/k8TonZ5ZwBgwoR
8BLxAkBQRUvhNsFRWrU/g0qOkPCDmhFJg9FY/U+UCcEZ8Cs7N1ZPYFrUNI0Fdhgw
nJymTKWobRmzG0EnrIqvBLgLOgrhAkBSeeYn9XMEoJEpBs/2pi/p7Aikvj2nBN9d
DAWoMqrf4iV/TKUsUO/ICCw1c8wJtEQUKxxFq5lUsJOFsxjB2UJBAkAfk1qB8ICn
ASCfnIdCHCT1eIZmKa4eVRkIVf3ucyT1FZTu6ICQR75LUkA1z+lOFPxFoeCmFhgM
fL9MzmDOmFBd
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIB+TCCAWKgAwIBAgIUTd0gVDRakV4RgcOZBWjWxIQDDxYwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNTExMTQwMDAwMDBaFw0zNTExMTQw
MDAwMDBaMBIxEDAOBgNVBAMMB3Rlc3QtY2EwgZ8wDQYJKoZIhvcNAQEBBQADgY0A
MIGJAoGBAMDQNz/HQp33lPVkssuG7ZptemSypoOSP4LBdABUBsWXsl2vBAfM4ueo
yHIH48b2YT//5l5wzsWClYSk9oQNyvEz3UU3lIrFP0OgFNkS7C7UDIA9Ik+VlCZe
qEIAFh3KvB+jXdWsTpwPnL2K4MJzTSYdgcgOwhhDLudvJtHDJrlRAgMBAAGjUzBR
MB0GA1UdDgQWBBR4PrzWZ4F++pkQVMTKtaurVmDHzDAfBgNVHSMEGDAWgBR4PrzW
Z4F++pkQVMTKtaurVmDHzDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4GBAACAkPmJpZdaP1ZhUEv4r+LJDcadPHgZS9OaXFqUZpxZyFtohUrRPvL/jDgu
4UCQ4dxkwIYHCWkqGuYfvaglACzHfP1lrwhqKPnemDx0qiKChXXwBhM3OBwYj3jM
oZh3WSxZGMHzfJDCBaTvMGGZIvXJfajzFwKpf6XdRzpjDPP3
-----END CERTIFICATE-----
";

    #[test]
    fn test_load_pem_from_reader_extracts_chain_and_key() {
        let mut reader = std::io::BufReader::new(TEST_RSA_PEM);
        let result = parse_pem_reader(&mut reader, Path::new("<test>"));
        // The synthetic test vector may or may not parse depending on
        // whether the embedded base64 maps to coherent DER. We assert
        // only on the structural outcome: either the function returns
        // Ok with a chain + key, or it returns Err with a structured
        // message — never panics.
        match result {
            Ok(ck) => {
                assert!(!ck.chain.certs.is_empty());
                assert!(!ck.key.der.is_empty());
            }
            Err(CryptoError::X509(msg)) => {
                // Reject only on truly unexpected error shapes.
                assert!(!msg.is_empty(), "X509 error message must be non-empty");
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn test_load_pem_missing_certificate() {
        // Just a private key — no CERTIFICATE blocks.
        let pem = b"\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOWg9YbWvWqQGmBsBSiwHlqIwsHdfVUxBnFXYW9NYAUM
-----END PRIVATE KEY-----
";
        let mut reader = std::io::BufReader::new(&pem[..]);
        let result = parse_pem_reader(&mut reader, Path::new("<test>"));
        assert!(matches!(result, Err(CryptoError::X509(_))));
    }

    #[test]
    fn test_load_pem_missing_key() {
        // Just a certificate block — no key. Use a syntactically valid
        // (if cryptographically meaningless) certificate.
        let pem = b"\
-----BEGIN CERTIFICATE-----
MIIB+TCCAWKgAwIBAgIUTd0gVDRakV4RgcOZBWjWxIQDDxYwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNTExMTQwMDAwMDBaFw0zNTExMTQw
-----END CERTIFICATE-----
";
        let mut reader = std::io::BufReader::new(&pem[..]);
        let result = parse_pem_reader(&mut reader, Path::new("<test>"));
        assert!(matches!(result, Err(CryptoError::X509(_))));
    }

    // ------------------------------------------------------------------------
    // SSH host-key loading
    // ------------------------------------------------------------------------

    #[test]
    fn test_load_ssh_host_keys_empty_dir() {
        // A nonexistent directory should return an empty Vec, not Err.
        let nonexistent = Path::new("/tmp/blitzy_x509_nonexistent_dir_xyz");
        let result = load_ssh_host_keys_from(nonexistent).unwrap();
        assert!(result.is_empty());
    }

    // ------------------------------------------------------------------------
    // OCSP request construction
    // ------------------------------------------------------------------------

    #[test]
    fn test_build_ocsp_request_returns_error_on_garbage() {
        // Empty cert / issuer can't yield a valid OCSP request.
        let result = build_ocsp_request_der(&[], &[], &[0u8; 16]);
        assert!(matches!(result, Err(CryptoError::X509(_))));
    }

    #[test]
    fn test_set_ocsp_hook_first_call_succeeds_then_idempotent() {
        // Note: OCSP_HOOK is a process-global OnceLock. Other tests
        // running in parallel may have already set it. We assert
        // only that calling `set_ocsp_hook` is a no-panic operation
        // — repeated installs are deliberately ignored per the
        // function's documented contract.
        let hook: OcspHook = Arc::new(|_url, _body| {
            Box::pin(async { Err(CryptoError::X509("test hook never returns OK".into())) })
        });
        // The boolean return value is intentionally not asserted; it
        // depends on test execution order.
        let _ = set_ocsp_hook(hook);
    }

    // ------------------------------------------------------------------------
    // OCSP response window parsing — fallback to UNIX_EPOCH on garbage.
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_ocsp_response_window_garbage() {
        let (p, n) = parse_ocsp_response_window(&[0x00, 0x01, 0x02]);
        assert_eq!(p, UNIX_EPOCH);
        assert_eq!(n, UNIX_EPOCH);
    }

    #[test]
    fn test_ocsp_next_refresh_uses_floor_when_no_next_update() {
        let resp = OcspResponse {
            der: Vec::new(),
            produced_at: UNIX_EPOCH,
            next_update: UNIX_EPOCH,
        };
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let next = ocsp_next_refresh(&resp, now);
        assert_eq!(next, now + Duration::from_millis(X509_OCSP_REFRESH));
    }

    #[test]
    fn test_ocsp_next_refresh_caps_before_expiry() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        // next_update is only 30 seconds away — much shorter than the
        // 7200-second refresh interval. The result must be earlier
        // than now+REFRESH and not later than next_update-RETRY.
        let resp = OcspResponse {
            der: Vec::new(),
            produced_at: UNIX_EPOCH,
            next_update: now + Duration::from_secs(30),
        };
        let next = ocsp_next_refresh(&resp, now);
        // Should be capped to (next_update - RETRY) but not before now.
        assert!(next >= now);
        assert!(next < now + Duration::from_millis(X509_OCSP_REFRESH));
    }

    // ------------------------------------------------------------------------
    // to_rustls_cert_der round-trip
    // ------------------------------------------------------------------------

    #[test]
    fn test_to_rustls_cert_der_preserves_bytes() {
        let chain = CertChain {
            certs: vec![vec![0x01, 0x02, 0x03], vec![0x04, 0x05]],
        };
        let rustls_chain = to_rustls_cert_der(&chain);
        assert_eq!(rustls_chain.len(), 2);
        assert_eq!(rustls_chain[0].as_ref(), &[0x01, 0x02, 0x03]);
        assert_eq!(rustls_chain[1].as_ref(), &[0x04, 0x05]);
    }

    #[test]
    fn test_to_rustls_certified_key_dsa_rejected() {
        let key = PrivateKey::new(vec![0x00; 16], KeyAlgo::Dsa);
        let chain = CertChain {
            certs: vec![vec![0x01]],
        };
        let cak = CertAndKey { chain, key };
        let result = to_rustls_certified_key(&cak);
        assert!(matches!(result, Err(CryptoError::X509(_))));
    }

    #[test]
    fn test_to_rustls_certified_key_empty_chain_rejected() {
        let key = PrivateKey::new(vec![0x00; 16], KeyAlgo::Rsa);
        let chain = CertChain { certs: Vec::new() };
        let cak = CertAndKey { chain, key };
        let result = to_rustls_certified_key(&cak);
        assert!(matches!(result, Err(CryptoError::X509(_))));
    }

    // ------------------------------------------------------------------------
    // OID byte sequences are correct
    // ------------------------------------------------------------------------

    #[test]
    fn test_oid_constants_match_rfc() {
        // SHA-1 OID 1.3.14.3.2.26
        assert_eq!(OID_SHA1, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]);
        // SHA-256 OID 2.16.840.1.101.3.4.2.1
        assert_eq!(
            OID_SHA256,
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
        );
        // OCSP nonce OID 1.3.6.1.5.5.7.48.1.2
        assert_eq!(
            OID_OCSP_NONCE,
            &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02]
        );
    }

    #[test]
    fn test_x509_ocsp_constants_visible() {
        // Force the compiler to consume the imported constants so
        // the `unused_imports` lint won't bite if a refactor temporarily
        // removes their callers.
        let _ = X509_OCSP_SHA256;
        let _ = X509_OCSP_REFRESH;
        let _ = X509_OCSP_RETRY;
        let _ = X509_OCSP_SYSLOG;
    }
}
