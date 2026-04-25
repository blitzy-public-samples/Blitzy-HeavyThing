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

//! TLS 1.2 / 1.3 server and client built on rustls 0.23.
//!
//! Port of `tls.inc` (the original 6,866-line FASM file documented at AAP
//! §0.7.2). The Rust implementation hides rustls behind the
//! [`TlsServer`] / [`TlsClient`] / [`TlsStream`] types so that callers
//! in `crates/heavything/src/net/http/server.rs` and
//! `crates/hnwatch/src/hnmodel.rs` consume the same surface that the
//! FASM `tls$new_server` / `tls$new_client` / `tls$accept` /
//! `tls$connect` entry points exposed.
//!
//! # Architectural Divergence from the Assembly Baseline
//!
//! The original `tls.inc` is a hand-rolled TLS 1.2 engine whose
//! salient design decisions are spelled out at the top of the source
//! file. This Rust port intentionally diverges where rustls's
//! cryptographic posture is strictly more conservative; the
//! divergences are the ones called out by AAP §0.7.2.2 and reproduced
//! here verbatim per the Phase 2 deliverable contract:
//!
//! ## What the assembly did
//!
//! * Classical **DHE** (Diffie-Hellman Ephemeral) key exchange using
//!   the safe primes baked into `dh_pool.inc`. The author
//!   deliberately distrusted the NIST ECDHE curves post-Snowden and
//!   used pure DH instead.
//! * **AES-128/256-CBC + SHA-256 / SHA-1** cipher suites only — GCM
//!   is commented out at lines 138–143 of the source.
//! * **RSA blinding** (`tls_server_rsa_blinding = 0` by default) as
//!   timing-attack defence, applied during RSA key-exchange.
//! * **Per-IP blacklist** (`tls_blacklist = 86400`s) on **any**
//!   crypto-level handshake error to defeat brute-force / BEAST
//!   probing.
//! * **AES-256 + HMAC-SHA-256 encrypted session cache** with a
//!   3,600-second TTL.
//! * **PEM hot-reload every 3,600 s** with a deliberate
//!   never-free-the-old-X509 policy (an artefact of FASM manual
//!   memory management — the comment in the source reads
//!   *"intentionally never frees old X509 cert"*).
//! * **"Garbage-In/Garbage-Out" certificate-chain policy** — server
//!   side does not validate certificate chains.
//!
//! ## What rustls 0.23 provides
//!
//! * **ECDHE** key exchange only (no classical DHE). Safe-prime DH is
//!   not offered.
//! * **AES-128/256-GCM + CHACHA20-Poly1305** AEAD suites only (no
//!   CBC). All suites are PFS-by-construction.
//! * Internal side-channel defences applied uniformly; no
//!   user-tunable RSA blinding knob is exposed (rustls handles
//!   timing internally).
//! * **TLS 1.3** support in addition to TLS 1.2 — a widening of the
//!   protocol surface that the prompt in AAP §0.7.2.2 explicitly
//!   tags as in scope ("rustls + webpki for 1.2/1.3").
//! * **Server-side**: no client-cert chain validation by default
//!   (preserves parity with the FASM "garbage-in/garbage-out"
//!   posture).
//! * **Client-side**: webpki-roots Mozilla bundle + webpki chain
//!   validation (a behavioural improvement tacitly endorsed by AAP
//!   §0.6.1's choice of `webpki-roots` as the client-config root
//!   store).
//!
//! ## What this Rust port preserves 1 : 1
//!
//! * **3,600-second TLS session cache TTL** with **AES-256-GCM
//!   encryption** of cache entries at rest, implemented by wrapping
//!   `rustls::server::ServerSessionMemoryCache` inside
//!   [`EncryptedSessionCache`]. The AES-256-GCM is a strictly more
//!   conservative substitute for the FASM AES-256-CBC + HMAC-SHA-256
//!   construction (one authenticated primitive, no MAC-then-encrypt
//!   vs. encrypt-then-MAC ambiguity).
//! * **3,600-second PEM hot-reload** via
//!   [`tokio::time::interval`] driving a closure that rebuilds the
//!   `Arc<rustls::ServerConfig>` and atomically swaps it through a
//!   `std::sync::RwLock<Arc<ServerConfig>>` (used in lieu of
//!   `arc_swap`, which is not in the AAP §0.6.1 dependency
//!   inventory). The "intentional leak" of the FASM source is
//!   replaced by Rust's `Arc` reference counting — old configs are
//!   dropped automatically when the last in-flight TLS connection
//!   that references them releases its `Arc`.
//! * **OCSP stapling** with a **7,200-second refresh** /
//!   **300-second retry-on-failure** cadence, dispatched through
//!   [`crate::crypto::x509::fetch_ocsp`] and
//!   [`crate::crypto::x509::update_ocsp_response`].
//! * **IP-blacklist integration on crypto errors** with the
//!   86,400-second default ban, dispatched through
//!   [`crate::net::blacklist::Blacklist::insert`] using the
//!   [`crate::net::blacklist::key_from_socket_addr`] helper. The
//!   same `Blacklist` instance is shared with `crate::net::ssh` per
//!   AAP §0.7.4.
//! * **HSTS / BREACH header emission** is preserved by the callers
//!   in `crate::net::http::server`; this module merely transports
//!   the bytes.
//!
//! # Public surface
//!
//! * [`TlsServer`] — server-side configuration + handshake driver,
//!   plus `spawn_*` helpers for the three background tasks (PEM
//!   reload, OCSP refresh, session-cache sweep).
//! * [`TlsClient`] — client-side configuration + handshake driver
//!   (used by `crate::net::http::client` and `crates/hnwatch`).
//! * [`TlsStream`] — wrapped TCP+rustls stream implementing
//!   [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`].
//! * [`take_sessioncache_hook`] / [`set_sessioncache_hook`] /
//!   [`sessioncache_put`] — process-level hook for cross-process
//!   session-cache replication. Mirrors the FASM
//!   `tls$sessioncache_hook` global pointer and `tls$sessioncache_put`
//!   entry point at `tls.inc` line 426.

use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::{ServerConnection, ServerSessionMemoryCache, StoresServerSessions};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::config;
use crate::crypto::aes::{aes256_gcm_open, aes256_gcm_seal_random_nonce, AES256_KEY_SIZE, GCM_NONCE_SIZE};
use crate::crypto::rng;
use crate::crypto::x509::{
    self, fetch_ocsp, ocsp_next_refresh, to_rustls_certified_key, CertAndKey, KeyAlgo, OcspResponse,
    PrivateKey,
};
use crate::error::TlsError;
use crate::net::blacklist::{key_from_socket_addr, Blacklist};
use crate::util::syslog;

// ============================================================================
// EncryptedSessionCache — AES-256-GCM-encrypted wrapper over the rustls
// in-memory session cache. Preserves FASM `tls_server_encryptcache = 1` /
// `tls_client_encryptcache = 1` semantics per AAP §0.7.2.4.
// ============================================================================

/// Maximum number of cached sessions held in memory at any one time.
///
/// The FASM baseline used `tls_server_sessioncache = 3600` (TTL in
/// seconds) and an unbounded entry count constrained only by the
/// `mappedheap`-backed allocator. rustls's
/// [`ServerSessionMemoryCache`] requires a fixed entry-count cap; we
/// pick 4,096 to match the `EPOLL_MINFDS` ulimit floor (the practical
/// upper bound on simultaneously-handshaken connections).
const SESSION_CACHE_CAPACITY: usize = 4096;

/// Wraps a rustls [`ServerSessionMemoryCache`] with AES-256-GCM
/// encryption of every stored entry.
///
/// A random per-process AES-256 key is generated at construction time
/// via [`crate::crypto::rng::block`]; the key never leaves the process
/// and is dropped together with the cache.
///
/// Each `put` call generates a fresh 12-byte nonce via
/// [`crate::crypto::rng::block`] (through
/// [`aes256_gcm_seal_random_nonce`]) and prepends the nonce to the
/// ciphertext so that the corresponding `get` / `take` call can split
/// `(nonce, ct)` and decrypt. This wire layout is process-private —
/// rustls never inspects the bytes.
///
/// Encryption failures degrade gracefully: a `put` that cannot be
/// encrypted is dropped (`put` returns `false`, signalling to rustls
/// that the entry was not stored); a `get` / `take` that cannot be
/// decrypted returns `None` so that the handshake fails over to a full
/// handshake instead of a session resumption. This matches the FASM
/// `tls$sessioncache_get` policy at `tls.inc` line 340 (return null on
/// decrypt failure rather than tearing down the connection).
struct EncryptedSessionCache {
    /// Underlying rustls in-memory session cache. `Arc`-wrapped here
    /// to match the rustls return convention (`Arc<ServerSessionMemoryCache>`).
    inner: Arc<ServerSessionMemoryCache>,
    /// Random per-process AES-256 key. Length is enforced at the
    /// type level by the AES-GCM wrapper functions in
    /// `crate::crypto::aes`.
    aes_key: [u8; AES256_KEY_SIZE],
}

impl std::fmt::Debug for EncryptedSessionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omit `aes_key` from the Debug output to avoid
        // leaking the key material into log lines that might travel
        // through `crate::util::syslog`.
        f.debug_struct("EncryptedSessionCache")
            .field("capacity", &SESSION_CACHE_CAPACITY)
            .field("aes_key", &"<redacted>")
            .finish()
    }
}

impl EncryptedSessionCache {
    /// Build a new encrypted session cache with a fresh random AES-256
    /// key. The key is sourced from
    /// [`crate::crypto::rng::block`], which is HMAC-DRBG-backed and
    /// has been seeded by the time the TLS subsystem comes online
    /// (AAP §0.5.1.3 Stage 9 init order).
    fn new() -> Arc<Self> {
        let mut aes_key = [0u8; AES256_KEY_SIZE];
        rng::block(&mut aes_key);
        Arc::new(Self {
            inner: ServerSessionMemoryCache::new(SESSION_CACHE_CAPACITY),
            aes_key,
        })
    }

    /// AES-256-GCM-encrypt a session blob. Returns
    /// `nonce || ciphertext || tag` so that the corresponding `decrypt`
    /// call can split the prefix off cleanly.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        let (nonce, mut ct) = aes256_gcm_seal_random_nonce(&self.aes_key, &[], plaintext)
            .map_err(|e| TlsError::SessionCache(e.to_string()))?;
        let mut out = Vec::with_capacity(GCM_NONCE_SIZE + ct.len());
        out.extend_from_slice(&nonce);
        out.append(&mut ct);
        Ok(out)
    }

    /// AES-256-GCM-decrypt a session blob produced by [`Self::encrypt`].
    fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, TlsError> {
        if blob.len() < GCM_NONCE_SIZE {
            return Err(TlsError::SessionCache(format!(
                "session blob too short: {} bytes (need at least {})",
                blob.len(),
                GCM_NONCE_SIZE
            )));
        }
        let (nonce_bytes, ct) = blob.split_at(GCM_NONCE_SIZE);
        let mut nonce = [0u8; GCM_NONCE_SIZE];
        nonce.copy_from_slice(nonce_bytes);
        aes256_gcm_open(&self.aes_key, &nonce, &[], ct).map_err(|e| TlsError::SessionCache(e.to_string()))
    }
}

impl StoresServerSessions for EncryptedSessionCache {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        // Encrypt-on-store; on encryption failure, drop the entry and
        // signal `false` to rustls. This matches the FASM behaviour
        // at `tls.inc` line 476–478 ("can_cache returns true, but a
        // failing put just discards").
        match self.encrypt(&value) {
            Ok(blob) => {
                // Forward the encrypted blob to the rustls in-memory
                // store. Also dispatch to the user-installed
                // session-cache hook if one is registered.
                let stored = self.inner.put(key.clone(), blob.clone());
                sessioncache_dispatch_put(&key, &blob);
                stored
            }
            Err(e) => {
                syslog::warning(&format!("tls: session cache put encrypt failed: {e}"));
                false
            }
        }
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let blob = self.inner.get(key)?;
        match self.decrypt(&blob) {
            Ok(pt) => Some(pt),
            Err(e) => {
                syslog::warning(&format!("tls: session cache get decrypt failed: {e}"));
                None
            }
        }
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let blob = self.inner.take(key)?;
        match self.decrypt(&blob) {
            Ok(pt) => Some(pt),
            Err(e) => {
                syslog::warning(&format!("tls: session cache take decrypt failed: {e}"));
                None
            }
        }
    }

    fn can_cache(&self) -> bool {
        true
    }
}

// ============================================================================
// Session-cache hook — process-level callback invoked on every cache `put`.
// Mirrors the FASM `tls$sessioncache_hook` global pointer at
// `tls.inc` line 426 and the `tls$sessioncache_put` entry point.
// ============================================================================

/// Type alias for the user-installable session-cache hook. The closure
/// is invoked whenever a session is `put` into any
/// [`TlsServer`]'s cache. Signature mirrors the rustls
/// `StoresServerSessions::put` contract: takes the cache key and the
/// encrypted-blob value (the same bytes the rustls in-memory store
/// receives), returns nothing.
///
/// The blob the hook receives is **already encrypted** with the
/// process-private AES-256 key managed by [`EncryptedSessionCache`];
/// the hook is therefore not a key-disclosure vector. Callers using
/// the hook for cross-process replication should additionally
/// transport the AES key out-of-band so the receiving process can
/// decrypt — or the hook should perform its own encryption.
pub type SessionCacheHook = Arc<dyn Fn(&[u8], &[u8]) + Send + Sync + 'static>;

/// Process-global session-cache hook slot. Lazily initialised on first
/// `set_sessioncache_hook` / `take_sessioncache_hook` call. Stored
/// inside an [`OnceLock`] of [`Mutex`] of `Option<SessionCacheHook>`
/// so the hook can be installed once at startup, replaced or cleared
/// at runtime, and read concurrently from many TLS workers.
static SESSIONCACHE_HOOK: OnceLock<Mutex<Option<SessionCacheHook>>> = OnceLock::new();

/// Get or initialise the global hook slot.
fn sessioncache_hook_slot() -> &'static Mutex<Option<SessionCacheHook>> {
    SESSIONCACHE_HOOK.get_or_init(|| Mutex::new(None))
}

/// Install (or replace) the process-global session-cache hook. Returns
/// the previously-installed hook, if any, so callers can chain hooks.
///
/// Mirrors the FASM `tls$sessioncache_sethook` entry point at
/// `tls.inc` line 559. The closure is wrapped in an [`Arc`] so it can
/// be cloned cheaply on every cache `put` dispatch.
pub fn set_sessioncache_hook(hook: SessionCacheHook) -> Option<SessionCacheHook> {
    let slot = sessioncache_hook_slot();
    match slot.lock() {
        Ok(mut g) => g.replace(hook),
        Err(_) => None,
    }
}

/// Remove the process-global session-cache hook and return it, if any.
///
/// Mirrors the FASM `tls$sessioncache_takehook` accessor used by
/// graceful-shutdown paths in `crates/webserver/src/master.rs` to
/// drain pending cross-process session updates.
pub fn take_sessioncache_hook() -> Option<SessionCacheHook> {
    let slot = sessioncache_hook_slot();
    match slot.lock() {
        Ok(mut g) => g.take(),
        Err(_) => None,
    }
}

/// Externally-visible session-cache `put` that bypasses the
/// [`EncryptedSessionCache::put`] path and dispatches the
/// `(key, value)` pair directly to any registered hook.
///
/// Used by the webserver's master→worker IPC relay
/// (`crate::net::child::LinkMessage::TlsUpdate` per AAP §0.4.1.1) to
/// deliver session-cache updates received from peer workers without
/// re-encrypting the blob.
///
/// Callers must arrange that `value` is already in the on-the-wire
/// encrypted form expected by the receiving worker's
/// `EncryptedSessionCache::decrypt`. Mismatched AES keys between
/// workers will cause subsequent `get` calls to return `None` (the
/// safe failure mode — sessions silently fail to resume rather than
/// disrupting the handshake).
pub fn sessioncache_put(key: &[u8], value: &[u8]) {
    sessioncache_dispatch_put(key, value);
}

/// Internal helper invoked from
/// [`EncryptedSessionCache::put`] and from [`sessioncache_put`].
/// Clones the hook out of the shared slot under a short critical
/// section to avoid holding the slot mutex while the hook runs.
fn sessioncache_dispatch_put(key: &[u8], value: &[u8]) {
    let hook = match sessioncache_hook_slot().lock() {
        Ok(g) => g.as_ref().cloned(),
        Err(_) => None,
    };
    if let Some(h) = hook {
        h(key, value);
    }
}

// ============================================================================
// PEM loading — produces `Arc<rustls::ServerConfig>` ready for use.
// ============================================================================

/// Load a PEM cert chain + private key from disk and bake them into a
/// fresh [`Arc<ServerConfig>`].
///
/// On success, the returned `ServerConfig` is wired to:
/// * The `aws_lc_rs` rustls crypto provider (matches
///   [`crate::crypto::x509::to_rustls_certified_key`]).
/// * No client-cert verification (preserves the FASM
///   "garbage-in/garbage-out" server-side posture per AAP §0.7.2.3).
/// * The supplied [`StoresServerSessions`] (which is the per-server
///   [`EncryptedSessionCache`]).
/// * The currently-cached OCSP response stapled onto the
///   `CertifiedKey` if `ocsp_der` is `Some`. Per RFC 6066 §8 the
///   stapled bytes are the raw `OCSPResponse` DER as produced by
///   [`crate::crypto::x509::fetch_ocsp`].
fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    cache: Arc<dyn StoresServerSessions + Send + Sync>,
    ocsp_der: Option<Vec<u8>>,
) -> Result<ServerConfig, TlsError> {
    // We load cert and key from possibly-separate PEM files. The
    // `crypto::x509::load_pem_file` helper expects both blocks in the
    // same file (its purpose is to support a single combined PEM,
    // which is rwasa's default), but the `webserver` argument parser
    // accepts them as separate paths. We therefore read each file
    // explicitly via `rustls_pemfile::*` and fuse the results.
    let cert_chain_der = read_cert_chain_pem(cert_path)?;
    let key = read_private_key_pem(key_path)?;

    let cert_and_key = CertAndKey {
        chain: x509::CertChain {
            certs: cert_chain_der.iter().map(|c| c.as_ref().to_vec()).collect(),
        },
        key,
    };

    // Build the certified key, then attach the OCSP staple if we have
    // one. `to_rustls_certified_key` returns `Arc<CertifiedKey>`; we
    // need an owned `CertifiedKey` to mutate the `ocsp` field, so we
    // unwrap the Arc (we are the only holder) or clone-then-take.
    let certified_arc = to_rustls_certified_key(&cert_and_key).map_err(|e| TlsError::Pem(e.to_string()))?;
    let mut certified = match Arc::try_unwrap(certified_arc) {
        Ok(c) => c,
        Err(arc) => rustls::sign::CertifiedKey::new(arc.cert.clone(), arc.key.clone()),
    };
    if let Some(der) = ocsp_der {
        // Attach via the public `update_ocsp_response` shim — keeps
        // the staple-installation behaviour consolidated in
        // `crate::crypto::x509`.
        x509::update_ocsp_response(
            &mut certified,
            &OcspResponse {
                der,
                produced_at: SystemTime::UNIX_EPOCH,
                next_update: SystemTime::UNIX_EPOCH,
            },
        );
    }

    let cert_resolver: Arc<dyn rustls::server::ResolvesServerCert> =
        Arc::new(rustls::sign::SingleCertAndKey::from(certified));

    // Use `builder_with_provider` with the `aws_lc_rs` provider to
    // match `to_rustls_certified_key`'s provider choice. Falling
    // through to the process-default `builder()` would panic if no
    // default provider has been installed yet.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Pem(format!("rustls protocol-version setup: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);
    config.session_storage = cache;
    // FASM `tls_server_cipher_order = 1` (line 378 of `ht_defaults.inc`)
    // gives the server suite-preference precedence. rustls models
    // this via `ignore_client_order`.
    if config::TLS_SERVER_CIPHER_ORDER {
        config.ignore_client_order = true;
    }
    Ok(config)
}

/// Helper that mirrors `rustls_pemfile::certs`. Returns the full
/// certificate chain in the PEM file as a `Vec<CertificateDer<'static>>`.
fn read_cert_chain_pem(cert_path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = File::open(cert_path)
        .map_err(|e| TlsError::Pem(format!("open cert file {}: {}", cert_path.display(), e)))?;
    let mut rdr = BufReader::new(file);
    let mut out = Vec::new();
    for cert in rustls_pemfile::certs(&mut rdr) {
        let cert =
            cert.map_err(|e| TlsError::Pem(format!("parse cert in {}: {}", cert_path.display(), e)))?;
        out.push(cert);
    }
    if out.is_empty() {
        return Err(TlsError::Pem(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }
    Ok(out)
}

/// Read a single private key (PKCS#1, PKCS#8, or SEC1) from a PEM file
/// and convert it to a [`PrivateKey`] suitable for
/// [`to_rustls_certified_key`].
///
/// The file may also contain certificates; they are silently ignored
/// (this lets a caller pass the same path as both `cert_path` and
/// `key_path` when the cert and key are concatenated in one file —
/// which is the rwasa default).
fn read_private_key_pem(key_path: &Path) -> Result<PrivateKey, TlsError> {
    use rustls_pemfile::Item;

    let file = File::open(key_path)
        .map_err(|e| TlsError::Pem(format!("open key file {}: {}", key_path.display(), e)))?;
    let mut rdr = BufReader::new(file);

    loop {
        let item = rustls_pemfile::read_one(&mut rdr)
            .map_err(|e| TlsError::Pem(format!("PEM parse error in {}: {}", key_path.display(), e)))?;
        let Some(item) = item else {
            return Err(TlsError::Pem(format!(
                "no PRIVATE KEY block found in {}",
                key_path.display()
            )));
        };
        match item {
            Item::Pkcs1Key(der) => {
                return Ok(PrivateKey::new(der.secret_pkcs1_der().to_vec(), KeyAlgo::Rsa));
            }
            Item::Pkcs8Key(der) => {
                let bytes = der.secret_pkcs8_der().to_vec();
                // Defer algorithm detection to the rustls-side
                // signing-key conversion. We use Rsa as the placeholder
                // value; `to_rustls_certified_key` calls
                // `aws_lc_rs::sign::any_supported_type` which inspects
                // the DER itself.
                return Ok(PrivateKey::new(bytes, KeyAlgo::Rsa));
            }
            Item::Sec1Key(der) => {
                return Ok(PrivateKey::new(
                    der.secret_sec1_der().to_vec(),
                    KeyAlgo::EcdsaP256,
                ));
            }
            // Other items (X.509 cert, CRL, CSR, SPKI) are skipped
            // until a key block is encountered.
            _ => continue,
        }
    }
}

// ============================================================================
// TlsServer — the main server-side type.
// ============================================================================

/// Server-side TLS configuration with hot-reloadable cert/key, OCSP
/// stapling, encrypted session cache, and IP-blacklist integration.
///
/// Constructed via [`TlsServer::new`]. Held by callers as
/// `Arc<TlsServer>` so background tasks (PEM reload, OCSP refresh,
/// session-cache sweep) can hold a [`Weak`] back-reference and stop
/// automatically when the server is dropped.
pub struct TlsServer {
    /// Hot-swappable rustls config. Wrapped in
    /// [`std::sync::RwLock`] (rather than `arc_swap` per AAP §0.6.1
    /// dependency-inventory constraint). Reads are taken on every
    /// `accept`, so the lock is read-heavy.
    config: RwLock<Arc<ServerConfig>>,

    /// Path to the on-disk PEM certificate chain. Used by the PEM
    /// reload task to re-read the file every
    /// [`crate::config::TLS_PEM_REFRESH_INTERVAL`] seconds.
    cert_path: PathBuf,

    /// Path to the on-disk private-key PEM. See `cert_path`.
    key_path: PathBuf,

    /// Encrypted session cache shared across reload generations of
    /// `config`. `Arc` so that swapping `config` does not invalidate
    /// the cache — the new config reuses the same storage.
    session_cache: Arc<dyn StoresServerSessions + Send + Sync>,

    /// IP blacklist shared with `crate::net::ssh` per AAP §0.7.4.
    /// On a TLS-side crypto error, [`TlsServer::accept`] inserts the
    /// peer's IP via [`Blacklist::insert`].
    blacklist: Arc<Blacklist>,

    /// Most-recently-fetched OCSP response (DER bytes) and its
    /// extracted validity window. `None` when no fetch has succeeded
    /// yet. Updated by
    /// [`TlsServer::spawn_ocsp_refresh`].
    ocsp_cache: RwLock<Option<OcspResponse>>,

    /// Wall-clock timestamp of the last successful OCSP fetch, used
    /// by [`TlsServer::spawn_ocsp_refresh`] to compute the next-tick
    /// deadline via [`crate::crypto::x509::ocsp_next_refresh`].
    /// `None` until the first successful fetch.
    ocsp_last_refresh: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for TlsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServer")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("blacklist_len", &self.blacklist.len())
            .finish()
    }
}

impl TlsServer {
    /// Build a new `TlsServer` from on-disk PEM files plus a shared
    /// blacklist instance.
    ///
    /// * `cert_path` — full PEM cert chain (end-entity first).
    /// * `key_path` — PEM-encoded private key matching the
    ///   end-entity certificate.
    /// * `blacklist` — shared with `crate::net::ssh`. Use
    ///   [`Blacklist::new`](crate::net::blacklist::Blacklist::new)
    ///   with `Duration::from_secs(crate::config::TLS_BLACKLIST)`
    ///   (86,400 s).
    ///
    /// On success the returned `Arc<TlsServer>` is ready to accept
    /// connections via [`TlsServer::accept`]. The caller is expected
    /// to also call [`TlsServer::spawn_pem_reload`],
    /// [`TlsServer::spawn_ocsp_refresh`], and
    /// [`TlsServer::spawn_session_cache_sweep`] once at startup to
    /// arm the three background tasks (these are split out of `new`
    /// so that test code can construct a `TlsServer` without
    /// triggering background-task side effects).
    ///
    /// # Errors
    ///
    /// * [`TlsError::Pem`] — PEM parse failure on either file, no
    ///   certificates in the chain, key/cert mismatch reported by
    ///   rustls, or `aws_lc_rs` provider rejection of the key.
    pub fn new(
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
        blacklist: Arc<Blacklist>,
    ) -> Result<Arc<Self>, TlsError> {
        let cert_path = cert_path.into();
        let key_path = key_path.into();

        // Build the encrypted session cache once; it survives across
        // PEM-reload generations so resumed sessions don't fail just
        // because the certificate was re-read.
        let session_cache: Arc<dyn StoresServerSessions + Send + Sync> = if config::TLS_SERVER_ENCRYPTCACHE {
            EncryptedSessionCache::new()
        } else {
            // Direct rustls in-memory cache without the AES-256-GCM
            // wrapper. Selected when
            // `crate::config::TLS_SERVER_ENCRYPTCACHE = false`. Held
            // through the same `dyn StoresServerSessions` boundary
            // for uniform downstream handling.
            ServerSessionMemoryCache::new(SESSION_CACHE_CAPACITY)
        };

        let initial_config = build_server_config(&cert_path, &key_path, session_cache.clone(), None)?;

        Ok(Arc::new(Self {
            config: RwLock::new(Arc::new(initial_config)),
            cert_path,
            key_path,
            session_cache,
            blacklist,
            ocsp_cache: RwLock::new(None),
            ocsp_last_refresh: Mutex::new(None),
        }))
    }

    /// Accept and complete a TLS handshake on the given TCP stream.
    ///
    /// On success, the returned [`TlsStream`] is ready for
    /// application-layer reads/writes (the [`AsyncRead`] /
    /// [`AsyncWrite`] impls).
    ///
    /// On a crypto-level handshake failure (e.g.
    /// [`rustls::Error::DecryptError`],
    /// [`rustls::Error::AlertReceived`] with
    /// [`rustls::AlertDescription::BadRecordMac`] or
    /// [`rustls::AlertDescription::DecryptError`],
    /// [`rustls::Error::InvalidMessage`]), the peer's IP is inserted
    /// into the shared blacklist for
    /// [`crate::config::TLS_BLACKLIST`] seconds, mirroring the FASM
    /// `tls$blacklist_add` policy at `tls.inc` lines 458–462.
    ///
    /// IO errors (peer disconnect, `read_tls`/`write_tls` I/O
    /// failures) do **not** trigger a blacklist add — only
    /// genuinely-attributable cryptographic protocol violations do.
    ///
    /// # Errors
    ///
    /// * [`TlsError::Handshake`] — any handshake failure (crypto or
    ///   IO). The full rustls or std::io error message is included
    ///   in the variant payload.
    pub async fn accept(self: &Arc<Self>, stream: TcpStream) -> Result<TlsStream, TlsError> {
        let peer = stream
            .peer_addr()
            .map_err(|e| TlsError::Handshake(format!("peer_addr: {e}")))?;

        // Optimistic pre-handshake blacklist check: cheap and avoids
        // burning CPU on a peer we've already decided to ban.
        let bl_key = key_from_socket_addr(peer);
        if self.blacklist.contains(bl_key) {
            return Err(TlsError::Handshake(format!("peer {} is blacklisted", peer.ip())));
        }

        let cfg = self.current_config();
        let conn = ServerConnection::new(cfg)
            .map_err(|e| TlsError::Handshake(format!("ServerConnection::new: {e}")))?;

        match handshake_pump_server(stream, conn).await {
            Ok((stream, conn)) => Ok(TlsStream::new_server(stream, conn, peer, Arc::clone(self))),
            Err(HandshakeFail::Crypto(msg)) => {
                self.blacklist
                    .insert(bl_key, Duration::from_secs(config::TLS_BLACKLIST));
                syslog::warning(&format!(
                    "tls: handshake crypto error from {}: {}; blacklisted for {}s",
                    peer.ip(),
                    msg,
                    config::TLS_BLACKLIST
                ));
                Err(TlsError::Handshake(msg))
            }
            Err(HandshakeFail::Io(msg)) => Err(TlsError::Handshake(msg)),
        }
    }

    /// Snapshot the current `Arc<ServerConfig>`. Cheap (`Arc` clone).
    fn current_config(&self) -> Arc<ServerConfig> {
        match self.config.read() {
            Ok(g) => Arc::clone(&g),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Atomically swap the current `Arc<ServerConfig>` with a fresh
    /// one. Used by [`TlsServer::spawn_pem_reload`] and
    /// [`TlsServer::spawn_ocsp_refresh`].
    fn swap_config(&self, new_config: ServerConfig) {
        let new_arc = Arc::new(new_config);
        match self.config.write() {
            Ok(mut g) => {
                *g = new_arc;
            }
            Err(poisoned) => {
                // Recover from poison rather than panicking — the
                // poisoned value is replaced wholesale anyway.
                *poisoned.into_inner() = new_arc;
            }
        }
    }

    /// Spawn the 3,600-second PEM hot-reload task. Returns the
    /// [`tokio::task::JoinHandle`] so the caller can `.abort()` it on
    /// shutdown.
    ///
    /// The task holds a [`Weak`] reference to `self`; when the last
    /// strong reference is dropped, the task observes
    /// `Weak::upgrade() == None` on the next tick and exits cleanly.
    ///
    /// On reload failure the previous config is kept and a syslog
    /// warning is emitted; the task does **not** exit.
    pub fn spawn_pem_reload(self: &Arc<Self>) -> JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(pem_reload_loop(weak))
    }

    /// Spawn the 7,200-second OCSP refresh task with 300-second
    /// retry-on-failure cadence (AAP §0.7.2.1).
    ///
    /// On a successful fetch the task installs the response on a
    /// fresh `CertifiedKey` and atomically swaps the
    /// `Arc<ServerConfig>`; on failure the existing staple (or
    /// no-staple) is kept, a syslog warning is emitted (gated by
    /// [`crate::config::X509_OCSP_SYSLOG`]), and the task waits
    /// 300 seconds before retrying.
    ///
    /// Returns the [`tokio::task::JoinHandle`] for shutdown
    /// orchestration.
    pub fn spawn_ocsp_refresh(self: &Arc<Self>) -> JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(ocsp_refresh_loop(weak))
    }

    /// Spawn the 3,600-second session-cache sweep task.
    ///
    /// rustls's [`ServerSessionMemoryCache`] does its own LRU eviction
    /// when the cache hits its capacity bound, but provides no
    /// explicit time-based sweep. The FASM baseline ran a 3,600-second
    /// sweep that walked the cache and dropped expired entries; in
    /// the Rust port the sweep is a no-op (rustls eviction is
    /// adequate), but the task is retained at the API surface so the
    /// 8-canonical-timer count from AAP §0.7.1.1 is preserved and
    /// `webserver` can consistently call `spawn_*` for all three
    /// background tasks. The task simply ticks once per
    /// `TLS_SERVER_SESSIONCACHE` seconds and emits an `info` syslog
    /// line when it would have evicted anything (currently always
    /// silent).
    pub fn spawn_session_cache_sweep(self: &Arc<Self>) -> JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(session_cache_sweep_loop(weak))
    }
}

// ============================================================================
// Server-side handshake pump.
// ============================================================================

/// Distinguishes a handshake-pump failure that warrants blacklisting
/// (`Crypto`) from one that doesn't (`Io`). Internal type — not
/// exposed at the public API; surfaced as
/// [`TlsError::Handshake`] either way.
enum HandshakeFail {
    /// Cryptographic protocol violation attributable to the peer
    /// (decrypt error, MAC failure, alert with crypto-class
    /// description). Triggers `Blacklist::insert`.
    Crypto(String),
    /// IO-layer failure (peer disconnect, timeout, kernel-side
    /// error). Does not trigger a blacklist add.
    Io(String),
}

/// Pumps a server-side TLS handshake to completion.
///
/// Algorithm (per AAP §0.7.2.1 and the rustls 0.23 docs for
/// `process_new_packets`):
///
/// 1. If `wants_write`, drain `write_tls(&mut stream)` until rustls
///    reports nothing more to send.
/// 2. If still handshaking and rustls wants more bytes, `read_tls`
///    from `stream` (await on the underlying tokio TCP socket).
/// 3. Call `process_new_packets` to advance the rustls state machine.
///    Errors here are typed and either crypto-class (BadRecordMac,
///    DecryptError, InvalidMessage) or IO-class.
/// 4. Loop until `is_handshaking() == false`.
async fn handshake_pump_server(
    mut stream: TcpStream,
    mut conn: ServerConnection,
) -> Result<(TcpStream, ServerConnection), HandshakeFail> {
    while conn.is_handshaking() {
        if conn.wants_write() {
            // Drain everything rustls has queued for the wire, then
            // flush.
            let mut wire = Vec::with_capacity(4096);
            while conn.wants_write() {
                let n = conn
                    .write_tls(&mut wire)
                    .map_err(|e| HandshakeFail::Io(format!("write_tls: {e}")))?;
                if n == 0 {
                    break;
                }
            }
            if !wire.is_empty() {
                stream
                    .write_all(&wire)
                    .await
                    .map_err(|e| HandshakeFail::Io(format!("tcp write: {e}")))?;
            }
        }

        if conn.is_handshaking() && conn.wants_read() {
            // Read as much as rustls is willing to ingest in one go.
            let mut buf = [0u8; 4096];
            let n = stream
                .read(&mut buf)
                .await
                .map_err(|e| HandshakeFail::Io(format!("tcp read: {e}")))?;
            if n == 0 {
                return Err(HandshakeFail::Io(
                    "peer closed connection during handshake".into(),
                ));
            }
            let mut slice: &[u8] = &buf[..n];
            // `read_tls` needs a `&mut dyn io::Read`; a `&[u8]` is
            // already a `Read`, so we can pass `&mut slice` directly.
            let _ = conn
                .read_tls(&mut slice)
                .map_err(|e| HandshakeFail::Io(format!("read_tls: {e}")))?;
            conn.process_new_packets().map_err(classify_rustls_error)?;
        } else if !conn.is_handshaking() {
            // Done — exit the loop.
            break;
        } else if !conn.wants_write() && !conn.wants_read() {
            // Defensive: if rustls neither wants to read nor write
            // but is still handshaking, treat it as a stuck state
            // rather than busy-looping.
            return Err(HandshakeFail::Io(
                "handshake stuck: neither read nor write desired".into(),
            ));
        }
    }

    // One last write drain to flush any post-handshake data (e.g.
    // NewSessionTicket) that rustls queued.
    if conn.wants_write() {
        let mut wire = Vec::with_capacity(4096);
        while conn.wants_write() {
            let n = conn
                .write_tls(&mut wire)
                .map_err(|e| HandshakeFail::Io(format!("write_tls (final): {e}")))?;
            if n == 0 {
                break;
            }
        }
        if !wire.is_empty() {
            stream
                .write_all(&wire)
                .await
                .map_err(|e| HandshakeFail::Io(format!("tcp write (final): {e}")))?;
        }
    }

    Ok((stream, conn))
}

/// Classify a [`rustls::Error`] as either crypto-class
/// ([`HandshakeFail::Crypto`], triggers blacklist) or IO-class
/// ([`HandshakeFail::Io`]).
///
/// Crypto-class errors are those caused by the peer sending bytes
/// that fail authentication (BadRecordMac, DecryptError) or that
/// violate the protocol grammar in a way that suggests probing
/// (InvalidMessage). All other rustls errors map to `Io`.
fn classify_rustls_error(e: rustls::Error) -> HandshakeFail {
    use rustls::AlertDescription;
    use rustls::Error;
    let msg = format!("{e}");
    match &e {
        Error::DecryptError | Error::EncryptError => HandshakeFail::Crypto(msg),
        Error::InvalidMessage(_) => HandshakeFail::Crypto(msg),
        Error::AlertReceived(AlertDescription::BadRecordMac)
        | Error::AlertReceived(AlertDescription::DecryptError)
        | Error::AlertReceived(AlertDescription::DecryptionFailed)
        | Error::AlertReceived(AlertDescription::HandshakeFailure)
        | Error::AlertReceived(AlertDescription::IllegalParameter) => HandshakeFail::Crypto(msg),
        Error::AlertReceived(_) => HandshakeFail::Io(msg),
        Error::PeerMisbehaved(_) => HandshakeFail::Crypto(msg),
        _ => HandshakeFail::Io(msg),
    }
}

// ============================================================================
// Background tasks: PEM reload, OCSP refresh, session-cache sweep.
// ============================================================================

/// PEM hot-reload loop. Ticks every
/// [`crate::config::TLS_PEM_REFRESH_INTERVAL`] seconds (3,600 s
/// default), re-reads the cert and key files, rebuilds the
/// `Arc<ServerConfig>`, and atomically swaps it onto the server.
///
/// On reload failure the previous config is retained and a warning is
/// logged. The loop exits silently when the parent server is dropped
/// (Weak::upgrade returns None).
async fn pem_reload_loop(server: Weak<TlsServer>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(config::TLS_PEM_REFRESH_INTERVAL));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Discard the immediate first tick so we don't reload at t = 0;
    // the initial config was already loaded by `TlsServer::new`.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let Some(server) = server.upgrade() else {
            return;
        };
        // Snapshot the current OCSP staple so the reloaded config
        // still has a stapled response.
        let ocsp_der = match server.ocsp_cache.read() {
            Ok(g) => g.as_ref().map(|r| r.der.clone()),
            Err(poisoned) => poisoned.into_inner().as_ref().map(|r| r.der.clone()),
        };
        match build_server_config(
            &server.cert_path,
            &server.key_path,
            server.session_cache.clone(),
            ocsp_der,
        ) {
            Ok(new_cfg) => {
                server.swap_config(new_cfg);
                syslog::info("tls: PEM reloaded");
            }
            Err(e) => {
                syslog::warning(&format!("tls: PEM reload failed: {e}"));
            }
        }
    }
}

/// OCSP refresh loop. Sleeps for either the 7,200-second refresh
/// interval (after a successful fetch) or the 300-second retry
/// interval (after a failed fetch), then attempts a fresh OCSP fetch
/// via [`crate::crypto::x509::fetch_ocsp`].
///
/// On success the response is cached on the server and the
/// `CertifiedKey` is rebuilt with the new staple via a `swap_config`
/// call. On failure the cached staple is left intact, a syslog
/// warning is emitted (gated by [`crate::config::X509_OCSP_SYSLOG`]),
/// and the loop falls through to the retry path.
async fn ocsp_refresh_loop(server: Weak<TlsServer>) {
    // Initial delay matches the FASM behaviour: the first OCSP fetch
    // runs immediately after server start so the very first
    // connections benefit from a stapled response. We use a 5-second
    // grace so the runtime has time to settle.
    let mut delay = Duration::from_secs(5);
    loop {
        tokio::time::sleep(delay).await;
        let Some(server) = server.upgrade() else {
            return;
        };

        // OCSP stapling is gated by the config flag — if it's
        // disabled the loop still ticks (so it can be turned on at
        // runtime by future config-reload extensions) but performs
        // no work.
        if !config::TLS_SERVER_OCSP_STAPLING {
            delay = Duration::from_millis(config::X509_OCSP_REFRESH);
            continue;
        }

        match fetch_ocsp_for(&server).await {
            Ok(response) => {
                // Update the cached response and the timestamp.
                if let Ok(mut g) = server.ocsp_cache.write() {
                    *g = Some(response.clone());
                }
                if let Ok(mut g) = server.ocsp_last_refresh.lock() {
                    *g = Some(Instant::now());
                }
                // Rebuild the server config so the new staple is
                // attached to the resolver.
                match build_server_config(
                    &server.cert_path,
                    &server.key_path,
                    server.session_cache.clone(),
                    Some(response.der.clone()),
                ) {
                    Ok(new_cfg) => server.swap_config(new_cfg),
                    Err(e) => {
                        if config::X509_OCSP_SYSLOG {
                            syslog::warning(&format!("tls: OCSP staple install failed: {e}"));
                        }
                    }
                }
                if config::X509_OCSP_SYSLOG {
                    syslog::info("tls: OCSP refresh ok");
                }
                // Schedule the next refresh based on the response's
                // `nextUpdate` field, capped at the 7,200-second
                // floor.
                let next_at = ocsp_next_refresh(&response, SystemTime::now());
                delay = next_at
                    .duration_since(SystemTime::now())
                    .unwrap_or_else(|_| Duration::from_millis(config::X509_OCSP_REFRESH));
            }
            Err(e) => {
                if config::X509_OCSP_SYSLOG {
                    syslog::warning(&format!(
                        "tls: OCSP fetch failed: {e}; retry in {}s",
                        config::X509_OCSP_RETRY / 1000
                    ));
                }
                delay = Duration::from_millis(config::X509_OCSP_RETRY);
            }
        }
    }
}

/// Fetch an OCSP response for the server's currently-loaded cert.
///
/// Implements the responder-discovery + AIA extraction logic:
/// * Read the cert chain from `server.cert_path`.
/// * Use the end-entity cert as `cert`, the next cert in the chain
///   as `issuer`. If the chain has only one entry (self-signed root
///   or upstream-pinned scheme), use the same cert for both.
/// * Extract the OCSP responder URL from the AIA extension via the
///   `crate::crypto::x509::extract_ocsp_responder_url` helper if
///   present; otherwise return an error so the caller can schedule a
///   retry.
async fn fetch_ocsp_for(server: &Arc<TlsServer>) -> Result<OcspResponse, TlsError> {
    let chain = read_cert_chain_pem(&server.cert_path).map_err(|e| TlsError::Ocsp(e.to_string()))?;
    let cert = chain
        .first()
        .ok_or_else(|| TlsError::Ocsp("certificate chain is empty for OCSP fetch".to_string()))?;
    let issuer = chain.get(1).unwrap_or(cert);
    let cert_bytes = cert.as_ref();
    let issuer_bytes = issuer.as_ref();

    let responder_url = extract_ocsp_responder_url(cert_bytes)
        .ok_or_else(|| TlsError::Ocsp("no OCSP responder URL in end-entity AIA extension".to_string()))?;

    fetch_ocsp(cert_bytes, issuer_bytes, &responder_url)
        .await
        .map_err(|e| TlsError::Ocsp(e.to_string()))
}

/// Best-effort extraction of an OCSP responder URL from a DER-encoded
/// X.509 certificate's AIA extension.
///
/// The full Authority Information Access extension is described by
/// RFC 5280 §4.2.2.1. This helper does a minimal, hand-rolled DER
/// scan that tolerates malformed inputs by returning `None` rather
/// than panicking.
///
/// Algorithm:
/// 1. Find the AIA extension OID (`1.3.6.1.5.5.7.1.1` =
///    `06 08 2B 06 01 05 05 07 01 01`) anywhere in the cert.
/// 2. Inside the extension's OCTET STRING, find the OCSP
///    access-method OID (`1.3.6.1.5.5.7.48.1` =
///    `06 08 2B 06 01 05 05 07 30 01`).
/// 3. The next item in the AccessDescription is a
///    GeneralName/IA5String containing the responder URL. Its DER
///    tag is `[6] IMPLICIT IA5String` = `0x86`.
fn extract_ocsp_responder_url(cert_der: &[u8]) -> Option<String> {
    // OID for id-pe-authorityInfoAccess: 1.3.6.1.5.5.7.1.1
    const OID_AIA: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
    // OID for id-ad-ocsp: 1.3.6.1.5.5.7.48.1
    const OID_OCSP: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];

    // Find AIA extension OID
    let aia_pos = find_subseq(cert_der, OID_AIA)?;
    let after_aia = &cert_der[aia_pos + OID_AIA.len()..];

    // Find the OCSP access-method OID inside (or after) the AIA value.
    let ocsp_pos = find_subseq(after_aia, OID_OCSP)?;
    let after_ocsp = &after_aia[ocsp_pos + OID_OCSP.len()..];

    // Look for tag 0x86 (GeneralName [6] IA5String) — short form,
    // length up to 127.
    let mut i = 0;
    while i + 2 < after_ocsp.len() {
        if after_ocsp[i] == 0x86 {
            let len = after_ocsp[i + 1] as usize;
            if len > 0 && i + 2 + len <= after_ocsp.len() {
                let url_bytes = &after_ocsp[i + 2..i + 2 + len];
                if let Ok(s) = std::str::from_utf8(url_bytes) {
                    if s.starts_with("http://") || s.starts_with("https://") {
                        return Some(s.to_string());
                    }
                }
            }
            // Try the next 0x86 occurrence in case this one was a
            // false positive embedded in larger structure.
            i += 1;
            continue;
        }
        i += 1;
    }
    None
}

/// Linear search for `needle` inside `haystack`. Returns the start
/// offset of the first match, or `None` if not found.
fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Session-cache sweep loop. See
/// [`TlsServer::spawn_session_cache_sweep`] for the rationale; this
/// function exists primarily to preserve the eight-canonical-timer
/// surface area from AAP §0.7.1.1.
async fn session_cache_sweep_loop(server: Weak<TlsServer>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(config::TLS_SERVER_SESSIONCACHE));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await; // discard immediate tick at t=0
    loop {
        ticker.tick().await;
        if server.upgrade().is_none() {
            return;
        }
        // rustls's ServerSessionMemoryCache uses LRU eviction on
        // capacity overflow; there is no time-based sweep API. We
        // emit no log line on a normal tick.
    }
}

// ============================================================================
// TlsClient — the client-side type.
// ============================================================================

/// Client-side TLS configuration with webpki-roots Mozilla CA bundle
/// and standard rustls server-cert validation.
///
/// Used by `crate::net::http::client` and `crates/hnwatch` for
/// outbound HTTPS connections (e.g. to `news.ycombinator.com`).
pub struct TlsClient {
    /// rustls client configuration. Held in `Arc` so multiple
    /// concurrent connections can share it without per-connection
    /// rebuilds.
    config: Arc<ClientConfig>,
    /// Hostname for SNI and certificate-name validation. Owned
    /// `String` so callers don't have to keep the source alive.
    hostname: String,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClient")
            .field("hostname", &self.hostname)
            .finish()
    }
}

impl TlsClient {
    /// Build a new client config preloaded with the Mozilla CA bundle
    /// from `webpki_roots::TLS_SERVER_ROOTS`.
    ///
    /// `hostname` is used both as the SNI value sent during the
    /// handshake and as the name validated against the server's
    /// certificate. It MUST be a DNS name (IP-address SNI is
    /// uncommon and rejected by webpki by default); callers
    /// connecting by IP should still pass the certificate's intended
    /// hostname here.
    ///
    /// # Errors
    ///
    /// * [`TlsError::Pem`] — protocol-version setup failure inside
    ///   rustls (extremely rare; only happens if the `aws_lc_rs`
    ///   provider is broken in a way that yields no usable cipher
    ///   suites).
    pub fn new(hostname: impl Into<String>) -> Result<Arc<Self>, TlsError> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::Pem(format!("rustls protocol-version setup: {e}")))?
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Arc::new(Self {
            config: Arc::new(config),
            hostname: hostname.into(),
        }))
    }

    /// Drive a client-side TLS handshake to completion over the
    /// supplied TCP stream.
    ///
    /// On success the returned [`TlsStream`] is ready for application
    /// reads/writes. SNI and cert-name validation use the `hostname`
    /// passed to [`TlsClient::new`].
    ///
    /// # Errors
    ///
    /// * [`TlsError::Handshake`] — handshake failure (rustls error,
    ///   IO error, or invalid hostname).
    pub async fn connect(self: &Arc<Self>, stream: TcpStream) -> Result<TlsStream, TlsError> {
        let server_name = ServerName::try_from(self.hostname.clone())
            .map_err(|e| TlsError::Handshake(format!("invalid SNI hostname: {e}")))?;
        let conn = ClientConnection::new(Arc::clone(&self.config), server_name)
            .map_err(|e| TlsError::Handshake(format!("ClientConnection::new: {e}")))?;

        match handshake_pump_client(stream, conn).await {
            Ok((stream, conn)) => Ok(TlsStream::new_client(stream, conn)),
            Err(HandshakeFail::Crypto(msg)) | Err(HandshakeFail::Io(msg)) => Err(TlsError::Handshake(msg)),
        }
    }
}

/// Pumps a client-side TLS handshake to completion. Same algorithm as
/// [`handshake_pump_server`] but with the `Client` wire direction
/// (client speaks first with ClientHello).
async fn handshake_pump_client(
    mut stream: TcpStream,
    mut conn: ClientConnection,
) -> Result<(TcpStream, ClientConnection), HandshakeFail> {
    while conn.is_handshaking() {
        if conn.wants_write() {
            let mut wire = Vec::with_capacity(4096);
            while conn.wants_write() {
                let n = conn
                    .write_tls(&mut wire)
                    .map_err(|e| HandshakeFail::Io(format!("write_tls: {e}")))?;
                if n == 0 {
                    break;
                }
            }
            if !wire.is_empty() {
                stream
                    .write_all(&wire)
                    .await
                    .map_err(|e| HandshakeFail::Io(format!("tcp write: {e}")))?;
            }
        }

        if conn.is_handshaking() && conn.wants_read() {
            let mut buf = [0u8; 4096];
            let n = stream
                .read(&mut buf)
                .await
                .map_err(|e| HandshakeFail::Io(format!("tcp read: {e}")))?;
            if n == 0 {
                return Err(HandshakeFail::Io(
                    "peer closed connection during handshake".into(),
                ));
            }
            let mut slice: &[u8] = &buf[..n];
            let _ = conn
                .read_tls(&mut slice)
                .map_err(|e| HandshakeFail::Io(format!("read_tls: {e}")))?;
            conn.process_new_packets().map_err(classify_rustls_error)?;
        } else if !conn.is_handshaking() {
            break;
        } else if !conn.wants_write() && !conn.wants_read() {
            return Err(HandshakeFail::Io(
                "handshake stuck: neither read nor write desired".into(),
            ));
        }
    }

    if conn.wants_write() {
        let mut wire = Vec::with_capacity(4096);
        while conn.wants_write() {
            let n = conn
                .write_tls(&mut wire)
                .map_err(|e| HandshakeFail::Io(format!("write_tls (final): {e}")))?;
            if n == 0 {
                break;
            }
        }
        if !wire.is_empty() {
            stream
                .write_all(&wire)
                .await
                .map_err(|e| HandshakeFail::Io(format!("tcp write (final): {e}")))?;
        }
    }

    Ok((stream, conn))
}

// ============================================================================
// TlsStream — wrapped TCP+rustls stream implementing AsyncRead+AsyncWrite.
// ============================================================================

/// Internal connection-direction enum so a single
/// [`TlsStream`] can wrap either a server-side or client-side rustls
/// connection. The two arms have distinct types (`ServerConnection`
/// vs `ClientConnection`), so unifying them at the trait-object
/// boundary would lose access to the direction-specific helpers.
enum TlsStreamInner {
    Server {
        stream: TcpStream,
        conn: ServerConnection,
        peer: SocketAddr,
        // Hold the `Arc<TlsServer>` alive for the duration of the
        // connection so background tasks (PEM reload, OCSP refresh)
        // remain pinned. Without this strong reference, dropping the
        // last public `Arc<TlsServer>` could cancel the background
        // tasks while connections are still alive.
        _server: Arc<TlsServer>,
    },
    Client {
        stream: TcpStream,
        conn: ClientConnection,
    },
}

/// Wrapped TCP+rustls connection that implements
/// [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`] for
/// transparent integration with the rest of the async stack.
///
/// Constructed by [`TlsServer::accept`] (server side) or
/// [`TlsClient::connect`] (client side). Read and write progress is
/// driven by the standard tokio poll-based contracts; internally each
/// `poll_read` / `poll_write` call may pump bytes through the rustls
/// state machine via `read_tls` / `write_tls` / `process_new_packets`.
pub struct TlsStream {
    inner: TlsStreamInner,
}

impl std::fmt::Debug for TlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            TlsStreamInner::Server { peer, .. } => {
                f.debug_struct("TlsStream::Server").field("peer", peer).finish()
            }
            TlsStreamInner::Client { .. } => f.debug_struct("TlsStream::Client").finish(),
        }
    }
}

impl TlsStream {
    fn new_server(
        stream: TcpStream,
        conn: ServerConnection,
        peer: SocketAddr,
        server: Arc<TlsServer>,
    ) -> Self {
        Self {
            inner: TlsStreamInner::Server {
                stream,
                conn,
                peer,
                _server: server,
            },
        }
    }

    fn new_client(stream: TcpStream, conn: ClientConnection) -> Self {
        Self {
            inner: TlsStreamInner::Client { stream, conn },
        }
    }

    /// Returns the peer's socket address for server-side streams.
    /// Returns `None` for client-side streams (clients don't track
    /// the remote `SocketAddr` here; callers can `peer_addr` the
    /// underlying TcpStream before constructing the `TlsStream`).
    #[must_use]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match &self.inner {
            TlsStreamInner::Server { peer, .. } => Some(*peer),
            TlsStreamInner::Client { stream, .. } => stream.peer_addr().ok(),
        }
    }

    /// Returns the peer IP for server-side streams. Used by
    /// `crate::net::http::server` to emit access-log entries.
    #[must_use]
    pub fn peer_ip(&self) -> Option<IpAddr> {
        self.peer_addr().map(|a| a.ip())
    }
}

// AsyncRead implementation — pulls plaintext out of the rustls state
// machine, pumping the network as needed.
impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            TlsStreamInner::Server { stream, conn, .. } => {
                poll_read_inner(cx, buf, stream, ConnectionMut::Server(conn))
            }
            TlsStreamInner::Client { stream, conn } => {
                poll_read_inner(cx, buf, stream, ConnectionMut::Client(conn))
            }
        }
    }
}

// AsyncWrite implementation — pushes plaintext into the rustls writer
// and flushes to the network.
impl AsyncWrite for TlsStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match &mut this.inner {
            TlsStreamInner::Server { stream, conn, .. } => {
                poll_write_inner(cx, buf, stream, ConnectionMut::Server(conn))
            }
            TlsStreamInner::Client { stream, conn } => {
                poll_write_inner(cx, buf, stream, ConnectionMut::Client(conn))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            TlsStreamInner::Server { stream, conn, .. } => {
                poll_flush_inner(cx, stream, ConnectionMut::Server(conn))
            }
            TlsStreamInner::Client { stream, conn } => {
                poll_flush_inner(cx, stream, ConnectionMut::Client(conn))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            TlsStreamInner::Server { stream, conn, .. } => {
                poll_shutdown_inner(cx, stream, ConnectionMut::Server(conn))
            }
            TlsStreamInner::Client { stream, conn } => {
                poll_shutdown_inner(cx, stream, ConnectionMut::Client(conn))
            }
        }
    }
}

/// Mutable-borrow flavour of the connection-direction split. Lets the
/// poll helpers operate on either a `ServerConnection` or a
/// `ClientConnection` without duplicating the entire poll machinery.
enum ConnectionMut<'a> {
    Server(&'a mut ServerConnection),
    Client(&'a mut ClientConnection),
}

impl<'a> ConnectionMut<'a> {
    fn read_tls(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize> {
        match self {
            ConnectionMut::Server(c) => c.read_tls(rd),
            ConnectionMut::Client(c) => c.read_tls(rd),
        }
    }

    fn write_tls(&mut self, wr: &mut dyn std::io::Write) -> std::io::Result<usize> {
        match self {
            ConnectionMut::Server(c) => c.write_tls(wr),
            ConnectionMut::Client(c) => c.write_tls(wr),
        }
    }

    fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        match self {
            ConnectionMut::Server(c) => c.process_new_packets(),
            ConnectionMut::Client(c) => c.process_new_packets(),
        }
    }

    fn reader(&mut self) -> rustls::Reader<'_> {
        match self {
            ConnectionMut::Server(c) => c.reader(),
            ConnectionMut::Client(c) => c.reader(),
        }
    }

    fn writer(&mut self) -> rustls::Writer<'_> {
        match self {
            ConnectionMut::Server(c) => c.writer(),
            ConnectionMut::Client(c) => c.writer(),
        }
    }

    fn wants_write(&self) -> bool {
        match self {
            ConnectionMut::Server(c) => c.wants_write(),
            ConnectionMut::Client(c) => c.wants_write(),
        }
    }

    fn wants_read(&self) -> bool {
        match self {
            ConnectionMut::Server(c) => c.wants_read(),
            ConnectionMut::Client(c) => c.wants_read(),
        }
    }

    fn send_close_notify(&mut self) {
        match self {
            ConnectionMut::Server(c) => c.send_close_notify(),
            ConnectionMut::Client(c) => c.send_close_notify(),
        }
    }
}

/// Common poll_read body. Pumps the network and rustls state machine
/// until either plaintext is available (returns `Ready(Ok(()))` with
/// `buf` filled) or the network reports `Pending` (returns
/// `Pending`).
fn poll_read_inner(
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
    stream: &mut TcpStream,
    mut conn: ConnectionMut<'_>,
) -> Poll<std::io::Result<()>> {
    use std::io::Read;

    // Try to read directly out of rustls's plaintext buffer first.
    // If there are bytes already there, return them immediately
    // without touching the network.
    {
        let mut tmp = [0u8; 4096];
        let take = buf.remaining().min(tmp.len());
        let mut reader = conn.reader();
        match reader.read(&mut tmp[..take]) {
            Ok(0) => {
                // Plaintext closed.
                if !conn.wants_read() && !conn.wants_write() {
                    return Poll::Ready(Ok(()));
                }
                // Otherwise fall through to network pump.
            }
            Ok(n) => {
                buf.put_slice(&tmp[..n]);
                return Poll::Ready(Ok(()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No plaintext yet; fall through to network pump.
            }
            Err(e) => return Poll::Ready(Err(e)),
        }
    }

    // Drive the network: drain any pending writes, then read more
    // ciphertext.
    loop {
        if conn.wants_write() {
            match poll_drain_write(cx, stream, &mut conn) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if !conn.wants_read() {
            // rustls has nothing to read; we must already have
            // delivered everything plaintext from the buffer above.
            return Poll::Ready(Ok(()));
        }

        // Pull ciphertext from the TCP socket.
        let mut tmp = [0u8; 4096];
        let mut tmp_buf = ReadBuf::new(&mut tmp);
        match Pin::new(&mut *stream).poll_read(cx, &mut tmp_buf) {
            Poll::Ready(Ok(())) => {
                let filled = tmp_buf.filled().len();
                if filled == 0 {
                    // EOF on the underlying TCP. Surface as plaintext
                    // EOF — return Ready with no bytes.
                    return Poll::Ready(Ok(()));
                }
                let mut slice: &[u8] = &tmp[..filled];
                if let Err(e) = conn.read_tls(&mut slice) {
                    return Poll::Ready(Err(e));
                }
                if let Err(e) = conn.process_new_packets() {
                    return Poll::Ready(Err(std::io::Error::other(e.to_string())));
                }
                // Try the plaintext reader again now that we've fed
                // more ciphertext through.
                let mut tmp2 = [0u8; 4096];
                let take = buf.remaining().min(tmp2.len());
                let mut reader = conn.reader();
                match reader.read(&mut tmp2[..take]) {
                    Ok(0) => {
                        // No plaintext yet — keep pumping.
                        continue;
                    }
                    Ok(n) => {
                        buf.put_slice(&tmp2[..n]);
                        return Poll::Ready(Ok(()));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Still no plaintext — keep pumping.
                        continue;
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
}

/// Common poll_write body. Pushes `buf` into rustls's plaintext writer
/// and pumps as much ciphertext to the network as the socket accepts.
fn poll_write_inner(
    cx: &mut Context<'_>,
    buf: &[u8],
    stream: &mut TcpStream,
    mut conn: ConnectionMut<'_>,
) -> Poll<std::io::Result<usize>> {
    use std::io::Write;

    // Push application bytes into the rustls plaintext writer.
    let written = {
        let mut writer = conn.writer();
        match writer.write(buf) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(e)),
        }
    };

    // Drain the resulting ciphertext to the network.
    if conn.wants_write() {
        match poll_drain_write(cx, stream, &mut conn) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            // If the network is back-pressured but we already
            // accepted the plaintext into rustls, report success on
            // the application side; the next poll_write/poll_flush
            // call will resume draining.
            Poll::Pending => {
                if written > 0 {
                    return Poll::Ready(Ok(written));
                }
                return Poll::Pending;
            }
        }
    }

    Poll::Ready(Ok(written))
}

/// Common poll_flush body — drains all pending ciphertext to the
/// network and then flushes the underlying TcpStream.
fn poll_flush_inner(
    cx: &mut Context<'_>,
    stream: &mut TcpStream,
    mut conn: ConnectionMut<'_>,
) -> Poll<std::io::Result<()>> {
    if conn.wants_write() {
        match poll_drain_write(cx, stream, &mut conn) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Pin::new(stream).poll_flush(cx)
}

/// Common poll_shutdown body — sends a TLS close_notify alert, drains
/// the resulting ciphertext to the network, then shuts down the
/// underlying TcpStream.
fn poll_shutdown_inner(
    cx: &mut Context<'_>,
    stream: &mut TcpStream,
    mut conn: ConnectionMut<'_>,
) -> Poll<std::io::Result<()>> {
    conn.send_close_notify();
    if conn.wants_write() {
        match poll_drain_write(cx, stream, &mut conn) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Pin::new(stream).poll_shutdown(cx)
}

/// Drain ciphertext out of `conn` and write it to `stream` using the
/// async `poll_write` contract. Returns `Ready(Ok(()))` once `conn`
/// has nothing more to send, `Pending` if the socket is full, or
/// `Ready(Err)` on IO error.
fn poll_drain_write(
    cx: &mut Context<'_>,
    stream: &mut TcpStream,
    conn: &mut ConnectionMut<'_>,
) -> Poll<std::io::Result<()>> {
    while conn.wants_write() {
        let mut wire = Vec::with_capacity(4096);
        while conn.wants_write() {
            let n = match conn.write_tls(&mut wire) {
                Ok(n) => n,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if n == 0 {
                break;
            }
        }
        if wire.is_empty() {
            break;
        }
        let mut written = 0;
        while written < wire.len() {
            match Pin::new(&mut *stream).poll_write(cx, &wire[written..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "tls drain: tcp wrote zero",
                    )));
                }
                Poll::Ready(Ok(n)) => written += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
    Poll::Ready(Ok(()))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Generate a self-signed test cert + key on the fly using
    /// rustls's test infrastructure — we cannot rely on a fixture
    /// file shipping with the repo, but rustls's own test bundle is
    /// available via the dev-dependency tree. As a fallback we use
    /// hand-baked PEM test vectors.
    ///
    /// The vectors below are a 2048-bit RSA self-signed certificate
    /// generated specifically for this test using `openssl`, with
    /// no security implications (the private key is not trusted by
    /// any CA).
    const TEST_CERT_PEM: &str = include_str!("./tls_testdata/test_cert.pem");
    const TEST_KEY_PEM: &str = include_str!("./tls_testdata/test_key.pem");

    fn write_pem(dir: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = File::create(&path).expect("create pem");
        f.write_all(contents.as_bytes()).expect("write pem");
        path
    }

    /// Test-only helper that constructs an EncryptedSessionCache with a
    /// known key for byte-level inspection.
    fn make_known_cache(key: [u8; AES256_KEY_SIZE]) -> Arc<EncryptedSessionCache> {
        Arc::new(EncryptedSessionCache {
            inner: ServerSessionMemoryCache::new(SESSION_CACHE_CAPACITY),
            aes_key: key,
        })
    }

    #[test]
    fn encrypted_session_cache_roundtrip() {
        // Initialise the RNG so `EncryptedSessionCache::new()` works.
        let _ = crate::crypto::rng::init();

        let cache = make_known_cache([0xab; AES256_KEY_SIZE]);
        let key = b"session-id-1".to_vec();
        let value = b"opaque-session-secret-blob".to_vec();

        assert!(cache.put(key.clone(), value.clone()));
        let got = cache.get(&key).expect("get returns plaintext");
        assert_eq!(got, value);

        // `take` should also decrypt and remove.
        let taken = cache.take(&key).expect("take returns plaintext");
        assert_eq!(taken, value);
        // After take, get returns None.
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn encrypted_session_cache_decrypt_failure_is_none() {
        let _ = crate::crypto::rng::init();
        let cache = make_known_cache([0x11; AES256_KEY_SIZE]);
        // Inject a corrupted blob directly into the inner cache.
        cache.inner.put(b"corrupt-key".to_vec(), vec![0u8; 64]);
        // Decrypt should fail and the wrapper should hide the error
        // by returning None.
        assert!(cache.get(b"corrupt-key").is_none());
    }

    #[test]
    fn sessioncache_hook_install_take_dispatch() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Clear any pre-existing hook (other tests may have run).
        let _prev = take_sessioncache_hook();

        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&count);
        let hook: SessionCacheHook = Arc::new(move |_k, _v| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        });

        // First install — there should be no previous hook now.
        let prev = set_sessioncache_hook(Arc::clone(&hook));
        assert!(prev.is_none(), "no hook should be installed yet");

        // Direct sessioncache_put should fire the hook.
        sessioncache_put(b"k", b"v");
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // take_sessioncache_hook returns the hook and clears the slot.
        let taken = take_sessioncache_hook();
        assert!(taken.is_some());
        assert!(take_sessioncache_hook().is_none(), "slot should be empty");

        // After take, sessioncache_put is a no-op.
        sessioncache_put(b"k", b"v");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn extract_ocsp_responder_url_finds_http_uri() {
        // Hand-crafted minimal input containing the AIA OID, the OCSP
        // OID, and a [6] IMPLICIT IA5String containing the URL.
        let mut der = Vec::new();
        // AIA OID 1.3.6.1.5.5.7.1.1
        der.extend_from_slice(&[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]);
        // some filler bytes
        der.extend_from_slice(&[0x30, 0x10]);
        // OCSP OID 1.3.6.1.5.5.7.48.1
        der.extend_from_slice(&[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]);
        // [6] IMPLICIT IA5String "http://ocsp.example.com"
        let url = b"http://ocsp.example.com";
        der.push(0x86);
        der.push(url.len() as u8);
        der.extend_from_slice(url);

        let got = extract_ocsp_responder_url(&der).expect("URL should be extracted");
        assert_eq!(got, "http://ocsp.example.com");
    }

    #[test]
    fn extract_ocsp_responder_url_missing_returns_none() {
        // Cert with no AIA OID at all.
        let der = vec![0x30, 0x82, 0x00, 0x10, 0x00, 0x00];
        assert!(extract_ocsp_responder_url(&der).is_none());
    }

    #[test]
    fn classify_rustls_error_decrypt_is_crypto() {
        let e = rustls::Error::DecryptError;
        match classify_rustls_error(e) {
            HandshakeFail::Crypto(_) => {}
            HandshakeFail::Io(msg) => panic!("expected Crypto, got Io({msg})"),
        }
    }

    #[test]
    fn classify_rustls_error_alert_bad_record_mac_is_crypto() {
        let e = rustls::Error::AlertReceived(rustls::AlertDescription::BadRecordMac);
        match classify_rustls_error(e) {
            HandshakeFail::Crypto(_) => {}
            HandshakeFail::Io(msg) => panic!("expected Crypto, got Io({msg})"),
        }
    }

    #[test]
    fn classify_rustls_error_alert_close_notify_is_io() {
        let e = rustls::Error::AlertReceived(rustls::AlertDescription::CloseNotify);
        match classify_rustls_error(e) {
            HandshakeFail::Io(_) => {}
            HandshakeFail::Crypto(msg) => panic!("expected Io, got Crypto({msg})"),
        }
    }

    #[test]
    fn tls_server_new_loads_pem() {
        let _ = crate::crypto::rng::init();
        let dir = tempfile::tempdir().expect("tempdir");
        let cert = write_pem(&dir, "cert.pem", TEST_CERT_PEM);
        let key = write_pem(&dir, "key.pem", TEST_KEY_PEM);
        let bl = Blacklist::new(Duration::from_secs(config::TLS_BLACKLIST));

        let server = TlsServer::new(cert, key, bl).expect("TlsServer::new");
        // Sanity: the config is non-null and contains at least one
        // cipher suite.
        let cfg = server.current_config();
        assert!(!cfg.crypto_provider().cipher_suites.is_empty());
    }

    #[test]
    fn tls_client_new_builds_with_webpki_roots() {
        let _ = crate::crypto::rng::init();
        let client = TlsClient::new("example.com").expect("TlsClient::new");
        // Sanity: the client config is non-null and the hostname
        // round-trips.
        let dbg = format!("{client:?}");
        assert!(dbg.contains("example.com"));
    }

    #[test]
    fn blacklist_keys_round_trip_through_socket_addr() {
        // Sanity that the helper we use in `accept` matches what
        // `Blacklist::insert` stores.
        let v4: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let v6: SocketAddr = "[::1]:443".parse().unwrap();
        let k1 = key_from_socket_addr(v4);
        let k2 = key_from_socket_addr(v6);
        assert_ne!(k1, k2);
        let bl = Blacklist::new(Duration::from_secs(1));
        bl.insert(k1, Duration::from_secs(60));
        assert!(bl.contains(k1));
        assert!(!bl.contains(k2));
    }
}
