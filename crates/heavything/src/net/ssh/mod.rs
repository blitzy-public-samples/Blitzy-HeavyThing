// HeavyThing x86_64 assembly language library and showcase programs
// Copyright © 2015 2 Ton Digital
//
// Homepage: https://2ton.com.au/
// Author: Jeff Marrison <jeff@2ton.com.au>
//
// This file is part of the HeavyThing library.
//
// The HeavyThing library is free software: you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// version 3 as published by the Free Software Foundation.
//
// The HeavyThing library is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the implied warranty
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License version 3 for more details.
//
// You should have received a copy of the GNU General Public License
// version 3 along with the HeavyThing library.  If not, see
// <https://www.gnu.org/licenses/>.
//
// Rust translation © 2026, licensed under GPL-3.0-or-later.

//! # SSH 2.0 Protocol Subsystem
//!
//! Rust port of the HeavyThing FASM `ssh.inc` file (6011 lines). Provides a
//! complete SSH 2.0 transport-layer + user-auth + connection-layer
//! implementation suitable for use as both a **server** (accepting inbound
//! SSH connections — used by the `sshtalk` binary crate) and a **client**
//! (initiating outbound SSH connections — reserved; not currently exercised
//! by in-scope binaries).
//!
//! ## Deliberate Protocol-Design Decisions (Inherited from FASM)
//!
//! The original HeavyThing SSH implementation deliberately constrains itself
//! to the following subset of RFC 4253. The Rust port preserves these
//! constraints byte-for-byte per AAP §0.8.1 and §0.8.9. The constraints are
//! visible in the FASM source itself (`ssh.inc` lines 22–84), where the
//! author calls them out as a "narrow-minded selection" of suites:
//!
//! - **Key Exchange**: `diffie-hellman-group-exchange-sha256` only. No
//!   `curve25519-sha256`, no `diffie-hellman-group14-sha256`, no ECDH. The
//!   FASM source intentionally omits elliptic-curve cryptography; the Rust
//!   port respects that.
//! - **Host Key Types**: `ssh-rsa` and `ssh-dss` only. No Ed25519, no ECDSA.
//! - **Encryption**: `aes256-cbc` only (both directions). No AES-GCM AEAD.
//! - **MAC**: `hmac-sha2-256` only. No Encrypt-then-MAC, no `hmac-sha1`.
//! - **Compression**: `zlib@openssh.com` (delayed) preferred; `zlib`
//!   (immediate) and `none` accepted. When
//!   [`crate::config::SSH_FORCE_COMPRESSION`] is true (the default), sessions
//!   without mutual compression support are refused.
//! - **Authentication**: `password` method only. No public-key auth, no
//!   GSSAPI. The keyboard-interactive method is supported on the *client*
//!   side as a transport for the password but the server side accepts only
//!   `password`-method requests.
//! - **Channel Types**: `session` only. No `direct-tcpip`, no
//!   `forwarded-tcpip`, no `x11`.
//! - **Subsystems**: `shell`, `exec`, and `sftp` subsystem requests are
//!   accepted (client-side API); the server only services `shell` and
//!   `exec`.
//!
//! ## CBC-Oracle Mitigation
//!
//! The FASM source highlights (`ssh.inc` lines 46–58) two compensations for
//! the Albrecht/Paterson/Watson 14-bit plaintext-recovery weakness in
//! SSH-CBC. The Rust port inherits both:
//!
//! 1. On HMAC failure, the receiver does not reply at all and treats the
//!    bad packet as a request to wait a random amount of time before tearing
//!    the connection down — making it impossible for the attacker to
//!    distinguish a length error from a MAC error by timing.
//! 2. In client mode, an `SSH_MSG_IGNORE` (2) carrying random-length data
//!    is injected immediately before the password is transmitted, smearing
//!    the password's CBC-block boundary across an attacker-unobservable
//!    offset.
//!
//! Both mitigations live in the [`server`] submodule's receive loop and are
//! reachable via the [`SshError::Cipher`] failure path.
//!
//! ## Frozen Banner
//!
//! The server identification string is byte-identical to the FASM source
//! (`ssh.inc` line 99 — `db 'SSH-2.0-HeavyThing', 13, 10`):
//!
//! ```text
//! SSH-2.0-HeavyThing\r\n
//! ```
//!
//! per RFC 4253 §4.2. This is a user-visible protocol field and must not be
//! altered.
//!
//! ## Architecture
//!
//! The subsystem is decomposed into five files:
//!
//! - [`compression`] — zlib streams (wraps `flate2`); compression-state FSM
//!   for both `zlib` (immediate) and `zlib@openssh.com` (delayed) modes.
//! - [`cipher`] — AES-256-CBC block cipher + HMAC-SHA-256 MAC; SSH binary
//!   packet framing helpers.
//! - [`kex`] — Diffie-Hellman Group-Exchange-SHA256; RSA/DSS sign + verify;
//!   session-key derivation per RFC 4253 §7.2.
//! - [`auth`] — auth callback registration; [`AuthCallback`],
//!   [`AuthArgs`], [`AuthOutcome`]; the 11 user-auth and connection-layer
//!   `SSH_MSG_*` wire constants used during userauth.
//! - [`server`] — [`SshSession`], [`SshServer`], [`SshChannel`], the full
//!   14-stage [`SshStage`] state machine, and the per-message dispatch
//!   table.
//!
//! ## Integration Contract with `tui::widgets::ssh`
//!
//! The TUI renderer for SSH sessions lives in [`crate::tui::widgets::ssh`]
//! (a separate subsystem, not a child of this module). That module defines
//! the `SshTransport` trait whose `send_bytes` / `set_window_size` /
//! `remote_addr` methods are implemented by [`SshChannel`] so that the TUI
//! widget renderer can write ANSI bytes directly through the SSH
//! `SSH_MSG_CHANNEL_DATA` (94) subprotocol. Consumers may coerce
//! `Arc<SshChannel>` → `Arc<dyn SshTransport>` at their use sites
//! (typically in `crates/sshtalk/src/screen.rs`).
//!
//! ## Usage
//!
//! ```ignore
//! use heavything::net::ssh::{SshServer, SshConfig};
//!
//! let cfg = SshConfig::default();
//! let _server = SshServer::new(cfg).with_auth(|user, pass| {
//!     user == "alice" && pass == "letmein"
//! });
//! // In an async context the caller drives `_server` through a
//! // `tokio::net::TcpListener::accept` loop; per-connection state
//! // is owned by an `SshSession` spawned via `tokio::spawn`.
//! ```
//!
//! ## Errors
//!
//! All operations in this subsystem return `Result<_, SshError>` (or
//! `Result<_, NetError>` at the outer layer where the `?` operator
//! transparently lifts via `#[from]`). [`SshError`] is re-exported here
//! from the crate-level error module ([`crate::error::SshError`]) so
//! consumers can write `use crate::net::ssh::SshError;` without reaching
//! across subsystem boundaries.
//!
//! ## `unsafe` Audit
//!
//! Zero `unsafe` blocks across all five sibling submodules and this
//! aggregator. Memory safety derives entirely from `aes` (raw AES-256
//! block cipher), `ring::hmac` (HMAC-SHA-256), `ring::digest` (SHA-256),
//! `ring::signature` (RSA signing), `flate2` (zlib streaming), and
//! `num-bigint` (DSA + DH modular arithmetic) — every one of which
//! exposes a fully safe public API. See `UNSAFE_AUDIT.md` at the repository
//! root for the per-site audit (AAP §0.7.4).
//!
//! ## References
//!
//! - RFC 4253 — The Secure Shell (SSH) Transport Layer Protocol
//! - RFC 4252 — The Secure Shell (SSH) Authentication Protocol
//! - RFC 4254 — The Secure Shell (SSH) Connection Protocol
//! - RFC 4419 — Diffie-Hellman Group Exchange for the SSH Transport Layer
//!              Protocol
//! - RFC 4256 — Generic Message Exchange Authentication for SSH
//!              (keyboard-interactive)
//! - HeavyThing FASM source: `ssh.inc` (the ported files preserve GPLv3
//!   attribution to 2 Ton Digital / Jeff Marrison)

// ===========================================================================
// Sibling submodule declarations (alphabetical for readability; Rust resolves
// dependency order at the compiler level).
// ===========================================================================

/// SSH 2.0 authentication-protocol layer — userauth frame parsing,
/// callback invocation, and frame construction. Port of the
/// authentication fragments of `ssh.inc` (`.got_userauth_*`,
/// `.got_service*`, `.got_ignore`, and callback registration
/// `ssh$set_authcb`).
pub mod auth;

/// AES-256-CBC encryption + HMAC-SHA-256 MAC for the SSH transport layer.
/// Port of the cipher / MAC fragments of `ssh.inc`. Owns the per-direction
/// [`CipherState`] type and the packet-framing helpers used by [`server`].
pub mod cipher;

/// zlib compression / decompression for the SSH transport layer. Port of
/// the compression fragments of `ssh.inc`, implementing both `zlib`
/// (immediate) and `zlib@openssh.com` (delayed-until-userauth) negotiation
/// behaviours.
pub mod compression;

/// `diffie-hellman-group-exchange-sha256` key exchange, six-key derivation
/// per RFC 4253 §7.2, and `ssh-rsa` / `ssh-dss` host-key signature
/// emission and verification. Port of the KEX fragments of `ssh.inc`
/// (`.got_kexinit`, `.got_kexgexreq`, `.got_kexgexgroup`,
/// `.got_kexgexinit`, `.got_kexgexreply`, `.keycalc`).
pub mod kex;

/// Top-level SSH state machine — port of the `ssh.inc` per-connection
/// protocol logic, integrating the [`auth`], [`cipher`], [`compression`],
/// and [`kex`] submodules into a single [`server::SshSession`] type plus
/// its `SshServer` listener factory and `SshChannel` outward-facing
/// handle.
pub mod server;

// ===========================================================================
// SshError re-export (canonical definition lives in `crate::error`).
//
// The crate-wide error taxonomy is defined in `crate::error` (see
// `error.rs` lines 269–299). That layout is enforced by the `#[from]`
// attribute on the `NetError::Ssh` variant, which requires `SshError` to
// be in scope where `NetError` is defined. We re-export here so consumers
// can write `use crate::net::ssh::SshError;` and stay within the
// `net::ssh` import path without having to reach across subsystem
// boundaries.
//
// Per AAP §0.5.1 / §0.6.3.1 the import discipline is to keep file imports
// scoped to the closest module that owns the type. The re-export below
// honours that for downstream consumers without changing the canonical
// definition site.
// ===========================================================================

/// Errors produced by the SSH subsystem.
///
/// Re-exported from [`crate::error::SshError`] so consumers can use a
/// single `use crate::net::ssh::SshError;` path. The variant taxonomy is
/// kept narrow (5 variants — `KeyExchange`, `Auth`, `Cipher`,
/// `Compression`, `HostKeys`) on purpose: every distinct user-visible SSH
/// failure mode that the FASM `ssh.inc` source surfaces collapses into
/// one of those five categories. Wider sub-categorisation is recorded in
/// the `String` payload of the `KeyExchange` / `Compression` /
/// `HostKeys` variants and in the `tracing::error!` events emitted by
/// the sibling submodules.
///
/// Conversion into the crate-wide [`crate::error::NetError`] is provided
/// automatically by `thiserror`'s `#[from]` derive on the
/// [`crate::error::NetError::Ssh`] variant — call sites returning
/// `Result<_, NetError>` can use `?` directly on `Result<_, SshError>`
/// without an explicit `.map_err(NetError::Ssh)`.
pub use crate::error::SshError;

/// Convenience type alias for fallible SSH-subsystem operations.
///
/// Equivalent to `std::result::Result<T, SshError>`. Used internally by
/// the [`auth`] submodule and exposed publicly so external callers can
/// write idiomatic signatures without re-stating the error type.
///
/// # Example
///
/// ```ignore
/// use heavything::net::ssh::{SshResult, SshError};
///
/// fn parse_packet(_buf: &[u8]) -> SshResult<()> {
///     Err(SshError::Cipher)
/// }
/// ```
pub type SshResult<T> = std::result::Result<T, SshError>;

// ===========================================================================
// Re-exports — server submodule (primary user-facing types).
//
// These types form the public API surface of the SSH server. Consumers
// should write `use crate::net::ssh::{SshServer, SshConfig, SshSession,
// SshChannel};` and avoid reaching into `crate::net::ssh::server::*`
// directly.
// ===========================================================================

pub use self::server::{
    ClientMode, SshChannel, SshConfig, SshServer, SshSession, SshStage, SSH_IDENT, SSH_IDENT_LEN,
};

// ===========================================================================
// Re-exports — auth submodule (authentication-protocol API).
//
// We re-export the three top-level types ([`AuthCallback`],
// [`AuthOutcome`], [`AuthArgs`]) plus the 11 SSH_MSG_* wire-format
// constants relevant to userauth and the first connection-layer message
// (`SSH_MSG_CHANNEL_OPEN` = 90). The remaining 18 connection-layer and
// disconnect message constants (`SSH_MSG_DISCONNECT`,
// `SSH_MSG_CHANNEL_DATA`, ...) live in [`server`] as `pub(crate)` items
// because they are dispatch-table internals, not part of the public API.
// ===========================================================================

pub use self::auth::{
    AuthArgs, AuthCallback, AuthOutcome, SSH_MSG_CHANNEL_OPEN, SSH_MSG_DEBUG, SSH_MSG_IGNORE,
    SSH_MSG_SERVICE_ACCEPT, SSH_MSG_SERVICE_REQUEST, SSH_MSG_USERAUTH_BANNER, SSH_MSG_USERAUTH_FAILURE,
    SSH_MSG_USERAUTH_INFO_REQUEST, SSH_MSG_USERAUTH_INFO_RESPONSE, SSH_MSG_USERAUTH_REQUEST,
    SSH_MSG_USERAUTH_SUCCESS,
};

// ===========================================================================
// Re-exports — cipher submodule.
//
// [`CipherState`] is the canonical per-direction cipher + MAC context.
// External consumers rarely need it (the [`server`] submodule owns the
// in/out instances), but it is re-exported so integration-test callers
// in `crates/heavything/tests/` can construct one for known-answer-vector
// tests against the FASM baseline.
// ===========================================================================

pub use self::cipher::CipherState;

// ===========================================================================
// Re-exports — compression submodule.
//
// External consumers rarely interact with these directly; the
// [`server::SshSession`] manages compression state internally. Re-exports
// are provided for integration tests and for advanced users who want to
// drive compression independently of the SSH transport layer.
// ===========================================================================

pub use self::compression::{CompressionState, DeflateStream, InflateStream};

// ===========================================================================
// Re-exports — kex submodule.
//
// [`KexHashBuilder`] is exposed for integration tests that build the
// exchange-hash `H` independently of a live session. The signing /
// verification helpers ([`sign_rsa`], [`sign_dss`], [`verify_signature`])
// are exposed for the same reason and for downstream consumers who wish
// to validate signatures over user-supplied data without driving a full
// SSH handshake.
//
// The 6 KEX-layer SSH_MSG_* constants are re-exported alongside their
// kex helpers — these are the message types that flow through the
// [`SshStage::WantKexInit`] → [`SshStage::WantNewKeys`] portion of the
// state machine.
// ===========================================================================

pub use self::kex::{
    sign_dss, sign_rsa, verify_signature, KexHashBuilder, SSH_MSG_KEXINIT, SSH_MSG_KEX_DH_GEX_GROUP,
    SSH_MSG_KEX_DH_GEX_INIT, SSH_MSG_KEX_DH_GEX_REPLY, SSH_MSG_KEX_DH_GEX_REQUEST, SSH_MSG_NEWKEYS,
};

// ===========================================================================
// Unit tests — re-export wiring + protocol-constant sanity.
//
// These tests do NOT exercise SSH protocol logic (the sibling submodules
// own those tests). Their sole purpose is to fail loudly during local
// `cargo test` if a re-export ever drifts out of alignment with the
// underlying definition site, or if a wire-format constant is silently
// renumbered.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Typecheck — the [`SshConfig::default`] and [`SshServer::new`] entry
    /// points are reachable via this module's re-exports. Compilation
    /// alone proves the module tree is wired correctly; the function
    /// pointers exist purely to anchor the type assertions.
    #[test]
    fn submodules_are_reachable() {
        let _: fn() -> SshConfig = SshConfig::default;
        let _: fn(SshConfig) -> SshServer = SshServer::new;
    }

    /// Verify that every variant of [`SshError`] is constructable through
    /// the re-exported alias. If `crate::error::SshError` ever loses or
    /// renames a variant, this test fails before the rest of the SSH
    /// stack does.
    #[test]
    fn ssh_error_variants_constructable() {
        let _ = SshError::KeyExchange("kex failed".to_string());
        let _ = SshError::Auth;
        let _ = SshError::Cipher;
        let _ = SshError::Compression("zlib failed".to_string());
        let _ = SshError::HostKeys("/etc/ssh missing".to_string());
    }

    /// Verify [`SshError`] produces non-empty Display output for every
    /// variant. `thiserror`'s `#[error("...")]` attribute MUST yield a
    /// human-readable string; an empty Display impl would be a
    /// regression.
    #[test]
    fn ssh_error_display_nonempty() {
        let errors = [
            SshError::KeyExchange("kex".into()),
            SshError::Auth,
            SshError::Cipher,
            SshError::Compression("zlib".into()),
            SshError::HostKeys("missing".into()),
        ];
        for e in &errors {
            let msg = format!("{}", e);
            assert!(!msg.is_empty(), "SshError {:?} produced empty Display", e);
        }
    }

    /// Verify [`SshError`] implements [`std::error::Error`] (delivered by
    /// `thiserror::Error`). This contract is required for `?`-propagation
    /// through `Box<dyn Error>` and `anyhow::Error` boundaries in the
    /// binary crates.
    #[test]
    fn ssh_error_impls_std_error() {
        fn is_error<E: std::error::Error>(_: &E) {}
        let e = SshError::Auth;
        is_error(&e);
    }

    /// Verify [`SshError`] is `Send + Sync`. The tokio runtime requires
    /// any error returned across an `await` point to satisfy these auto
    /// traits; if one of `crate::error::SshError`'s payloads ever
    /// becomes non-`Send` or non-`Sync`, this test will fail at compile
    /// time.
    #[test]
    fn ssh_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SshError>();
    }

    /// Verify [`SshError`] flows through `?` into [`crate::error::NetError`]
    /// without an explicit `.map_err`. This is the contract that keeps
    /// the call-site code path in [`server`] readable.
    #[test]
    fn ssh_error_flows_into_net_error() {
        use crate::error::NetError;
        fn returns_net_error() -> Result<(), NetError> {
            Err::<(), _>(SshError::Auth)?;
            Ok(())
        }
        assert!(matches!(returns_net_error(), Err(NetError::Ssh(SshError::Auth))));
    }

    /// Verify the [`SshResult`] alias resolves correctly.
    #[test]
    fn ssh_result_alias_works() {
        fn ok_one() -> SshResult<u32> {
            Ok(1)
        }
        fn err_one() -> SshResult<u32> {
            Err(SshError::Auth)
        }
        assert_eq!(ok_one().unwrap(), 1);
        assert!(matches!(err_one(), Err(SshError::Auth)));
    }

    /// Verify the auth-submodule SSH_MSG_* constants are reachable via
    /// the re-export and carry their RFC-mandated wire numbers.
    /// Numbers per RFC 4252 §6 + RFC 4253 §12 + RFC 4254 §9.
    #[test]
    fn ssh_msg_auth_constants_reachable() {
        assert_eq!(SSH_MSG_IGNORE, 2);
        assert_eq!(SSH_MSG_DEBUG, 4);
        assert_eq!(SSH_MSG_SERVICE_REQUEST, 5);
        assert_eq!(SSH_MSG_SERVICE_ACCEPT, 6);
        assert_eq!(SSH_MSG_USERAUTH_REQUEST, 50);
        assert_eq!(SSH_MSG_USERAUTH_FAILURE, 51);
        assert_eq!(SSH_MSG_USERAUTH_SUCCESS, 52);
        assert_eq!(SSH_MSG_USERAUTH_BANNER, 53);
        assert_eq!(SSH_MSG_USERAUTH_INFO_REQUEST, 60);
        assert_eq!(SSH_MSG_USERAUTH_INFO_RESPONSE, 61);
        assert_eq!(SSH_MSG_CHANNEL_OPEN, 90);
    }

    /// Verify the kex-submodule SSH_MSG_* constants are reachable via
    /// the re-export and carry their RFC-mandated wire numbers per
    /// RFC 4253 §12 and RFC 4419 §5.
    #[test]
    fn ssh_msg_kex_constants_reachable() {
        assert_eq!(SSH_MSG_KEXINIT, 20);
        assert_eq!(SSH_MSG_NEWKEYS, 21);
        assert_eq!(SSH_MSG_KEX_DH_GEX_GROUP, 31);
        assert_eq!(SSH_MSG_KEX_DH_GEX_INIT, 32);
        assert_eq!(SSH_MSG_KEX_DH_GEX_REPLY, 33);
        assert_eq!(SSH_MSG_KEX_DH_GEX_REQUEST, 34);
    }

    /// Verify [`SshStage`] enum discriminants match the FASM
    /// `ssh_stage_*` constants at `ssh.inc` lines 195–209.
    #[test]
    fn ssh_stage_reexport_reachable() {
        assert_eq!(SshStage::Idents as u32, 0);
        assert_eq!(SshStage::WantKexInit as u32, 1);
        assert_eq!(SshStage::WantKexGexReq as u32, 2);
        assert_eq!(SshStage::WantKexGexGroup as u32, 3);
        assert_eq!(SshStage::WantKexGexInit as u32, 4);
        assert_eq!(SshStage::WantKexGexReply as u32, 5);
        assert_eq!(SshStage::WantNewKeys as u32, 6);
        assert_eq!(SshStage::WantService as u32, 7);
        assert_eq!(SshStage::WantUserauth as u32, 8);
        assert_eq!(SshStage::WantChannel as u32, 9);
        assert_eq!(SshStage::Channel as u32, 10);
        assert_eq!(SshStage::Interactive as u32, 11);
        assert_eq!(SshStage::TornDown as u32, 12);
        assert_eq!(SshStage::Goaway as u32, 13);
    }

    /// Verify [`ClientMode`] discriminants match the FASM
    /// `ssh_clientmode_*` constants.
    #[test]
    fn client_mode_reexport_reachable() {
        assert_eq!(ClientMode::Server as u32, 0);
        assert_eq!(ClientMode::SessionClient as u32, 1);
        assert_eq!(ClientMode::SftpClient as u32, 2);
    }

    /// Verify [`SSH_IDENT`] is byte-identical to the FASM source
    /// `ssh_ident db 'SSH-2.0-HeavyThing', 13, 10` at `ssh.inc` line 99.
    /// This banner is part of the observable wire protocol per RFC 4253
    /// §4.2 and MUST NOT change.
    #[test]
    fn ssh_ident_byte_exact() {
        assert_eq!(SSH_IDENT, b"SSH-2.0-HeavyThing\r\n");
        assert_eq!(SSH_IDENT_LEN, 20);
        assert_eq!(SSH_IDENT_LEN, SSH_IDENT.len());
    }

    /// Verify [`AuthOutcome`] is `Copy` (lightweight value semantics for
    /// dispatch-table return values per `ssh.inc`'s
    /// `.got_userauth_request` reply path).
    #[test]
    fn auth_outcome_is_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<AuthOutcome>();
    }

    /// Verify the kex helpers are reachable through the re-export.
    /// Compilation alone validates the re-export — naming each symbol
    /// in a `let _ = identifier;` binding causes the compiler to
    /// resolve it through this module's `pub use`. If a symbol
    /// disappears from `kex.rs`, this test fails to build.
    #[test]
    fn kex_helpers_reexport_reachable() {
        let _builder_ctor: fn() -> KexHashBuilder = KexHashBuilder::new;
        // Binding the function items (not pointers) avoids the
        // `function-casts-as-integer` lint while still resolving the
        // symbol through this module's `pub use` line. The borrow
        // elision rules forbid coercing these to `fn` pointers because
        // each takes one or more borrowed-slice parameters whose
        // lifetimes cannot be elided in a function-pointer context.
        let _ = sign_rsa;
        let _ = sign_dss;
        let _ = verify_signature;
    }

    /// Verify [`CipherState`] and the compression types are reachable as
    /// types (no instance constructed — that requires `ring`-backed
    /// initialisation that would slow down this aggregator-level test).
    #[test]
    fn cipher_and_compression_types_reachable() {
        // `size_of::<T>` is a compile-time check that requires `T` to be
        // `Sized`. If any of these re-exports ever drifts to a non-Sized
        // alias (e.g., a trait object), this test fails to compile.
        let _ = std::mem::size_of::<CipherState>();
        let _ = std::mem::size_of::<CompressionState>();
        let _ = std::mem::size_of::<DeflateStream>();
        let _ = std::mem::size_of::<InflateStream>();
    }
}
