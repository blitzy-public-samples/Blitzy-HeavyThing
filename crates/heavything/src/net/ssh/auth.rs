// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2015-2018 2 Ton Digital, Jeff Marrison.
// Copyright (C) 2026 Blitzy Rust Port contributors.
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
//
// Source: ssh.inc (authentication handlers `.got_userauth_*`, `.got_service*`,
//         `.got_ignore`, and callback registration `ssh$set_authcb`).

//! SSH 2.0 authentication-protocol layer — pure parsing and wire-format
//! construction for the userauth subprotocol.
//!
//! This module is the Rust translation of the authentication fragments
//! of `ssh.inc`. It deliberately covers only the **message parsing,
//! callback invocation, and frame construction** for the SSH userauth
//! flow per AAP §0.5.1.4 and the per-folder requirements; it does
//! **not** own socket I/O (which belongs to `server.rs`), it does
//! **not** own crypto contexts (which belong to `cipher.rs` +
//! `kex.rs`), and it does **not** directly manage the
//! [`Blacklist`](crate::net::blacklist::Blacklist) (which is owned by
//! the `Ssh` struct in `server.rs`).
//!
//! # FASM source coverage
//!
//! The handlers and constants in this module map line-by-line to the
//! following spans of `ssh.inc`:
//!
//! | Rust item                            | `ssh.inc` lines       |
//! |--------------------------------------|-----------------------|
//! | [`AUTHFAIL_PAYLOAD`]                 | 2786–2788 (`.authfail`) |
//! | [`PASSWORD_METHOD`]                  | 3034–3036 (`.password_method`) |
//! | [`DEFAULT_AUTH`]                     | 3043–3045 (`.default_auth`)    |
//! | [`NO_METHOD`]                        | 3047–3049 (`.no_method`)       |
//! | [`KEYBOARD_INTERACTIVE`]             | 3038–3040 (`.keyboardinteractive`) |
//! | [`SESSION_STR`]                      | 2877–2879 (`.sessionstr`)      |
//! | [`CLIENT_SERVICENAME`]               | 4692–4695 (`.client_servicename`) |
//! | [`SSH_SERVICE`]                      | 116–118   (`ssh_service`)      |
//! | [`handle_service_request`]           | 2881–2906 (`.got_servicerequest`) |
//! | [`build_client_userauth_request`]    | 2908–3032 (`.got_serviceaccept`)  |
//! | [`handle_userauth_request`]          | 2629–2790 (`.got_userauth_request`) |
//! | [`handle_userauth_success`]          | 2818–2875 (`.got_userauth_success`) |
//! | [`handle_userauth_failure`]          | 2813–2816 (`.got_userauth_failure`) |
//! | [`handle_userauth_info_request`]     | 2519–2627 (`.got_userauth_info_request`) |
//! | [`handle_ignore`]                    | 3050–3056 (`.got_ignore`)      |
//! | [`build_random_ignore_payload`]      | comment block 50–58 (timing-attack mitigation) |
//! | [`AuthCallback`] (set via `set_authcb`) | 619–622 (`ssh$set_authcb`) — the actual setter is on the `Ssh` struct in `server.rs`; this module defines only the callback type |
//!
//! # Public API at a glance
//!
//! * [`AuthCallback`] — the [`Arc`]-wrapped closure type registered by
//!   server applications to validate `(username, password)` tuples.
//! * [`AuthOutcome`] — three-valued enum (`Granted` / `Denied` /
//!   `NoCallback`) returned from [`handle_userauth_request`].
//! * [`AuthArgs`] — three-variant enum encoding the client-side
//!   credential bundle (`DefaultTaketwo` / `UsernameOnly` /
//!   `UsernameAndPassword`).
//! * Server-side handlers: [`handle_service_request`],
//!   [`handle_userauth_request`], [`build_userauth_failure_payload`],
//!   plus the [`USERAUTH_SUCCESS_PAYLOAD`] empty-slice constant.
//! * Client-side helpers: [`build_client_service_request`],
//!   [`build_client_userauth_request`],
//!   [`build_random_ignore_payload`], [`handle_userauth_info_request`],
//!   [`handle_userauth_success`], [`handle_userauth_failure`].
//! * Universal: [`handle_ignore`] for `SSH_MSG_IGNORE` /
//!   `SSH_MSG_DEBUG` / `SSH_MSG_USERAUTH_BANNER`.
//! * Eleven message-type [`u8`] constants (`SSH_MSG_*`) plus eight
//!   wire-format byte payload constants.
//!
//! # Blacklist-integration contract
//!
//! This module performs **pure** protocol parsing and never directly
//! mutates the IP blacklist. The `Ssh` server struct in `server.rs`
//! owns `Arc<crate::net::blacklist::Blacklist>` and is solely
//! responsible for:
//!
//! 1. Calling
//!    `blacklist.contains(crate::net::blacklist::key_from_ipv4(peer))`
//!    in `ssh$connected` (`ssh.inc` line 651) — rejecting the peer
//!    with the `ssh_ident_blacklisted` banner on a hit.
//! 2. Calling
//!    `blacklist.add(crate::net::blacklist::key_from_ipv4(peer))` in
//!    the `.badhmac` branch (`ssh.inc` lines 1355–1420) when the
//!    server-side HMAC check fails.
//!
//! Authentication failure paths inside this module simply return
//! [`AuthOutcome::Denied`]; they never blacklist on their own. A
//! server-policy layer (e.g., "blacklist after N failed auths in T
//! seconds") may be added on top of this module without modifying
//! its parsing logic.
//!
//! # Threading and async-ness
//!
//! Every handler in this module is **synchronous** — they operate on
//! in-memory byte buffers that have already been decrypted and
//! decompressed by the packet-processing pipeline in `server.rs`.
//! Async I/O is solely `server.rs`'s concern.
//!
//! # `unsafe` audit
//!
//! This module contributes **zero** `unsafe` blocks to the crate's
//! `UNSAFE_AUDIT.md` tally per AAP §0.7.4.1. Correctness derives
//! entirely from safe slice indexing, [`u32::from_be_bytes`], and the
//! crate-internal RNG.

use std::sync::Arc;

use crate::crypto::rng;
use crate::error::SshError;

// ============================================================================
// Phase 2 — Type aliases and core types
// ============================================================================

/// Server-side password-authentication callback.
///
/// Invoked by the server's `USERAUTH_REQUEST` handler
/// ([`handle_userauth_request`]; `ssh.inc` lines 2629–2790) when a
/// peer presents a `password` method authentication request.
///
/// # Arguments
///
/// * `username` — UTF-8-decoded username. The original FASM call site
///   used `string$from_utf8` on the length-prefixed byte sequence
///   before passing the resulting string pointer via `rsi`
///   (`ssh.inc` line 2666).
/// * `password` — UTF-8-decoded cleartext password. The original
///   FASM call site decoded via `string$from_utf8` and passed it via
///   `rdx` (`ssh.inc` lines 2722–2727).
///
/// # Return value
///
/// `true` to grant access, `false` to deny. Callers who hash and
/// compare passwords are responsible for using a constant-time
/// comparator (e.g., `subtle::ConstantTimeEq`) to prevent timing
/// leaks — this module does not mandate a particular comparison
/// strategy. See `ssh.inc` comment lines 50–80 for the original
/// author's discussion of CBC-related timing attacks and their
/// mitigation in client mode.
///
/// # Why [`Arc`]?
///
/// 1. The server registers a single callback at startup but invokes
///    it from each active SSH session — [`Arc`]'s clone-by-refcount
///    avoids Rc-vs-Box ownership headaches.
/// 2. SSH sessions run as independent `tokio` tasks potentially on
///    different threads; the `Send + Sync` trait bounds on `dyn Fn`
///    are satisfied by [`Arc`] for closures captured-by-value.
/// 3. The callback's lifetime must outlive the server's lifetime
///    without explicit lifetime annotations leaking into the public
///    API.
pub type AuthCallback = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// Outcome of a `password`-method authentication request.
///
/// Returned by [`handle_userauth_request`] alongside the parsed
/// [`UserauthRequestParsed`] bundle so the caller (`server.rs`) can
/// branch on the result without re-running the parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Callback accepted the credentials. Caller (`server.rs`) should
    /// advance the SSH stage to `WantChannel` and transmit
    /// `SSH_MSG_USERAUTH_SUCCESS` (52) — see `ssh.inc` lines
    /// 2738–2747.
    Granted,
    /// Callback rejected the credentials. Caller should transmit
    /// `SSH_MSG_USERAUTH_FAILURE` (51) carrying the
    /// [`AUTHFAIL_PAYLOAD`] blob (partial-success flag is `1`,
    /// indicating the peer MAY retry with the same `password`
    /// method — see `ssh.inc` lines 2771–2788).
    Denied,
    /// No callback was registered — immediate-success path per
    /// `ssh.inc` line 2638 (`.got_userauth_request_immediatesuccess`,
    /// continued at line 2790). The caller treats this identically
    /// to [`Granted`](AuthOutcome::Granted) except that no credential
    /// validation occurred.
    NoCallback,
}

/// Parsed client-side authentication context.
///
/// Captures the three-way branch from `ssh.inc` lines 2908–3032
/// (`.got_serviceaccept`) where the FASM code selects between three
/// distinct USERAUTH_REQUEST shapes based on whether the client has
/// configured a username and/or password prior to connecting. The
/// `'a` lifetime ties the parsed credentials to the caller's owned
/// [`String`] storage — no copies are made until
/// [`build_client_userauth_request`] serialises the wire frame.
#[derive(Debug, Clone)]
pub enum AuthArgs<'a> {
    /// No username and no password configured — the client sends the
    /// pre-baked [`DEFAULT_AUTH`] blob declaring username `taketwo`,
    /// service `ssh-connection`, and method `none`. Mirrors
    /// `.got_serviceaccept_nousername` (`ssh.inc` lines 2975–2988).
    DefaultTaketwo,
    /// Username configured, no password — the client sends
    /// `username + ssh-connection + none`. Mirrors
    /// `.got_serviceaccept_nopassword` (`ssh.inc` lines 2990–3032).
    UsernameOnly {
        /// UTF-8-encoded username; serialised as a length-prefixed
        /// SSH string per RFC 4251 §5.
        username: &'a str,
    },
    /// Both username and password configured — the client sends
    /// `username + ssh-connection + keyboard-interactive` and waits
    /// for the server's `SSH_MSG_USERAUTH_INFO_REQUEST` challenge.
    /// The actual password bytes do **not** ride in this initial
    /// request; they are sent in the response frame produced by
    /// [`handle_userauth_info_request`] in reaction to the server's
    /// challenge. Mirrors the keyboard-interactive branch of
    /// `.got_serviceaccept` (`ssh.inc` lines 2926–2972).
    UsernameAndPassword {
        /// UTF-8-encoded username.
        username: &'a str,
        /// UTF-8-encoded password — held here only so the higher-level
        /// client driver can later forward it to
        /// [`handle_userauth_info_request`] when the server challenges.
        password: &'a str,
    },
}

// ============================================================================
// Phase 3 — SSH message-type constants (RFC 4252 / RFC 4253 / RFC 4254 / RFC 4256)
// ============================================================================

/// `SSH_MSG_IGNORE` — RFC 4253 §11.2. Discarded by both sides; in
/// client mode we deliberately inject one with a random-length payload
/// before transmitting the password to mask the password's CBC-block
/// boundary (see `ssh.inc` comment block lines 50–58).
pub const SSH_MSG_IGNORE: u8 = 2;

/// `SSH_MSG_DEBUG` — RFC 4253 §11.3. Silently discarded.
pub const SSH_MSG_DEBUG: u8 = 4;

/// `SSH_MSG_SERVICE_REQUEST` — RFC 4253 §10. Carries the
/// length-prefixed service identifier (e.g., `ssh-userauth` —
/// see [`CLIENT_SERVICENAME`]).
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;

/// `SSH_MSG_SERVICE_ACCEPT` — RFC 4253 §10. Echoes the requested
/// service identifier back to the peer; carries the same byte payload
/// as the request that elicited it.
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;

/// `SSH_MSG_USERAUTH_REQUEST` — RFC 4252 §5. Format:
/// `string username || string service-name || string method-name ||
/// bool partial-success || ...method-specific...`.
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

/// `SSH_MSG_USERAUTH_FAILURE` — RFC 4252 §5.1. Carries
/// [`AUTHFAIL_PAYLOAD`] (`ssh.inc` line 2786 — `password` method
/// still available to retry; partial-success flag is `1`).
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;

/// `SSH_MSG_USERAUTH_SUCCESS` — RFC 4252 §5.1. The server's
/// confirmation that authentication succeeded; carries no payload
/// beyond the message-type byte itself (see
/// [`USERAUTH_SUCCESS_PAYLOAD`]).
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;

/// `SSH_MSG_USERAUTH_BANNER` — RFC 4252 §5.4. Discarded by this
/// implementation per the FASM convention of routing all three
/// "harmless informational" messages (`IGNORE`, `DEBUG`, `BANNER`) to
/// the same `.got_ignore` label (`ssh.inc` lines 1581–1599).
pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;

/// `SSH_MSG_USERAUTH_INFO_REQUEST` — RFC 4256 §3.2. Sent by the
/// server during the `keyboard-interactive` challenge-response
/// handshake; format is
/// `string name || string instruction || string language ||
/// uint32 num-prompts || ...prompts...`.
pub const SSH_MSG_USERAUTH_INFO_REQUEST: u8 = 60;

/// `SSH_MSG_USERAUTH_INFO_RESPONSE` — RFC 4256 §3.4. Format:
/// `uint32 num-responses || string response-1 || ...string response-N`.
pub const SSH_MSG_USERAUTH_INFO_RESPONSE: u8 = 61;

/// `SSH_MSG_CHANNEL_OPEN` — RFC 4254 §5.1. Constructed by
/// [`handle_userauth_success`] post-authentication to open the first
/// `session` channel.
pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;

// ============================================================================
// Phase 4 — Constant wire-format payloads (byte-identical to ssh.inc)
// ============================================================================

/// `.authfail` — `SSH_MSG_USERAUTH_FAILURE` (51) payload sent after
/// a failed `password`-method attempt.
///
/// Layout:
///
/// ```text
/// [0, 0, 0, 8] uint32-be name-list length = 8
/// [p, a, s, s, w, o, r, d] name-list = "password"
/// [1] bool partial_success = true (peer MAY retry with same method)
/// ```
///
/// Total: 13 bytes. Mirrors `ssh.inc` lines 2786–2788
/// (`.authfail` / `.authfaillen = $ - .authfail`).
pub const AUTHFAIL_PAYLOAD: &[u8] = &[0, 0, 0, 8, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', 1];

/// `.password_method` — length-prefixed method name `password`
/// followed by a zero byte (`partial_success = false`). Used during
/// **client-side** `USERAUTH_REQUEST` construction; differs from
/// [`AUTHFAIL_PAYLOAD`] only in the trailing flag (here `0` because
/// the client has no partial-success state yet). Total 13 bytes.
/// Mirrors `ssh.inc` lines 3034–3036.
pub const PASSWORD_METHOD: &[u8] = &[0, 0, 0, 8, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', 0];

/// `.default_auth` — fall-back `USERAUTH_REQUEST` body sent when the
/// client has no username configured.
///
/// Layout:
///
/// ```text
/// [0, 0, 0, 7] uint32-be username length = 7
/// [t, a, k, e, t, w, o] username = "taketwo"
/// [0, 0, 0, 14] uint32-be service-name length = 14
/// [s, s, h, -, c, o, n, n, e, c, t, i, o, n] service = "ssh-connection"
/// [0, 0, 0, 4] uint32-be method-name length = 4
/// [n, o, n, e] method = "none"
/// ```
///
/// Total: 37 bytes. Mirrors `ssh.inc` lines 3043–3045.
pub const DEFAULT_AUTH: &[u8] = &[
    0, 0, 0, 7, b't', b'a', b'k', b'e', b't', b'w', b'o', 0, 0, 0, 14, b's', b's', b'h', b'-', b'c', b'o',
    b'n', b'n', b'e', b'c', b't', b'i', b'o', b'n', 0, 0, 0, 4, b'n', b'o', b'n', b'e',
];

/// `.no_method` — length-prefixed method name `none`. Appended to
/// the (`username` + [`SSH_SERVICE`]) prefix when the client has a
/// username but no password. Total 8 bytes. Mirrors `ssh.inc` lines
/// 3047–3049.
pub const NO_METHOD: &[u8] = &[0, 0, 0, 4, b'n', b'o', b'n', b'e'];

/// `.keyboardinteractive` — method-name + language tag + empty
/// submethods triple. Appended to the (`username` + [`SSH_SERVICE`])
/// prefix when the client has both username AND password configured.
/// Triggers the server's `SSH_MSG_USERAUTH_INFO_REQUEST` challenge,
/// which we answer in [`handle_userauth_info_request`].
///
/// Layout:
///
/// ```text
/// [0, 0, 0, 20] uint32-be method-name length = 20
/// [k, e, y, b, o, a, r, d, -, i, n, t, e, r, a, c, t, i, v, e]
/// [0, 0, 0, 5] uint32-be language length = 5
/// [e, n, -, U, S]
/// [0, 0, 0, 0] uint32-be submethods length = 0 (empty list)
/// ```
///
/// Total: 37 bytes. Mirrors `ssh.inc` lines 3038–3040.
pub const KEYBOARD_INTERACTIVE: &[u8] = &[
    0, 0, 0, 20, b'k', b'e', b'y', b'b', b'o', b'a', b'r', b'd', b'-', b'i', b'n', b't', b'e', b'r', b'a',
    b'c', b't', b'i', b'v', b'e', 0, 0, 0, 5, b'e', b'n', b'-', b'U', b'S', 0, 0, 0, 0,
];

/// `.sessionstr` — length-prefixed channel type `session`. The
/// 11-byte prefix of every `SSH_MSG_CHANNEL_OPEN` (90) frame this
/// implementation emits post-authentication. Mirrors `ssh.inc` lines
/// 2877–2879.
pub const SESSION_STR: &[u8] = &[0, 0, 0, 7, b's', b'e', b's', b's', b'i', b'o', b'n'];

/// `.client_servicename` — length-prefixed `ssh-userauth`
/// (12 ASCII chars, with 4-byte length prefix = 16 bytes total).
/// The exact byte sequence a client sends inside
/// `SSH_MSG_SERVICE_REQUEST` (5) and that the server echoes back
/// inside `SSH_MSG_SERVICE_ACCEPT` (6). Mirrors `ssh.inc` lines
/// 4692–4695.
pub const CLIENT_SERVICENAME: &[u8] = &[
    0, 0, 0, 0x0C, b's', b's', b'h', b'-', b'u', b's', b'e', b'r', b'a', b'u', b't', b'h',
];

/// `ssh_service` — length-prefixed `ssh-connection` (14 chars +
/// 4-byte length prefix = 18 bytes total). The service name a client
/// embeds **inside** `USERAUTH_REQUEST` declaring which service it
/// wishes to access post-authentication. Distinct from
/// [`CLIENT_SERVICENAME`] which is the authentication service itself.
/// Mirrors `ssh.inc` lines 116–118.
pub const SSH_SERVICE: &[u8] = &[
    0, 0, 0, 14, b's', b's', b'h', b'-', b'c', b'o', b'n', b'n', b'e', b'c', b't', b'i', b'o', b'n',
];

/// `SSH_MSG_USERAUTH_SUCCESS` (52) carries no payload bytes beyond
/// the single message-type byte. This empty slice is exposed for
/// API symmetry with the other payload constants — callers in
/// `server.rs` simply transmit the message-type byte directly.
/// See RFC 4252 §5.1 and `ssh.inc` lines 2738–2747.
pub const USERAUTH_SUCCESS_PAYLOAD: &[u8] = &[];

// Compile-time length assertions guarding the byte literals against
// typos. If any of these fail, `cargo build` will produce
// `error[E0080]` referencing the offending constant.
const _: () = assert!(AUTHFAIL_PAYLOAD.len() == 13);
const _: () = assert!(PASSWORD_METHOD.len() == 13);
const _: () = assert!(DEFAULT_AUTH.len() == 37);
const _: () = assert!(NO_METHOD.len() == 8);
const _: () = assert!(KEYBOARD_INTERACTIVE.len() == 37);
const _: () = assert!(SESSION_STR.len() == 11);
const _: () = assert!(CLIENT_SERVICENAME.len() == 16);
const _: () = assert!(SSH_SERVICE.len() == 18);
const _: () = assert!(USERAUTH_SUCCESS_PAYLOAD.is_empty());

// ============================================================================
// Phase 5 — Wire-format parsing helpers (RFC 4251 §5)
// ============================================================================

/// Parse an SSH `string` (length-prefixed byte sequence) per RFC 4251
/// §5 starting at `*offset` within `buf`. Advances `*offset` past the
/// 4-byte length prefix and the payload, returning the payload slice.
///
/// The FASM equivalent is the inline parsing scattered throughout the
/// `.got_userauth_request` body (`ssh.inc` lines 2657–2725) where each
/// length read is followed by an immediate bounds check
/// (`je .got_userauth_request_fail1`). This Rust helper centralises
/// the same bounds-checking logic.
///
/// # Errors
///
/// Returns [`SshError::Auth`] if there are fewer than 4 bytes remaining
/// for the length prefix, if the declared payload length would exceed
/// the buffer, or if `*offset` already points past the end of `buf`.
pub(crate) fn parse_ssh_string<'a>(buf: &'a [u8], offset: &mut usize) -> Result<&'a [u8], SshError> {
    let start = *offset;
    if start + 4 > buf.len() {
        return Err(SshError::Auth);
    }
    let len_bytes: [u8; 4] = match buf[start..start + 4].try_into() {
        Ok(arr) => arr,
        Err(_) => return Err(SshError::Auth),
    };
    let length = u32::from_be_bytes(len_bytes) as usize;
    let payload_start = start + 4;
    let payload_end = match payload_start.checked_add(length) {
        Some(end) => end,
        None => return Err(SshError::Auth),
    };
    if payload_end > buf.len() {
        return Err(SshError::Auth);
    }
    *offset = payload_end;
    Ok(&buf[payload_start..payload_end])
}

/// Parse a big-endian unsigned 32-bit integer at `*offset` within
/// `buf`. Advances `*offset` by 4. Mirrors the inline `mov eax, [rsi];
/// bswap eax` patterns scattered throughout `ssh.inc`.
///
/// # Errors
///
/// Returns [`SshError::Auth`] if fewer than 4 bytes remain at the
/// requested offset.
pub(crate) fn parse_u32_be(buf: &[u8], offset: &mut usize) -> Result<u32, SshError> {
    let start = *offset;
    if start + 4 > buf.len() {
        return Err(SshError::Auth);
    }
    let bytes: [u8; 4] = match buf[start..start + 4].try_into() {
        Ok(arr) => arr,
        Err(_) => return Err(SshError::Auth),
    };
    *offset = start + 4;
    Ok(u32::from_be_bytes(bytes))
}

/// Parse a single SSH `boolean` octet at `*offset` per RFC 4251 §5.
/// Any nonzero value is interpreted as `true`, zero as `false`.
/// Advances `*offset` by 1.
///
/// # Errors
///
/// Returns [`SshError::Auth`] if `*offset` points past the end of
/// `buf`.
pub(crate) fn parse_bool(buf: &[u8], offset: &mut usize) -> Result<bool, SshError> {
    let start = *offset;
    if start >= buf.len() {
        return Err(SshError::Auth);
    }
    let value = buf[start] != 0;
    *offset = start + 1;
    Ok(value)
}

// ============================================================================
// Phase 6 — Server-side handlers
// ============================================================================

/// Outcome of a successful [`handle_service_request`] call.
///
/// The caller (`server.rs`) uses [`Self::accept_payload`] as the body
/// of the `SSH_MSG_SERVICE_ACCEPT` (6) frame it transmits and consults
/// [`Self::advance_stage`] to decide whether to advance the SSH state
/// machine to `WantUserauth`.
#[derive(Debug, Clone)]
pub struct ServiceRequestResult {
    /// Pre-computed body of the `SSH_MSG_SERVICE_ACCEPT` (6) frame.
    /// Per `ssh.inc` line 2904, the server echoes back the exact
    /// `ssh-userauth` length-prefixed identifier the client sent.
    pub accept_payload: Vec<u8>,
    /// Whether the caller should advance the session stage to
    /// `WantUserauth` before transmitting the accept frame. Always
    /// `true` on success in this implementation; declared explicitly
    /// to make the contract clear at the call site.
    pub advance_stage: bool,
}

/// Server-side handler for `SSH_MSG_SERVICE_REQUEST` (5).
///
/// Mirrors `ssh.inc` lines 2881–2906 (`.got_servicerequest`). The
/// FASM code (a) checks that the packet body is exactly
/// 16 bytes long (length of [`CLIENT_SERVICENAME`]), then (b) does a
/// `memcmp` against `.client_servicename` and (c) prepares an echo
/// `SSH_MSG_SERVICE_ACCEPT` (6) frame.
///
/// Constant-time comparison is **not** required here: the service
/// name is public protocol metadata, not a secret.
///
/// # Errors
///
/// Returns [`SshError::Auth`] if the packet body has the wrong length
/// or the wrong contents — both correspond to the FASM `.badlength`
/// fatal-teardown branch (`ssh.inc` line 2890).
pub fn handle_service_request(packet_body: &[u8]) -> Result<ServiceRequestResult, SshError> {
    if packet_body.len() != CLIENT_SERVICENAME.len() {
        return Err(SshError::Auth);
    }
    if packet_body != CLIENT_SERVICENAME {
        return Err(SshError::Auth);
    }
    Ok(ServiceRequestResult {
        accept_payload: CLIENT_SERVICENAME.to_vec(),
        advance_stage: true,
    })
}

/// Parsed contents of an `SSH_MSG_USERAUTH_REQUEST` (50) frame body.
///
/// Mirrors the temporary structure the FASM code holds in its register
/// allocations across `.got_userauth_request` (`ssh.inc` lines
/// 2629–2790). The `servicename` field is intentionally a `Vec<u8>`
/// (not a [`String`]): per the FASM source comment at line 2678,
/// the implementation does **not** validate the service name's UTF-8
/// or its semantic value — it merely passes the bytes through.
#[derive(Debug, Clone)]
pub struct UserauthRequestParsed {
    /// UTF-8-decoded username extracted from the first SSH string in
    /// the request body. Empty when the parser fell into the
    /// "wrong method" branch (in which case the password field is
    /// also empty by construction).
    pub username: String,
    /// Raw bytes of the service-name field. NOT validated against
    /// [`SSH_SERVICE`] — the FASM source explicitly elides this
    /// check (`ssh.inc` line 2678 comment: "if we cared about the
    /// contents of the servicename, we would create a string here").
    pub servicename: Vec<u8>,
    /// UTF-8-decoded password (empty when the request used a method
    /// other than `password`, since the parser short-circuits before
    /// reading the password field in that case).
    pub password: String,
}

/// Server-side handler for `SSH_MSG_USERAUTH_REQUEST` (50).
///
/// Mirrors `ssh.inc` lines 2629–2790 (`.got_userauth_request`).
/// Parses the 4 length-prefixed strings (`username`, `service-name`,
/// `method-name`, and — only if the method is `password` — `password`)
/// plus the intermediate boolean (`partial-success`, ignored per FASM
/// line 2708 `add r12, 1`), then dispatches to the registered
/// callback if the method is exactly `password`.
///
/// # Returns
///
/// The parsed bundle plus an [`AuthOutcome`]:
///
/// * [`AuthOutcome::Granted`] — callback returned `true`. Caller
///   transmits `SSH_MSG_USERAUTH_SUCCESS` (52).
/// * [`AuthOutcome::Denied`] — callback returned `false` **or** the
///   method-name was anything other than `password`. Caller
///   transmits `SSH_MSG_USERAUTH_FAILURE` (51) with
///   [`AUTHFAIL_PAYLOAD`]. Mirrors the FASM `fail2` branch
///   (`ssh.inc` lines 2761–2790).
/// * [`AuthOutcome::NoCallback`] — no callback was registered.
///   Caller treats this exactly like `Granted` (see
///   `.got_userauth_request_immediatesuccess`, `ssh.inc` line 2638).
///
/// # Errors
///
/// Returns [`SshError::Auth`] (the FASM `fail1` / `.badlength`
/// terminal-teardown branch) when:
///
/// * The packet body is shorter than 20 bytes (FASM `cmp r14, 20 / jb
///   .got_userauth_request_fail1`, lines 2631–2634).
/// * Any of the length-prefixed strings is truncated or malformed.
/// * The username or password bytes are not valid UTF-8 (FASM
///   `string$from_utf8` failure paths, lines 2665, 2722).
pub fn handle_userauth_request(
    packet_body: &[u8],
    callback: Option<&AuthCallback>,
) -> Result<(UserauthRequestParsed, AuthOutcome), SshError> {
    // Minimum-length check matches FASM lines 2631–2634.
    if packet_body.len() < 20 {
        return Err(SshError::Auth);
    }

    let mut offset = 0usize;

    // 1) username (UTF-8). FASM lines 2657–2670: parse string, then
    //    `string$from_utf8`. UTF-8 failure → fail1 → Err here.
    let username_bytes = parse_ssh_string(packet_body, &mut offset)?;
    let username = match std::str::from_utf8(username_bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => return Err(SshError::Auth),
    };

    // 2) service-name (raw bytes, NOT UTF-8-validated per line 2678).
    let servicename_bytes = parse_ssh_string(packet_body, &mut offset)?;
    let servicename = servicename_bytes.to_vec();

    // 3) method-name (raw bytes). FASM lines 2696–2706 do two dword
    //    compares ('pass' == [r12], 'word' == [r12+4]); if either
    //    differs → fail2 (USERAUTH_FAILURE, NOT teardown).
    let method_bytes = parse_ssh_string(packet_body, &mut offset)?;
    if method_bytes != b"password" {
        // fail2: keep the connection, deny the attempt. Returned
        // bundle still includes the parsed username so callers can
        // log it; password is empty since we short-circuit.
        return Ok((
            UserauthRequestParsed {
                username,
                servicename,
                password: String::new(),
            },
            AuthOutcome::Denied,
        ));
    }

    // 4) partial-success boolean (ignored per FASM line 2708).
    let _partial_success = parse_bool(packet_body, &mut offset)?;

    // 5) password (UTF-8). FASM line 2717.
    let password_bytes = parse_ssh_string(packet_body, &mut offset)?;
    let password = match std::str::from_utf8(password_bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => return Err(SshError::Auth),
    };

    // Callback dispatch (FASM lines 2725–2739).
    let outcome = match callback {
        None => AuthOutcome::NoCallback,
        Some(cb) => {
            if cb(&username, &password) {
                AuthOutcome::Granted
            } else {
                AuthOutcome::Denied
            }
        }
    };

    Ok((
        UserauthRequestParsed {
            username,
            servicename,
            password,
        },
        outcome,
    ))
}

/// Returns the canonical `SSH_MSG_USERAUTH_FAILURE` (51) payload.
///
/// Provided as a function (rather than a re-export of the constant)
/// to give callers a stable, immutable reference and to make the
/// intent clear at every transmission site. Mirrors the FASM use of
/// `.authfail` at `ssh.inc` lines 2768–2779 inside the `fail2`
/// branch.
#[inline]
pub fn build_userauth_failure_payload() -> &'static [u8] {
    AUTHFAIL_PAYLOAD
}

// ============================================================================
// Phase 7 — Client-side handlers
// ============================================================================

/// Builds the body of the `SSH_MSG_SERVICE_REQUEST` (5) frame the
/// client transmits immediately after `NEWKEYS`.
///
/// This is a one-line wrapper around [`CLIENT_SERVICENAME`]; provided
/// as a function so the call site reads symmetrically with
/// [`build_client_userauth_request`] and [`build_random_ignore_payload`].
///
/// Mirrors the implicit precondition of `.got_serviceaccept` on
/// `ssh.inc` line 2908: the server only reaches that handler if the
/// client previously sent a service-request whose body is byte-equal
/// to [`CLIENT_SERVICENAME`].
#[inline]
pub fn build_client_service_request() -> Vec<u8> {
    CLIENT_SERVICENAME.to_vec()
}

/// Builds the body of the first `SSH_MSG_USERAUTH_REQUEST` (50)
/// frame the client transmits, choosing among three pre-baked layouts
/// per the [`AuthArgs`] discriminant.
///
/// Mirrors `ssh.inc` lines 2908–3032 (`.got_serviceaccept`):
///
/// * [`AuthArgs::DefaultTaketwo`] → returns [`DEFAULT_AUTH`] verbatim
///   (FASM lines 2975–2988, `.got_serviceaccept_nousername`).
/// * [`AuthArgs::UsernameOnly`] → returns
///   `length-prefixed username || ssh-connection || none` (FASM
///   lines 2990–3032, `.got_serviceaccept_nopassword`).
/// * [`AuthArgs::UsernameAndPassword`] → returns
///   `length-prefixed username || ssh-connection || keyboard-interactive`
///   (FASM lines 2926–2972). The password itself does **not** ride
///   in this initial frame; it is sent in the response frame produced
///   by [`handle_userauth_info_request`] when the server later
///   challenges with `SSH_MSG_USERAUTH_INFO_REQUEST` (60).
pub fn build_client_userauth_request(args: &AuthArgs<'_>) -> Vec<u8> {
    match args {
        AuthArgs::DefaultTaketwo => DEFAULT_AUTH.to_vec(),
        AuthArgs::UsernameOnly { username } => {
            let user_bytes = username.as_bytes();
            let user_len = user_bytes.len();
            let mut out = Vec::with_capacity(4 + user_len + SSH_SERVICE.len() + NO_METHOD.len());
            out.extend_from_slice(&(user_len as u32).to_be_bytes());
            out.extend_from_slice(user_bytes);
            out.extend_from_slice(SSH_SERVICE);
            out.extend_from_slice(NO_METHOD);
            out
        }
        AuthArgs::UsernameAndPassword {
            username,
            password: _,
        } => {
            // `password` is intentionally unused here: the FASM
            // implementation defers password transmission to the
            // keyboard-interactive challenge (see
            // `handle_userauth_info_request`).
            let user_bytes = username.as_bytes();
            let user_len = user_bytes.len();
            let mut out = Vec::with_capacity(4 + user_len + SSH_SERVICE.len() + KEYBOARD_INTERACTIVE.len());
            out.extend_from_slice(&(user_len as u32).to_be_bytes());
            out.extend_from_slice(user_bytes);
            out.extend_from_slice(SSH_SERVICE);
            out.extend_from_slice(KEYBOARD_INTERACTIVE);
            out
        }
    }
}

/// Builds the body of an `SSH_MSG_IGNORE` (2) frame containing a
/// random number of random bytes, intended to be transmitted
/// **immediately before** the password during keyboard-interactive
/// authentication as a CBC-plaintext-leak timing-attack mitigation.
///
/// The FASM source comment block at `ssh.inc` lines 50–80 describes
/// this technique:
///
/// > "in client mode, we send an SSH_MSG_IGNORE with a random
/// > amount of actual data prior to sending our password anyway —
/// > this appears to fully deal with the issue."
///
/// # Implementation notes
///
/// * Length is in `[16, 255]` bytes — small enough to be cheap on
///   the wire, large enough to obscure the password's CBC-block
///   boundary. The exact range is not pinned by the FASM source for
///   this code path (the `.badhmac` recovery path at `ssh.inc` line
///   1408 uses a much wider range, but the pre-password injection is
///   simpler).
/// * Length and payload bytes are sourced from
///   [`crate::crypto::rng`] (HMAC-DRBG seeded from `/dev/urandom` +
///   `rdtsc` + `gettimeofday`). [`rng::int`] returns a `u64`;
///   modular reduction by 240 yields a value in `[0, 239]`, to
///   which we add 16 → `[16, 255]`.
/// * The returned `Vec<u8>` is the **frame body** (length prefix +
///   random bytes); the caller wraps it with the
///   `SSH_MSG_IGNORE` (2) message-type byte and any encryption /
///   MAC envelope before transmission.
///
/// The leading 4-byte length prefix means the caller only needs to
/// concatenate `[2u8]` + this body to obtain the full payload of
/// the unencrypted SSH packet, matching RFC 4253 §11.2's requirement
/// that `SSH_MSG_IGNORE` carry a single `string`.
pub fn build_random_ignore_payload() -> Vec<u8> {
    // Random length in [16, 255]: % 240 yields [0, 239], + 16 → [16, 255].
    let len = 16 + (rng::int() % 240) as usize;
    let mut out = Vec::with_capacity(4 + len);
    out.extend_from_slice(&(len as u32).to_be_bytes());
    let mut random_bytes = vec![0u8; len];
    rng::block(&mut random_bytes);
    out.extend_from_slice(&random_bytes);
    out
}

/// Constructed response to `SSH_MSG_USERAUTH_INFO_REQUEST` (60).
///
/// Tuple-struct wrapper around the byte body of an
/// `SSH_MSG_USERAUTH_INFO_RESPONSE` (61) frame. Distinguishes the
/// pre-built response from arbitrary `Vec<u8>` data at API
/// boundaries.
#[derive(Debug, Clone)]
pub struct UserauthInfoResponseFrame(pub Vec<u8>);

/// Client-side handler for `SSH_MSG_USERAUTH_INFO_REQUEST` (60).
///
/// Mirrors `ssh.inc` lines 2519–2627 (`.got_userauth_info_request`).
///
/// The server-issued challenge has the structure
/// `string name || string instruction || string language ||
/// uint32 num-prompts || (string prompt || bool echo){num-prompts}`.
/// The FASM implementation ignores every prompt's text and echo flag
/// (lines 2532–2563 just parse-and-skip), then branches on
/// `num-prompts`:
///
/// * `num-prompts == 0` → reply with empty info-response: a single
///   big-endian `uint32` of value `0`.
/// * `num-prompts == 1` → reply with one length-prefixed string: the
///   client's password (UTF-8).
/// * `num-prompts >= 2` → fatal `.badlength` (`ssh.inc` lines
///   2574–2576). FASM dies; we return [`SshError::Auth`].
///
/// # Errors
///
/// * `num-prompts >= 2` — too many prompts for the FASM-supported
///   single-prompt password protocol.
/// * `num-prompts == 1` but `password.is_none()` — the client must
///   have a password configured to honor the challenge.
/// * Truncated buffer / malformed string fields.
pub fn handle_userauth_info_request(
    packet_body: &[u8],
    password: Option<&str>,
) -> Result<UserauthInfoResponseFrame, SshError> {
    let mut offset = 0usize;

    // Parse and discard `name`, `instruction`, `language` (FASM lines
    // 2532–2563 — the FASM source explicitly skips over these).
    let _name = parse_ssh_string(packet_body, &mut offset)?;
    let _instruction = parse_ssh_string(packet_body, &mut offset)?;
    let _language = parse_ssh_string(packet_body, &mut offset)?;

    let num_prompts = parse_u32_be(packet_body, &mut offset)?;

    // FASM line 2574–2576: `cmp edx, 2 / jnb .badlength`.
    if num_prompts >= 2 {
        return Err(SshError::Auth);
    }

    if num_prompts == 0 {
        // Empty response: single big-endian u32 of value 0.
        // FASM `.got_userauth_info_request_noreply` (lines 2613–2627).
        return Ok(UserauthInfoResponseFrame(vec![0, 0, 0, 0]));
    }

    // num_prompts == 1: must have a password to send.
    let pwd = match password {
        Some(p) => p,
        None => return Err(SshError::Auth),
    };

    let pwd_bytes = pwd.as_bytes();
    let pwd_len = pwd_bytes.len();
    let mut out = Vec::with_capacity(4 + 4 + pwd_len);
    // num-responses = 1 (big-endian u32).
    out.extend_from_slice(&1u32.to_be_bytes());
    // length-prefixed password string.
    out.extend_from_slice(&(pwd_len as u32).to_be_bytes());
    out.extend_from_slice(pwd_bytes);

    Ok(UserauthInfoResponseFrame(out))
}

/// Output of [`handle_userauth_success`].
///
/// Bundles the freshly-generated channel ID (which the caller stores
/// in the `Ssh` session struct) and the pre-computed
/// `SSH_MSG_CHANNEL_OPEN` (90) frame body to transmit immediately
/// after authentication completes.
#[derive(Debug, Clone)]
pub struct UserauthSuccessFrame {
    /// Random 32-bit channel identifier that the caller (`server.rs`
    /// in client-mode) stores in `Ssh.channel_id` (see FASM
    /// `[ssh_channelid_ofs]`, line 2849). Generated via
    /// [`rng::int`] truncated to `u32`.
    pub channel_id: u32,
    /// Pre-computed body of the `SSH_MSG_CHANNEL_OPEN` (90) frame,
    /// in the layout
    /// `[`[`SESSION_STR`]` (11 bytes) || channel_id (BE u32) ||
    /// initial_window=0x7FFFFFFF (BE u32) || max_packet=32768
    /// (BE u32)]`. Total 23 bytes. Mirrors `ssh.inc` lines
    /// 2849–2871.
    pub channel_open_payload: Vec<u8>,
}

/// Client-side handler for `SSH_MSG_USERAUTH_SUCCESS` (52).
///
/// Mirrors `ssh.inc` lines 2818–2875 (`.got_userauth_success`). Per
/// the FASM source, this handler:
///
/// 1. Advances the SSH stage to `WantChannel` (caller's
///    responsibility — not done here).
/// 2. Promotes pending `zlib@openssh.com` compression from state 1
///    → state 2 if applicable (caller's responsibility — operates
///    on the `Ssh.compstate` field; see FASM line 2836 area).
/// 3. Calls `rng$u32` for a random channel ID and stores it in
///    `[ssh_channelid_ofs]` (FASM line 2849).
/// 4. Constructs the `SSH_MSG_CHANNEL_OPEN` (90) body (this
///    function's job).
///
/// # Channel ID generation
///
/// The FASM source uses a dedicated `rng$u32` entry point. Per the
/// AAP §0.7 cross-reference table, the Rust port truncates
/// [`rng::int`]'s `u64` return to `u32` (low 32 bits). This is
/// semantically equivalent: the underlying HMAC-DRBG yields uniform
/// random bytes regardless of which 32-bit slice is taken.
///
/// # Wire-format channel-ID endianness
///
/// The FASM source stores `channel_id` host-endian (little-endian on
/// x86_64) but writes it big-endian to the wire via `bswap eax`
/// (`ssh.inc` line 2855). In Rust we use [`u32::to_be_bytes`] which
/// produces the wire-format bytes directly.
pub fn handle_userauth_success() -> UserauthSuccessFrame {
    // Truncating cast of u64 → u32 takes the low 32 bits — matches
    // FASM `mov eax, [rbx+ssh_rng_state_ofs]; bswap eax` semantics
    // for emitting a 32-bit field while consuming a 64-bit RNG word.
    let channel_id = rng::int() as u32;

    // Layout: SESSION_STR (11) || channel_id (4) || window (4) || max_packet (4) = 23 bytes.
    let mut out = Vec::with_capacity(SESSION_STR.len() + 4 + 4 + 4);
    out.extend_from_slice(SESSION_STR);
    out.extend_from_slice(&channel_id.to_be_bytes());
    // Initial local window: 0x7FFF_FFFF (FASM line 2859).
    out.extend_from_slice(&0x7FFF_FFFFu32.to_be_bytes());
    // Maximum packet size: 32768 (FASM line 2865).
    out.extend_from_slice(&32_768u32.to_be_bytes());

    UserauthSuccessFrame {
        channel_id,
        channel_open_payload: out,
    }
}

/// Client-side handler for `SSH_MSG_USERAUTH_FAILURE` (51).
///
/// Mirrors `ssh.inc` line 2816 (`.got_userauth_failure`). The FASM
/// author chose to terminate the connection rather than retry other
/// authentication methods, so this function unconditionally returns
/// an [`SshError::Auth`] for the caller to use as a teardown signal.
#[inline]
#[must_use = "the returned SshError is the teardown signal — propagate it"]
pub fn handle_userauth_failure() -> SshError {
    SshError::Auth
}

/// Universal no-op handler for `SSH_MSG_IGNORE` (2),
/// `SSH_MSG_DEBUG` (4), and `SSH_MSG_USERAUTH_BANNER` (53).
///
/// Mirrors `ssh.inc` lines 3050–3056 (`.got_ignore`). The FASM source
/// uses a single `.got_ignore` label for all three message types
/// (see the dispatch table at `ssh.inc` lines 1581–1599).
///
/// The caller is responsible for resetting the packet buffer and
/// `peeklen` state machine fields after this returns; those
/// manipulations operate on the `Ssh` struct in `server.rs`, not on
/// any data this module owns.
#[inline]
pub fn handle_ignore() -> Result<(), SshError> {
    Ok(())
}

// ============================================================================
// Phase 8 — Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Constant integrity
    // ------------------------------------------------------------------

    #[test]
    fn test_auth_message_type_constants() {
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

    #[test]
    fn test_constant_payload_lengths() {
        // Cross-checked against the FASM `_len = $ - .label` computations
        // (see Phase 4 of the file's agent prompt).
        assert_eq!(AUTHFAIL_PAYLOAD.len(), 13);
        assert_eq!(PASSWORD_METHOD.len(), 13);
        assert_eq!(DEFAULT_AUTH.len(), 37);
        assert_eq!(NO_METHOD.len(), 8);
        assert_eq!(KEYBOARD_INTERACTIVE.len(), 37);
        assert_eq!(SESSION_STR.len(), 11);
        assert_eq!(CLIENT_SERVICENAME.len(), 16);
        assert_eq!(SSH_SERVICE.len(), 18);
        assert!(USERAUTH_SUCCESS_PAYLOAD.is_empty());
    }

    #[test]
    fn test_authfail_payload_partial_success_byte() {
        // Final byte is `1` — peer MAY retry with the same `password`
        // method per ssh.inc line 2786.
        assert_eq!(AUTHFAIL_PAYLOAD[12], 1);
        // The leading 12 bytes are the length prefix + "password".
        assert_eq!(
            &AUTHFAIL_PAYLOAD[..12],
            &[0, 0, 0, 8, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd',]
        );
    }

    #[test]
    fn test_password_method_has_zero_final_byte() {
        // Differs from AUTHFAIL_PAYLOAD only in the trailing flag byte.
        assert_eq!(PASSWORD_METHOD[12], 0);
        assert_eq!(&PASSWORD_METHOD[..12], &AUTHFAIL_PAYLOAD[..12]);
    }

    #[test]
    fn test_default_auth_layout() {
        // username "taketwo" (4-byte len + 7 bytes) + service
        // "ssh-connection" (4 + 14) + method "none" (4 + 4) = 37 bytes.
        assert_eq!(DEFAULT_AUTH[..4], [0, 0, 0, 7]);
        assert_eq!(&DEFAULT_AUTH[4..11], b"taketwo");
        assert_eq!(DEFAULT_AUTH[11..15], [0, 0, 0, 14]);
        assert_eq!(&DEFAULT_AUTH[15..29], b"ssh-connection");
        assert_eq!(DEFAULT_AUTH[29..33], [0, 0, 0, 4]);
        assert_eq!(&DEFAULT_AUTH[33..37], b"none");
    }

    #[test]
    fn test_keyboard_interactive_layout() {
        assert_eq!(KEYBOARD_INTERACTIVE[..4], [0, 0, 0, 20]);
        assert_eq!(&KEYBOARD_INTERACTIVE[4..24], b"keyboard-interactive");
        assert_eq!(KEYBOARD_INTERACTIVE[24..28], [0, 0, 0, 5]);
        assert_eq!(&KEYBOARD_INTERACTIVE[28..33], b"en-US");
        // Trailing four zero bytes = empty submethods list.
        assert_eq!(KEYBOARD_INTERACTIVE[33..37], [0, 0, 0, 0]);
    }

    #[test]
    fn test_no_method_layout() {
        assert_eq!(NO_METHOD, &[0, 0, 0, 4, b'n', b'o', b'n', b'e']);
    }

    #[test]
    fn test_session_str_layout() {
        assert_eq!(
            SESSION_STR,
            &[0, 0, 0, 7, b's', b'e', b's', b's', b'i', b'o', b'n']
        );
    }

    #[test]
    fn test_client_servicename_layout() {
        assert_eq!(CLIENT_SERVICENAME[..4], [0, 0, 0, 0x0C]);
        assert_eq!(&CLIENT_SERVICENAME[4..16], b"ssh-userauth");
    }

    #[test]
    fn test_ssh_service_layout() {
        assert_eq!(SSH_SERVICE[..4], [0, 0, 0, 14]);
        assert_eq!(&SSH_SERVICE[4..18], b"ssh-connection");
    }

    // ------------------------------------------------------------------
    // Phase 5 — parsing helpers
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_ssh_string_ok() {
        let buf = [0u8, 0, 0, 5, b'h', b'e', b'l', b'l', b'o', 0xAB, 0xCD];
        let mut offset = 0;
        let s = parse_ssh_string(&buf, &mut offset).unwrap();
        assert_eq!(s, b"hello");
        assert_eq!(offset, 9);
    }

    #[test]
    fn test_parse_ssh_string_zero_length() {
        let buf = [0u8, 0, 0, 0];
        let mut offset = 0;
        let s = parse_ssh_string(&buf, &mut offset).unwrap();
        assert!(s.is_empty());
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_parse_ssh_string_truncated_length() {
        let buf = [0u8, 0, 0]; // only 3 bytes — can't even read the length prefix.
        let mut offset = 0;
        assert!(parse_ssh_string(&buf, &mut offset).is_err());
    }

    #[test]
    fn test_parse_ssh_string_truncated_payload() {
        let buf = [0u8, 0, 0, 5, b'h', b'i']; // claims 5 bytes, only 2 follow.
        let mut offset = 0;
        assert!(parse_ssh_string(&buf, &mut offset).is_err());
    }

    #[test]
    fn test_parse_ssh_string_offset_past_end() {
        let buf = [0u8, 0, 0, 0];
        let mut offset = 4;
        assert!(parse_ssh_string(&buf, &mut offset).is_err());
    }

    #[test]
    fn test_parse_ssh_string_overflow_protection() {
        // declared length = 0xFFFF_FFFF; even the buffer length bound
        // check should reject this without overflowing usize on 32-bit.
        let buf = [0xFFu8, 0xFF, 0xFF, 0xFF, b'a'];
        let mut offset = 0;
        assert!(parse_ssh_string(&buf, &mut offset).is_err());
    }

    #[test]
    fn test_parse_u32_be() {
        let buf = [0u8, 0, 0, 42];
        let mut offset = 0;
        let v = parse_u32_be(&buf, &mut offset).unwrap();
        assert_eq!(v, 42);
        assert_eq!(offset, 4);

        let buf2 = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let mut offset2 = 0;
        assert_eq!(parse_u32_be(&buf2, &mut offset2).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn test_parse_u32_be_truncated() {
        let buf = [0u8, 0, 0];
        let mut offset = 0;
        assert!(parse_u32_be(&buf, &mut offset).is_err());
    }

    #[test]
    fn test_parse_bool() {
        let buf = [0u8, 1, 0xFF];
        let mut offset = 0;
        assert!(!parse_bool(&buf, &mut offset).unwrap());
        assert_eq!(offset, 1);
        assert!(parse_bool(&buf, &mut offset).unwrap());
        assert_eq!(offset, 2);
        // RFC 4251 §5: any nonzero is true.
        assert!(parse_bool(&buf, &mut offset).unwrap());
        assert_eq!(offset, 3);
    }

    #[test]
    fn test_parse_bool_at_eof() {
        let buf = [];
        let mut offset = 0;
        assert!(parse_bool(&buf, &mut offset).is_err());
    }

    // ------------------------------------------------------------------
    // Phase 6 — server-side handlers
    // ------------------------------------------------------------------

    #[test]
    fn test_service_request_accepts_ssh_userauth() {
        let result = handle_service_request(CLIENT_SERVICENAME).unwrap();
        assert_eq!(result.accept_payload, CLIENT_SERVICENAME.to_vec());
        assert!(result.advance_stage);
    }

    #[test]
    fn test_service_request_rejects_wrong_service() {
        // 16-byte buffer (matches expected length) but wrong content.
        let bogus = [
            0u8, 0, 0, 0x0C, b's', b's', b'h', b'-', b'c', b'o', b'n', b'n', b'e', b'c', b't', b'p',
        ];
        assert!(handle_service_request(&bogus).is_err());
    }

    #[test]
    fn test_service_request_rejects_wrong_length() {
        // 14-byte buffer.
        let too_short = [0u8; 14];
        assert!(handle_service_request(&too_short).is_err());

        // 17-byte buffer (one byte too many).
        let too_long = [0u8; 17];
        assert!(handle_service_request(&too_long).is_err());
    }

    /// Helper: builds a valid `password`-method userauth-request body
    /// for `username`/`password`. Layout matches the FASM-parsed
    /// expectations of `.got_userauth_request`.
    fn build_password_userauth_body(username: &str, password: &str) -> Vec<u8> {
        let mut out = Vec::new();
        // username string
        out.extend_from_slice(&(username.len() as u32).to_be_bytes());
        out.extend_from_slice(username.as_bytes());
        // service-name = "ssh-connection"
        out.extend_from_slice(SSH_SERVICE);
        // method-name = "password"
        out.extend_from_slice(&[0, 0, 0, 8, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd']);
        // partial-success bool = 0
        out.push(0);
        // password string
        out.extend_from_slice(&(password.len() as u32).to_be_bytes());
        out.extend_from_slice(password.as_bytes());
        out
    }

    #[test]
    fn test_userauth_request_immediate_success_no_callback() {
        let body = build_password_userauth_body("alice", "hunter2");
        let (parsed, outcome) = handle_userauth_request(&body, None).unwrap();
        assert_eq!(parsed.username, "alice");
        assert_eq!(parsed.password, "hunter2");
        assert_eq!(parsed.servicename, b"ssh-connection".to_vec());
        assert_eq!(outcome, AuthOutcome::NoCallback);
    }

    #[test]
    fn test_userauth_request_granted() {
        let body = build_password_userauth_body("bob", "s3cret");
        let cb: AuthCallback = Arc::new(|user, pass| user == "bob" && pass == "s3cret");
        let (parsed, outcome) = handle_userauth_request(&body, Some(&cb)).unwrap();
        assert_eq!(parsed.username, "bob");
        assert_eq!(parsed.password, "s3cret");
        assert_eq!(outcome, AuthOutcome::Granted);
    }

    #[test]
    fn test_userauth_request_denied_by_callback() {
        let body = build_password_userauth_body("eve", "wrongpw");
        let cb: AuthCallback = Arc::new(|_u, _p| false);
        let (parsed, outcome) = handle_userauth_request(&body, Some(&cb)).unwrap();
        assert_eq!(parsed.username, "eve");
        assert_eq!(parsed.password, "wrongpw");
        assert_eq!(outcome, AuthOutcome::Denied);
    }

    #[test]
    fn test_userauth_request_callback_sees_correct_args() {
        use std::sync::Mutex;
        let captured: Arc<Mutex<Option<(String, String)>>> = Arc::new(Mutex::new(None));
        let captured_cb = Arc::clone(&captured);
        let cb: AuthCallback = Arc::new(move |u, p| {
            *captured_cb.lock().unwrap() = Some((u.to_string(), p.to_string()));
            true
        });
        let body = build_password_userauth_body("carol", "passw0rd");
        let (_, outcome) = handle_userauth_request(&body, Some(&cb)).unwrap();
        assert_eq!(outcome, AuthOutcome::Granted);
        let cap = captured.lock().unwrap();
        let (u, p) = cap.as_ref().expect("callback should have been invoked");
        assert_eq!(u, "carol");
        assert_eq!(p, "passw0rd");
    }

    #[test]
    fn test_userauth_request_wrong_method_publickey() {
        // Build a userauth-request with method="publickey" instead of
        // "password". FASM `fail2` path → AuthOutcome::Denied (NOT Err).
        let mut body = Vec::new();
        body.extend_from_slice(&5u32.to_be_bytes()); // username len
        body.extend_from_slice(b"alice");
        body.extend_from_slice(SSH_SERVICE);
        body.extend_from_slice(&9u32.to_be_bytes()); // method-name len = 9
        body.extend_from_slice(b"publickey");
        // No more bytes needed after method (parser short-circuits).
        // But add some padding to ensure we're past 20 bytes.
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);

        let cb: AuthCallback = Arc::new(|_u, _p| true);
        let (parsed, outcome) = handle_userauth_request(&body, Some(&cb)).unwrap();
        assert_eq!(parsed.username, "alice");
        assert_eq!(parsed.password, ""); // short-circuited before reading password
        assert_eq!(outcome, AuthOutcome::Denied);
    }

    #[test]
    fn test_userauth_request_too_short() {
        // 19 bytes — below the 20-byte minimum.
        let body = [0u8; 19];
        assert!(handle_userauth_request(&body, None).is_err());
    }

    #[test]
    fn test_userauth_request_invalid_utf8_username() {
        // Build a body where the username bytes are invalid UTF-8.
        let mut body = Vec::new();
        body.extend_from_slice(&2u32.to_be_bytes()); // claim 2-byte username
        body.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8 prefix
        body.extend_from_slice(SSH_SERVICE);
        body.extend_from_slice(&[0, 0, 0, 8, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd']);
        body.push(0);
        body.extend_from_slice(&0u32.to_be_bytes()); // empty password

        assert!(handle_userauth_request(&body, None).is_err());
    }

    #[test]
    fn test_userauth_request_truncated_method() {
        // Username+service parse OK, but method length claims more bytes
        // than the buffer contains.
        let mut body = Vec::new();
        body.extend_from_slice(&3u32.to_be_bytes()); // username len
        body.extend_from_slice(b"abc");
        body.extend_from_slice(SSH_SERVICE);
        body.extend_from_slice(&100u32.to_be_bytes()); // claim 100-byte method
                                                       // No method bytes follow → truncation → fail1.
                                                       // Pad to satisfy the 20-byte minimum check.
        while body.len() < 24 {
            body.push(0);
        }

        assert!(handle_userauth_request(&body, None).is_err());
    }

    #[test]
    fn test_build_userauth_failure_payload_returns_authfail() {
        assert_eq!(build_userauth_failure_payload(), AUTHFAIL_PAYLOAD);
    }

    // ------------------------------------------------------------------
    // Phase 7 — client-side handlers
    // ------------------------------------------------------------------

    #[test]
    fn test_build_client_service_request_returns_ssh_userauth() {
        assert_eq!(build_client_service_request(), CLIENT_SERVICENAME.to_vec());
    }

    #[test]
    fn test_build_client_userauth_request_default_taketwo() {
        let out = build_client_userauth_request(&AuthArgs::DefaultTaketwo);
        assert_eq!(out, DEFAULT_AUTH.to_vec());
    }

    #[test]
    fn test_build_client_userauth_request_username_only() {
        let args = AuthArgs::UsernameOnly { username: "alice" };
        let out = build_client_userauth_request(&args);
        // Layout: [0,0,0,5, 'a','l','i','c','e'] || SSH_SERVICE || NO_METHOD
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0, 0, 0, 5, b'a', b'l', b'i', b'c', b'e']);
        expected.extend_from_slice(SSH_SERVICE);
        expected.extend_from_slice(NO_METHOD);
        assert_eq!(out, expected);
        // Sanity: ends with "none".
        assert_eq!(&out[out.len() - 4..], b"none");
    }

    #[test]
    fn test_build_client_userauth_request_user_pass() {
        let args = AuthArgs::UsernameAndPassword {
            username: "alice",
            password: "ignored-here",
        };
        let out = build_client_userauth_request(&args);
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0, 0, 0, 5, b'a', b'l', b'i', b'c', b'e']);
        expected.extend_from_slice(SSH_SERVICE);
        expected.extend_from_slice(KEYBOARD_INTERACTIVE);
        assert_eq!(out, expected);
        // Sanity: the password bytes do NOT appear anywhere — they
        // ride in the later USERAUTH_INFO_RESPONSE, not this frame.
        assert!(!out.windows(b"ignored-here".len()).any(|w| w == b"ignored-here"));
    }

    #[test]
    fn test_build_client_userauth_request_empty_username_only() {
        let args = AuthArgs::UsernameOnly { username: "" };
        let out = build_client_userauth_request(&args);
        // [0,0,0,0] (zero-length username) || SSH_SERVICE || NO_METHOD
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0, 0, 0, 0]);
        expected.extend_from_slice(SSH_SERVICE);
        expected.extend_from_slice(NO_METHOD);
        assert_eq!(out, expected);
    }

    #[test]
    fn test_build_random_ignore_payload_length_prefix_consistent() {
        // We MUST initialise the RNG once before any rng:: calls.
        // The initialization is idempotent enough that repeated calls
        // are tolerated; each test crate calls it independently.
        let _ = rng::init();

        let payload = build_random_ignore_payload();
        assert!(
            payload.len() >= 4,
            "payload must contain at least the 4-byte length prefix"
        );
        let claimed_len_bytes: [u8; 4] = payload[..4].try_into().unwrap();
        let claimed_len = u32::from_be_bytes(claimed_len_bytes) as usize;
        assert_eq!(
            claimed_len,
            payload.len() - 4,
            "length prefix must equal the body length"
        );
        // Range constraint: 16 <= claimed_len <= 255.
        assert!(
            (16..=255).contains(&claimed_len),
            "claimed_len {claimed_len} must be in [16, 255]"
        );
    }

    #[test]
    fn test_build_random_ignore_payload_varies() {
        // Two consecutive calls should (with overwhelming probability)
        // produce different bodies. If both are byte-identical we have
        // a bug in the RNG plumbing.
        let _ = rng::init();
        let p1 = build_random_ignore_payload();
        let p2 = build_random_ignore_payload();
        // Compare the bodies (post-length-prefix). If lengths differ the
        // assertion trivially passes; if they match we compare bytes.
        if p1.len() == p2.len() {
            assert_ne!(&p1[4..], &p2[4..], "two RNG draws yielded identical bodies");
        }
    }

    #[test]
    fn test_handle_userauth_info_request_no_prompts() {
        // 3 empty strings + uint32 num_prompts=0.
        let body = [0u8; 16];
        let resp = handle_userauth_info_request(&body, None).unwrap();
        // Empty info-response: [0,0,0,0] (num-responses=0).
        assert_eq!(resp.0, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_handle_userauth_info_request_one_prompt_with_password() {
        // name="A", instruction="B", language="C", num-prompts=1, then
        // a prompt string "P:" + bool echo (we do not parse those — the
        // FASM source ignores them).
        let mut body = Vec::new();
        body.extend_from_slice(&[0, 0, 0, 1, b'A']); // name
        body.extend_from_slice(&[0, 0, 0, 1, b'B']); // instruction
        body.extend_from_slice(&[0, 0, 0, 1, b'C']); // language
        body.extend_from_slice(&1u32.to_be_bytes()); // num_prompts = 1
        body.extend_from_slice(&[0, 0, 0, 2, b'P', b':']); // prompt
        body.push(1); // echo

        let resp = handle_userauth_info_request(&body, Some("hunter2")).unwrap();
        // Expected: [0,0,0,1] (num-responses=1) || [0,0,0,7,"hunter2"]
        let mut expected = Vec::new();
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(&7u32.to_be_bytes());
        expected.extend_from_slice(b"hunter2");
        assert_eq!(resp.0, expected);
    }

    #[test]
    fn test_handle_userauth_info_request_one_prompt_no_password() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0, 0, 0, 0]); // name
        body.extend_from_slice(&[0, 0, 0, 0]); // instruction
        body.extend_from_slice(&[0, 0, 0, 0]); // language
        body.extend_from_slice(&1u32.to_be_bytes()); // num_prompts = 1

        assert!(handle_userauth_info_request(&body, None).is_err());
    }

    #[test]
    fn test_handle_userauth_info_request_too_many_prompts() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0, 0, 0, 0]); // name
        body.extend_from_slice(&[0, 0, 0, 0]); // instruction
        body.extend_from_slice(&[0, 0, 0, 0]); // language
        body.extend_from_slice(&2u32.to_be_bytes()); // num_prompts = 2 → fail

        assert!(handle_userauth_info_request(&body, Some("anything")).is_err());
    }

    #[test]
    fn test_handle_userauth_info_request_truncated() {
        // 4 bytes — can't even parse the first string's length field
        // beyond the prefix.
        let body = [0u8, 0, 0, 5];
        assert!(handle_userauth_info_request(&body, None).is_err());
    }

    #[test]
    fn test_handle_userauth_info_request_empty_password_one_prompt() {
        // num_prompts == 1, password is Some(""). Should produce a
        // valid response with a zero-length password string.
        let mut body = Vec::new();
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.extend_from_slice(&1u32.to_be_bytes());

        let resp = handle_userauth_info_request(&body, Some("")).unwrap();
        // [0,0,0,1] (num-responses=1) || [0,0,0,0] (zero-length password)
        assert_eq!(resp.0, vec![0, 0, 0, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn test_handle_userauth_success_channel_payload() {
        let _ = rng::init();
        let frame = handle_userauth_success();
        let payload = &frame.channel_open_payload;

        // Must be exactly 23 bytes.
        assert_eq!(payload.len(), SESSION_STR.len() + 4 + 4 + 4);
        assert_eq!(payload.len(), 23);

        // Prefix == SESSION_STR.
        assert_eq!(&payload[..SESSION_STR.len()], SESSION_STR);

        // Channel ID (BE u32) at bytes 11..15.
        let cid_bytes: [u8; 4] = payload[11..15].try_into().unwrap();
        assert_eq!(u32::from_be_bytes(cid_bytes), frame.channel_id);

        // Initial window: 0x7FFF_FFFF (BE) at bytes 15..19.
        assert_eq!(payload[15..19], [0x7F, 0xFF, 0xFF, 0xFF]);

        // Max packet size: 32768 (BE u32 = 0x0000_8000) at bytes 19..23.
        assert_eq!(payload[19..23], [0x00, 0x00, 0x80, 0x00]);
    }

    #[test]
    fn test_handle_userauth_success_channel_id_varies() {
        let _ = rng::init();
        let f1 = handle_userauth_success();
        let f2 = handle_userauth_success();
        // Two consecutive calls should (with overwhelming probability)
        // produce different channel IDs.
        assert_ne!(f1.channel_id, f2.channel_id);
    }

    #[test]
    fn test_handle_userauth_failure_returns_auth_error() {
        let err = handle_userauth_failure();
        assert!(matches!(err, SshError::Auth));
    }

    #[test]
    fn test_handle_ignore_returns_ok() {
        assert!(handle_ignore().is_ok());
    }

    // ------------------------------------------------------------------
    // Trait-bound and type-level assertions
    // ------------------------------------------------------------------

    #[test]
    fn test_authcallback_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AuthCallback>();
    }

    #[test]
    fn test_authoutcome_value_semantics() {
        // AuthOutcome must be copyable and usable in pattern matches.
        let g = AuthOutcome::Granted;
        let g2 = g; // Copy
        assert_eq!(g, g2);
        assert_ne!(AuthOutcome::Granted, AuthOutcome::Denied);
        assert_ne!(AuthOutcome::Granted, AuthOutcome::NoCallback);
        assert_ne!(AuthOutcome::Denied, AuthOutcome::NoCallback);
    }

    #[test]
    fn test_authargs_lifetime_compiles() {
        // Compile-time exercise: AuthArgs holds &str references
        // bound to local storage.
        let user = String::from("dave");
        let pass = String::from("topsecret");
        let args = AuthArgs::UsernameAndPassword {
            username: &user,
            password: &pass,
        };
        let frame = build_client_userauth_request(&args);
        assert!(!frame.is_empty());
        // Use `user` and `pass` after the borrow ends to confirm
        // storage outlives the borrow.
        assert_eq!(user.len() + pass.len(), 13);
    }

    #[test]
    fn test_userauth_success_payload_is_empty() {
        // Defensive sanity check on the exported empty-slice constant.
        assert_eq!(USERAUTH_SUCCESS_PAYLOAD.len(), 0);
        assert!(USERAUTH_SUCCESS_PAYLOAD.is_empty());
    }
}
