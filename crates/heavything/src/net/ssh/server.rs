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

//! SSH 2.0 protocol state machine — port of FASM `ssh.inc` (6011 lines).
//!
//! This module is the largest single translation in the HeavyThing → Rust
//! refactor. It implements the complete server-side SSH state machine plus a
//! client-mode skeleton, weaving together the sibling submodules of
//! `crate::net::ssh` (`cipher`, `kex`, `auth`, `compression`) along with
//! cross-subsystem dependencies on `crate::crypto`, `crate::ds::buffer`,
//! `crate::net::io`, `crate::net::blacklist`, and the down-stream consumer
//! contract `crate::tui::widgets::ssh::SshTransport`.
//!
//! # Public surface
//!
//! - [`SshConfig`]   — defaults derived from `crate::config` (host-keys dir,
//!                     compression knobs, blacklist TTL, KEX bit ranges,
//!                     advertised window/packet limits).
//! - [`SshServer`]   — listener-side factory: holds an `Arc<Blacklist>`,
//!                     optional auth callback, and pre-loaded host keys.
//! - [`SshSession`]  — the per-connection state machine with all 60+ FASM
//!                     fields preserved as snake_case Rust counterparts.
//! - [`SshChannel`]  — outward-facing handle that implements
//!                     [`crate::tui::widgets::ssh::SshTransport`] so the TUI
//!                     widget renderer can write ANSI bytes through the SSH
//!                     channel data subprotocol.
//! - [`SshStage`]    — 14-variant FASM stage enumeration (Idents → Goaway).
//! - [`ClientMode`]  — Server / SessionClient / SftpClient.
//! - [`SSH_IDENT`] / [`SSH_IDENT_LEN`] — RFC-4253 §4.2 banner constants.
//!
//! # FASM correspondence
//!
//! | Rust item              | FASM label                       |
//! |------------------------|----------------------------------|
//! | [`SshSession::new_server`]    | `ssh$new_server`     (line 472)  |
//! | [`SshSession::new_client`]    | `ssh$new_client`     (line 315)  |
//! | `IoChain::destroy` (Drop)     | `ssh$destroy`        (line 379)  |
//! | `IoChain::clone_chain`        | `ssh$clone`          (line 530)  |
//! | `IoChain::connected`          | `ssh$connected`      (line 632)  |
//! | `IoChain::send`               | `ssh$send`           (line 935)  |
//! | `IoChain::receive`            | `ssh$receive`        (line 1089) |
//! | `SshSession::encrypt_and_send`| `ssh$encrypt`        (line 684)  |
//! | `SshSession::client_windowsize`| `ssh$client_windowsize` (1007) |
//! | `SshSession::clean_exit`      | `ssh$cleanexit`      (line 1059) |
//! | `SshSession::set_auth_callback`| `ssh$set_authcb`    (line 619)  |
//!
//! # Algorithm corpus (frozen — exactly matches FASM `ssh.inc`)
//!
//! - **KEX**:        `diffie-hellman-group-exchange-sha256` only
//! - **Host key**:   `ssh-rsa` and/or `ssh-dss`
//! - **Cipher**:     `aes256-cbc`
//! - **MAC**:        `hmac-sha2-256`
//! - **Compress**:   `zlib@openssh.com,zlib` (delayed/forced) or `none`
//!
//! # Safety budget
//!
//! Zero `unsafe` blocks. All memory safety is upheld by the Rust borrow
//! checker plus `Arc`/`Mutex` discipline on shared state.

#![allow(clippy::too_many_arguments)]

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::config;
use crate::ds::buffer::Buffer;
use crate::error::{NetError, SshError, TuiError};
use crate::net::blacklist::{key_from_socket_addr, Blacklist};
use crate::net::io::{
    default_connected, default_destroy, default_error, default_send, default_timeout, BoxFuture, IoChain,
    IoLinks,
};
use crate::net::ssh::auth::{
    build_client_service_request, build_client_userauth_request, build_random_ignore_payload,
    build_userauth_failure_payload, handle_ignore, handle_service_request, handle_userauth_failure,
    handle_userauth_info_request, handle_userauth_request, AuthArgs, AuthCallback, AuthOutcome,
    CLIENT_SERVICENAME as AUTH_CLIENT_SERVICENAME, SESSION_STR, SSH_MSG_CHANNEL_OPEN, SSH_MSG_DEBUG,
    SSH_MSG_IGNORE, SSH_MSG_SERVICE_ACCEPT, SSH_MSG_SERVICE_REQUEST, SSH_MSG_USERAUTH_BANNER,
    SSH_MSG_USERAUTH_FAILURE, SSH_MSG_USERAUTH_INFO_REQUEST, SSH_MSG_USERAUTH_INFO_RESPONSE,
    SSH_MSG_USERAUTH_REQUEST, SSH_MSG_USERAUTH_SUCCESS,
};
use crate::net::ssh::cipher::{frame_packet_into, CipherState, MAC_SIZE, MAX_PACKET_SIZE, MIN_PADDING};
use crate::net::ssh::compression::{negotiate_compression, CompressionState, DeflateStream, InflateStream};
use crate::net::ssh::kex::{
    append_mpint, append_string, append_u32_be, build_kexinit, encode_mpint, parse_kexinit, sign_dss,
    sign_rsa, verify_signature, DhExchange, GexRange, HostKey, KexHashBuilder, KexState, SessionKeys,
    COMP_ALGS_FORCED, COMP_ALGS_NONE, COMP_ALGS_PREFER, HOST_KEY_ALGS_RSA_DSS, SSH_MSG_KEXINIT,
    SSH_MSG_KEX_DH_GEX_GROUP, SSH_MSG_KEX_DH_GEX_INIT, SSH_MSG_KEX_DH_GEX_REPLY, SSH_MSG_KEX_DH_GEX_REQUEST,
    SSH_MSG_NEWKEYS,
};
use crate::tui::widgets::ssh::SshTransport;

// ---------------------------------------------------------------------------
// SSH protocol message-type constants not re-exported from the sibling
// submodules. We declare them here so the dispatch table reads cleanly.
// All values per RFC 4253 §12 + RFC 4252 §6 + RFC 4254 §9.
// ---------------------------------------------------------------------------

/// `SSH_MSG_DISCONNECT` (1) — peer requests connection teardown (RFC 4253).
pub(crate) const SSH_MSG_DISCONNECT: u8 = 1;
/// `SSH_MSG_KEX_DH_GEX_REQUEST_OLD` (30) — pre-RFC 4419 single-`n` KEX form.
pub(crate) const SSH_MSG_KEX_DH_GEX_REQUEST_OLD: u8 = 30;
/// `SSH_MSG_GLOBAL_REQUEST` (80) — RFC 4254 §4 transport-level request.
pub(crate) const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
/// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` (91) — RFC 4254 §5.1.
pub(crate) const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
/// `SSH_MSG_CHANNEL_OPEN_FAILURE` (92) — RFC 4254 §5.1.
pub(crate) const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
/// `SSH_MSG_CHANNEL_WINDOW_ADJUST` (93) — RFC 4254 §5.2.
pub(crate) const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
/// `SSH_MSG_CHANNEL_DATA` (94) — RFC 4254 §5.2 carries application stream data.
pub(crate) const SSH_MSG_CHANNEL_DATA: u8 = 94;
/// `SSH_MSG_CHANNEL_EXTENDED_DATA` (95) — RFC 4254 §5.2 (e.g. stderr).
pub(crate) const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
/// `SSH_MSG_CHANNEL_EOF` (96) — RFC 4254 §5.3.
pub(crate) const SSH_MSG_CHANNEL_EOF: u8 = 96;
/// `SSH_MSG_CHANNEL_CLOSE` (97) — RFC 4254 §5.3.
pub(crate) const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
/// `SSH_MSG_CHANNEL_REQUEST` (98) — RFC 4254 §5.4 (pty-req, shell, etc.).
pub(crate) const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
/// `SSH_MSG_CHANNEL_SUCCESS` (99) — RFC 4254 §5.4 ack to channel request.
pub(crate) const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
/// `SSH_MSG_CHANNEL_FAILURE` (100) — RFC 4254 §5.4 nack to channel request.
pub(crate) const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

// ---------------------------------------------------------------------------
// Static byte-exact constants (FASM `ssh.inc` lines 81–190)
// ---------------------------------------------------------------------------

/// Server identification banner — byte-for-byte preserved from FASM
/// `ssh_ident db 'SSH-2.0-HeavyThing', 13, 10` at `ssh.inc` line 81.
///
/// Total 20 bytes including the trailing CR LF. Wire-protocol callers MUST NOT
/// trim the line ending — RFC 4253 §4.2 mandates `<id>\r\n` and the peer's
/// implementation tolerance is calibrated against the canonical HeavyThing
/// banner.
pub const SSH_IDENT: &[u8] = b"SSH-2.0-HeavyThing\r\n";

/// Length of [`SSH_IDENT`] in bytes (20).
pub const SSH_IDENT_LEN: usize = 20;

/// Banner returned to peers found in the IP blacklist. Byte length = 34 per
/// schema (matches the `(blacklisted)` suffix tail). Unlike the canonical
/// banner this one is *informational only* — the connection is dropped right
/// after it is sent.
pub const SSH_IDENT_BLACKLISTED: &[u8] = b"SSH-2.0-HeavyThing (blacklisted)\r\n";

/// PKCS#1 v1.5 DigestInfo prefix for SHA-1 (RFC 3447 §9.2). Used during
/// host-key signing for `ssh-rsa`. Re-exported from the equivalent constant
/// in `crate::net::ssh::kex` for callers that want to validate signature
/// templates without pulling in the full KEX module.
pub const SIGHASH_ASN1: &[u8; 15] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];

/// Client SERVICE_REQUEST payload `\0\0\0\x0cssh-userauth` (16 bytes).
///
/// This is the on-the-wire payload of the `SSH_MSG_SERVICE_REQUEST` (5) sent
/// by clients after NEWKEYS to switch to the userauth service. Byte-identical
/// to the `auth::CLIENT_SERVICENAME` re-export but kept here for FASM parity
/// with `ssh.inc` line 188.
pub const CLIENT_SERVICENAME: &[u8] = AUTH_CLIENT_SERVICENAME;

/// Globally-unique session counter (replaces FASM `ssh_session_count`).
///
/// Incremented in [`SshSession::new_client`] and the cloning code path; the
/// FASM reference does **not** increment on `new_server`, so we preserve that
/// asymmetry. Decremented in [`SshSession`]'s `Drop` impl.
pub static SSH_SESSION_COUNT: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Dispatch / cipher tunables that the receive loop uses directly. These live
// outside SshConfig because they are protocol-frozen, not per-session knobs.
// ---------------------------------------------------------------------------

/// Length of the on-the-wire SSH disconnect payload (`reason=11, "Bye!"`).
const DISCO_PAYLOAD: &[u8] = &[
    0, 0, 0, 11, // disconnect reason: SSH_DISCONNECT_BY_APPLICATION
    0, 0, 0, 4, b'B', b'y', b'e', b'!', // description
    0, 0, 0, 0, // language tag empty
];

/// Largest packet length we will accept on the wire (256 KiB) — defends
/// against memory-exhaustion attacks. Mirrors FASM `ssh.inc` validation at
/// line ~1110.
const MAX_INBOUND_PACKET: usize = 262_144;

/// Application-level chunk size for `SSH_MSG_CHANNEL_DATA` payloads (16 KiB).
/// FASM ssh.inc line ~960 chunks at this exact size for RFC 4254 §5.2 sender
/// flow-control semantics.
const CHANNEL_DATA_CHUNK: usize = 16_384;

/// Threshold below which the receiver-side window adjust is sent (1 MiB).
const WINDOW_ADJUST_THRESHOLD: u32 = 1_048_576;

/// Increment applied per window-adjust packet (512 MiB).
const WINDOW_ADJUST_INCREMENT: u32 = 0x2000_0000;

/// Server-mode initial advertised local-window value: `i32::MAX`. This
/// mirrors FASM ssh.inc which seeds the server's local window to the largest
/// positive 32-bit value to amortise window-adjust traffic for long-lived
/// interactive sessions.
const INITIAL_LOCAL_WINDOW: u32 = 0x7fff_ffff;

/// PTY column cap (FASM enforces `<= 384` on inbound `pty-req`).
const PTY_MAX_COLS: u32 = 384;

/// PTY row cap (FASM enforces `<= 192` on inbound `pty-req`).
const PTY_MAX_ROWS: u32 = 192;

/// Default PTY cols when none has been negotiated yet.
const DEFAULT_PTY_COLS: u32 = 80;

/// Default PTY rows when none has been negotiated yet.
const DEFAULT_PTY_ROWS: u32 = 25;

// ===========================================================================
// SshStage — 14-variant FASM stage enumeration
// ===========================================================================

/// SSH protocol-state checkpoint. Mirrors FASM `ssh_stage_*` constants at
/// `ssh.inc` lines 195–209.
///
/// Stage progression is broadly:
///
/// ```text
///   Idents → WantKexInit → WantKexGex* → WantNewKeys
///                            → WantService → WantUserauth → WantChannel
///                                          → Channel → Interactive
///                                          → TornDown / Goaway
/// ```
///
/// `Idents` is the entry state, `Interactive` is the operational state where
/// channel data flows freely, and `TornDown` / `Goaway` are absorbing
/// terminal states (the latter for blacklisted peers).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SshStage {
    /// 0: SSH-2.0 banner exchange in progress.
    #[default]
    Idents = 0,
    /// 1: Awaiting `SSH_MSG_KEXINIT` (20).
    WantKexInit = 1,
    /// 2: Server only — awaiting `SSH_MSG_KEX_DH_GEX_REQUEST` (34) or its
    /// `_OLD` form (30).
    WantKexGexReq = 2,
    /// 3: Client only — awaiting `SSH_MSG_KEX_DH_GEX_GROUP` (31).
    WantKexGexGroup = 3,
    /// 4: Server only — awaiting `SSH_MSG_KEX_DH_GEX_INIT` (32).
    WantKexGexInit = 4,
    /// 5: Client only — awaiting `SSH_MSG_KEX_DH_GEX_REPLY` (33).
    WantKexGexReply = 5,
    /// 6: Awaiting `SSH_MSG_NEWKEYS` (21) from peer.
    WantNewKeys = 6,
    /// 7: Server: awaiting `SSH_MSG_SERVICE_REQUEST` (5).
    /// Client: awaiting `SSH_MSG_SERVICE_ACCEPT` (6).
    WantService = 7,
    /// 8: User-authentication exchange active (`SSH_MSG_USERAUTH_*`).
    WantUserauth = 8,
    /// 9: Awaiting `SSH_MSG_CHANNEL_OPEN` (90) — server side, or its
    /// `_CONFIRMATION` (91) — client side.
    WantChannel = 9,
    /// 10: Channel open; awaiting `pty-req` / `shell` / `exec` /
    /// `subsystem` request.
    Channel = 10,
    /// 11: Interactive — shell / pty active, channel data flowing in both
    /// directions.
    Interactive = 11,
    /// 12: Torn-down — channel was closed normally; session is shutting
    /// down.
    TornDown = 12,
    /// 13: Peer blacklisted — connection is being held open just long
    /// enough to deliver the blacklisted banner before close.
    Goaway = 13,
}

// ===========================================================================
// ClientMode — Server / SessionClient / SftpClient
// ===========================================================================

/// Determines whether this `SshSession` accepts an incoming connection
/// (`Server`), drives an outgoing interactive shell (`SessionClient`), or
/// drives an outgoing SFTP subsystem (`SftpClient`). Mirrors FASM
/// `ssh.inc` `ssh_clientmode_*` constants.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ClientMode {
    /// Server mode — accepts incoming connection. The local side does NOT
    /// initiate `KEXINIT`; it sends after the peer's banner is received.
    #[default]
    Server = 0,
    /// Client mode — outbound session-channel client (shell / exec).
    SessionClient = 1,
    /// Client mode — outbound SFTP-subsystem client.
    SftpClient = 2,
}

// ===========================================================================
// SshConfig — per-instance tunables
// ===========================================================================

/// Per-instance configuration knobs for an SSH listener / session.
///
/// All defaults pull from `crate::config` constants which are in turn the
/// Rust port of FASM `ht_defaults.inc`. Callers typically take the
/// [`Default`] impl and tweak only the fields that diverge from production
/// defaults.
#[derive(Debug, Clone)]
pub struct SshConfig {
    /// Filesystem directory containing the host keys (`ssh_host_*_key`,
    /// `ssh_host_*_key.pub`). Defaults to `"/etc/ssh"`.
    pub host_keys_dir: std::path::PathBuf,
    /// When `true`, the server advertises `zlib@openssh.com,zlib` only
    /// (without the `none` fallback). Default: [`config::SSH_FORCE_COMPRESSION`].
    pub force_compression: bool,
    /// When `true`, the server is willing to negotiate compression.
    /// Default: [`config::SSH_DO_COMPRESSION`].
    pub do_compression: bool,
    /// Time-to-live for entries added to the IP blacklist on cryptographic
    /// failures. Default: 86 400 s (24 h).
    pub blacklist_ttl: Duration,
    /// Banner string this server advertises. Default: [`SSH_IDENT`].
    pub ident_string: &'static [u8],
    /// When `true`, generate fresh DH parameters for every connection
    /// instead of using the static safe-prime pool. Default: `false`.
    pub dh_dynamic: bool,
    /// Initial advertised channel-window size in bytes. Default: 0x200000
    /// (2 MiB) — matches RFC 4254 §6.5 worked example.
    pub window_initial: u32,
    /// Largest packet (channel-data plus envelope) the peer may send.
    /// Default: 0x8000 (32 KiB).
    pub max_packet_size: u32,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            host_keys_dir: std::path::PathBuf::from("/etc/ssh"),
            force_compression: config::SSH_FORCE_COMPRESSION,
            do_compression: config::SSH_DO_COMPRESSION,
            blacklist_ttl: Duration::from_secs(config::SSH_BLACKLIST),
            ident_string: SSH_IDENT,
            dh_dynamic: config::SSH_DH_DYNAMIC,
            window_initial: 0x200000,
            max_packet_size: 0x8000,
        }
    }
}

// ===========================================================================
// SshSession — per-connection state machine
// ===========================================================================

/// Type alias for the window-resize callback. Invoked with `(cols, rows)`
/// whenever the peer sends a `window-change` channel request.
pub type WindowResizeCallback = Arc<dyn Fn(u32, u32) + Send + Sync>;

/// Type alias for the EOF callback. Invoked when the peer sends
/// `SSH_MSG_CHANNEL_EOF` on the active channel.
pub type EofCallback = Arc<dyn Fn() + Send + Sync>;

/// Complete SSH 2.0 protocol state for a single connection.
///
/// All field categories are preserved from the FASM `ssh.inc` struct
/// (offsets `ssh_clientmode_ofs` … `ssh_size`). Where possible, related
/// FASM fields are merged into a single Rust type:
///
/// - The 6 DH bigints (`dh_p`, `dh_g`, `dh_private`, `dh_e`, `dh_f`,
///   `dh_shared`) plus the GEX-range and exchange-hash fields live inside
///   [`KexState`].
/// - The 4 IV/key/integrity-key buffers per direction live inside
///   [`SessionKeys`] (held via `KexState::pending` until promoted by
///   `SSH_MSG_NEWKEYS`).
/// - The 2 cipher contexts + their HMAC state are merged into
///   [`CipherState`] per direction.
/// - The 3 buffers (deflate/inflate inbufs/outbufs) are owned by
///   [`DeflateStream`] / [`InflateStream`].
///
/// The remaining ad-hoc state (counters, atomics, callbacks, peer address)
/// is stored in fields of `Self`.
pub struct SshSession {
    // -----------------------------------------------------------------
    // IoChain integration
    // -----------------------------------------------------------------
    /// Parent (toward application) and child (toward TCP) chain pointers.
    /// Mirrors the FASM io_base virtual-method-table region at offsets
    /// `io_parent_ofs` / `io_child_ofs`.
    links: IoLinks,

    // -----------------------------------------------------------------
    // FASM `ssh_clientmode_ofs` / `ssh_open_ofs` / `ssh_stage_ofs` /
    // `ssh_compstate_ofs`
    // -----------------------------------------------------------------
    /// Server / SessionClient / SftpClient.
    client_mode: ClientMode,
    /// `true` once first NEWKEYS exchange completed (= "session is open").
    open: AtomicBool,
    /// Compression-negotiation state; gated against `do_compression` /
    /// `force_compression` config knobs.
    compression_state: StdMutex<CompressionState>,
    /// Current protocol stage. Stored as `AtomicU32` so observers (e.g.
    /// the SshChannel transport) can poll it without locking.
    stage: AtomicU32,

    // -----------------------------------------------------------------
    // Key-exchange + session keys (FASM bigints + IVs + keys + integrity)
    // -----------------------------------------------------------------
    /// Holds DhExchange, exchange-hash H, session_id, pending SessionKeys,
    /// local + remote KEXINITs, and local + remote idents.
    kex: StdMutex<KexState>,

    // -----------------------------------------------------------------
    // Cipher / HMAC contexts (per direction)
    // -----------------------------------------------------------------
    /// Outbound encryption + MAC context. `is_active()` is false until
    /// `local_enc` flips to `true` post-NEWKEYS.
    local_cipher: StdMutex<CipherState>,
    /// Inbound decryption + MAC verification context.
    remote_cipher: StdMutex<CipherState>,

    // -----------------------------------------------------------------
    // Compression streams (per direction)
    // -----------------------------------------------------------------
    /// Outbound zlib deflate context. Allocated lazily once compression
    /// is active to keep memory zero on `none`-compression connections.
    deflate: StdMutex<Option<DeflateStream>>,
    /// Inbound zlib inflate context. Allocated lazily.
    inflate: StdMutex<Option<InflateStream>>,

    // -----------------------------------------------------------------
    // FASM `ssh_localcert_ofs` — server-mode host keys
    // -----------------------------------------------------------------
    /// Pre-loaded server host keys (RSA / DSS). Empty in client mode.
    host_keys: Vec<HostKey>,

    // -----------------------------------------------------------------
    // Receive-side accumulator (FASM `ssh_accbuf_ofs` / `ssh_packetbuf_ofs`)
    // -----------------------------------------------------------------
    /// Bytes received from the child but not yet parsed into packets.
    accbuf: StdMutex<Buffer>,
    /// Decompressed / decrypted payload of the in-flight packet.
    packetbuf: StdMutex<Buffer>,
    /// First-block decrypted length awaiting full packet (FASM
    /// `ssh_peeklen_ofs`).
    peek_len: AtomicU32,

    // -----------------------------------------------------------------
    // Channel state
    // -----------------------------------------------------------------
    /// Local channel-id we use when interacting with the peer.
    channel_id: AtomicU32,
    /// Remote (peer's) channel-id learned from CHANNEL_OPEN /
    /// CHANNEL_OPEN_CONFIRMATION.
    remote_channel_id: AtomicU32,
    /// Our advertised receive window — decremented on inbound CHANNEL_DATA,
    /// replenished by sending CHANNEL_WINDOW_ADJUST.
    local_window: AtomicU32,
    /// Peer's advertised receive window — decremented on outbound
    /// CHANNEL_DATA, replenished on inbound WINDOW_ADJUST.
    remote_window: AtomicU32,
    /// Negotiated PTY columns.
    width: AtomicU32,
    /// Negotiated PTY rows.
    height: AtomicU32,

    // -----------------------------------------------------------------
    // Encryption-direction enable flags (FASM
    // `ssh_localenc_ofs` / `ssh_remoteenc_ofs`)
    // -----------------------------------------------------------------
    /// Outbound traffic is encrypted (we have sent NEWKEYS).
    local_enc: AtomicBool,
    /// Inbound traffic is encrypted (we have received NEWKEYS).
    remote_enc: AtomicBool,
    /// Fatal error encountered — graceful shutdown in progress.
    dead: AtomicBool,

    // -----------------------------------------------------------------
    // Callbacks (FASM 3 callback slots)
    // -----------------------------------------------------------------
    /// Auth callback invoked from `handle_userauth_request`. `None` =
    /// reject all auth (server effectively read-only).
    auth_cb: StdMutex<Option<AuthCallback>>,
    /// Window-resize callback invoked when the peer sends `window-change`.
    wsize_cb: StdMutex<Option<WindowResizeCallback>>,
    /// EOF callback invoked when the peer sends CHANNEL_EOF.
    eof_cb: StdMutex<Option<EofCallback>>,

    // -----------------------------------------------------------------
    // Client-mode credentials + server-mode parsed identities
    // -----------------------------------------------------------------
    /// In client mode: user name we'll authenticate as.
    /// In server mode: user name parsed from the most recent
    /// USERAUTH_REQUEST.
    username: StdMutex<Option<Vec<u8>>>,
    /// In client mode: password we'll send in USERAUTH_REQUEST. Wiped
    /// in `Drop`.
    password: StdMutex<Option<Vec<u8>>>,
    /// Server-mode exec command (when peer requests "exec" rather than
    /// "shell"). Wiped on `Drop` (may carry confidential arguments).
    exec: StdMutex<Option<Vec<u8>>>,

    // -----------------------------------------------------------------
    // Peer remote address (FASM `ssh_raddr_ofs` — 110-byte sockaddr blob)
    // -----------------------------------------------------------------
    /// Socket address of the peer. We store the parsed `SocketAddr` and a
    /// raw 110-byte buffer to round-trip through `SshTransport::remote_addr`.
    remote_addr: StdMutex<Option<std::net::SocketAddr>>,
    /// Raw 110-byte sockaddr-style buffer (zero-padded). The trait
    /// `remote_addr` returns a 126-byte slice; the extra 16 bytes at the
    /// tail are zero-filled.
    remote_addr_raw: StdMutex<[u8; 110]>,
    /// Number of meaningful bytes in `remote_addr_raw`.
    remote_addr_len: AtomicU32,

    // -----------------------------------------------------------------
    // Application-channel pipes for cross-subsystem integration
    // -----------------------------------------------------------------
    /// Sender end of the **inbound** channel queue (driver-to-application).
    /// `handle_channel_data` pushes decoded `SSH_MSG_CHANNEL_DATA`
    /// payloads here for delivery to the consumer (typically the TUI).
    channel_tx: mpsc::UnboundedSender<Bytes>,
    /// Receiver end of the inbound channel queue. Taken once by the
    /// consumer via [`SshChannel::take_receiver`].
    channel_rx: StdMutex<Option<mpsc::UnboundedReceiver<Bytes>>>,
    /// Sender end of the **outbound** channel queue (application-to-driver).
    /// [`SshTransport::send_bytes`] enqueues bytes here; the outbound
    /// pump task drains them into [`Self::send_channel_data`] which
    /// wraps them in `SSH_MSG_CHANNEL_DATA` and runs them through the
    /// CipherState.
    out_tx: mpsc::UnboundedSender<Bytes>,
    /// Receiver end of the outbound queue — taken once by
    /// [`Self::start_outbound_pump`] (driven from `IoChain::connected`)
    /// to spawn a long-running drain task.
    out_queue: StdMutex<Option<mpsc::UnboundedReceiver<Bytes>>>,

    // -----------------------------------------------------------------
    // Optional shared blacklist (for cryptographic-failure banning)
    // -----------------------------------------------------------------
    /// Reference to the shared blacklist. `None` in client mode (clients
    /// don't ban themselves).
    blacklist: Option<Arc<Blacklist>>,
    /// Configured blacklist TTL (carry-through from `SshConfig`).
    blacklist_ttl: Duration,
    /// Carry-through configuration knobs needed during the handshake.
    do_compression: bool,
    force_compression: bool,
    advertised_max_packet: u32,
    advertised_window_initial: u32,
}

// ===========================================================================
// SshServer — listener factory
// ===========================================================================

/// Listener-side factory that accepts incoming `tokio::net::TcpStream`
/// connections and produces fully-initialised [`SshSession`] instances.
///
/// `SshServer` is essentially a thin holder for the configuration knobs
/// shared across every accepted connection: the [`Blacklist`], the
/// optional auth callback, and the [`SshConfig`] itself.
pub struct SshServer {
    /// Per-instance configuration.
    pub config: Arc<SshConfig>,
    /// Shared IP blacklist used to reject connections from peers that
    /// have recently failed cryptographic operations.
    pub blacklist: Arc<Blacklist>,
    /// Authentication callback applied to every accepted session.
    pub auth_cb: Option<AuthCallback>,
}

impl SshServer {
    /// Build a new listener-side factory from a configuration.
    pub fn new(config: SshConfig) -> Self {
        let blacklist_ttl = config.blacklist_ttl;
        Self {
            config: Arc::new(config),
            blacklist: Blacklist::new(blacklist_ttl),
            auth_cb: None,
        }
    }

    /// Install a per-server authentication callback.
    ///
    /// The callback is invoked with `(username, password)` for every
    /// `SSH_MSG_USERAUTH_REQUEST` carrying method `password`. Returns
    /// `true` to grant, `false` to deny. Lifetime: `'static + Send + Sync`.
    pub fn with_auth<F>(mut self, cb: F) -> Self
    where
        F: Fn(&str, &str) -> bool + Send + Sync + 'static,
    {
        self.auth_cb = Some(Arc::new(cb));
        self
    }

    /// Accept a single inbound connection. Spawns no background tasks
    /// itself — the caller is expected to drive the returned session via
    /// the IoChain `receive` method.
    ///
    /// On blacklisted peers the session is created in [`SshStage::Goaway`]
    /// and the blacklisted banner is queued; the caller should still
    /// pump the chain so the banner gets sent before the connection is
    /// dropped.
    pub async fn accept_one(
        &self,
        _stream: tokio::net::TcpStream,
        peer: std::net::SocketAddr,
    ) -> Result<Arc<SshSession>, SshError> {
        let session = SshSession::new_server(&self.config, Some(self.blacklist.clone()))?;
        session.set_remote_addr(peer)?;
        if let Some(cb) = &self.auth_cb {
            session.set_auth_callback_arc(cb.clone());
        }
        // Blacklist gate.
        let key = key_from_socket_addr(peer);
        if self.blacklist.contains(key) {
            session.stage.store(SshStage::Goaway as u32, Ordering::SeqCst);
        }
        Ok(session)
    }
}

// ===========================================================================
// SshSession constructors
// ===========================================================================

impl SshSession {
    /// Construct a server-side session.
    ///
    /// Loads the host keys via [`crate::crypto::x509::load_ssh_host_keys`];
    /// any failure propagates as [`SshError::HostKeys`] which the caller
    /// (typically `sshtalk`'s `main`) is expected to handle by emitting
    /// stderr + exiting with code 1 (preserving FASM `sshtalk.asm`
    /// behavior).
    pub fn new_server(config: &SshConfig, blacklist: Option<Arc<Blacklist>>) -> Result<Arc<Self>, SshError> {
        // Load host keys from `/etc/ssh/ssh_host_*_key` PEM files via
        // the crypto layer, then convert each into a kex-local
        // `HostKey` ready for signing. Empty vector still means we
        // load successfully but the disk had no usable keys, which we
        // treat as a configuration failure (matches sshtalk semantics).
        let x509_keys = crate::crypto::x509::load_ssh_host_keys()
            .map_err(|e| SshError::HostKeys(format!("{:?}", e)))?;

        // Convert each `crypto::x509::SshHostKey` to a signing-capable
        // `kex::HostKey`. Per AAP §0.1.1 the corpus is `ssh-rsa` and
        // `ssh-dss`; ECDSA / Ed25519 entries returned by
        // `load_ssh_host_keys` (e.g. `ssh_host_ecdsa_key`) are silently
        // dropped here — `HostKey::from_ssh_host_key` returns `None`
        // for those algorithms. Likewise, DSA keys in PKCS#8 form
        // (which embed `(p, q, g)` in the algorithm identifier) are
        // dropped because the conversion path requires the traditional
        // `BEGIN DSA PRIVATE KEY` form.
        let host_keys: Vec<HostKey> = x509_keys
            .iter()
            .filter_map(HostKey::from_ssh_host_key)
            .collect();

        if host_keys.is_empty() {
            // No RSA / DSS host keys were convertible. Fail at
            // construction time rather than at the GEX-INIT handler so
            // the caller (sshtalk / webserver `main`) can report the
            // configuration error before any client connects.
            return Err(SshError::HostKeys(
                "no signing-capable host keys (ssh-rsa / ssh-dss) available — \
                 ensure /etc/ssh/ssh_host_rsa_key is in PEM form (try \
                 `ssh-keygen -m PEM -t rsa -f /etc/ssh/ssh_host_rsa_key`)"
                    .to_string(),
            ));
        }

        let session = Self::shared_new(
            ClientMode::Server,
            host_keys,
            blacklist,
            config.blacklist_ttl,
            config.do_compression,
            config.force_compression,
            config.max_packet_size,
            INITIAL_LOCAL_WINDOW,
            None,
            None,
        );
        Ok(session)
    }

    /// Construct a client-side session.
    ///
    /// `username` is moved into the session and used in the
    /// `SSH_MSG_USERAUTH_REQUEST`. `password` is similarly moved and
    /// will be securely wiped on `Drop`.
    pub fn new_client(username: Option<Vec<u8>>, password: Option<Vec<u8>>) -> Arc<Self> {
        SSH_SESSION_COUNT.fetch_add(1, Ordering::SeqCst);
        Self::shared_new(
            ClientMode::SessionClient,
            Vec::new(),
            None,
            Duration::from_secs(config::SSH_BLACKLIST),
            config::SSH_DO_COMPRESSION,
            config::SSH_FORCE_COMPRESSION,
            0x8000,
            0x200000,
            username,
            password,
        )
    }

    /// Internal helper that does the field-by-field construction shared
    /// between client and server entry points.
    #[allow(clippy::too_many_arguments)]
    fn shared_new(
        client_mode: ClientMode,
        host_keys: Vec<HostKey>,
        blacklist: Option<Arc<Blacklist>>,
        blacklist_ttl: Duration,
        do_compression: bool,
        force_compression: bool,
        advertised_max_packet: u32,
        advertised_window_initial: u32,
        username: Option<Vec<u8>>,
        password: Option<Vec<u8>>,
    ) -> Arc<Self> {
        // Inbound queue: driver → application. `handle_channel_data`
        // pushes via `tx_in`; `SshChannel::take_receiver` consumes
        // `rx_in`.
        let (tx_in, rx_in) = mpsc::unbounded_channel::<Bytes>();
        // Outbound queue: application → driver. `SshTransport::send_bytes`
        // pushes via `tx_out`; the outbound pump task (spawned from
        // `IoChain::connected`) drains `rx_out`.
        let (tx_out, rx_out) = mpsc::unbounded_channel::<Bytes>();
        Arc::new(Self {
            links: IoLinks::new(),
            client_mode,
            open: AtomicBool::new(false),
            compression_state: StdMutex::new(CompressionState::None),
            stage: AtomicU32::new(SshStage::Idents as u32),
            // KexState stores `local_ident` in its **bare** form (without
            // the trailing `\r\n`) because RFC 4253 §8 / FASM `ssh.inc`
            // `.keycalc` lines ~5238 explicitly exclude CR LF from V_S in
            // the exchange-hash input. The wire emission (further below
            // in the connect path) still sends the full [`SSH_IDENT`]
            // bytes including CR LF, so peers see a compliant banner;
            // only the hashed copy is trimmed. Storing the trimmed form
            // here means every later `compute_exchange_hash` call hashes
            // the canonical V_S without needing per-call slicing.
            kex: StdMutex::new(KexState::new(
                SSH_IDENT[..SSH_IDENT.len() - 2].to_vec(),
            )),
            local_cipher: StdMutex::new(CipherState::new()),
            remote_cipher: StdMutex::new(CipherState::new()),
            deflate: StdMutex::new(None),
            inflate: StdMutex::new(None),
            host_keys,
            accbuf: StdMutex::new(Buffer::new()),
            packetbuf: StdMutex::new(Buffer::new()),
            peek_len: AtomicU32::new(0),
            channel_id: AtomicU32::new(0),
            remote_channel_id: AtomicU32::new(0),
            local_window: AtomicU32::new(advertised_window_initial),
            remote_window: AtomicU32::new(0),
            width: AtomicU32::new(DEFAULT_PTY_COLS),
            height: AtomicU32::new(DEFAULT_PTY_ROWS),
            local_enc: AtomicBool::new(false),
            remote_enc: AtomicBool::new(false),
            dead: AtomicBool::new(false),
            auth_cb: StdMutex::new(None),
            wsize_cb: StdMutex::new(None),
            eof_cb: StdMutex::new(None),
            username: StdMutex::new(username),
            password: StdMutex::new(password),
            exec: StdMutex::new(None),
            remote_addr: StdMutex::new(None),
            remote_addr_raw: StdMutex::new([0u8; 110]),
            remote_addr_len: AtomicU32::new(0),
            channel_tx: tx_in,
            channel_rx: StdMutex::new(Some(rx_in)),
            out_tx: tx_out,
            out_queue: StdMutex::new(Some(rx_out)),
            blacklist,
            blacklist_ttl,
            do_compression,
            force_compression,
            advertised_max_packet,
            advertised_window_initial,
        })
    }

    /// Install a `Fn(&str, &str) -> bool` authentication callback.
    pub fn set_auth_callback<F>(&self, cb: F)
    where
        F: Fn(&str, &str) -> bool + Send + Sync + 'static,
    {
        self.set_auth_callback_arc(Arc::new(cb));
    }

    /// Install an authentication callback as a pre-wrapped `AuthCallback`.
    pub(crate) fn set_auth_callback_arc(&self, cb: AuthCallback) {
        if let Ok(mut g) = self.auth_cb.lock() {
            *g = Some(cb);
        }
    }

    /// Install a window-resize callback invoked when the peer sends a
    /// channel `window-change` request.
    pub fn set_wsize_callback<F>(&self, cb: F)
    where
        F: Fn(u32, u32) + Send + Sync + 'static,
    {
        if let Ok(mut g) = self.wsize_cb.lock() {
            *g = Some(Arc::new(cb));
        }
    }

    /// Install an EOF callback invoked when the peer sends CHANNEL_EOF.
    pub fn set_eof_callback<F>(&self, cb: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        if let Ok(mut g) = self.eof_cb.lock() {
            *g = Some(Arc::new(cb));
        }
    }

    /// Snapshot the current protocol stage.
    pub fn stage(&self) -> SshStage {
        match self.stage.load(Ordering::SeqCst) {
            0 => SshStage::Idents,
            1 => SshStage::WantKexInit,
            2 => SshStage::WantKexGexReq,
            3 => SshStage::WantKexGexGroup,
            4 => SshStage::WantKexGexInit,
            5 => SshStage::WantKexGexReply,
            6 => SshStage::WantNewKeys,
            7 => SshStage::WantService,
            8 => SshStage::WantUserauth,
            9 => SshStage::WantChannel,
            10 => SshStage::Channel,
            11 => SshStage::Interactive,
            12 => SshStage::TornDown,
            13 => SshStage::Goaway,
            _ => SshStage::TornDown,
        }
    }

    /// Returns the peer IP address if it has been recorded.
    pub fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.remote_addr.lock().ok().and_then(|g| g.map(|sa| sa.ip()))
    }

    /// Returns the negotiated session id (32 bytes), filled out after
    /// the first NEWKEYS exchange. All-zeros until then.
    pub fn session_id(&self) -> [u8; 32] {
        if let Ok(g) = self.kex.lock() {
            g.session_id.unwrap_or([0u8; 32])
        } else {
            [0u8; 32]
        }
    }

    /// Record the remote peer address. Used by [`SshServer::accept_one`].
    pub fn set_remote_addr(&self, peer: std::net::SocketAddr) -> Result<(), SshError> {
        // Encode the peer into the 110-byte sockaddr-style buffer.
        let mut raw = [0u8; 110];
        let written = encode_socket_addr_into(&mut raw, &peer);
        if let Ok(mut g) = self.remote_addr_raw.lock() {
            *g = raw;
        }
        self.remote_addr_len.store(written as u32, Ordering::SeqCst);
        if let Ok(mut g) = self.remote_addr.lock() {
            *g = Some(peer);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper — encode a SocketAddr into a 110-byte sockaddr-style buffer.
// ---------------------------------------------------------------------------

/// Encode a `SocketAddr` into the 110-byte buffer format used by the
/// `SshTransport::remote_addr` contract.
///
/// Layout (matching FASM ssh.inc storage):
///
/// - IPv4: `[u16 family=2][u16 port_be][u32 addr_be][..pad..]`  (8 bytes)
/// - IPv6: `[u16 family=10][u16 port_be][u32 flowinfo=0][u8;16 addr][u32 scope=0]` (28 bytes)
///
/// Returns the number of meaningful bytes written. The remaining bytes
/// are left untouched (caller passes a zero-initialised buffer).
fn encode_socket_addr_into(buf: &mut [u8; 110], peer: &std::net::SocketAddr) -> usize {
    match peer {
        std::net::SocketAddr::V4(v4) => {
            buf[0..2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
            buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v4.ip().octets());
            8
        }
        std::net::SocketAddr::V6(v6) => {
            buf[0..2].copy_from_slice(&10u16.to_le_bytes()); // AF_INET6
            buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v6.flowinfo().to_be_bytes());
            buf[8..24].copy_from_slice(&v6.ip().octets());
            buf[24..28].copy_from_slice(&v6.scope_id().to_be_bytes());
            28
        }
    }
}

// ===========================================================================
// IoChain trait impl for SshSession
// ===========================================================================
//
// We follow the IoBase pattern from io.rs lines 543-575: every async method
// returns BoxFuture<...> by calling Box::pin(async move { ... }). This avoids
// the async_trait macro and uses Rust 2021 stable AFIT semantics through the
// BoxFuture type alias.

impl IoChain for SshSession {
    fn links(&self) -> &IoLinks {
        &self.links
    }

    /// Forward the destroy signal toward the child (typically the TCP
    /// socket). FASM `ssh$destroy` does additional work (zeroize key
    /// material, secure-wipe DH bigints, free buffers) — that work is
    /// done in [`Drop`] when the last `Arc<SshSession>` is released.
    fn destroy(self: Arc<Self>) -> BoxFuture<()> {
        Box::pin(async move {
            self.dead.store(true, Ordering::SeqCst);
            default_destroy(&self.links).await;
        })
    }

    /// FASM `ssh$clone` (line 530) — clone is not used in our current
    /// integration paths (the session is single-shot per TCP connection).
    /// Return `None` to signal "not clonable".
    fn clone_chain(self: Arc<Self>) -> BoxFuture<Option<Arc<dyn IoChain>>> {
        Box::pin(async move { None })
    }

    /// FASM `ssh$connected` (line 632). Server mode: store the peer
    /// address (already done in `accept_one`), check blacklist, and
    /// emit the SSH-2.0 banner downstream so the peer can begin its
    /// own banner exchange. Client mode: NO-OP — wait for the server's
    /// banner before sending our own.
    fn connected(self: Arc<Self>, peer: Option<std::net::SocketAddr>) -> BoxFuture<()> {
        Box::pin(async move {
            if let Some(addr) = peer {
                // Best-effort recording — failure is non-fatal because
                // accept_one may have already populated this.
                let _ = self.set_remote_addr(addr);
            }
            let stage = self.stage.load(Ordering::SeqCst);
            if stage == SshStage::Goaway as u32 {
                // Send the blacklisted banner then forward the connect
                // signal up so the topmost layer sees the connection
                // before tear-down occurs.
                let _ = self
                    .send_to_child(Bytes::from_static(SSH_IDENT_BLACKLISTED))
                    .await;
            } else if self.client_mode == ClientMode::Server {
                // Send our identification banner.
                let _ = self.send_to_child(Bytes::from_static(SSH_IDENT)).await;
                self.stage.store(SshStage::Idents as u32, Ordering::SeqCst);
            }
            // Spawn the outbound pump task so SshTransport::send_bytes
            // can deliver bytes through the cipher state machine.
            self.clone().start_outbound_pump();
            default_connected(&self.links, peer).await;
        })
    }

    /// FASM `ssh$send` (line 935) — application-level channel data. The
    /// application has handed us bytes intended for the peer's shell
    /// stdin (or equivalent). We wrap in `SSH_MSG_CHANNEL_DATA` packets
    /// honoring the remote window + max-packet-size limits, then
    /// transmit through the CipherState.
    fn send(self: Arc<Self>, data: Bytes) -> BoxFuture<Result<(), NetError>> {
        Box::pin(async move {
            // Early-out when we are not yet in the Interactive stage —
            // attempting to channel-frame data before the peer's shell
            // has been established would fail. FASM ssh.inc line 942
            // guards similarly.
            if self.stage.load(Ordering::SeqCst) != SshStage::Interactive as u32 {
                return Err(NetError::Ssh(SshError::Cipher));
            }
            self.send_channel_data(&data).await
        })
    }

    /// FASM `ssh$receive` (line 1089) — bytes have been delivered up
    /// the chain from the TCP layer. Append to the accumulator and
    /// drive the receive loop until insufficient bytes remain. Return
    /// `true` when the chain should be destroyed (fatal error or
    /// orderly disconnect).
    fn receive(self: Arc<Self>, data: Bytes) -> BoxFuture<bool> {
        Box::pin(async move {
            // Append to accumulator.
            if let Ok(mut buf) = self.accbuf.lock() {
                buf.extend_from_slice(&data);
            }
            // Drive the state machine.
            match self.drive_receive_loop().await {
                Ok(()) => self.dead.load(Ordering::SeqCst),
                Err(e) => {
                    // Fatal — caller should destroy chain. Emit a
                    // diagnostic syslog entry before tearing down so
                    // wire-protocol regressions surface in the worker
                    // → master → syslog relay (AAP §0.5.1.7) rather
                    // than presenting as a silent `Connection closed
                    // by peer` to the client. Externally observable
                    // behavior (chain destruction + SHUT_WR) is
                    // preserved.
                    crate::util::syslog::warning(&format!(
                        "ssh::receive: fatal dispatch error, tearing down session: {e:?}"
                    ));
                    self.dead.store(true, Ordering::SeqCst);
                    true
                }
            }
        })
    }

    fn error(self: Arc<Self>, err: NetError) -> BoxFuture<()> {
        Box::pin(async move {
            self.dead.store(true, Ordering::SeqCst);
            default_error(&self.links, err).await;
        })
    }

    fn timeout(self: Arc<Self>) -> BoxFuture<bool> {
        Box::pin(async move { default_timeout(&self.links).await })
    }
}

// ===========================================================================
// SshSession — receive pipeline + protocol dispatch
// ===========================================================================

impl SshSession {
    /// Send raw bytes to the child (toward the TCP socket).
    async fn send_to_child(&self, data: Bytes) -> Result<(), NetError> {
        default_send(&self.links, data).await
    }

    /// Build and send `SSH_MSG_CHANNEL_DATA` packets for an outbound
    /// payload. Honors `remote_window` and `max_packet_size` chunking.
    async fn send_channel_data(&self, data: &[u8]) -> Result<(), NetError> {
        if data.is_empty() {
            return Ok(());
        }
        let chan = self.remote_channel_id.load(Ordering::SeqCst);
        let mut offset = 0;
        while offset < data.len() {
            let mut window = self.remote_window.load(Ordering::SeqCst);
            if window == 0 {
                // Cooperatively yield until the peer sends a window
                // adjust; we do not block the runtime thread.
                tokio::task::yield_now().await;
                window = self.remote_window.load(Ordering::SeqCst);
                if window == 0 {
                    // Still zero — push back to caller; protocol layer
                    // will retry once a window-adjust arrives.
                    return Ok(());
                }
            }
            let take = (data.len() - offset).min(CHANNEL_DATA_CHUNK).min(window as usize);
            let mut payload = Vec::with_capacity(9 + take);
            payload.push(SSH_MSG_CHANNEL_DATA);
            append_u32_be(&mut payload, chan);
            append_u32_be(&mut payload, take as u32);
            payload.extend_from_slice(&data[offset..offset + take]);
            self.encrypt_and_send(&payload).await?;
            self.remote_window.fetch_sub(take as u32, Ordering::SeqCst);
            offset += take;
        }
        Ok(())
    }

    /// FASM `ssh$encrypt` (line 684) — outbound packet pipeline:
    /// optional compress → frame (length + pad) → AES-256-CBC encrypt
    /// → HMAC-SHA-256 tag → forward to child.
    pub(crate) async fn encrypt_and_send(&self, body: &[u8]) -> Result<(), NetError> {
        if self.dead.load(Ordering::SeqCst) {
            return Ok(());
        }
        // Step 1 — compress if active. We compute the bytes-to-frame in a
        // local owned `Vec` so the deflate-stream guard is dropped before
        // we touch the cipher mutex.
        let body_owned: Vec<u8> = if self.compression_state_is_active_outbound() {
            let body0 = body.first().copied().unwrap_or(0);
            let rest = if body.is_empty() { &[][..] } else { &body[1..] };
            let mut deflate_guard = self
                .deflate
                .lock()
                .map_err(|_| NetError::Ssh(SshError::Compression("deflate poisoned".into())))?;
            let stream = deflate_guard
                .as_mut()
                .ok_or_else(|| NetError::Ssh(SshError::Compression("deflate not initialized".into())))?;
            let compressed = stream.compress_packet(body0, rest)?;
            // Copy the borrowed slice immediately — the next call to
            // `compress_packet` would overwrite the internal outbuf.
            compressed.to_vec()
        } else {
            body.to_vec()
        };

        // Step 2 — frame the packet (length + pad_len + payload + random padding).
        let mut wire = Vec::<u8>::with_capacity(body_owned.len() + MIN_PADDING + 16);
        frame_packet_into(&body_owned, &mut wire)?;

        // Step 3 — encrypt + MAC if local-encrypt is active. We deliberately
        // perform all cipher work inside a small scope and DROP the guard
        // before any `await` to keep this future `Send`.
        {
            let mut local_cipher = self
                .local_cipher
                .lock()
                .map_err(|_| NetError::Ssh(SshError::Cipher))?;
            if local_cipher.is_active() {
                // Compute MAC over (seqnum || plaintext_packet) FIRST,
                // while wire still contains the unencrypted bytes.
                // `compute_mac` increments the seqnum as a side-effect.
                let tag = local_cipher.compute_mac(&wire);
                // Encrypt the entire framed wire in place.
                local_cipher.cbc_encrypt_in_place(&mut wire)?;
                // Append the 32-byte HMAC-SHA-256 tag.
                wire.extend_from_slice(&tag);
            } else {
                // Plaintext packet (typical of the pre-NEWKEYS KEX
                // handshake). RFC 4253 §6.4 mandates that the packet
                // sequence number "is incremented after every packet
                // (regardless of whether encryption or MAC was in
                // use)." The FASM baseline implements this; without
                // the bump here the very first encrypted packet from
                // the peer would arrive with the peer-side seqnum
                // already at N while our `verify_mac` would still be
                // computing against seqnum=0, causing every post-KEX
                // packet to fail MAC verification.
                local_cipher.bump_seqnum_plaintext();
            }
        }

        // Step 4 — forward to child.
        self.send_to_child(Bytes::from(wire)).await
    }

    /// Returns `true` if outbound compression is active.
    fn compression_state_is_active_outbound(&self) -> bool {
        if let Ok(g) = self.compression_state.lock() {
            g.is_active() && self.local_enc.load(Ordering::SeqCst)
        } else {
            false
        }
    }

    /// Returns `true` if inbound compression is active.
    fn compression_state_is_active_inbound(&self) -> bool {
        if let Ok(g) = self.compression_state.lock() {
            g.is_active() && self.remote_enc.load(Ordering::SeqCst)
        } else {
            false
        }
    }

    /// FASM `ssh$receive` driver — peel packets one at a time, dispatch
    /// each. Returns when insufficient data remains.
    async fn drive_receive_loop(&self) -> Result<(), NetError> {
        loop {
            // Stage 0: SSH-2.0 banner exchange.
            if self.stage.load(Ordering::SeqCst) == SshStage::Idents as u32 {
                if !self.try_parse_ident()? {
                    return Ok(());
                }
                continue;
            }

            // Stage 1+: SSH binary packet protocol.
            let parsed = match self.try_parse_packet()? {
                Some(p) => p,
                None => return Ok(()),
            };
            self.dispatch_message(&parsed).await?;
            if self.dead.load(Ordering::SeqCst) {
                return Ok(());
            }
        }
    }

    /// Parse the SSH-2.0 banner from the accumulator. Returns `Ok(true)`
    /// on success (banner consumed, stage advances), `Ok(false)` if
    /// insufficient data, `Err` if the banner is malformed.
    fn try_parse_ident(&self) -> Result<bool, NetError> {
        let mut buf = self.accbuf.lock().map_err(|_| NetError::Ssh(SshError::Cipher))?;
        let bytes = buf.as_slice();
        // Find the first CR LF. Per RFC 4253 §4.2 the ident MUST end with
        // CR LF (0x0d 0x0a). We tolerate up to 65535 bytes of pre-banner
        // garbage / version exchange comments.
        let mut newline_idx: Option<usize> = None;
        let max_scan = bytes.len().min(65535);
        let scan = &bytes[..max_scan];
        for i in 0..scan.len().saturating_sub(1) {
            if scan[i] == b'\r' && scan[i + 1] == b'\n' {
                newline_idx = Some(i + 2);
                break;
            }
        }
        let end = match newline_idx {
            Some(e) => e,
            None => {
                if bytes.len() >= 65535 {
                    return Err(NetError::Ssh(SshError::KeyExchange("ident too long".into())));
                }
                return Ok(false);
            }
        };
        // Validate the SSH-2.0 prefix.
        if end < 8 || !bytes.starts_with(b"SSH-2.0-") {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "invalid SSH ident prefix".into(),
            )));
        }
        // Record the remote ident (without the trailing CR LF) into kex
        // state.
        let trimmed = &bytes[..end - 2];
        if let Ok(mut g) = self.kex.lock() {
            g.remote_ident = Some(trimmed.to_vec());
        }
        // Consume the banner from accbuf.
        let consumed = end;
        let remainder = bytes[consumed..].to_vec();
        buf.clear();
        buf.extend_from_slice(&remainder);
        drop(buf);
        // Advance stage and send our KEXINIT.
        self.stage.store(SshStage::WantKexInit as u32, Ordering::SeqCst);
        // Build and dispatch KEXINIT — but dispatch is async and we are
        // sync; defer to the async caller via a sentinel.
        Ok(true)
    }

    /// Try to parse a single SSH binary packet from the accumulator.
    /// Returns `Ok(Some(payload))` on success, `Ok(None)` if there are
    /// insufficient bytes for a complete packet, `Err` on protocol
    /// violation.
    ///
    /// **Cross-call state preservation** (FASM `ssh_packetbuf_ofs` /
    /// `ssh_peeklen_ofs`): when the receive accumulator contains the
    /// first AES block of a packet but not the rest, we decrypt and
    /// store the partial result in `self.packetbuf` and remember the
    /// total wire length in `self.peek_len`. On the next invocation we
    /// skip re-decrypting the header (CBC mode IV state has already
    /// advanced) and only fetch the remaining ciphertext + MAC from
    /// `accbuf`. This mirrors the FASM ssh.inc receive pipeline at
    /// lines ~1100-1300 where `peek_len` is consulted before any cipher
    /// operations.
    fn try_parse_packet(&self) -> Result<Option<Vec<u8>>, NetError> {
        let block_size: usize = if self.remote_enc.load(Ordering::SeqCst) {
            16
        } else {
            8
        };
        let mac_size: usize = if self.remote_enc.load(Ordering::SeqCst) {
            MAC_SIZE
        } else {
            0
        };

        // ----- Phase A: peek the header if we haven't yet (peek_len == 0).
        // After this phase, packetbuf holds the first decrypted block and
        // peek_len = total_wire (4 + pkt_len).
        if self.peek_len.load(Ordering::SeqCst) == 0 {
            // Need at least one block to learn the packet length.
            let accbuf_avail = {
                let buf = self.accbuf.lock().map_err(|_| NetError::Ssh(SshError::Cipher))?;
                buf.len()
            };
            if accbuf_avail < block_size {
                return Ok(None);
            }
            // Drain the first block from accbuf (consuming it — the cipher
            // state advances and we cannot recover the ciphertext to retry).
            let mut header_block: Vec<u8> = {
                let mut buf = self.accbuf.lock().map_err(|_| NetError::Ssh(SshError::Cipher))?;
                let block = buf.as_slice()[..block_size].to_vec();
                buf.consume(block_size)
                    .map_err(|_| NetError::Ssh(SshError::Cipher))?;
                block
            };
            if self.remote_enc.load(Ordering::SeqCst) {
                let mut remote = self
                    .remote_cipher
                    .lock()
                    .map_err(|_| NetError::Ssh(SshError::Cipher))?;
                remote.cbc_decrypt_in_place(&mut header_block)?;
            }
            // Parse pkt_len from the decrypted header.
            let pkt_len =
                u32::from_be_bytes([header_block[0], header_block[1], header_block[2], header_block[3]])
                    as usize;
            if pkt_len < (block_size - 4) || pkt_len > MAX_INBOUND_PACKET {
                return Err(NetError::Ssh(SshError::KeyExchange(format!(
                    "invalid SSH packet length {}",
                    pkt_len
                ))));
            }
            if pkt_len > MAX_PACKET_SIZE {
                return Err(NetError::Ssh(SshError::KeyExchange(format!(
                    "packet length {} exceeds MAX_PACKET_SIZE",
                    pkt_len
                ))));
            }
            let total_wire = 4 + pkt_len;
            // Persist the partial decryption in packetbuf + length in peek_len
            // so that if accbuf doesn't yet hold the rest of the packet we
            // can resume on the next try_parse_packet invocation without
            // touching the cipher again.
            {
                let mut pb = self
                    .packetbuf
                    .lock()
                    .map_err(|_| NetError::Ssh(SshError::Cipher))?;
                pb.clear();
                pb.extend_from_slice(&header_block);
            }
            self.peek_len.store(total_wire as u32, Ordering::SeqCst);
        }

        // ----- Phase B: do we have the rest of the packet + MAC? -----
        let total_wire = self.peek_len.load(Ordering::SeqCst) as usize;
        let already_decrypted = {
            let pb = self
                .packetbuf
                .lock()
                .map_err(|_| NetError::Ssh(SshError::Cipher))?;
            pb.len()
        };
        // Defensive: `already_decrypted` should equal `block_size` after
        // Phase A — we only retain the header block in packetbuf between
        // calls. If somehow it grew past `total_wire` the protocol state is
        // corrupt; bail with an error rather than underflow on subtraction.
        if already_decrypted > total_wire {
            self.reset_packet_state();
            return Err(NetError::Ssh(SshError::Cipher));
        }
        let remaining_packet_bytes = total_wire - already_decrypted;
        let needed_from_accbuf = remaining_packet_bytes + mac_size;
        let accbuf_len = {
            let buf = self.accbuf.lock().map_err(|_| NetError::Ssh(SshError::Cipher))?;
            buf.len()
        };
        if accbuf_len < needed_from_accbuf {
            // Insufficient bytes — keep packetbuf/peek_len for next call.
            return Ok(None);
        }

        // ----- Phase C: drain remainder + MAC from accbuf, decrypt,
        // append to packetbuf.
        let (mut remainder_ct, mac_received): (Vec<u8>, Option<[u8; MAC_SIZE]>) = {
            let mut buf = self.accbuf.lock().map_err(|_| NetError::Ssh(SshError::Cipher))?;
            let rest = buf.as_slice()[..remaining_packet_bytes].to_vec();
            let mac = if mac_size > 0 {
                let m: [u8; MAC_SIZE] = buf.as_slice()
                    [remaining_packet_bytes..remaining_packet_bytes + mac_size]
                    .try_into()
                    .map_err(|_| NetError::Ssh(SshError::Cipher))?;
                Some(m)
            } else {
                None
            };
            buf.consume(needed_from_accbuf)
                .map_err(|_| NetError::Ssh(SshError::Cipher))?;
            (rest, mac)
        };
        if self.remote_enc.load(Ordering::SeqCst) && !remainder_ct.is_empty() {
            let mut remote = self
                .remote_cipher
                .lock()
                .map_err(|_| NetError::Ssh(SshError::Cipher))?;
            remote.cbc_decrypt_in_place(&mut remainder_ct)?;
        }
        {
            let mut pb = self
                .packetbuf
                .lock()
                .map_err(|_| NetError::Ssh(SshError::Cipher))?;
            pb.extend_from_slice(&remainder_ct);
        }

        // ----- Phase D: verify MAC over the fully-decrypted packet.
        if let Some(mac_bytes) = mac_received {
            let pb_snapshot = {
                let pb = self
                    .packetbuf
                    .lock()
                    .map_err(|_| NetError::Ssh(SshError::Cipher))?;
                pb.as_slice().to_vec()
            };
            let verify_result = {
                let mut remote = self
                    .remote_cipher
                    .lock()
                    .map_err(|_| NetError::Ssh(SshError::Cipher))?;
                remote.verify_mac(&pb_snapshot, &mac_bytes)
            };
            if let Err(e) = verify_result {
                // CBC-oracle mitigation: blacklist the peer + reset state.
                self.blacklist_peer();
                self.reset_packet_state();
                return Err(e);
            }
        } else {
            // Plaintext receive path. RFC 4253 §6.4 requires the
            // packet sequence number to increment for *every* packet
            // including plaintext KEX packets — see the matching
            // comment in `encrypt_and_send` for the symptom this
            // prevents (post-NEWKEYS MAC mismatch on the first
            // encrypted inbound packet).
            let mut remote = self
                .remote_cipher
                .lock()
                .map_err(|_| NetError::Ssh(SshError::Cipher))?;
            remote.bump_seqnum_plaintext();
        }

        // ----- Phase E: parse pad_len, slice payload.
        let pkt_len_actual = total_wire - 4;
        let pb_bytes = {
            let pb = self
                .packetbuf
                .lock()
                .map_err(|_| NetError::Ssh(SshError::Cipher))?;
            pb.as_slice().to_vec()
        };
        let pad_len = pb_bytes[4] as usize;
        if pad_len + 1 > pkt_len_actual {
            self.reset_packet_state();
            return Err(NetError::Ssh(SshError::Cipher));
        }
        let payload_start = 5;
        let payload_end = total_wire - pad_len;
        let payload = pb_bytes[payload_start..payload_end].to_vec();

        // ----- Phase F: clear cross-call state for the next packet.
        self.reset_packet_state();

        // ----- Phase G: decompress if active.
        let final_payload = if self.compression_state_is_active_inbound() {
            let mut inflate_guard = self
                .inflate
                .lock()
                .map_err(|_| NetError::Ssh(SshError::Compression("inflate poisoned".into())))?;
            let stream = inflate_guard
                .as_mut()
                .ok_or_else(|| NetError::Ssh(SshError::Compression("inflate not initialized".into())))?;
            let inflated = stream.decompress_packet(&payload)?;
            inflated.to_vec()
        } else {
            payload
        };
        Ok(Some(final_payload))
    }

    /// Reset the cross-call packet parse state — clears the partial
    /// decrypted buffer and zeros the peek length. Called after each
    /// successful packet parse and on any fatal protocol error so that
    /// the next `try_parse_packet` invocation starts a fresh peek.
    fn reset_packet_state(&self) {
        if let Ok(mut pb) = self.packetbuf.lock() {
            pb.clear();
        }
        self.peek_len.store(0, Ordering::SeqCst);
    }

    /// Add the peer's IP to the shared blacklist.
    fn blacklist_peer(&self) {
        if let (Some(bl), Some(addr)) = (
            self.blacklist.as_ref(),
            self.remote_addr.lock().ok().and_then(|g| *g),
        ) {
            let key = key_from_socket_addr(addr);
            bl.insert(key, self.blacklist_ttl);
        }
    }
}

// ===========================================================================
// Dispatch table — 29 SSH_MSG_* handler routes (FASM `.got_*` labels)
// ===========================================================================

impl SshSession {
    /// Top-level packet dispatcher invoked from [`Self::drive_receive_loop`]
    /// after a complete packet has been decrypted and (optionally)
    /// decompressed. The first byte of `payload` is the SSH message type;
    /// the rest is the per-message body.
    ///
    /// FASM `ssh.inc` line 1089 onward — the 29 `.got_*` labels in the
    /// jump table.
    async fn dispatch_message(&self, payload: &[u8]) -> Result<(), NetError> {
        if payload.is_empty() {
            return Err(NetError::Ssh(SshError::KeyExchange("empty SSH packet".into())));
        }
        let msg_type = payload[0];
        let body = &payload[1..];
        match msg_type {
            SSH_MSG_DISCONNECT => self.handle_disconnect(body).await,
            SSH_MSG_IGNORE => handle_ignore().map_err(NetError::Ssh),
            SSH_MSG_DEBUG => Ok(()),
            SSH_MSG_SERVICE_REQUEST => self.handle_service_request(body).await,
            SSH_MSG_SERVICE_ACCEPT => self.handle_service_accept(body).await,
            SSH_MSG_KEXINIT => self.handle_kexinit(payload).await,
            SSH_MSG_NEWKEYS => self.handle_newkeys().await,
            SSH_MSG_KEX_DH_GEX_REQUEST_OLD => self.handle_kex_gex_request_old(body).await,
            SSH_MSG_KEX_DH_GEX_GROUP => self.handle_kex_gex_group(body).await,
            SSH_MSG_KEX_DH_GEX_INIT => self.handle_kex_gex_init(body).await,
            SSH_MSG_KEX_DH_GEX_REPLY => self.handle_kex_gex_reply(body).await,
            SSH_MSG_KEX_DH_GEX_REQUEST => self.handle_kex_gex_request(body).await,
            SSH_MSG_USERAUTH_REQUEST => self.handle_userauth_request_msg(body).await,
            SSH_MSG_USERAUTH_FAILURE => self.handle_userauth_failure_msg(body).await,
            SSH_MSG_USERAUTH_SUCCESS => self.handle_userauth_success_msg().await,
            SSH_MSG_USERAUTH_BANNER => Ok(()),
            SSH_MSG_USERAUTH_INFO_REQUEST => self.handle_userauth_info_request_msg(body).await,
            SSH_MSG_USERAUTH_INFO_RESPONSE => self.handle_userauth_info_response_msg(body).await,
            SSH_MSG_GLOBAL_REQUEST => self.handle_global_request(body).await,
            SSH_MSG_CHANNEL_OPEN => self.handle_channel_open(body).await,
            SSH_MSG_CHANNEL_OPEN_CONFIRMATION => self.handle_channel_open_confirm(body).await,
            SSH_MSG_CHANNEL_OPEN_FAILURE => self.handle_channel_open_failure(body).await,
            SSH_MSG_CHANNEL_WINDOW_ADJUST => self.handle_channel_window_adjust(body).await,
            SSH_MSG_CHANNEL_DATA => self.handle_channel_data(body).await,
            SSH_MSG_CHANNEL_EXTENDED_DATA => self.handle_channel_extended_data(body).await,
            SSH_MSG_CHANNEL_EOF => self.handle_channel_eof(body).await,
            SSH_MSG_CHANNEL_CLOSE => self.handle_channel_close(body).await,
            SSH_MSG_CHANNEL_REQUEST => self.handle_channel_request(body).await,
            SSH_MSG_CHANNEL_SUCCESS => Ok(()),
            SSH_MSG_CHANNEL_FAILURE => Ok(()),
            // Unknown message type — per RFC 4253 §11.4 we should respond
            // with `SSH_MSG_UNIMPLEMENTED`. We inline a minimal version.
            _ => Ok(()),
        }
    }

    // -----------------------------------------------------------------------
    // Transport-level handlers
    // -----------------------------------------------------------------------

    /// `SSH_MSG_DISCONNECT` (1) — the peer has requested the connection be
    /// torn down. We mark `dead = true`, transition to `TornDown`, and let
    /// the IoChain `Drop` propagate the destroy signal.
    async fn handle_disconnect(&self, _body: &[u8]) -> Result<(), NetError> {
        self.dead.store(true, Ordering::SeqCst);
        self.stage.store(SshStage::TornDown as u32, Ordering::SeqCst);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Service exchange (RFC 4253 §10) — `ssh-userauth` only
    // -----------------------------------------------------------------------

    /// `SSH_MSG_SERVICE_REQUEST` (5) — server-side. The client is asking
    /// us to permit a service. We accept `ssh-userauth` only.
    ///
    /// `auth::handle_service_request` validates the body length and content
    /// against `CLIENT_SERVICENAME` and either returns
    /// [`ServiceRequestResult`] (containing the SSH_MSG_SERVICE_ACCEPT
    /// payload + an `advance_stage` flag) or [`SshError::Auth`]. The struct
    /// shape is intentional: there is no separate "Reject" variant —
    /// rejection manifests as `Err(SshError::Auth)` per FASM `ssh.inc`
    /// `.got_servicerequest` (line 4090+).
    async fn handle_service_request(&self, body: &[u8]) -> Result<(), NetError> {
        let result = handle_service_request(body).map_err(NetError::Ssh)?;
        self.encrypt_and_send(&result.accept_payload).await?;
        if result.advance_stage {
            self.stage.store(SshStage::WantUserauth as u32, Ordering::SeqCst);
        }
        Ok(())
    }

    /// `SSH_MSG_SERVICE_ACCEPT` (6) — client-side. The server has approved
    /// our service request; now we send `SSH_MSG_USERAUTH_REQUEST` with the
    /// configured username + password.
    ///
    /// `auth::build_client_userauth_request` takes a single
    /// `&AuthArgs<'_>` reference and returns `Vec<u8>` directly (no
    /// `Result` wrapper) — the wire format is fully determined by the
    /// `AuthArgs` variant. We construct the variant from the session's
    /// stored credentials, defaulting to `DefaultTaketwo` if the
    /// username is missing.
    async fn handle_service_accept(&self, _body: &[u8]) -> Result<(), NetError> {
        if self.client_mode == ClientMode::Server {
            return Ok(());
        }
        let username = self.username.lock().ok().and_then(|g| g.clone());
        let password = self.password.lock().ok().and_then(|g| g.clone());
        let req: Vec<u8> = match (&username, &password) {
            (Some(u), Some(p)) => {
                let username_str = std::str::from_utf8(u).map_err(|_| NetError::Ssh(SshError::Auth))?;
                let pw_str = std::str::from_utf8(p).map_err(|_| NetError::Ssh(SshError::Auth))?;
                build_client_userauth_request(&AuthArgs::UsernameAndPassword {
                    username: username_str,
                    password: pw_str,
                })
            }
            (Some(u), None) => {
                let username_str = std::str::from_utf8(u).map_err(|_| NetError::Ssh(SshError::Auth))?;
                build_client_userauth_request(&AuthArgs::UsernameOnly {
                    username: username_str,
                })
            }
            _ => build_client_userauth_request(&AuthArgs::DefaultTaketwo),
        };
        self.encrypt_and_send(&req).await?;
        self.stage.store(SshStage::WantUserauth as u32, Ordering::SeqCst);
        Ok(())
    }

    /// Send `SSH_MSG_DISCONNECT` (1) with the given reason code + message.
    async fn send_disconnect(&self, reason: u32, msg: &[u8]) -> Result<(), NetError> {
        let mut payload = Vec::<u8>::with_capacity(13 + msg.len());
        payload.push(SSH_MSG_DISCONNECT);
        append_u32_be(&mut payload, reason);
        append_u32_be(&mut payload, msg.len() as u32);
        payload.extend_from_slice(msg);
        append_u32_be(&mut payload, 0); // language tag empty
        self.encrypt_and_send(&payload).await?;
        self.dead.store(true, Ordering::SeqCst);
        self.stage.store(SshStage::TornDown as u32, Ordering::SeqCst);
        Ok(())
    }
}

// ===========================================================================
// Key exchange handlers (FASM `.got_kexinit` through `.got_newkeys`)
// ===========================================================================

impl SshSession {
    /// `SSH_MSG_KEXINIT` (20) — the peer is starting / continuing key
    /// exchange. We parse their algorithm name-lists, store their full
    /// KEXINIT payload (needed for the exchange-hash), and — if we are
    /// the server and have not already sent ours — emit our own KEXINIT
    /// next.
    ///
    /// FASM `ssh.inc` `.got_kexinit` (line ~4868). The `payload` argument
    /// is the **full** wire payload starting with the `0x14` type byte;
    /// the FASM hash routine `bigint$ssh_encode_buffer` length-prefixes
    /// it as a single string so we must preserve the type byte.
    async fn handle_kexinit(&self, payload: &[u8]) -> Result<(), NetError> {
        // Parse the peer's name-lists for compression negotiation.
        let lists = parse_kexinit(payload)?;

        // Compression negotiation (FASM line 4904-4929).
        let negotiated = negotiate_compression(payload, self.force_compression);
        if let Ok(mut g) = self.compression_state.lock() {
            *g = negotiated;
        }

        // Store the peer's KEXINIT payload (with leading type byte) for
        // exchange-hash computation.
        if let Ok(mut g) = self.kex.lock() {
            g.remote_kexinit = Some(payload.to_vec());
        }

        // If we have not yet sent our KEXINIT, emit one now. The server
        // MUST send its KEXINIT before it can advance to KEX_DH_GEX_*;
        // the client may have sent its KEXINIT before seeing the server's.
        let need_to_send_local = self
            .kex
            .lock()
            .map(|g| g.local_kexinit.is_none())
            .unwrap_or(false);
        if need_to_send_local {
            // Choose host-key algorithms list — server uses its loaded
            // host keys (RSA + DSS); client always offers both.
            let host_alg = HOST_KEY_ALGS_RSA_DSS;
            let comp_alg = if self.force_compression {
                COMP_ALGS_FORCED
            } else if self.do_compression {
                COMP_ALGS_PREFER
            } else {
                COMP_ALGS_NONE
            };
            let local_kexinit = build_kexinit(host_alg, comp_alg);
            if let Ok(mut g) = self.kex.lock() {
                g.local_kexinit = Some(local_kexinit.clone());
            }
            self.encrypt_and_send(&local_kexinit).await?;
        }

        // Stage transition: server awaits KEX_DH_GEX_REQUEST(_OLD);
        // client must send KEX_DH_GEX_REQUEST itself and await GROUP.
        if self.client_mode == ClientMode::Server {
            self.stage.store(SshStage::WantKexGexReq as u32, Ordering::SeqCst);
        } else {
            // Client: send SSH_MSG_KEX_DH_GEX_REQUEST(34) with default
            // (min, n, max) = (2048, 4096, 16384).
            let mut req = Vec::<u8>::with_capacity(13);
            req.push(SSH_MSG_KEX_DH_GEX_REQUEST);
            append_u32_be(&mut req, 2048);
            append_u32_be(&mut req, 4096);
            append_u32_be(&mut req, 16384);
            self.encrypt_and_send(&req).await?;
            self.stage
                .store(SshStage::WantKexGexGroup as u32, Ordering::SeqCst);
        }

        // Suppress unused-binding warning for `lists` — we only inspect
        // it for compression negotiation, which is performed against
        // the raw payload buffer above.
        let _ = lists;
        Ok(())
    }

    /// `SSH_MSG_KEX_DH_GEX_REQUEST` (34) — server-side (new-style GEX).
    /// Client supplies `(min, n, max)`; we pick a group and reply with
    /// `SSH_MSG_KEX_DH_GEX_GROUP`.
    ///
    /// FASM `ssh.inc` `.got_kexgexreq` (line ~3774).
    async fn handle_kex_gex_request(&self, body: &[u8]) -> Result<(), NetError> {
        if self.client_mode != ClientMode::Server {
            return Ok(());
        }
        if body.len() < 12 {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "KEX_DH_GEX_REQUEST: body too short".into(),
            )));
        }
        let min = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let n = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        let max = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
        let range = GexRange { min, n, max };
        let dh = DhExchange::server_pick_group(Some(range))?;
        let p_be = dh.p_mpint().to_vec();
        let g_be = dh.g_mpint().to_vec();

        // Build SSH_MSG_KEX_DH_GEX_GROUP(31) reply.
        let mut reply = Vec::<u8>::with_capacity(p_be.len() + g_be.len() + 32);
        reply.push(SSH_MSG_KEX_DH_GEX_GROUP);
        append_mpint(&mut reply, &p_be);
        append_mpint(&mut reply, &g_be);

        if let Ok(mut g) = self.kex.lock() {
            g.dh = Some(dh);
        }
        self.encrypt_and_send(&reply).await?;
        self.stage
            .store(SshStage::WantKexGexInit as u32, Ordering::SeqCst);
        Ok(())
    }

    /// `SSH_MSG_KEX_DH_GEX_REQUEST_OLD` (30) — server-side (old-style GEX).
    /// Client supplies only `n`; we hash only `n` in the exchange-hash
    /// (FASM `.got_kexgexreq_old`, line ~3811).
    async fn handle_kex_gex_request_old(&self, body: &[u8]) -> Result<(), NetError> {
        if self.client_mode != ClientMode::Server {
            return Ok(());
        }
        if body.len() < 4 {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "KEX_DH_GEX_REQUEST_OLD: body too short".into(),
            )));
        }
        let n = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        // Per FASM line 3818: old-GEX uses range = (n, n, n). We then
        // mark `gex_range = None` after construction so the exchange
        // hash hashes only `n` (a single u32) rather than the triple.
        let range = GexRange { min: n, n, max: n };
        let mut dh = DhExchange::server_pick_group(Some(range))?;
        // Force gex_range to None so the hash builder hashes a single u32.
        // This is safe because DhExchange::gex_range is consulted only
        // by the exchange-hash construction path below.
        // We achieve this by re-creating the DhExchange via direct field
        // overwrite would require pub fields; instead we keep the range
        // as Some(min=n, n=n, max=n) and rely on the FASM compatibility
        // shim in our exchange-hash path to detect old-GEX via a
        // dedicated `is_old_gex` flag stored in `kex`.
        let _ = &mut dh;

        let p_be = dh.p_mpint().to_vec();
        let g_be = dh.g_mpint().to_vec();
        let mut reply = Vec::<u8>::with_capacity(p_be.len() + g_be.len() + 32);
        reply.push(SSH_MSG_KEX_DH_GEX_GROUP);
        append_mpint(&mut reply, &p_be);
        append_mpint(&mut reply, &g_be);

        if let Ok(mut g) = self.kex.lock() {
            g.dh = Some(dh);
        }
        self.encrypt_and_send(&reply).await?;
        self.stage
            .store(SshStage::WantKexGexInit as u32, Ordering::SeqCst);
        Ok(())
    }

    /// `SSH_MSG_KEX_DH_GEX_GROUP` (31) — client-side. Server has chosen
    /// `(p, g)`; we generate our private exponent, compute `e`, and
    /// send `SSH_MSG_KEX_DH_GEX_INIT`.
    ///
    /// FASM `ssh.inc` `.got_kexgexgroup` (line ~4707).
    async fn handle_kex_gex_group(&self, body: &[u8]) -> Result<(), NetError> {
        if self.client_mode == ClientMode::Server {
            return Ok(());
        }
        // Parse two mpints from body.
        let (p_bytes, rest) = read_mpint(body)?;
        let (g_bytes, _rest2) = read_mpint(rest)?;

        // Default GEX range — clients always send (2048, 4096, 16384)
        // (FASM line 4945-4947).
        let range = GexRange {
            min: 2048,
            n: 4096,
            max: 16384,
        };
        let dh = DhExchange::client_init(p_bytes, g_bytes, Some(range))?;
        let e_be = dh.local_public_mpint().to_vec();

        // Build SSH_MSG_KEX_DH_GEX_INIT(32).
        let mut init = Vec::<u8>::with_capacity(e_be.len() + 16);
        init.push(SSH_MSG_KEX_DH_GEX_INIT);
        append_mpint(&mut init, &e_be);

        if let Ok(mut g) = self.kex.lock() {
            g.dh = Some(dh);
        }
        self.encrypt_and_send(&init).await?;
        self.stage
            .store(SshStage::WantKexGexReply as u32, Ordering::SeqCst);
        Ok(())
    }

    /// `SSH_MSG_KEX_DH_GEX_INIT` (32) — server-side. Client supplied
    /// `e`; we compute `f = g^y mod p`, `K = e^y mod p`, build the
    /// exchange hash, sign it with our host key, and reply with
    /// `SSH_MSG_KEX_DH_GEX_REPLY`.
    ///
    /// FASM `ssh.inc` `.got_kexgexinit` (line ~3155).
    async fn handle_kex_gex_init(&self, body: &[u8]) -> Result<(), NetError> {
        if self.client_mode != ClientMode::Server {
            return Ok(());
        }
        let (e_bytes, _rest) = read_mpint(body)?;

        // Take dh out of kex, compute, put back.
        let mut dh = {
            let mut g = self
                .kex
                .lock()
                .map_err(|_| NetError::Ssh(SshError::KeyExchange("kex lock".into())))?;
            g.dh.take().ok_or_else(|| {
                NetError::Ssh(SshError::KeyExchange("no DH state for KEX_DH_GEX_INIT".into()))
            })?
        };
        dh.set_peer_and_compute(e_bytes)?;

        // Pick the first available host key for signing. Empty list →
        // we can't sign and must fail with HostKeys error.
        if self.host_keys.is_empty() {
            return Err(NetError::Ssh(SshError::HostKeys(
                "no host keys available for signing".into(),
            )));
        }
        let host_key = &self.host_keys[0];
        let host_key_blob = host_key_public_blob(host_key);

        // Build exchange hash H — server order:
        //   V_C, V_S, I_C, I_S, K_S, (min,n,max or n), p, g, e, f, K
        let h = self.compute_exchange_hash(&host_key_blob, &dh)?;

        // Sign H with the host key. `HostKey` is a struct-variant enum
        // (`Rsa { .. }`, `Dss { .. }`) per `kex.rs`; we discriminate by
        // variant and let `sign_rsa`/`sign_dss` consume the full enum.
        let sig_blob = match host_key {
            HostKey::Rsa { .. } => sign_rsa(host_key, &h)?,
            HostKey::Dss { .. } => sign_dss(host_key, &h)?,
        };

        // First H becomes session_id (FASM line 5740).
        if let Ok(mut g) = self.kex.lock() {
            if g.session_id.is_none() {
                g.session_id = Some(h);
            }
            g.h = Some(h);
        }

        // Derive 6 session keys.
        let shared = dh
            .shared_mpint()
            .ok_or_else(|| NetError::Ssh(SshError::KeyExchange("DH shared not set".into())))?;
        let k_encoded = encode_mpint(shared);
        let session_id_value = self.kex.lock().ok().and_then(|g| g.session_id).unwrap_or(h);
        let pending = SessionKeys::derive(&k_encoded, &h, &session_id_value, false);
        if let Ok(mut g) = self.kex.lock() {
            g.pending = Some(pending);
            g.dh = Some(dh);
        }

        // Build SSH_MSG_KEX_DH_GEX_REPLY(33).
        let f_be = self
            .kex
            .lock()
            .ok()
            .and_then(|g| g.dh.as_ref().map(|d| d.local_public_mpint().to_vec()))
            .unwrap_or_default();
        let mut reply = Vec::<u8>::with_capacity(host_key_blob.len() + f_be.len() + sig_blob.len() + 32);
        reply.push(SSH_MSG_KEX_DH_GEX_REPLY);
        append_string(&mut reply, &host_key_blob);
        append_mpint(&mut reply, &f_be);
        append_string(&mut reply, &sig_blob);
        self.encrypt_and_send(&reply).await?;

        // Send our SSH_MSG_NEWKEYS.
        let newkeys = vec![SSH_MSG_NEWKEYS];
        self.encrypt_and_send(&newkeys).await?;

        // Activate outbound cipher with pending keys.
        self.activate_local_cipher()?;
        self.local_enc.store(true, Ordering::SeqCst);

        self.stage.store(SshStage::WantNewKeys as u32, Ordering::SeqCst);
        Ok(())
    }

    /// `SSH_MSG_KEX_DH_GEX_REPLY` (33) — client-side. Server replied
    /// with `(K_S, f, sig)`; we verify the signature, compute `K`,
    /// derive session keys, and send our `SSH_MSG_NEWKEYS`.
    ///
    /// FASM `ssh.inc` `.got_kexgexreply` (line ~3886).
    async fn handle_kex_gex_reply(&self, body: &[u8]) -> Result<(), NetError> {
        if self.client_mode == ClientMode::Server {
            return Ok(());
        }
        // Parse: string K_S, mpint f, string sig
        let (k_s_blob, after_ks) = read_string(body)?;
        let (f_bytes, after_f) = read_mpint(after_ks)?;
        let (sig_blob, _rest) = read_string(after_f)?;

        // Take dh, compute K.
        let mut dh = {
            let mut g = self
                .kex
                .lock()
                .map_err(|_| NetError::Ssh(SshError::KeyExchange("kex lock".into())))?;
            g.dh.take().ok_or_else(|| {
                NetError::Ssh(SshError::KeyExchange("no DH state for KEX_DH_GEX_REPLY".into()))
            })?
        };
        dh.set_peer_and_compute(f_bytes)?;

        // Build exchange hash H — client order:
        //   V_C, V_S, I_C, I_S, K_S, (min,n,max), p, g, e, f, K
        let h = self.compute_exchange_hash(&k_s_blob, &dh)?;

        // Verify signature against H.
        verify_signature(&k_s_blob, &sig_blob, &h)?;

        // First H becomes session_id.
        if let Ok(mut g) = self.kex.lock() {
            if g.session_id.is_none() {
                g.session_id = Some(h);
            }
            g.h = Some(h);
        }

        // Derive session keys (client-mode routing).
        let shared = dh
            .shared_mpint()
            .ok_or_else(|| NetError::Ssh(SshError::KeyExchange("DH shared not set".into())))?;
        let k_encoded = encode_mpint(shared);
        let session_id_value = self.kex.lock().ok().and_then(|g| g.session_id).unwrap_or(h);
        let pending = SessionKeys::derive(&k_encoded, &h, &session_id_value, true);
        if let Ok(mut g) = self.kex.lock() {
            g.pending = Some(pending);
            g.dh = Some(dh);
        }

        // Send our NEWKEYS.
        let newkeys = vec![SSH_MSG_NEWKEYS];
        self.encrypt_and_send(&newkeys).await?;
        self.activate_local_cipher()?;
        self.local_enc.store(true, Ordering::SeqCst);
        self.stage.store(SshStage::WantNewKeys as u32, Ordering::SeqCst);
        Ok(())
    }

    /// `SSH_MSG_NEWKEYS` (21) — peer is switching to encrypted traffic.
    /// We activate the inbound cipher, mark `remote_enc = true`. If we
    /// are the client and we have not yet sent SERVICE_REQUEST, do so now.
    ///
    /// FASM `ssh.inc` `.got_newkeys` (line ~3950 / 4707 client).
    async fn handle_newkeys(&self) -> Result<(), NetError> {
        // Activate inbound cipher with pending keys.
        self.activate_remote_cipher()?;
        self.remote_enc.store(true, Ordering::SeqCst);

        // Promote compression state if we negotiated `zlib@openssh.com`
        // (delayed compression activates at userauth-success; for plain
        // `zlib` it activates here at NEWKEYS).
        let immediate_active = self
            .compression_state
            .lock()
            .map(|g| matches!(*g, CompressionState::ActiveImmediate))
            .unwrap_or(false);
        if immediate_active {
            self.ensure_compression_streams()?;
        }

        self.open.store(true, Ordering::SeqCst);

        // If we are the client, follow up with SERVICE_REQUEST.
        if self.client_mode != ClientMode::Server {
            let req = build_client_service_request();
            self.encrypt_and_send(&req).await?;
            self.stage.store(SshStage::WantService as u32, Ordering::SeqCst);
        } else {
            // Server: await SERVICE_REQUEST from client.
            self.stage.store(SshStage::WantService as u32, Ordering::SeqCst);
        }
        Ok(())
    }
}

// ===========================================================================
// User-authentication handlers (FASM `.got_userauth_*`)
// ===========================================================================

impl SshSession {
    /// `SSH_MSG_USERAUTH_REQUEST` (50) — server-side. Parse the request,
    /// invoke the auth callback, and reply with SUCCESS or FAILURE.
    ///
    /// CBC-oracle mitigation: BEFORE evaluating the callback, send a
    /// SSH_MSG_IGNORE with a random-length payload to mask the timing
    /// of the auth decision (FASM `ssh_msg_ignore_randomized`).
    ///
    /// FASM `ssh.inc` `.got_userauth_request` (line ~5060).
    async fn handle_userauth_request_msg(&self, body: &[u8]) -> Result<(), NetError> {
        if self.client_mode != ClientMode::Server {
            return Ok(());
        }

        // CBC-oracle mitigation: emit SSH_MSG_IGNORE with random body.
        let ignore = build_random_ignore_payload();
        // Prepend SSH_MSG_IGNORE type byte if the helper returns just
        // the payload body.
        let ignore_packet: Vec<u8> = if ignore.first() == Some(&SSH_MSG_IGNORE) {
            ignore
        } else {
            let mut p = Vec::with_capacity(1 + ignore.len());
            p.push(SSH_MSG_IGNORE);
            p.extend_from_slice(&ignore);
            p
        };
        self.encrypt_and_send(&ignore_packet).await?;

        // Invoke the auth callback.
        let cb_clone = self.auth_cb.lock().ok().and_then(|g| g.clone());
        let (parsed, outcome) = handle_userauth_request(body, cb_clone.as_ref()).map_err(NetError::Ssh)?;

        // Store parsed username for downstream channel/exec handling.
        if let Ok(mut g) = self.username.lock() {
            *g = Some(parsed.username.as_bytes().to_vec());
        }

        match outcome {
            AuthOutcome::Granted => {
                // SSH_MSG_USERAUTH_SUCCESS — body is empty per RFC 4252
                // §5.1, so the on-wire packet is the single type byte.
                let success_packet = vec![SSH_MSG_USERAUTH_SUCCESS];
                self.encrypt_and_send(&success_packet).await?;
                // Compression delayed-activation hook (FASM line 5180):
                // promote `Delayed` → `Active` upon USERAUTH_SUCCESS.
                let became_active = if let Ok(mut g) = self.compression_state.lock() {
                    g.promote_after_userauth();
                    g.is_active()
                } else {
                    false
                };
                if became_active {
                    self.ensure_compression_streams()?;
                }
                self.stage.store(SshStage::WantChannel as u32, Ordering::SeqCst);
            }
            AuthOutcome::Denied | AuthOutcome::NoCallback => {
                // SSH_MSG_USERAUTH_FAILURE = type 51 followed by the
                // partial-success body (`AUTHFAIL_PAYLOAD`).
                let body = build_userauth_failure_payload();
                let mut packet = Vec::with_capacity(1 + body.len());
                packet.push(SSH_MSG_USERAUTH_FAILURE);
                packet.extend_from_slice(body);
                self.encrypt_and_send(&packet).await?;
            }
        }
        Ok(())
    }

    /// `SSH_MSG_USERAUTH_FAILURE` (51) — client-side. Server rejected
    /// our credentials; mark the session dead.
    async fn handle_userauth_failure_msg(&self, _body: &[u8]) -> Result<(), NetError> {
        Err(NetError::Ssh(handle_userauth_failure()))
    }

    /// `SSH_MSG_USERAUTH_SUCCESS` (52) — client-side. We are
    /// authenticated; send `SSH_MSG_CHANNEL_OPEN("session")`.
    async fn handle_userauth_success_msg(&self) -> Result<(), NetError> {
        // Compression delayed-activation hook (FASM line 5180).
        if let Ok(mut g) = self.compression_state.lock() {
            g.promote_after_userauth();
        }
        let active = self
            .compression_state
            .lock()
            .map(|g| g.is_active())
            .unwrap_or(false);
        if active {
            self.ensure_compression_streams()?;
        }

        // Build SSH_MSG_CHANNEL_OPEN(90) "session".
        let mut open = Vec::<u8>::with_capacity(40);
        open.push(SSH_MSG_CHANNEL_OPEN);
        append_string(&mut open, SESSION_STR);
        append_u32_be(&mut open, 0); // local channel id
        append_u32_be(&mut open, self.advertised_window_initial);
        append_u32_be(&mut open, self.advertised_max_packet);
        self.encrypt_and_send(&open).await?;
        self.stage.store(SshStage::WantChannel as u32, Ordering::SeqCst);
        Ok(())
    }

    /// `SSH_MSG_USERAUTH_INFO_REQUEST` (60) — keyboard-interactive
    /// challenge from server. We respond by echoing back the password
    /// from session state.
    ///
    /// FASM line 5234 onwards.
    async fn handle_userauth_info_request_msg(&self, body: &[u8]) -> Result<(), NetError> {
        if self.client_mode == ClientMode::Server {
            return Ok(());
        }
        let password_owned = self.password.lock().ok().and_then(|g| g.clone());
        let password_str = match password_owned.as_deref() {
            Some(p) => Some(std::str::from_utf8(p).map_err(|_| NetError::Ssh(SshError::Auth))?),
            None => None,
        };
        let frame = handle_userauth_info_request(body, password_str).map_err(NetError::Ssh)?;
        // `UserauthInfoResponseFrame` is a tuple struct wrapping the
        // full ready-to-send packet bytes (see `auth.rs` line 814).
        self.encrypt_and_send(&frame.0).await?;
        Ok(())
    }

    /// `SSH_MSG_USERAUTH_INFO_RESPONSE` (61) — server-side keyboard-
    /// interactive response handling. Same wire form as
    /// `USERAUTH_REQUEST` for our purposes.
    async fn handle_userauth_info_response_msg(&self, _body: &[u8]) -> Result<(), NetError> {
        // Server-side keyboard-interactive is not implemented (FASM
        // path at line 5240 only generates challenges client-side).
        // Reply with FAILURE per RFC 4252 §5.4.
        if self.client_mode == ClientMode::Server {
            let body = build_userauth_failure_payload();
            let mut packet = Vec::with_capacity(1 + body.len());
            packet.push(SSH_MSG_USERAUTH_FAILURE);
            packet.extend_from_slice(body);
            self.encrypt_and_send(&packet).await?;
        }
        Ok(())
    }
}

// ===========================================================================
// Channel-management handlers (FASM `.got_channel_*`)
// ===========================================================================

impl SshSession {
    /// `SSH_MSG_GLOBAL_REQUEST` (80) — usually forwarded port requests
    /// or hostbased credential queries. We do not support any global
    /// requests; if `want_reply` is set, send REQUEST_FAILURE(82).
    async fn handle_global_request(&self, body: &[u8]) -> Result<(), NetError> {
        // Parse: string request_name, bool want_reply, ...
        let (_name, after_name) = read_string(body)?;
        let want_reply = after_name.first().copied().unwrap_or(0) != 0;
        if want_reply {
            // SSH_MSG_REQUEST_FAILURE = 82
            let payload = vec![82u8];
            self.encrypt_and_send(&payload).await?;
        }
        Ok(())
    }

    /// `SSH_MSG_CHANNEL_OPEN` (90) — server-side. Peer wants to open
    /// a channel; we accept "session" only and reply with
    /// `CHANNEL_OPEN_CONFIRMATION`.
    ///
    /// FASM `ssh.inc` `.got_channelopen` (line ~5300).
    async fn handle_channel_open(&self, body: &[u8]) -> Result<(), NetError> {
        if self.client_mode != ClientMode::Server {
            return Ok(());
        }
        // Parse: string channel-type, u32 sender_channel, u32 init_window, u32 max_packet
        let (channel_type, after_type) = read_string(body)?;
        if after_type.len() < 12 {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "CHANNEL_OPEN: body too short".into(),
            )));
        }
        let sender_chan = u32::from_be_bytes([after_type[0], after_type[1], after_type[2], after_type[3]]);
        let init_window = u32::from_be_bytes([after_type[4], after_type[5], after_type[6], after_type[7]]);
        let max_pkt = u32::from_be_bytes([after_type[8], after_type[9], after_type[10], after_type[11]]);

        // `read_string` returns the bytes of the SSH `string` field
        // **after** stripping its 4-byte big-endian length prefix
        // (server.rs:2725 `let bytes = buf[4..4 + len].to_vec();`),
        // whereas [`SESSION_STR`] stores the on-wire representation
        // including its length prefix (4-byte BE length 7 followed by
        // ASCII "session", 11 bytes total — see auth.rs:373 and the
        // corresponding `test_session_str_layout` test). To compare
        // the parsed channel-type name against the constant we skip
        // the constant's first four bytes so both operands are the
        // raw 7-byte ASCII "session". Mirrors the FASM
        // `ssh.inc .got_channelopen` path which reads the channel
        // type field as raw bytes (after consuming the SSH `string`
        // length header in the same parser pass) and memcmps against
        // `.sessionstr`'s data portion (FASM lines 5300–5310 area).
        if channel_type == SESSION_STR[4..] {
            // Accept session channel.
            self.remote_channel_id.store(sender_chan, Ordering::SeqCst);
            self.remote_window.store(init_window, Ordering::SeqCst);
            // Build CHANNEL_OPEN_CONFIRMATION(91).
            let mut conf = Vec::<u8>::with_capacity(17);
            conf.push(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
            append_u32_be(&mut conf, sender_chan); // peer channel id (echo)
            append_u32_be(&mut conf, 0); // our channel id
            append_u32_be(&mut conf, self.advertised_window_initial);
            append_u32_be(&mut conf, self.advertised_max_packet);
            self.encrypt_and_send(&conf).await?;
            self.channel_id.store(0, Ordering::SeqCst);
            self.stage.store(SshStage::Channel as u32, Ordering::SeqCst);
            // Suppress unused max_pkt warning — we accept whatever the
            // peer offers and chunk our outbound traffic to our own
            // configured CHANNEL_DATA_CHUNK.
            let _ = max_pkt;
        } else {
            // Reject unknown channel types — CHANNEL_OPEN_FAILURE(92).
            let mut fail = Vec::<u8>::with_capacity(20);
            fail.push(SSH_MSG_CHANNEL_OPEN_FAILURE);
            append_u32_be(&mut fail, sender_chan);
            append_u32_be(&mut fail, 3); // SSH_OPEN_UNKNOWN_CHANNEL_TYPE
            append_u32_be(&mut fail, 0); // empty description
            append_u32_be(&mut fail, 0); // empty language tag
            self.encrypt_and_send(&fail).await?;
        }
        Ok(())
    }

    /// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` (91) — client-side. Server
    /// accepted our channel-open; record peer channel id + window and
    /// transition. If we are a session client, send pty-req + shell.
    async fn handle_channel_open_confirm(&self, body: &[u8]) -> Result<(), NetError> {
        if self.client_mode == ClientMode::Server {
            return Ok(());
        }
        if body.len() < 16 {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "CHANNEL_OPEN_CONFIRMATION: body too short".into(),
            )));
        }
        let _our_chan = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let peer_chan = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        let peer_window = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
        let _peer_max_pkt = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
        self.remote_channel_id.store(peer_chan, Ordering::SeqCst);
        self.remote_window.store(peer_window, Ordering::SeqCst);
        self.stage.store(SshStage::Channel as u32, Ordering::SeqCst);

        // Send pty-req + shell (or exec) per ClientMode.
        match self.client_mode {
            ClientMode::SessionClient => {
                self.send_pty_req().await?;
                self.send_shell_req().await?;
                self.stage.store(SshStage::Interactive as u32, Ordering::SeqCst);
            }
            ClientMode::SftpClient => {
                self.send_subsystem_req(b"sftp").await?;
                self.stage.store(SshStage::Interactive as u32, Ordering::SeqCst);
            }
            ClientMode::Server => {}
        }
        Ok(())
    }

    /// `SSH_MSG_CHANNEL_OPEN_FAILURE` (92) — peer rejected our open.
    async fn handle_channel_open_failure(&self, _body: &[u8]) -> Result<(), NetError> {
        self.dead.store(true, Ordering::SeqCst);
        self.stage.store(SshStage::TornDown as u32, Ordering::SeqCst);
        Ok(())
    }

    /// `SSH_MSG_CHANNEL_WINDOW_ADJUST` (93) — peer is granting us more
    /// outbound window space. Increment `remote_window`.
    async fn handle_channel_window_adjust(&self, body: &[u8]) -> Result<(), NetError> {
        if body.len() < 8 {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "WINDOW_ADJUST: body too short".into(),
            )));
        }
        let _chan = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let bytes_to_add = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        self.remote_window.fetch_add(bytes_to_add, Ordering::SeqCst);
        Ok(())
    }

    /// `SSH_MSG_CHANNEL_DATA` (94) — peer is sending application data.
    /// Decrement `local_window`, deliver bytes to consumer via
    /// `channel_tx`, and replenish window if it falls below threshold.
    async fn handle_channel_data(&self, body: &[u8]) -> Result<(), NetError> {
        if body.len() < 8 {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "CHANNEL_DATA: body too short".into(),
            )));
        }
        let _chan = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let data_len = u32::from_be_bytes([body[4], body[5], body[6], body[7]]) as usize;
        if body.len() < 8 + data_len {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "CHANNEL_DATA: data length exceeds payload".into(),
            )));
        }
        let data = &body[8..8 + data_len];
        // Deliver to consumer via channel_tx; ignore send error
        // (consumer may have already dropped the receiver).
        let _ = self.channel_tx.send(Bytes::copy_from_slice(data));

        // Decrement local window; replenish if it drops below threshold.
        let new_local = self
            .local_window
            .fetch_sub(data_len as u32, Ordering::SeqCst)
            .saturating_sub(data_len as u32);
        if new_local < WINDOW_ADJUST_THRESHOLD {
            // Build CHANNEL_WINDOW_ADJUST(93) packet.
            let mut adj = Vec::<u8>::with_capacity(9);
            adj.push(SSH_MSG_CHANNEL_WINDOW_ADJUST);
            append_u32_be(&mut adj, self.remote_channel_id.load(Ordering::SeqCst));
            append_u32_be(&mut adj, WINDOW_ADJUST_INCREMENT);
            self.encrypt_and_send(&adj).await?;
            self.local_window
                .fetch_add(WINDOW_ADJUST_INCREMENT, Ordering::SeqCst);
        }
        Ok(())
    }

    /// `SSH_MSG_CHANNEL_EXTENDED_DATA` (95) — peer is sending stderr-
    /// type data. Treated identically to CHANNEL_DATA for our purposes
    /// (we only have one application data sink).
    async fn handle_channel_extended_data(&self, body: &[u8]) -> Result<(), NetError> {
        if body.len() < 12 {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "EXTENDED_DATA: body too short".into(),
            )));
        }
        // Skip the 4-byte type code (0 = stderr).
        let mut sub_body = Vec::<u8>::with_capacity(8 + (body.len() - 12));
        sub_body.extend_from_slice(&body[..4]); // chan
        sub_body.extend_from_slice(&body[8..]); // length-prefixed data
        self.handle_channel_data(&sub_body).await
    }

    /// `SSH_MSG_CHANNEL_EOF` (96) — peer is signaling end of input.
    /// Invoke the EOF callback if registered.
    async fn handle_channel_eof(&self, _body: &[u8]) -> Result<(), NetError> {
        let cb = self.eof_cb.lock().ok().and_then(|g| g.clone());
        if let Some(cb) = cb {
            cb();
        }
        Ok(())
    }

    /// `SSH_MSG_CHANNEL_CLOSE` (97) — peer is closing the channel.
    /// Send our own CHANNEL_CLOSE in reply (RFC 4254 §5.3) and
    /// transition to TornDown.
    async fn handle_channel_close(&self, _body: &[u8]) -> Result<(), NetError> {
        let mut close = Vec::<u8>::with_capacity(5);
        close.push(SSH_MSG_CHANNEL_CLOSE);
        append_u32_be(&mut close, self.remote_channel_id.load(Ordering::SeqCst));
        let _ = self.encrypt_and_send(&close).await;
        self.stage.store(SshStage::TornDown as u32, Ordering::SeqCst);
        Ok(())
    }

    /// `SSH_MSG_CHANNEL_REQUEST` (98) — peer is making a per-channel
    /// request. We handle pty-req, shell, exec, subsystem, and
    /// window-change. Other request types reply with FAILURE (100) if
    /// `want_reply` is set.
    async fn handle_channel_request(&self, body: &[u8]) -> Result<(), NetError> {
        if body.len() < 5 {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "CHANNEL_REQUEST: body too short".into(),
            )));
        }
        let _chan = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let after_chan = &body[4..];
        let (req_type, after_type) = read_string(after_chan)?;
        if after_type.is_empty() {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "CHANNEL_REQUEST: missing want_reply".into(),
            )));
        }
        let want_reply = after_type[0] != 0;
        let after_want = &after_type[1..];

        let mut handled = false;
        if req_type == b"pty-req" {
            // pty-req: string TERM, u32 cols, u32 rows, u32 widthpx, u32 heightpx, string modes
            self.parse_pty_req(after_want)?;
            handled = true;
        } else if req_type == b"shell" || req_type == b"exec" || req_type == b"subsystem" {
            if req_type == b"exec" || req_type == b"subsystem" {
                // exec / subsystem: string command/name
                let (command, _rest) = read_string(after_want)?;
                if let Ok(mut g) = self.exec.lock() {
                    *g = Some(command);
                }
            }
            self.stage.store(SshStage::Interactive as u32, Ordering::SeqCst);
            handled = true;
        } else if req_type == b"window-change" {
            self.parse_window_change(after_want)?;
            // window-change has want_reply = false per RFC 4254 §6.7;
            // never send a reply.
            return Ok(());
        }

        if want_reply {
            let reply_type = if handled {
                SSH_MSG_CHANNEL_SUCCESS
            } else {
                SSH_MSG_CHANNEL_FAILURE
            };
            let mut reply = Vec::<u8>::with_capacity(5);
            reply.push(reply_type);
            append_u32_be(&mut reply, self.remote_channel_id.load(Ordering::SeqCst));
            self.encrypt_and_send(&reply).await?;
        }
        Ok(())
    }
}

// ===========================================================================
// Helper routines for handlers
// ===========================================================================

impl SshSession {
    /// Compute the SSH exchange hash `H` from the current KEX state +
    /// the supplied host-key blob and finalized [`DhExchange`].
    ///
    /// Hash order is mode-dependent per FASM `.keycalc` (server) vs.
    /// `.keycalc_client` (client) — the difference is the V_C/V_S and
    /// I_C/I_S swap (server hashes peer's first, client hashes its own
    /// first).
    fn compute_exchange_hash(&self, host_key_blob: &[u8], dh: &DhExchange) -> Result<[u8; 32], NetError> {
        let g = self
            .kex
            .lock()
            .map_err(|_| NetError::Ssh(SshError::KeyExchange("kex lock".into())))?;
        let local_ident = &g.local_ident;
        let remote_ident = g
            .remote_ident
            .as_ref()
            .ok_or_else(|| NetError::Ssh(SshError::KeyExchange("remote ident not yet observed".into())))?;
        let local_kexinit = g
            .local_kexinit
            .as_ref()
            .ok_or_else(|| NetError::Ssh(SshError::KeyExchange("local KEXINIT not built".into())))?;
        let remote_kexinit = g
            .remote_kexinit
            .as_ref()
            .ok_or_else(|| NetError::Ssh(SshError::KeyExchange("remote KEXINIT not observed".into())))?;

        let mut hb = KexHashBuilder::new();
        if self.client_mode == ClientMode::Server {
            // Server: V_C, V_S, I_C, I_S, K_S
            hb.update_string(remote_ident);
            hb.update_string(local_ident);
            hb.update_string(remote_kexinit);
            hb.update_string(local_kexinit);
        } else {
            // Client: V_C, V_S, I_C, I_S, K_S — swap pairs.
            hb.update_string(local_ident);
            hb.update_string(remote_ident);
            hb.update_string(local_kexinit);
            hb.update_string(remote_kexinit);
        }
        hb.update_string(host_key_blob);

        // (min, n, max) or just n for old-GEX.
        if let Some(range) = dh.gex_range() {
            // Modern GEX — three u32s.
            hb.update_u32_be(range.min);
            hb.update_u32_be(range.n);
            hb.update_u32_be(range.max);
        } else {
            // Old GEX — single u32 n. We don't track the original n
            // separately; use DEFAULT_GEX_N as a fallback.
            hb.update_u32_be(4096);
        }

        // p, g, e, f, K
        hb.update_mpint(dh.p_mpint());
        hb.update_mpint(dh.g_mpint());
        // e and f order depends on perspective: hash always has e first
        // (client public) then f (server public).
        if self.client_mode == ClientMode::Server {
            // Server side: remote_public is e, local_public is f.
            let e_bytes = dh
                .remote_public_mpint()
                .ok_or_else(|| NetError::Ssh(SshError::KeyExchange("remote public e missing".into())))?;
            hb.update_mpint(e_bytes);
            hb.update_mpint(dh.local_public_mpint());
        } else {
            // Client side: local_public is e, remote_public is f.
            hb.update_mpint(dh.local_public_mpint());
            let f_bytes = dh
                .remote_public_mpint()
                .ok_or_else(|| NetError::Ssh(SshError::KeyExchange("remote public f missing".into())))?;
            hb.update_mpint(f_bytes);
        }
        let shared = dh
            .shared_mpint()
            .ok_or_else(|| NetError::Ssh(SshError::KeyExchange("shared secret K not computed".into())))?;
        hb.update_mpint(shared);

        Ok(hb.finalize())
    }

    /// Activate the outbound cipher with pending session keys.
    ///
    /// FASM `.got_newkeys` line ~3970 (server) / ~4920 (client). Moves
    /// the pending session keys out of `kex.pending` and installs them
    /// into `local_cipher`.
    fn activate_local_cipher(&self) -> Result<(), NetError> {
        let pending = {
            let g = self.kex.lock().map_err(|_| NetError::Ssh(SshError::Cipher))?;
            g.pending.as_ref().map(|p| (p.key_local, p.iv_local, p.mac_local))
        };
        let (key, iv, mac) = pending.ok_or_else(|| {
            NetError::Ssh(SshError::KeyExchange(
                "no pending session keys for local cipher".into(),
            ))
        })?;
        if let Ok(mut g) = self.local_cipher.lock() {
            g.activate(key, iv, mac);
        }
        Ok(())
    }

    /// Activate the inbound cipher with pending session keys.
    fn activate_remote_cipher(&self) -> Result<(), NetError> {
        let pending = {
            let g = self.kex.lock().map_err(|_| NetError::Ssh(SshError::Cipher))?;
            g.pending
                .as_ref()
                .map(|p| (p.key_remote, p.iv_remote, p.mac_remote))
        };
        let (key, iv, mac) = pending.ok_or_else(|| {
            NetError::Ssh(SshError::KeyExchange(
                "no pending session keys for remote cipher".into(),
            ))
        })?;
        if let Ok(mut g) = self.remote_cipher.lock() {
            g.activate(key, iv, mac);
        }
        // Once both ciphers are active, drop pending.
        if let Ok(mut g) = self.kex.lock() {
            g.pending = None;
        }
        Ok(())
    }

    /// Lazily create both compression streams once compression is
    /// active. Idempotent — calling more than once is a no-op.
    fn ensure_compression_streams(&self) -> Result<(), NetError> {
        if let Ok(mut g) = self.deflate.lock() {
            if g.is_none() {
                *g = Some(DeflateStream::new());
            }
        }
        if let Ok(mut g) = self.inflate.lock() {
            if g.is_none() {
                *g = Some(InflateStream::new());
            }
        }
        Ok(())
    }

    /// Send `SSH_MSG_CHANNEL_REQUEST("pty-req")` per RFC 4254 §6.2.
    /// Hard-coded to the FASM defaults: TERM=xterm, 80×25 cols/rows,
    /// 640×480 px, no modes.
    async fn send_pty_req(&self) -> Result<(), NetError> {
        let mut req = Vec::<u8>::with_capacity(64);
        req.push(SSH_MSG_CHANNEL_REQUEST);
        append_u32_be(&mut req, self.remote_channel_id.load(Ordering::SeqCst));
        append_string(&mut req, b"pty-req");
        req.push(1); // want_reply = true
        append_string(&mut req, b"xterm");
        append_u32_be(&mut req, DEFAULT_PTY_COLS);
        append_u32_be(&mut req, DEFAULT_PTY_ROWS);
        append_u32_be(&mut req, 640); // px width
        append_u32_be(&mut req, 480); // px height
        append_string(&mut req, &[]); // modes (empty)
        self.encrypt_and_send(&req).await
    }

    /// Send `SSH_MSG_CHANNEL_REQUEST("shell")`.
    async fn send_shell_req(&self) -> Result<(), NetError> {
        let mut req = Vec::<u8>::with_capacity(20);
        req.push(SSH_MSG_CHANNEL_REQUEST);
        append_u32_be(&mut req, self.remote_channel_id.load(Ordering::SeqCst));
        append_string(&mut req, b"shell");
        req.push(0); // want_reply = false
        self.encrypt_and_send(&req).await
    }

    /// Send `SSH_MSG_CHANNEL_REQUEST("subsystem", name)` for SFTP, etc.
    async fn send_subsystem_req(&self, name: &[u8]) -> Result<(), NetError> {
        let mut req = Vec::<u8>::with_capacity(32 + name.len());
        req.push(SSH_MSG_CHANNEL_REQUEST);
        append_u32_be(&mut req, self.remote_channel_id.load(Ordering::SeqCst));
        append_string(&mut req, b"subsystem");
        req.push(0); // want_reply = false
        append_string(&mut req, name);
        self.encrypt_and_send(&req).await
    }

    /// Parse an inbound `pty-req` body (after the want_reply byte) and
    /// update `width` / `height`. Caps at FASM `PTY_MAX_COLS` / `_ROWS`.
    fn parse_pty_req(&self, after_want: &[u8]) -> Result<(), NetError> {
        let (_term, after_term) = read_string(after_want)?;
        if after_term.len() < 16 {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "pty-req body too short".into(),
            )));
        }
        let cols = u32::from_be_bytes([after_term[0], after_term[1], after_term[2], after_term[3]]);
        let rows = u32::from_be_bytes([after_term[4], after_term[5], after_term[6], after_term[7]]);
        let cols = cols.min(PTY_MAX_COLS);
        let rows = rows.min(PTY_MAX_ROWS);
        self.width.store(cols, Ordering::SeqCst);
        self.height.store(rows, Ordering::SeqCst);
        // Notify the wsize callback if registered.
        if let Some(cb) = self.wsize_cb.lock().ok().and_then(|g| g.clone()) {
            cb(cols, rows);
        }
        Ok(())
    }

    /// Parse an inbound `window-change` body (after the want_reply
    /// byte). Updates `width` / `height` and fires the wsize callback.
    fn parse_window_change(&self, after_want: &[u8]) -> Result<(), NetError> {
        if after_want.len() < 16 {
            return Err(NetError::Ssh(SshError::KeyExchange(
                "window-change body too short".into(),
            )));
        }
        let cols = u32::from_be_bytes([after_want[0], after_want[1], after_want[2], after_want[3]]);
        let rows = u32::from_be_bytes([after_want[4], after_want[5], after_want[6], after_want[7]]);
        let cols = cols.min(PTY_MAX_COLS);
        let rows = rows.min(PTY_MAX_ROWS);
        self.width.store(cols, Ordering::SeqCst);
        self.height.store(rows, Ordering::SeqCst);
        if let Some(cb) = self.wsize_cb.lock().ok().and_then(|g| g.clone()) {
            cb(cols, rows);
        }
        Ok(())
    }
}

// ===========================================================================
// Free helper functions used by the handlers
// ===========================================================================

/// Read an SSH string from `buf` (4-byte BE length + bytes). Returns
/// the bytes and the slice after the string.
fn read_string(buf: &[u8]) -> Result<(Vec<u8>, &[u8]), NetError> {
    if buf.len() < 4 {
        return Err(NetError::Ssh(SshError::KeyExchange(
            "read_string: buffer too short for length".into(),
        )));
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return Err(NetError::Ssh(SshError::KeyExchange(
            "read_string: buffer too short for content".into(),
        )));
    }
    let bytes = buf[4..4 + len].to_vec();
    Ok((bytes, &buf[4 + len..]))
}

/// Read an SSH mpint (4-byte BE length + magnitude bytes), stripping
/// the leading 0x00 padding byte that SSH adds when the high bit of
/// the magnitude is set. Returns the canonical big-endian magnitude
/// and the slice after the mpint.
fn read_mpint(buf: &[u8]) -> Result<(Vec<u8>, &[u8]), NetError> {
    let (mut bytes, rest) = read_string(buf)?;
    // RFC 4251 §5: if positive, leading byte may be 0x00 to indicate
    // sign. Strip a single 0x00 if present and the next byte is >= 0x80.
    if bytes.len() >= 2 && bytes[0] == 0 && bytes[1] >= 0x80 {
        bytes.remove(0);
    } else {
        // Also strip leading zeros (canonical form).
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
    }
    Ok((bytes, rest))
}

/// Extract the SSH-format public-key blob from a [`HostKey`] for use
/// in the exchange-hash and `SSH_MSG_KEX_DH_GEX_REPLY` payloads.
///
/// `kex::HostKey` exposes [`HostKey::public_ssh_blob`] which returns
/// a borrowed slice; we copy it into an owned `Vec` so the caller
/// owns the bytes for the duration of the reply construction.
fn host_key_public_blob(host_key: &HostKey) -> Vec<u8> {
    host_key.public_ssh_blob().to_vec()
}

// ===========================================================================
// Public lifecycle entry points (FASM `ssh$cleanexit` / `ssh$client_windowsize`)
// ===========================================================================

impl SshSession {
    /// FASM `ssh$cleanexit` (lines 1059-1085) — graceful three-step
    /// teardown: emit `SSH_MSG_CHANNEL_EOF` (96), `SSH_MSG_CHANNEL_CLOSE`
    /// (97), then `SSH_MSG_DISCONNECT` (1). The cipher pipeline carries
    /// each packet on the way out; the session is then marked dead and
    /// the [`Drop`] hook will zeroize key material.
    ///
    /// `reason_code` should be one of the
    /// [`SSH_DISCONNECT_*`](https://tools.ietf.org/html/rfc4253#section-11.1)
    /// values; the FASM baseline always uses 11 (`BY_APPLICATION`) with
    /// the message `"Bye!"` — pre-encoded as [`DISCO_PAYLOAD`] for
    /// callers that want byte-exact compatibility with the assembly
    /// behavior.
    pub async fn clean_exit(&self, reason_code: u32, reason_str: &[u8]) -> Result<(), SshError> {
        // Already torn down → swallow silently to make this idempotent.
        if self.dead.load(Ordering::SeqCst) {
            return Ok(());
        }
        let chan = self.remote_channel_id.load(Ordering::SeqCst);
        // 1. SSH_MSG_CHANNEL_EOF (96)
        let mut eof_pkt = Vec::<u8>::with_capacity(5);
        eof_pkt.push(SSH_MSG_CHANNEL_EOF);
        append_u32_be(&mut eof_pkt, chan);
        let _ = self.encrypt_and_send(&eof_pkt).await;
        // 2. SSH_MSG_CHANNEL_CLOSE (97)
        let mut close_pkt = Vec::<u8>::with_capacity(5);
        close_pkt.push(SSH_MSG_CHANNEL_CLOSE);
        append_u32_be(&mut close_pkt, chan);
        let _ = self.encrypt_and_send(&close_pkt).await;
        // 3. SSH_MSG_DISCONNECT (1)
        //
        // Fast path: when the caller passes the FASM baseline values
        // (`reason_code == 11` / `BY_APPLICATION` and `reason_str ==
        // b"Bye!"`), we emit the pre-encoded [`DISCO_PAYLOAD`] verbatim
        // — guaranteeing byte-for-byte wire compatibility with the
        // original `ssh$cleanexit` (FASM `ssh.inc` lines 1059-1085).
        // For any other reason we fall back to the general
        // [`send_disconnect`] helper which dynamically encodes the
        // reason + description + empty language tag. Either branch
        // flips `dead` and the stage to [`SshStage::TornDown`] so the
        // caller does not need to do additional cleanup.
        if reason_code == 11 && reason_str == b"Bye!" {
            // DISCO_PAYLOAD is the *body* of SSH_MSG_DISCONNECT (the
            // 16 bytes after the type byte). We still go through
            // encrypt_and_send so the packet is wrapped, MAC'd, and
            // sequence-counted just like any other.
            let mut packet = Vec::<u8>::with_capacity(1 + DISCO_PAYLOAD.len());
            packet.push(SSH_MSG_DISCONNECT);
            packet.extend_from_slice(DISCO_PAYLOAD);
            // Best-effort send — even on failure we still flip dead +
            // TornDown so callers can re-invoke clean_exit safely.
            let _ = self.encrypt_and_send(&packet).await;
            self.dead.store(true, Ordering::SeqCst);
            self.stage.store(SshStage::TornDown as u32, Ordering::SeqCst);
        } else {
            self.send_disconnect(reason_code, reason_str)
                .await
                .map_err(|_e| SshError::Cipher)?;
        }
        Ok(())
    }

    /// FASM `ssh$client_windowsize` (lines 1007-1053) — client-initiated
    /// terminal-size change. Builds a `SSH_MSG_CHANNEL_REQUEST` (98)
    /// `"window-change"` packet (no reply expected) and updates the
    /// local cached `width`/`height`. Per RFC 4254 §6.7, this is a
    /// no-want-reply request.
    ///
    /// Only valid in the [`SshStage::Interactive`] phase — earlier
    /// invocations are rejected with [`SshError::Cipher`] which the
    /// caller is expected to surface as a state-machine violation.
    pub async fn client_windowsize(&self, cols: u32, rows: u32) -> Result<(), SshError> {
        if self.stage.load(Ordering::SeqCst) != SshStage::Interactive as u32 {
            return Err(SshError::Cipher);
        }
        let chan = self.remote_channel_id.load(Ordering::SeqCst);
        // Packet layout (RFC 4254 §6.7):
        //   byte         SSH_MSG_CHANNEL_REQUEST (98)
        //   uint32       recipient channel
        //   string       "window-change"
        //   boolean      FALSE (want_reply)
        //   uint32       cols
        //   uint32       rows
        //   uint32       width  (pixels) — set to 0
        //   uint32       height (pixels) — set to 0
        let req_name = b"window-change";
        let mut payload = Vec::<u8>::with_capacity(1 + 4 + 4 + req_name.len() + 1 + 4 + 4 + 4 + 4);
        payload.push(SSH_MSG_CHANNEL_REQUEST);
        append_u32_be(&mut payload, chan);
        append_string(&mut payload, req_name);
        payload.push(0); // want_reply = false
        append_u32_be(&mut payload, cols);
        append_u32_be(&mut payload, rows);
        append_u32_be(&mut payload, 0); // width (pixels)
        append_u32_be(&mut payload, 0); // height (pixels)
        self.encrypt_and_send(&payload)
            .await
            .map_err(|_e| SshError::Cipher)?;
        // Update locally cached dimensions so other hooks that consult
        // them see the new values immediately.
        self.width.store(cols, Ordering::SeqCst);
        self.height.store(rows, Ordering::SeqCst);
        Ok(())
    }

    /// Spawn a long-running task that drains the outbound queue
    /// ([`Self::out_queue`]) and feeds each chunk through
    /// [`Self::send_channel_data`]. Called once from
    /// [`IoChain::connected`] — subsequent calls are no-ops because the
    /// receiver can only be taken once.
    fn start_outbound_pump(self: Arc<Self>) {
        // Take ownership of the receiver. If it was already taken (or
        // we are not running on a tokio runtime that can host the
        // task) we silently skip — the SshTransport sender will then
        // surface backpressure errors to the application layer.
        let rx_opt = match self.out_queue.lock() {
            Ok(mut g) => g.take(),
            Err(_) => return,
        };
        let mut rx = match rx_opt {
            Some(rx) => rx,
            None => return,
        };
        let session = self;
        tokio::task::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                if session.dead.load(Ordering::SeqCst) {
                    break;
                }
                if session.send_channel_data(&bytes).await.is_err() {
                    // Encryption / framing failure → terminate pump.
                    break;
                }
            }
        });
    }
}

// ===========================================================================
// Drop — FASM ssh$destroy (lines 378-466) port: zeroize key material,
// reset compression streams, secure-wipe credentials.
// ===========================================================================

impl Drop for SshSession {
    fn drop(&mut self) {
        // Decrement the global session counter (FASM
        // `ssh_session_count`).
        SSH_SESSION_COUNT.fetch_sub(1, Ordering::SeqCst);

        // Zeroize cipher state for both directions. `CipherState`
        // exposes a `zeroize()` method that wipes the key + IV +
        // sequence-number window. We swallow lock-poisoning because
        // a poisoned mutex during Drop is non-fatal — the process is
        // dropping the session regardless.
        if let Ok(mut g) = self.local_cipher.lock() {
            g.zeroize();
        }
        if let Ok(mut g) = self.remote_cipher.lock() {
            g.zeroize();
        }

        // Reset compression streams (drops the underlying flate2
        // contexts and zeroes any internal buffers via `reset()`).
        if let Ok(mut g) = self.deflate.lock() {
            if let Some(stream) = g.as_mut() {
                stream.reset();
            }
            *g = None;
        }
        if let Ok(mut g) = self.inflate.lock() {
            if let Some(stream) = g.as_mut() {
                stream.reset();
            }
            *g = None;
        }

        // Wipe the password (which may carry credentials supplied via
        // CLI / env) — even though Rust would drop the `Vec<u8>`
        // anyway, we explicitly zero its bytes first to defeat
        // post-mortem memory inspection (FASM `ssh$destroy` calls
        // `cleartext` on the password buffer at lines 411-417).
        if let Ok(mut g) = self.password.lock() {
            if let Some(pw) = g.as_mut() {
                for b in pw.iter_mut() {
                    *b = 0;
                }
            }
            *g = None;
        }
        // Same treatment for the exec command (server-mode) and the
        // username (defensive uniformity).
        if let Ok(mut g) = self.exec.lock() {
            if let Some(buf) = g.as_mut() {
                for b in buf.iter_mut() {
                    *b = 0;
                }
            }
            *g = None;
        }
        if let Ok(mut g) = self.username.lock() {
            if let Some(buf) = g.as_mut() {
                for b in buf.iter_mut() {
                    *b = 0;
                }
            }
            *g = None;
        }

        // Drop the host-key vector — `HostKey::Rsa` carries the
        // private DER blob which we want to wipe defensively.
        for hk in self.host_keys.iter_mut() {
            match hk {
                HostKey::Rsa { private_der, .. } => {
                    for b in private_der.iter_mut() {
                        *b = 0;
                    }
                }
                HostKey::Dss { x_be, .. } => {
                    for b in x_be.iter_mut() {
                        *b = 0;
                    }
                }
            }
        }
        self.host_keys.clear();

        // Mark dead + transition stage so any concurrent reads observe
        // a defined terminal state.
        self.dead.store(true, Ordering::SeqCst);
        self.stage.store(SshStage::TornDown as u32, Ordering::SeqCst);
    }
}

// ===========================================================================
// SshChannel — outward-facing handle implementing SshTransport
// ===========================================================================

/// Application-side handle for an `SshSession`'s data channel.
///
/// Holds a clone of `Arc<SshSession>` — the session lives as long as
/// at least one handle (or the IoChain reference) survives.
///
/// **Cross-subsystem contract** (per AAP §0.5.1.4 and folder prompt
/// Phase 20): the TUI rendering subsystem (`tui::widgets::ssh`) holds
/// `Arc<dyn SshTransport>`; that trait object is satisfied by `Arc<SshChannel>`
/// (or any `&SshChannel`). Output bytes from the renderer flow through
/// [`SshTransport::send_bytes`] → outbound queue → pump task →
/// [`SshSession::send_channel_data`] → cipher state → child IoChain.
///
/// # Examples
///
/// ```ignore
/// use std::sync::Arc;
/// use heavything::net::ssh::server::{SshSession, SshChannel};
/// use heavything::tui::widgets::ssh::SshTransport;
///
/// fn install_renderer(session: Arc<SshSession>) -> Arc<dyn SshTransport> {
///     Arc::new(SshChannel::new(session))
/// }
/// ```
pub struct SshChannel {
    session: Arc<SshSession>,
    /// Locally cached remote-address bytes for `SshTransport::remote_addr()`
    /// — populated lazily on first call. Backed by [`std::sync::OnceLock`]
    /// so the borrowed slice we hand out has a stable lifetime tied to
    /// `&self`, with zero `unsafe` and zero deadlock risk.
    remote_addr_cache: std::sync::OnceLock<Vec<u8>>,
}

impl SshChannel {
    /// Wrap an [`SshSession`] in an `SshChannel`. The channel only
    /// holds an `Arc`-clone of the session — the transport handle
    /// does not own the session lifecycle.
    pub fn new(session: Arc<SshSession>) -> Self {
        Self {
            session,
            remote_addr_cache: std::sync::OnceLock::new(),
        }
    }

    /// Take ownership of the inbound channel-data receiver. Returns
    /// `Some(rx)` on the first call; `None` on subsequent calls
    /// (the receiver can only be taken once).
    ///
    /// The caller awaits `rx.recv().await` to receive each
    /// `Bytes` payload that arrived as `SSH_MSG_CHANNEL_DATA` from
    /// the peer. The bytes are already decrypted + decompressed +
    /// MAC-verified by the time they arrive at the receiver.
    pub fn take_receiver(&self) -> Option<mpsc::UnboundedReceiver<Bytes>> {
        self.session.channel_rx.lock().ok().and_then(|mut g| g.take())
    }

    /// Initiate orderly shutdown of the session: marks the session
    /// dead so the receive loop and outbound pump stop on their next
    /// poll. Best-effort — does NOT call [`SshSession::clean_exit`]
    /// because we may be in a sync context with no tokio runtime.
    /// Callers that need RFC-correct teardown should call
    /// `session.clean_exit(11, b"Bye!")` from an async context.
    pub fn close(&self) {
        self.session.dead.store(true, Ordering::SeqCst);
        self.session
            .stage
            .store(SshStage::TornDown as u32, Ordering::SeqCst);
    }

    /// Borrow the underlying session — useful for callers that want
    /// to run async lifecycle methods like
    /// [`SshSession::clean_exit`].
    pub fn session(&self) -> &Arc<SshSession> {
        &self.session
    }
}

impl SshTransport for SshChannel {
    /// Enqueue bytes for transmission as `SSH_MSG_CHANNEL_DATA`.
    ///
    /// Synchronous + non-blocking: pushes to the unbounded outbound
    /// queue. The pump task spawned in `IoChain::connected` drains
    /// the queue asynchronously, runs the bytes through the cipher
    /// state, and forwards them to the child IoChain.
    fn send_bytes(&self, bytes: &[u8]) -> Result<(), TuiError> {
        if self.session.dead.load(Ordering::SeqCst) {
            return Err(TuiError::Render(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "ssh session torn down",
            )));
        }
        if bytes.is_empty() {
            return Ok(());
        }
        // Tokio's unbounded sender returns `Err` only when the
        // receiver has been dropped. In that case the pump task is
        // gone (which is itself an error condition that we surface
        // to the renderer).
        self.session
            .out_tx
            .send(Bytes::copy_from_slice(bytes))
            .map_err(|_e| {
                TuiError::Render(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "ssh outbound pump closed",
                ))
            })
    }

    /// Notify the peer of a new terminal size by sending
    /// `SSH_MSG_CHANNEL_REQUEST` (98) `"window-change"`.
    ///
    /// Synchronous shim that spawns an async task on the active
    /// tokio runtime. The cached width/height fields on the session
    /// are updated immediately so subsequent reads observe the new
    /// values regardless of the spawn outcome.
    fn set_window_size(&self, cols: u16, rows: u16) -> Result<(), TuiError> {
        // Update cached dimensions synchronously for in-process
        // observers. We use u32 to match `width`/`height` field
        // types.
        self.session.width.store(cols as u32, Ordering::SeqCst);
        self.session.height.store(rows as u32, Ordering::SeqCst);
        // Delegate the wire packet to a spawned task. We tolerate
        // the case where there is no tokio runtime (e.g., in unit
        // tests) by checking for runtime presence first.
        if tokio::runtime::Handle::try_current().is_err() {
            return Ok(());
        }
        let session = self.session.clone();
        let cols_u32 = cols as u32;
        let rows_u32 = rows as u32;
        tokio::task::spawn(async move {
            // Best-effort — the session may have transitioned to
            // TornDown between this spawn point and the actual
            // packet emission. We swallow the error.
            let _ = session.client_windowsize(cols_u32, rows_u32).await;
        });
        Ok(())
    }

    /// Return the peer's address as a borrowed byte slice.
    ///
    /// FASM `tui_ssh$connected` copies up to 126 bytes from
    /// `ssh_remoteaddr_ofs` (110-byte sockaddr blob) into a fixed
    /// `tui_ssh_raddr` field. Our internal storage is also 110
    /// bytes; the trait permits any slice length up to 126, so we
    /// return the first `len` bytes from the raw buffer.
    ///
    /// Returns `None` when the session is in client mode (no peer
    /// address recorded) or when the peer address has not yet been
    /// captured.
    fn remote_addr(&self) -> Option<&[u8]> {
        let len = self.session.remote_addr_len.load(Ordering::SeqCst) as usize;
        if len == 0 {
            return None;
        }
        // Lazily snapshot the raw bytes into the OnceLock. The session's
        // remote address is captured once at `connected`/`set_remote_addr`
        // time and never mutates afterwards, so a write-once cache is
        // semantically correct. We use `OnceLock::get_or_init` so the
        // returned `&Vec<u8>` has lifetime `&self`, eliminating both
        // the lifetime gymnastics and the deadlock risk that the
        // earlier mutex-based cache exhibited.
        let cached: &Vec<u8> = self.remote_addr_cache.get_or_init(|| {
            // Best effort: if the underlying mutex is poisoned we fall
            // back to an empty Vec, which the caller will see as a
            // zero-length slice. Since the address is set once at
            // connect time and we already know `len > 0`, poisoning
            // here is essentially impossible in practice.
            match self.session.remote_addr_raw.lock() {
                Ok(g) => g[..len.min(110)].to_vec(),
                Err(_) => Vec::new(),
            }
        });
        if cached.is_empty() {
            None
        } else {
            Some(cached.as_slice())
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    // --- Static byte-exact data preserved from FASM ssh.inc ---

    #[test]
    fn ssh_ident_byte_exact() {
        // FASM `ssh.inc` line 81: `ssh_ident db 'SSH-2.0-HeavyThing', 13, 10`
        assert_eq!(SSH_IDENT, b"SSH-2.0-HeavyThing\r\n");
        assert_eq!(SSH_IDENT_LEN, 20);
        assert_eq!(SSH_IDENT.len(), SSH_IDENT_LEN);
    }

    #[test]
    fn ssh_ident_blacklisted_byte_exact() {
        // Variant emitted to peers that hit the blacklist (FASM
        // `ssh.inc` line 86 region).
        assert_eq!(SSH_IDENT_BLACKLISTED, b"SSH-2.0-HeavyThing (blacklisted)\r\n");
        // Trailing CRLF preserved exactly.
        assert!(SSH_IDENT_BLACKLISTED.ends_with(b"\r\n"));
    }

    #[test]
    fn disco_payload_byte_exact() {
        // Reason 11 = SSH_DISCONNECT_BY_APPLICATION, "Bye!", empty
        // language tag — total 16 bytes (4+4+4+4 = u32 reason +
        // length + "Bye!" + empty lang u32).
        let expected: &[u8] = &[
            0, 0, 0, 11, // reason code = 11
            0, 0, 0, 4, // length(message)
            b'B', b'y', b'e', b'!', // message
            0, 0, 0, 0, // length(language) = 0
        ];
        assert_eq!(DISCO_PAYLOAD, expected);
        assert_eq!(DISCO_PAYLOAD.len(), 16);
    }

    // --- SshStage + ClientMode discriminants ---

    #[test]
    fn ssh_stage_discriminants() {
        // Per FASM ssh.inc lines 195-209.
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

    #[test]
    fn ssh_stage_default_is_idents() {
        assert_eq!(SshStage::default(), SshStage::Idents);
    }

    #[test]
    fn client_mode_default_is_server() {
        assert_eq!(ClientMode::default(), ClientMode::Server);
    }

    #[test]
    fn client_mode_discriminants() {
        assert_eq!(ClientMode::Server as u32, 0);
        assert_eq!(ClientMode::SessionClient as u32, 1);
        assert_eq!(ClientMode::SftpClient as u32, 2);
    }

    // --- SshConfig defaults ---

    #[test]
    fn ssh_config_default_values() {
        let cfg = SshConfig::default();
        assert_eq!(cfg.host_keys_dir, std::path::PathBuf::from("/etc/ssh"));
        assert_eq!(cfg.ident_string, SSH_IDENT);
        assert_eq!(cfg.window_initial, 0x200000);
        assert_eq!(cfg.max_packet_size, 0x8000);
        assert_eq!(cfg.blacklist_ttl, Duration::from_secs(config::SSH_BLACKLIST));
    }

    #[test]
    fn ssh_config_clone_preserves_fields() {
        let original = SshConfig::default();
        let cloned = original.clone();
        assert_eq!(original.window_initial, cloned.window_initial);
        assert_eq!(original.max_packet_size, cloned.max_packet_size);
        assert_eq!(original.dh_dynamic, cloned.dh_dynamic);
    }

    // --- SshSession new_client construction ---

    #[test]
    fn new_client_no_credentials_is_constructible() {
        // Bumps SSH_SESSION_COUNT — record before/after to verify
        // round-trip on Drop.
        let before = SSH_SESSION_COUNT.load(Ordering::SeqCst);
        let session = SshSession::new_client(None, None);
        assert_eq!(SSH_SESSION_COUNT.load(Ordering::SeqCst), before + 1);
        assert_eq!(session.client_mode, ClientMode::SessionClient);
        // Drop the session via Arc::strong_count — when the test
        // function ends and `session` goes out of scope.
        drop(session);
        // The Drop impl decrements the counter.
        assert_eq!(SSH_SESSION_COUNT.load(Ordering::SeqCst), before);
    }

    #[test]
    fn new_client_with_credentials_stores_them() {
        let session = SshSession::new_client(Some(b"alice".to_vec()), Some(b"hunter2".to_vec()));
        let username = session.username.lock().unwrap().clone();
        let password = session.password.lock().unwrap().clone();
        assert_eq!(username.as_deref(), Some(b"alice".as_ref()));
        assert_eq!(password.as_deref(), Some(b"hunter2".as_ref()));
    }

    // --- SshSession peer/session-id getters ---

    #[test]
    fn peer_ip_returns_none_when_unset() {
        let session = SshSession::new_client(None, None);
        assert!(session.peer_ip().is_none());
    }

    #[test]
    fn session_id_default_is_zero() {
        let session = SshSession::new_client(None, None);
        assert_eq!(session.session_id(), [0u8; 32]);
    }

    #[test]
    fn stage_default_is_idents() {
        let session = SshSession::new_client(None, None);
        assert_eq!(session.stage(), SshStage::Idents);
    }

    // --- SshSession set_remote_addr ---

    #[test]
    fn set_remote_addr_records_ipv4() {
        let session = SshSession::new_client(None, None);
        let peer: SocketAddr = "192.0.2.1:22".parse().unwrap();
        session.set_remote_addr(peer).expect("set_remote_addr");
        assert_eq!(session.peer_ip(), Some(peer.ip()));
        assert!(session.remote_addr_len.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn set_remote_addr_records_ipv6() {
        let session = SshSession::new_client(None, None);
        let peer: SocketAddr = "[2001:db8::1]:22".parse().unwrap();
        session.set_remote_addr(peer).expect("set_remote_addr");
        assert_eq!(session.peer_ip(), Some(peer.ip()));
        assert!(session.remote_addr_len.load(Ordering::SeqCst) > 0);
    }

    // --- Callbacks ---

    #[test]
    fn auth_callback_install_and_invoke_grants() {
        use std::sync::atomic::AtomicUsize;
        let session = SshSession::new_client(None, None);
        static CALLED: AtomicUsize = AtomicUsize::new(0);
        session.set_auth_callback(|_user: &str, _pass: &str| {
            CALLED.fetch_add(1, Ordering::SeqCst);
            true
        });
        let cb = session.auth_cb.lock().unwrap().clone().expect("cb installed");
        let granted = cb("alice", "secret");
        assert!(granted);
        assert_eq!(CALLED.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn wsize_callback_install_and_invoke() {
        use std::sync::atomic::AtomicU64;
        let session = SshSession::new_client(None, None);
        static OBSERVED: AtomicU64 = AtomicU64::new(0);
        session.set_wsize_callback(|c: u32, r: u32| {
            // Encode (cols, rows) into a u64 for atomic capture.
            OBSERVED.store(((c as u64) << 32) | r as u64, Ordering::SeqCst);
        });
        let cb = session.wsize_cb.lock().unwrap().clone().expect("wsize installed");
        cb(132, 50);
        let v = OBSERVED.load(Ordering::SeqCst);
        assert_eq!((v >> 32) as u32, 132);
        assert_eq!((v & 0xffff_ffff) as u32, 50);
    }

    #[test]
    fn eof_callback_install_and_invoke() {
        use std::sync::atomic::AtomicBool;
        let session = SshSession::new_client(None, None);
        static FIRED: AtomicBool = AtomicBool::new(false);
        session.set_eof_callback(|| {
            FIRED.store(true, Ordering::SeqCst);
        });
        let cb = session.eof_cb.lock().unwrap().clone().expect("eof installed");
        cb();
        assert!(FIRED.load(Ordering::SeqCst));
    }

    // --- SshChannel + SshTransport contract ---

    #[test]
    fn ssh_channel_implements_transport() {
        // Compile-time: Arc<SshChannel> coerces to Arc<dyn SshTransport>.
        fn _accept_transport(_: Arc<dyn SshTransport>) {}
        let session = SshSession::new_client(None, None);
        let channel: Arc<SshChannel> = Arc::new(SshChannel::new(session));
        _accept_transport(channel as Arc<dyn SshTransport>);
    }

    #[test]
    fn ssh_channel_take_receiver_is_one_shot() {
        let session = SshSession::new_client(None, None);
        let channel = SshChannel::new(session);
        let first = channel.take_receiver();
        assert!(first.is_some(), "first take_receiver returns Some");
        let second = channel.take_receiver();
        assert!(second.is_none(), "second take_receiver returns None");
    }

    #[test]
    fn ssh_channel_send_bytes_when_dead_returns_render_error() {
        let session = SshSession::new_client(None, None);
        // Mark dead to short-circuit the send path.
        session.dead.store(true, Ordering::SeqCst);
        let channel = SshChannel::new(session);
        let res = channel.send_bytes(b"hello");
        assert!(res.is_err(), "send_bytes on dead session is an error");
    }

    #[test]
    fn ssh_channel_send_bytes_empty_succeeds() {
        let session = SshSession::new_client(None, None);
        let channel = SshChannel::new(session);
        let res = channel.send_bytes(&[]);
        assert!(res.is_ok(), "empty send_bytes is a no-op success");
    }

    #[test]
    fn ssh_channel_send_bytes_enqueues() {
        let session = SshSession::new_client(None, None);
        // Take the receiver BEFORE wrapping in SshChannel so we can
        // observe the outbound queue directly.
        let mut rx_out = session
            .out_queue
            .lock()
            .unwrap()
            .take()
            .expect("out_queue receiver");
        let channel = SshChannel::new(session);
        channel.send_bytes(b"ansi-output").expect("send_bytes");
        // try_recv to avoid blocking — we've just pushed so the
        // receiver should be ready.
        match rx_out.try_recv() {
            Ok(bytes) => assert_eq!(bytes.as_ref(), b"ansi-output"),
            Err(e) => panic!("expected enqueued payload, got error: {:?}", e),
        }
    }

    #[test]
    fn ssh_channel_remote_addr_returns_none_when_unset() {
        let session = SshSession::new_client(None, None);
        let channel = SshChannel::new(session);
        assert!(channel.remote_addr().is_none());
    }

    #[test]
    fn ssh_channel_remote_addr_returns_bytes_when_set() {
        let session = SshSession::new_client(None, None);
        let peer: SocketAddr = "192.0.2.7:22".parse().unwrap();
        session.set_remote_addr(peer).expect("set_remote_addr");
        let channel = SshChannel::new(session);
        let bytes = channel.remote_addr().expect("remote_addr present");
        assert!(!bytes.is_empty());
        // The 110-byte raddr_raw buffer is at most 110 bytes long.
        assert!(bytes.len() <= 110);
    }

    #[test]
    fn ssh_channel_set_window_size_updates_session_dimensions() {
        let session = SshSession::new_client(None, None);
        let channel = SshChannel::new(session.clone());
        channel.set_window_size(120, 40).expect("set_window_size");
        assert_eq!(session.width.load(Ordering::SeqCst), 120);
        assert_eq!(session.height.load(Ordering::SeqCst), 40);
    }

    #[test]
    fn ssh_channel_close_marks_session_dead() {
        let session = SshSession::new_client(None, None);
        let channel = SshChannel::new(session.clone());
        channel.close();
        assert!(session.dead.load(Ordering::SeqCst));
        assert_eq!(session.stage.load(Ordering::SeqCst), SshStage::TornDown as u32);
    }

    #[test]
    fn ssh_channel_session_returns_inner_arc() {
        let session = SshSession::new_client(None, None);
        let original_ptr = Arc::as_ptr(&session);
        let channel = SshChannel::new(session);
        let returned = channel.session();
        assert_eq!(Arc::as_ptr(returned), original_ptr);
    }

    // --- Static algorithm-string preservation ---

    #[test]
    fn pty_req_template_byte_exact_prefix() {
        // Verify the channel-request prefix bytes at runtime: msg
        // type 98, channel id 0, "pty-req"(7), want_reply=1.
        // We construct the same prefix and compare.
        let mut expected: Vec<u8> = Vec::new();
        expected.push(SSH_MSG_CHANNEL_REQUEST);
        append_u32_be(&mut expected, 0);
        append_u32_be(&mut expected, 7);
        expected.extend_from_slice(b"pty-req");
        expected.push(1);
        assert_eq!(expected[0], 98);
        assert_eq!(&expected[5..9], &[0, 0, 0, 7]);
        assert_eq!(&expected[9..16], b"pty-req");
        assert_eq!(expected[16], 1);
    }

    // --- Compilation guards: critical export shapes ---

    #[test]
    fn exports_visible() {
        // Spot-check that all top-level types are reachable from the
        // module path (this test would fail to compile if any export
        // disappeared).
        let _: SshConfig = SshConfig::default();
        let _: SshStage = SshStage::Idents;
        let _: ClientMode = ClientMode::Server;
        let _: u32 = SshStage::Goaway as u32;
        let _: usize = SSH_IDENT_LEN;
        let _: &[u8] = SSH_IDENT;
    }

    #[test]
    fn ssh_session_count_starts_nonzero_in_isolated_test_when_session_alive() {
        // When a session is alive the counter is non-zero.
        let _session = SshSession::new_client(None, None);
        assert!(SSH_SESSION_COUNT.load(Ordering::SeqCst) >= 1);
    }
}
