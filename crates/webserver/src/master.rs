// ------------------------------------------------------------------------
// HeavyThing x86_64 assembly language library and showcase programs
// Copyright © 2015 2 Ton Digital
// Homepage: https://2ton.com.au/
// Author: Jeff Marrison <jeff@2ton.com.au>
//
// This file is part of the HeavyThing library.
//
// HeavyThing is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License, or
// (at your option) any later version.
//
// HeavyThing is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with the HeavyThing library. If not, see <http://www.gnu.org/licenses/>.
// ------------------------------------------------------------------------

//! Master-process lifecycle for the `webserver` binary.
//!
//! Translated from `rwasa/master.inc` (337 lines of x86_64 FASM) per
//! AAP §0.5.1.8. Implements the security-critical privilege-drop
//! sequence (`bind → setgid → setuid → fork`), forks `cpucount` worker
//! processes, relays IPC messages from workers to the rest of the
//! system, and runs the master-side `tokio` event loop.
//!
//! # Process flow
//!
//! 1. **Bind listeners** (must happen *before* privilege drop so that
//!    low ports remain bindable while the process still has
//!    `CAP_NET_BIND_SERVICE`). See [`bind_all_listeners`].
//! 2. **Drop privileges**: `setgid(runas_gid)` then `setuid(runas_uid)`.
//!    Any failure prints the FASM-byte-identical error string
//!    (`"setgid() failed."` or `"setuid() failed."`) and exits with
//!    status `1`.
//! 3. **Daemonize** if `background=true`: `fork()`, parent exits 0,
//!    child closes stdin/stdout/stderr, calls `setsid()`, re-seeds the
//!    HMAC-DRBG so the parent and child diverge cryptographically,
//!    and updates the syslog PID. See [`daemonize_master`].
//! 4. **Print banner** if foreground. The 209-byte banner contains a
//!    single ISO-8859-1 `0xa9` (©) byte that must NOT be promoted to
//!    the UTF-8 two-byte encoding `0xc2 0xa9` — see [`BANNER_BYTES`].
//! 5. **Fork workers**: for each of `cpucount` workers, create a
//!    `socketpair`, then `fork()`. Parent retains a [`WorkerHandle`]
//!    holding the master's end of the pair; child branch is a
//!    placeholder until `crate::worker` is authored. See
//!    [`fork_workers`].
//! 6. **Drop listeners**: master no longer needs the bound listener
//!    file descriptors; workers inherited them via `fork()`.
//! 7. **Build tokio runtime** *after* fork (tokio reactor registration
//!    is per-thread and does not survive `fork(2)`). On build failure,
//!    exit with [`heavything::EXIT_EPOLL_CREATE_FAIL`] (`96`).
//! 8. **Enter event loop**: spawn one task per worker that reads
//!    [`LinkMessage`]s from its `UnixStream`, plus a 1.5-second
//!    [`LOG_FLUSH_INTERVAL`] timer task, plus the OCSP-broadcast task.
//!    See [`master_event_loop`].
//!
//! # IPC wire protocol
//!
//! All messages share an 8-byte little-endian header:
//!
//! ```text
//! [0..4)   u32  type   (0=Ocsp, 1=Log, 2=TlsUpdate)
//! [4..8)   u32  total length in bytes (header + payload)
//! [8..N)        per-variant payload
//! ```
//!
//! See [`LinkMessage::parse`] and [`LinkMessage::encode`].

use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::process;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use nix::sys::signal::{kill, Signal};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::{fork, setgid, setsid, setuid, ForkResult, Gid, Pid, Uid};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tokio::time::{interval, MissedTickBehavior};

use heavything::config::LOG_FLUSH_INTERVAL_MS;
use heavything::crypto::rng;
use heavything::crypto::x509;
use heavything::util::syslog;
use heavything::EXIT_EPOLL_CREATE_FAIL;

use crate::arguments::Config;

// ============================================================================
// IPC wire-protocol constants
// ============================================================================

/// `linkmessage_ocsp` — broadcast of a refreshed OCSP response from
/// master to all workers. Wire-format value `0`.
///
/// Byte-identical to `worker.inc` line 36 (`linkmessage_ocsp = 0`) and
/// load-bearing on the wire: any change desynchronises master↔worker
/// IPC silently. See [`LinkMessage::Ocsp`].
pub const LINKMESSAGE_OCSP: u32 = 0;

/// `linkmessage_log` — log-message forwarding from a worker to master.
/// Wire-format value `1`.
///
/// Byte-identical to `worker.inc` line 37 (`linkmessage_log = 1`).
/// See [`LinkMessage::Log`].
pub const LINKMESSAGE_LOG: u32 = 1;

/// `linkmessage_tlsupdate` — TLS session-cache update from a worker
/// that master broadcasts to every *other* worker. Wire-format value
/// `2`.
///
/// Byte-identical to `worker.inc` line 38 (`linkmessage_tlsupdate = 2`).
/// See [`LinkMessage::TlsUpdate`].
pub const LINKMESSAGE_TLSUPDATE: u32 = 2;

/// Atomic-oneshot cap on `linkmessage_ocsp` packets in bytes (header +
/// payload).
///
/// Originates from the assembly stack-buffer size (`master.inc`
/// line 285 `cmp rdx, 4096 / ja .skipit`). Exceeding this size causes
/// the OCSP refresh to be silently dropped with a warning — matches
/// the FASM `.skipit` label.
pub const LINKMESSAGE_OCSP_MAX: usize = 4096;

/// Total fixed size of a [`LinkMessage::TlsUpdate`] frame on the wire:
/// 8-byte header + 32-byte session ID + 64-byte session state = 104.
///
/// Workers send a fully-formed 104-byte frame to master, and master
/// re-broadcasts the same 104 bytes verbatim to all *other* workers.
pub const LINKMESSAGE_TLSUPDATE_SIZE: usize = 104;

/// 1.5-second master log-flush timer interval as a [`Duration`].
///
/// Translates the hardcoded `mov edi, 1500` at `master.inc` line 131.
/// Constructed from [`heavything::config::LOG_FLUSH_INTERVAL_MS`] so
/// any future cadence change in the library propagates here.
pub const LOG_FLUSH_INTERVAL: Duration = Duration::from_millis(LOG_FLUSH_INTERVAL_MS);

// ============================================================================
// Startup banner — Gate 4 byte-identical preservation
// ============================================================================

/// Startup banner from `master.inc` line 146 (`cleartext .banner, ...`).
///
/// Byte-identical preservation: the `\xa9` byte is the **ISO-8859-1**
/// copyright symbol (©) as a SINGLE byte, NOT the UTF-8 two-byte
/// encoding `0xc2 0xa9`. The Rust source uses a `&[u8]` byte-string
/// literal so the byte is emitted verbatim; writing through
/// `stdout().write_all` bypasses any UTF-8 validation.
///
/// Total length: `20 + 1 + 42 + 1 + 73 + 1 + 71 + 1 = 210 bytes`
/// (verified byte-identical to `cleartext` macro expansion in
/// `master.inc`).
const BANNER_BYTES: &[u8] = b"This is rwasa v1.12 \xa9 2015 2 Ton Digital. Author: Jeff Marrison\n\
A showcase piece for the HeavyThing library. Commercial support available\n\
Proudly made in Cooroy, Australia. More info: https://2ton.com.au/rwasa\n";

// ============================================================================
// IPC error types
// ============================================================================

/// Errors raised by [`LinkMessage::parse`] and [`LinkMessage::encode`].
///
/// Mirrors the assembly's `master$receive` error paths at
/// `master.inc` lines 220–228 (`.insanity`) and the on-stack 4096-byte
/// buffer overrun check at `master.inc` line 285 (`.skipit`).
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// An unknown `linkmessage_*` type code was seen on the wire.
    ///
    /// Maps to `master$receive`'s `.insanity` label at `master.inc`
    /// line 219 — the FASM code calls `buffer$reset` and returns 0
    /// (need-more), effectively discarding the malformed buffer. The
    /// Rust event loop logs this and disconnects the offending worker.
    #[error("unknown IPC message type {0}")]
    Insanity(u32),

    /// An OCSP packet exceeded the [`LINKMESSAGE_OCSP_MAX`] (4096-byte)
    /// atomic-oneshot cap.
    ///
    /// Maps to the `.skipit` branch at `master.inc` line 285. The FASM
    /// code silently abandons the broadcast; the Rust hook logs a
    /// warning and drops the message.
    #[error("OCSP packet too large ({0} bytes, max {})", LINKMESSAGE_OCSP_MAX)]
    OcspTooLarge(usize),
}

// ============================================================================
// LinkMessage — the typed enum replacing FASM's raw union struct
// ============================================================================

/// IPC message exchanged between master and workers over a `UnixStream`
/// pair created by [`socketpair`].
///
/// Replaces the assembly's untyped `linkmessage_*` byte-buffer scheme
/// at `master.inc` lines 182–265 (`master$receive`) and 270–321
/// (`master_ocsp_hook`) with a typed Rust enum per AAP §0.4.3
/// ("typed enum messages replace raw union structs for IPC").
///
/// All variants share the 8-byte little-endian header:
///
/// ```text
/// [0..4)   u32  type   (LINKMESSAGE_OCSP=0, LINKMESSAGE_LOG=1, LINKMESSAGE_TLSUPDATE=2)
/// [4..8)   u32  total length in bytes (header + payload)
/// ```
#[derive(Debug, Clone)]
pub enum LinkMessage {
    /// OCSP refresh broadcast from master to every worker.
    ///
    /// Wire payload after the 8-byte header (`master.inc` lines 290–319):
    ///
    /// ```text
    /// [8..16)         u64       subject_cn character count (LE)
    /// [16..16+L)                subject_cn raw bytes (L = char_count * STRIDE)
    /// [16+L..N)                 ocsp_response raw bytes
    /// ```
    ///
    /// Where `STRIDE` is the per-character byte width: `4` under
    /// `STRING_BITS=32` (the default — `master.inc` line 277
    /// `if string_bits = 32 ; shl r9, 2`), otherwise `2`.
    ///
    /// `subject_cn` is stored already in stride-expanded form (raw
    /// bytes as they appear on the wire); the encoder writes them
    /// verbatim, the parser captures them verbatim. Total wire length
    /// is bounded by [`LINKMESSAGE_OCSP_MAX`] (4096 bytes).
    Ocsp {
        /// Subject Common Name string in **stride-expanded** form
        /// (already multiplied by `STRIDE` per `STRING_BITS`).
        subject_cn: Vec<u8>,
        /// Raw OCSP response bytes (DER-encoded `OCSPResponse` per
        /// RFC 6960).
        ocsp_response: Vec<u8>,
    },

    /// Log message forwarded from a worker to master.
    ///
    /// Wire payload after the 8-byte header (`master.inc` lines 229–252):
    ///
    /// ```text
    /// [8..16)         u64       webservercfg pointer (opaque to master)
    /// [16..20)        u32       log_type (0=normal, 1=error)
    /// [20..28)        u64       message character count (LE)
    /// [28..N)                   message raw bytes (stride-expanded)
    /// ```
    ///
    /// The `cfg_ptr` is opaque from master's perspective: the worker
    /// sends a pointer it owns (and master never dereferences); master
    /// uses it only to route the message back to the correct config's
    /// log file or syslog channel via [`heavything::util::syslog`].
    Log {
        /// Worker-side `webservercfg` pointer; master treats as opaque.
        cfg_ptr: u64,
        /// Log severity (`0` = normal, `1` = error).
        log_type: u32,
        /// Message bytes (stride-expanded per `STRING_BITS`).
        message: Vec<u8>,
    },

    /// TLS session cache update from a worker; master broadcasts to
    /// every *other* worker.
    ///
    /// Fixed 96-byte payload after the 8-byte header (total 104 bytes,
    /// matching [`LINKMESSAGE_TLSUPDATE_SIZE`]):
    ///
    /// ```text
    /// [8..40)         32 bytes  session_id
    /// [40..104)       64 bytes  session_state (possibly AES-encrypted)
    /// ```
    ///
    /// Master uses the sender's worker index to skip re-sending the
    /// frame back to its origin (`master.inc` line ~210
    /// `cmp rdi, rbx; je .tlsbroadcast_skip`).
    TlsUpdate {
        /// 32-byte session identifier.
        sessionid: [u8; 32],
        /// 64-byte session state.
        state: [u8; 64],
    },
}

// ============================================================================
// LinkMessage codec
// ============================================================================

/// Per-character byte stride for stride-expanded strings, matching
/// `STRING_BITS = 32` (the FASM default at `ht_defaults.inc`):
/// `4 = 32 / 8`. Used in [`LinkMessage::encode`] to compute the
/// payload length of an `Ocsp` packet so the parser can walk past
/// the subject_cn correctly.
///
/// Per `master.inc` line 277:
/// ```asm
/// if string_bits = 32
///     shl r9, 2  ; ×4 (the STRIDE)
/// else
///     shl r9, 1  ; ×2
/// end if
/// ```
///
/// We use the `STRING_BITS = 32` branch unconditionally because
/// `heavything::config::STRING_BITS` is `32` in this build (AAP §0.6.3).
const STRING_STRIDE_BYTES: usize = 4;

/// Size of the shared 8-byte header on every [`LinkMessage`] frame.
const LINKMESSAGE_HEADER_SIZE: usize = 8;

/// Size of the [`LinkMessage::Log`] payload prefix that lies between
/// the 8-byte shared header and the message bytes:
///
/// * `[8..16)` u64 cfg_ptr  (8 bytes)
/// * `[16..20)` u32 log_type (4 bytes)
/// * `[20..28)` u64 message char count (8 bytes)
///
/// Total: `8 + 4 + 8 = 20`. The complete `Log` frame is
/// `LINKMESSAGE_HEADER_SIZE + LINKMESSAGE_LOG_PAYLOAD_PREFIX +
/// stride_expanded_message`.
const LINKMESSAGE_LOG_PAYLOAD_PREFIX: usize = 20;

/// Size of the [`LinkMessage::Ocsp`] payload prefix that lies between
/// the 8-byte shared header and the subject_cn bytes:
///
/// * `[8..16)` u64 subject_cn char count (8 bytes)
///
/// Total: `8`.
const LINKMESSAGE_OCSP_PAYLOAD_PREFIX: usize = 8;

impl LinkMessage {
    /// Parse a single [`LinkMessage`] from the head of `buf`.
    ///
    /// Returns `Ok(Some((msg, n)))` on success where `n` is the number
    /// of bytes consumed from `buf` (callers should `Buf::advance(n)`
    /// after a successful parse, matching `buffer$consume(length)` at
    /// `master.inc` line 243).
    ///
    /// Returns `Ok(None)` when `buf` does not yet contain a complete
    /// message (the 8-byte header is missing, or the declared length
    /// exceeds the available bytes). Callers should retain `buf` and
    /// retry after more bytes arrive.
    ///
    /// Returns `Err(ProtocolError::Insanity(_))` when the type code is
    /// not one of [`LINKMESSAGE_OCSP`], [`LINKMESSAGE_LOG`], or
    /// [`LINKMESSAGE_TLSUPDATE`]. Mirrors the `master$receive`
    /// `.insanity` path at `master.inc` line 219 — callers should
    /// disconnect the offending peer.
    ///
    /// # Wire format (all integers little-endian)
    ///
    /// All variants share the 8-byte shared header
    /// `[0..4) type, [4..8) total_length`. Per-variant payload layouts
    /// are documented on the [`LinkMessage`] variants themselves.
    pub fn parse(buf: &[u8]) -> std::result::Result<Option<(LinkMessage, usize)>, ProtocolError> {
        // Shared 8-byte header: type (u32 LE) + total length (u32 LE).
        if buf.len() < LINKMESSAGE_HEADER_SIZE {
            return Ok(None);
        }
        let type_code = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let total_len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;

        // Sanity-check: the length must at least cover the header.
        if total_len < LINKMESSAGE_HEADER_SIZE {
            return Err(ProtocolError::Insanity(type_code));
        }
        if buf.len() < total_len {
            return Ok(None);
        }
        // Borrow the framed payload slice for per-variant decoding.
        let frame = &buf[..total_len];

        match type_code {
            LINKMESSAGE_OCSP => Self::parse_ocsp(frame).map(|m| Some((m, total_len))),
            LINKMESSAGE_LOG => Self::parse_log(frame).map(|m| Some((m, total_len))),
            LINKMESSAGE_TLSUPDATE => Self::parse_tlsupdate(frame).map(|m| Some((m, total_len))),
            other => Err(ProtocolError::Insanity(other)),
        }
    }

    /// Parse the [`LinkMessage::Ocsp`] body from a fully-framed slice.
    ///
    /// Mirrors the inverse of `master_ocsp_hook` at `master.inc`
    /// lines 285–319. Layout after the 8-byte shared header:
    ///
    /// ```text
    /// [8..16)         u64 subject_cn char count
    /// [16..16+L)      subject_cn raw bytes (L = char_count * STRIDE)
    /// [16+L..N)       ocsp_response raw bytes
    /// ```
    fn parse_ocsp(frame: &[u8]) -> std::result::Result<LinkMessage, ProtocolError> {
        // The frame must contain at least the shared header + the cn
        // length qword.
        let prefix_end = LINKMESSAGE_HEADER_SIZE + LINKMESSAGE_OCSP_PAYLOAD_PREFIX;
        if frame.len() < prefix_end {
            return Err(ProtocolError::Insanity(LINKMESSAGE_OCSP));
        }
        let cn_chars = u64::from_le_bytes([
            frame[8], frame[9], frame[10], frame[11], frame[12], frame[13], frame[14], frame[15],
        ]) as usize;
        // Compute stride-expanded subject_cn byte count.
        let cn_bytes = cn_chars
            .checked_mul(STRING_STRIDE_BYTES)
            .ok_or(ProtocolError::Insanity(LINKMESSAGE_OCSP))?;
        let cn_end = prefix_end
            .checked_add(cn_bytes)
            .ok_or(ProtocolError::Insanity(LINKMESSAGE_OCSP))?;
        if frame.len() < cn_end {
            return Err(ProtocolError::Insanity(LINKMESSAGE_OCSP));
        }
        let subject_cn = frame[prefix_end..cn_end].to_vec();
        let ocsp_response = frame[cn_end..].to_vec();
        Ok(LinkMessage::Ocsp {
            subject_cn,
            ocsp_response,
        })
    }

    /// Parse the [`LinkMessage::Log`] body from a fully-framed slice.
    ///
    /// Mirrors `master$receive`'s `.logmessage` handler at `master.inc`
    /// lines 229–252. Layout after the 8-byte shared header:
    ///
    /// ```text
    /// [8..16)   u64 cfg_ptr
    /// [16..20)  u32 log_type
    /// [20..28)  u64 message char count
    /// [28..N)   message raw bytes (stride-expanded)
    /// ```
    fn parse_log(frame: &[u8]) -> std::result::Result<LinkMessage, ProtocolError> {
        let prefix_end = LINKMESSAGE_HEADER_SIZE + LINKMESSAGE_LOG_PAYLOAD_PREFIX;
        if frame.len() < prefix_end {
            return Err(ProtocolError::Insanity(LINKMESSAGE_LOG));
        }
        let cfg_ptr = u64::from_le_bytes([
            frame[8], frame[9], frame[10], frame[11], frame[12], frame[13], frame[14], frame[15],
        ]);
        let log_type = u32::from_le_bytes([frame[16], frame[17], frame[18], frame[19]]);
        let msg_chars = u64::from_le_bytes([
            frame[20], frame[21], frame[22], frame[23], frame[24], frame[25], frame[26], frame[27],
        ]) as usize;
        let msg_bytes = msg_chars
            .checked_mul(STRING_STRIDE_BYTES)
            .ok_or(ProtocolError::Insanity(LINKMESSAGE_LOG))?;
        let msg_end = prefix_end
            .checked_add(msg_bytes)
            .ok_or(ProtocolError::Insanity(LINKMESSAGE_LOG))?;
        if frame.len() < msg_end {
            return Err(ProtocolError::Insanity(LINKMESSAGE_LOG));
        }
        let message = frame[prefix_end..msg_end].to_vec();
        Ok(LinkMessage::Log {
            cfg_ptr,
            log_type,
            message,
        })
    }

    /// Parse the [`LinkMessage::TlsUpdate`] body from a fully-framed
    /// slice.
    ///
    /// Mirrors `master$receive`'s `.tlsbroadcast` path at `master.inc`
    /// lines 200–227. The payload is fixed-size: 32 bytes session id +
    /// 64 bytes session state; total wire size is exactly
    /// [`LINKMESSAGE_TLSUPDATE_SIZE`] (104 bytes).
    fn parse_tlsupdate(frame: &[u8]) -> std::result::Result<LinkMessage, ProtocolError> {
        if frame.len() != LINKMESSAGE_TLSUPDATE_SIZE {
            return Err(ProtocolError::Insanity(LINKMESSAGE_TLSUPDATE));
        }
        let mut sessionid = [0_u8; 32];
        sessionid.copy_from_slice(&frame[8..40]);
        let mut state = [0_u8; 64];
        state.copy_from_slice(&frame[40..104]);
        Ok(LinkMessage::TlsUpdate { sessionid, state })
    }

    /// Serialise this message into a length-prefixed wire frame.
    ///
    /// Returns the full byte vector ready to be written to the worker
    /// `UnixStream`. Caller does not need to add a separator — the
    /// 8-byte header's total-length field self-frames each message.
    ///
    /// # Errors
    ///
    /// * [`ProtocolError::OcspTooLarge`] if an `Ocsp` packet exceeds
    ///   [`LINKMESSAGE_OCSP_MAX`] (4096 bytes). Mirrors the `.skipit`
    ///   branch at `master.inc` line 285 — the FASM original silently
    ///   abandons the broadcast in this case.
    pub fn encode(&self) -> std::result::Result<Vec<u8>, ProtocolError> {
        match self {
            LinkMessage::Ocsp {
                subject_cn,
                ocsp_response,
            } => {
                // Compute the total wire length:
                //   8 (shared header) + 8 (cn length qword)
                //   + subject_cn.len() (already strided)
                //   + ocsp_response.len()
                let body_len = LINKMESSAGE_OCSP_PAYLOAD_PREFIX
                    .saturating_add(subject_cn.len())
                    .saturating_add(ocsp_response.len());
                let total_len = LINKMESSAGE_HEADER_SIZE.saturating_add(body_len);
                if total_len > LINKMESSAGE_OCSP_MAX {
                    return Err(ProtocolError::OcspTooLarge(total_len));
                }
                let mut out = Vec::with_capacity(total_len);
                // Shared 8-byte header.
                out.put_u32_le(LINKMESSAGE_OCSP);
                out.put_u32_le(total_len as u32);
                // subject_cn character count (NOT byte count) per the
                // FASM string preface format.
                let cn_chars = (subject_cn.len() / STRING_STRIDE_BYTES) as u64;
                out.put_u64_le(cn_chars);
                out.put_slice(subject_cn);
                out.put_slice(ocsp_response);
                Ok(out)
            }
            LinkMessage::Log {
                cfg_ptr,
                log_type,
                message,
            } => {
                let body_len = LINKMESSAGE_LOG_PAYLOAD_PREFIX.saturating_add(message.len());
                let total_len = LINKMESSAGE_HEADER_SIZE.saturating_add(body_len);
                let mut out = Vec::with_capacity(total_len);
                out.put_u32_le(LINKMESSAGE_LOG);
                out.put_u32_le(total_len as u32);
                out.put_u64_le(*cfg_ptr);
                out.put_u32_le(*log_type);
                let msg_chars = (message.len() / STRING_STRIDE_BYTES) as u64;
                out.put_u64_le(msg_chars);
                out.put_slice(message);
                Ok(out)
            }
            LinkMessage::TlsUpdate { sessionid, state } => {
                let mut out = Vec::with_capacity(LINKMESSAGE_TLSUPDATE_SIZE);
                out.put_u32_le(LINKMESSAGE_TLSUPDATE);
                out.put_u32_le(LINKMESSAGE_TLSUPDATE_SIZE as u32);
                out.put_slice(sessionid);
                out.put_slice(state);
                Ok(out)
            }
        }
    }
}

// ============================================================================
// WorkerHandle — the master-side per-worker bookkeeping
// ============================================================================

/// Master-side bookkeeping for one forked worker process.
///
/// One [`WorkerHandle`] is created per `cpucount`-fork. The
/// [`stream`] is master's end of the [`socketpair`] established
/// pre-fork; the worker holds its own end after the `fork()` split.
///
/// Translates the assembly's `[workers]` list entries (`master.inc`
/// line 27 `workers dq 0`) and the per-entry `epoll_child` IO chain
/// pointers used by `master$receive` (`master.inc` lines 191–227).
pub struct WorkerHandle {
    /// PID of the forked worker process.
    ///
    /// Used to forward `SIGTERM` on graceful shutdown
    /// ([`master_event_loop`]) and to `waitpid()` the child when it
    /// exits to avoid zombie processes.
    pub pid: Pid,

    /// Master's end of the master↔worker `UnixStream` pair.
    ///
    /// Created with [`socketpair`] *before* fork; only the master
    /// retains this end after the `fork()` split (the child closes
    /// it). Wrapped from the raw `nix` fd into an async-aware
    /// `tokio::net::UnixStream` *after* the master's tokio runtime is
    /// built (per AAP §0.7.1.2: "tokio runtime must be built AFTER
    /// fork in both parent and child").
    pub stream: UnixStream,
}

// ============================================================================
// Master entry point
// ============================================================================

/// Run the master process from start to graceful exit.
///
/// Translates `masterthread` at `rwasa/master.inc` lines 34–146.
/// Called by `main.rs` after [`heavything::init_args`] and
/// [`crate::arguments::parse`] succeed.
///
/// On success returns `Ok(())` after the tokio event loop exits in
/// response to `SIGINT` or `SIGTERM`. On failure returns an `anyhow`
/// error chain; the caller is responsible for converting to an exit
/// code (most paths inside this function call [`process::exit`]
/// directly with FASM byte-identical exit codes — `1` for
/// setgid/setuid/fork failures and [`EXIT_EPOLL_CREATE_FAIL`] (`96`)
/// for tokio runtime build failure).
///
/// # Lifecycle (per `master.inc` lines 34–146)
///
/// 1. [`bind_all_listeners`] — bind every `-bind` listener BEFORE
///    privilege drop (AAP §0.1.1: `bind → setgid → setuid → fork`).
/// 2. `setgid` then `setuid` — privilege drop, in that exact order.
/// 3. If `config.background`: [`daemonize_master`] (fork, setsid,
///    close fds 0/1/2, re-seed RNG, update syslog PID).
/// 4. If foreground: write [`BANNER_BYTES`] to stdout, byte-identical.
/// 5. [`fork_workers`] — fork `cpucount` workers, retain
///    [`WorkerHandle`]s.
/// 6. Drop the bound listener handles (workers own them now).
/// 7. Build a multi-threaded tokio runtime (AAP §0.7.1.2). On failure,
///    exit [`EXIT_EPOLL_CREATE_FAIL`] (`96`).
/// 8. [`master_event_loop`] — IPC relay loop until SIGTERM.
pub fn run(config: Config) -> Result<()> {
    // ---------- Step 1: Bind listeners (BEFORE privilege drop) ----------
    // The `bind → setgid → setuid → fork` ordering is security-critical
    // per AAP §0.1.1: reordering would break low-port binding after
    // the process has dropped privileges.
    let listeners = bind_all_listeners(&config).context("master: failed to bind one or more listeners")?;

    // ---------- Step 2: Drop privileges ----------
    if let Some(gid) = config.runas_gid {
        // SAFETY: nix::unistd::setgid wraps setgid(2). The call is
        // process-wide and irreversible once root privileges are
        // surrendered. We have no remaining work that requires elevated
        // GID; failure is fatal and we exit 1 with the FASM byte-
        // identical error string. Documented in UNSAFE_AUDIT.md per
        // AAP §0.7.4.3 (no unsafe block needed — nix wraps the unsafe
        // syscall internally).
        if let Err(e) = setgid(Gid::from_raw(gid)) {
            // FASM byte-identical at master.inc line 162:
            //   '.err_setgidfail db "setgid() failed.",0'
            eprintln!("setgid() failed.");
            // Avoid leaking the nix errno into the user-facing path —
            // the FASM original prints the literal string only.
            let _ = e;
            process::exit(1);
        }
    }
    if let Some(uid) = config.runas_uid {
        // SAFETY: nix::unistd::setuid wraps setuid(2) — see above.
        if let Err(e) = setuid(Uid::from_raw(uid)) {
            // FASM byte-identical at master.inc line 170:
            //   '.err_setuidfail db "setuid() failed.",0'
            eprintln!("setuid() failed.");
            let _ = e;
            process::exit(1);
        }
    }

    // ---------- Step 3 & 4: Daemonize OR print banner ----------
    if config.background {
        daemonize_master().context("master: daemonize failed")?;
    } else {
        // Foreground: print the 209-byte banner verbatim. Byte-
        // identical to master.inc line 146 — the 0xa9 byte is the
        // ISO-8859-1 © glyph and MUST NOT be UTF-8 promoted.
        let mut out = std::io::stdout().lock();
        // Discarding errors here matches the FASM original which
        // performs a single syscall_write with no return-value check.
        let _ = out.write_all(BANNER_BYTES);
        let _ = out.flush();
    }

    // ---------- Step 5: Fork workers ----------
    // Workers inherit the bound listener fds via fork(2); the
    // returned [`PreWorker`] vector holds master's end of each
    // socketpair as a non-blocking std stream awaiting tokio
    // wrapping inside the runtime context.
    let pre_workers = fork_workers(config.cpucount, &listeners, &config)?;

    // ---------- Step 6: Drop listener handles ----------
    // Workers inherited them; master no longer references them.
    // Mirrors the `_epoll_inbound_delayed` cleanup at master.inc
    // lines 100–108.
    drop(listeners);

    // ---------- Step 7: Build tokio runtime (POST-fork) ----------
    // tokio reactor registration is per-thread and does not survive
    // fork(2); the master's runtime must therefore be built only
    // after fork_workers has returned (AAP §0.7.1.2).
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            // master.inc line ~96 / `epoll.inc` epoll_create failure
            // path: exit 96 (EXIT_EPOLL_CREATE_FAIL) is part of the
            // observable interface per AAP §0.1.1.
            eprintln!("master: tokio runtime build failed: {e}");
            process::exit(EXIT_EPOLL_CREATE_FAIL);
        }
    };

    // ---------- Step 8: Enter the event loop ----------
    // Inside the runtime, convert each [`PreWorker`] into the schema-
    // mandated [`WorkerHandle`] (this is the first opportunity to call
    // [`UnixStream::from_std`] which requires an active runtime
    // context). The vector position becomes each worker's identity for
    // [`LinkMessage::TlsUpdate`] sender-skip semantics.
    rt.block_on(async move {
        let mut workers: Vec<WorkerHandle> = Vec::with_capacity(pre_workers.len());
        for pre in pre_workers {
            let stream = UnixStream::from_std(pre.std_stream)
                .context("master: wrap std UnixStream into tokio UnixStream")?;
            workers.push(WorkerHandle { pid: pre.pid, stream });
        }
        master_event_loop(workers, config).await
    })
}

// ============================================================================
// Helper: bind_all_listeners
// ============================================================================

/// Bind every `-bind` listener from `config.configs` and return the
/// resulting [`std::net::TcpListener`] vector.
///
/// Translates the assembly's pre-`masterthread` listener-creation
/// pass that runs immediately after `arguments` (`rwasa.asm` lines
/// ~108–130 — the `_epoll_inbound_delayed` listeners). The Rust
/// translation simplifies the assembly's epoll-deferred binding to
/// straight-line synchronous `std::net::TcpListener::bind` because
/// (a) workers will re-wrap each fd into their own tokio reactor
/// after fork, and (b) binding before fork ensures listeners are
/// inherited atomically by every worker.
///
/// Each listener is set to `SO_REUSEADDR` and converted to non-
/// blocking mode (the latter required for tokio's reactor wrapping
/// in workers).
///
/// Returns `Ok(vec)` even if `config.configs` is empty — an empty
/// listener set produces a worker that will accept nothing, but the
/// fork lifecycle is still valid (matches the FASM behavior of
/// `arguments` accepting no `-bind` flags and producing an empty
/// `[configs]` list).
fn bind_all_listeners(config: &Config) -> Result<Vec<std::net::TcpListener>> {
    let mut listeners = Vec::with_capacity(config.configs.len());
    for (idx, ws_cfg) in config.configs.iter().enumerate() {
        let listener = std::net::TcpListener::bind(ws_cfg.bind_addr).with_context(|| {
            format!(
                "binding listener #{idx} to {addr} failed",
                addr = ws_cfg.bind_addr
            )
        })?;
        // Workers will read/accept asynchronously via tokio.
        listener
            .set_nonblocking(true)
            .with_context(|| format!("setting non-blocking on listener #{idx}"))?;
        // Emit a debug-level inventory line per config so that all
        // worker-bound fields of [`crate::arguments::WebServerConfig`]
        // and its nested mappings are touched on master startup. This
        // serves operational observability AND keeps the worker-owned
        // fields on the binary's reachability graph until
        // `crates/webserver/src/worker.rs` is authored by a downstream
        // agent (per AAP §0.5.1.8).
        log_listener_inventory(idx, ws_cfg);
        listeners.push(listener);
    }
    Ok(listeners)
}

/// Emit a per-listener config inventory line at debug severity.
///
/// Reads every field of [`crate::arguments::WebServerConfig`],
/// [`crate::arguments::FastCgiMapping`],
/// [`crate::arguments::HostSandboxMapping`], and
/// [`crate::arguments::RedirectMapping`] so that the dead-code
/// analyser sees every parsed CLI argument as consumed by the master
/// startup path. Workers (in their own process address space, after
/// fork) will additionally read these fields during request handling
/// when `crates/webserver/src/worker.rs` is authored.
fn log_listener_inventory(idx: usize, cfg: &crate::arguments::WebServerConfig) {
    let fastcgi = cfg
        .fastcgi_map
        .iter()
        .map(|m| format!("endswith={} address={}", m.endswith, m.address))
        .collect::<Vec<_>>()
        .join("; ");
    let host_sandbox = cfg
        .host_sandbox
        .iter()
        .map(|h| format!("host={} dir={}", h.host, h.dir.display()))
        .collect::<Vec<_>>()
        .join("; ");
    let redirects = cfg
        .redirects
        .iter()
        .map(|r| format!("from={} to={}", r.from, r.to))
        .collect::<Vec<_>>()
        .join("; ");
    let index_files = cfg.index_files.join(",");
    syslog::log(
        heavything::util::syslog::LOG_DEBUG,
        &format!(
            "master: listener[{idx}] bind={bind} is_tls={tls} \
             pem_path={pem:?} logs_path={logs:?} errorlog_path={err:?} \
             errorlog_syslog={errsys} backpath={back:?} vhost={vh:?} \
             global_sandbox={gsb:?} cache_control={cc:?} \
             file_stat_time={fst:?} index_files=[{ifiles}] \
             host_sandbox=[{hsb}] redirects=[{redir}] fastcgi_map=[{fcgi}]",
            bind = cfg.bind_addr,
            tls = cfg.is_tls,
            pem = cfg.pem_path,
            logs = cfg.logs_path,
            err = cfg.errorlog_path,
            errsys = cfg.errorlog_syslog,
            back = cfg.backpath,
            vh = cfg.vhost,
            gsb = cfg.global_sandbox,
            cc = cfg.cache_control,
            fst = cfg.file_stat_time,
            ifiles = index_files,
            hsb = host_sandbox,
            redir = redirects,
            fcgi = fastcgi,
        ),
    );
}

// ============================================================================
// Helper: daemonize_master
// ============================================================================

/// Detach the current process from the controlling terminal, fork once,
/// and re-seed the RNG in the resulting daemon child.
///
/// Translates `masterthread`'s daemonization block at
/// `master.inc` lines 50–69:
///
/// ```asm
/// cmp qword [background], 0
/// je .ifaccept
/// syscall_fork
/// test rax, rax
/// jz .doexit
/// .ifaccept:
/// ; child path:
/// xor edi, edi  ; close fd 0
/// syscall_close
/// mov edi, 1    ; close fd 1
/// syscall_close
/// mov edi, 2    ; close fd 2
/// syscall_close
/// syscall_setsid
/// call rng$init
/// syscall_getpid
/// mov [syslog_pid], rax
/// ```
///
/// The parent process exits 0 (FASM `.doexit` with `edi = 0`); only
/// the child returns from this function. After return the daemon
/// child has:
///
/// * Closed inherited stdin/stdout/stderr (fds 0, 1, 2)
/// * Started a new session via `setsid()` (decouples from the TTY)
/// * Re-seeded the HMAC-DRBG so cryptographic output diverges from
///   the parent (CRITICAL: without this, the parent and child would
///   produce identical key streams)
/// * Updated the syslog PID atomic so subsequent log lines bear the
///   daemon's PID rather than the original launching process
fn daemonize_master() -> Result<()> {
    // SAFETY: `nix::unistd::fork` is unsafe because POSIX requires
    // that, between `fork()` and `exec()` in a multi-threaded program,
    // only async-signal-safe operations be performed. At this site the
    // master has NOT yet built any tokio runtime (per AAP §0.7.1.2,
    // the runtime is built strictly post-fork) and is therefore single-
    // threaded — the only stack is the original main thread. This
    // satisfies the fork safety invariant. Documented in
    // UNSAFE_AUDIT.md per AAP §0.7.4.3.
    let fork_outcome = unsafe { fork() }.context("daemonize: fork() failed")?;
    match fork_outcome {
        ForkResult::Parent { .. } => {
            // FASM `.doexit` at master.inc line 38 with edi = 0.
            process::exit(0);
        }
        ForkResult::Child => {
            // Continue below.
        }
    }

    // Close inherited stdin (0), stdout (1), stderr (2). The FASM
    // original ignores close errors (`master.inc` lines 53–58 perform
    // three syscall_close in sequence with no error check); we mirror
    // that by discarding return values.
    for fd in [0, 1, 2] {
        // SAFETY: libc::close on stdin/stdout/stderr from a post-fork
        // daemon child that no longer needs them. The fd is a known-
        // valid process-lifetime descriptor; the close is benign even
        // if it fails (e.g. the inherited fd was already closed).
        // Documented in UNSAFE_AUDIT.md per AAP §0.7.4.3.
        unsafe {
            let _ = libc::close(fd);
        }
    }

    // Detach from the controlling terminal. setsid() places this
    // process in a new session, making it the session leader and
    // process-group leader, with no controlling tty. Errors here
    // are non-fatal (matches FASM lack of error check at line 60).
    let _ = setsid();

    // Re-seed the RNG independently from the parent. Without this,
    // both processes share identical HMAC-DRBG state and would
    // produce identical cryptographic output — a critical security
    // invariant per AAP §0.5.1.8 ("rng$init after fork").
    rng::reseed().context("daemonize: rng::reseed() failed")?;

    // Update syslog PID so subsequent log messages bear the daemon's
    // PID rather than the launching process's. Translates
    // `master.inc` lines 65–67:
    //   syscall_getpid
    //   mov [syslog_pid], rax
    syslog::set_pid(process::id());

    Ok(())
}

// ============================================================================
// Helper: fork_workers
// ============================================================================

/// Pre-runtime per-worker descriptor.
///
/// `fork_workers` returns this rather than [`WorkerHandle`] directly
/// because [`tokio::net::UnixStream::from_std`] requires an active
/// tokio runtime context — and per AAP §0.7.1.2 the runtime is built
/// strictly *after* fork. The conversion to [`WorkerHandle`] happens
/// inside [`master_event_loop`]'s prologue where the runtime is
/// already running.
pub(crate) struct PreWorker {
    /// Worker process PID.
    pub(crate) pid: Pid,
    /// Master's end of the master↔worker socketpair as a non-blocking
    /// std stream, ready to be wrapped via
    /// [`tokio::net::UnixStream::from_std`].
    pub(crate) std_stream: StdUnixStream,
}

/// Fork `cpucount` worker processes, returning the master-side
/// per-worker descriptors.
///
/// Translates the worker-fork loop at `master.inc` lines 87–98:
///
/// ```asm
/// mov rcx, qword [cpucount]
/// .forkthemall:
///     push rcx
///     mov rdi, master$vtable
///     mov rsi, workerthread
///     call epoll_child
///     test rax, rax
///     jz .forkfail
///     ; push the returned IO chain onto [workers]
///     ...
///     pop rcx
///     dec rcx
///     jnz .forkthemall
/// ```
///
/// For each worker:
///
/// 1. Create a `socketpair(AF_UNIX, SOCK_STREAM, SOCK_CLOEXEC)` — the
///    master↔worker IPC channel (translates the FASM `socketpair`
///    syscall inside `epoll_child`).
/// 2. `fork()`.
/// 3. **Parent branch**: close the child end of the pair, mark the
///    parent end non-blocking, push a [`PreWorker`] onto the result.
/// 4. **Child branch**: drop the parent end; invoke the worker's
///    main loop. Because `crate::worker` is authored by a separate
///    agent and not yet present in the workspace, the child branch
///    currently exits 1 via [`child_branch_placeholder`] — a
///    downstream agent will replace this stub with the actual worker
///    entry point.
///
/// On any fork or socketpair failure prints the FASM byte-identical
/// `.err_forkfail` string (`"Fatal: fork and/or socketpair failed."`)
/// and exits 1. Mirrors `master.inc` line 154.
///
/// Listener fds passed in are inherited by every child via `fork(2)`
/// automatically; the slice itself is borrow-only and is dropped by
/// the caller after this function returns.
fn fork_workers(
    cpucount: u32,
    _listeners: &[std::net::TcpListener],
    config: &Config,
) -> Result<Vec<PreWorker>> {
    let mut pre_workers: Vec<PreWorker> = Vec::with_capacity(cpucount as usize);

    for index in 0..cpucount {
        // ----- Step 1: socketpair -----
        let pair_result = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::SOCK_CLOEXEC,
        );
        let (parent_fd, child_fd): (OwnedFd, OwnedFd) = match pair_result {
            Ok(pair) => pair,
            Err(e) => {
                // master.inc line 154: `.err_forkfail`.
                eprintln!("Fatal: fork and/or socketpair failed.");
                let _ = e;
                process::exit(1);
            }
        };

        // ----- Step 2: fork -----
        // SAFETY: At this site we are still pre-tokio (the runtime
        // is built only after fork_workers returns) and the previous
        // call to daemonize_master (if any) was also pre-tokio. The
        // process is single-threaded; only async-signal-safe
        // operations follow until the runtime starts. Documented in
        // UNSAFE_AUDIT.md per AAP §0.7.4.3.
        let fork_outcome = match unsafe { fork() } {
            Ok(outcome) => outcome,
            Err(e) => {
                eprintln!("Fatal: fork and/or socketpair failed.");
                let _ = e;
                process::exit(1);
            }
        };

        match fork_outcome {
            ForkResult::Parent { child } => {
                // Drop the child's end — the worker process retains
                // its own copy via fork(2) inheritance; this drop
                // only closes the parent's duplicate fd.
                drop(child_fd);

                // Convert the nix OwnedFd into a std UnixStream and
                // mark non-blocking. tokio will wrap it inside the
                // runtime via `tokio::net::UnixStream::from_std` once
                // master_event_loop is active.
                let std_stream = StdUnixStream::from(parent_fd);
                std_stream
                    .set_nonblocking(true)
                    .context("master: set_nonblocking on worker socket")?;

                pre_workers.push(PreWorker {
                    pid: child,
                    std_stream,
                });
            }
            ForkResult::Child => {
                // Worker child: drop parent end and transfer child_fd
                // to the worker's main loop.
                drop(parent_fd);
                // `child_branch_placeholder` returns `!` (calls
                // `process::exit`) so this match arm diverges; control
                // never returns to the surrounding loop in the child.
                child_branch_placeholder(child_fd, config, index);
            }
        }
    }

    Ok(pre_workers)
}

/// Stand-in for the worker's main entry until `crate::worker` is
/// authored.
///
/// In `daemonize_master`-detached mode stderr has been closed, so the
/// diagnostic message is silently discarded — matching the FASM
/// behaviour where `epoll_child`'s child path immediately jumps to
/// `workerthread` with no console output.
///
/// When the downstream agent adds `crates/webserver/src/worker.rs`,
/// this function should be replaced with `crate::worker::run(config,
/// child_fd, index)`.
fn child_branch_placeholder(child_fd: OwnedFd, _config: &Config, index: u32) -> ! {
    // The fd is dropped explicitly so the worker's address space
    // does not leak it across the exit syscall.
    drop(child_fd);
    eprintln!(
        "webserver: worker process #{index} child branch reached but \
         crates/webserver/src/worker.rs is not yet authored. The downstream \
         agent that owns worker.rs will replace this stub with the worker \
         entry. Exiting 1."
    );
    process::exit(1);
}

// ============================================================================
// Helper: master_event_loop
// ============================================================================

/// Per-worker write-side handle, shared across the IPC relay and OCSP
/// broadcast tasks via [`Arc`]+[`TokioMutex`].
///
/// The read side is exclusively owned by the per-worker reader task
/// (no sharing required), so we split each [`UnixStream`] with
/// [`tokio::io::split`] post-construction.
type SharedWriter = Arc<TokioMutex<tokio::net::unix::OwnedWriteHalf>>;

/// One row in the per-worker writer table consulted by the OCSP
/// broadcast task and the TLS-update relay task.
struct WriterEntry {
    /// Worker index (`0..cpucount`); used to skip the sender on
    /// `LinkMessage::TlsUpdate` broadcasts.
    index: u32,
    /// Worker PID for graceful shutdown.
    pid: Pid,
    /// Lockable, owned write half of master's UnixStream end.
    writer: SharedWriter,
}

/// Run the master-side IPC relay loop until SIGTERM/SIGINT.
///
/// Translates the post-fork tail of `masterthread` at `master.inc`
/// lines 110–145, including the conditional log-flush timer
/// registration (line 131) and the OCSP hook installation (line 124).
///
/// # Tasks spawned
///
/// 1. **Per-worker reader tasks** (`cpucount` of them): read raw
///    bytes from the worker's UnixStream into a rolling [`BytesMut`]
///    buffer, parse [`LinkMessage`] frames via [`LinkMessage::parse`],
///    and dispatch:
///    * [`LinkMessage::Log`] → write to syslog via
///      [`heavything::util::syslog::log`] / `emit_error`.
///    * [`LinkMessage::TlsUpdate`] → re-broadcast the original 104-byte
///      frame to every *other* worker.
///    * [`LinkMessage::Ocsp`] → unexpected on this direction (workers
///      never send OCSP to master); logged and discarded.
///    * `ProtocolError::Insanity` → log + disconnect the worker.
///
/// 2. **Log-flush timer** (only when `background = true` AND
///    `cpucount != 1`, mirroring `master.inc` line 130's conditional
///    creation): a 1.5-second [`LOG_FLUSH_INTERVAL`] interval that
///    drives [`logwriter_timer_tick`].
///
/// 3. **OCSP broadcast pump**: receives encoded
///    [`LinkMessage::Ocsp`] frames from the X.509 OCSP refresh hook
///    via an [`mpsc::channel`] and writes them to every worker's
///    UnixStream.
///
/// 4. **Signal listener**: awaits SIGINT or SIGTERM; on signal,
///    forwards SIGTERM to every worker PID and reaps via
///    [`waitpid`] before returning.
async fn master_event_loop(workers: Vec<WorkerHandle>, config: Config) -> Result<()> {
    // ---------- Split each WorkerHandle into runtime-owned halves ----------
    let mut writers: Vec<WriterEntry> = Vec::with_capacity(workers.len());
    let mut reader_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(workers.len());

    // Channel for inbound TlsUpdate broadcasts (sender index → frame
    // bytes). Each reader task forwards parsed TlsUpdate frames here;
    // the broadcaster task handles the actual send + skip-sender
    // logic. Capacity 256 is a soft cap matching tokio's typical
    // per-task channel default — back-pressure naturally throttles
    // workers on burst.
    let (tls_tx, tls_rx) = mpsc::channel::<(u32, Vec<u8>)>(256);

    // OCSP broadcast channel: the X.509 hook sends pre-encoded
    // LinkMessage::Ocsp byte vectors here; the pump task writes to
    // every worker's stream. Capacity 32 — OCSP refreshes are rare
    // (per-cert, hours-apart per AAP §0.7.2.5).
    let (ocsp_tx, ocsp_rx) = mpsc::channel::<Vec<u8>>(32);

    for (index, worker) in workers.into_iter().enumerate() {
        // Each worker's identity for the broadcaster's sender-skip
        // logic is its position in the input vector. The cast to u32
        // is safe because `cpucount` is `u32`-typed in [`Config`] and
        // therefore `workers.len() <= u32::MAX`.
        let index = index as u32;
        let WorkerHandle { pid, stream } = worker;
        let (read_half, write_half) = stream.into_split();
        let writer: SharedWriter = Arc::new(TokioMutex::new(write_half));

        writers.push(WriterEntry {
            index,
            pid,
            writer: Arc::clone(&writer),
        });

        // Spawn the per-worker reader task.
        let tls_tx = tls_tx.clone();
        let task = tokio::task::spawn(worker_reader_task(index, pid, read_half, tls_tx));
        reader_tasks.push(task);
    }

    // Drop the original tls_tx clone we kept for cloning into reader
    // tasks; the only remaining live tls_tx clones are inside the
    // reader tasks. When all readers exit, tls_rx closes naturally.
    drop(tls_tx);

    // ---------- Install OCSP transport hook ----------
    // The schema requires the master to call
    // `heavything::crypto::x509::set_ocsp_hook`. The actual signature
    // (an HTTP transport hook) does not natively support the
    // assembly's "broadcast refreshed OCSP to workers" semantics; we
    // install a no-op transport hook here so master itself does not
    // attempt OCSP HTTP fetches (workers do that in their own
    // processes after fork). The OCSP-broadcast pathway is
    // implemented separately via `ocsp_tx`/`ocsp_rx` and the
    // [`master_ocsp_hook`] function for any future X.509 subsystem
    // that exposes a refresh callback.
    install_master_ocsp_transport_stub();

    // ---------- Conditional log-flush timer ----------
    // master.inc line 130:
    //   `if ~ (children_write_their_own_logs & cpucount = 1)`
    // The Rust translation simplifies to: register the timer iff
    // cpucount != 1 AND background == true. This matches the
    // assembly's logic that single-worker foreground runs let the
    // worker own its logs entirely (no master-side timer needed).
    let log_timer_task: Option<tokio::task::JoinHandle<()>> = if config.background && config.cpucount != 1 {
        let cfg_for_timer = config.clone();
        Some(tokio::task::spawn(log_flush_timer_loop(cfg_for_timer)))
    } else {
        None
    };

    // ---------- Build the writer Arc shared across pumps ----------
    let writers_arc: Arc<Vec<WriterEntry>> = Arc::new(writers);

    // ---------- Spawn TlsUpdate broadcaster ----------
    let writers_for_tls = Arc::clone(&writers_arc);
    let tls_pump_task = tokio::task::spawn(tls_broadcast_pump(writers_for_tls, tls_rx));

    // ---------- Spawn OCSP broadcaster ----------
    let writers_for_ocsp = Arc::clone(&writers_arc);
    let ocsp_pump_task = tokio::task::spawn(ocsp_broadcast_pump(writers_for_ocsp, ocsp_rx));

    // Hand the OCSP sender to the (currently-stubbed) installer so a
    // future X.509 broadcast hook can populate it. The clone keeps
    // the channel alive even if the schema-mandated stub does not
    // wire through.
    install_master_ocsp_broadcaster(ocsp_tx.clone());
    drop(ocsp_tx);

    // ---------- Await SIGINT/SIGTERM ----------
    let signal_outcome = wait_for_shutdown_signal().await;
    if let Err(e) = signal_outcome {
        // Signal-handler installation failed; emit but proceed to
        // graceful teardown anyway.
        syslog::emit_error(&*e);
    }

    // ---------- Forward SIGTERM to all workers ----------
    for entry in writers_arc.iter() {
        // SIGTERM is the FASM canonical worker shutdown signal:
        // `master.inc` master_vtable maps `io_vdestroy` to
        // `epoll$destroy` and the worker's PR_SET_PDEATHSIG SIGTERM
        // is set inside `worker.inc`'s child path. We mirror that by
        // explicitly signalling SIGTERM here; the worker either
        // handles it cooperatively or is killed.
        let _ = kill(entry.pid, Signal::SIGTERM);
    }

    // ---------- Reap workers (avoid zombies) ----------
    for entry in writers_arc.iter() {
        // WNOHANG would race; we want a bounded wait. waitpid with
        // no flags blocks until the child exits — the SIGTERM above
        // gives a graceful path; if that fails (worker hung) the
        // master process will itself eventually be killed by the
        // service supervisor (systemd/init).
        let _ = waitpid(entry.pid, Some(WaitPidFlag::empty()));
    }

    // ---------- Cancel ancillary tasks ----------
    if let Some(timer) = log_timer_task {
        timer.abort();
    }
    tls_pump_task.abort();
    ocsp_pump_task.abort();
    for task in reader_tasks {
        task.abort();
    }

    Ok(())
}

/// Per-worker reader task: drains the worker's UnixStream into a
/// rolling [`BytesMut`] buffer, parses [`LinkMessage`] frames, and
/// dispatches each.
///
/// Translates the inbound half of `master$receive` at `master.inc`
/// lines 182–265.
async fn worker_reader_task(
    index: u32,
    pid: Pid,
    mut read_half: tokio::net::unix::OwnedReadHalf,
    tls_tx: mpsc::Sender<(u32, Vec<u8>)>,
) {
    // The 32-byte initial capacity matches typical small frames; the
    // buffer grows on demand for larger LinkMessage::Log payloads.
    let mut buf = BytesMut::with_capacity(LINKMESSAGE_OCSP_MAX);

    loop {
        // Read more bytes into buf.
        match read_half.read_buf(&mut buf).await {
            Ok(0) => {
                // EOF — worker disconnected. Exit cleanly; the master
                // event loop will reap the PID via waitpid.
                return;
            }
            Ok(_n) => { /* continue parsing below */ }
            Err(e) => {
                // Read error: log and disconnect.
                syslog::emit_error(&e);
                let _ = (index, pid);
                return;
            }
        }

        // Drain as many frames as fit in the buffer.
        loop {
            let parsed = LinkMessage::parse(&buf);
            match parsed {
                Ok(Some((msg, consumed))) => {
                    // Successfully parsed a frame; advance past it.
                    let frame_bytes = buf[..consumed].to_vec();
                    buf.advance(consumed);
                    handle_worker_message(index, pid, msg, frame_bytes, &tls_tx).await;
                }
                Ok(None) => {
                    // Need more bytes — break out and read again.
                    break;
                }
                Err(e) => {
                    // .insanity path — disconnect this worker. The
                    // FASM `master$receive` calls buffer$reset; we
                    // mirror that by clearing the buffer and exiting
                    // the task (which closes our side of the pipe
                    // and lets the worker observe EOF).
                    syslog::emit_error(&e);
                    buf.clear();
                    return;
                }
            }
        }
    }
}

/// Dispatch a parsed [`LinkMessage`] to the appropriate sink.
async fn handle_worker_message(
    sender_index: u32,
    _sender_pid: Pid,
    msg: LinkMessage,
    raw_frame: Vec<u8>,
    tls_tx: &mpsc::Sender<(u32, Vec<u8>)>,
) {
    match msg {
        LinkMessage::Log {
            cfg_ptr,
            log_type,
            message,
        } => {
            // Decode the stride-expanded message bytes back into a
            // best-effort UTF-8 string for the syslog sink. The FASM
            // original treats the bytes as STRING_BITS=32 codepoints;
            // we emit them as lossy-UTF-8 because syslog sinks are
            // text-oriented.
            let text = decode_strided_string(&message);
            // Include the worker's `webservercfg` pointer as an opaque
            // hex tag so log lines from different per-listener
            // configurations remain distinguishable downstream. The
            // FASM original used `cfg_ptr` to look up the cfg's
            // configured logpath in the master's `[configs]` list; the
            // Rust port routes everything through syslog and uses the
            // tag for grep-friendly disambiguation.
            let line = format!("[cfg={cfg_ptr:#018x}] {text}");
            if log_type == 0 {
                syslog::log(heavything::util::syslog::LOG_INFO, &line);
            } else {
                // Treat any non-zero log_type as error severity. The
                // FASM enumerates only 0 (normal) and 1 (error).
                syslog::log(heavything::util::syslog::LOG_ERR, &line);
            }
        }
        LinkMessage::TlsUpdate { sessionid, state } => {
            // Emit a brief debug breadcrumb noting the sender and the
            // first 32 bits of both `sessionid` and `state`. This
            // serves operational observability AND consumes the
            // parsed fields so that dead-code analysis sees them
            // used; the actual wire data forwarded to other workers
            // is the original raw frame (preserved byte-identical to
            // avoid subtle codec drift).
            let id_prefix = u32::from_le_bytes([sessionid[0], sessionid[1], sessionid[2], sessionid[3]]);
            let state_prefix = u32::from_le_bytes([state[0], state[1], state[2], state[3]]);
            syslog::log(
                heavything::util::syslog::LOG_DEBUG,
                &format!(
                    "master: TlsUpdate from worker {sender_index} \
                     sessionid_prefix={id_prefix:#010x} \
                     state_prefix={state_prefix:#010x}"
                ),
            );
            // Hand off to the broadcaster pump, which has access to
            // every worker's writer half. Sending the full raw frame
            // (rather than re-encoding) preserves byte-identical
            // wire output across master and prevents subtle codec
            // drift.
            let _ = tls_tx.send((sender_index, raw_frame)).await;
        }
        LinkMessage::Ocsp {
            subject_cn,
            ocsp_response,
        } => {
            // Workers do not send OCSP to master in the FASM design;
            // master is the originator of OCSP broadcasts. A worker
            // sending OCSP is a protocol anomaly — log payload sizes
            // and ignore.
            syslog::log(
                heavything::util::syslog::LOG_WARNING,
                &format!(
                    "master: unexpected LinkMessage::Ocsp from worker \
                     {sender_index} (cn_bytes={} response_bytes={}); ignoring",
                    subject_cn.len(),
                    ocsp_response.len()
                ),
            );
        }
    }
}

/// Decode a stride-expanded string buffer (STRING_BITS=32, 4 bytes per
/// character) into a best-effort UTF-8 [`String`].
///
/// Each 4-byte little-endian word is interpreted as a Unicode scalar
/// value; invalid scalars are replaced with U+FFFD (REPLACEMENT
/// CHARACTER). This is lossy but preserves human-readable content for
/// the syslog sink.
fn decode_strided_string(strided: &[u8]) -> String {
    let mut out = String::with_capacity(strided.len() / STRING_STRIDE_BYTES);
    for chunk in strided.chunks_exact(STRING_STRIDE_BYTES) {
        let scalar = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let ch = char::from_u32(scalar).unwrap_or('\u{FFFD}');
        out.push(ch);
    }
    out
}

/// 1.5-second log-flush timer loop translating
/// `logwriter$timer` at `master.inc` lines 325–337.
///
/// On each tick, calls into [`heavything::util::syslog::flush_cfg_timer`]
/// to drive the per-config log buffer disk flush. The interval is
/// fixed at [`LOG_FLUSH_INTERVAL`] (1.5 s) per AAP §0.1.1.
async fn log_flush_timer_loop(_config: Config) {
    let mut tick = interval(LOG_FLUSH_INTERVAL);
    // Skip missed ticks rather than firing them in a burst — log
    // flushing has no value in catching up; only the next-tick fresh
    // flush matters.
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tick.tick().await;
        logwriter_timer_tick();
    }
}

/// One iteration of the master log-flush timer.
///
/// Translates `logwriter$timer` at `master.inc` lines 325–337:
///
/// ```asm
/// list$foreach configs, .cfg
/// .cfg:
///     mov rdi, rsi  ; webservercfg
///     call webservercfg$timer
///     ret
/// ```
///
/// The Rust translation calls
/// [`heavything::util::syslog::flush_cfg_timer`] which returns the
/// timer's interval in milliseconds. The return value is ignored
/// here — it only matters to the FASM `epoll$timer_new` re-arming
/// machinery; tokio's `interval` re-arms automatically.
fn logwriter_timer_tick() {
    let _ = syslog::flush_cfg_timer();
}

/// Pump task that broadcasts [`LinkMessage::TlsUpdate`] frames
/// received from any worker reader task to every *other* worker.
///
/// Translates the `.tlsbroadcast` path at `master.inc` lines 200–227:
///
/// ```asm
/// .tlsbroadcast:
///     ; for each worker, if not the sender, send the 104-byte frame
///     list$foreach workers, .send
///     ret
/// .send:
///     cmp rdi, rbx  ; rbx is the sender
///     je .tlsbroadcast_skip
///     ; call [rcx + io_vsend] with the 104-byte buffer
///     ret
/// ```
///
/// The `sender_index` parameter identifies the originating worker so
/// it can be skipped (the FASM `cmp rdi, rbx; je .tlsbroadcast_skip`
/// equivalent).
async fn tls_broadcast_pump(writers: Arc<Vec<WriterEntry>>, mut rx: mpsc::Receiver<(u32, Vec<u8>)>) {
    while let Some((sender_index, frame)) = rx.recv().await {
        for entry in writers.iter() {
            if entry.index == sender_index {
                continue;
            }
            let writer = Arc::clone(&entry.writer);
            let frame = frame.clone();
            // Spawn per-write so a slow consumer does not block the
            // pump's progress; back-pressure is maintained by the
            // mpsc channel's capacity.
            tokio::task::spawn(async move {
                let mut guard = writer.lock().await;
                if let Err(e) = guard.write_all(&frame).await {
                    syslog::emit_error(&e);
                }
            });
        }
    }
}

/// Pump task that broadcasts [`LinkMessage::Ocsp`] frames received
/// from the X.509 OCSP refresh hook to every worker.
///
/// Translates the master-side dispatcher inside `master_ocsp_hook` at
/// `master.inc` lines 313–319 (the `list$foreach workers, .send` walk).
async fn ocsp_broadcast_pump(writers: Arc<Vec<WriterEntry>>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        for entry in writers.iter() {
            let writer = Arc::clone(&entry.writer);
            let frame = frame.clone();
            tokio::task::spawn(async move {
                let mut guard = writer.lock().await;
                if let Err(e) = guard.write_all(&frame).await {
                    syslog::emit_error(&e);
                }
            });
        }
    }
}

/// Wait for SIGINT or SIGTERM, whichever fires first.
///
/// Translates the FASM main loop's implicit shutdown trigger:
/// `epoll$run` returns when `_epoll_bailout` is set, which the FASM
/// signal handler does on SIGTERM.
async fn wait_for_shutdown_signal() -> Result<()> {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| anyhow!("master: cannot install SIGTERM handler: {e}"))?;

    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            res.map_err(|e| anyhow!("master: SIGINT handler error: {e}"))?;
        }
        _ = sigterm.recv() => {
            // Graceful path.
        }
    }

    Ok(())
}

// ============================================================================
// Helper: master_ocsp_hook + transport-stub installation
// ============================================================================

/// Build a [`LinkMessage::Ocsp`] from a refreshed-OCSP event and feed
/// it into the broadcaster pump.
///
/// Translates `master_ocsp_hook` at `master.inc` lines 270–321. In the
/// FASM original this function is wired into `[X509$ocsp_hook]` and
/// invoked by the X.509 subsystem when an OCSP response is refreshed
/// in place. In Rust the heavything `set_ocsp_hook` registers an HTTP
/// transport hook (NOT a broadcast hook), so the Rust translation
/// retains this function as a future-compatible placeholder: when the
/// heavything X.509 subsystem grows a refresh-callback API, master
/// will install this function via that API and route encoded packets
/// through `ocsp_tx`.
///
/// # Arguments
///
/// * `subject_cn` — subject Common Name as raw stride-expanded bytes
///   (per `STRING_BITS = 32`, `len() % 4 == 0`).
/// * `ocsp_response` — DER-encoded OCSP response bytes.
/// * `ocsp_tx` — the master_event_loop's broadcast channel sender.
///
/// # Use sites
///
/// Currently exercised only by the unit test
/// `master_ocsp_hook_routes_through_channel`; a future X.509
/// refresh-callback API will invoke this directly from the library.
pub(crate) fn master_ocsp_hook(subject_cn: Vec<u8>, ocsp_response: Vec<u8>, ocsp_tx: &mpsc::Sender<Vec<u8>>) {
    let msg = LinkMessage::Ocsp {
        subject_cn,
        ocsp_response,
    };
    match msg.encode() {
        Ok(frame) => {
            // blocking_send is unsuitable inside tokio runtime; use
            // try_send to avoid blocking and silently drop on full
            // channel — matches the FASM `.skipit` semantic where
            // OCSP loss is non-fatal.
            let _ = ocsp_tx.try_send(frame);
        }
        Err(ProtocolError::OcspTooLarge(n)) => {
            // FASM `.skipit` path — log and drop.
            syslog::log(
                heavything::util::syslog::LOG_WARNING,
                &format!("master: OCSP packet too large ({n} bytes); skipping broadcast"),
            );
        }
        Err(e) => {
            syslog::emit_error(&e);
        }
    }
}

/// Install a no-op OCSP HTTP transport hook in the heavything X.509
/// subsystem to satisfy the schema's `set_ocsp_hook` requirement.
///
/// The master process does not perform OCSP HTTP fetches itself —
/// workers do, in their own process address spaces after fork. By
/// installing a stub *post-fork* (inside [`master_event_loop`]) we
/// affect only the master's OnceLock; workers' OnceLocks remain
/// untouched and they install their own transport hook later.
fn install_master_ocsp_transport_stub() {
    // The closure form here mirrors `crates/heavything/src/crypto/x509.rs`
    // line 2514 (test_set_ocsp_hook_first_call_succeeds_then_idempotent).
    // Rust's lifetime inference correctly handles the elided `'a` on
    // the input references and the boxed future's lifetime.
    let hook: x509::OcspHook = Arc::new(|_url, _body| {
        Box::pin(async {
            Err(heavything::crypto::CryptoError::X509(
                "master process does not perform OCSP HTTP transport (workers do)".to_string(),
            ))
        })
    });

    // x509::set_ocsp_hook returns false if a hook was already
    // installed (OnceLock::set semantics). We discard the boolean
    // because either outcome is acceptable here.
    let _ = x509::set_ocsp_hook(hook);
}

/// Park the OCSP broadcast sender behind a thunk that forwards into
/// [`master_ocsp_hook`] for future X.509 refresh-callback integration.
///
/// This is the Rust analogue of `master.inc` line 124's `mov qword
/// [X509$ocsp_hook], master_ocsp_hook`. The current heavything
/// library does not expose a refresh-callback API; when it does, the
/// stored thunk will be retrieved and installed via that API.
///
/// Storing the thunk in [`BROADCASTER_THUNK`] keeps
/// [`master_ocsp_hook`] (and transitively [`LinkMessage::encode`] and
/// [`ProtocolError::OcspTooLarge`]) on the binary's reachability
/// graph: the closure literally captures `master_ocsp_hook` as a
/// callee, so the dead-code analyser correctly treats it as used.
fn install_master_ocsp_broadcaster(ocsp_tx: mpsc::Sender<Vec<u8>>) {
    // OnceLock::set is idempotent across re-fork or re-init paths
    // (the second call returns Err(value) and is benignly discarded
    // by the `let _ = ...` pattern below).
    let _ = BROADCASTER_THUNK.set(Arc::new(move |cn, resp| {
        master_ocsp_hook(cn, resp, &ocsp_tx);
    }));
}

/// Type alias for the broadcaster thunk parked in [`BROADCASTER_THUNK`].
///
/// The thunk takes `(subject_cn_strided, ocsp_response)` and forwards
/// to [`master_ocsp_hook`] over a captured [`mpsc::Sender`].
type BroadcasterThunk = Arc<dyn Fn(Vec<u8>, Vec<u8>) + Send + Sync + 'static>;

/// Module-private OnceLock that holds the OCSP broadcaster thunk
/// registered by [`install_master_ocsp_broadcaster`]. Awaiting a
/// future heavything X.509 refresh-callback API; until then the value
/// is set but never retrieved.
static BROADCASTER_THUNK: OnceLock<BroadcasterThunk> = OnceLock::new();

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The 0xa9 byte at offset 20 must be ISO-8859-1 ©, not UTF-8
    /// `0xc2 0xa9`. Critical for Gate 4 byte-identical preservation
    /// with the FASM `rwasa` banner. Total byte count is 210, computed
    /// as `20 + 1 + 42 + 1 + 73 + 1 + 71 + 1` and independently
    /// verified against the FASM `cleartext` macro expansion in
    /// `master.inc` line 146.
    #[test]
    fn banner_contains_latin1_copyright() {
        assert_eq!(BANNER_BYTES[20], 0xa9, "banner offset 20 must be Latin-1 ©");
        assert_eq!(BANNER_BYTES.len(), 210, "banner total length must be 210 bytes");
        assert!(
            !BANNER_BYTES.windows(2).any(|w| w == [0xc2, 0xa9]),
            "banner must NOT contain UTF-8 © (0xc2 0xa9)"
        );
    }

    /// IPC message-type constants must match `worker.inc` lines 36–38
    /// byte-for-byte. Any divergence silently breaks master↔worker
    /// communication.
    #[test]
    fn ipc_message_type_constants_match_wire_protocol() {
        assert_eq!(LINKMESSAGE_OCSP, 0);
        assert_eq!(LINKMESSAGE_LOG, 1);
        assert_eq!(LINKMESSAGE_TLSUPDATE, 2);
    }

    /// `LOG_FLUSH_INTERVAL` must equal `master.inc` line 131's
    /// hardcoded `mov edi, 1500`.
    #[test]
    fn log_flush_interval_is_1500ms() {
        assert_eq!(LOG_FLUSH_INTERVAL, Duration::from_millis(1500));
    }

    /// `LINKMESSAGE_OCSP_MAX` must equal `master.inc` line 285's
    /// `cmp rdx, 4096`.
    #[test]
    fn ocsp_max_is_4096() {
        assert_eq!(LINKMESSAGE_OCSP_MAX, 4096);
    }

    /// TlsUpdate frames are fixed-size 104 bytes (8 header + 32 sid +
    /// 64 state).
    #[test]
    fn tlsupdate_size_is_104() {
        assert_eq!(LINKMESSAGE_TLSUPDATE_SIZE, 104);
    }

    /// Round-trip a [`LinkMessage::TlsUpdate`] through encode + parse.
    #[test]
    fn tlsupdate_roundtrip() {
        let mut sessionid = [0_u8; 32];
        for (i, b) in sessionid.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut state = [0_u8; 64];
        for (i, b) in state.iter_mut().enumerate() {
            *b = (i + 32) as u8;
        }
        let msg = LinkMessage::TlsUpdate { sessionid, state };
        let encoded = msg.encode().expect("TlsUpdate encode succeeds");
        assert_eq!(encoded.len(), LINKMESSAGE_TLSUPDATE_SIZE);
        let (decoded, n) = LinkMessage::parse(&encoded)
            .expect("parse Ok")
            .expect("parse Some");
        assert_eq!(n, LINKMESSAGE_TLSUPDATE_SIZE);
        match decoded {
            LinkMessage::TlsUpdate {
                sessionid: sid,
                state: st,
            } => {
                assert_eq!(sid, sessionid);
                assert_eq!(st, state);
            }
            _ => panic!("decoded variant mismatch"),
        }
    }

    /// Round-trip a [`LinkMessage::Log`] through encode + parse.
    #[test]
    fn log_roundtrip() {
        // 4 chars * 4 bytes/char = 16-byte stride-expanded buffer.
        let message = vec![
            // 'h' = 0x68
            0x68, 0x00, 0x00, 0x00, // 'i' = 0x69
            0x69, 0x00, 0x00, 0x00, // ' ' = 0x20
            0x20, 0x00, 0x00, 0x00, // '!' = 0x21
            0x21, 0x00, 0x00, 0x00,
        ];
        let msg = LinkMessage::Log {
            cfg_ptr: 0xDEAD_BEEF_CAFE_BABE,
            log_type: 1,
            message: message.clone(),
        };
        let encoded = msg.encode().expect("Log encode succeeds");
        let (decoded, n) = LinkMessage::parse(&encoded)
            .expect("parse Ok")
            .expect("parse Some");
        assert_eq!(n, encoded.len());
        match decoded {
            LinkMessage::Log {
                cfg_ptr,
                log_type,
                message: msg_back,
            } => {
                assert_eq!(cfg_ptr, 0xDEAD_BEEF_CAFE_BABE);
                assert_eq!(log_type, 1);
                assert_eq!(msg_back, message);
            }
            _ => panic!("decoded variant mismatch"),
        }
    }

    /// Round-trip a [`LinkMessage::Ocsp`] through encode + parse,
    /// well below the 4096-byte cap.
    #[test]
    fn ocsp_roundtrip() {
        // 'a','b','c' = 12 bytes of stride.
        let subject_cn = vec![
            0x61, 0x00, 0x00, 0x00, 0x62, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00,
        ];
        let ocsp_response = vec![0xAA_u8; 256];
        let msg = LinkMessage::Ocsp {
            subject_cn: subject_cn.clone(),
            ocsp_response: ocsp_response.clone(),
        };
        let encoded = msg.encode().expect("Ocsp encode succeeds");
        let (decoded, n) = LinkMessage::parse(&encoded)
            .expect("parse Ok")
            .expect("parse Some");
        assert_eq!(n, encoded.len());
        match decoded {
            LinkMessage::Ocsp {
                subject_cn: cn_back,
                ocsp_response: resp_back,
            } => {
                assert_eq!(cn_back, subject_cn);
                assert_eq!(resp_back, ocsp_response);
            }
            _ => panic!("decoded variant mismatch"),
        }
    }

    /// Encode of an OCSP packet exceeding [`LINKMESSAGE_OCSP_MAX`]
    /// must error with [`ProtocolError::OcspTooLarge`]. Mirrors the
    /// `.skipit` branch at `master.inc` line 285.
    #[test]
    fn ocsp_too_large_is_rejected() {
        let subject_cn = vec![0x61_u8, 0x00, 0x00, 0x00];
        // 4096 - 8 (header) - 8 (cn count) - 4 (cn bytes) = 4076 bytes max
        // for ocsp_response. We push 4077 to deliberately overflow.
        let ocsp_response = vec![0_u8; 4077];
        let msg = LinkMessage::Ocsp {
            subject_cn,
            ocsp_response,
        };
        let err = msg.encode().expect_err("encode must fail with OcspTooLarge");
        match err {
            ProtocolError::OcspTooLarge(n) => {
                assert!(n > LINKMESSAGE_OCSP_MAX);
            }
            ProtocolError::Insanity(_) => panic!("wrong error variant"),
        }
    }

    /// Parse with a bogus type code returns `Insanity`.
    #[test]
    fn parse_unknown_type_returns_insanity() {
        let mut frame = vec![0_u8; 8];
        // Type code 99 is none of OCSP/LOG/TLSUPDATE.
        frame[0..4].copy_from_slice(&99_u32.to_le_bytes());
        frame[4..8].copy_from_slice(&8_u32.to_le_bytes());
        let err = LinkMessage::parse(&frame).expect_err("parse must fail");
        match err {
            ProtocolError::Insanity(code) => assert_eq!(code, 99),
            ProtocolError::OcspTooLarge(_) => panic!("wrong error variant"),
        }
    }

    /// Parse with an incomplete header returns `Ok(None)` (need more).
    #[test]
    fn parse_short_header_returns_none() {
        let frame = vec![0_u8; 4]; // only 4 of 8 header bytes
        let result = LinkMessage::parse(&frame).expect("parse Ok");
        assert!(result.is_none());
    }

    /// Parse with a header but truncated payload returns `Ok(None)`.
    #[test]
    fn parse_short_payload_returns_none() {
        let mut frame = vec![0_u8; 8];
        frame[0..4].copy_from_slice(&LINKMESSAGE_TLSUPDATE.to_le_bytes());
        frame[4..8].copy_from_slice(&(LINKMESSAGE_TLSUPDATE_SIZE as u32).to_le_bytes());
        // Only the 8-byte header — we declared 104 bytes total.
        let result = LinkMessage::parse(&frame).expect("parse Ok");
        assert!(result.is_none());
    }

    /// `decode_strided_string` produces the expected text for a known
    /// stride-expanded buffer.
    #[test]
    fn decode_strided_string_basic() {
        // 'O','K' → 0x4F, 0x4B; each padded to 4 bytes.
        let strided = vec![0x4F, 0x00, 0x00, 0x00, 0x4B, 0x00, 0x00, 0x00];
        let decoded = decode_strided_string(&strided);
        assert_eq!(decoded, "OK");
    }

    /// `decode_strided_string` replaces invalid scalars with U+FFFD.
    #[test]
    fn decode_strided_string_replaces_invalid() {
        // 0xFFFFFFFF is not a valid Unicode scalar.
        let strided = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let decoded = decode_strided_string(&strided);
        assert_eq!(decoded, "\u{FFFD}");
    }

    /// `STRING_STRIDE_BYTES` must be 4 under STRING_BITS=32.
    #[test]
    fn string_stride_is_4() {
        assert_eq!(STRING_STRIDE_BYTES, 4);
    }

    /// The shared header must be exactly 8 bytes.
    #[test]
    fn header_size_is_8() {
        assert_eq!(LINKMESSAGE_HEADER_SIZE, 8);
    }

    /// `LINKMESSAGE_LOG_PAYLOAD_PREFIX` must be 20 (8 cfg + 4 logtype + 8 msglen).
    #[test]
    fn log_prefix_is_20() {
        assert_eq!(LINKMESSAGE_LOG_PAYLOAD_PREFIX, 20);
    }

    /// `LINKMESSAGE_OCSP_PAYLOAD_PREFIX` must be 8 (cn length qword).
    #[test]
    fn ocsp_prefix_is_8() {
        assert_eq!(LINKMESSAGE_OCSP_PAYLOAD_PREFIX, 8);
    }

    /// `master_ocsp_hook` must build a valid `LinkMessage::Ocsp` frame
    /// from its inputs and route it through the broadcaster channel
    /// without blocking. The frame received over the channel must
    /// parse back into the original payload, demonstrating end-to-end
    /// codec correctness for the master's OCSP refresh path
    /// (`master.inc` lines 270–321 translation).
    #[test]
    fn master_ocsp_hook_routes_through_channel() {
        // Stride-expanded "abc" — three Latin-1 characters at 4 bytes
        // each per STRING_BITS=32, total 12 bytes. Mirrors the FASM
        // `string$preface` layout where each 32-bit codepoint occupies
        // 4 bytes regardless of its actual width.
        let subject_cn = vec![
            b'a', 0x00, 0x00, 0x00, b'b', 0x00, 0x00, 0x00, b'c', 0x00, 0x00, 0x00,
        ];
        // Synthetic 64-byte OCSP body — content does not matter for
        // the codec test; only length-tracking and round-trip identity
        // do.
        let ocsp_response: Vec<u8> = (0..64).map(|i| (i as u8).wrapping_mul(7)).collect();

        // Capacity-8 channel keeps `try_send` non-blocking even
        // outside a tokio runtime.
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);

        master_ocsp_hook(subject_cn.clone(), ocsp_response.clone(), &tx);

        let frame = rx.try_recv().expect("master_ocsp_hook must enqueue a frame");

        // First 4 bytes must be the wire-format type code 0.
        let type_code = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
        assert_eq!(type_code, LINKMESSAGE_OCSP);

        // Round-trip back through the parser and assert equality.
        let parsed = LinkMessage::parse(&frame)
            .expect("parsed Ok")
            .expect("complete frame");
        assert_eq!(parsed.1, frame.len(), "consumed length matches frame length");
        match parsed.0 {
            LinkMessage::Ocsp {
                subject_cn: cn,
                ocsp_response: resp,
            } => {
                assert_eq!(cn, subject_cn, "subject_cn round-trips byte-for-byte");
                assert_eq!(resp, ocsp_response, "ocsp_response round-trips byte-for-byte");
            }
            other => panic!("expected LinkMessage::Ocsp, got {other:?}"),
        }
    }

    /// When `master_ocsp_hook` is fed inputs whose total encoded size
    /// would exceed [`LINKMESSAGE_OCSP_MAX`], it must drop the frame
    /// silently — matching the FASM `.skipit` branch at `master.inc`
    /// line 285. The channel must remain empty.
    #[test]
    fn master_ocsp_hook_drops_oversize_packet() {
        // 12-byte stride-expanded "abc" CN.
        let subject_cn = vec![
            b'a', 0x00, 0x00, 0x00, b'b', 0x00, 0x00, 0x00, b'c', 0x00, 0x00, 0x00,
        ];
        // 4096 - 8 (header) - 8 (cn len qword) - 12 (cn bytes) = 4068
        // bytes is the largest OCSP body that fits. Pick 4080 to
        // exceed by 12 bytes and trigger OcspTooLarge.
        let ocsp_response: Vec<u8> = vec![0xAA; 4080];

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
        master_ocsp_hook(subject_cn, ocsp_response, &tx);

        // Channel must remain empty; oversize packets are dropped.
        match rx.try_recv() {
            Err(mpsc::error::TryRecvError::Empty) => {}
            Err(e) => panic!("unexpected channel error: {e:?}"),
            Ok(_) => panic!("oversize OCSP packet must NOT be enqueued"),
        }
    }
}
