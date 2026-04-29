// HeavyThing x86_64 assembly language library — Rust translation.
//
// Rust translation © 2026, licensed under GPL-3.0-or-later.
//
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

//! Fork-and-socketpair child process management + typed master↔worker IPC.
//!
//! This module is the Rust translation of the FASM assembly source
//! `epoll_child.inc` (168 lines in the original). It delivers two layered
//! APIs per AAP §0.4.1 and §0.5.1.4:
//!
//! 1. **[`spawn_child`]** — a low-level one-shot `fork(2)`+`socketpair(2)`
//!    helper that creates a child process sharing an `AF_UNIX SOCK_STREAM`
//!    channel with the parent. The child installs `PR_SET_PDEATHSIG`
//!    (`SIGTERM`) as its very first post-fork action, matching the
//!    assembly baseline at `epoll_child.inc:110–113`. The child PID is
//!    registered in a process-wide registry so [`killall_children`] can
//!    deliver `SIGTERM` to every live child at parent exit, replacing the
//!    assembly's `epoll_child$killall` entry-point.
//!
//! 2. **[`ChildProcess`]** + **[`LinkMessage`]** — the typed IPC surface.
//!    The master↔worker relay has **exactly three** message types per
//!    AAP §0.1.1:
//!    * [`LinkMessage::Log`] — worker→master log record (master flushes
//!      log records at 1.5 s intervals on behalf of all workers, matching
//!      the assembly logflush timer).
//!    * [`LinkMessage::TlsUpdate`] — master→worker session-cache
//!      broadcast so every worker observes new TLS session entries.
//!    * [`LinkMessage::Ocsp`] — master→worker freshly-fetched OCSP
//!      response for stapling (7200 s refresh, 300 s retry per
//!      `tls.inc`).
//!
//! # Architectural diagram
//!
//! ```text
//!                     spawn_child(child_main)
//!                             │
//!                             ▼
//!                 ┌──────────────────────┐
//!                 │ socketpair(AF_UNIX,  │  ← returns (OwnedFd, OwnedFd)
//!                 │   SOCK_STREAM,       │    in nix 0.29
//!                 │   SOCK_CLOEXEC)      │
//!                 └──────────┬───────────┘
//!                            │
//!                     unsafe fork()  ◄── UNSAFE SITE #1
//!                            │
//!              ┌─────────────┴──────────────┐
//!              ▼                            ▼
//!      ForkResult::Parent            ForkResult::Child
//!              │                            │
//!     close(child_fd)             set_pdeathsig(SIGTERM)
//!              │                            │
//!     from_raw_fd(parent_fd)      close(parent_fd)
//!     (UNSAFE SITE #2)                     │
//!              │                   from_raw_fd(child_fd)
//!     set_nonblocking(true)       (UNSAFE SITE #3)
//!              │                            │
//!     UnixStream::from_std        child_main(std_stream)
//!              │                            │
//!     register_child_pid(pid)      std::process::exit(0)
//!              │
//!     Ok(ChildProcess { pid,
//!         parent_socket })
//! ```
//!
//! # Wire format (TLV, hand-rolled)
//!
//! Each [`LinkMessage`] encodes to the following byte sequence:
//!
//! ```text
//!   u8  tag       : 1 = Log, 2 = TlsUpdate, 3 = Ocsp
//!   u32 body_len  : little-endian; length of body bytes that follow
//!   [body_len bytes of variant body]
//!
//!   body for Log:
//!     u64 timestamp_ms  (little-endian)
//!     u8  severity      (3=Err, 4=Warning, 6=Info, 7=Debug)
//!     u16 facility_len  (little-endian; 0xFFFF = facility is None,
//!                        any other value is the UTF-8 byte length
//!                        of a Some(facility) — including 0 for
//!                        Some(""), so that None and Some("") round
//!                        trip losslessly)
//!     <facility_len bytes of UTF-8 facility name, present iff
//!      facility_len != 0xFFFF; may be zero-length when the
//!      facility is Some("")>
//!     u32 msg_len       (little-endian)
//!     <msg_len bytes of message payload>
//!
//!   body for TlsUpdate:
//!     u16 sid_len       (little-endian)
//!     <sid_len bytes of session id>
//!     u32 val_len       (little-endian)
//!     <val_len bytes of encrypted session value>
//!     u64 expires_ms    (little-endian)
//!
//!   body for Ocsp:
//!     u32 der_len       (little-endian)
//!     <der_len bytes of DER-encoded OCSP response>
//!     u64 fetched_ms    (little-endian)
//! ```
//!
//! [`ChildProcess::send_message`] prepends an outer `u32` little-endian
//! framing length to the encoded buffer before writing to the
//! socket, giving the full on-wire layout:
//!
//! ```text
//!   u32 frame_len  (LE)  ← outer framing added by send_message
//!   u8  tag
//!   u32 body_len   (LE)
//!   <body bytes>
//! ```
//!
//! [`ChildProcess::recv_message`] strips the outer framing, reads the
//! next `frame_len` bytes, and hands that slice to
//! [`LinkMessage::decode`]. Frames larger than [`MAX_FRAME_SIZE`]
//! (16 MiB) are rejected with [`NetError::Io`] (kind
//! [`std::io::ErrorKind::InvalidData`]) to prevent denial-of-service
//! via oversized allocations.
//!
//! # `unsafe` audit
//!
//! This module contributes **three** `unsafe` blocks to the crate's
//! [`UNSAFE_AUDIT.md`](../../../../UNSAFE_AUDIT.md) tally, all in
//! [`spawn_child`]:
//!
//! | # | Site                             | Category                   |
//! |---|----------------------------------|----------------------------|
//! | 1 | `unsafe { fork() }`              | FFI-nix                    |
//! | 2 | `UnixStream::from_raw_fd(parent)`| FFI-nix (fd construction)  |
//! | 3 | `UnixStream::from_raw_fd(child)` | FFI-nix (fd construction)  |
//!
//! Each site has a `// SAFETY:` comment explaining the invariants,
//! a dedicated entry in `UNSAFE_AUDIT.md`, and a corresponding test
//! in `crates/heavything/tests/ffi_boundary.rs` per AAP §0.7.4.4.
//!
//! # Caller contract for `child_main`
//!
//! Per AAP §0.7.4.2, the child process MUST re-seed the cryptographic
//! RNG (`crate::crypto::rng::reseed()`) before performing any
//! cryptographic operation, because `fork()` leaves parent and child
//! with identical RNG state. The Rust port does not perform this
//! re-seed inside [`spawn_child`] itself because the RNG module lives
//! in a different subsystem; the contract is imposed on `child_main`
//! which is typically the first thing a worker crate (e.g.,
//! `webserver::worker`) does in its `fn main`. Additionally, the
//! child process must build its own `tokio::runtime::Runtime` via
//! [`crate::net::runtime::build()`](../runtime/index.html) — the
//! parent's runtime is NOT usable post-fork.
//!
//! # Lifetime & cleanup
//!
//! Every successful [`spawn_child`] call in the parent registers the
//! child PID in a process-wide [`std::sync::OnceLock`]-initialised
//! [`std::sync::Mutex`]-protected [`Vec`]. The parent SHOULD call
//! [`install_cleanup_handlers`] once after all workers have been
//! spawned; this installs `SIGTERM`/`SIGINT` handlers that invoke
//! [`killall_children`] to deliver `SIGTERM` to every registered
//! PID before the parent itself exits. `killall_children` is
//! idempotent and best-effort; individual `kill` errors are
//! silently swallowed because at exit-time the target process may
//! already be gone.

use std::io::{Error as IoError, ErrorKind};
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::sync::{Mutex, OnceLock};

use nix::sys::prctl;
use nix::sys::signal::{kill, Signal};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use nix::unistd::{close, fork, ForkResult, Pid};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::signal::unix::{signal, SignalKind};

use crate::error::NetError;

// ============================================================================
// Constants
// ============================================================================

/// Maximum allowed framing length in bytes for a single [`LinkMessage`]
/// (16 MiB). Frames larger than this in [`ChildProcess::recv_message`] or
/// bodies larger than this in [`LinkMessage::decode`] are rejected with
/// [`NetError::Io`] to prevent denial-of-service via oversized buffers.
///
/// 16 MiB comfortably accommodates the largest realistic payload
/// (a full OCSP response + TLS session cache entry rarely exceeds a
/// few kilobytes) while capping the worst-case allocation.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

// ============================================================================
// Log severity — RFC 5424 subset used by syslog.inc
// ============================================================================

/// Syslog severity level for [`LogRecord`] entries.
///
/// The four variants correspond to the RFC 5424 severity levels
/// actually used by the assembly `syslog.inc` module (the full RFC
/// defines eight; the assembly library only emits these four).
/// Numeric discriminants match the RFC 5424 priority byte mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LogSeverity {
    /// Error condition (RFC 5424 severity 3).
    Err = 3,
    /// Warning condition (RFC 5424 severity 4).
    Warning = 4,
    /// Informational (RFC 5424 severity 6).
    Info = 6,
    /// Debug-level (RFC 5424 severity 7).
    Debug = 7,
}

impl LogSeverity {
    /// Parse a wire-byte into a [`LogSeverity`], or return an
    /// [`NetError::Io`] with [`ErrorKind::InvalidData`] for unknown
    /// values. Private: the public API accepts [`LogSeverity`]
    /// directly in [`LogRecord::severity`].
    fn from_u8(v: u8) -> Result<Self, NetError> {
        match v {
            3 => Ok(LogSeverity::Err),
            4 => Ok(LogSeverity::Warning),
            6 => Ok(LogSeverity::Info),
            7 => Ok(LogSeverity::Debug),
            other => Err(NetError::Io(IoError::new(
                ErrorKind::InvalidData,
                format!("LinkMessage::Log: invalid severity byte {other}"),
            ))),
        }
    }
}

// ============================================================================
// LogRecord — worker→master log entry
// ============================================================================

/// A single log record destined for the master process.
///
/// Workers produce [`LogRecord`] values locally (via the syslog
/// subsystem) and relay them to the master over the socketpair as
/// [`LinkMessage::Log`]. The master is the sole process that writes
/// to the external `/dev/log` syslog socket (or writes to a log
/// file), which serializes log output across all workers and honours
/// the 1.5 s flush timer defined in `rwasa/master.inc`.
///
/// # Sole-writer enforcement (post-fork socket disable)
///
/// `init()` (in [`crate::util::syslog`]) opens the `/dev/log`
/// `UnixDatagram` once in the master before `fork()`. The file
/// descriptor is therefore inherited by every worker. To make the
/// "master is sole writer" contract real (rather than aspirational),
/// each worker calls
/// [`crate::util::syslog::set_socket`]`(None)` immediately after
/// installing the IPC log hook in its multi-worker startup path:
///
/// ```ignore
/// // crates/webserver/src/worker.rs — multi-worker branch
/// install_log_hook(log_tx);            // route every log() call to master via IPC
/// install_tls_sessioncache_hook(tls_tx);
/// syslog::set_socket(None);            // close inherited UnixDatagram
/// ```
///
/// After `set_socket(None)` the worker's `log()` calls invoke only
/// the IPC hook — the direct `/dev/log` write path is dormant. The
/// master, having no hook installed, writes verbatim to `/dev/log`
/// when it receives [`LinkMessage::Log`] from any worker (preserving
/// the original RFC 5424 severity from the worker's call site, not a
/// collapsed normal/error bit). This eliminates the duplicate
/// datagram emission documented in QA Final Checkpoint 17 Issue #1
/// (MAJOR severity).
///
/// Single-worker mode (`-cpu 1`) bypasses this entirely: the worker
/// is the only process and writes directly. No hook is installed,
/// no socket is closed, no relay is needed.
///
/// # Fields
///
/// * `timestamp_ms` — Unix epoch milliseconds when the log event
///   was captured in the worker. Serialized as little-endian `u64`.
/// * `severity` — RFC 5424 severity; see [`LogSeverity`].
/// * `facility` — optional syslog facility name (e.g., `"net"`,
///   `"ssh"`, `"tls"`). Encoded with a `u16` length prefix on the
///   wire: the sentinel value `0xFFFF` encodes `None`, and any
///   other value (including `0`) encodes `Some(s)` with `s` being
///   exactly that many UTF-8 bytes. This preserves the
///   `None` vs `Some("")` distinction losslessly across a
///   parent→child round trip. Facility names longer than
///   `0xFFFE` bytes are truncated by [`LinkMessage::encode`]
///   rather than panicking or colliding with the `None` sentinel.
/// * `message` — raw message payload; intentionally `Vec<u8>`
///   rather than `String` so that non-UTF-8 binary payloads
///   (e.g., hex dumps of handshake failures) can be relayed
///   without lossy conversion.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogRecord {
    /// Unix epoch milliseconds at the time of log capture.
    pub timestamp_ms: u64,
    /// Severity level; see [`LogSeverity`].
    pub severity: LogSeverity,
    /// Optional syslog facility name.
    pub facility: Option<String>,
    /// Raw log message payload (not required to be UTF-8).
    pub message: Vec<u8>,
}

// ============================================================================
// TlsSessionBlob — master→worker TLS session cache entry
// ============================================================================

/// Encrypted TLS session cache entry broadcast to all workers.
///
/// The assembly `tls.inc` session cache is encrypted with AES-256
/// before storage so that an attacker who compromises memory of one
/// worker cannot trivially forge sessions for other connections.
/// The Rust port preserves this by transporting the encrypted form
/// (rather than the cleartext session secrets) across the IPC
/// channel; the rustls `StoresServerSessions` wrapper encrypts/
/// decrypts on each `put`/`get` per AAP §0.7.2.4.
///
/// # Fields
///
/// * `session_id` — session identifier used as the cache key.
///   Typically 32 bytes but variable per rustls.
/// * `encrypted_value` — AES-256-encrypted session state.
/// * `expires_unix_ms` — Unix epoch milliseconds at which this
///   entry expires (3600 s TTL default, per AAP §0.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsSessionBlob {
    /// Cache key (the TLS session id).
    pub session_id: Vec<u8>,
    /// AES-256-encrypted session state blob.
    pub encrypted_value: Vec<u8>,
    /// Unix epoch milliseconds at which this entry expires.
    pub expires_unix_ms: u64,
}

// ============================================================================
// OcspResponse — master→worker OCSP staple
// ============================================================================

/// DER-encoded OCSP response for stapling during new TLS handshakes.
///
/// The master fetches OCSP responses every 7200 s (with a 300 s
/// retry on fetch failure) per AAP §0.1.1 and broadcasts them to
/// every worker as [`LinkMessage::Ocsp`] so workers can staple them
/// onto outgoing `CertificateStatus` handshake messages without
/// each worker hitting the OCSP responder independently.
///
/// # Fields
///
/// * `der` — the OCSP response in DER (ASN.1) encoding.
/// * `fetched_unix_ms` — Unix epoch milliseconds when the response
///   was fetched from the OCSP responder. Used to calculate the
///   staple's age on the worker side.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OcspResponse {
    /// DER-encoded OCSP response bytes.
    pub der: Vec<u8>,
    /// Unix epoch milliseconds at fetch time.
    pub fetched_unix_ms: u64,
}

// ============================================================================
// LinkMessage — the three IPC message types
// ============================================================================

/// Master↔worker IPC message. Exactly three variants per AAP §0.1.1.
///
/// The three variants correspond to the three `linkmessage_*` structs
/// in the assembly baseline: `linkmessage_log`, `linkmessage_tlsupdate`,
/// `linkmessage_ocsp`. Adding more variants is out-of-scope expansion
/// per AAP §0.3.2.5.
///
/// See the module-level rustdoc for the wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkMessage {
    /// Worker → master: log record to be flushed by the master
    /// (consolidates logging across workers; 1.5 s flush interval
    /// owned by master).
    Log(LogRecord),
    /// Master → workers: a new TLS session cache entry observed by
    /// any worker, broadcast so all workers share session cache
    /// state.
    TlsUpdate(TlsSessionBlob),
    /// Master → workers: freshly-fetched OCSP response to staple onto
    /// new TLS handshakes; 7200 s refresh, 300 s retry on fetch
    /// failure.
    Ocsp(OcspResponse),
}

// ============================================================================
// LinkMessage — codec
// ============================================================================

/// Wire-format tag for [`LinkMessage::Log`].
const TAG_LOG: u8 = 1;
/// Wire-format tag for [`LinkMessage::TlsUpdate`].
const TAG_TLS_UPDATE: u8 = 2;
/// Wire-format tag for [`LinkMessage::Ocsp`].
const TAG_OCSP: u8 = 3;

/// Wire header size: `u8 tag + u32 body_len`.
const HEADER_LEN: usize = 1 + 4;

/// Sentinel value for the `u16 facility_len` field in the
/// [`LinkMessage::Log`] wire format indicating `facility = None`.
///
/// Any other `u16` value (including `0`) encodes `Some` with that
/// many UTF-8 bytes following. This preserves the `None` vs
/// `Some("")` distinction losslessly across the wire.
const FACILITY_NONE_SENTINEL: u16 = 0xFFFF;

/// Maximum UTF-8 byte length of a `Some(facility)` on the wire.
///
/// One value below `u16::MAX` so that the sentinel used for
/// [`FACILITY_NONE_SENTINEL`] never collides with a legitimately
/// present facility. Facilities longer than this limit are
/// truncated by [`LinkMessage::encode`] rather than panicking.
const FACILITY_LEN_MAX: u16 = 0xFFFE;

impl LinkMessage {
    /// Encode this [`LinkMessage`] into `buf` (appending to the end).
    ///
    /// Emits `u8 tag || u32 body_len (LE) || body bytes` per the
    /// module-level wire format specification. The inner `body_len`
    /// is patched in after the body has been written so that
    /// variable-length fields do not require a two-pass encode.
    ///
    /// This function never fails: all encode operations are
    /// infallible byte appends.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            LinkMessage::Log(rec) => {
                let body_len_pos = write_header(buf, TAG_LOG);
                let body_start = buf.len();
                // u64 timestamp_ms
                buf.extend_from_slice(&rec.timestamp_ms.to_le_bytes());
                // u8 severity
                buf.push(rec.severity as u8);
                // u16 facility_len + facility.
                //
                // The sentinel value FACILITY_NONE_SENTINEL (0xFFFF)
                // encodes `None`; any other value encodes `Some(s)`
                // with `s.len()` bytes of UTF-8 following. This is
                // what preserves the `None` vs `Some("")` distinction
                // losslessly — otherwise they would both collapse to
                // "length=0" on the wire and decode indistinguishably.
                //
                // Pathologically long facility names (>= 0xFFFE bytes)
                // are truncated to FACILITY_LEN_MAX rather than either
                // panicking or wrapping around into the None sentinel.
                match rec.facility.as_deref() {
                    None => {
                        buf.extend_from_slice(&FACILITY_NONE_SENTINEL.to_le_bytes());
                    }
                    Some(s) => {
                        let fac_bytes = s.as_bytes();
                        let fac_len_u16 = if fac_bytes.len() > FACILITY_LEN_MAX as usize {
                            FACILITY_LEN_MAX
                        } else {
                            // Cast is lossless because we just bounded by 0xFFFE.
                            fac_bytes.len() as u16
                        };
                        buf.extend_from_slice(&fac_len_u16.to_le_bytes());
                        buf.extend_from_slice(&fac_bytes[..fac_len_u16 as usize]);
                    }
                }
                // u32 msg_len + msg
                let msg_len_u32 = u32::try_from(rec.message.len()).unwrap_or(u32::MAX);
                buf.extend_from_slice(&msg_len_u32.to_le_bytes());
                buf.extend_from_slice(&rec.message[..msg_len_u32 as usize]);
                patch_body_len(buf, body_len_pos, body_start);
            }
            LinkMessage::TlsUpdate(blob) => {
                let body_len_pos = write_header(buf, TAG_TLS_UPDATE);
                let body_start = buf.len();
                // u16 sid_len + sid
                let sid_len_u16 = u16::try_from(blob.session_id.len()).unwrap_or(u16::MAX);
                buf.extend_from_slice(&sid_len_u16.to_le_bytes());
                buf.extend_from_slice(&blob.session_id[..sid_len_u16 as usize]);
                // u32 val_len + val
                let val_len_u32 = u32::try_from(blob.encrypted_value.len()).unwrap_or(u32::MAX);
                buf.extend_from_slice(&val_len_u32.to_le_bytes());
                buf.extend_from_slice(&blob.encrypted_value[..val_len_u32 as usize]);
                // u64 expires_ms
                buf.extend_from_slice(&blob.expires_unix_ms.to_le_bytes());
                patch_body_len(buf, body_len_pos, body_start);
            }
            LinkMessage::Ocsp(ocsp) => {
                let body_len_pos = write_header(buf, TAG_OCSP);
                let body_start = buf.len();
                // u32 der_len + der
                let der_len_u32 = u32::try_from(ocsp.der.len()).unwrap_or(u32::MAX);
                buf.extend_from_slice(&der_len_u32.to_le_bytes());
                buf.extend_from_slice(&ocsp.der[..der_len_u32 as usize]);
                // u64 fetched_ms
                buf.extend_from_slice(&ocsp.fetched_unix_ms.to_le_bytes());
                patch_body_len(buf, body_len_pos, body_start);
            }
        }
    }

    /// Decode a [`LinkMessage`] from the start of `buf`.
    ///
    /// Returns `(message, bytes_consumed)` on success where
    /// `bytes_consumed` equals `HEADER_LEN + body_len`. The caller
    /// is responsible for skipping past the consumed bytes if the
    /// buffer contains additional data.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Io`] with:
    ///
    /// * [`ErrorKind::UnexpectedEof`] if `buf` is shorter than the
    ///   header or shorter than the declared body length.
    /// * [`ErrorKind::InvalidData`] if the tag is not one of
    ///   `{1, 2, 3}`, if the declared body length exceeds
    ///   [`MAX_FRAME_SIZE`], if internal length fields overflow
    ///   the body, or if the severity byte is not one of
    ///   `{3, 4, 6, 7}`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), NetError> {
        if buf.len() < HEADER_LEN {
            return Err(NetError::Io(IoError::new(
                ErrorKind::UnexpectedEof,
                format!(
                    "LinkMessage header truncated (need {HEADER_LEN} bytes, have {})",
                    buf.len()
                ),
            )));
        }
        let tag = buf[0];
        let body_len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if body_len > MAX_FRAME_SIZE {
            return Err(NetError::Io(IoError::new(
                ErrorKind::InvalidData,
                format!("LinkMessage body_len {body_len} exceeds MAX_FRAME_SIZE {MAX_FRAME_SIZE}"),
            )));
        }
        let end = HEADER_LEN.checked_add(body_len).ok_or_else(|| {
            NetError::Io(IoError::new(
                ErrorKind::InvalidData,
                "LinkMessage body_len overflow",
            ))
        })?;
        if buf.len() < end {
            return Err(NetError::Io(IoError::new(
                ErrorKind::UnexpectedEof,
                format!(
                    "LinkMessage body truncated (need {end} bytes, have {})",
                    buf.len()
                ),
            )));
        }
        let body = &buf[HEADER_LEN..end];
        let msg = match tag {
            TAG_LOG => decode_log(body)?,
            TAG_TLS_UPDATE => decode_tls_update(body)?,
            TAG_OCSP => decode_ocsp(body)?,
            other => {
                return Err(NetError::Io(IoError::new(
                    ErrorKind::InvalidData,
                    format!("LinkMessage: unknown tag {other}"),
                )));
            }
        };
        Ok((msg, end))
    }
}

/// Append `[tag, 0, 0, 0, 0]` (the tag plus a placeholder body length)
/// and return the byte offset of the body-length u32 for later
/// patching via [`patch_body_len`].
fn write_header(buf: &mut Vec<u8>, tag: u8) -> usize {
    buf.push(tag);
    let body_len_pos = buf.len();
    buf.extend_from_slice(&[0u8; 4]);
    body_len_pos
}

/// Patch the body-length u32 at `body_len_pos` to the actual body
/// length (`buf.len() - body_start`). Truncates if the body exceeds
/// `u32::MAX` (in practice impossible given [`MAX_FRAME_SIZE`]).
fn patch_body_len(buf: &mut [u8], body_len_pos: usize, body_start: usize) {
    let body_len = buf.len() - body_start;
    let body_len_u32 = u32::try_from(body_len).unwrap_or(u32::MAX);
    buf[body_len_pos..body_len_pos + 4].copy_from_slice(&body_len_u32.to_le_bytes());
}

/// Decode the body of a [`LinkMessage::Log`] variant.
fn decode_log(body: &[u8]) -> Result<LinkMessage, NetError> {
    // u64 timestamp_ms + u8 severity + u16 fac_len = 11 bytes minimum
    const MIN_LOG: usize = 8 + 1 + 2;
    if body.len() < MIN_LOG {
        return Err(NetError::Io(IoError::new(
            ErrorKind::UnexpectedEof,
            format!("Log body truncated (need {MIN_LOG} bytes, have {})", body.len()),
        )));
    }
    let ts = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let severity = LogSeverity::from_u8(body[8])?;
    // The u16 facility length is overloaded: FACILITY_NONE_SENTINEL
    // (0xFFFF) means the record's facility is `None` and no facility
    // bytes follow. Any other value is the on-wire UTF-8 byte length
    // of a `Some(...)` facility — note that 0 is a legitimate value
    // here (it encodes `Some("")`) and MUST NOT be collapsed back to
    // `None`, which is the behavior the pre-sentinel codec had.
    let fac_len_raw = u16::from_le_bytes([body[9], body[10]]);
    let facility_is_none = fac_len_raw == FACILITY_NONE_SENTINEL;
    let fac_len = if facility_is_none { 0 } else { fac_len_raw as usize };
    let msg_len_start = 11 + fac_len;
    // Need at least msg_len_start + 4 bytes for the u32 msg_len.
    if body.len() < msg_len_start + 4 {
        return Err(NetError::Io(IoError::new(
            ErrorKind::UnexpectedEof,
            format!(
                "Log facility+msg_len truncated (need {} bytes, have {})",
                msg_len_start + 4,
                body.len()
            ),
        )));
    }
    let facility = if facility_is_none {
        None
    } else {
        // Allow non-UTF-8 facility names defensively via lossy conversion,
        // though the assembly only emits ASCII facility names. Note that
        // `fac_len == 0` is a legitimate `Some("")` here; the slice is
        // empty but `Some(String::new())` is what we return.
        let fac_bytes = &body[11..11 + fac_len];
        Some(String::from_utf8_lossy(fac_bytes).into_owned())
    };
    let msg_len = u32::from_le_bytes(body[msg_len_start..msg_len_start + 4].try_into().unwrap()) as usize;
    let msg_end = msg_len_start + 4 + msg_len;
    if body.len() < msg_end {
        return Err(NetError::Io(IoError::new(
            ErrorKind::UnexpectedEof,
            format!(
                "Log message truncated (need {msg_end} bytes, have {})",
                body.len()
            ),
        )));
    }
    let message = body[msg_len_start + 4..msg_end].to_vec();
    Ok(LinkMessage::Log(LogRecord {
        timestamp_ms: ts,
        severity,
        facility,
        message,
    }))
}

/// Decode the body of a [`LinkMessage::TlsUpdate`] variant.
fn decode_tls_update(body: &[u8]) -> Result<LinkMessage, NetError> {
    // u16 sid_len minimum
    if body.len() < 2 {
        return Err(NetError::Io(IoError::new(
            ErrorKind::UnexpectedEof,
            "TlsUpdate body truncated (sid_len)",
        )));
    }
    let sid_len = u16::from_le_bytes([body[0], body[1]]) as usize;
    let val_len_start = 2 + sid_len;
    if body.len() < val_len_start + 4 {
        return Err(NetError::Io(IoError::new(
            ErrorKind::UnexpectedEof,
            "TlsUpdate body truncated (sid+val_len)",
        )));
    }
    let session_id = body[2..2 + sid_len].to_vec();
    let val_len = u32::from_le_bytes(body[val_len_start..val_len_start + 4].try_into().unwrap()) as usize;
    let val_start = val_len_start + 4;
    let val_end = val_start + val_len;
    let expires_end = val_end + 8;
    if body.len() < expires_end {
        return Err(NetError::Io(IoError::new(
            ErrorKind::UnexpectedEof,
            format!(
                "TlsUpdate body truncated (need {expires_end} bytes, have {})",
                body.len()
            ),
        )));
    }
    let encrypted_value = body[val_start..val_end].to_vec();
    let expires_unix_ms = u64::from_le_bytes(body[val_end..expires_end].try_into().unwrap());
    Ok(LinkMessage::TlsUpdate(TlsSessionBlob {
        session_id,
        encrypted_value,
        expires_unix_ms,
    }))
}

/// Decode the body of a [`LinkMessage::Ocsp`] variant.
fn decode_ocsp(body: &[u8]) -> Result<LinkMessage, NetError> {
    if body.len() < 4 {
        return Err(NetError::Io(IoError::new(
            ErrorKind::UnexpectedEof,
            "Ocsp body truncated (der_len)",
        )));
    }
    let der_len = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
    let der_start = 4;
    let der_end = der_start + der_len;
    let fetched_end = der_end + 8;
    if body.len() < fetched_end {
        return Err(NetError::Io(IoError::new(
            ErrorKind::UnexpectedEof,
            format!(
                "Ocsp body truncated (need {fetched_end} bytes, have {})",
                body.len()
            ),
        )));
    }
    let der = body[der_start..der_end].to_vec();
    let fetched_unix_ms = u64::from_le_bytes(body[der_end..fetched_end].try_into().unwrap());
    Ok(LinkMessage::Ocsp(OcspResponse { der, fetched_unix_ms }))
}

// ============================================================================
// ChildProcess — parent-side handle to a spawned worker
// ============================================================================

/// A spawned child process with an async Unix-domain socket to its parent.
///
/// Returned by [`spawn_child`]. The parent holds this struct to communicate
/// with the child via the [`LinkMessage`] protocol.
///
/// # Drop semantics
///
/// Dropping a `ChildProcess` **only closes the parent-side socket**. It does
/// **not** send a signal to the child, does **not** `waitpid(2)` on the
/// child, and does **not** remove the child's PID from the internal
/// kill-list populated by [`spawn_child`]. This matches the FASM
/// baseline in `epoll_child.inc`, where the `epoll$destroy` chain closes
/// only the parent-side fd and leaves the PID in `epoll_child_pids` for
/// later `epoll_child_killall` to signal.
///
/// To forcibly terminate the child, send it a cooperative-shutdown
/// [`LinkMessage`] (or call [`killall_children`]). To reap zombies after
/// termination, the caller must `waitpid(2)` separately (in practice
/// `webserver::master` waits on EOF of each IPC channel in its main
/// event loop, which happens after `SIGTERM`).
///
/// # Non-blocking
///
/// `parent_socket` is the parent's end of the AF_UNIX/SOCK_STREAM
/// socketpair created by [`spawn_child`]. It is configured non-blocking
/// and wrapped in [`tokio::net::UnixStream`], so reads and writes
/// integrate with the tokio reactor. A tokio runtime must therefore be
/// active on the thread that invokes [`spawn_child`] and on the thread
/// that calls [`send_message`](ChildProcess::send_message) /
/// [`recv_message`](ChildProcess::recv_message).
pub struct ChildProcess {
    /// POSIX process ID of the spawned child.
    ///
    /// Registered in the module-private `CHILD_PIDS` list so that
    /// [`killall_children`] can signal it on parent shutdown.
    pub pid: Pid,

    /// Parent-side of the AF_UNIX `SOCK_STREAM` socketpair connecting
    /// parent to child. Read/write [`LinkMessage`] frames via
    /// [`ChildProcess::send_message`] / [`ChildProcess::recv_message`],
    /// which apply an outer `u32` (LE) length prefix on top of the
    /// self-delimited [`LinkMessage`] wire frame.
    pub parent_socket: UnixStream,
}

// ============================================================================
// Global child-PID registry
// ============================================================================

/// Module-private registry of child PIDs spawned via [`spawn_child`].
///
/// Populated by [`register_child_pid`] in the parent branch of
/// [`spawn_child`]. Drained and signalled by [`killall_children`] on
/// parent shutdown. Lazily initialized on first access because the master
/// process may not need the registry at all (e.g., during
/// argument-parsing errors that abort before any fork).
///
/// Replaces the FASM `epoll_child_pids` list-backed global in
/// `epoll_child.inc:4–12`.
static CHILD_PIDS: OnceLock<Mutex<Vec<Pid>>> = OnceLock::new();

/// Accessor for the global child-PID registry. Lazily initializes on first
/// call; subsequent calls return the same `Mutex`.
fn child_pids() -> &'static Mutex<Vec<Pid>> {
    CHILD_PIDS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Register a spawned child's PID with the module-private registry so
/// that [`killall_children`] can signal it at parent shutdown.
///
/// Gracefully handles a poisoned mutex by recovering the inner vector:
/// poisoning during server shutdown is a benign indicator that an
/// earlier drain panicked, and we still need to register the new PID
/// to preserve the invariant that every spawned child is on the list.
fn register_child_pid(pid: Pid) {
    let mut guard = match child_pids().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.push(pid);
}

// ============================================================================
// spawn_child — the fork-and-socketpair entry point (3 unsafe sites)
// ============================================================================

/// Spawn a child process connected to the parent over an
/// AF_UNIX/SOCK_STREAM/SOCK_CLOEXEC socketpair. The child runs
/// `child_main`, passing its side of the socketpair as a blocking
/// [`std::os::unix::net::UnixStream`].
///
/// # Behavior
///
/// 1. Creates an AF_UNIX/SOCK_STREAM/SOCK_CLOEXEC socketpair via
///    [`nix::sys::socket::socketpair`].
/// 2. Calls `fork(2)`.
/// 3. In the **parent**: closes the child-side fd, wraps the parent-side
///    fd in a non-blocking [`tokio::net::UnixStream`], registers the
///    child PID in the module-private kill-list used by
///    [`killall_children`], and returns a [`ChildProcess`].
/// 4. In the **child**: calls `prctl(PR_SET_PDEATHSIG, SIGTERM)` so that
///    the kernel terminates this process if the parent dies; closes the
///    parent-side fd; wraps the child-side fd in a blocking
///    [`std::os::unix::net::UnixStream`]; invokes `child_main`; and
///    unconditionally calls `std::process::exit(0)` after `child_main`
///    returns (matching the FASM `syscall_exit(0)` baseline from
///    `epoll_child.inc:113` — "should normally never return").
///
/// # Caller contract — child-side
///
/// The body of `child_main` **must**:
///
/// * Reseed the crypto RNG via `crate::crypto::rng::reseed` (or
///   equivalent) before any cryptographic operation. `fork(2)` duplicates
///   HMAC-DRBG state verbatim, so without reseeding the parent and child
///   would emit identical "random" streams — see AAP §0.7.4.2.
/// * Build its own tokio runtime via `crate::net::runtime::build` (or
///   directly via `tokio::runtime::Builder`). The parent's tokio runtime
///   is **not** inherited in a usable form: fork duplicates the reactor's
///   epoll fd, but the tasks registered on it belong to the (now-absent
///   in this process) parent's threads. See AAP §0.7.1.2.
/// * Normally never return. If `child_main` *does* return,
///   [`spawn_child`] calls `std::process::exit(0)` on its behalf so that
///   the child cannot accidentally fall through into any post-fork code
///   that would mistake it for the parent. This mirrors the FASM
///   baseline and prevents the classic double-execution bug.
///
/// # Errors
///
/// * [`NetError::Fork`] if `socketpair(2)` or `fork(2)` fails.
/// * [`NetError::Io`] if the parent-side fd cannot be set non-blocking
///   or wrapped into a tokio `UnixStream` (the latter requires an active
///   tokio runtime on the calling thread). On such errors we SIGTERM the
///   (already-spawned) child before returning, because the caller has
///   no other handle with which to reach it.
///
/// # Safety
///
/// This function contains 3 `unsafe` blocks — see the `// SAFETY:`
/// comments at each site and the matching entries in `/UNSAFE_AUDIT.md`.
/// The **Caller contract** above (reseed RNG, build a new tokio runtime
/// in the child) is safety-critical for cryptographic correctness and
/// tokio-reactor correctness respectively; it is enforced by
/// documentation and by integration tests in
/// `crates/heavything/tests/ffi_boundary.rs`, not by the compiler.
pub fn spawn_child<F>(child_main: F) -> Result<ChildProcess, NetError>
where
    F: FnOnce(std::os::unix::net::UnixStream) + Send + 'static,
{
    // Step 1 — create the AF_UNIX/SOCK_STREAM/SOCK_CLOEXEC socketpair.
    //
    // `nix::sys::socket::socketpair` returns a `(OwnedFd, OwnedFd)` tuple
    // in nix 0.29. We must unwrap these into raw fds (`into_raw_fd`
    // consumes the `OwnedFd` and suppresses its `Drop`) so that neither
    // side's `Drop` fires in the post-fork wrong branch — which would
    // prematurely close the fd in both processes.
    let (parent_ofd, child_ofd) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(NetError::Fork)?;
    let parent_fd: RawFd = parent_ofd.into_raw_fd();
    let child_fd: RawFd = child_ofd.into_raw_fd();

    // Step 2 — fork.
    //
    // SAFETY:
    //
    // * `fork(2)` is marked `unsafe` by `nix` because the child must not
    //   execute any code that is not async-signal-safe until it either
    //   `exec`s or terminates via `_exit`. Our child branch below
    //   performs only the following steps prior to handing control to
    //   `child_main`:
    //     - `prctl(PR_SET_PDEATHSIG, SIGTERM)` — documented
    //       async-signal-safe in `signal-safety(7)`.
    //     - `close(parent_fd)` — documented async-signal-safe.
    //     - `std::os::unix::net::UnixStream::from_raw_fd(child_fd)` — a
    //       pure Rust wrapper around an already-owned fd; does not call
    //       into libc.
    //     - `child_main(stream)` — the *caller* is responsible for
    //       making `child_main` async-signal-safe until it has
    //       constructed its own tokio runtime, per the `# Caller
    //       contract` section of this doc comment. This preserves the
    //       FASM baseline in `epoll_child.inc:72–85`, which likewise
    //       hands control to user-supplied code post-fork before
    //       creating its own epoll descriptor.
    // * The parent's tokio runtime is NOT safely inherited; see AAP
    //   §0.7.1.2. The `child_main` contract mandates constructing a
    //   fresh runtime in the child.
    // * `fork` in a multi-threaded program is hazardous because only
    //   the calling thread survives the fork; any mutex locked by
    //   another thread will deadlock if the child attempts to take it.
    //   Tests for this function use a single-threaded tokio runtime
    //   (`#[tokio::test(flavor = "current_thread")]`). Callers in
    //   production (the `webserver` master process per AAP §0.5.1.8)
    //   fork before spawning additional threads.
    // * On fork failure we close both fds before returning to avoid
    //   leaking descriptors. On fork success, each branch is
    //   responsible for closing the wrong-side fd.
    // * See `/UNSAFE_AUDIT.md` entry `net::child::spawn_child::fork`.
    let fork_result = unsafe { fork() }.map_err(|e| {
        // Close both fds before returning; neither branch of the fork
        // will run because the syscall itself failed.
        let _ = close(parent_fd);
        let _ = close(child_fd);
        NetError::Fork(e)
    })?;

    match fork_result {
        ForkResult::Parent { child: pid } => {
            // Parent branch: close child's side of the pair, wrap
            // parent's side into a non-blocking tokio `UnixStream`.
            let _ = close(child_fd);

            // SAFETY:
            //
            // * `parent_fd` was just returned by `socketpair(2)` above.
            // * We own it exclusively: it was handed to us via `OwnedFd`
            //   from `socketpair`, and we consumed the `OwnedFd` via
            //   `into_raw_fd` to suppress its `Drop`. No other code
            //   path has observed or re-used this fd.
            // * The child branch of the fork does NOT see `parent_fd`
            //   as an active descriptor from its perspective either —
            //   though the fd value is duplicated by fork into the
            //   child's table, the child immediately `close`s it in
            //   the `ForkResult::Child` arm below.
            // * Constructing
            //   `std::os::unix::net::UnixStream::from_raw_fd(parent_fd)`
            //   transfers ownership of the fd to the returned
            //   `UnixStream`, whose `Drop` will `close(2)` it. No
            //   double-close occurs because we do not call `close`
            //   explicitly on `parent_fd` in this branch.
            // * See `/UNSAFE_AUDIT.md` entry
            //   `net::child::spawn_child::parent_from_raw_fd`.
            let std_stream: std::os::unix::net::UnixStream =
                unsafe { std::os::unix::net::UnixStream::from_raw_fd(parent_fd) };

            // If setting non-blocking or wrapping into tokio fails, the
            // child we just spawned is otherwise unreachable — SIGTERM it
            // inline before returning the error.
            if let Err(e) = std_stream.set_nonblocking(true) {
                let _ = kill(pid, Signal::SIGTERM);
                return Err(NetError::Io(e));
            }
            let parent_socket = match UnixStream::from_std(std_stream) {
                Ok(stream) => stream,
                Err(e) => {
                    let _ = kill(pid, Signal::SIGTERM);
                    return Err(NetError::Io(e));
                }
            };

            // Register the child PID so that `killall_children` (and
            // any signal handler installed via
            // `install_cleanup_handlers`) can signal it at parent
            // shutdown. Register AFTER successful wrapping so a failed
            // spawn does not leave a stale PID in the list.
            register_child_pid(pid);

            Ok(ChildProcess { pid, parent_socket })
        }
        ForkResult::Child => {
            // Child branch — MUST be async-signal-safe until
            // `child_main` takes over.

            // Step 1 — install "die when parent dies".
            //
            // `set_pdeathsig` wraps `prctl(PR_SET_PDEATHSIG, ...)`,
            // which is documented async-signal-safe. Failure here is
            // intentionally swallowed: the only observable consequence
            // is that this child becomes an orphan rather than
            // auto-terminating on parent death, but the parent's
            // `killall_children` path still sends SIGTERM on graceful
            // shutdown. Propagating the error here would be
            // architecturally wrong — there is no caller to receive it
            // in the child's code path.
            let _ = prctl::set_pdeathsig(Signal::SIGTERM);

            // Step 2 — close parent's end of the socketpair.
            let _ = close(parent_fd);

            // SAFETY:
            //
            // * `child_fd` was returned by `socketpair(2)` in the
            //   pre-fork parent. `fork(2)` duplicates the fd table
            //   verbatim, so this child inherits the same raw fd
            //   number pointing at the same kernel socket.
            // * The `OwnedFd` for `child_fd` was consumed by
            //   `into_raw_fd` before the fork, so its `Drop` will not
            //   run in either process.
            // * We have not re-used `child_fd` in this branch (we only
            //   closed `parent_fd` above).
            // * The resulting `std::os::unix::net::UnixStream` takes
            //   ownership; its `Drop` will close the fd when
            //   `child_main` returns (or sooner, if `child_main` drops
            //   it explicitly). The fd is also closed at
            //   kernel-teardown time when we call
            //   `std::process::exit(0)` below.
            // * See `/UNSAFE_AUDIT.md` entry
            //   `net::child::spawn_child::child_from_raw_fd`.
            let child_stream: std::os::unix::net::UnixStream =
                unsafe { std::os::unix::net::UnixStream::from_raw_fd(child_fd) };

            // Hand off to caller-supplied child main. Per the caller
            // contract this should normally never return; however, to
            // defend against a buggy `child_main` that falls off its
            // end, we explicitly `exit(0)` afterwards so the child
            // cannot accidentally fall through into any post-fork
            // code that would mistake it for the parent. This matches
            // the FASM `syscall_exit(0)` baseline at
            // `epoll_child.inc:113`.
            child_main(child_stream);
            std::process::exit(0);
        }
    }
}

// ============================================================================
// killall_children / install_cleanup_handlers
// ============================================================================

/// Send `SIGTERM` to every child PID registered via [`spawn_child`].
///
/// Idempotent and best-effort: errors from individual `kill(2)` calls
/// are swallowed because at shutdown time there is nothing actionable
/// that a master process can do about a child that has already exited
/// (`ESRCH`) or that we no longer have permission to signal (`EPERM`,
/// which can only arise after an unprivileged re-exec because the
/// master kept privilege to deliver signals after the privilege-drop
/// sequence in AAP §0.1.1). After this call returns, the internal PID
/// list is empty, so subsequent invocations are no-ops.
///
/// Does **not** block waiting for child exits. If the caller needs to
/// ensure children have reaped, it must `waitpid(2)` separately (in
/// practice `webserver::master` waits on EOF of each IPC channel in
/// its main event loop, which happens shortly after each child's
/// SIGTERM is delivered).
///
/// This is the Rust port of `epoll_child_killall` in
/// `epoll_child.inc:117–155`.
pub fn killall_children() {
    let mut guard = match child_pids().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    for pid in guard.drain(..) {
        // Ignore individual kill errors; see doc comment.
        let _ = kill(pid, Signal::SIGTERM);
    }
}

/// Install async signal handlers that invoke [`killall_children`] when
/// the current process receives `SIGTERM` or `SIGINT`.
///
/// Spawns two background tokio tasks on the current runtime, one per
/// signal. On the first matching signal, the corresponding task calls
/// `killall_children()` and returns. The tasks do **not** themselves
/// cause the process to exit — that remains the caller's
/// responsibility, typically via the master's main event loop
/// observing EOF on each IPC channel after children terminate. This
/// separation lets a master process implement a graceful shutdown of
/// the form "on SIGTERM, stop accepting, drain request pipeline, kill
/// children, await EOF, exit" without the signal handler
/// short-circuiting the drain step.
///
/// # Errors
///
/// Returns [`NetError::Io`] if either signal handler cannot be
/// registered (the error wraps the underlying
/// `tokio::signal::unix::signal` `io::Error`).
///
/// # Requires tokio runtime
///
/// Must be called from within a tokio runtime. The spawned
/// signal-handler tasks run on whichever runtime is active at
/// call-time.
pub fn install_cleanup_handlers() -> Result<(), NetError> {
    let mut sigterm_stream = signal(SignalKind::terminate()).map_err(NetError::Io)?;
    let mut sigint_stream = signal(SignalKind::interrupt()).map_err(NetError::Io)?;

    tokio::spawn(async move {
        if sigterm_stream.recv().await.is_some() {
            killall_children();
        }
    });
    tokio::spawn(async move {
        if sigint_stream.recv().await.is_some() {
            killall_children();
        }
    });

    Ok(())
}

// ============================================================================
// ChildProcess — async IPC send/recv
// ============================================================================

impl ChildProcess {
    /// Send one [`LinkMessage`] to the child.
    ///
    /// Wire layout of a full send: `u32 outer_len (LE) || inner_frame`,
    /// where `inner_frame` is the encoding produced by
    /// [`LinkMessage::encode`] (itself `u8 tag || u32 body_len (LE) ||
    /// body`). The outer length prefix is redundant with the inner
    /// frame's self-delimitation, but it lets
    /// [`recv_message`](ChildProcess::recv_message) allocate the exact
    /// body size up-front without parsing the inner header twice.
    ///
    /// # Errors
    ///
    /// * [`NetError::Io`] wrapping any socket I/O error.
    /// * [`NetError::Io`] with [`ErrorKind::InvalidData`] if the encoded
    ///   frame exceeds [`MAX_FRAME_SIZE`] (sanity check against caller
    ///   bugs; in practice only the `Log` variant can approach the cap).
    pub async fn send_message(&mut self, msg: &LinkMessage) -> Result<(), NetError> {
        let mut buf = Vec::with_capacity(HEADER_LEN + 64);
        msg.encode(&mut buf);
        if buf.len() > MAX_FRAME_SIZE {
            return Err(NetError::Io(IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "LinkMessage encoded length {} exceeds MAX_FRAME_SIZE {}",
                    buf.len(),
                    MAX_FRAME_SIZE
                ),
            )));
        }
        let outer_len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        self.parent_socket
            .write_all(&outer_len.to_le_bytes())
            .await
            .map_err(NetError::Io)?;
        self.parent_socket.write_all(&buf).await.map_err(NetError::Io)?;
        Ok(())
    }

    /// Receive one [`LinkMessage`] from the child.
    ///
    /// Returns `Ok(None)` on clean EOF — i.e. the child closed its end
    /// of the socket without starting a partial frame — so that callers
    /// can distinguish "peer hung up" from an actual I/O error in
    /// graceful-shutdown logic.
    ///
    /// # Errors
    ///
    /// * [`NetError::Io`] wrapping any socket I/O error or a
    ///   mid-frame [`ErrorKind::UnexpectedEof`] (observed while
    ///   reading the body after the length prefix was already read).
    /// * [`NetError::Io`] with [`ErrorKind::InvalidData`] if the
    ///   declared outer length exceeds [`MAX_FRAME_SIZE`], or if
    ///   [`LinkMessage::decode`] rejects the inner frame (unknown
    ///   tag, invalid severity, inner body length exceeds
    ///   [`MAX_FRAME_SIZE`], truncated body).
    pub async fn recv_message(&mut self) -> Result<Option<LinkMessage>, NetError> {
        let mut len_buf = [0u8; 4];
        match self.parent_socket.read_exact(&mut len_buf).await {
            Ok(_) => {}
            // Clean EOF at frame boundary — signal graceful close.
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(NetError::Io(e)),
        }
        let outer_len = u32::from_le_bytes(len_buf) as usize;
        if outer_len > MAX_FRAME_SIZE {
            return Err(NetError::Io(IoError::new(
                ErrorKind::InvalidData,
                format!("LinkMessage outer frame length {outer_len} exceeds MAX_FRAME_SIZE {MAX_FRAME_SIZE}"),
            )));
        }
        let mut frame = vec![0u8; outer_len];
        self.parent_socket
            .read_exact(&mut frame)
            .await
            .map_err(NetError::Io)?;
        let (msg, _consumed) = LinkMessage::decode(&frame)?;
        Ok(Some(msg))
    }
}

// ============================================================================
// Tests — in-file unit tests (codec + registry)
//
// Fork-based integration tests live in
// `crates/heavything/tests/ffi_boundary.rs` so that they run in a
// real process context and do not interfere with the parallel
// `cargo test --lib` harness.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Codec fixtures ------------------------------------------------------

    fn sample_log_record() -> LogRecord {
        LogRecord {
            timestamp_ms: 0x0123_4567_89ab_cdef,
            severity: LogSeverity::Info,
            facility: Some("webserver".to_string()),
            message: b"hello from worker 7".to_vec(),
        }
    }

    fn sample_tls_blob() -> TlsSessionBlob {
        TlsSessionBlob {
            session_id: b"sid-0123".to_vec(),
            encrypted_value: b"encrypted-opaque-blob".to_vec(),
            expires_unix_ms: 1_700_000_000_000,
        }
    }

    fn sample_ocsp_response() -> OcspResponse {
        OcspResponse {
            der: b"\x30\x82\x01\x0b\x0a\x01\x00\xa0\x82\x01\x04".to_vec(),
            fetched_unix_ms: 1_700_000_123_456,
        }
    }

    // --- Round-trip tests ----------------------------------------------------

    #[test]
    fn test_link_message_log_roundtrip() {
        // Nominal case: full LogRecord with facility + message.
        let original = LinkMessage::Log(sample_log_record());
        let mut buf = Vec::new();
        original.encode(&mut buf);
        let (decoded, consumed) = LinkMessage::decode(&buf).expect("decode of full LogRecord should succeed");
        assert_eq!(decoded, original);
        assert_eq!(consumed, buf.len());

        // Edge case: None facility + empty message body.
        let original_empty = LinkMessage::Log(LogRecord {
            timestamp_ms: 42,
            severity: LogSeverity::Err,
            facility: None,
            message: Vec::new(),
        });
        let mut buf_empty = Vec::new();
        original_empty.encode(&mut buf_empty);
        let (decoded_empty, consumed_empty) = LinkMessage::decode(&buf_empty)
            .expect("decode of empty-facility/message LogRecord should succeed");
        assert_eq!(decoded_empty, original_empty);
        assert_eq!(consumed_empty, buf_empty.len());

        // Severity coverage: Warning + Debug, empty facility string.
        let original_warn = LinkMessage::Log(LogRecord {
            timestamp_ms: u64::MAX,
            severity: LogSeverity::Warning,
            facility: Some(String::new()),
            message: b"warn me once".to_vec(),
        });
        let mut buf_warn = Vec::new();
        original_warn.encode(&mut buf_warn);
        let (decoded_warn, _) =
            LinkMessage::decode(&buf_warn).expect("decode of Warning LogRecord should succeed");
        assert_eq!(decoded_warn, original_warn);

        let original_debug = LinkMessage::Log(LogRecord {
            timestamp_ms: 1,
            severity: LogSeverity::Debug,
            facility: Some("dbg".to_string()),
            message: b"trace".to_vec(),
        });
        let mut buf_debug = Vec::new();
        original_debug.encode(&mut buf_debug);
        let (decoded_debug, _) =
            LinkMessage::decode(&buf_debug).expect("decode of Debug LogRecord should succeed");
        assert_eq!(decoded_debug, original_debug);
    }

    #[test]
    fn test_link_message_tls_update_roundtrip() {
        let original = LinkMessage::TlsUpdate(sample_tls_blob());
        let mut buf = Vec::new();
        original.encode(&mut buf);
        let (decoded, consumed) = LinkMessage::decode(&buf).expect("decode of TlsUpdate should succeed");
        assert_eq!(decoded, original);
        assert_eq!(consumed, buf.len());

        // Edge case: empty session_id and encrypted_value.
        let original_empty = LinkMessage::TlsUpdate(TlsSessionBlob {
            session_id: Vec::new(),
            encrypted_value: Vec::new(),
            expires_unix_ms: 0,
        });
        let mut buf_empty = Vec::new();
        original_empty.encode(&mut buf_empty);
        let (decoded_empty, _) =
            LinkMessage::decode(&buf_empty).expect("decode of empty TlsSessionBlob should succeed");
        assert_eq!(decoded_empty, original_empty);
    }

    #[test]
    fn test_link_message_ocsp_roundtrip() {
        let original = LinkMessage::Ocsp(sample_ocsp_response());
        let mut buf = Vec::new();
        original.encode(&mut buf);
        let (decoded, consumed) = LinkMessage::decode(&buf).expect("decode of Ocsp should succeed");
        assert_eq!(decoded, original);
        assert_eq!(consumed, buf.len());

        // Edge case: empty DER (pathological but allowed).
        let original_empty = LinkMessage::Ocsp(OcspResponse {
            der: Vec::new(),
            fetched_unix_ms: 0,
        });
        let mut buf_empty = Vec::new();
        original_empty.encode(&mut buf_empty);
        let (decoded_empty, _) =
            LinkMessage::decode(&buf_empty).expect("decode of empty OcspResponse should succeed");
        assert_eq!(decoded_empty, original_empty);
    }

    #[test]
    fn test_link_message_invalid_tag() {
        // Tag = 99 (no such variant), body_len = 0 (well-formed header).
        let mut buf = Vec::new();
        buf.push(99u8);
        buf.extend_from_slice(&0u32.to_le_bytes());
        let err = LinkMessage::decode(&buf).expect_err("decode of tag=99 should fail");
        match err {
            NetError::Io(io_err) => {
                assert_eq!(io_err.kind(), ErrorKind::InvalidData);
            }
            other => panic!("expected NetError::Io(InvalidData), got {other:?}"),
        }

        // Tag = 0 (also unknown) — same failure path.
        let mut buf_zero = Vec::new();
        buf_zero.push(0u8);
        buf_zero.extend_from_slice(&0u32.to_le_bytes());
        let err_zero = LinkMessage::decode(&buf_zero).expect_err("decode of tag=0 should fail");
        match err_zero {
            NetError::Io(io_err) => {
                assert_eq!(io_err.kind(), ErrorKind::InvalidData);
            }
            other => panic!("expected NetError::Io(InvalidData), got {other:?}"),
        }
    }

    #[test]
    fn test_link_message_oversized_frame() {
        // Construct a header declaring body_len = 20 MiB (> 16 MiB
        // MAX_FRAME_SIZE cap) without actually allocating the body.
        let oversized_body_len: u32 = 20 * 1024 * 1024;
        let mut buf = Vec::with_capacity(HEADER_LEN);
        buf.push(TAG_LOG);
        buf.extend_from_slice(&oversized_body_len.to_le_bytes());

        let err = LinkMessage::decode(&buf).expect_err("oversized body_len must be rejected");
        match err {
            NetError::Io(io_err) => {
                assert_eq!(io_err.kind(), ErrorKind::InvalidData);
                let msg = io_err.to_string();
                assert!(
                    msg.contains("MAX_FRAME_SIZE"),
                    "error message {msg:?} should mention MAX_FRAME_SIZE"
                );
            }
            other => panic!("expected NetError::Io(InvalidData), got {other:?}"),
        }
    }

    // --- Registry test -------------------------------------------------------

    #[test]
    fn test_register_and_drain_child_pids() {
        // The CHILD_PIDS registry is process-global; other tests in this
        // file do not touch it (they only exercise the codec), but we
        // drain any stale entries first so that assertions below are
        // deterministic even under repeated `cargo test` runs on the
        // same process.
        {
            let mut guard = child_pids().lock().expect("registry not poisoned");
            guard.clear();
        }

        // Register three deliberately-fake high PIDs, well outside the
        // range of any real PID on a reasonable system (default
        // `kernel.pid_max` is 4_194_304 on 64-bit Linux, but
        // `2_000_001..=2_000_003` is high enough that we will not
        // collide with this test process's PID or any daemon).
        let fake_pids_raw: [i32; 3] = [2_000_001, 2_000_002, 2_000_003];
        for &raw in &fake_pids_raw {
            register_child_pid(Pid::from_raw(raw));
        }

        // Drain and collect into raw i32s so that ordering is easy to
        // assert.
        let drained: Vec<i32> = {
            let mut guard = child_pids().lock().expect("registry not poisoned");
            guard.drain(..).map(|p| p.as_raw()).collect()
        };
        assert_eq!(drained.len(), 3, "expected 3 drained PIDs, got {drained:?}");
        for &expected in &fake_pids_raw {
            assert!(
                drained.contains(&expected),
                "expected fake pid {expected} in drained list {drained:?}"
            );
        }

        // Registry must now be empty, so a subsequent drain returns
        // nothing and `killall_children` is a no-op.
        {
            let guard = child_pids().lock().expect("registry not poisoned");
            assert!(
                guard.is_empty(),
                "registry should be empty after drain, got {guard:?}"
            );
        }
        killall_children();
    }
}
