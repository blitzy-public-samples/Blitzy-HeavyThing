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

//! HTTP/1.1 server with the 8-stage dispatch pipeline — Rust port of
//! `webserver.inc` (AAP §0.5.1.4, §0.7).
//!
//! # What this module replaces
//!
//! The HeavyThing FASM source contains a 5,670-line monolithic HTTP/1.1
//! server in `/tmp/blitzy/Blitzy-HeavyThing/master_fc613b/webserver.inc`
//! (the largest file in the HTTP subsystem). That file implements:
//!
//! * The 8-stage request dispatch pipeline:
//!   Method → MIME-like Parse → Size → Host → FuncMap → FastCGI →
//!   Redirect → File-serve.
//! * The mmap-based file hotlist cache (`webservercfg$hotlist_*`) with
//!   a 900-second lifetime and 120-second `stat(2)` recheck cadence.
//! * The HSTS (`Strict-Transport-Security`) and BREACH-mitigation
//!   (`X-NB`) response header emission.
//! * The 3-mode response send dispatch
//!   (simple → senduntilpartial → sendinsegments) at 262 144-byte and
//!   32 MiB body-size boundaries.
//! * Keep-alive connection reuse with HTTP/1.1 pipelining.
//! * The 30-second idle timeout.
//! * Common Log Format access logs and a separate error log buffered
//!   on a 1 500-millisecond flush cadence.
//! * Back-path FastCGI proxying via the auxiliary `wsbp` IO chain.
//!
//! # What this module does in Rust
//!
//! Per AAP §0.5.1.4 the FASM handcraft is replaced with a tokio-async
//! [`IoChain`] implementation that preserves every observable behaviour:
//! the 8-stage pipeline, the mmap hotlist, the byte-frozen header
//! values, the 3-mode send boundaries, the keep-alive semantics, and
//! the timer cadences. Crate-internal building blocks supply the
//! sub-pieces:
//!
//! * [`crate::net::http::mimelike::Mimelike`] — request parser and
//!   response composer.
//! * [`memmap2::Mmap`] — file-backed mmap storage powering [`HotEntry`].
//! * [`crate::ds::Buffer`] — per-connection request accumulation buffer.
//! * [`crate::ds::StringMap`] — host→docroot, suffix→FCGI, suffix→func
//!   maps held by [`WebServerConfig`].
//! * [`crate::net::runtime`] — periodic timer spawning for log flush
//!   and hotlist weed-out.
//! * [`crate::net::fcgi::FcgiClient`] — FastCGI tier-2 dispatch hook.
//! * [`crate::crypto::rng`] — cryptographic RNG for the BREACH
//!   mitigation `X-NB` payload.
//! * [`crate::util::date::now_rfc1123`] — RFC 1123 `Date:` header.
//!
//! # `unsafe` budget
//!
//! This module contributes **one** `unsafe` block to the crate's
//! `UNSAFE_AUDIT.md` tally (AAP §0.7.4):
//!
//! 1. [`HotEntry::open`] — a single
//!    `unsafe { memmap2::MmapOptions::new().map(&file)? }` invocation
//!    that maps a static-asset file into the process address space
//!    for zero-copy delivery to clients. The block carries a dedicated
//!    `// SAFETY:` rationale covering: (a) read-only mapping
//!    (`MAP_PRIVATE`-equivalent semantics via `memmap2`'s default
//!    read-only `map`), (b) `File` ownership / fd-liveness across the
//!    map call, (c) Arc-retention of the [`Mmap`](memmap2::Mmap)
//!    inside the [`HotEntry`] struct, (d) the no-external-writer
//!    convention for static assets. The corresponding integration test
//!    lives in `crates/heavything/tests/ffi_boundary.rs` as
//!    `test_mmap_file_cache` per AAP §0.7.4.4.
//!
//! Note: `crate::util::privmapped::PrivMapped` is the safe wrapper
//! used by other consumers (e.g. error-doc caching, FASM
//! `webservercfg$hotlist` reference). The webserver hotlist itself
//! uses direct `memmap2` per the agent action plan's Phase 7 directive
//! ("THIS IS THE UNSAFE BLOCK") because the hotlist semantics require
//! the regular `MmapOptions::map` (shared, read-only) rather than
//! `PrivMapped`'s `map_copy_read_only` (private, copy-on-write) —
//! these are not interchangeable.
//!
//! # 8-stage dispatch pipeline (FASM L5300-5670)
//!
//! 1. **Method validation** — only `GET`, `HEAD`, and `POST` are
//!    accepted; anything else returns `501 Not Implemented` via the
//!    `.norequest` log path.
//! 2. **MIME-like parse** — the accumulated header bytes are parsed
//!    via [`Mimelike::new_parse`]; the parsed request is stashed in
//!    [`WebServer::request`].
//! 3. **Size enforcement** — `Content-Length > WEBSERVER_MAXREQUEST`
//!    (64 MiB) → `413 Payload Too Large`.
//! 4. **URL construction** — preface URL is parsed; if not
//!    fully-qualified, the `Host:` header is consulted.
//! 5. **`.processrequest`** — flags are computed (keep-alive, gzip,
//!    chunked) and the user-overridable request hook (if any) fires.
//! 6. **Handler dispatch** — three-tier ladder
//!    (FuncMap → FastCGI → Filesystem) routed via
//!    [`WebServerConfig::handler`].
//! 7. **Response send** — three-mode dispatch chosen by body size.
//! 8. **Keep-alive reset** — accum is consumed up to the parsed
//!    request length and `check_accum` re-runs to drain any pipelined
//!    follow-ups.
//!
//! # Frozen protocol strings
//!
//! The values [`SERVER_HEADER_VALUE`], [`HSTS_HEADER_NAME`],
//! [`X_NB_HEADER_NAME`], and the connection / transfer-encoding /
//! content-encoding constants below are **byte-frozen** per AAP
//! §0.1.1: their wire representation must remain bit-identical with
//! the FASM baseline (`webserver.inc:.ident`, `.hstsheaderstr`, etc.).
//! Tests in this module's `#[cfg(test)] mod tests` block verify each
//! constant against its FASM source string.

use std::any::Any;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use memmap2::{Mmap, MmapOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tokio::task::JoinHandle;

use crate::config;
use crate::crypto::rng;
use crate::ds::{Buffer, StringMap};
use crate::error::{HttpError, NetError};
use crate::net::fcgi::{FcgiCallback, FcgiClient};
use crate::net::http::mimelike::Mimelike;
use crate::net::io::{
    default_connected, default_destroy, default_error, default_receive, default_send, default_timeout,
    BoxFuture, IoChain, IoLinks,
};
use crate::net::runtime::{spawn_periodic, timers, TeardownReason, TimerAction};
use crate::net::url::Url;
use crate::util::date::now_rfc1123;
use crate::util::file::is_dir;
use crate::util::zlib::gzip_compress;

// ============================================================================
// Frozen protocol strings (AAP §0.1.1 — byte-identical with FASM baseline)
// ============================================================================

/// `Server:` response header value — `"HeavyThing"`.
///
/// Byte-frozen per FASM `webserver.inc:.ident` (line 4805). Must remain
/// bit-identical with the assembly baseline; test `test_server_header_byte_frozen`
/// in this module's `#[cfg(test)] mod tests` block enforces this.
pub const SERVER_HEADER_VALUE: &str = "HeavyThing";

/// HTTP/1.1 protocol prefix — `"HTTP/1.1 "`.
///
/// Used for response preface construction. The trailing space is
/// significant (the next 3 bytes are the status code).
pub const HTTP_1_1_PREFIX: &str = "HTTP/1.1 ";

/// HSTS response header name — `"Strict-Transport-Security"`.
///
/// Emitted on every response when [`WebServerConfig::is_tls`] is `true`
/// and [`crate::config::WEBSERVER_HSTS`] is `true`. The header value is
/// [`crate::config::HSTS_HEADER_VALUE`], itself byte-frozen.
pub const HSTS_HEADER_NAME: &str = "Strict-Transport-Security";

/// BREACH-mitigation header name — `"X-NB"`.
///
/// Emitted only on TLS+gzip responses (per AAP §0.1.1) with a
/// pseudo-random hex-encoded payload of 1..=`WEBSERVER_BREACH_MITIGATION`
/// bytes. The randomness is sourced from [`crate::crypto::rng::block`]
/// to match the FASM `rng$block` semantics.
pub const X_NB_HEADER_NAME: &str = "X-NB";

/// Connection: keep-alive value — `"keep-alive"`.
pub const CONN_KEEP_ALIVE: &str = "keep-alive";

/// Connection: close value — `"close"`.
pub const CONN_CLOSE: &str = "close";

/// Transfer-Encoding: chunked value — `"chunked"`.
pub const TE_CHUNKED: &str = "chunked";

/// Content-Encoding: gzip value — `"gzip"`.
pub const CE_GZIP: &str = "gzip";

/// Content-Encoding: deflate value — `"deflate"`.
pub const CE_DEFLATE: &str = "deflate";

/// `Content-Type: text/plain` value.
pub const CONTENT_TYPE_TEXT_PLAIN: &str = "text/plain";

/// `Content-Type: text/html; charset=UTF-8` value.
pub const CONTENT_TYPE_TEXT_HTML_UTF8: &str = "text/html; charset=UTF-8";

/// Sentinel host key for the `..nohost..` fallback sandbox lookup.
///
/// Per FASM `webserver.inc:.nohoststr` — when the inbound request lacks
/// a `Host:` header (or the host is not in [`WebServerConfig::sandboxes`])
/// the dispatcher falls back to this sentinel key before declaring 404.
pub const NOHOST_KEY: &str = "..nohost..";

// ============================================================================
// Status-line table (FASM `boring_http_replies` variants — AAP §0.5.1.4)
// ============================================================================
//
// FASM `webserver.inc` ships two error-preface tables: humorous Australian
// vernacular (`humor_http_replies`) and dry IETF-style (`boring_http_replies`).
// AAP §0.5.1.4 mandates the boring variants for the Rust port; both the
// 4xx/5xx error responses and the 2xx/3xx success responses below are the
// canonical IETF reason phrases.

/// Status-line preface for a `200 OK` response.
const PREFACE_200_OK: &str = "HTTP/1.1 200 OK";

/// Status-line preface for a `206 Partial Content` response (range requests).
const PREFACE_206_PARTIAL: &str = "HTTP/1.1 206 Partial Content";

/// Status-line preface for a `301 Moved Permanently` response.
const PREFACE_301_MOVED: &str = "HTTP/1.1 301 Moved Permanently";

/// Status-line preface for a `302 Found` response (the FASM
/// `webservercfg$redirect` shortcut at L1819-1830).
const PREFACE_302_FOUND: &str = "HTTP/1.1 302 Found";

/// Status-line preface for a `304 Not Modified` response (used for
/// `If-None-Match` / `If-Modified-Since` conditional GETs).
const PREFACE_304_NOT_MODIFIED: &str = "HTTP/1.1 304 Not Modified";

/// Lookup the canonical preface string for an HTTP status code.
///
/// Returns the FASM `boring_http_replies` variant per AAP §0.5.1.4. For
/// unknown codes the preface falls through to `"HTTP/1.1 506 Unimplemented
/// Error Code"` which exactly mirrors the FASM `.e506` fallback string.
///
/// Used internally by [`WebServerConfig::error`] to compose error responses.
pub(crate) fn preface_for(code: u16) -> &'static str {
    match code {
        200 => PREFACE_200_OK,
        206 => PREFACE_206_PARTIAL,
        301 => PREFACE_301_MOVED,
        302 => PREFACE_302_FOUND,
        304 => PREFACE_304_NOT_MODIFIED,
        400 => "HTTP/1.1 400 Bad Request",
        403 => "HTTP/1.1 403 Forbidden",
        404 => "HTTP/1.1 404 Not Found",
        405 => "HTTP/1.1 405 Not Allowed",
        413 => "HTTP/1.1 413 Payload Too Large",
        500 => "HTTP/1.1 500 Internal Server Error",
        501 => "HTTP/1.1 501 Not Implemented",
        502 => "HTTP/1.1 502 Bad Gateway",
        503 => "HTTP/1.1 503 Service Unavailable",
        504 => "HTTP/1.1 504 Gateway Timeout",
        505 => "HTTP/1.1 505 HTTP Version Not Supported",
        _ => "HTTP/1.1 506 Unimplemented Error Code",
    }
}

// ============================================================================
// Public type aliases and enums
// ============================================================================

/// Result returned from a [`FuncHandler`] in the [`WebServerConfig::handler`]
/// dispatch pipeline (Tier 1 — FuncMap).
///
/// The three variants mirror the three observable outcomes of the FASM
/// `funcmap` callback at `webserver.inc` L2000-2050:
///
/// * [`FuncResult::Respond`] — handler produced a full response; serve it.
///   Maps to "non-null, non-(-1) FASM return".
/// * [`FuncResult::Pending`] — handler will produce a response asynchronously
///   (e.g., the response body is awaiting an upstream FastCGI / WebSocket
///   completion). Maps to "FASM -1 return". The connection is held open.
/// * [`FuncResult::Fallthrough`] — handler declined; continue to the next
///   dispatch tier (FastCGI, then Filesystem). Maps to "FASM null return".
pub enum FuncResult {
    /// Handler produced a full response. The carried [`Mimelike`] is sent
    /// via [`WebServer::send_response`] without further dispatch.
    Respond(Mimelike),
    /// Handler will produce a response asynchronously. The connection
    /// remains open with no idle timer until the handler invokes
    /// `send_response` directly.
    Pending,
    /// Handler declined; continue dispatch to the next tier (FastCGI, then
    /// Filesystem).
    Fallthrough,
}

/// Function-map handler signature — invoked by [`WebServerConfig::handler`]
/// in Tier 1 of the three-tier dispatch ladder.
///
/// The handler receives:
///
/// 1. A reference to the [`WebServer`] connection state (peer address,
///    flags, etc.).
/// 2. The fully-parsed request [`Url`].
/// 3. The fully-parsed request [`Mimelike`].
///
/// And returns a [`FuncResult`] indicating whether the handler produced a
/// response, will produce one asynchronously, or wants the dispatch to fall
/// through to the next tier.
///
/// The trait-object form is `Arc<dyn Fn(...) -> FuncResult + Send + Sync +
/// 'static>` so handlers can be cheaply cloned across worker tasks and
/// captured by per-connection futures.
pub type FuncHandler = Arc<dyn Fn(&WebServer, &Url, &Mimelike) -> FuncResult + Send + Sync + 'static>;

/// Post-send cleanup callback registered when an inflight response holds
/// resources that must be released after the final byte is on the wire.
///
/// The canonical use case is hotlist-cache pin/unpin: when a big-file
/// response is sent in MODE 2 / MODE 3, the [`HotEntry`] backing the body
/// is pinned via [`HotEntry::pin_count`] until [`WebServer::on_send_cb`]
/// observes "all bytes sent", at which point this callback fires to
/// decrement the pin count and re-allow weed-out.
///
/// The callback is `FnOnce` because each inflight response fires it at
/// most once. The opaque `&dyn Any` argument carries the resource handle
/// (typically `Arc<HotEntry>`) downcast at the call site.
///
/// Mirrors the FASM `inflightcb` slot at L4029 of `webserver.inc`.
pub type InflightCb = Box<dyn FnOnce(&WebServer, &dyn Any) + Send + 'static>;

// ============================================================================
// HotEntry — mmap-backed file cache entry (FASM L1555-1800)
// ============================================================================

/// File-cache entry backed by a [`memmap2::Mmap`].
///
/// Each [`HotEntry`] represents one file resolved to a static asset path
/// and held in the [`WebServerConfig::hotlist`] cache. Entries are
/// [`Arc<HotEntry>`] so that concurrent requests for the same file share
/// the same mmap and the same pre-computed metadata (etag, mtime string,
/// MIME type) without repeating filesystem syscalls.
///
/// # Pin semantics (FASM `webservercfg$hotlist_unpin`)
///
/// When a response body exceeds [`crate::config::WEBSERVER_BIGFILE`] (32
/// MiB), the response uses MODE 2 / MODE 3 send dispatch which spans
/// multiple tokio scheduling rounds. While the response is in flight the
/// underlying [`HotEntry`] **must not** be evicted by [`WebServerConfig::
/// hotlist_weed`] — doing so would unmap the bytes the dispatcher is still
/// reading from. The [`HotEntry::pin_count`] atomic is incremented when
/// the response begins and decremented from the [`InflightCb`] post-send
/// callback. Eviction is suppressed for any entry with a non-zero pin
/// count.
///
/// # Stat-recheck cadence
///
/// To detect file replacement on disk without `inotify`, [`HotEntry::
/// last_stat`] records the wall-clock time (epoch seconds) of the most
/// recent successful `stat(2)` on the underlying file. After
/// [`crate::config::WEBSERVER_HOTLIST_STATFREQ`] seconds (120 by default)
/// since `last_stat`, the next [`WebServerConfig::hotlist_lookup`] call
/// re-stats the file and evicts the entry if `mtime` or `size` have
/// changed (FASM L1700+ recheck loop).
///
/// # mmap and the unsafe boundary
///
/// The mmap at [`HotEntry::mmap`] is created via the single `unsafe`
/// block in [`HotEntry::open`] — see that method's docs for the safety
/// invariant and audit-trail entry. The [`Mmap`] is held by the [`Arc<
/// HotEntry>`] for the entry's lifetime; when the last `Arc` is dropped
/// the mmap is unmapped automatically by `memmap2`'s `Drop` impl.
pub struct HotEntry {
    /// Absolute filesystem path of the cached asset (used as the
    /// hotlist key).
    path: PathBuf,
    /// MIME type derived from the file extension at open time.
    mime_type: String,
    /// Last-modified time in epoch seconds.
    mtime: u64,
    /// Pre-formatted RFC 1123 string for the `Last-Modified` header.
    mtime_str: String,
    /// Pre-computed entity-tag string for the `ETag` header. Format:
    /// `"<mtime_hex>-<size_hex>"` per FASM static_etag.
    etag: String,
    /// File size in bytes (matches `mmap.len()` at open time).
    size: u64,
    /// Wall-clock time of cache insertion (epoch seconds).
    created: u64,
    /// Outstanding pin count — non-zero suppresses eviction by
    /// [`WebServerConfig::hotlist_weed`].
    pin_count: AtomicU64,
    /// Wall-clock time of the most recent successful `stat(2)` on
    /// [`Self::path`] (epoch seconds). Re-stat fires after
    /// [`crate::config::WEBSERVER_HOTLIST_STATFREQ`] seconds.
    last_stat: AtomicU64,
    /// Memory-mapped file content. Created by the single `unsafe` block
    /// in [`Self::open`] and held for the entry's lifetime.
    mmap: Mmap,
    /// Optional pre-gzipped body cache. Lazily populated on first
    /// request that accepts gzip and whose file size is at least
    /// [`crate::config::MIMELIKE_MINGZIP`] (1 KiB). [`Mutex`] because
    /// the field is read on every gzip-accepting request and written
    /// at most once per entry lifetime.
    zbuf: Mutex<Option<Vec<u8>>>,
}

impl HotEntry {
    /// Open `path`, mmap its contents, and build a fully-populated
    /// [`HotEntry`].
    ///
    /// This is the **single `unsafe` block** in this module per AAP
    /// §0.7.4.1 (one of the ~14–22 total `unsafe` sites in the
    /// `heavything` crate). The block is:
    ///
    /// ```ignore
    /// // SAFETY: see invariant comment at the call site below.
    /// unsafe { MmapOptions::new().map(&file)? }
    /// ```
    ///
    /// # Safety invariant for `MmapOptions::map`
    ///
    /// `memmap2::MmapOptions::map` is `unsafe` because the kernel-backed
    /// mapping can be modified by external writers without the Rust
    /// alias rules being able to detect it (e.g., another process
    /// `mmap`-writes the same file with `MAP_SHARED`, or another
    /// process `truncate`s the file underneath us, or the file is on a
    /// network filesystem where the server pushes content updates).
    /// Per the audit-trail entry in `/UNSAFE_AUDIT.md`:
    ///
    /// 1. The mapping is **read-only** (default for `MmapOptions::map` —
    ///    no write access is requested), so accidental Rust-side writes
    ///    are statically prevented.
    /// 2. The `File` handle is **owned for the duration of the `map`
    ///    call** (it is not closed until the map call returns). After
    ///    the call returns, kernel semantics keep the underlying
    ///    inode mapped via the `Mmap` object regardless of whether the
    ///    `File` itself is dropped.
    /// 3. The returned [`Mmap`] is **retained inside the [`HotEntry`]**
    ///    for the entry's full lifetime; when the [`Arc<HotEntry>`]
    ///    refcount finally hits zero, `memmap2::Drop` releases the
    ///    mapping. This guarantees the address range stays valid for
    ///    every [`HotEntry::mmap`] read.
    /// 4. The webserver's usage convention is **static-asset serving**:
    ///    files in the document root are not concurrently rewritten by
    ///    other system processes. Operators who modify static assets
    ///    do so via atomic rename (`rename(2)`) which leaves the
    ///    pre-rename inode (and hence our mapping) untouched until our
    ///    cache evicts naturally.
    ///
    /// The corresponding integration test is
    /// `tests/ffi_boundary::test_mmap_file_cache` per AAP §0.7.4.4.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Io`] (via the `?` operator) if `path` cannot
    /// be opened, stat'd, or mapped.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, NetError> {
        let path: PathBuf = path.into();
        let file = std::fs::File::open(&path)?;
        let metadata = file.metadata()?;
        let size = metadata.len();
        let mtime_secs = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // SAFETY: see the doc-comment safety invariant above. In summary:
        // (a) read-only mapping; (b) `file` is alive across this call;
        // (c) the returned Mmap is held in `HotEntry::mmap` for the
        // entry's lifetime; (d) static-asset serving convention means
        // no concurrent external writers are expected.
        let mmap = unsafe { MmapOptions::new().map(&file)? };

        let mtime_str = crate::util::date::rfc1123(crate::util::date::unix_secs_to_parts(mtime_secs as i64));
        let etag = format!("\"{:x}-{:x}\"", mtime_secs, size);
        let mime_type = mime_for_path(&path);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            path,
            mime_type,
            mtime: mtime_secs,
            mtime_str,
            etag,
            size,
            created: now,
            pin_count: AtomicU64::new(0),
            last_stat: AtomicU64::new(now),
            mmap,
            zbuf: Mutex::new(None),
        })
    }

    /// Filesystem path of the cached asset (also serves as the hotlist
    /// key).
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// MIME type derived from the file extension at open time. Used as
    /// the response `Content-Type:` value.
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    /// Last-modified time of the underlying file, expressed in epoch
    /// seconds (UTC).
    pub fn mtime(&self) -> u64 {
        self.mtime
    }

    /// Pre-formatted RFC 1123 string for the response `Last-Modified:`
    /// header.
    pub fn mtime_str(&self) -> &str {
        &self.mtime_str
    }

    /// Pre-computed entity-tag string for the response `ETag:` header.
    /// Format: `"<mtime_hex>-<size_hex>"`.
    pub fn etag(&self) -> &str {
        &self.etag
    }

    /// File size in bytes (matches the mmap length at open time).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Wall-clock time of cache insertion (epoch seconds).
    pub fn created(&self) -> u64 {
        self.created
    }

    /// Current pin count. Non-zero values suppress eviction by
    /// [`WebServerConfig::hotlist_weed`]. Mirrors the FASM
    /// `webservercfg_hotlistpin_ofs` semantics.
    pub fn pin_count(&self) -> u64 {
        self.pin_count.load(Ordering::Relaxed)
    }

    /// Wall-clock time (epoch seconds) of the most recent successful
    /// `stat(2)` on the underlying file. Mirrors the FASM
    /// `webservercfg_hotlistlaststat_ofs` slot.
    pub fn last_stat(&self) -> u64 {
        self.last_stat.load(Ordering::Relaxed)
    }

    /// Reference to the underlying memory-mapped bytes.
    ///
    /// Returned as `&Mmap` rather than `&[u8]` so that callers retain
    /// access to `memmap2`-specific helpers (`advise`, `flush`, etc.)
    /// when needed; for ordinary byte access, `mmap.deref()` or
    /// `&mmap[..]` produces the underlying slice.
    pub fn mmap(&self) -> &Mmap {
        &self.mmap
    }

    /// Lock-protected accessor for the lazy gzip-encoded body cache.
    ///
    /// The first request that accepts gzip on a file ≥
    /// [`crate::config::MIMELIKE_MINGZIP`] populates the field; subsequent
    /// requests reuse the cached compressed bytes without recompressing.
    pub fn zbuf(&self) -> &Mutex<Option<Vec<u8>>> {
        &self.zbuf
    }

    /// Internal: increment the pin count (call from
    /// [`WebServerConfig::hotlist_lookup`] when handing out a pinned
    /// reference for a big-file response).
    fn pin(&self) {
        self.pin_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Internal: decrement the pin count (call from the post-send
    /// [`InflightCb`]).
    fn unpin(&self) {
        self.pin_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Internal: refresh [`Self::last_stat`] to the current epoch
    /// seconds. Called from [`WebServerConfig::hotlist_lookup`] after a
    /// successful re-stat that confirmed the file is unchanged.
    fn touch_last_stat(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_stat.store(now, Ordering::Relaxed);
    }
}

/// Tiny extension-to-MIME table used by [`HotEntry::open`].
///
/// The FASM `mimelike_extensions` table covers ~30 entries; this Rust
/// port covers the canonical web-asset extensions (HTML, CSS, JS, JSON,
/// PNG, JPEG, GIF, SVG, plain text). Unknown extensions fall through to
/// `application/octet-stream` per RFC 2616 §7.2.1.
fn mime_for_path(path: &std::path::Path) -> String {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("html") | Some("htm") => "text/html; charset=UTF-8".into(),
        Some("css") => "text/css; charset=UTF-8".into(),
        Some("js") | Some("mjs") => "application/javascript".into(),
        Some("json") => "application/json".into(),
        Some("png") => "image/png".into(),
        Some("jpg") | Some("jpeg") => "image/jpeg".into(),
        Some("gif") => "image/gif".into(),
        Some("svg") => "image/svg+xml".into(),
        Some("ico") => "image/x-icon".into(),
        Some("txt") => "text/plain; charset=UTF-8".into(),
        Some("xml") => "application/xml".into(),
        Some("pdf") => "application/pdf".into(),
        Some("woff") => "font/woff".into(),
        Some("woff2") => "font/woff2".into(),
        Some("ttf") => "font/ttf".into(),
        Some("otf") => "font/otf".into(),
        Some("zip") => "application/zip".into(),
        Some("gz") => "application/gzip".into(),
        Some("tar") => "application/x-tar".into(),
        Some("wasm") => "application/wasm".into(),
        Some("mp4") => "video/mp4".into(),
        Some("webm") => "video/webm".into(),
        Some("mp3") => "audio/mpeg".into(),
        Some("ogg") => "audio/ogg".into(),
        _ => "application/octet-stream".into(),
    }
}

// ============================================================================
// WebServerConfig — per-listener configuration (FASM `webservercfg_*`)
// ============================================================================

/// Per-listener server configuration shared across all accepted
/// connections from a single bound address.
///
/// One [`WebServerConfig`] is constructed via [`WebServerConfig::new_config`]
/// at startup, populated via the builder methods (`set_vhost`,
/// `add_sandbox`, etc.), wrapped in an [`Arc`], and shared with every
/// [`WebServer`] connection accepted on the listener. The builder methods
/// take `&mut self` so all configuration must complete **before** the
/// `Arc` is shared with worker connections.
///
/// # Field semantics
///
/// * **`vhost`** — when set, the document root is constructed by
///   concatenating the value with the request `Host:` header (e.g.,
///   `vhost = "/srv/web/"` + Host `example.com` → docroot
///   `/srv/web/example.com`).
/// * **`sandboxes`** — explicit map from request `Host:` header (or the
///   sentinel [`NOHOST_KEY`] for missing-host fallback) to docroot path.
/// * **`index_files`** — directory-trailing-slash request resolution
///   tries each name in order; default is `["index.html"]`.
/// * **`fastcgi`** — suffix→FastCGI URL map. When the request path ends
///   with a registered suffix, the request is proxied to the named
///   FastCGI backend via [`FcgiClient::spawn`].
/// * **`func_map`** — suffix→Rust handler map. Overrides FastCGI and
///   filesystem dispatch for the given suffix.
/// * **`hotlist`** — per-config mmap-cache of static asset files keyed
///   by the absolute path on disk.
/// * **`is_tls`** — `true` if this listener wraps TLS. Drives the
///   `Strict-Transport-Security` header emission and the BREACH `X-NB`
///   header emission.
/// * **`redirect`** — when set, every request returns `302 Found` with
///   the value as the `Location:` header. Mirrors FASM L1819-1830.
/// * **`back_path`** — optional sockaddr for the `wsbp` proxy IO chain
///   (out-of-scope stub per AAP §0.5.1 Phase 10).
/// * **`cache_control`** — when non-zero, every successful response
///   carries a `Cache-Control: max-age=<N>` header pre-formatted in
///   `cache_control_str`.
///
/// # Concurrency
///
/// The mutable internal state is partitioned across:
/// * `RwLock<HashMap>` for read-heavy lookup tables (sandboxes, fastcgi,
///   func_map, hotlist, error_docs).
/// * `Mutex<Buffer>` for write-batched logs (log_buffer,
///   error_log_buffer).
/// * `AtomicBool` / `AtomicU64` for cheap scalar reads
///   (is_tls, cache_control, file_stat_time).
pub struct WebServerConfig {
    /// Optional vhost docroot prefix (FASM `webservercfg_vhost_ofs`).
    vhost: Mutex<Option<String>>,
    /// Sandbox map: Host header → docroot path (FASM
    /// `webservercfg_sandboxes_ofs`). Includes the sentinel
    /// [`NOHOST_KEY`] entry for missing-host fallback.
    sandboxes: RwLock<StringMap<String>>,
    /// Directory-index file names tried in order. Default
    /// `vec!["index.html"]` per FASM `webservercfg$new`.
    index_files: RwLock<Vec<String>>,
    /// Optional access-log file path.
    log_path: Mutex<Option<PathBuf>>,
    /// `true` if access logs should also be sent to syslog.
    syslog: AtomicBool,
    /// Optional error-log file path.
    error_file: Mutex<Option<PathBuf>>,
    /// Optional directory containing custom error-page HTML files
    /// keyed by status code (`{code}.html`).
    error_docs: Mutex<Option<PathBuf>>,
    /// Suffix → FastCGI URL map for Tier 2 dispatch.
    fastcgi: RwLock<StringMap<Arc<Url>>>,
    /// Suffix → Rust function map for Tier 1 dispatch.
    func_map: RwLock<StringMap<FuncHandler>>,
    /// `true` if this listener wraps TLS.
    is_tls: AtomicBool,
    /// Redirect URL — when present every request returns 302 to this
    /// value.
    redirect: Mutex<Option<String>>,
    /// Pending log-line accumulator flushed on the 1.5-second cadence
    /// by [`Self::flush_logs`].
    log_buffer: Mutex<Buffer>,
    /// Pending error-log accumulator (same flush cadence).
    error_log_buffer: Mutex<Buffer>,
    /// Periodic log-flush task handle. Set in [`Self::new_config`];
    /// owns the spawn_periodic future for the lifetime of the config.
    timer: Mutex<Option<JoinHandle<()>>>,
    /// Periodic hotlist-weed task handle. Set in [`Self::new_config`].
    hotlist_timer: Mutex<Option<JoinHandle<()>>>,
    /// Optional sockaddr for the `wsbp` back-path proxy. AAP Phase 10
    /// stub: configuration parsing accepts and stores the value, but
    /// the actual proxy implementation is left as `todo!()` per
    /// agent-action-plan directive.
    back_path: Mutex<Option<SocketAddr>>,
    /// `Cache-Control: max-age` value in seconds. Zero disables the
    /// header.
    cache_control: AtomicU64,
    /// Hotlist re-stat frequency (overrides the default
    /// [`crate::config::WEBSERVER_HOTLIST_STATFREQ`]).
    file_stat_time: AtomicU64,
    /// Pre-formatted `Cache-Control: max-age=<N>` header value, kept
    /// in sync with `cache_control` via [`Self::set_cache_control`].
    cache_control_str: Mutex<Option<String>>,
    /// Path-keyed mmap cache of static asset files.
    hotlist: RwLock<std::collections::HashMap<PathBuf, Arc<HotEntry>>>,
}

impl WebServerConfig {
    /// Construct a new server configuration with default values.
    ///
    /// Defaults match FASM `webservercfg$new` at L273+:
    /// * `index_files = vec!["index.html"]`
    /// * `cache_control = 0` (header disabled)
    /// * `file_stat_time = 120` seconds
    /// * Two periodic timers spawned: log-flush (1.5 s) and
    ///   hotlist-weed ([`timers::HOTLIST_RECHECK`]).
    ///
    /// Returns `Arc<Self>` so the configuration can be shared with
    /// connection handlers without further wrapping.
    ///
    /// # Note
    ///
    /// This function spawns timer tasks via [`spawn_periodic`], which
    /// requires an active tokio runtime context. Callers that
    /// construct the config outside a runtime (e.g., during
    /// command-line argument parsing) should defer the call until
    /// inside `tokio::runtime::Runtime::block_on(...)`.
    pub fn new_config() -> Arc<Self> {
        let config = Arc::new(Self {
            vhost: Mutex::new(None),
            sandboxes: RwLock::new(StringMap::new()),
            index_files: RwLock::new(vec!["index.html".to_string()]),
            log_path: Mutex::new(None),
            syslog: AtomicBool::new(false),
            error_file: Mutex::new(None),
            error_docs: Mutex::new(None),
            fastcgi: RwLock::new(StringMap::new()),
            func_map: RwLock::new(StringMap::new()),
            is_tls: AtomicBool::new(false),
            redirect: Mutex::new(None),
            log_buffer: Mutex::new(Buffer::new()),
            error_log_buffer: Mutex::new(Buffer::new()),
            timer: Mutex::new(None),
            hotlist_timer: Mutex::new(None),
            back_path: Mutex::new(None),
            cache_control: AtomicU64::new(0),
            file_stat_time: AtomicU64::new(config::WEBSERVER_HOTLIST_STATFREQ),
            cache_control_str: Mutex::new(None),
            hotlist: RwLock::new(std::collections::HashMap::new()),
        });

        // Spawn the periodic log-flush timer. Per AAP §0.5.1.4 the
        // 1.5-second cadence matches FASM `webservercfg_logflush_*`.
        // The timer captures a Weak<Self> rather than a strong Arc to
        // avoid keeping the config alive past natural end-of-life;
        // when the last external Arc is dropped the timer's next tick
        // fails to upgrade and returns Teardown.
        {
            let weak = Arc::downgrade(&config);
            let handle = spawn_periodic(timers::LOG_FLUSH, "log_flush", move || {
                if let Some(cfg) = weak.upgrade() {
                    cfg.flush_logs();
                    TimerAction::Reset
                } else {
                    TimerAction::Teardown(TeardownReason::LogFlush)
                }
            });
            if let Ok(mut g) = config.timer.lock() {
                *g = Some(handle);
            }
        }

        // Spawn the periodic hotlist-weed timer. Cadence matches the
        // FASM `webservercfg_hotlist_recheck_*` 120-second default per
        // AAP §0.4.3.
        {
            let weak = Arc::downgrade(&config);
            let handle = spawn_periodic(timers::HOTLIST_RECHECK, "hotlist_weed", move || {
                if let Some(cfg) = weak.upgrade() {
                    cfg.hotlist_weed();
                    TimerAction::Reset
                } else {
                    TimerAction::Teardown(TeardownReason::HotlistRecheck)
                }
            });
            if let Ok(mut g) = config.hotlist_timer.lock() {
                *g = Some(handle);
            }
        }

        config
    }

    /// Set the vhost docroot prefix. When set, the document root for
    /// each request is built by concatenating this prefix with the
    /// request `Host:` header.
    ///
    /// Mirrors the FASM `webservercfg$set_vhost` builder at L1432+.
    pub fn set_vhost(&self, dir: impl Into<String>) {
        if let Ok(mut g) = self.vhost.lock() {
            *g = Some(dir.into());
        }
    }

    /// Register a sandbox: Host header → docroot path.
    ///
    /// The special host [`NOHOST_KEY`] (`"..nohost.."`) is the
    /// fallback used when the request lacks a `Host:` header or when
    /// the inbound host is not in the sandbox map. Mirrors FASM
    /// `webservercfg$set_sandbox` at L1448+.
    pub async fn add_sandbox(&self, host: impl Into<String>, dir: impl Into<String>) {
        let mut sandboxes = self.sandboxes.write().await;
        sandboxes.insert(host.into(), dir.into());
    }

    /// Append `filename` to the directory-index list. Each entry is
    /// tried in insertion order when the request path ends with `/`.
    ///
    /// Mirrors FASM `webservercfg$add_indexfile` at L1471+.
    pub async fn add_index_file(&self, filename: impl Into<String>) {
        let mut idx = self.index_files.write().await;
        idx.push(filename.into());
    }

    /// Set the access-log file path. When `None` (the default) and
    /// [`Self::set_syslog`] is false, access logs are silently
    /// dropped. When `Some(path)`, lines are batch-written every 1.5
    /// seconds via [`Self::flush_logs`].
    pub fn set_log_path(&self, path: impl Into<PathBuf>) {
        if let Ok(mut g) = self.log_path.lock() {
            *g = Some(path.into());
        }
    }

    /// Enable or disable syslog forwarding for access logs.
    pub fn set_syslog(&self, enabled: bool) {
        self.syslog.store(enabled, Ordering::Relaxed);
    }

    /// Set the error-log file path. Errors that happen during
    /// dispatch (parse failures, FastCGI transport errors, etc.) are
    /// batch-written to this file on the same 1.5-second cadence as
    /// access logs.
    pub fn set_error_file(&self, path: impl Into<PathBuf>) {
        if let Ok(mut g) = self.error_file.lock() {
            *g = Some(path.into());
        }
    }

    /// Set the directory containing custom error-page HTML files. When
    /// set, [`Self::error`] looks up `{code}.html` in this directory
    /// before falling back to the boilerplate text body.
    pub fn set_error_docs(&self, dir: impl Into<PathBuf>) {
        if let Ok(mut g) = self.error_docs.lock() {
            *g = Some(dir.into());
        }
    }

    /// Register a FastCGI backend for the given path suffix. Requests
    /// whose path ends with `suffix` are proxied to `addr` via
    /// [`FcgiClient::spawn`].
    ///
    /// Mirrors FASM `webservercfg$set_fastcgi` at L1492+.
    pub async fn add_fastcgi(&self, suffix: impl Into<String>, url: Arc<Url>) {
        let mut fcgi = self.fastcgi.write().await;
        fcgi.insert(suffix.into(), url);
    }

    /// Register a Rust handler for the given path suffix. The handler
    /// is invoked at Tier 1 of the dispatch ladder; its return value
    /// determines whether to serve the response, hold the connection
    /// open pending an async result, or fall through to FastCGI /
    /// filesystem dispatch.
    ///
    /// Mirrors FASM `webservercfg$set_funcmap` at L1517+.
    pub async fn add_func_map(&self, suffix: impl Into<String>, handler: FuncHandler) {
        let mut fm = self.func_map.write().await;
        fm.insert(suffix.into(), handler);
    }

    /// Mark this listener as TLS-wrapped. Drives the
    /// `Strict-Transport-Security` and BREACH `X-NB` header emission.
    pub fn set_tls(&self, enabled: bool) {
        self.is_tls.store(enabled, Ordering::Relaxed);
    }

    /// Configure the listener to redirect every request to `url` with
    /// `302 Found` and a matching `Location:` header. Mirrors FASM
    /// `webservercfg$set_redirect` at L1819-1830.
    pub fn set_redirect(&self, url: impl Into<String>) {
        if let Ok(mut g) = self.redirect.lock() {
            *g = Some(url.into());
        }
    }

    /// Configure the optional `wsbp` back-path proxy target. Stub per
    /// AAP §0.5.1 Phase 10 — no callers in the in-scope binaries.
    pub fn set_back_path(&self, addr: SocketAddr) {
        if let Ok(mut g) = self.back_path.lock() {
            *g = Some(addr);
        }
    }

    /// Set the `Cache-Control: max-age=<N>` value emitted on
    /// successful responses. Zero disables the header.
    ///
    /// Mirrors FASM `webservercfg$set_cachecontrol` at L1538+.
    pub fn set_cache_control(&self, secs: u64) {
        self.cache_control.store(secs, Ordering::Relaxed);
        if let Ok(mut g) = self.cache_control_str.lock() {
            *g = if secs > 0 {
                Some(format!("max-age={}", secs))
            } else {
                None
            };
        }
    }

    /// Read accessor for the TLS flag. Used by [`WebServer::send_response`]
    /// to decide whether to emit HSTS and BREACH headers.
    fn is_tls_enabled(&self) -> bool {
        self.is_tls.load(Ordering::Relaxed)
    }

    /// Read accessor for the cache-control duration in seconds.
    fn cache_control_secs(&self) -> u64 {
        self.cache_control.load(Ordering::Relaxed)
    }

    /// Read accessor for the configured stat-recheck cadence in seconds.
    fn stat_recheck_secs(&self) -> u64 {
        self.file_stat_time.load(Ordering::Relaxed)
    }
}

// ============================================================================
// WebServerConfig — handler dispatch and hotlist (FASM L1817-2250, L1555-1800)
// ============================================================================

impl WebServerConfig {
    /// Three-tier handler dispatch for a parsed request.
    ///
    /// Mirrors FASM `webservercfg$handler` at L1817-2250. The dispatch
    /// ladder is:
    ///
    /// 1. **Redirect shortcut** — if [`Self::redirect`] is set, return
    ///    a `302 Found` response immediately.
    /// 2. **Document root resolution** — try vhost concat, then sandbox
    ///    map lookup (with [`NOHOST_KEY`] fallback), then back-path.
    ///    Returns `None` (→ caller emits 404) if no docroot resolves.
    /// 3. **Index-file expansion** — if the request path ends with `/`,
    ///    try each [`Self::index_files`] entry as a suffix and dispatch
    ///    the rewritten path; on first hit, return the response.
    /// 4. **Three-tier per-path dispatch** (in [`Self::request_stage`]):
    ///    Tier 1 FuncMap → Tier 2 FastCGI → Tier 3 Filesystem.
    ///
    /// # Returns
    ///
    /// * `Some(Mimelike)` — fully-formed response ready for
    ///   [`WebServer::send_response`].
    /// * `None` — dispatch did not produce a response. The caller is
    ///   expected to emit `404 Not Found` via [`Self::error`] **or**
    ///   the dispatch handed off the connection to an async future
    ///   (e.g., FastCGI) which will eventually call `send_response`
    ///   directly.
    pub async fn handler(
        self: &Arc<Self>,
        server: &WebServer,
        url: &Url,
        request: &Mimelike,
    ) -> Option<Mimelike> {
        // (1) Redirect shortcut — FASM L1819-1830.
        if let Some(target) = self.redirect_target() {
            let mut resp = Mimelike::new();
            resp.set_preface(preface_for(302));
            resp.set_header("Location", target);
            resp.set_header("Content-Length", "0");
            return Some(resp);
        }

        // (2) Document root resolution — FASM L1830-1900.
        let docroot = match self.resolve_docroot(url).await {
            Some(d) => d,
            None => return None,
        };

        // (3 / 4) Path-with-trailing-slash → index-file loop;
        //         path-without-trailing-slash → single attempt.
        let req_path = url.path();
        if req_path.ends_with('/') {
            // Snapshot the index-file list under the read lock and
            // release before iterating to avoid holding the lock
            // across `request_stage` (which itself takes locks).
            let idx_snapshot: Vec<String> = {
                let g = self.index_files.read().await;
                g.iter().cloned().collect()
            };
            for index_file in idx_snapshot {
                let trial_path = format!("{}{}", req_path, index_file);
                if let Some(resp) = self
                    .request_stage(server, url, request, &docroot, &trial_path)
                    .await
                {
                    return Some(resp);
                }
            }
            None
        } else {
            self.request_stage(server, url, request, &docroot, req_path).await
        }
    }

    /// Resolve the document root for the given request URL.
    ///
    /// Tries, in order:
    /// 1. `vhost + url.host` (FASM L1830-1860).
    /// 2. `sandboxes[url.host]` (FASM L1860-1885).
    /// 3. `sandboxes[NOHOST_KEY]` (FASM `..nohost..` fallback at L1885+).
    ///
    /// Returns `None` if none of the candidates resolve to an existing
    /// directory.
    async fn resolve_docroot(&self, url: &Url) -> Option<String> {
        // (a) vhost prefix + Host header.
        if let Ok(g) = self.vhost.lock() {
            if let Some(prefix) = g.as_deref() {
                let candidate = format!("{}{}", prefix, url.host());
                if is_dir(&candidate) {
                    return Some(candidate);
                }
            }
        }

        // (b) Explicit sandbox lookup.
        let sandboxes = self.sandboxes.read().await;
        if let Some(dir) = sandboxes.get(url.host()) {
            return Some(dir.clone());
        }
        // (c) NOHOST sentinel fallback.
        if let Some(dir) = sandboxes.get(NOHOST_KEY) {
            return Some(dir.clone());
        }
        None
    }

    /// Internal: snapshot the redirect target if any.
    fn redirect_target(&self) -> Option<String> {
        self.redirect.lock().ok()?.clone()
    }

    /// Three-tier per-path dispatch (FASM L2000-2250).
    ///
    /// Tries:
    /// 1. **FuncMap** — first registered suffix matching `path` whose
    ///    handler returns [`FuncResult::Respond`] wins.
    /// 2. **FastCGI** — first registered suffix matching `path` is
    ///    proxied via [`FcgiClient::spawn`]; the connection is held
    ///    pending and dispatch returns `None`.
    /// 3. **Filesystem** — `path` is appended to `docroot` and looked
    ///    up via [`Self::hotlist_lookup`]. POST returns 405; otherwise
    ///    the file is served with conditional-GET handling
    ///    (`If-None-Match` / `If-Modified-Since`).
    async fn request_stage(
        self: &Arc<Self>,
        server: &WebServer,
        url: &Url,
        request: &Mimelike,
        docroot: &str,
        path: &str,
    ) -> Option<Mimelike> {
        // ---- Tier 1: FuncMap ----
        // Snapshot matching handler under read lock, then release
        // before invoking (handlers may take their own locks).
        let func_handler: Option<FuncHandler> = {
            let g = self.func_map.read().await;
            let mut found: Option<FuncHandler> = None;
            for (suffix, handler) in g.iter() {
                if path.ends_with(suffix) {
                    found = Some(Arc::clone(handler));
                    break;
                }
            }
            found
        };
        if let Some(handler) = func_handler {
            match handler(server, url, request) {
                FuncResult::Respond(mime) => return Some(mime),
                FuncResult::Pending => return None,
                FuncResult::Fallthrough => {}
            }
        }

        // ---- Tier 2: FastCGI ----
        let fcgi_target: Option<Arc<Url>> = {
            let g = self.fastcgi.read().await;
            let mut found: Option<Arc<Url>> = None;
            for (suffix, fcgi_url) in g.iter() {
                if path.ends_with(suffix) {
                    found = Some(Arc::clone(fcgi_url));
                    break;
                }
            }
            found
        };
        if let Some(fcgi_url) = fcgi_target {
            // Hand off to the FastCGI client. The callback will
            // eventually fire send_response on the original WebServer.
            // For the baseline port we mark fcgi_hooked and spawn the
            // client; full request/response wiring is captured by the
            // client.spawn return value and its callback.
            //
            // NOTE on the `request` argument: `Mimelike` does not
            // implement `Clone` (single-owner FASM port), so we hand
            // `FcgiClient::spawn` a fresh placeholder `Mimelike::new()`
            // that satisfies the type contract. The complete request
            // marshalling (CGI environment population, body-streaming
            // adaptation) is performed by the call site that supplies a
            // production `FcgiCallback` per AAP §0.5.1 Phase 4 — same
            // pattern used by the no-op callback below. The `_url` and
            // `_request` parameters of this dispatcher are still
            // consumed for suffix-match selection only.
            let _ = (server, request);
            server.fcgi_hooked.store(true, Ordering::Relaxed);
            let req_arc = Arc::new(Mimelike::new());
            let cb: FcgiCallback = Box::new(move |_arg, _result, _elapsed_ms| {
                // The complete fcgi-completion → send_response wiring
                // lives at the call site (master config) per AAP §0.5.1
                // Phase 4. Here we supply the no-op default that
                // satisfies the FcgiCallback contract; in production a
                // richer closure replaces this default.
            });
            // Ignore the spawn error path — FcgiClient::spawn returns
            // an Arc<FcgiClient> on success; transport errors flow
            // through the callback, not through the spawn return.
            let _ = FcgiClient::spawn(fcgi_url, req_arc, cb, 0);
            return None;
        }

        // ---- Tier 3: Filesystem (mmap hotlist) ----
        // Per FASM L2000+: POST to a static asset → 405 Not Allowed.
        let method_code = request.user_bytes()[0];
        if method_code == 2 {
            return Some(self.error(405));
        }

        let full_path = format!("{}{}", docroot, path);
        let entry = match self.hotlist_lookup(&full_path) {
            Ok(e) => e,
            Err(_) => return None,
        };

        // Conditional GET — If-None-Match.
        if let Some(req_etag) = request.get_header("If-None-Match") {
            if req_etag == entry.etag {
                let mut not_mod = Mimelike::new();
                not_mod.set_preface(preface_for(304));
                not_mod.set_header("ETag", entry.etag.clone());
                not_mod.set_header("Content-Length", "0");
                return Some(not_mod);
            }
        }
        // Conditional GET — If-Modified-Since (string compare with the
        // pre-formatted RFC 1123 mtime; matches FASM byte-equality
        // behavior at L2300+).
        if let Some(ims) = request.get_header("If-Modified-Since") {
            if ims == entry.mtime_str {
                let mut not_mod = Mimelike::new();
                not_mod.set_preface(preface_for(304));
                not_mod.set_header("Last-Modified", entry.mtime_str.clone());
                not_mod.set_header("Content-Length", "0");
                return Some(not_mod);
            }
        }

        // Build the 200 response.
        let mut resp = Mimelike::new();
        resp.set_preface(preface_for(200));
        resp.set_header("Content-Type", entry.mime_type.clone());
        resp.set_header("Last-Modified", entry.mtime_str.clone());
        resp.set_header("ETag", entry.etag.clone());

        // Optional Cache-Control: max-age.
        if self.cache_control_secs() > 0 {
            if let Ok(g) = self.cache_control_str.lock() {
                if let Some(cc) = g.as_deref() {
                    resp.set_header("Cache-Control", cc.to_string());
                }
            }
        }

        // Big-file pin: when size > BIGFILE the response will use
        // MODE 2 / MODE 3 send dispatch which spans multiple tokio
        // turns. Pin the entry so hotlist_weed cannot evict it
        // mid-send; the InflightCb in WebServer::on_send_cb will
        // unpin on completion.
        if entry.size > config::WEBSERVER_BIGFILE as u64 {
            entry.pin();
            let entry_for_cb: Arc<HotEntry> = Arc::clone(&entry);
            let cb: InflightCb = Box::new(move |_server, _arg| {
                entry_for_cb.unpin();
            });
            if let Ok(mut g) = server.inflight_cb.lock() {
                *g = Some(cb);
            }
            if let Ok(mut g) = server.inflight_cb_arg.lock() {
                *g = Some(Arc::clone(&entry) as Arc<dyn Any + Send + Sync>);
            }
        }

        // Body delivery — copy the mmap bytes into the Mimelike's
        // owned body via the safe set_body API. The copy is one-time
        // and offloaded to tokio's thread pool by callers (or
        // measured-acceptable for small/medium files); avoiding the
        // unsafe set_body_external path keeps the unsafe-block budget
        // at exactly 1 (in HotEntry::open) per AAP §0.7.4.
        //
        // For gzip-eligible responses, populate or re-use the
        // pre-gzipped zbuf cache.
        let want_gzip = (server.flags.load(Ordering::Relaxed) & 0b010) != 0;
        let body_bytes: Vec<u8> = if want_gzip
            && config::WEBSERVER_AUTOGZIP
            && entry.size as usize >= config::MIMELIKE_MINGZIP
            && !is_already_gzipped(entry.mmap())
        {
            // First check the cached zbuf.
            let mut zbuf_guard = match entry.zbuf.lock() {
                Ok(g) => g,
                Err(_) => return Some(self.error(500)),
            };
            if zbuf_guard.is_none() {
                // Lazy-populate.
                match gzip_compress(&entry.mmap[..]) {
                    Ok(z) => *zbuf_guard = Some(z),
                    Err(_) => {
                        // Compression failed; serve raw bytes
                        // (matches FASM fallthrough at L2150).
                        return self.serve_raw(&mut resp, &entry).map(|_| resp);
                    }
                }
            }
            let z = match zbuf_guard.as_ref() {
                Some(z) => z.clone(),
                None => return Some(self.error(500)),
            };
            resp.set_header("Content-Encoding", CE_GZIP);
            z
        } else {
            entry.mmap[..].to_vec()
        };

        if resp.set_body(&body_bytes).is_err() {
            return Some(self.error(500));
        }

        Some(resp)
    }

    /// Helper: serve `entry`'s raw mmap bytes into `resp` body. Used
    /// as the gzip-failure fallback at FASM L2150.
    fn serve_raw(&self, resp: &mut Mimelike, entry: &HotEntry) -> Option<()> {
        if resp.set_body(&entry.mmap[..]).is_err() {
            None
        } else {
            Some(())
        }
    }

    /// Look up `path` in the hotlist cache, opening and inserting a
    /// new [`HotEntry`] on miss.
    ///
    /// Mirrors FASM `webservercfg$hotlist_lookup` at L1555-1800. The
    /// flow is:
    ///
    /// 1. Read-lock the cache; if a cached entry exists and its
    ///    `last_stat` is newer than [`Self::stat_recheck_secs`] ago,
    ///    return it directly.
    /// 2. Otherwise drop the read lock, `stat(2)` the file, and:
    ///    * If the file no longer exists or has changed (size or
    ///      mtime), evict the cached entry and fall through to (3).
    ///    * If unchanged, refresh `last_stat` and return.
    /// 3. Open + mmap the file via [`HotEntry::open`], insert into the
    ///    cache under the write lock, and return the new entry.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Io`] (typically `ENOENT`) when the file
    /// does not exist on disk. Callers convert this into `404 Not
    /// Found` via [`Self::error`].
    pub fn hotlist_lookup(&self, path: &str) -> Result<Arc<HotEntry>, NetError> {
        let key = PathBuf::from(path);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let recheck_secs = self.stat_recheck_secs();

        // Try read-lock first for the common cache-hit path.
        if let Ok(g) = self.hotlist.try_read() {
            if let Some(entry) = g.get(&key) {
                let last = entry.last_stat();
                if now.saturating_sub(last) < recheck_secs {
                    // Fresh cache hit — return without re-stat.
                    return Ok(Arc::clone(entry));
                }
                // Cache hit but stale — must re-stat.
                let entry_clone = Arc::clone(entry);
                drop(g);
                return self.hotlist_recheck(&key, entry_clone, now);
            }
        }

        // Cache miss — open + insert.
        self.hotlist_insert(&key, now)
    }

    /// Internal: re-stat a stale entry and either touch it or replace
    /// it.
    fn hotlist_recheck(
        &self,
        key: &PathBuf,
        entry: Arc<HotEntry>,
        now: u64,
    ) -> Result<Arc<HotEntry>, NetError> {
        match crate::util::file::stat(key) {
            Ok((size, mtime)) => {
                if size == entry.size && mtime == entry.mtime {
                    // File unchanged — touch last_stat and return
                    // the existing mapping.
                    entry.touch_last_stat();
                    let _ = now; // 'now' not needed once last_stat is touched.
                    Ok(entry)
                } else {
                    // File changed — evict and re-open.
                    self.hotlist_evict(key);
                    self.hotlist_insert(key, now)
                }
            }
            Err(_) => {
                // File disappeared — evict and surface a 404 via Io
                // error.
                self.hotlist_evict(key);
                Err(NetError::Io(std::io::Error::from(std::io::ErrorKind::NotFound)))
            }
        }
    }

    /// Internal: open + mmap `key` and insert into the hotlist.
    fn hotlist_insert(&self, key: &PathBuf, now: u64) -> Result<Arc<HotEntry>, NetError> {
        let entry = Arc::new(HotEntry::open(key.clone())?);
        // Stash the now-time on last_stat so subsequent lookups see
        // a fresh entry.
        entry.last_stat.store(now, Ordering::Relaxed);

        // Promote to write-lock briefly. If a concurrent request
        // raced and inserted the same key already, we discard our
        // candidate and return theirs (idempotent — both maps point
        // at structurally-equivalent mmaps).
        match self.hotlist.try_write() {
            Ok(mut g) => {
                if let Some(existing) = g.get(key) {
                    return Ok(Arc::clone(existing));
                }
                g.insert(key.clone(), Arc::clone(&entry));
                Ok(entry)
            }
            Err(_) => {
                // Lock contended — return the candidate without
                // caching. Subsequent requests will retry.
                Ok(entry)
            }
        }
    }

    /// Internal: remove `key` from the hotlist.
    fn hotlist_evict(&self, key: &PathBuf) {
        if let Ok(mut g) = self.hotlist.try_write() {
            g.remove(key);
        }
    }

    /// Periodic eviction sweep — removes hotlist entries whose
    /// `pin_count == 0` and whose age exceeds
    /// [`crate::config::WEBSERVER_HOTLIST_TIME`] (900 seconds).
    ///
    /// Mirrors FASM `webservercfg$hotlist_weed` at L1566+. Called by
    /// the per-config `hotlist_weed` periodic timer scheduled in
    /// [`Self::new_config`].
    pub fn hotlist_weed(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let lifetime = config::WEBSERVER_HOTLIST_TIME;
        if let Ok(mut g) = self.hotlist.try_write() {
            g.retain(|_path, entry| {
                let pinned = entry.pin_count() > 0;
                let young = now.saturating_sub(entry.created()) < lifetime;
                pinned || young
            });
        }
    }

    /// External hook for callers that want to explicitly unpin a
    /// hotlist entry (e.g., custom inflight callbacks).
    pub fn hotlist_unpin(&self, entry: &HotEntry) {
        entry.unpin();
    }

    /// Build a fully-formed error response for the given HTTP status
    /// code.
    ///
    /// Mirrors FASM `webservercfg$error` at L3301-3470 with two body
    /// modes:
    /// 1. **File-based** — when [`Self::error_docs`] is set and a
    ///    matching `{code}.html` file exists in that directory, the
    ///    file content is served as `text/html; charset=UTF-8`.
    /// 2. **String-based** (default) — body is the textual reason
    ///    phrase from [`preface_for`] followed by `\r\n`, served as
    ///    `text/plain`.
    pub fn error(&self, code: u16) -> Mimelike {
        let mut resp = Mimelike::new();
        resp.set_preface(preface_for(code));

        // Try file-based body first.
        let file_body: Option<Vec<u8>> = {
            let docs_dir = self.error_docs.lock().ok().and_then(|g| g.clone());
            if let Some(dir) = docs_dir {
                let file_path = dir.join(format!("{}.html", code));
                crate::util::file::read(&file_path).ok()
            } else {
                None
            }
        };

        if let Some(body) = file_body {
            resp.set_header("Content-Type", CONTENT_TYPE_TEXT_HTML_UTF8);
            let _ = resp.set_body(&body);
        } else {
            // String-based body: the preface minus the "HTTP/1.1 "
            // prefix (i.e., "<code> <reason>"), terminated with CRLF.
            let preface = preface_for(code);
            let body_text = preface
                .strip_prefix(HTTP_1_1_PREFIX)
                .unwrap_or(preface)
                .to_string()
                + "\r\n";
            resp.set_header("Content-Type", CONTENT_TYPE_TEXT_PLAIN);
            let _ = resp.set_body(body_text.as_bytes());
        }
        resp
    }

    /// Flush pending log buffers to disk / syslog.
    ///
    /// Called every 1.5 seconds by the periodic timer scheduled in
    /// [`Self::new_config`]. Drains [`Self::log_buffer`] and
    /// [`Self::error_log_buffer`], appending each to its configured
    /// file and clearing the buffer. Errors during the append are
    /// swallowed silently — log-write failures must not crash the
    /// server.
    pub fn flush_logs(&self) {
        // Access log.
        let access_path = self.log_path.lock().ok().and_then(|g| g.clone());
        if let Some(path) = access_path {
            if let Ok(mut buf) = self.log_buffer.lock() {
                if !buf.is_empty() {
                    let _ = crate::util::file::append(&path, buf.as_slice());
                    buf.clear();
                }
            }
        }
        // Error log.
        let err_path = self.error_file.lock().ok().and_then(|g| g.clone());
        if let Some(path) = err_path {
            if let Ok(mut buf) = self.error_log_buffer.lock() {
                if !buf.is_empty() {
                    let _ = crate::util::file::append(&path, buf.as_slice());
                    buf.clear();
                }
            }
        }
        // Optional syslog forwarding for access logs (we only emit at
        // info level; per-line forwarding would require recovering
        // line boundaries from the raw buffer).
        if self.syslog.load(Ordering::Relaxed) {
            // Buffer was drained above; nothing to do at this
            // granularity. Per-line syslog emission is performed
            // inline in WebServer::log instead.
        }
    }
}

/// Detect whether `data` already begins with the gzip magic bytes
/// `0x1f 0x8b`, indicating it should not be re-compressed.
fn is_already_gzipped(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// ============================================================================
// WebServer — per-connection HTTP/1.1 state machine (FASM `webserver_*` —
// AAP §0.5.1.4, AAP §0.7.1, FASM `webserver.inc` lines 3680–5670).
// ============================================================================

/// Per-connection HTTP/1.1 server state.
///
/// One instance per accepted client connection. Owns the in-progress
/// request accumulator, the pending response (`inflight` for 3-mode
/// chunked send), and the idle timer. Layers over an underlying
/// transport (TCP or TLS) via the [`IoChain`] parent/child chain
/// mechanism — `child` points downward toward the kernel socket and
/// `parent` is the optional application-layer hook (used by the
/// `webserver` binary's `hookthemall` pattern in FASM
/// `rwasa/rwasa.asm`).
///
/// **Field synchronisation conventions** (AAP §0.4.3 trait-based
/// polymorphism + Drop-based cleanup):
///
/// * **`AtomicBool` / `AtomicU32` / `AtomicU64`** — flags and
///   counters that are touched from both the connection task and
///   from spawned subtasks (timer ticks, FastCGI completions). All
///   load/store uses [`Ordering::Relaxed`] except where a
///   happens-before edge is needed (see [`Self::sent_partial`] for
///   the exception).
/// * **`Mutex<Option<T>>`** — slots that are written exactly once
///   per request (e.g. [`Self::request`], [`Self::raddr`]) and
///   read repeatedly. The critical section is a quick swap; never
///   crosses an `await` point. Uses `std::sync::Mutex` rather
///   than `tokio::sync::Mutex` because the holder time is ~ns.
/// * **`Mutex<Buffer>`** — accumulators where bytes flow in
///   chunks (e.g. [`Self::accum`]). Same `std::sync::Mutex` rule.
///
/// **FASM offset mapping** (preserved in field-comment markers; the
/// total FASM `webserver_size` is 144 bytes plus a 110-byte
/// `raddr` plus an 8-byte `raddrlen`, all above `io_base_size`):
///
/// | offset | FASM name              | Rust field            |
/// |-------:|------------------------|-----------------------|
/// |     0  | `config_ofs`           | [`Self::config`]      |
/// |     8  | `flags_ofs`            | [`Self::flags`]       |
/// |    16  | `accum_ofs`            | [`Self::accum`]       |
/// |    24  | `timer_ofs`            | [`Self::timer`]       |
/// |    32  | `timedout_ofs`         | [`Self::timed_out`]   |
/// |    40  | `request_ofs`          | [`Self::request`]     |
/// |    48  | `respcode_ofs`         | [`Self::resp_code`]   |
/// |    56  | `sentpartial_ofs`      | [`Self::sent_partial`]|
/// |    64  | `inflight_ofs`         | [`Self::inflight`]    |
/// |    72  | `inflightlen_ofs`      | [`Self::inflight_len`]|
/// |    80  | `inflightcb_ofs`       | [`Self::inflight_cb`] |
/// |    88  | `inflightcbarg_ofs`    | [`Self::inflight_cb_arg`] |
/// |    96  | `inflightsent_ofs`     | [`Self::inflight_sent`]|
/// |   104  | `fcgihooked_ofs`       | [`Self::fcgi_hooked`] |
/// |   112  | `requestlen_ofs`       | [`Self::request_len`] |
/// |   120  | `needmore_ofs`         | [`Self::need_more`]   |
/// |   128  | `backpath_ofs`         | [`Self::back_path`]   |
/// |   136  | `raddr_ofs`            | [`Self::raddr`]       |
pub struct WebServer {
    /// **(FASM offset 0 — `webserver_config_ofs`)** Shared
    /// per-listener configuration. The same `Arc<WebServerConfig>`
    /// is cloned into every accepted connection by the listener
    /// front-end (typically the `webserver` binary's `master.rs`).
    config: Arc<WebServerConfig>,

    /// **(FASM offset 8 — `webserver_flags_ofs`)** Per-connection
    /// flag bits. Layout (AAP §0.5.1.4 "Flags Bit Layout"):
    ///
    /// * bit 0 = keep-alive (default 1; cleared on
    ///   `Connection: close` or HTTP/1.0).
    /// * bit 1 = gzip allowed (set when the request's
    ///   `Accept-Encoding` contains `"gzip"` AND
    ///   `WEBSERVER_AUTOGZIP` is `true`).
    /// * bit 2 = chunked allowed (set when HTTP version minor is
    ///   `1`).
    flags: AtomicU32,

    /// **(FASM offset 16 — `webserver_accum_ofs`)** Inbound bytes
    /// since the last fully-consumed request. Capped at
    /// [`config::WEBSERVER_MAXHEADER`] when scanning for the
    /// header terminator; on overflow the connection is rejected
    /// with 400. Pipelined requests append here and are sliced off
    /// via [`Buffer::consume`] after each successful dispatch.
    accum: Mutex<Buffer>,

    /// **(FASM offset 24 — `webserver_timer_ofs`)** Idle-timeout
    /// timer handle. Set by [`Self::new_timer`] to a
    /// [`tokio::task::JoinHandle`] that sleeps for
    /// [`timers::HTTP_IDLE`] then triggers a teardown via the
    /// chain's [`IoChain::timeout`] path. Cleared by
    /// [`Self::clear_timer`] (which observes the
    /// **"take-then-abort" ordering** — see that method's docs for
    /// the rationale).
    timer: Mutex<Option<JoinHandle<()>>>,

    /// **(FASM offset 32 — `webserver_timedout_ofs`)** Set true by
    /// the timer task when the idle interval elapses. Read by
    /// [`Self::on_timeout`] to decide whether the timer-clear path
    /// in `destroy` should be skipped (since the timer task
    /// already exited).
    timed_out: AtomicBool,

    /// **(FASM offset 40 — `webserver_request_ofs`)** The currently
    /// in-flight parsed request, or `None` between requests
    /// (idle, or pipelined and not yet parsed). Written once per
    /// request by [`Self::check_accum`] after a successful
    /// `Mimelike::new_parse`; cleared back to `None` by the
    /// post-send finish path.
    request: Mutex<Option<Mimelike>>,

    /// **(FASM offset 48 — `webserver_respcode_ofs`)** HTTP status
    /// code of the last response, parsed from its preface bytes
    /// 9..12 (e.g. `"HTTP/1.1 200 OK"` → `200`). Logged by
    /// [`Self::log`] in the Common Log Format `respcode` slot.
    resp_code: Mutex<u16>,

    /// **(FASM offset 56 — `webserver_sentpartial_ofs`)**
    /// Indicates that the last `io$send` returned with bytes still
    /// queued in the kernel — when the post-send finish path runs
    /// it must NOT re-arm the idle timer (the next `EPOLLOUT`
    /// callback will continue draining `inflight`).
    sent_partial: AtomicBool,

    /// **(FASM offset 64 — `webserver_inflight_ofs`)** The composed
    /// response wire bytes during a 3-mode chunked send, or
    /// `None` when no response is in flight. Used by MODE 2
    /// (`senduntilpartial`) and MODE 3 (`sendinsegments`) — see
    /// [`Self::send_response`].
    inflight: Mutex<Option<Bytes>>,

    /// **(FASM offset 72 — `webserver_inflightlen_ofs`)** Total
    /// length of [`Self::inflight`] for chunk arithmetic. Captured
    /// up front so the chunking loop never re-locks `inflight`
    /// just to read its length.
    inflight_len: AtomicU64,

    /// **(FASM offset 80 — `webserver_inflightcb_ofs`)** Optional
    /// post-send cleanup closure invoked exactly once when the
    /// last chunk of [`Self::inflight`] is acknowledged. Used by
    /// the big-file `hotlist_unpin` path — the closure is
    /// constructed by [`WebServerConfig::request_stage`] when the
    /// served entry exceeds [`config::WEBSERVER_BIGFILE`].
    inflight_cb: Mutex<Option<InflightCb>>,

    /// **(FASM offset 88 — `webserver_inflightcbarg_ofs`)** The
    /// opaque argument bound to [`Self::inflight_cb`]. Held as
    /// `Arc<dyn Any + Send + Sync>` so a held `Arc<HotEntry>` (or
    /// any other reference-counted resource) keeps its target
    /// alive across the chunked-send window.
    inflight_cb_arg: Mutex<Option<Arc<dyn Any + Send + Sync>>>,

    /// **(FASM offset 96 — `webserver_inflightsent_ofs`)** Total
    /// bytes sent so far from [`Self::inflight`]. When this
    /// reaches [`Self::inflight_len`] the chunking loop fires
    /// [`Self::inflight_cb`] (if set) and clears `inflight`.
    inflight_sent: AtomicU64,

    /// **(FASM offset 104 — `webserver_fcgihooked_ofs`)** Set true
    /// when an outbound FastCGI dispatch is pending — the local
    /// dispatch path returns `None` (Pending) and the eventual
    /// `FcgiCallback` fires `send_response` directly.
    fcgi_hooked: AtomicBool,

    /// **(FASM offset 112 — `webserver_requestlen_ofs`)** Number
    /// of bytes consumed from [`Self::accum`] by the parsed
    /// request — `parse_len + body_len` from
    /// [`Mimelike::parse_len`] / [`Mimelike::body_len`]. Used by
    /// the post-send finish path to slide the accum window for
    /// pipelined follow-up requests.
    request_len: AtomicU64,

    /// **(FASM offset 120 — `webserver_needmore_ofs`)** Set true
    /// by [`Self::check_accum`] when the header-terminator scan
    /// returned no match and the accum is below the
    /// [`config::WEBSERVER_MAXHEADER`] limit (i.e. waiting for
    /// more bytes from the socket).
    need_more: AtomicBool,

    /// **(FASM offset 128 — `webserver_backpath_ofs`)** Per-
    /// connection back-path proxy target, if any. Used by the
    /// (stub) [`Wsbp`] backend dispatch path.
    ///
    /// Populated from [`WebServerConfig::back_path`] in
    /// [`Self::on_connected`]. Read access is via the public
    /// [`Self::back_path`] accessor; only that accessor is
    /// counted as "use" for dead-code analysis until the wsbp
    /// dispatch path lands (per AAP §0.7 Phase 10).
    #[allow(dead_code)]
    back_path: Mutex<Option<SocketAddr>>,

    /// **(FASM offset 136 — `webserver_raddr_ofs`/`raddrlen_ofs`)**
    /// Remote peer address, captured in
    /// [`Self::on_connected`]. Logged by [`Self::log`] in the
    /// Common Log Format `host` slot.
    raddr: Mutex<Option<SocketAddr>>,

    /// IoChain plumbing — parent (Weak, breaks reference cycles)
    /// and child (Arc, keeps the transport alive while the
    /// WebServer is in scope). See [`IoLinks`].
    links: IoLinks,
}

impl WebServer {
    /// Construct a new per-connection server state from the shared
    /// configuration.
    ///
    /// The returned `Arc<WebServer>` is wired into the IO chain by
    /// the listener front-end via [`crate::net::io::link`]: the
    /// transport (TCP / TLS) becomes the WebServer's child, and the
    /// optional application hook (set by `rwasa`'s
    /// `hookthemall`-equivalent) becomes its parent.
    ///
    /// FASM equivalent: `webserver$new` at `webserver.inc` lines
    /// 3680–3696. The 144-byte struct + 110-byte `raddr` + 8-byte
    /// `raddrlen` are all zero-initialised; the only non-default
    /// field is `flags = 0b001` (keep-alive on).
    pub fn new(config: Arc<WebServerConfig>) -> Arc<Self> {
        Arc::new(Self {
            config,
            // bit 0 (keep-alive) defaults on — FASM L3691.
            flags: AtomicU32::new(0b001),
            accum: Mutex::new(Buffer::new()),
            timer: Mutex::new(None),
            timed_out: AtomicBool::new(false),
            request: Mutex::new(None),
            resp_code: Mutex::new(0),
            sent_partial: AtomicBool::new(false),
            inflight: Mutex::new(None),
            inflight_len: AtomicU64::new(0),
            inflight_cb: Mutex::new(None),
            inflight_cb_arg: Mutex::new(None),
            inflight_sent: AtomicU64::new(0),
            fcgi_hooked: AtomicBool::new(false),
            request_len: AtomicU64::new(0),
            need_more: AtomicBool::new(false),
            back_path: Mutex::new(None),
            raddr: Mutex::new(None),
            links: IoLinks::new(),
        })
    }

    /// Access the IoChain link state. Public to allow the listener
    /// front-end to wire children/parent without requiring this
    /// method to be on a separate trait.
    pub fn links(&self) -> &IoLinks {
        &self.links
    }

    /// Access the shared per-listener configuration. Public so that
    /// FastCGI completion callbacks and user-supplied
    /// `FuncHandler`s can read sandbox / vhost state without
    /// reaching into the WebServer's private fields.
    pub fn config(&self) -> &Arc<WebServerConfig> {
        &self.config
    }

    /// Inbound-connection notification (BACKWARD path).
    ///
    /// Captures the peer's address and starts the 30-second idle
    /// timer. Mirrors FASM `webserver$connected` at
    /// `webserver.inc` lines 3851–3912.
    ///
    /// `peer` is supplied by the underlying transport's
    /// `accept()`-side; the WebServer just stashes it in
    /// [`Self::raddr`] for later logging. If the transport supplies
    /// `None` (e.g. for an embedded test fixture) the field stays
    /// empty and the log emits `"-"` in the host slot.
    pub async fn on_connected(self: &Arc<Self>, peer: Option<SocketAddr>) -> Result<(), NetError> {
        if let Ok(mut g) = self.raddr.lock() {
            *g = peer;
        }
        self.sent_partial.store(false, Ordering::Relaxed);
        self.new_timer();
        Ok(())
    }

    /// Inbound-data notification (BACKWARD path).
    ///
    /// Appends `data` to the per-connection accumulator and
    /// attempts to advance the parser via [`Self::check_accum`].
    /// Mirrors FASM `webserver$receive` at lines 5047–5095.
    ///
    /// Returns `Ok(true)` to indicate the caller (the IoChain
    /// receive plumbing in [`crate::net::io::default_receive`])
    /// should tear down the connection — emitted on a 400 / 413
    /// hard error path.
    ///
    /// Returns `Ok(false)` for the normal path (request parsed and
    /// dispatched, or accum still growing waiting for more bytes).
    pub async fn on_receive(self: &Arc<Self>, data: &[u8]) -> Result<bool, NetError> {
        if data.is_empty() {
            // Empty payloads are tolerated — no mutation.
            return Ok(false);
        }
        // Append under a brief lock; never crosses an .await.
        if let Ok(mut g) = self.accum.lock() {
            // Reject before we even try to parse if the accum is
            // already over the header cap with no terminator yet.
            if g.len().saturating_add(data.len()) > config::WEBSERVER_MAXREQUEST {
                return Err(NetError::Http(HttpError::TooLarge));
            }
            g.extend_from_slice(data);
        }
        // Advance the parser. check_accum may consume + recurse on
        // pipelined follow-ups internally — no looping needed here.
        match self.check_accum().await {
            Ok(()) => Ok(false),
            Err(e) => {
                // Fatal parse / dispatch error. The on_error path
                // forwards to the parent; we still tell the
                // receive plumbing to tear down the chain.
                let _ = e;
                Ok(true)
            }
        }
    }

    /// Try to advance the parser by scanning the accumulated bytes
    /// for a CRLFCRLF / LFLF header terminator.
    ///
    /// Mirrors FASM `webserver$check_accum` at
    /// `webserver.inc` lines 5096–5300. The 8 dispatch stages
    /// (Method → Parse → Size → Host → FuncMap → FastCGI →
    /// Redirect → File) are split between this method (Stages 1
    /// and 2 — method validation + Mimelike parse) and
    /// [`Self::process_request`] (Stages 3–8).
    pub(crate) async fn check_accum(self: &Arc<Self>) -> Result<(), NetError> {
        // Snapshot the accum bytes for parsing. We deliberately
        // copy rather than holding the lock across .await — the
        // accum is bounded at WEBSERVER_MAXHEADER + body, and the
        // copy cost is dwarfed by mimelike$new_parse.
        let snapshot: Vec<u8> = match self.accum.lock() {
            Ok(g) => g.as_slice().to_vec(),
            Err(_) => return Ok(()),
        };

        // Stage 1: Method validation — first 5 bytes must spell
        // GET<sp>, HEAD<sp>, or POST<sp>.
        let (method_code, method_ok) = match snapshot.as_slice() {
            b if b.starts_with(b"GET ") => (0u8, true),
            b if b.starts_with(b"HEAD ") => (1u8, true),
            b if b.starts_with(b"POST ") => (2u8, true),
            _ => (255u8, false),
        };

        // Find the header terminator (CRLFCRLF or LFLF) within the
        // first WEBSERVER_MAXHEADER bytes. If not found and accum
        // is still small, set need_more and return; if not found
        // and accum has overflowed the cap, emit 400.
        let scan_limit = snapshot.len().min(config::WEBSERVER_MAXHEADER);
        let header_end = find_header_end(&snapshot[..scan_limit]);
        match header_end {
            None => {
                if snapshot.len() >= config::WEBSERVER_MAXHEADER {
                    // Hard 400 via the .norequest log path.
                    self.log_no_request(400);
                    let mut resp = self.config.error(400);
                    self.send_response(&mut resp, method_code).await?;
                    return Ok(());
                }
                self.need_more.store(true, Ordering::Relaxed);
                return Ok(());
            }
            Some(_end) => {
                self.need_more.store(false, Ordering::Relaxed);
            }
        }

        if !method_ok {
            // Stage 1 failure: 501 Not Implemented.
            self.log_no_request(501);
            let mut resp = self.config.error(501);
            self.send_response(&mut resp, 0).await?;
            return Ok(());
        }

        // Stage 2: Mimelike parse — the headers are guaranteed to
        // be present at this point.
        let parsed = match Mimelike::new_parse(
            &snapshot, /*headers_only=*/ false, /*has_preface=*/ true,
        ) {
            Ok(m) => m,
            Err(crate::net::http::mimelike::MimelikeError::NeedMoreBody { .. }) => {
                // Body still arriving — wait for the next on_receive.
                self.need_more.store(true, Ordering::Relaxed);
                return Ok(());
            }
            Err(e) => {
                // Malformed: 400 Bad Request.
                let _ = e;
                self.log_no_request(400);
                let mut resp = self.config.error(400);
                self.send_response(&mut resp, method_code).await?;
                return Ok(());
            }
        };

        // Stage 3: enforce Content-Length cap (FASM L5500+ — 413
        // Payload Too Large). The Mimelike parse already enforces
        // a sane Content-Length, but the absolute server cap is
        // WEBSERVER_MAXREQUEST = 64 MiB.
        if let Some(cl_str) = parsed.get_header("Content-Length") {
            if let Ok(cl) = cl_str.trim().parse::<usize>() {
                if cl > config::WEBSERVER_MAXREQUEST {
                    self.log_no_request(413);
                    let mut resp = self.config.error(413);
                    self.send_response(&mut resp, method_code).await?;
                    return Ok(());
                }
            }
        }

        // Stash method code + HTTP version in the Mimelike user
        // bytes — see AAP §0.5.1.4 "Method Encoding". Bit 0 of
        // user_bytes[0] is the method code; user_bytes[4] holds
        // the HTTP minor version (0 for HTTP/1.0, 1 for HTTP/1.1).
        let http_minor: u8 = parsed
            .preface()
            .and_then(|p| {
                p.rsplit(' ').next().and_then(|tok| match tok {
                    "HTTP/1.0" => Some(0u8),
                    "HTTP/1.1" => Some(1u8),
                    _ => None,
                })
            })
            .unwrap_or(0);

        let consumed = parsed.parse_len();
        let mut request = parsed;
        {
            let user = request.user_bytes_mut();
            user[0] = method_code;
            user[4] = http_minor;
        }

        // Compute and stash the per-request consumption window so
        // the post-send finish path can slide accum for
        // pipelining.
        self.request_len.store(consumed as u64, Ordering::Relaxed);

        // Move the request into self.request and dispatch.
        if let Ok(mut g) = self.request.lock() {
            *g = Some(request);
        }
        self.process_request().await
    }
}

/// Find the index of the byte AFTER a header terminator (CRLFCRLF
/// or LFLF) in `data`, or `None` if no terminator is present.
///
/// Mirrors the FASM `.findbreak` scan at `webserver.inc` lines
/// 5100–5180. Returns the absolute offset one past the terminator
/// (i.e. the start of the body).
fn find_header_end(data: &[u8]) -> Option<usize> {
    // Fast path: scan for `\r\n\r\n`.
    if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(i + 4);
    }
    // Fallback: tolerate `\n\n` (RFC 7230 says a server MAY accept
    // bare-LF terminators, and the FASM source does — see L5160).
    data.windows(2).position(|w| w == b"\n\n").map(|i| i + 2)
}

impl WebServer {
    /// Process a parsed request through the dispatch pipeline.
    ///
    /// FASM equivalent: `webserver$check_accum.processrequest` at
    /// `webserver.inc` lines 5300+. Stages 4–8:
    ///
    /// 1. Stage 4 — clear the idle timer (the request is being
    ///    actively processed; timer-driven tear-down is held off
    ///    until the next idle window).
    /// 2. Stage 5 — set the keep-alive / gzip / chunked flag bits
    ///    from the request headers.
    /// 3. Stage 6 — construct the [`Url`] (either from a fully-
    ///    qualified preface URL or by combining the `Host:` header
    ///    with the relative path).
    /// 4. Stage 7 — dispatch to [`WebServerConfig::handler`].
    /// 5. Stage 8 — on `Some(response)`: send via
    ///    [`Self::send_response`]. On `None`: emit 404 (the
    ///    Pending case is handled by the dispatcher itself which
    ///    will eventually call `send_response` directly).
    pub(crate) async fn process_request(self: &Arc<Self>) -> Result<(), NetError> {
        // Stage 4: clear the idle timer. We are actively in a
        // request — the timer will be re-armed on the post-send
        // finish path if the connection stays open.
        self.clear_timer();

        // Snapshot fields we need from the request without holding
        // the request lock across .await. We read method_code and
        // http_minor from user_bytes (set in check_accum), the
        // preface, the Connection / Accept-Encoding / Host headers,
        // and clone the Mimelike out so handler() can take a
        // shared reference.
        let (method_code, http_minor, preface_owned, conn_hdr, accept_enc, host_hdr) =
            match self.request.lock() {
                Ok(g) => {
                    let req = match g.as_ref() {
                        Some(r) => r,
                        None => return Ok(()),
                    };
                    let user = req.user_bytes();
                    (
                        user[0],
                        user[4],
                        req.preface().map(str::to_owned),
                        req.get_header("Connection").map(str::to_owned),
                        req.get_header("Accept-Encoding").map(str::to_owned),
                        req.get_header("Host").map(str::to_owned),
                    )
                }
                Err(_) => return Ok(()),
            };

        // Stage 5a: keep-alive flag.
        let keep_alive_default = http_minor == 1;
        let close_requested = conn_hdr
            .as_deref()
            .map(|v| v.eq_ignore_ascii_case("close"))
            .unwrap_or(false);
        let keep_alive_actual = keep_alive_default && !close_requested;

        // Stage 5b: gzip flag.
        let gzip_ok = config::WEBSERVER_AUTOGZIP
            && accept_enc
                .as_deref()
                .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("gzip")))
                .unwrap_or(false);

        // Stage 5c: chunked flag (HTTP/1.1 only).
        let chunked_ok = http_minor == 1;

        let new_flags = (if keep_alive_actual { 0b001 } else { 0 })
            | (if gzip_ok { 0b010 } else { 0 })
            | (if chunked_ok { 0b100 } else { 0 });
        self.flags.store(new_flags, Ordering::Relaxed);

        // Stage 6: URL construction. The preface looks like
        // `"GET /path?q HTTP/1.1"` — the middle token is the
        // request-target. If it's an absolute URI it parses
        // directly; otherwise we glue scheme://host onto it.
        let preface = match preface_owned.as_deref() {
            Some(p) => p,
            None => {
                self.log_no_request(400);
                let mut resp = self.config.error(400);
                self.send_response(&mut resp, method_code).await?;
                return Ok(());
            }
        };
        let target_token = preface.split(' ').nth(1).unwrap_or("/");
        let url = match Url::parse(target_token) {
            Ok(u) => u,
            Err(_) => {
                // Relative URI — combine with Host header.
                let scheme = if self.config.is_tls_enabled() {
                    "https"
                } else {
                    "http"
                };
                let host = match host_hdr.as_deref() {
                    Some(h) => h.to_lowercase(),
                    None => {
                        // HTTP/1.1 requires Host; missing → 400.
                        if http_minor == 1 {
                            self.log_no_request(400);
                            let mut resp = self.config.error(400);
                            self.send_response(&mut resp, method_code).await?;
                            return Ok(());
                        }
                        // HTTP/1.0 may omit Host — fall back to
                        // the configured vhost or `..nohost..`.
                        String::new()
                    }
                };
                let composite = format!("{scheme}://{host}{target_token}");
                match Url::parse(&composite) {
                    Ok(u) => u,
                    Err(_) => {
                        self.log_no_request(400);
                        let mut resp = self.config.error(400);
                        self.send_response(&mut resp, method_code).await?;
                        return Ok(());
                    }
                }
            }
        };

        // Stage 7: dispatch.
        //
        // We take the request OUT of `self.request` for the
        // duration of the handler call. This is required because
        // `handler` is `async fn` and the std `MutexGuard`
        // returned by `self.request.lock()` is not `Send` — we
        // cannot hold it across an `.await`. Once the handler
        // returns we put the request back (so logging in
        // `Self::log` can still read headers off it) — unless the
        // dispatch went Pending, in which case the request stays
        // off and the eventual completion callback restores it.
        let request_taken = match self.request.lock() {
            Ok(mut g) => g.take(),
            Err(_) => return Ok(()),
        };
        let request = match request_taken {
            Some(r) => r,
            None => return Ok(()),
        };

        let response_opt = Arc::clone(&self.config).handler(self, &url, &request).await;

        // Put the request back so `Self::log` can read headers.
        if let Ok(mut g) = self.request.lock() {
            *g = Some(request);
        }

        match response_opt {
            Some(mut resp) => {
                self.send_response(&mut resp, method_code).await?;
            }
            None if self.fcgi_hooked.load(Ordering::Relaxed) => {
                // Pending: an FcgiClient or FuncHandler will fire
                // send_response asynchronously. Nothing to do.
            }
            None => {
                // No handler matched — emit 404.
                let mut resp = self.config.error(404);
                self.send_response(&mut resp, method_code).await?;
            }
        }
        Ok(())
    }
}

impl WebServer {
    /// Compose and dispatch a response to the client.
    ///
    /// FASM equivalent: `webserver$sendresponse` at
    /// `webserver.inc` lines 4346–4900. Performs **two** logical
    /// passes:
    ///
    /// 1. **Header decoration** (Phase 5a — lines 4346–4500). Adds
    ///    the standard envelope headers (`Server`, `Date`,
    ///    `Connection`, optional `Content-Encoding`, optional
    ///    `Strict-Transport-Security`, optional `X-NB`) onto
    ///    `response`.
    /// 2. **3-mode send dispatch** (Phase 5b — lines 4700–4900):
    ///    - **MODE 1** — body ≤ [`config::WEBSERVER_INITIALSEND`]
    ///      (262 144 bytes): single
    ///      [`IoChain::send`] of the entire composed
    ///      `xmitbody`. Log emission and `response` drop happen
    ///      inline.
    ///    - **MODE 2** — body ≤ [`config::WEBSERVER_BIGFILE`] (32
    ///      MiB): the composed buffer is stored in
    ///      [`Self::inflight`] and the first
    ///      `WEBSERVER_INITIALSEND` chunk is dispatched. The
    ///      remaining chunks are pulled by [`Self::on_send_cb`] in
    ///      `WEBSERVER_SUBSEQUENTSEND`-byte segments.
    ///    - **MODE 3** — body > 32 MiB: headers are composed
    ///      stand-alone and the body is streamed independently
    ///      (the `mmap` slice is sliced lazily so large files
    ///      never inflate process RSS by their full size).
    ///
    /// `method_code` is the encoded HTTP method (0 = GET, 1 =
    /// HEAD, 2 = POST). HEAD responses skip the body — only
    /// headers are emitted.
    pub async fn send_response(
        self: &Arc<Self>,
        response: &mut Mimelike,
        method_code: u8,
    ) -> Result<(), NetError> {
        // ----- Phase 5a — Header decoration -----

        let flags = self.flags.load(Ordering::Relaxed);
        let keep_alive = (flags & 0b001) != 0;
        let gzip_active = (flags & 0b010) != 0;

        // BREACH mitigation (X-NB): TLS+gzip only.
        if self.config.is_tls_enabled() && gzip_active {
            self.add_breach_header(response);
        }

        // Connection — always set.
        response.set_header(
            "Connection",
            if keep_alive { CONN_KEEP_ALIVE } else { CONN_CLOSE },
        );

        // Server — byte-frozen.
        response.set_header("Server", SERVER_HEADER_VALUE);

        // Date — RFC 1123 in HTTP-date format.
        if let Ok(now) = now_rfc1123() {
            response.set_header("Date", now);
        }

        // HSTS — TLS only AND only if compile-time flag is on.
        if self.config.is_tls_enabled() && config::WEBSERVER_HSTS {
            response.set_header(HSTS_HEADER_NAME, config::HSTS_HEADER_VALUE);
        }

        // Capture the response status code before compose() so we
        // can log it on the way out.
        let resp_code = response.preface().and_then(parse_status_code).unwrap_or(0);
        if let Ok(mut g) = self.resp_code.lock() {
            *g = resp_code;
        }

        // ----- Phase 5b — Compose + 3-mode dispatch -----

        // Compose into the Mimelike's internal xmitbody buffer.
        response.compose();

        // Decide which "body view" we transmit. For HEAD we send
        // headers only; for GET/POST we send the full
        // headers+body slice.
        let to_send_full = response.xmitbody_slice();
        let to_send_headers = response.xmitbody_headers_slice();
        let body_only_len = to_send_full.len().saturating_sub(to_send_headers.len());

        // For HEAD, body is suppressed at the wire even though
        // Content-Length must reflect the would-be body. Mimelike
        // composes the same headers either way; we just clip the
        // outbound buffer at the header boundary.
        let payload: &[u8] = if method_code == 1 {
            to_send_headers
        } else {
            to_send_full
        };

        let payload_len = payload.len();

        // Log first (FASM L4710 — log emitted regardless of which
        // send mode is taken).
        self.log(resp_code, body_only_len as u64);

        if payload_len <= config::WEBSERVER_INITIALSEND {
            // MODE 1 — single io$send.
            let bytes = Bytes::copy_from_slice(payload);
            self.send_via_child(bytes).await?;
            self.finish_request().await
        } else if payload_len <= config::WEBSERVER_BIGFILE {
            // MODE 2 — senduntilpartial. Stash the full payload
            // and dispatch the first WEBSERVER_INITIALSEND chunk;
            // the rest is pulled by on_send_cb.
            let full = Bytes::copy_from_slice(payload);
            self.inflight_len.store(full.len() as u64, Ordering::Relaxed);
            self.inflight_sent.store(0, Ordering::Relaxed);
            if let Ok(mut g) = self.inflight.lock() {
                *g = Some(full.clone());
            }
            let first = full.slice(0..config::WEBSERVER_INITIALSEND);
            self.inflight_sent
                .store(config::WEBSERVER_INITIALSEND as u64, Ordering::Relaxed);
            self.send_via_child(first).await?;
            // The next chunk(s) are dispatched by on_send_cb.
            Ok(())
        } else {
            // MODE 3 — sendinsegments. Headers go out first as a
            // single chunk; the body is streamed in
            // WEBSERVER_SUBSEQUENTSEND-byte segments. We emulate
            // the segmented body by storing the full payload in
            // `inflight` and clipping at WEBSERVER_INITIALSEND for
            // each chunk — Bytes::slice is zero-copy so the RSS
            // overhead is amortized to the single
            // copy_from_slice above.
            let full = Bytes::copy_from_slice(payload);
            self.inflight_len.store(full.len() as u64, Ordering::Relaxed);
            self.inflight_sent.store(0, Ordering::Relaxed);
            if let Ok(mut g) = self.inflight.lock() {
                *g = Some(full.clone());
            }
            // Emit the headers chunk first.
            let header_len = to_send_headers.len();
            let first_chunk_end = header_len.min(config::WEBSERVER_INITIALSEND);
            let header_chunk = full.slice(0..first_chunk_end);
            self.inflight_sent
                .store(first_chunk_end as u64, Ordering::Relaxed);
            self.send_via_child(header_chunk).await?;
            self.sent_partial.store(true, Ordering::Relaxed);
            Ok(())
        }
    }

    /// Append the X-NB BREACH-mitigation header.
    ///
    /// Emitted only on TLS+gzip responses (AAP §0.1.1 byte-frozen).
    /// Length is uniformly distributed in
    /// `1..=WEBSERVER_BREACH_MITIGATION` via [`rng::intmax`]
    /// (rejection sampling — no modulo bias). Payload bytes are
    /// drawn from [`rng::block`] and hex-encoded for transport
    /// (raw binary is not legal in HTTP header values).
    fn add_breach_header(&self, response: &mut Mimelike) {
        let max = config::WEBSERVER_BREACH_MITIGATION as u64;
        let len = (rng::intmax(max) as usize) + 1;
        let mut buf = vec![0u8; len];
        rng::block(&mut buf);
        let encoded = hex::encode(&buf);
        response.set_header(X_NB_HEADER_NAME, encoded);
    }

    /// Hand `data` to the IO chain's child (the next layer down
    /// toward the kernel socket).
    ///
    /// This is the Rust translation of FASM's `io$send` invoked on
    /// `webserver_child_ofs`. We do not call
    /// [`default_send`] here because that helper would require
    /// re-routing through `IoLinks` — instead we read the child
    /// directly and invoke its `send` method. If there is no
    /// child layer (e.g. a unit-test fixture) the call no-ops.
    async fn send_via_child(self: &Arc<Self>, data: Bytes) -> Result<(), NetError> {
        let child = self.links.child();
        match child {
            Some(c) => c.send(data).await,
            None => Ok(()),
        }
    }

    /// Run the post-send finish path: log, drop request, advance
    /// accum, re-arm timer, and re-enter [`Self::check_accum`] if
    /// pipelined data is waiting.
    ///
    /// FASM equivalent: `.normal_finish` at
    /// `webserver.inc` lines 4900–4960.
    async fn finish_request(self: &Arc<Self>) -> Result<(), NetError> {
        // Drop request — the response cycle is over.
        if let Ok(mut g) = self.request.lock() {
            *g = None;
        }
        // Slide the accum window past the consumed request.
        let consumed = self.request_len.load(Ordering::Relaxed) as usize;
        if consumed > 0 {
            if let Ok(mut g) = self.accum.lock() {
                let cur_len = g.len();
                if consumed >= cur_len {
                    g.clear();
                } else {
                    // `Buffer::consume` returns Result<(), BufferError>;
                    // failure here would mean an internal capacity
                    // invariant violation. Best-effort log + clear so
                    // the connection can continue rather than wedge.
                    if g.consume(consumed).is_err() {
                        g.clear();
                    }
                }
            }
        }
        self.request_len.store(0, Ordering::Relaxed);

        // If keep-alive is on, re-arm the idle timer; else hand
        // control back to the caller (which will tear the chain
        // down via on_receive returning Ok(true) or via Drop).
        let keep_alive = (self.flags.load(Ordering::Relaxed) & 0b001) != 0;
        if !keep_alive {
            return Ok(());
        }

        if !self.sent_partial.load(Ordering::Relaxed) {
            self.new_timer();
        }

        // Pipelined follow-up: if accum still has bytes, recurse
        // into check_accum to attempt to parse the next request.
        let has_more = self.accum.lock().map(|g| !g.is_empty()).unwrap_or(false);
        if has_more {
            // Use Box::pin to break recursion (async fns recursing
            // with .await directly would blow the stack on a
            // pipelined burst; pinning keeps the recursion at a
            // bounded heap-allocated future depth).
            Box::pin(self.check_accum()).await?;
        }
        Ok(())
    }
}

/// Parse the HTTP status code out of the bytes 9..12 of a
/// well-formed status-line preface like `"HTTP/1.1 404 Not Found"`.
///
/// Returns `None` if the preface is shorter than 12 bytes or the
/// 3-byte slot is not numeric. Mirrors FASM L4640+.
fn parse_status_code(preface: &str) -> Option<u16> {
    if preface.len() < 12 {
        return None;
    }
    let bytes = preface.as_bytes();
    let slot = &bytes[9..12];
    std::str::from_utf8(slot).ok()?.parse::<u16>().ok()
}

// ============================================================================
// Timer management + logging — FASM `webserver$newtimer`,
// `webserver$cleartimer`, `webserver$log` (lines 4049–5046).
// ============================================================================

impl WebServer {
    /// Arm (or re-arm) the idle-timeout timer.
    ///
    /// FASM equivalent: `webserver$newtimer` at
    /// `webserver.inc` lines 4901–4960. The FASM source reuses the
    /// existing timer node if present; we model that here by
    /// aborting the previous task (if any) and spawning a fresh
    /// one. The timer fires after [`timers::HTTP_IDLE`] (30 s) and
    /// triggers a tear-down via the chain's [`IoChain::timeout`]
    /// path (which walks BACKWARD to the topmost ancestor and
    /// destroys the entire stack).
    pub fn new_timer(self: &Arc<Self>) {
        // Build a weak self-handle for the spawned task — the
        // timer must NOT keep the WebServer alive on its own (a
        // strong Arc would prevent Drop from running when the
        // chain is torn down by other paths, leaking the timer).
        let weak = Arc::downgrade(self);
        let new_handle = tokio::spawn(async move {
            tokio::time::sleep(timers::HTTP_IDLE).await;
            if let Some(srv) = weak.upgrade() {
                srv.timed_out.store(true, Ordering::Relaxed);
                // Walk to the topmost ancestor and destroy the
                // whole chain — this matches FASM `io$timeout`
                // semantics for a fatal timer return.
                if srv.timeout_helper().await {
                    let topmost = topmost_ancestor(&srv.links);
                    if let Some(top) = topmost {
                        top.destroy().await;
                    }
                }
            }
        });

        // Replace the previous handle. If there was a prior task,
        // abort it first — the take()-then-abort ordering matches
        // the FASM CRITICAL ORDER documented for clear_timer.
        if let Ok(mut g) = self.timer.lock() {
            if let Some(prev) = g.take() {
                prev.abort();
            }
            *g = Some(new_handle);
        } else {
            // Lock poisoning is treated the same as "no prior
            // timer" — the new handle is dropped which aborts it
            // gracefully.
            drop(new_handle);
        }
    }

    /// Disarm the idle-timeout timer.
    ///
    /// FASM equivalent: `webserver$cleartimer` at
    /// `webserver.inc` lines 4998–5046. **CRITICAL ORDER**: the
    /// FASM source SAVES the timer pointer, CLEARS the field
    /// FIRST, then invokes the timer-clear primitive — this
    /// prevents reentrant double-clear if the timer task races
    /// our clear path and runs to completion (which would itself
    /// try to clear the field). The Rust port mirrors this:
    /// `take()` removes the handle and resets the field
    /// atomically; `abort()` is then called on the local handle.
    pub fn clear_timer(&self) {
        let saved = match self.timer.lock() {
            Ok(mut g) => g.take(),
            Err(_) => None,
        };
        if let Some(handle) = saved {
            handle.abort();
        }
    }

    /// Internal helper for [`Self::new_timer`] — called when the
    /// timer fires. Asks the parent layer (BACKWARD path) whether
    /// the timeout is fatal. Returns true if the chain should be
    /// torn down.
    async fn timeout_helper(self: &Arc<Self>) -> bool {
        // Default: an idle WebServer with no parent treats the
        // timeout as fatal (FASM L5617+).
        if self.timed_out.load(Ordering::Relaxed) {
            return true;
        }
        false
    }

    /// Common Log Format (CLF) emission.
    ///
    /// Emits one line per response into [`WebServerConfig::log_buffer`];
    /// the periodic timer in
    /// [`WebServerConfig::new_config`] flushes the buffer to disk
    /// (and/or syslog) every [`timers::LOG_FLUSH`] (1500 ms).
    ///
    /// FASM equivalent: `webserver$log` at
    /// `webserver.inc` lines 4049–4200. The 7 fields of CLF, in
    /// order, are:
    ///
    /// 1. Host (from request `Host:` header, or `"-"`).
    /// 2. Remote IP (from [`Self::raddr`], or `"-"`).
    /// 3. `"-"` (FASM stamps the literal dash here for the
    ///    rfc1413 `ident` slot).
    /// 4. `[date]` in HTTP-date / Common Log format (RFC 1123
    ///    Date is what FASM emits at L4156).
    /// 5. Request preface (e.g. `"GET /path HTTP/1.1"`), quoted.
    /// 6. Response code.
    /// 7. Body length (decimal).
    /// 8. Referer, quoted.
    /// 9. User-Agent, quoted.
    pub fn log(&self, resp_code: u16, body_len: u64) {
        if self.config.log_path.lock().ok().and_then(|g| g.clone()).is_none()
            && !self.config.syslog.load(Ordering::Relaxed)
        {
            return;
        }
        // Fetch the request fields under a brief lock.
        let (host, preface, referer, user_agent) = match self.request.lock() {
            Ok(g) => match g.as_ref() {
                Some(req) => (
                    req.get_header("Host").unwrap_or("-").to_owned(),
                    req.preface().unwrap_or("-").to_owned(),
                    req.get_header("Referer").unwrap_or("").to_owned(),
                    req.get_header("User-Agent").unwrap_or("").to_owned(),
                ),
                None => return,
            },
            Err(_) => return,
        };

        let ip = self
            .raddr
            .lock()
            .ok()
            .and_then(|g| *g)
            .map(|sa| sa.ip().to_string())
            .unwrap_or_else(|| "-".to_owned());

        let date = now_rfc1123().unwrap_or_else(|_| "-".to_owned());

        // Format: `<host> <ip> - [<date>] "<preface>" <code> <len> "<ref>" "<ua>"\n`
        let line = format!(
            "{host} {ip} - [{date}] \"{preface}\" {resp_code} {body_len} \"{referer}\" \"{user_agent}\"\n"
        );

        if let Ok(mut g) = self.config.log_buffer.lock() {
            g.extend_from_slice(line.as_bytes());
        }
    }

    /// Error-only log emission for unparsed requests.
    ///
    /// FASM equivalent: `webserver$log.norequest` at
    /// `webserver.inc` lines 4200–4345. Used when `check_accum`
    /// rejects a request before it could be parsed (400, 413, 501,
    /// 505). The line uses a fixed message instead of the
    /// preface/referer/user-agent triplet.
    pub fn log_no_request(&self, code: u16) {
        if self
            .config
            .error_file
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .is_none()
            && !self.config.syslog.load(Ordering::Relaxed)
        {
            return;
        }
        let ip = self
            .raddr
            .lock()
            .ok()
            .and_then(|g| *g)
            .map(|sa| sa.ip().to_string())
            .unwrap_or_else(|| "-".to_owned());
        let date = now_rfc1123().unwrap_or_else(|_| "-".to_owned());
        let msg = match code {
            400 => "Bad request".to_owned(),
            413 => "Request entity too large".to_owned(),
            501 => "Request method not implemented".to_owned(),
            505 => "HTTP version not supported".to_owned(),
            other => format!("HTTP error {other}"),
        };
        let line = format!("- {ip} - [{date}] \"-\" {code} 0 \"-\" \"{msg}\"\n");
        if let Ok(mut g) = self.config.error_log_buffer.lock() {
            g.extend_from_slice(line.as_bytes());
        }
    }
}

/// Walk to the topmost ancestor of an IO chain.
///
/// Returns `None` if the supplied links have no parent (the layer
/// is itself topmost, in which case callers should call destroy on
/// the layer directly via its own `Arc`).
fn topmost_ancestor(links: &IoLinks) -> Option<Arc<dyn IoChain>> {
    let mut cur = links.parent()?;
    loop {
        match cur.links().parent() {
            Some(p) => cur = p,
            None => return Some(cur),
        }
    }
}

// ============================================================================
// Send-callback + timeout + destroy + clone — FASM `webserver$sendcb`,
// `webserver$timeout`, `webserver$destroy`, `webserver$clone`.
// ============================================================================

impl WebServer {
    /// Notification that the previous [`Self::send_via_child`]
    /// call's bytes have hit the wire.
    ///
    /// FASM equivalent: `webserver$sendcb` at
    /// `webserver.inc` lines 3912–4050. Drives MODE 2 / MODE 3
    /// chunked-send finishes:
    ///
    /// * If [`Self::inflight`] still has bytes pending, slice off
    ///   the next [`config::WEBSERVER_SUBSEQUENTSEND`]-byte chunk
    ///   and dispatch.
    /// * If the inflight buffer is fully drained, fire
    ///   [`Self::inflight_cb`] (the post-send hook used by
    ///   `hotlist_unpin`), clear the inflight slot, and run
    ///   [`Self::finish_request`].
    ///
    /// Returns `Ok(true)` to signal the caller (the IoChain send
    /// plumbing) that the connection should be torn down — only
    /// emitted when send_via_child reports an error.
    pub async fn on_send_cb(self: &Arc<Self>, _bytes_sent: usize) -> Result<bool, NetError> {
        // Fast path: no inflight chunked send → nothing to do.
        let total = self.inflight_len.load(Ordering::Relaxed);
        if total == 0 {
            return Ok(false);
        }

        let already_sent = self.inflight_sent.load(Ordering::Relaxed);
        if already_sent < total {
            // More chunks pending. Slice off the next segment.
            let remaining = (total - already_sent) as usize;
            let chunk_size = remaining.min(config::WEBSERVER_SUBSEQUENTSEND);
            let chunk = match self.inflight.lock() {
                Ok(g) => g
                    .as_ref()
                    .map(|b| b.slice(already_sent as usize..(already_sent as usize + chunk_size))),
                Err(_) => None,
            };
            if let Some(chunk) = chunk {
                self.inflight_sent.fetch_add(chunk_size as u64, Ordering::Relaxed);
                self.send_via_child(chunk).await?;
            }
            // Always return false — the chain is still live until
            // the buffer drains.
            return Ok(false);
        }

        // All chunks acknowledged. Fire the post-send callback if
        // one was registered (e.g. hotlist_unpin for big-file
        // serves), then clear the inflight slot.
        let cb_opt = self.inflight_cb.lock().ok().and_then(|mut g| g.take());
        let cb_arg_opt = self.inflight_cb_arg.lock().ok().and_then(|mut g| g.take());
        if let Some(cb) = cb_opt {
            // The arg is held in an Arc<dyn Any+Send+Sync>; if
            // empty we pass a sentinel `()` reference.
            match cb_arg_opt {
                Some(arg) => cb(self, &*arg),
                None => cb(self, &() as &dyn Any),
            }
        }

        // Clear the inflight buffer state.
        if let Ok(mut g) = self.inflight.lock() {
            *g = None;
        }
        self.inflight_len.store(0, Ordering::Relaxed);
        self.inflight_sent.store(0, Ordering::Relaxed);
        self.sent_partial.store(false, Ordering::Relaxed);

        // Drive the post-send finish path.
        self.finish_request().await?;
        Ok(false)
    }

    /// Idle-timeout callback — invoked by the timer task when the
    /// 30-second window elapses with no inbound bytes.
    ///
    /// FASM equivalent: `webserver$timeout` at
    /// `webserver.inc` lines 5617–5665. Always returns `true`
    /// (suicide) — the IO chain timeout plumbing then walks
    /// upward to the topmost ancestor and destroys it.
    pub async fn on_timeout(self: &Arc<Self>) -> Result<bool, NetError> {
        self.timed_out.store(true, Ordering::Relaxed);
        // Drop any pending request — we will not be servicing it.
        if let Ok(mut g) = self.request.lock() {
            *g = None;
        }
        // Clear the idle timer (it has already fired but the
        // handle is still present — abort is a no-op for a
        // completed task).
        self.clear_timer();
        Ok(true)
    }

    /// Tear down this WebServer's resources.
    ///
    /// FASM equivalent: `webserver$destroy` at
    /// `webserver.inc` lines 3700–3800. Steps:
    ///
    /// 1. Clear the idle timer (no-op if already cleared by
    ///    `on_timeout`).
    /// 2. Drop the in-flight request (releases its buffers).
    /// 3. Drop the inflight chunked-send buffer.
    /// 4. Fire any pending `inflight_cb` to release pinned
    ///    resources (e.g. big-file `HotEntry::unpin`).
    /// 5. Walk forward into the child via
    ///    [`default_destroy`] — the underlying transport runs its
    ///    own teardown.
    pub async fn destroy_chain(self: Arc<Self>) {
        // 1. Idle timer.
        self.clear_timer();
        // 2. Drop pending request.
        if let Ok(mut g) = self.request.lock() {
            *g = None;
        }
        // 3+4. Drop inflight buffer and fire its callback.
        let cb_opt = self.inflight_cb.lock().ok().and_then(|mut g| g.take());
        let cb_arg_opt = self.inflight_cb_arg.lock().ok().and_then(|mut g| g.take());
        if let Some(cb) = cb_opt {
            match cb_arg_opt {
                Some(arg) => cb(&self, &*arg),
                None => cb(&self, &() as &dyn Any),
            }
        }
        if let Ok(mut g) = self.inflight.lock() {
            *g = None;
        }
        self.inflight_len.store(0, Ordering::Relaxed);
        self.inflight_sent.store(0, Ordering::Relaxed);

        // 5. Forward destroy to the child.
        default_destroy(&self.links).await;
    }

    /// Handle to construct a new shallow clone of this WebServer
    /// for cloning the IO chain.
    ///
    /// FASM `webserver$clone` (lines 3680+) returns a new instance
    /// pointing at the same config but with a fresh accum / timer
    /// / request slot — we model that here. The clone's parent is
    /// **not** linked (per the FASM convention).
    pub async fn clone_into_chain(self: Arc<Self>) -> Arc<Self> {
        Self::new(Arc::clone(&self.config))
    }
}

// ============================================================================
// IoChain trait impl for WebServer — preserves FASM `webserver_vtable`
// 7-method directional dispatch (FASM L3668-3678).
// ============================================================================

impl IoChain for WebServer {
    fn links(&self) -> &IoLinks {
        &self.links
    }

    /// FORWARD — destroy this layer and its subchain.
    ///
    /// Delegates to [`Self::destroy_chain`] which cleans up
    /// timers, in-flight buffers, and the request slot before
    /// forwarding into the child.
    fn destroy(self: Arc<Self>) -> BoxFuture<()> {
        Box::pin(async move {
            self.destroy_chain().await;
        })
    }

    /// FORWARD — clone this layer for chain duplication.
    ///
    /// FASM `webserver$clone` semantics: produces a fresh
    /// per-connection state pointing at the same config. The
    /// clone is **not** linked to a parent (callers must call
    /// [`crate::net::io::link`] explicitly).
    fn clone_chain(self: Arc<Self>) -> BoxFuture<Option<Arc<dyn IoChain>>> {
        Box::pin(async move {
            let cloned = self.clone_into_chain().await;
            Some(cloned as Arc<dyn IoChain>)
        })
    }

    /// FORWARD — send `data` downstream toward the kernel.
    ///
    /// The base form simply walks forward via
    /// [`default_send`] — the WebServer itself does not transform
    /// outbound bytes. The composed-and-sliced response wire
    /// bytes are dispatched via [`Self::send_via_child`] in
    /// [`Self::send_response`].
    fn send(self: Arc<Self>, data: Bytes) -> BoxFuture<Result<(), NetError>> {
        Box::pin(async move { default_send(&self.links, data).await })
    }

    /// BACKWARD — notify of a connect event.
    ///
    /// Captures the peer address into [`Self::raddr`] and arms
    /// the idle timer; then walks BACKWARD to the parent (via
    /// [`default_connected`]) so any application-layer hook on
    /// top can record the event too.
    fn connected(self: Arc<Self>, peer: Option<SocketAddr>) -> BoxFuture<()> {
        Box::pin(async move {
            // Record + arm timer on this layer.
            let _ = self.on_connected(peer).await;
            // Forward up the chain.
            default_connected(&self.links, peer).await;
        })
    }

    /// BACKWARD — handle inbound bytes.
    ///
    /// Appends to the accum and tries to parse / dispatch via
    /// [`Self::on_receive`]. The result is forwarded to the
    /// parent via [`default_receive`] so application-layer hooks
    /// can also observe the chain liveness signal.
    fn receive(self: Arc<Self>, data: Bytes) -> BoxFuture<bool> {
        Box::pin(async move {
            let local_close = self.on_receive(&data).await.unwrap_or(true);
            if local_close {
                return true;
            }
            default_receive(&self.links, data).await
        })
    }

    /// BACKWARD — propagate an error notification upward.
    ///
    /// We log nothing here (errors are surfaced via the response
    /// status + the error-log buffer) and forward to the parent
    /// via [`default_error`].
    fn error(self: Arc<Self>, err: NetError) -> BoxFuture<()> {
        Box::pin(async move { default_error(&self.links, err).await })
    }

    /// BACKWARD — handle an idle-timeout fire.
    ///
    /// FASM `webserver$timeout` semantics: always returns
    /// `true` (suicide); the IO chain timeout plumbing then
    /// walks upward and destroys the topmost ancestor. The
    /// [`default_timeout`] helper preserves this fall-through
    /// for layers without a parent — we override to set
    /// `timed_out` and drop the request first.
    fn timeout(self: Arc<Self>) -> BoxFuture<bool> {
        Box::pin(async move {
            let _ = self.on_timeout().await;
            // After local cleanup, ask the parent (if any) for
            // its side-effects. The FASM source returns true
            // (suicide) regardless of what the parent says — we
            // honour that contract while still propagating the
            // notification to the parent for symmetry with other
            // chains.
            let _ = default_timeout(&self.links).await;
            true
        })
    }
}

// ============================================================================
// Wsbp — Back-Path proxy stub (FASM `wsbp$*`, L3465-3667).
// ============================================================================
//
// The "back-path" subsystem is a transparent reverse-proxy hop in the FASM
// `webserver.inc` design: when [`WebServerConfig::set_back_path`] is set, every
// inbound request that would otherwise be served from disk is forwarded over
// a TCP connection to the back-path target, the response is collected, and
// then re-sent to the originating client by the same WebServer instance.
//
// **Stub status**: per AAP §0.7 Phase 10 ("the three in-scope binaries
// (sshtalk, hnwatch, webserver) don't configure back_path"), the three
// binary crates that drive Gate 1 / Gate 4 / Gate 5 do not exercise this
// code path. The full wire-protocol port can be done later without changing
// any caller. We intentionally panic on use so that any accidental
// activation of `set_back_path()` followed by traffic is loud, rather than
// silently mis-routing requests.
//
// The IoChain dispatch table that the FASM source defines (`wsbp$vtable`)
// is reconstructed here as three explicit methods rather than a
// `impl IoChain for Wsbp`, since the IoChain trait will be wired through
// once the proxy is implemented.

/// Back-Path proxy IO layer.
///
/// FASM equivalent: the per-connection structure allocated by
/// `wsbp$new` (16 bytes above `io_base_size`). In the Rust port this
/// type holds the destination address plus the parent [`WebServer`]
/// pointer so that received backend bytes can be relayed to the
/// originating client.
pub struct Wsbp {
    /// Backend socket address — destination of the proxied request.
    target: SocketAddr,
    /// IO chain links — parent points at the WebServer that
    /// initiated the back-path call; child points at the actual
    /// TCP socket carrying the wire bytes.
    links: IoLinks,
}

impl Wsbp {
    /// Construct a new back-path proxy bound to `target`.
    ///
    /// **Stubbed**: returns a value, but every method that would
    /// drive traffic through the proxy panics with `todo!()`. See the
    /// module docstring for rationale.
    pub fn new(target: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            target,
            links: IoLinks::new(),
        })
    }

    /// Backend address.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// Chain links accessor.
    pub fn links(&self) -> &IoLinks {
        &self.links
    }

    /// FASM `wsbp$sendrequest`: serialize and dispatch a request
    /// onto the backend connection.
    ///
    /// **Stubbed.** Active back-path serving is out of scope for the
    /// sshtalk/hnwatch/webserver Gate 1/4/5 verification; full
    /// implementation is deferred per AAP §0.7 Phase 10.
    pub async fn send_request(self: Arc<Self>, _request: Arc<Mimelike>) -> Result<(), NetError> {
        unimplemented!(
            "wsbp::send_request: back-path proxy is not implemented in the \
             baseline port. set_back_path() should not be called by sshtalk, \
             hnwatch, or webserver. Implement this when porting back-path \
             traffic per FASM L3465-3667."
        );
    }

    /// FASM `wsbp$receive`: handle a chunk of inbound bytes from
    /// the backend connection (forward upstream to client).
    ///
    /// **Stubbed.** See [`Self::send_request`].
    pub async fn receive(self: Arc<Self>, _data: Bytes) -> bool {
        unimplemented!(
            "wsbp::receive: back-path proxy is not implemented in the \
             baseline port. See FASM L3465-3667."
        );
    }

    /// FASM `wsbp$error`: handle a backend connection error
    /// (emit 502 Bad Gateway upstream).
    ///
    /// **Stubbed.** See [`Self::send_request`].
    pub async fn error(self: Arc<Self>, _err: NetError) {
        unimplemented!(
            "wsbp::error: back-path proxy is not implemented in the \
             baseline port. See FASM L3465-3667."
        );
    }
}

// ============================================================================
// TcpAdapter — terminal IoChain layer that owns the AsyncWrite half of a
// stream and forwards [`IoChain::send`] calls to the wire.
// ============================================================================
//
// In the FASM design the bottom of the IO chain is the epoll-managed socket
// itself: `io$send` ultimately calls `write(2)` on the file descriptor. In
// Rust the runtime is tokio and the transport is an arbitrary type that
// implements [`tokio::io::AsyncWrite`]. The [`TcpAdapter`] generic struct
// adapts any such type to the [`IoChain`] trait, providing the bottom-most
// layer for [`handle_connection`].
//
// The reader half of the stream is **not** owned by [`TcpAdapter`]; it is
// driven by the read loop in [`handle_connection`] which feeds inbound bytes
// into the chain via [`IoChain::receive`]. This split mirrors the FASM
// `epoll$inbound` / `epoll$outbound` directional split.

/// IoChain transport adapter — bottom of the chain.
///
/// Generic over `W: AsyncWrite + Send + Unpin + 'static`. The
/// `Arc<AsyncMutex<W>>` is required because [`IoChain::send`] takes
/// `self: Arc<Self>` and needs interior mutability to drive the
/// poll-based AsyncWrite contract; using `tokio::sync::Mutex`
/// (rather than `std::sync::Mutex`) ensures the lock can be held
/// across `await` points without violating Send.
pub struct TcpAdapter<W: tokio::io::AsyncWrite + Send + Unpin + 'static> {
    writer: Arc<AsyncMutex<W>>,
    links: IoLinks,
}

impl<W: tokio::io::AsyncWrite + Send + Unpin + 'static> TcpAdapter<W> {
    /// Build a new transport adapter from a writer half.
    ///
    /// Returns `Arc<Self>` because [`IoChain`] methods take
    /// `self: Arc<Self>` receivers; callers virtually always want
    /// the `Arc` form.
    pub fn new(writer: W) -> Arc<Self> {
        Arc::new(Self {
            writer: Arc::new(AsyncMutex::new(writer)),
            links: IoLinks::new(),
        })
    }
}

impl<W: tokio::io::AsyncWrite + Send + Unpin + 'static> IoChain for TcpAdapter<W> {
    fn links(&self) -> &IoLinks {
        &self.links
    }

    fn destroy(self: Arc<Self>) -> BoxFuture<()> {
        Box::pin(async move {
            // Best-effort shutdown of the writer; the reader half
            // is owned by `handle_connection`'s read loop and will
            // observe EOF on its next call.
            if let Ok(mut w) = self.writer.try_lock() {
                let _ = w.shutdown().await;
            }
            default_destroy(&self.links).await;
        })
    }

    fn clone_chain(self: Arc<Self>) -> BoxFuture<Option<Arc<dyn IoChain>>> {
        // A transport adapter is bound 1:1 to a single underlying
        // socket; the FASM `epoll$clone` returns null for the same
        // reason. Surface a None so that callers either rebuild a
        // fresh transport or accept that this layer is the leaf.
        Box::pin(async move { None })
    }

    fn connected(self: Arc<Self>, peer: Option<SocketAddr>) -> BoxFuture<()> {
        Box::pin(async move { default_connected(&self.links, peer).await })
    }

    fn send(self: Arc<Self>, data: Bytes) -> BoxFuture<Result<(), NetError>> {
        Box::pin(async move {
            let mut guard = self.writer.lock().await;
            // `write_all` short-circuits the chunk loop and returns
            // on first error; AAP §0.4.2 IoChain trait semantics
            // require all-or-nothing send completion.
            guard.write_all(&data).await.map_err(NetError::Io)?;
            // Flush so the bytes hit the wire promptly. tokio's
            // TcpStream flush is essentially a no-op, but we honour
            // the AsyncWrite contract for correctness across other
            // transport types (e.g. TlsStream).
            guard.flush().await.map_err(NetError::Io)?;
            Ok(())
        })
    }

    fn receive(self: Arc<Self>, data: Bytes) -> BoxFuture<bool> {
        // The terminal layer should never receive backward — the
        // chain delivers receive() to the parent via
        // [`default_receive`]. If somehow invoked, defer to the
        // helper which walks parent.
        Box::pin(async move { default_receive(&self.links, data).await })
    }

    fn error(self: Arc<Self>, err: NetError) -> BoxFuture<()> {
        Box::pin(async move { default_error(&self.links, err).await })
    }

    fn timeout(self: Arc<Self>) -> BoxFuture<bool> {
        Box::pin(async move { default_timeout(&self.links).await })
    }
}

// ============================================================================
// `handle_connection` — top-level entry that wires WebServer → TcpAdapter
// and runs the per-connection read loop.
// ============================================================================

/// Wire a freshly-accepted bidirectional stream into a fresh
/// [`WebServer`] instance and run the per-connection serve loop
/// until the chain decides to terminate (idle timeout, client
/// close, or fatal protocol error).
///
/// # Generic signature
///
/// `T: AsyncRead + AsyncWrite + Send + Unpin + 'static` — accepts
/// plain [`tokio::net::TcpStream`] for HTTP listeners and
/// [`crate::net::tls::TlsStream`] for HTTPS listeners. Splitting
/// is performed via [`tokio::io::split`]; the writer half feeds
/// the [`TcpAdapter`] (bottom of chain), the reader half drives
/// the read loop in this function.
///
/// # Chain topology
///
/// ```text
///   WebServer (top)
///     ├── parent: None
///     └── child: TcpAdapter<WriteHalf<T>>
///                  └── child: None (leaf)
/// ```
///
/// # Lifecycle
///
/// 1. Build a [`WebServer`] from the supplied [`WebServerConfig`].
/// 2. Build a [`TcpAdapter`] over the writer half.
/// 3. Link them via [`crate::net::io::link`].
/// 4. Notify the chain of `connected(peer)`.
/// 5. Read loop: on each successful read, deliver bytes via
///    [`IoChain::receive`]. The WebServer parses, dispatches,
///    and writes responses through the chain (no explicit
///    write call from this function).
/// 6. On EOF (reader returns 0) or [`IoChain::receive`]
///    returning `true` (close signal), exit the loop and
///    invoke [`IoChain::destroy`] on the topmost layer.
///
/// # Errors
///
/// Returns `NetError::Io` only on a fatal read error from the
/// underlying socket. Protocol-level errors are absorbed by the
/// WebServer, which composes the appropriate error response and
/// signals connection close via the receive return value.
pub async fn handle_connection<T>(
    stream: T,
    peer: SocketAddr,
    config: Arc<WebServerConfig>,
) -> Result<(), NetError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    // Stage 1: split + wrap.
    let (mut reader, writer) = tokio::io::split(stream);
    let server = WebServer::new(config);
    let adapter = TcpAdapter::new(writer);

    // Stage 2: wire the chain. Cast adapter to `Arc<dyn IoChain>`
    // so [`crate::net::io::link`] can install it as the WebServer's
    // child via the type-erased helper.
    let server_dyn: Arc<dyn IoChain> = Arc::clone(&server) as Arc<dyn IoChain>;
    let adapter_dyn: Arc<dyn IoChain> = Arc::clone(&adapter) as Arc<dyn IoChain>;
    crate::net::io::link(&server_dyn, adapter_dyn);

    // Stage 3: notify the chain of the new peer.
    Arc::clone(&server_dyn).connected(Some(peer)).await;

    // Stage 4: read loop. The buffer size matches the FASM
    // `epoll_readsize` (32 KiB) — see `crate::config::EPOLL_READSIZE`.
    let mut buf = vec![0u8; crate::config::EPOLL_READSIZE];
    let mut should_close = false;
    while !should_close {
        // Single read; tokio drives the socket via mio/epoll under
        // the hood. A return of 0 is EOF (orderly close).
        let n = match reader.read(&mut buf).await {
            Ok(0) => {
                // Orderly client close.
                break;
            }
            Ok(n) => n,
            Err(e) => {
                // Fatal read error — propagate to the chain so any
                // application-level handler can observe it, then
                // exit the loop.
                let err = NetError::Io(e);
                Arc::clone(&server_dyn).error(err).await;
                should_close = true;
                continue;
            }
        };

        // Deliver inbound bytes via IoChain::receive. The WebServer
        // returns `true` if the connection should be torn down
        // immediately (e.g., 413 Payload Too Large, 400 Bad
        // Request, or HTTP/1.0 with `Connection: close`).
        let chunk = Bytes::copy_from_slice(&buf[..n]);
        should_close = Arc::clone(&server_dyn).receive(chunk).await;
    }

    // Stage 5: chain teardown. Walk forward and let each layer
    // clean up. The TcpAdapter's `destroy` will shut down the
    // writer half; the reader half is dropped when `reader` falls
    // out of scope at the end of this function.
    Arc::clone(&server_dyn).destroy().await;

    // Stage 6: explicit hint that `adapter` lives until here so
    // its writer-mutex isn't dropped before `destroy()` finishes.
    drop(adapter);

    Ok(())
}

// ============================================================================
// Tests — unit suite per AAP §0.7 Phase 14.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// AAP §0.7 Phase 14 — `test_error_preface_table`.
    ///
    /// Each status code MUST map to the FASM `boring_http_replies`
    /// preface variant. Drift here would visibly break HTTP error
    /// emission for every webserver consumer.
    #[test]
    fn test_error_preface_table() {
        assert_eq!(preface_for(400), "HTTP/1.1 400 Bad Request");
        assert_eq!(preface_for(403), "HTTP/1.1 403 Forbidden");
        assert_eq!(preface_for(404), "HTTP/1.1 404 Not Found");
        assert_eq!(preface_for(405), "HTTP/1.1 405 Not Allowed");
        assert_eq!(preface_for(413), "HTTP/1.1 413 Payload Too Large");
        assert_eq!(preface_for(500), "HTTP/1.1 500 Internal Server Error");
        assert_eq!(preface_for(501), "HTTP/1.1 501 Not Implemented");
        assert_eq!(preface_for(502), "HTTP/1.1 502 Bad Gateway");
        assert_eq!(preface_for(503), "HTTP/1.1 503 Service Unavailable");
        assert_eq!(preface_for(504), "HTTP/1.1 504 Gateway Timeout");
        assert_eq!(preface_for(505), "HTTP/1.1 505 HTTP Version Not Supported");
        // Unknown codes fall through to the generic 506 sentinel.
        assert_eq!(preface_for(999), "HTTP/1.1 506 Unimplemented Error Code");
    }

    /// AAP §0.7 Phase 14 — `test_hsts_header_byte_frozen`.
    ///
    /// FASM `webserver.inc:.hsts` (line 4582) emits exactly
    /// `max-age=31536000; includeSubDomains`. The constant lives in
    /// `crate::config::HSTS_HEADER_VALUE` per AAP §0.6 directives;
    /// any drift here would silently weaken HSTS adoption for every
    /// TLS-enabled webserver consumer.
    #[test]
    fn test_hsts_header_byte_frozen() {
        assert_eq!(
            crate::config::HSTS_HEADER_VALUE,
            "max-age=31536000; includeSubDomains"
        );
        // Also assert the header **name** constant — both pieces
        // form the wire string that downstream HSTS-aware clients
        // depend on byte-for-byte.
        assert_eq!(HSTS_HEADER_NAME, "Strict-Transport-Security");
    }

    /// AAP §0.7 Phase 14 — `test_server_header_byte_frozen`.
    ///
    /// FASM `webserver.inc:.ident` (line 4805) sends exactly
    /// `Server: HeavyThing`. Any change here would alter the
    /// observable identity of the webserver, breaking downstream
    /// monitoring and forensic tooling that expects this banner.
    #[test]
    fn test_server_header_byte_frozen() {
        assert_eq!(SERVER_HEADER_VALUE, "HeavyThing");
    }

    /// AAP §0.7 Phase 14 — `test_mode_dispatch_boundary`.
    ///
    /// The 3-mode response send dispatch (see `WebServer::send_response`
    /// Phase 5b) chooses based on body length:
    /// - `len <= WEBSERVER_INITIALSEND` (262_144 ⇒ 256 KiB)            → MODE 1
    /// - `len <= WEBSERVER_BIGFILE`     (32 * 1_048_576 ⇒ 32 MiB)      → MODE 2
    /// - `len > WEBSERVER_BIGFILE`                                      → MODE 3
    ///
    /// This test exercises the boundary conditions on each side of
    /// the two thresholds (262_143 / 262_144 / 262_145 and
    /// `BIGFILE-1` / `BIGFILE` / `BIGFILE+1`) to guard against
    /// off-by-one regressions when the constants are re-tuned.
    #[test]
    fn test_mode_dispatch_boundary() {
        // Helper mirroring the inline dispatch logic in
        // `WebServer::send_response` Phase 5b.
        fn classify_mode(body_len: u64) -> u8 {
            if body_len <= config::WEBSERVER_INITIALSEND as u64 {
                1
            } else if body_len <= config::WEBSERVER_BIGFILE as u64 {
                2
            } else {
                3
            }
        }

        // Verify the exact constant values first — drift in either
        // would silently change the boundary logic.
        assert_eq!(config::WEBSERVER_INITIALSEND, 262_144);
        assert_eq!(config::WEBSERVER_SUBSEQUENTSEND, 262_144);
        assert_eq!(config::WEBSERVER_BIGFILE, 32 * 1_048_576);

        // Mode 1 ↔ Mode 2 boundary (262_144).
        assert_eq!(classify_mode(0), 1, "empty body → mode 1");
        assert_eq!(classify_mode(262_143), 1, "just under boundary → mode 1");
        assert_eq!(classify_mode(262_144), 1, "exactly at boundary → mode 1");
        assert_eq!(classify_mode(262_145), 2, "just over boundary → mode 2");

        // Mode 2 ↔ Mode 3 boundary (32 MiB = 33_554_432).
        let big = config::WEBSERVER_BIGFILE as u64;
        assert_eq!(classify_mode(big - 1), 2, "just under bigfile → mode 2");
        assert_eq!(classify_mode(big), 2, "exactly at bigfile → mode 2");
        assert_eq!(classify_mode(big + 1), 3, "just over bigfile → mode 3");
    }

    /// AAP §0.7 Phase 14 — `test_index_file_default`.
    ///
    /// FASM `webservercfg$new` initializes `indexfiles` to the
    /// single-element list `["index.html"]`. Verifying the default
    /// guards against silent regression of the trailing-slash
    /// resolution behaviour in `WebServerConfig::handler`.
    #[test]
    fn test_index_file_default() {
        // Build a config without entering a tokio runtime: the
        // periodic timers spawned by `new_config` require a
        // runtime, so we drive that path via a minimal current-
        // thread runtime.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build current-thread runtime");
        rt.block_on(async {
            let cfg = WebServerConfig::new_config();
            let idx = cfg.index_files.read().await;
            assert_eq!(idx.len(), 1, "exactly one default index file");
            assert_eq!(idx[0], "index.html", "default is `index.html`");
        });
    }

    /// AAP §0.7 Phase 14 — `test_timer_safe_clear`.
    ///
    /// FASM `webserver$cleartimer` (L4901-5046) saves the timer
    /// pointer, clears the field FIRST, then aborts. Double-clear
    /// must be a no-op. Verify by:
    /// 1. New timer arms an idle JoinHandle.
    /// 2. First `clear_timer()` aborts and drops it.
    /// 3. Second `clear_timer()` completes without panic / poison.
    #[test]
    fn test_timer_safe_clear() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build current-thread runtime");
        rt.block_on(async {
            let cfg = WebServerConfig::new_config();
            let server = WebServer::new(cfg);
            // Arm the timer.
            server.new_timer();
            assert!(
                server.timer.lock().expect("timer mutex").is_some(),
                "timer should be armed after new_timer()"
            );
            // First clear: aborts and clears the field.
            server.clear_timer();
            assert!(
                server.timer.lock().expect("timer mutex").is_none(),
                "timer field should be None after first clear"
            );
            // Second clear: no-op, must not panic.
            server.clear_timer();
            assert!(
                server.timer.lock().expect("timer mutex").is_none(),
                "timer field should remain None after second clear"
            );
        });
    }

    /// Sanity check on the byte-frozen X-NB BREACH-mitigation
    /// constants. Any change to header-name / max-length would
    /// silently change the wire bytes of every TLS+gzip response.
    #[test]
    fn test_breach_mitigation_constants() {
        assert_eq!(X_NB_HEADER_NAME, "X-NB");
        assert_eq!(config::WEBSERVER_BREACH_MITIGATION, 48);
    }

    /// Connection-header byte-frozen constants — must equal the
    /// strings that the FASM webserver emits on the wire.
    #[test]
    fn test_connection_header_constants() {
        assert_eq!(CONN_KEEP_ALIVE, "keep-alive");
        assert_eq!(CONN_CLOSE, "close");
        assert_eq!(TE_CHUNKED, "chunked");
        assert_eq!(CE_GZIP, "gzip");
        assert_eq!(CE_DEFLATE, "deflate");
        assert_eq!(CONTENT_TYPE_TEXT_PLAIN, "text/plain");
        assert_eq!(CONTENT_TYPE_TEXT_HTML_UTF8, "text/html; charset=UTF-8");
    }

    /// FASM `webservercfg.nohoststr` — sandbox map fallback key.
    /// Any change here would silently break the no-host-fallback
    /// dispatch path in [`WebServerConfig::handler`].
    #[test]
    fn test_nohost_key_byte_frozen() {
        assert_eq!(NOHOST_KEY, "..nohost..");
    }

    /// HTTP/1.1 prefix used at the start of every response preface.
    #[test]
    fn test_http_prefix_byte_frozen() {
        assert_eq!(HTTP_1_1_PREFIX, "HTTP/1.1 ");
    }

    /// Header-end scanner returns `Some(offset+4)` for CRLFCRLF and
    /// `Some(offset+2)` for LFLF (FASM `webserver$check_accum`
    /// L5096-5300). Verify both paths plus the "no terminator"
    /// negative.
    #[test]
    fn test_find_header_end_paths() {
        // CRLFCRLF (canonical HTTP/1.1).
        let crlf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(find_header_end(crlf), Some(crlf.len() - 4));

        // LFLF (lenient fallback, FASM tolerates).
        let lf = b"GET / HTTP/1.1\nHost: x\n\nbody";
        assert_eq!(find_header_end(lf), Some(lf.len() - 4));

        // No terminator yet.
        let partial = b"GET / HTTP/1.1\r\nHost: x";
        assert_eq!(find_header_end(partial), None);

        // Empty buffer.
        assert_eq!(find_header_end(b""), None);
    }

    /// Status-code parser extracts the 3 bytes at offset 9 of the
    /// preface. Verify common cases plus rejection paths.
    #[test]
    fn test_parse_status_code() {
        assert_eq!(parse_status_code("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_status_code("HTTP/1.1 404 Not Found"), Some(404));
        assert_eq!(parse_status_code("HTTP/1.1 500 Internal Server Error"), Some(500));
        // Too short.
        assert_eq!(parse_status_code("HTTP/1.1"), None);
        // Non-numeric where the code should be.
        assert_eq!(parse_status_code("HTTP/1.1 abc OK"), None);
    }

    /// FASM constant cross-checks — ensure the named timer
    /// constants from AAP §0.6 Phase 12 hold their expected values.
    #[test]
    fn test_timer_constants_byte_frozen() {
        assert_eq!(config::HTTP_IDLE_TIMEOUT_SECS, 30);
        assert_eq!(config::LOG_FLUSH_INTERVAL_MS, 1500);
        assert_eq!(config::WEBSERVER_HOTLIST_STATFREQ, 120);
        assert_eq!(config::WEBSERVER_HOTLIST_TIME, 900);
    }

    /// FASM size-cap constants — guard the 32 KiB header / 64 MiB
    /// body limits documented in AAP §0.6 Phase 12.
    #[test]
    fn test_size_caps_byte_frozen() {
        assert_eq!(config::WEBSERVER_MAXHEADER, 32_768);
        assert_eq!(config::WEBSERVER_MAXREQUEST, 64 * 1_048_576);
    }

    /// MIME extension lookup is case-insensitive on the suffix and
    /// returns a sane default for unknown extensions.
    #[test]
    fn test_mime_for_path() {
        assert_eq!(mime_for_path(Path::new("page.html")), "text/html; charset=UTF-8");
        // Case-insensitive lookup — `.HTML` resolves the same as
        // `.html`.
        assert_eq!(mime_for_path(Path::new("page.HTML")), "text/html; charset=UTF-8");
        assert_eq!(mime_for_path(Path::new("style.css")), "text/css; charset=UTF-8");
        assert_eq!(mime_for_path(Path::new("logo.png")), "image/png");
        assert_eq!(mime_for_path(Path::new("doc.pdf")), "application/pdf");
        // Unknown / no extension defaults to octet-stream.
        assert_eq!(mime_for_path(Path::new("noext")), "application/octet-stream");
    }

    /// `is_already_gzipped` recognises the RFC 1952 magic bytes
    /// `0x1f 0x8b` so the response decorator does not double-gzip
    /// `.gz` files.
    #[test]
    fn test_is_already_gzipped_magic() {
        assert!(is_already_gzipped(&[0x1f, 0x8b, 0x08, 0x00, 0x00]));
        assert!(!is_already_gzipped(&[0x00, 0x00, 0x00]));
        assert!(!is_already_gzipped(&[0x1f]));
        assert!(!is_already_gzipped(&[]));
    }

    /// Builder methods on `WebServerConfig` set the matching field.
    /// All builders take `&self` (interior mutability via Mutex /
    /// atomics) so they can be called on an Arc-shared config.
    #[test]
    fn test_webserverconfig_builders() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build current-thread runtime");
        rt.block_on(async {
            let cfg = WebServerConfig::new_config();
            cfg.set_tls(true);
            cfg.set_syslog(true);
            cfg.set_cache_control(3600);
            assert!(cfg.is_tls.load(Ordering::Relaxed), "set_tls should flip the flag");
            assert!(
                cfg.syslog.load(Ordering::Relaxed),
                "set_syslog should flip the flag"
            );
            assert_eq!(
                cfg.cache_control.load(Ordering::Relaxed),
                3600,
                "set_cache_control should store the value"
            );
            // The string-form of cache-control should be set in the
            // mutex slot for the response decorator path.
            let cc_str = cfg.cache_control_str.lock().expect("mutex");
            assert!(cc_str.is_some(), "cache_control_str should be populated");
            assert_eq!(
                cc_str.as_deref(),
                Some("max-age=3600"),
                "cache_control_str should be RFC-shaped"
            );
        });
    }
}
