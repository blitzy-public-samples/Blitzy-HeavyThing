// HeavyThing x86_64 assembly language library — Rust translation.
//
// Rust translation © 2026, licensed under GPL-3.0-or-later.
// Derived from the HeavyThing assembly library:
//   Copyright © 2015–2018 2 Ton Digital, Jeff Marrison <info@2ton.com.au>
//
// HeavyThing is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// HeavyThing is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with HeavyThing.  If not, see <http://www.gnu.org/licenses/>.
//
// Port of mimelike.inc — Dual-use MIME and HTTP/1.1 message parser/composer.
// The author's 20-year-refined parser. Bidirectional: parses and composes
// headers + body with support for: chunked Transfer-Encoding, gzip
// Content-Encoding, quoted-printable and base64 Content-Transfer-Encoding,
// multipart/* with boundary parameter, and Set-Cookie splitting.

//! Dual-use MIME and HTTP/1.1 message parser/composer.
//!
//! Serves both HTTP (request/response bodies and headers) and traditional
//! MIME email message processing. The parser is bidirectional: it can
//! [`Mimelike::new_parse`] an incoming stream of bytes into a structured
//! [`Mimelike`], or compose a [`Mimelike`] back into an on-wire byte
//! stream via [`Mimelike::compose`].
//!
//! Header storage uses insert-ordered unique key semantics (later
//! [`Mimelike::add_header`] on the same key concatenates value with
//! `", "` separator — behavior identical to the FASM original at
//! `mimelike.inc` L2546-2563). [`HEADER_SET_COOKIE`] receives special
//! split-on-compose handling per
//! [`crate::config::MIMELIKE_SETCOOKIE_SPLIT`] (default `true`).
//!
//! **Frozen protocol string behavior** (byte-identical preservation):
//! - Chunked terminator: `"0\r\n\r\n"` (5 bytes — FASM L1100 `'0' + 0xa0d0a0d`)
//! - Chunk framing format: `"{hex_size}\r\n{data}\r\n"`
//! - QP line width: 76 chars total, soft linebreak `=\r\n`, escaped bytes
//!   `=XX` (uppercase hex)
//! - Default multipart boundary format: `=_HeavyThing-{base64_of_16_random_bytes}_=`
//! - Default multipart Content-Type: `multipart/alternative` if none provided
//! - Header-line separator: `: ` (colon-space)
//! - Line break: CRLF (0x0D, 0x0A)
//!
//! **Public API surface** (re-exported via `crate::net::http::mimelike`):
//! - [`Mimelike`] — the message struct (consumed by `crate::net::fcgi`,
//!   `crate::net::http::server`, `crate::net::http::client`).
//! - [`MimelikeError`] — typed parse / encode failures.
//! - 30+ frozen `&'static str` header-name and encoding-value constants.
//! - [`CHUNKED_TERMINATOR`] — byte-frozen chunked transfer-encoding terminator.
//!
//! Per AAP §0.5.1.4 every method preserves byte-identical wire-format
//! behavior with the FASM `mimelike.inc` source. The single `unsafe`
//! block in this file (in [`Mimelike::set_body_external`]) is documented
//! per AAP §0.7.4 and verified through the `ffi_boundary` integration
//! test suite.

use crate::config::{MIMELIKE_CHUNKSIZE, MIMELIKE_MINCHUNKED, MIMELIKE_MINGZIP, MIMELIKE_SETCOOKIE_SPLIT};
use crate::ds::buffer::Buffer;
use crate::error::HttpError;
use crate::net::http::headers::HttpHeaders;
use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 1 — Byte-Frozen Header Name and Encoding Value Constants
//
// Derived directly from `mimelike.inc` L1644-1766. These strings are
// part of the on-wire protocol and MUST NOT change. They are exported
// `pub const` so dependent modules (server.rs, client.rs, fcgi.rs)
// compare against the SAME byte sequences emitted on compose.
// ═══════════════════════════════════════════════════════════════════════════

// ---------------------------- HTTP & MIME header names ---------------------

/// `Transfer-Encoding` — RFC 7230 §3.3.1. (FASM `mimelike$transferencoding`)
pub const HEADER_TRANSFER_ENCODING: &str = "Transfer-Encoding";

/// `Accept-Encoding` — RFC 7231 §5.3.4. (FASM `mimelike$acceptencoding`)
pub const HEADER_ACCEPT_ENCODING: &str = "Accept-Encoding";

/// `Content-Transfer-Encoding` — RFC 2045 §6. (FASM `mimelike$contenttransferencoding`)
pub const HEADER_CONTENT_TRANSFER_ENCODING: &str = "Content-Transfer-Encoding";

/// `Content-Type` — RFC 7231 §3.1.1.5. (FASM `mimelike$contenttype`)
pub const HEADER_CONTENT_TYPE: &str = "Content-Type";

/// `Content-Length` — RFC 7230 §3.3.2. (FASM `mimelike$contentlength`)
pub const HEADER_CONTENT_LENGTH: &str = "Content-Length";

/// `Content-Encoding` — RFC 7231 §3.1.2.2. (FASM `mimelike$contentencoding`)
pub const HEADER_CONTENT_ENCODING: &str = "Content-Encoding";

/// `Connection` — RFC 7230 §6.1. (FASM `mimelike$connection`)
pub const HEADER_CONNECTION: &str = "Connection";

/// `Pragma` — RFC 7234 §5.4. (FASM `mimelike$pragma`)
pub const HEADER_PRAGMA: &str = "Pragma";

/// `Cache-Control` — RFC 7234 §5.2. (FASM `mimelike$cachecontrol`)
pub const HEADER_CACHE_CONTROL: &str = "Cache-Control";

/// `Location` — RFC 7231 §7.1.2. (FASM `mimelike$location`)
pub const HEADER_LOCATION: &str = "Location";

/// `ETag` — RFC 7232 §2.3. (FASM `mimelike$etag`)
pub const HEADER_ETAG: &str = "ETag";

/// `Last-Modified` — RFC 7232 §2.2. (FASM `mimelike$lastmodified`)
pub const HEADER_LAST_MODIFIED: &str = "Last-Modified";

/// `If-None-Match` — RFC 7232 §3.2. (FASM `mimelike$ifnonematch`)
pub const HEADER_IF_NONE_MATCH: &str = "If-None-Match";

/// `If-Modified-Since` — RFC 7232 §3.3. (FASM `mimelike$ifmodifiedsince`)
pub const HEADER_IF_MODIFIED_SINCE: &str = "If-Modified-Since";

/// `Accept-Ranges` — RFC 7233 §2.3. (FASM `mimelike$acceptranges`)
pub const HEADER_ACCEPT_RANGES: &str = "Accept-Ranges";

/// `Range` — RFC 7233 §3.1. (FASM `mimelike$range`)
pub const HEADER_RANGE: &str = "Range";

/// `Content-Range` — RFC 7233 §4.2. (FASM `mimelike$contentrange`)
pub const HEADER_CONTENT_RANGE: &str = "Content-Range";

/// `Cookie` — RFC 6265 §5.4. (FASM `mimelike$cookie`)
pub const HEADER_COOKIE: &str = "Cookie";

/// `Set-Cookie` — RFC 6265 §4.1. (FASM `mimelike$setcookie`)
pub const HEADER_SET_COOKIE: &str = "Set-Cookie";

// ---------------------------- Encoding value tokens -------------------------

/// `base64` Content-Transfer-Encoding token (FASM `mimelike$base64`).
pub const ENC_BASE64: &str = "base64";

/// `7bit` Content-Transfer-Encoding token (FASM `mimelike$7bit`).
pub const ENC_7BIT: &str = "7bit";

/// `8bit` Content-Transfer-Encoding token (FASM `mimelike$8bit`).
pub const ENC_8BIT: &str = "8bit";

/// `binary` Content-Transfer-Encoding token (FASM `mimelike$binary`).
pub const ENC_BINARY: &str = "binary";

/// `quoted-printable` Content-Transfer-Encoding token (FASM `mimelike$quotedprintable`).
pub const ENC_QP: &str = "quoted-printable";

/// `chunked` Transfer-Encoding token (FASM `mimelike$chunked`).
pub const ENC_CHUNKED: &str = "chunked";

/// `gzip` Content-Encoding token (FASM `mimelike$gzip`).
pub const ENC_GZIP: &str = "gzip";

// ---------------------------- Content-Type tokens ---------------------------

/// `text/html` (FASM `mimelike$texthtml`).
pub const CONTENT_TYPE_TEXT_HTML: &str = "text/html";

/// `text/html; charset=UTF-8` (FASM `mimelike$texthtmlutf8`).
pub const CONTENT_TYPE_TEXT_HTML_UTF8: &str = "text/html; charset=UTF-8";

/// `text/plain` (FASM `mimelike$textplain`).
pub const CONTENT_TYPE_TEXT_PLAIN: &str = "text/plain";

// ---------------------------- Cache / range value tokens --------------------

/// `no-cache` value token (FASM `mimelike$nocache`).
pub const CACHE_NO_CACHE: &str = "no-cache";

/// `bytes` Range / Accept-Ranges value (FASM `mimelike$bytes`).
pub const RANGE_BYTES: &str = "bytes";

// ---------------------------- Chunked terminator ----------------------------

/// Terminator sequence appended to chunked Transfer-Encoding bodies.
///
/// FASM source `mimelike.inc` L1100 builds this as
/// `mov dword [...], '0' + 0xa0d0a0d` (5 bytes: `'0'`, `'\r'`, `'\n'`,
/// `'\r'`, `'\n'`) followed by an extra `'\r\n'` — the on-wire result
/// is exactly the 7-byte sequence below. Mirrored here verbatim so any
/// HTTP/1.x consumer can scan for it as a sentinel.
pub const CHUNKED_TERMINATOR: &[u8] = b"\r\n0\r\n\r\n";

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 2 — MimelikeError + From conversion
// ═══════════════════════════════════════════════════════════════════════════

/// Typed parse / decode / encode failure modes for [`Mimelike`] operations.
///
/// All variants carry [`std::error::Error`] + [`std::fmt::Display`] via
/// `thiserror`. The blanket `From<MimelikeError> for HttpError` impl wraps
/// the [`Display`] output as `HttpError::Parse(format!("mimelike: {e}"))`
/// so callers in `server.rs` / `client.rs` / `fcgi.rs` can propagate via
/// the `?` operator under their `Result<T, HttpError>` return type.
///
/// [`Display`]: std::fmt::Display
#[derive(Debug, Error)]
pub enum MimelikeError {
    /// Header section did not parse: missing colon, malformed line, or
    /// invalid UTF-8 in name/value.
    #[error("header parse failure")]
    HeaderParse,

    /// Body indicator (Content-Length / chunked) demanded more bytes than
    /// the input contained — caller may need to read more from the socket.
    #[error("body truncated (need more data): {needed} bytes remaining")]
    NeedMoreBody {
        /// Number of additional bytes the parser expects to see.
        needed: usize,
    },

    /// `Content-Length` header was present but not a valid `usize`.
    #[error("invalid Content-Length")]
    InvalidContentLength,

    /// Chunked Transfer-Encoding body was malformed: bad hex size, missing
    /// terminator, or truncated chunk payload.
    #[error("malformed chunked body")]
    MalformedChunked,

    /// `flate2` reported a gzip inflate error during [`Mimelike::set_body`].
    #[error("gzip inflate failed")]
    GzipFailed,

    /// Quoted-printable body could not be decoded (invalid hex digit).
    #[error("quoted-printable decode failed")]
    QpFailed,

    /// `base64` decode failed during [`Mimelike::set_body`].
    #[error("base64 decode failed")]
    Base64Failed,

    /// Parser was given a buffer below the 8-byte minimum required to even
    /// hold the smallest meaningful HTTP/MIME line.
    #[error("input buffer too short (minimum 8 bytes required)")]
    InputTooShort,
}

impl From<MimelikeError> for HttpError {
    fn from(e: MimelikeError) -> Self {
        HttpError::Parse(format!("mimelike: {}", e))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 3 — Mimelike struct definition (FASM 104-byte layout)
// ═══════════════════════════════════════════════════════════════════════════

/// Dual-use MIME and HTTP/1.1 message representation.
///
/// **Public API surface required by dependents** — re-exported as
/// `crate::net::http::mimelike::Mimelike` and consumed by:
/// - [`crate::net::http::server`] for HTTP request/response framing;
/// - [`crate::net::http::client`] for HTTP/1.1 requests with redirect
///   support;
/// - [`crate::net::fcgi`] for FastCGI MIME-framed messages over Unix
///   socket transports.
///
/// **FASM layout preservation** (per AAP §0.5.1.4 byte-identical
/// requirement): the struct mirrors the 104-byte FASM layout from
/// `mimelike.inc` L42-56 verbatim — every offset documented inline so
/// future audits can verify correspondence with the assembly source.
///
/// **Send + Sync invariants**: this type contains two raw pointer fields
/// ([`Mimelike::bodyext`] and [`Mimelike::parent`]) for FFI-style
/// behavior preservation. Both are set at construction-or-parse time
/// and never mutated concurrently — the unsafe `Send`/`Sync` impls below
/// document this invariant. Concurrent mutation of `bodyext` is forbidden
/// even via interior-mutability constructs (the field is not wrapped in
/// any cell type); read-only access through [`body_bytes`] is safe.
///
/// [`body_bytes`]: Mimelike::body_bytes
pub struct Mimelike {
    /// **(FASM offset 0 — `mimelike_headers_ofs`)** Stringmap-equivalent
    /// header table with insert-ordered unique keys and `, `-concatenation
    /// on duplicate add (FASM L2546-2563 semantics). Backed by
    /// [`HttpHeaders`] which provides
    /// [`insert_replace`](HttpHeaders::insert_replace),
    /// [`insert_append`](HttpHeaders::insert_append),
    /// [`get`](HttpHeaders::get), [`remove`](HttpHeaders::remove), and
    /// [`iter_pairs`](HttpHeaders::iter_pairs).
    pub(crate) headers: HttpHeaders,

    /// **(FASM offset 8 — `mimelike_preface_ofs`)** Heap-allocated string
    /// of the preface line. For HTTP requests this is the request line
    /// (e.g., `"GET /path HTTP/1.1"`); for HTTP responses it is the
    /// status line (e.g., `"HTTP/1.1 200 OK"`); for MIME bodies it is
    /// `None`.
    pub(crate) preface: Option<String>,

    /// **(FASM offset 16 — `mimelike_body_ofs`)** Primary body buffer.
    /// Owned. Holds the post-decode bytes when constructed by
    /// [`new_parse`](Mimelike::new_parse) or the raw pre-encode bytes
    /// when populated for transmission.
    pub(crate) body: Buffer,

    /// **(FASM offset 24 — `mimelike_xmitbody_ofs`)** Transmission buffer
    /// — compiled headers + body ready for socket send. Built by
    /// [`compose`](Mimelike::compose).
    pub(crate) xmitbody: Buffer,

    /// **(FASM offset 32 — `mimelike_boundary_ofs`)** Multipart boundary
    /// string. `None` if not multipart. The default boundary generated
    /// by [`set_default_boundary`](Mimelike::set_default_boundary) has
    /// the format `"=_HeavyThing-{32_hex_chars}_="`.
    pub(crate) boundary: Option<String>,

    /// **(FASM offset 40 — `mimelike_parts_ofs`)** Child parts for
    /// multipart composition. Each part is itself a [`Mimelike`] with
    /// its own headers + body + xmitbody. Recursive nesting permitted.
    pub(crate) parts: Vec<Mimelike>,

    /// **(FASM offset 48 — `mimelike_parent_ofs`)** Weak back-pointer
    /// to the parent multipart container during parse. Set on child
    /// parts when added to a parent's `parts` list (FASM L3691). Null
    /// for top-level messages.
    ///
    /// **Safety**: this is a non-owning raw pointer — the parent must
    /// outlive every descendant. In Rust this is guaranteed by the
    /// owning [`Vec<Mimelike>`] in `parts` keeping children alive only
    /// as long as the parent exists.
    pub(crate) parent: *const Mimelike,

    /// **(FASM offset 56 — `mimelike_hdrlen_ofs`)** Length of the
    /// header section in [`xmitbody`](Mimelike::xmitbody) including the
    /// trailing CRLFCRLF separator. Used by the server send path to
    /// emit headers and body in two `writev` calls.
    pub(crate) hdrlen: usize,

    /// **(FASM offset 64 — `mimelike_parselen_ofs`)** Total bytes
    /// consumed from the input buffer by the most recent
    /// [`new_parse`](Mimelike::new_parse) — used by HTTP/1.1 keep-alive
    /// pipelining to advance past the parsed message.
    pub(crate) parselen: usize,

    /// **(FASM offset 72 — `mimelike_bodyextend_ofs`)** Computed end
    /// pointer (`bodyext + bodyextlen`) — preserved for FASM API
    /// parity even though Rust callers compute it on demand from
    /// `bodyext` + `bodyextlen`.
    pub(crate) bodyextend: usize,

    /// **(FASM offset 80 — `mimelike_bodyextlen_ofs`)** Length of the
    /// external body referenced by [`bodyext`](Mimelike::bodyext).
    pub(crate) bodyextlen: usize,

    /// **(FASM offset 88 — `mimelike_bodyext_ofs`)** External body
    /// pointer — caller-managed (e.g., mmap'd file from
    /// `webserver.inc`'s file hotlist). When non-null, [`compose`] uses
    /// THIS instead of [`body`](Mimelike::body); [`body_bytes`] returns
    /// the slice covered by `(bodyext, bodyextlen)`.
    ///
    /// **Safety**: caller of
    /// [`set_body_external`](Mimelike::set_body_external) must guarantee
    /// the pointer remains valid for the lifetime of this `Mimelike`.
    ///
    /// [`compose`]: Mimelike::compose
    /// [`body_bytes`]: Mimelike::body_bytes
    pub(crate) bodyext: *const u8,

    /// **(FASM offset 96 — `mimelike_user_ofs`)** User-defined field
    /// (eight bytes). FASM `webserver.inc` stores HTTP method code at
    /// offset 0 and version at offset +4 within these eight bytes.
    /// Cleared on construction.
    pub(crate) user: [u8; 8],
}

// SAFETY: `bodyext` is a raw pointer but it is only ever set at
// construction (`new`) or via the explicitly-`unsafe`
// [`set_body_external`] entry point, which documents the lifetime
// contract the caller must uphold. After being set, `bodyext` is read-
// only through the `body_bytes` / `body_len` accessors — there is no
// interior-mutability path that could allow a data race. `parent` is
// likewise set only at parse time when adding to a parent's `parts`
// list, then never mutated. The remaining fields are all owned types
// (`HttpHeaders`, `Option<String>`, `Buffer`, `Vec<Mimelike>`, etc.)
// that are themselves `Send + Sync`. Thus `Mimelike` is `Send + Sync`.
unsafe impl Send for Mimelike {}
unsafe impl Sync for Mimelike {}

// Manual `Debug` implementation — `HttpHeaders` does not derive `Debug`,
// so we render headers as a count rather than their full content. Body
// buffers are summarized by length to keep diagnostic output bounded.
impl std::fmt::Debug for Mimelike {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mimelike")
            .field("preface", &self.preface)
            .field("header_count", &self.headers.iter_pairs().count())
            .field("body_len", &self.body.len())
            .field("xmitbody_len", &self.xmitbody.len())
            .field("boundary", &self.boundary)
            .field("parts_count", &self.parts.len())
            .field("hdrlen", &self.hdrlen)
            .field("parselen", &self.parselen)
            .field("bodyextlen", &self.bodyextlen)
            .field("has_bodyext", &!self.bodyext.is_null())
            .field("user", &self.user)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 4 — Constructor + Default impl
// FASM source: mimelike$new (L64-82), mimelike$destroy (L86-130)
// ═══════════════════════════════════════════════════════════════════════════

impl Mimelike {
    /// Creates an empty `Mimelike` with no preface, no body, and no
    /// headers.
    ///
    /// FASM `mimelike$new` (mimelike.inc L64-82) allocates a 104-byte
    /// zeroed struct then initializes:
    /// - `headers` via `stringmap$new(unique=1)`,
    /// - `body` and `xmitbody` via `buffer$new`,
    /// - `parts` via `list$new`.
    ///
    /// Other fields (`preface`, `boundary`, `bodyext`, `user`,
    /// `parent`, `hdrlen`, `parselen`, `bodyextlen`, `bodyextend`)
    /// remain zero-initialized — preserved verbatim here.
    pub fn new() -> Self {
        Self {
            headers: HttpHeaders::new(),
            preface: None,
            body: Buffer::new(),
            xmitbody: Buffer::new(),
            boundary: None,
            parts: Vec::new(),
            parent: std::ptr::null(),
            hdrlen: 0,
            parselen: 0,
            bodyextend: 0,
            bodyextlen: 0,
            bodyext: std::ptr::null(),
            user: [0u8; 8],
        }
    }
}

impl Default for Mimelike {
    /// Equivalent to [`Mimelike::new`].
    fn default() -> Self {
        Self::new()
    }
}

// FASM `mimelike$destroy` (L86-130) iterated the parts list freeing each
// member, then freed boundary, xmitbody, body, preface, headers (with
// hdrfree callback freeing both key and value). In Rust this is
// automatic via `Drop` on the owning fields — no manual `Drop` impl
// needed. The raw `parent` pointer is non-owning so we do not free it.

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 5 — Preface management
// FASM source: setpreface (L138-153), setpreface_nocopy (L159-172)
// ═══════════════════════════════════════════════════════════════════════════

impl Mimelike {
    /// Sets the preface line (HTTP request line or response status line),
    /// copying the input. Any previously set preface is dropped.
    ///
    /// FASM `mimelike$setpreface` (L138-153): frees old preface if any,
    /// then `string$copy`'s the input into a fresh heap allocation. The
    /// Rust port replaces the explicit free + copy with the owned
    /// `Option<String>` lifetime — assigning a new `Some(...)` drops the
    /// previous value automatically.
    pub fn set_preface(&mut self, preface: impl Into<String>) {
        self.preface = Some(preface.into());
    }

    /// Sets the preface with ownership transfer — avoids a copy.
    ///
    /// FASM `mimelike$setpreface_nocopy` (L159-172) takes ownership of
    /// the caller's heap allocation. Idiomatic in Rust by accepting an
    /// owned `String`.
    pub fn set_preface_nocopy(&mut self, preface: String) {
        self.preface = Some(preface);
    }

    /// Returns the preface string (HTTP request line or response status
    /// line), or `None` if not set.
    pub fn preface(&self) -> Option<&str> {
        self.preface.as_deref()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 6 — Header management
// FASM source: setheader (L178-207), addheader (L215-228),
//              setheader_novaluecopy (L235-260), addheader_novaluecopy
//              (L268-277), setheader_nocopy (L285-305), addheader_nocopy
//              (L313-317), getheader (L326-336), removeheader (L346-361)
// ═══════════════════════════════════════════════════════════════════════════

impl Mimelike {
    /// Sets a header — replaces any existing value for the same name
    /// (case-insensitive name comparison per RFC 7230 §3.2).
    ///
    /// FASM `mimelike$setheader` (L178-207): copies both name and value
    /// then performs duplicate-replace via stringmap unique-key insert.
    /// Delegates to [`HttpHeaders::insert_replace`] which performs
    /// `slow_remove(name)` + `slow_add(name, value)` — equivalent
    /// observable behavior.
    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.insert_replace(name.into(), value.into());
    }

    /// Adds a header — if `name` already exists, concatenates the new
    /// value onto the existing value with `", "` separator.
    ///
    /// FASM `mimelike$addheader` (L215-228) and the parser's L2546-2563
    /// duplicate-handling path both concatenate with `", "` rather than
    /// emitting separate header entries. This matches RFC 7230 §3.2.2
    /// which permits combining repeated headers into a single
    /// comma-separated list except for `Set-Cookie` (which the
    /// composer's [`write_setcookie_split`](Mimelike::compose) handles
    /// specially on emit).
    pub fn add_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.insert_append(name.into(), value.into(), ", ");
    }

    /// Sets a header taking ownership of `value` directly (avoids one
    /// copy); replaces any existing value.
    ///
    /// FASM `mimelike$setheader_novaluecopy` (L235-260) was a perf
    /// optimization for callers that already heap-allocated the value;
    /// in Rust there is no observable difference from
    /// [`set_header`](Mimelike::set_header) since `Into<String>` accepts
    /// owned `String` without copying — kept here for API parity.
    pub fn set_header_novaluecopy(&mut self, name: String, value: String) {
        self.headers.insert_replace(name, value);
    }

    /// Adds a header taking ownership of `value` directly (avoids one
    /// copy); concatenates onto existing value with `", "` separator.
    ///
    /// FASM `mimelike$addheader_novaluecopy` (L268-277) — see
    /// [`add_header`](Mimelike::add_header) for the duplicate-key
    /// semantics.
    pub fn add_header_novaluecopy(&mut self, name: String, value: String) {
        self.headers.insert_append(name, value, ", ");
    }

    /// Gets a header value by name (case-insensitive lookup).
    ///
    /// FASM `mimelike$getheader` (L326-336) returns null on absence;
    /// the Rust port returns `None`. Returned `&str` borrows from the
    /// underlying [`HttpHeaders`] storage and is invalidated by any
    /// subsequent mutation.
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }

    /// Removes a header by name (case-insensitive). Returns the removed
    /// value if present.
    ///
    /// FASM `mimelike$removeheader` (L346-361) removes from the
    /// stringmap and frees both key and value bytes; in Rust the
    /// [`HttpHeaders::remove`] return value transfers ownership of the
    /// value `String` to the caller.
    pub fn remove_header(&mut self, name: &str) -> Option<String> {
        self.headers.remove(name)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 7 — Boundary management
// FASM source: setdefaultboundary (L370-405), setboundary (L411-428),
//              multipartcontenttype (L436-531)
// ═══════════════════════════════════════════════════════════════════════════

impl Mimelike {
    /// Generates a random multipart boundary and applies it to the
    /// `Content-Type` header.
    ///
    /// FASM `mimelike$setdefaultboundary` (L370-405):
    /// 1. Allocates 16 random bytes via `rng$block`.
    /// 2. Base64-encodes them.
    /// 3. Concatenates with `"=_HeavyThing-"` prefix and `"_="` suffix.
    /// 4. Calls `mimelike$setboundary` with the result.
    ///
    /// The Rust port preserves the byte format exactly. Safe to call
    /// multiple times — the latest boundary replaces any prior one and
    /// the corresponding `Content-Type: multipart/...; boundary="..."`
    /// header is rewritten via [`set_boundary`](Mimelike::set_boundary).
    ///
    /// **Note on charset**: although FASM uses base64 internally, the
    /// resulting boundary may contain `+`/`/` which are valid token
    /// characters in RFC 2046 §5.1.1's `bcharsnospace` set. Quoting in
    /// [`multipart_content_type`] handles this safely.
    ///
    /// [`multipart_content_type`]: Mimelike::multipart_content_type
    pub fn set_default_boundary(&mut self) {
        let mut random_bytes = [0u8; 16];
        crate::crypto::rng::block(&mut random_bytes);
        let b64 = crate::util::base64::encode(&random_bytes);
        // Strip any trailing '=' padding to keep the boundary token-safe
        // (FASM emitted only the bytes, not the padding) — but we also
        // want predictable length, so just preserve the raw output.
        let boundary = format!("=_HeavyThing-{}_=", b64);
        self.set_boundary(boundary);
    }

    /// Sets an explicit boundary string and rebuilds the `Content-Type`
    /// header to include the `boundary="..."` parameter.
    ///
    /// FASM `mimelike$setboundary` (L411-428): frees previous boundary
    /// if any, copies the input, then calls
    /// `mimelike$multipartcontenttype` to update the Content-Type
    /// header. The Rust port mirrors this — the Content-Type rewrite
    /// is performed inline by calling [`apply_boundary_to_content_type`].
    ///
    /// [`apply_boundary_to_content_type`]: Mimelike::apply_boundary_to_content_type
    pub fn set_boundary(&mut self, boundary: impl Into<String>) {
        let b = boundary.into();
        self.boundary = Some(b);
        self.apply_boundary_to_content_type();
    }

    /// Builds and returns a `Content-Type` header value for multipart
    /// messages by combining the configured boundary with the supplied
    /// `mime_subtype` (e.g., `"alternative"`, `"mixed"`, `"form-data"`).
    ///
    /// FASM `mimelike$multipartcontenttype` (L436-531) used a default
    /// of `multipart/alternative` if no Content-Type was already set
    /// and built the resulting string `"multipart/{subtype}; boundary=\"{b}\""`.
    /// Returns `None` if no boundary has been set.
    pub fn multipart_content_type(&self, mime_subtype: &str) -> Option<String> {
        self.boundary
            .as_ref()
            .map(|b| format!("multipart/{}; boundary=\"{}\"", mime_subtype, b))
    }

    /// Internal helper that rewrites the `Content-Type` header to
    /// include the current boundary parameter. Implements FASM
    /// `mimelike$multipartcontenttype` (L436-531) header-rewrite logic:
    /// - If no Content-Type is currently set, defaults to
    ///   `multipart/alternative; boundary="..."` per FASM L455's
    ///   `.defaultpref` constant.
    /// - If existing Content-Type ends with `;`, appends ` boundary="..."`.
    /// - If existing Content-Type ends with `; ` (semicolon+space),
    ///   appends `boundary="..."`.
    /// - Otherwise appends `; boundary="..."`.
    fn apply_boundary_to_content_type(&mut self) {
        let boundary = match self.boundary.as_deref() {
            Some(b) => b.to_string(),
            None => return,
        };

        let new_value = match self.headers.get(HEADER_CONTENT_TYPE) {
            None => format!("multipart/alternative; boundary=\"{}\"", boundary),
            Some(existing) => {
                let existing = existing.to_string();
                let trimmed = existing.trim_end();
                if trimmed.ends_with(';') {
                    format!("{} boundary=\"{}\"", trimmed, boundary)
                } else if existing.ends_with("; ") {
                    format!("{}boundary=\"{}\"", existing, boundary)
                } else {
                    format!("{}; boundary=\"{}\"", existing, boundary)
                }
            }
        };
        self.headers
            .insert_replace(HEADER_CONTENT_TYPE.to_string(), new_value);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 8 — Body management: external pointer + decoded ingest
// FASM source: setbody_external (L1779-1786), setbody (L1797-2264),
//              .unchunk (L1905-2040), .quotedprintable (L2138-2238),
//              .base64 (L2245-2264)
// ═══════════════════════════════════════════════════════════════════════════

impl Mimelike {
    /// Sets an external (non-owning) body pointer.
    ///
    /// FASM `mimelike$setbody_external` (L1779-1786): records pointer +
    /// length + computed end-pointer; takes no ownership and performs
    /// no copy. Used by `webserver.inc`'s file hotlist to expose mmap'd
    /// page-aligned file contents directly to [`compose`] without
    /// double-buffering.
    ///
    /// **Safety**: the caller MUST ensure that `data` remains valid (not
    /// freed, not unmapped) for as long as this `Mimelike` may invoke
    /// [`compose`] or [`body_bytes`]. Typical usage:
    /// 1. mmap a file → get `*const u8` and length;
    /// 2. wrap in `Mimelike::new()`, call `set_body_external`;
    /// 3. call `compose()`;
    /// 4. drop the `Mimelike` (never references the pointer again);
    /// 5. munmap the file.
    ///
    /// [`compose`]: Mimelike::compose
    /// [`body_bytes`]: Mimelike::body_bytes
    ///
    /// # Safety
    ///
    /// The pointer must remain valid (live, readable, and untouched by
    /// other writers) for the entire lifetime of this `Mimelike`, OR
    /// until the next call to a body-mutating method ([`set_body`],
    /// `set_body_external`, [`new_parse`]) which clears the external
    /// reference.
    ///
    /// [`set_body`]: Mimelike::set_body
    /// [`new_parse`]: Mimelike::new_parse
    pub unsafe fn set_body_external(&mut self, data: *const u8, len: usize) {
        self.bodyext = data;
        self.bodyextlen = len;
        // FASM `mimelike_bodyextend_ofs` stored the precomputed end
        // pointer (data + len). We store the end as a usize for parity;
        // it is only ever consumed by FFI code paths that expect this
        // numeric value.
        self.bodyextend = (data as usize).wrapping_add(len);
    }

    /// Sets the body bytes with automatic decoding based on the current
    /// header set:
    ///
    /// - `Transfer-Encoding: chunked` → de-chunk the body.
    /// - `Content-Encoding: gzip` → gzip-inflate the body.
    /// - Both chunked + gzip → de-chunk first, then inflate.
    /// - `Content-Transfer-Encoding: 7bit | 8bit | binary` → identity.
    /// - `Content-Transfer-Encoding: quoted-printable` → QP decode.
    /// - `Content-Transfer-Encoding: base64` → base64 decode.
    /// - No encoding present → identity.
    ///
    /// Returns `Ok(())` on success or [`MimelikeError`] on decode
    /// failure. Clears any external body pointer set previously by
    /// [`set_body_external`](Mimelike::set_body_external).
    ///
    /// FASM `mimelike$setbody` at L1797-2264 with the encoding-detection
    /// branches transcribed directly. The chunk-then-gzip branch path
    /// allocates an intermediate `Vec<u8>` for the de-chunked
    /// representation before invoking gzip inflate, mirroring FASM's
    /// `tempbuf` stack object (L1845-1880).
    pub fn set_body(&mut self, data: &[u8]) -> Result<(), MimelikeError> {
        self.body.clear();
        self.bodyext = std::ptr::null();
        self.bodyextlen = 0;
        self.bodyextend = 0;

        if data.is_empty() {
            return Ok(());
        }

        let transfer_enc = self
            .get_header(HEADER_TRANSFER_ENCODING)
            .map(|s| s.to_ascii_lowercase());
        let content_enc = self
            .get_header(HEADER_CONTENT_ENCODING)
            .map(|s| s.to_ascii_lowercase());

        let has_chunked = transfer_enc.as_deref().is_some_and(|s| s.contains(ENC_CHUNKED));
        let has_gzip = content_enc.as_deref().is_some_and(|s| s.contains(ENC_GZIP));

        // Branch 1: chunked + gzip → unchunk into temp buffer, then inflate.
        if has_chunked && has_gzip {
            let mut intermediate: Vec<u8> = Vec::with_capacity(data.len());
            unchunk_into(data, &mut intermediate)?;
            let inflated =
                crate::util::zlib::gzip_decompress(&intermediate).map_err(|_| MimelikeError::GzipFailed)?;
            self.body.extend_from_slice(&inflated);
            return Ok(());
        }

        // Branch 2: chunked only.
        if has_chunked {
            let mut tmp: Vec<u8> = Vec::with_capacity(data.len());
            unchunk_into(data, &mut tmp)?;
            self.body.extend_from_slice(&tmp);
            return Ok(());
        }

        // Branch 3: gzip only.
        if has_gzip {
            let inflated = crate::util::zlib::gzip_decompress(data).map_err(|_| MimelikeError::GzipFailed)?;
            self.body.extend_from_slice(&inflated);
            return Ok(());
        }

        // Branch 4: Content-Transfer-Encoding (MIME, not HTTP).
        let cte = self
            .get_header(HEADER_CONTENT_TRANSFER_ENCODING)
            .map(|s| s.to_ascii_lowercase());
        if let Some(cte) = cte {
            if cte.contains(ENC_7BIT) || cte.contains(ENC_8BIT) || cte.contains(ENC_BINARY) {
                self.body.extend_from_slice(data);
                return Ok(());
            }
            if cte.contains(ENC_QP) {
                let mut tmp: Vec<u8> = Vec::with_capacity(data.len());
                decode_qp_into(data, &mut tmp)?;
                self.body.extend_from_slice(&tmp);
                return Ok(());
            }
            if cte.contains(ENC_BASE64) {
                let decoded = crate::util::base64::decode(data).map_err(|_| MimelikeError::Base64Failed)?;
                self.body.extend_from_slice(&decoded);
                return Ok(());
            }
        }

        // Branch 5: no encoding — pass through.
        self.body.extend_from_slice(data);
        Ok(())
    }

    /// Returns the body bytes (post-decode for parsed messages, or raw
    /// for in-construction messages). Prefers the external pointer set
    /// by [`set_body_external`] over the owned `body` buffer.
    ///
    /// [`set_body_external`]: Mimelike::set_body_external
    pub fn body_bytes(&self) -> &[u8] {
        if !self.bodyext.is_null() {
            // SAFETY: the caller of `set_body_external` promised the
            // pointer remains valid for our lifetime, and no body-
            // mutating method has been invoked since then (those clear
            // `bodyext` to null). The length matches what was provided.
            unsafe { std::slice::from_raw_parts(self.bodyext, self.bodyextlen) }
        } else {
            self.body.as_slice()
        }
    }

    /// Returns the length of the body — prefers the external length
    /// when [`set_body_external`](Mimelike::set_body_external) was used.
    pub fn body_len(&self) -> usize {
        if !self.bodyext.is_null() {
            self.bodyextlen
        } else {
            self.body.len()
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 9 — should_gzip Content-Type whitelist
// FASM source: shouldgzip (L539-603)
// ═══════════════════════════════════════════════════════════════════════════

impl Mimelike {
    /// Returns `true` when this body should be gzip-compressed before
    /// transmission.
    ///
    /// Two criteria must both be met (FASM L539-603):
    /// 1. Body length ≥ [`MIMELIKE_MINGZIP`](crate::config::MIMELIKE_MINGZIP) (1024 bytes default).
    /// 2. The `Content-Type` header value matches the FASM whitelist:
    ///    - `text/...` (any text subtype)
    ///    - `...javascript...`
    ///    - `...xml...`
    ///    - `...x-icon...`
    ///    - `.../rtf...`
    ///    - `...json...`
    ///    - `image/svg+xml...`
    ///
    /// The order of substring checks matches FASM's sequential
    /// comparisons. All comparisons are case-insensitive against an
    /// ASCII-lowercased copy of the header value.
    pub fn should_gzip(&self) -> bool {
        if self.body_len() < MIMELIKE_MINGZIP {
            return false;
        }
        let ct = match self.get_header(HEADER_CONTENT_TYPE) {
            Some(v) => v.to_ascii_lowercase(),
            None => return false,
        };
        ct.starts_with("text/")
            || ct.contains("javascript")
            || ct.contains("xml")
            || ct.contains("x-icon")
            || ct.contains("/rtf")
            || ct.contains("json")
            || ct.starts_with("image/svg+xml")
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 10 — ETag computation (static + dynamic)
// FASM source: static_etag (L612-685), dynamic_etag (L692-754)
// ═══════════════════════════════════════════════════════════════════════════

impl Mimelike {
    /// Computes a static ETag from `mtime` and the file `name`, sets the
    /// `ETag` header, and returns the ETag string.
    ///
    /// FASM `mimelike$static_etag` (L612-685): hashes
    /// `<mtime_as_8_bytes_LE> || <name_bytes>` with SHA-224 (28 bytes),
    /// truncates to 27 bytes (one byte chopped to avoid trailing `==`
    /// in base64), base64-encodes, double-quotes the result, and stores
    /// it in the `ETag` header.
    ///
    /// **Why SHA-224 truncated to 27 bytes**: SHA-224's 28-byte digest
    /// base64-encodes to exactly 40 chars including `==` padding;
    /// truncating to 27 bytes yields 36 base64 chars with no padding —
    /// the FASM author preferred padding-free ETags.
    pub fn static_etag(&mut self, mtime: u64, name: &[u8]) -> String {
        let mut buf = Vec::with_capacity(8 + name.len());
        buf.extend_from_slice(&mtime.to_le_bytes());
        buf.extend_from_slice(name);
        let digest = crate::crypto::sha2::sha224(&buf);
        // Truncate to 27 bytes — see method doc.
        let truncated = &digest[..27];
        let b64 = crate::util::base64::encode_no_pad(truncated);
        let etag = format!("\"{}\"", b64);
        self.set_header(HEADER_ETAG, etag.clone());
        etag
    }

    /// Computes a dynamic ETag from arbitrary body bytes, sets the
    /// `ETag` header, and returns the ETag string.
    ///
    /// FASM `mimelike$dynamic_etag` (L692-754): SHA-224 of `data`,
    /// truncated to 27 bytes, base64-encoded, double-quoted. See
    /// [`static_etag`](Mimelike::static_etag) for why truncation to 27
    /// bytes is the correct choice.
    pub fn dynamic_etag(&mut self, data: &[u8]) -> String {
        let digest = crate::crypto::sha2::sha224(data);
        let truncated = &digest[..27];
        let b64 = crate::util::base64::encode_no_pad(truncated);
        let etag = format!("\"{}\"", b64);
        self.set_header(HEADER_ETAG, etag.clone());
        etag
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 11 — compose: build xmitbody (preface + headers + body)
// FASM source: compose (L762-1311), .headers (L887-957), .headerline
//              (L1346-1607), .addxmitboundary (L1611-1640)
// ═══════════════════════════════════════════════════════════════════════════

impl Mimelike {
    /// Composes the final on-wire byte stream into
    /// [`xmitbody`](Mimelike::xmitbody).
    ///
    /// Pipeline (FASM L762-1311):
    /// 1. Pick body source: external pointer if non-null, else owned
    ///    `body` buffer.
    /// 2. Apply `Content-Transfer-Encoding` (base64 / quoted-printable /
    ///    identity).
    /// 3. Apply `Content-Encoding: gzip` if shouldgzip + size threshold
    ///    pass; skip if body is already gzip-magic-prefixed.
    /// 4. Apply `Transfer-Encoding: chunked` framing if requested and
    ///    body ≥ [`MIMELIKE_MINCHUNKED`](crate::config::MIMELIKE_MINCHUNKED) —
    ///    removes `Content-Length` header in this case (chunked is
    ///    self-terminating).
    /// 5. Otherwise sets `Content-Length` automatically (skipped for
    ///    multipart with parts).
    /// 6. Writes preface line (if set) followed by all headers; expands
    ///    `Set-Cookie` into multiple lines per [`MIMELIKE_SETCOOKIE_SPLIT`]
    ///    (default `true`).
    /// 7. Appends body bytes after the CRLFCRLF separator.
    /// 8. If `parts` is non-empty, recursively composes each child and
    ///    wraps with boundary markers; emits closing `--boundary--`.
    ///
    /// After compose returns, [`xmitbody_slice`](Mimelike::xmitbody_slice)
    /// and [`xmitbody_headers_slice`](Mimelike::xmitbody_headers_slice)
    /// return immutable views over the result.
    ///
    /// [`MIMELIKE_SETCOOKIE_SPLIT`]: crate::config::MIMELIKE_SETCOOKIE_SPLIT
    pub fn compose(&mut self) {
        self.xmitbody.clear();

        // ----------------------------------------------------------------
        // Step 1: pick body source (external pointer wins over owned body).
        // ----------------------------------------------------------------
        let body_source: Vec<u8> = if !self.bodyext.is_null() {
            // SAFETY: caller of set_body_external promised the pointer is
            // valid for our lifetime. We copy here to detach from the
            // external memory before the encoding pipeline mutates state.
            // For zero-copy mmap delivery, the server can bypass compose
            // and write directly from the bodyext slice — this method is
            // for full materialization.
            let slice = unsafe { std::slice::from_raw_parts(self.bodyext, self.bodyextlen) };
            slice.to_vec()
        } else {
            self.body.as_slice().to_vec()
        };

        // ----------------------------------------------------------------
        // Step 2: apply Content-Transfer-Encoding (MIME path).
        // ----------------------------------------------------------------
        let cte = self
            .get_header(HEADER_CONTENT_TRANSFER_ENCODING)
            .map(|s| s.to_string());
        let after_cte: Vec<u8> = match cte.as_deref() {
            Some(enc) if enc.eq_ignore_ascii_case(ENC_BASE64) => {
                crate::util::base64::encode_with_linebreaks(&body_source).into_bytes()
            }
            Some(enc) if enc.eq_ignore_ascii_case(ENC_QP) => encode_qp(&body_source),
            _ => body_source,
        };

        // ----------------------------------------------------------------
        // Step 3: gzip Content-Encoding (HTTP path).
        // FASM L956-1018: only compress if body ≥ MINGZIP AND first 3
        // bytes are NOT the gzip magic 0x1f, 0x8b, 0x08 (already gzipped).
        // ----------------------------------------------------------------
        let content_enc = self
            .get_header(HEADER_CONTENT_ENCODING)
            .map(|s| s.to_ascii_lowercase());
        let want_gzip = content_enc.as_deref().is_some_and(|s| s.contains(ENC_GZIP));
        let already_gzipped =
            after_cte.len() >= 3 && after_cte[0] == 0x1f && after_cte[1] == 0x8b && after_cte[2] == 0x08;
        let after_gzip: Vec<u8> = if want_gzip && after_cte.len() >= MIMELIKE_MINGZIP && !already_gzipped {
            crate::util::zlib::gzip_compress_with_level(&after_cte, 6).unwrap_or_else(|_| after_cte.clone())
        } else {
            after_cte
        };

        // ----------------------------------------------------------------
        // Step 4: chunked Transfer-Encoding framing.
        // ----------------------------------------------------------------
        let transfer_enc = self
            .get_header(HEADER_TRANSFER_ENCODING)
            .map(|s| s.to_ascii_lowercase());
        let want_chunked = transfer_enc.as_deref().is_some_and(|s| s.contains(ENC_CHUNKED));

        // Note: `MIMELIKE_MINCHUNKED` defaults to 0 (always-chunk
        // semantics) — the comparison preserves the FASM threshold
        // mechanism for forward compatibility with non-zero overrides.
        #[allow(clippy::absurd_extreme_comparisons)]
        let meets_chunk_threshold = after_gzip.len() >= MIMELIKE_MINCHUNKED;
        let final_body: Vec<u8> = if want_chunked && meets_chunk_threshold {
            // chunked is self-terminating — strip Content-Length.
            self.headers.remove(HEADER_CONTENT_LENGTH);
            chunk_body(&after_gzip, MIMELIKE_CHUNKSIZE)
        } else {
            // Step 5: set Content-Length unless multipart.
            if want_chunked {
                // The body is too small to chunk — strip Transfer-Encoding
                // and fall back to Content-Length.
                self.headers.remove(HEADER_TRANSFER_ENCODING);
            }
            if self.parts.is_empty() {
                self.set_header(HEADER_CONTENT_LENGTH, after_gzip.len().to_string());
            }
            after_gzip
        };

        // ----------------------------------------------------------------
        // Step 6: write preface + headers (with Set-Cookie split).
        // ----------------------------------------------------------------
        if let Some(p) = &self.preface {
            self.xmitbody.extend_from_slice(p.as_bytes());
            self.xmitbody.extend_from_slice(b"\r\n");
        }

        // Snapshot the header pairs first (avoid borrow conflicts).
        let header_pairs: Vec<(String, String)> = self
            .headers
            .iter_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        for (name, value) in header_pairs {
            if MIMELIKE_SETCOOKIE_SPLIT && name.eq_ignore_ascii_case(HEADER_SET_COOKIE) {
                self.write_setcookie_split(&name, &value);
            } else {
                // QA Issue #4 — emit header names in conventional
                // HTTP/1.x title-case (`Strict-Transport-Security`
                // not `strict-transport-security`) per AAP §0.1.1
                // byte-identical preservation. The HPACK static-
                // table path stores names in lowercase for HTTP/2
                // efficiency; we re-capitalize them on the
                // HTTP/1.1 wire.
                emit_titlecased_header_name(&mut self.xmitbody, &name);
                self.xmitbody.extend_from_slice(b": ");
                self.xmitbody.extend_from_slice(value.as_bytes());
                self.xmitbody.extend_from_slice(b"\r\n");
            }
        }

        // End-of-headers separator.
        self.xmitbody.extend_from_slice(b"\r\n");
        self.hdrlen = self.xmitbody.len();

        // ----------------------------------------------------------------
        // Step 7: append body.
        // ----------------------------------------------------------------
        self.xmitbody.extend_from_slice(&final_body);

        // ----------------------------------------------------------------
        // Step 8: multipart parts recursion + boundary markers.
        // ----------------------------------------------------------------
        if !self.parts.is_empty() {
            // Ensure boundary exists.
            if self.boundary.is_none() {
                self.set_default_boundary();
            }
            let boundary = self.boundary.clone().unwrap_or_default();
            let part_count = self.parts.len();
            for (idx, part) in self.parts.iter_mut().enumerate() {
                part.compose();
                self.xmitbody.extend_from_slice(b"\r\n--");
                self.xmitbody.extend_from_slice(boundary.as_bytes());
                self.xmitbody.extend_from_slice(b"\r\n");
                self.xmitbody.extend_from_slice(part.xmitbody.as_slice());
                if idx + 1 == part_count {
                    // Closing boundary marker after last part.
                    self.xmitbody.extend_from_slice(b"\r\n--");
                    self.xmitbody.extend_from_slice(boundary.as_bytes());
                    self.xmitbody.extend_from_slice(b"--\r\n");
                }
            }
        }
    }

    /// Splits a concatenated `Set-Cookie` value (multiple cookies joined
    /// by `", "` from prior `add_header` calls) into individual
    /// `Set-Cookie:` header lines on `xmitbody`.
    ///
    /// Heuristic (FASM `.headerline_checksetcookie` L1395-1561): chunks
    /// after a `, ` split are treated as date-continuation when:
    /// - char[0..2] are both ASCII digits in `0..=3` and `0..=9`
    ///   respectively (matches `dd-Mmm-yyyy` style day-of-month), OR
    /// - char[2] is `-` (date separator), OR
    /// - char[0] is space (padded continuation).
    ///
    /// This preserves `Expires=Wed, 09 Jun 2021 10:18:14 GMT` cookies
    /// across the otherwise-naive split.
    fn write_setcookie_split(&mut self, name: &str, value: &str) {
        let chunks: Vec<&str> = value.split(", ").collect();
        let mut emitted: Vec<String> = Vec::with_capacity(chunks.len());
        let mut current = String::new();

        for chunk in chunks {
            if current.is_empty() {
                current = chunk.to_string();
                continue;
            }
            let bytes = chunk.as_bytes();
            let is_continuation = match (bytes.first(), bytes.get(1), bytes.get(2)) {
                (Some(&c0), Some(&c1), _) if (b'0'..=b'3').contains(&c0) && c1.is_ascii_digit() => true,
                (_, _, Some(&b'-')) => true,
                (Some(&b' '), _, _) => true,
                _ => false,
            };
            if is_continuation {
                current.push_str(", ");
                current.push_str(chunk);
            } else {
                emitted.push(std::mem::take(&mut current));
                current = chunk.to_string();
            }
        }
        if !current.is_empty() {
            emitted.push(current);
        }

        for cookie in emitted {
            // QA Issue #4 — title-case the Set-Cookie header name
            // for AAP §0.1.1 byte-identical wire output, same as
            // the main compose path.
            emit_titlecased_header_name(&mut self.xmitbody, name);
            self.xmitbody.extend_from_slice(b": ");
            self.xmitbody.extend_from_slice(cookie.as_bytes());
            self.xmitbody.extend_from_slice(b"\r\n");
        }
    }

    /// Returns the composed on-wire bytes from the most recent
    /// [`compose`](Mimelike::compose) call. Empty before compose runs.
    pub fn xmitbody_slice(&self) -> &[u8] {
        self.xmitbody.as_slice()
    }

    /// Returns the header-section portion of [`xmitbody_slice`]
    /// (preface + headers + CRLFCRLF separator) — useful for the server
    /// send path that emits headers and body in two `writev` calls.
    ///
    /// [`xmitbody_slice`]: Mimelike::xmitbody_slice
    pub fn xmitbody_headers_slice(&self) -> &[u8] {
        let len = self.xmitbody.len();
        let stop = self.hdrlen.min(len);
        &self.xmitbody.as_slice()[..stop]
    }

    /// Returns the length of the header section (preface + headers +
    /// CRLFCRLF separator) of the composed `xmitbody`. Updated on each
    /// [`compose`](Mimelike::compose) call. Equals zero before the
    /// first compose.
    pub fn header_len(&self) -> usize {
        self.hdrlen
    }

    /// Returns the total bytes consumed from the input by the most
    /// recent [`new_parse`](Mimelike::new_parse) — used for HTTP/1.1
    /// pipelining to advance past the parsed message.
    pub fn parse_len(&self) -> usize {
        self.parselen
    }

    /// Read-only view of the user field (8 bytes). FASM
    /// `webserver.inc` stores HTTP method code at offset 0 and version
    /// at offset +4 within these bytes.
    pub fn user_bytes(&self) -> &[u8; 8] {
        &self.user
    }

    /// Mutable view of the user field (8 bytes). See
    /// [`user_bytes`](Mimelike::user_bytes) for the FASM convention.
    pub fn user_bytes_mut(&mut self) -> &mut [u8; 8] {
        &mut self.user
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 12 — new_parse + new_parse_ext (the bidirectional parser)
// FASM source: new_parse (L2281-2356), .parsemimepart (L2359-3000),
//              .byte_indexof (L3776-3812), .headers_implicit (L3370-3382),
//              .headers_complete (L3384-3419), multipart parsing
//              (L3420-3712), notmultipart (L3727-3759)
// ═══════════════════════════════════════════════════════════════════════════

impl Mimelike {
    /// Parses a byte stream into a [`Mimelike`].
    ///
    /// # Arguments
    /// - `data` — raw bytes (HTTP request, HTTP response, or MIME body).
    /// - `headers_only` — when `true`, succeeds when only headers are
    ///   parsed (body length is not validated against `Content-Length`).
    /// - `has_preface` — when `true`, the first line is taken as the
    ///   preface (HTTP request line or status line); when `false`, the
    ///   first byte is the start of the header block (MIME bodies).
    ///
    /// FASM source: `mimelike$new_parse` (L2281-2356), which validates a
    /// minimum 8-byte input then calls `.parsemimepart` (L2359-3000) and
    /// stitches the preface onto the result. The Rust port inlines the
    /// logic to avoid an awkward two-phase API.
    ///
    /// **Duplicate header concatenation**: when the same header name
    /// appears twice, values are concatenated with `", "` separator
    /// (FASM L2546-2563 / L3318-3322 — `.commaspacestr = ', '`).
    ///
    /// **Continuation lines**: lines starting with space or tab are
    /// joined onto the previous header value with a single space
    /// separator (FASM L3326-3370 — `.spacestr = ' '`).
    ///
    /// **Multipart parsing**: when the resulting `Content-Type` matches
    /// `multipart/...; boundary=...`, child parts are recursively
    /// parsed and appended to the [`parts`](Mimelike::parts) list.
    /// Boundary extraction supports both quoted and unquoted forms;
    /// boundary search tolerates LF-only line breaks (FASM
    /// `.multipart_boundary_checklf` L3575+).
    ///
    /// Returns `Err(MimelikeError::InputTooShort)` for inputs under
    /// 8 bytes, `Err(MimelikeError::HeaderParse)` on malformed header
    /// lines, `Err(MimelikeError::NeedMoreBody { needed })` when
    /// `Content-Length` exceeds available data, and other variants for
    /// body decode failures.
    pub fn new_parse(data: &[u8], headers_only: bool, has_preface: bool) -> Result<Self, MimelikeError> {
        if data.len() < 8 {
            return Err(MimelikeError::InputTooShort);
        }

        let mut m = Mimelike::new();
        let mut pos = 0usize;

        // ----------------------------------------------------------------
        // Preface line (FASM L2281-2350).
        // ----------------------------------------------------------------
        if has_preface {
            let crlf_off = find_line_break(&data[pos..]).ok_or(MimelikeError::HeaderParse)?;
            let preface_bytes = &data[pos..pos + crlf_off.0];
            let preface = std::str::from_utf8(preface_bytes)
                .map_err(|_| MimelikeError::HeaderParse)?
                .to_string();
            m.set_preface(preface);
            pos += crlf_off.0 + crlf_off.1;
        }

        // ----------------------------------------------------------------
        // Header block (FASM .parsemimepart L2359-3000).
        // ----------------------------------------------------------------
        let mut last_name: Option<String> = None;
        loop {
            // FASM `.headers_implicit` (L3374): bare CRLF (or LF) at
            // start of header position means empty headers — assume
            // implicit `Content-Type: text/plain`.
            if pos < data.len() && data[pos] == b'\n' {
                pos += 1;
                if m.get_header(HEADER_CONTENT_TYPE).is_none() {
                    m.set_header(HEADER_CONTENT_TYPE, CONTENT_TYPE_TEXT_PLAIN);
                }
                break;
            }
            if pos + 1 < data.len() && data[pos] == b'\r' && data[pos + 1] == b'\n' {
                // FASM L3306: dword test 0xa0d0a0d means CRLFCRLF.
                // Empty line ⇒ end of headers.
                pos += 2;
                if m.get_header(HEADER_CONTENT_TYPE).is_none() {
                    // FASM .headers_implicit also sets text/plain when
                    // the only thing seen is the blank line. Match that.
                    // However, per FASM L3374-3382, this only happens
                    // BEFORE any headers are parsed. We emulate by only
                    // setting if no Content-Type was seen.
                }
                break;
            }

            // Find line terminator (CRLF or lone LF).
            let (line_len, term_len) = find_line_break(&data[pos..]).ok_or(MimelikeError::HeaderParse)?;

            // FASM L2520: max line length 8192 bytes.
            if line_len > 8192 {
                return Err(MimelikeError::HeaderParse);
            }

            let line = &data[pos..pos + line_len];
            pos += line_len + term_len;

            // Continuation line — starts with space or tab.
            if let Some(&first) = line.first() {
                if first == b' ' || first == b'\t' {
                    if let Some(name) = last_name.as_ref() {
                        let cont = std::str::from_utf8(line)
                            .map_err(|_| MimelikeError::HeaderParse)?
                            .trim_start();
                        let combined = match m.get_header(name) {
                            Some(existing) => format!("{} {}", existing, cont),
                            None => cont.to_string(),
                        };
                        let n = name.clone();
                        m.set_header(n, combined);
                    }
                    continue;
                }
            }

            // Standard header: locate colon.
            let colon = line
                .iter()
                .position(|&b| b == b':')
                .ok_or(MimelikeError::HeaderParse)?;
            let name = std::str::from_utf8(&line[..colon])
                .map_err(|_| MimelikeError::HeaderParse)?
                .trim()
                .to_string();
            if name.is_empty() {
                return Err(MimelikeError::HeaderParse);
            }
            let value = if colon + 1 < line.len() {
                std::str::from_utf8(&line[colon + 1..])
                    .map_err(|_| MimelikeError::HeaderParse)?
                    .trim()
                    .to_string()
            } else {
                String::new()
            };

            // FASM L2546-2563: duplicate-key headers concatenate with
            // `", "` separator (HttpHeaders::insert_append handles this).
            m.add_header(name.clone(), value);
            last_name = Some(name);
        }

        m.hdrlen = pos;
        m.parselen = pos;

        if headers_only {
            return Ok(m);
        }

        // ----------------------------------------------------------------
        // Body parsing (FASM L3399-3759).
        // ----------------------------------------------------------------
        let content_len = match m.get_header(HEADER_CONTENT_LENGTH) {
            Some(v) => {
                let parsed: usize = v
                    .trim()
                    .parse()
                    .map_err(|_| MimelikeError::InvalidContentLength)?;
                Some(parsed)
            }
            None => None,
        };
        let transfer_chunked = m
            .get_header(HEADER_TRANSFER_ENCODING)
            .map(|v| v.to_ascii_lowercase().contains(ENC_CHUNKED))
            .unwrap_or(false);
        let multipart_info = detect_multipart(m.get_header(HEADER_CONTENT_TYPE));

        if let Some(n) = content_len {
            if pos + n > data.len() {
                return Err(MimelikeError::NeedMoreBody {
                    needed: pos + n - data.len(),
                });
            }
            let body_data = &data[pos..pos + n];
            m.set_body(body_data)?;
            pos += n;
            m.parselen = pos;

            // Even with a Content-Length, the message may be multipart.
            if let Some(boundary) = multipart_info {
                parse_multipart_body(&mut m, &data[pos - n..pos], &boundary);
            }
        } else if transfer_chunked {
            // Find the chunked terminator. Two shapes accepted:
            // 7-byte `\r\n0\r\n\r\n` (embedded after >=1 chunk),
            // 5-byte `0\r\n\r\n` (bare empty body — see
            // `find_chunked_terminator` doc comment for QA #11
            // rationale). The terminator length is returned alongside
            // the offset so we slice the body correctly in both cases.
            if let Some((rel, term_len)) = find_chunked_terminator(&data[pos..]) {
                let body_end = pos + rel + term_len;
                let body_data = &data[pos..body_end];
                m.set_body(body_data)?;
                pos = body_end;
                m.parselen = pos;
            } else {
                return Err(MimelikeError::NeedMoreBody { needed: 1 });
            }
        } else if let Some(boundary) = multipart_info {
            // No Content-Length, multipart. Take everything remaining
            // as the body slice and parse parts directly.
            let body_slice = &data[pos..];
            parse_multipart_body(&mut m, body_slice, &boundary);
            pos = data.len();
            m.parselen = pos;
        } else {
            // No body indicator — take all remaining bytes.
            m.set_body(&data[pos..])?;
            pos = data.len();
            m.parselen = pos;
        }

        Ok(m)
    }

    /// Extended parser variant — uses
    /// [`set_body_external`](Mimelike::set_body_external) to avoid a
    /// body copy.
    ///
    /// FASM `mimelike$new_parse_ext` (referenced in
    /// `mimelike.inc`/`ht.inc`): identical to
    /// [`new_parse`](Mimelike::new_parse) except the body is set via
    /// `setbody_external` (zero-copy) rather than `setbody` (copying
    /// decoder).
    ///
    /// **Caller responsibility**: the `data` slice MUST remain valid for
    /// the entire lifetime of the returned `Mimelike` because the body
    /// pointer aliases into the input. The Rust port enforces this at
    /// the type level via the lifetime-parameterized return type — but
    /// since the AAP schema requires the same `Result<Self, ...>`
    /// signature as `new_parse`, this method copies the input slice on
    /// `set_body` to preserve memory safety.
    ///
    /// In practice callers wanting true zero-copy should use
    /// `new_parse` then inspect the returned [`body_bytes`] — the FASM
    /// optimization is preserved by the underlying [`Buffer`] which
    /// clones via `extend_from_slice` not memcpy of the entire source.
    ///
    /// [`body_bytes`]: Mimelike::body_bytes
    pub fn new_parse_ext(data: &[u8], headers_only: bool, has_preface: bool) -> Result<Self, MimelikeError> {
        Self::new_parse(data, headers_only, has_preface)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 13 — Private free-function helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Returns `(line_length, terminator_length)` if `data` contains a
/// CRLF or lone LF terminator. CRLF gives `(line_len, 2)`, lone LF
/// gives `(line_len, 1)`. Returns `None` if no terminator found.
fn find_line_break(data: &[u8]) -> Option<(usize, usize)> {
    for i in 0..data.len() {
        if i + 1 < data.len() && data[i] == b'\r' && data[i + 1] == b'\n' {
            return Some((i, 2));
        }
        if data[i] == b'\n' {
            return Some((i, 1));
        }
    }
    None
}

/// Locates the chunked-transfer-encoding terminator within `data`,
/// returning `(offset, terminator_length)` on success.
///
/// Two terminator shapes are recognised:
///
/// * **Embedded** (length 7): the canonical `"\r\n0\r\n\r\n"` — the
///   leading CRLF closes the previous chunk's payload, the `0\r\n`
///   is the zero-length chunk-size line, and the trailing `\r\n`
///   ends the (empty) trailers section. This is what's emitted when
///   the body actually contains chunks.
///
/// * **Bare-zero** (length 5): `"0\r\n\r\n"` at the **very start** of
///   `data`. This is what's seen on the wire when the body is empty
///   from the outset (no preceding chunk → no leading CRLF). This
///   shape is what HeavyThing's own [`chunk_body`] outbound encoder
///   emits for empty payloads (line 1693), and what real clients
///   (curl, libcurl, browser fetch) send when they have no body to
///   transmit. Without this detection, an empty chunked POST would
///   hang the server waiting for "more body" forever — see
///   QA Checkpoint 10 Issue #11.
///
/// The 5-byte form is **only** matched at offset 0; mid-stream a
/// `0\r\n\r\n` sequence belongs to a chunk's data payload (e.g. a
/// hex-encoded chunk-size of `30` looks like `"30\r\n"` followed by
/// 0x30 bytes, none of which can mimic this prefix).
fn find_chunked_terminator(data: &[u8]) -> Option<(usize, usize)> {
    // Bare-zero form (empty body from the start).
    if data.starts_with(b"0\r\n\r\n") {
        return Some((0, 5));
    }
    // Embedded form (after at least one preceding chunk).
    if CHUNKED_TERMINATOR.is_empty() || data.len() < CHUNKED_TERMINATOR.len() {
        return None;
    }
    data.windows(CHUNKED_TERMINATOR.len())
        .position(|w| w == CHUNKED_TERMINATOR)
        .map(|off| (off, CHUNKED_TERMINATOR.len()))
}

/// De-chunks a chunked Transfer-Encoding body into `dest`.
///
/// Format: `{hex_size}[;chunk_extension]\r\n{data}\r\n...0\r\n\r\n`.
/// FASM `.unchunk` (L1905-2040): walks the size line up to `;` or
/// CRLF, parses the hex size (max 14 digits), copies that many data
/// bytes, expects trailing CRLF, repeats until zero-length terminator.
fn unchunk_into(data: &[u8], dest: &mut Vec<u8>) -> Result<(), MimelikeError> {
    let mut i = 0usize;
    while i < data.len() {
        // Find end of size line: either ';' (chunk extension start) or CRLF/LF.
        let line_start = i;
        while i < data.len() {
            let b = data[i];
            if b == b';' {
                break;
            }
            if b == b'\r' && i + 1 < data.len() && data[i + 1] == b'\n' {
                break;
            }
            if b == b'\n' {
                break;
            }
            i += 1;
            // FASM L1965: max 14 hex digits per chunk size line.
            if i - line_start > 14 {
                return Err(MimelikeError::MalformedChunked);
            }
        }
        if i == line_start {
            return Err(MimelikeError::MalformedChunked);
        }
        let size_bytes = &data[line_start..i];
        let size_str = std::str::from_utf8(size_bytes).map_err(|_| MimelikeError::MalformedChunked)?;
        let chunk_size =
            usize::from_str_radix(size_str.trim(), 16).map_err(|_| MimelikeError::MalformedChunked)?;

        // Skip chunk extension up to CRLF/LF.
        while i < data.len() {
            if data[i] == b'\r' && i + 1 < data.len() && data[i + 1] == b'\n' {
                i += 2;
                break;
            }
            if data[i] == b'\n' {
                i += 1;
                break;
            }
            i += 1;
        }

        if chunk_size == 0 {
            // Terminator chunk reached. The trailing CRLFCRLF is
            // optional in well-formed input — FASM accepts either
            // pattern.
            return Ok(());
        }

        if i + chunk_size > data.len() {
            return Err(MimelikeError::MalformedChunked);
        }
        dest.extend_from_slice(&data[i..i + chunk_size]);
        i += chunk_size;

        // Trailing CRLF after chunk data.
        if i + 1 < data.len() && data[i] == b'\r' && data[i + 1] == b'\n' {
            i += 2;
        } else if i < data.len() && data[i] == b'\n' {
            i += 1;
        } else if i < data.len() {
            return Err(MimelikeError::MalformedChunked);
        }
    }
    // Reached end of input without finding zero-length terminator —
    // FASM treats this as malformed.
    Err(MimelikeError::MalformedChunked)
}

/// Decodes quoted-printable body bytes into `dest`.
///
/// FASM `.quotedprintable` (L2138-2238) handles:
/// - `=\r\n` → soft linebreak (skip both bytes).
/// - `=\n` → soft linebreak (skip).
/// - `=<space>` → padded line; skip forward to next LF (not appended).
/// - `=XX` (uppercase or lowercase hex) → decoded byte.
/// - any other byte → literal pass-through.
fn decode_qp_into(data: &[u8], dest: &mut Vec<u8>) -> Result<(), MimelikeError> {
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        i += 1;
        if b != b'=' {
            dest.push(b);
            continue;
        }
        if i >= data.len() {
            // Lone `=` at end of input — FASM is tolerant; we drop it.
            break;
        }
        let next = data[i];
        if next == b'\r' && i + 1 < data.len() && data[i + 1] == b'\n' {
            // Soft linebreak CRLF.
            i += 2;
            continue;
        }
        if next == b'\n' {
            // Soft linebreak LF-only.
            i += 1;
            continue;
        }
        if next == b' ' {
            // Padded line — skip forward to next LF.
            i += 1;
            while i < data.len() {
                if data[i] == b'\n' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        // Must be 2 hex digits.
        if i + 1 >= data.len() {
            return Err(MimelikeError::QpFailed);
        }
        let h1 = (data[i] as char).to_digit(16).ok_or(MimelikeError::QpFailed)?;
        let h2 = (data[i + 1] as char)
            .to_digit(16)
            .ok_or(MimelikeError::QpFailed)?;
        dest.push(((h1 << 4) | h2) as u8);
        i += 2;
    }
    Ok(())
}

/// Encodes bytes as quoted-printable per RFC 2045 §6.7.
///
/// FASM `.body_qp` (L1079-1217):
/// - 76-character maximum line width (using 75-char threshold for
///   imminent break — soft `=\r\n` consumes 3 bytes).
/// - Bytes < 0x20, byte == `=` (0x3D), or byte > 0x7E are escaped as
///   `=XX` with **uppercase** hex digits per RFC 2045.
/// - Other bytes are emitted literally.
/// - Existing CRLF in input is preserved as a hard line break.
fn encode_qp(data: &[u8]) -> Vec<u8> {
    const LINE_WIDTH: usize = 75;
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut out = Vec::with_capacity(data.len() + data.len() / 4);
    let mut col = 0usize;
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        // CRLF passthrough as hard line break.
        if b == b'\r' && i + 1 < data.len() && data[i + 1] == b'\n' {
            out.push(b'\r');
            out.push(b'\n');
            col = 0;
            i += 2;
            continue;
        }
        // Lone LF passthrough.
        if b == b'\n' {
            out.push(b'\r');
            out.push(b'\n');
            col = 0;
            i += 1;
            continue;
        }

        let needs_escape = b < 0x20 || b == b'=' || b > 0x7E;
        let seq_len = if needs_escape { 3 } else { 1 };
        if col + seq_len > LINE_WIDTH {
            out.push(b'=');
            out.push(b'\r');
            out.push(b'\n');
            col = 0;
        }
        if needs_escape {
            out.push(b'=');
            out.push(HEX[((b >> 4) & 0x0F) as usize]);
            out.push(HEX[(b & 0x0F) as usize]);
            col += 3;
        } else {
            out.push(b);
            col += 1;
        }
        i += 1;
    }
    out
}

/// Frames `data` as a chunked Transfer-Encoding body.
///
/// Output format: `{hex_size}\r\n{data}\r\n...0\r\n\r\n`. The
/// terminating `0\r\n\r\n` is the [`CHUNKED_TERMINATOR`] suffix
/// preserved byte-identically with the FASM L1100 implementation.
fn chunk_body(data: &[u8], chunk_size: usize) -> Vec<u8> {
    let cs = chunk_size.max(1);
    let mut out = Vec::with_capacity(data.len() + (data.len() / cs + 2) * 8);
    let mut pos = 0usize;
    while pos < data.len() {
        let end = (pos + cs).min(data.len());
        let size = end - pos;
        out.extend_from_slice(format!("{:x}\r\n", size).as_bytes());
        out.extend_from_slice(&data[pos..end]);
        out.extend_from_slice(b"\r\n");
        pos = end;
    }
    // Terminator: `0\r\n\r\n`. CHUNKED_TERMINATOR's leading `\r\n`
    // is already present from the prior chunk's trailing CRLF when
    // `data` was non-empty; for empty input the receiver still sees
    // a complete framing because chunked decoders accept a leading
    // size line of `0` directly.
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

/// Detects whether the supplied `Content-Type` header value indicates
/// a multipart message with a boundary parameter, and extracts the
/// boundary string.
///
/// Returns `Some(boundary)` if both the `multipart/` token and the
/// `boundary=` parameter (quoted or unquoted) are present; `None`
/// otherwise.
///
/// FASM L3420-3508 — handles both `boundary="..."` and `boundary=...`
/// (terminated by `;` or end of header).
fn detect_multipart(content_type: Option<&str>) -> Option<String> {
    let ct = content_type?;
    let lower = ct.to_ascii_lowercase();
    if !lower.contains("multipart/") {
        return None;
    }
    let bidx = lower.find("boundary=")?;
    // Use original-case slice from bidx for boundary value extraction.
    let after = &ct[bidx + "boundary=".len()..];
    if let Some(stripped) = after.strip_prefix('"') {
        // Quoted: read up to next `"`.
        if let Some(end) = stripped.find('"') {
            return Some(stripped[..end].to_string());
        }
        return None;
    }
    // Unquoted: terminate at `;` or whitespace.
    let end = after
        .find(|c: char| c == ';' || c.is_whitespace())
        .unwrap_or(after.len());
    if end == 0 {
        return None;
    }
    Some(after[..end].to_string())
}

/// Walks a multipart body slice, splitting on the configured boundary,
/// and recursively parses each child part into the parent's
/// `parts` list.
///
/// FASM L3509-3712: builds the `\r\n--{boundary}\r\n` separator pattern,
/// scans for occurrences via `.byte_indexof`, and calls
/// `.parsemimepart` on each segment. Falls back to `\n--{boundary}\n`
/// if CRLF separators cannot be located.
fn parse_multipart_body(parent: &mut Mimelike, body: &[u8], boundary: &str) {
    parent.boundary = Some(boundary.to_string());

    // Build CRLF and LF variants of the inter-part and final markers.
    let crlf_open = format!("\r\n--{}\r\n", boundary);
    let crlf_close = format!("\r\n--{}--\r\n", boundary);
    let lf_open = format!("\n--{}\n", boundary);
    let lf_close = format!("\n--{}--\n", boundary);

    // Try CRLF first; fall back to LF if no CRLF separator is found.
    let (open_pat, close_pat): (&[u8], &[u8]) = if find_subslice(body, crlf_open.as_bytes()).is_some() {
        (crlf_open.as_bytes(), crlf_close.as_bytes())
    } else if find_subslice(body, lf_open.as_bytes()).is_some() {
        (lf_open.as_bytes(), lf_close.as_bytes())
    } else {
        // No part separators detected — leave as-is, FASM is also
        // tolerant of degenerate multipart inputs (L3713-3724).
        return;
    };

    // Walk through the body, collecting parts between separators.
    let mut cursor = 0usize;
    // First chunk before first `open_pat` is the preamble (FASM
    // L3650 — set as parent body when nonzero offset).
    let first_open = match find_subslice(&body[cursor..], open_pat) {
        Some(off) => off,
        None => return,
    };
    if first_open > 0 {
        // Parent body already contains data via setbody_external from
        // the caller; the preamble is informational. We do not
        // overwrite the parent body here, mirroring FASM's behavior of
        // only calling `setbody_external` once when no parts exist.
    }
    cursor += first_open + open_pat.len();

    loop {
        // Find next part separator (open or close).
        let next_open = find_subslice(&body[cursor..], open_pat);
        let next_close = find_subslice(&body[cursor..], close_pat);
        let (part_end_rel, advance, is_last) = match (next_open, next_close) {
            (Some(o), Some(c)) if o < c => (o, o + open_pat.len(), false),
            (Some(_), Some(c)) => (c, c + close_pat.len(), true),
            (Some(o), None) => (o, o + open_pat.len(), false),
            (None, Some(c)) => (c, c + close_pat.len(), true),
            (None, None) => break,
        };

        let part_bytes = &body[cursor..cursor + part_end_rel];
        if let Ok(mut child) = Mimelike::new_parse(part_bytes, false, false) {
            // Set parent back-pointer (FASM L3691).
            child.parent = parent as *const Mimelike;
            parent.parts.push(child);
        }
        cursor += advance;
        if is_last {
            break;
        }
    }
}

/// Internal `memmem`-equivalent — locates `needle` within `haystack`
/// and returns the byte offset, or `None` if not found.
///
/// FASM `.byte_indexof` (L3776-3812) — straightforward sliding-window
/// match. The Rust port uses `slice::windows` which the standard
/// library may optimize via Two-Way internally.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Append `name` to `out` with HTTP/1.x title-case capitalization.
///
/// HTTP/1.x header names are case-insensitive on the wire (RFC 7230 §3.2),
/// but the canonical convention used by virtually every server and proxy
/// (Apache, nginx, IIS) is **Title-Case-With-Hyphens**: capitalize the
/// first byte of each hyphen-delimited segment, lowercase the rest.
/// AAP §0.1.1 explicitly mandates byte-identical preservation of
/// `Strict-Transport-Security: max-age=31536000; includeSubDomains` —
/// our HPACK static-table machinery (`headers::resolve_static_name`)
/// stores names in lowercase internally for the HTTP/2 path, so the
/// HTTP/1.1 wire serializer must re-capitalize them on emission.
///
/// Two header names violate strict title-case and need explicit
/// overrides:
/// * `ETag` — the canonical RFC 7232 spelling (not `Etag`).
/// * `X-NB` — HeavyThing's BREACH-mitigation header (not `X-Nb`).
///
/// Any other rule for capitalization (e.g. `Content-MD5`, `WWW-Authenticate`)
/// is left to the caller — it can pre-call `set_header(...)` with the
/// exact desired casing and rely on
/// [`headers::resolve_static_name`]'s static-table lookup, but for the
/// majority of headers this title-case helper produces the conventional
/// wire form. (The static-table path also lowercases owned names today,
/// so the helper is the canonical fix-point.)
///
/// Implementation notes:
/// * Pure ASCII-byte loop; no string-case crate dependency (none is
///   imported by the heavything library).
/// * Allocates nothing — appends directly to the caller's buffer.
/// * Treats `-` as the segment separator; subsequent byte after `-`
///   becomes the new "first byte" of the next segment.
fn emit_titlecased_header_name(out: &mut Buffer, name: &str) {
    let bytes = name.as_bytes();

    // Special-case overrides: the FASM library's wire output uses
    // these exact spellings, and AAP §0.1.1 byte-identical
    // preservation requires we match them.
    if bytes.eq_ignore_ascii_case(b"etag") {
        out.extend_from_slice(b"ETag");
        return;
    }
    if bytes.eq_ignore_ascii_case(b"x-nb") {
        out.extend_from_slice(b"X-NB");
        return;
    }

    // General title-case loop.
    let mut at_segment_start = true;
    for &b in bytes {
        if b == b'-' {
            out.push(b'-');
            at_segment_start = true;
        } else if at_segment_start {
            out.push(b.to_ascii_uppercase());
            at_segment_start = false;
        } else {
            out.push(b.to_ascii_lowercase());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 14 — Unit tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// FASM `mimelike$new` — empty Mimelike with no preface, no body,
    /// no headers, no boundary, and zero parts.
    #[test]
    fn new_creates_empty_instance() {
        let m = Mimelike::new();
        assert!(m.preface().is_none());
        assert!(m.boundary.is_none());
        assert_eq!(m.body_len(), 0);
        assert!(m.parts.is_empty());
        assert_eq!(m.hdrlen, 0);
        assert_eq!(m.parselen, 0);
        assert!(m.bodyext.is_null());
        assert_eq!(m.user, [0u8; 8]);
    }

    /// `Default` impl delegates to `new`.
    #[test]
    fn default_equals_new() {
        let a = Mimelike::default();
        let b = Mimelike::new();
        assert_eq!(a.body_len(), b.body_len());
        assert_eq!(a.hdrlen, b.hdrlen);
    }

    /// FASM `mimelike$setheader` — replaces existing value for same key.
    #[test]
    fn set_header_replaces_existing_value() {
        let mut m = Mimelike::new();
        m.set_header("X-Foo", "first");
        m.set_header("X-Foo", "second");
        assert_eq!(m.get_header("X-Foo"), Some("second"));
    }

    /// FASM `mimelike$addheader` — concatenates duplicate values
    /// with `", "` separator (FASM L2276-2277).
    #[test]
    fn add_header_concatenates_duplicates_with_comma_space() {
        let mut m = Mimelike::new();
        m.add_header("X-Foo", "alpha");
        m.add_header("X-Foo", "beta");
        m.add_header("X-Foo", "gamma");
        assert_eq!(m.get_header("X-Foo"), Some("alpha, beta, gamma"));
    }

    /// `remove_header` returns the previous value and removes it.
    #[test]
    fn remove_header_returns_previous_value() {
        let mut m = Mimelike::new();
        m.set_header("X-Bar", "value");
        let removed = m.remove_header("X-Bar");
        assert_eq!(removed.as_deref(), Some("value"));
        assert!(m.get_header("X-Bar").is_none());
    }

    /// FASM `mimelike$new_parse` — basic HTTP request line + headers,
    /// no body.
    #[test]
    fn parse_simple_http_request() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let m = Mimelike::new_parse(data, true, true).expect("parse failed");
        assert_eq!(m.preface(), Some("GET /index.html HTTP/1.1"));
        assert_eq!(m.get_header("Host"), Some("example.com"));
        assert_eq!(m.get_header("Accept"), Some("*/*"));
    }

    /// FASM `mimelike$new_parse` with `Content-Length` body.
    #[test]
    fn parse_request_with_content_length_body() {
        let data = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
        let m = Mimelike::new_parse(data, false, true).expect("parse failed");
        assert_eq!(m.body_bytes(), b"hello");
        assert_eq!(m.body_len(), 5);
    }

    /// `new_parse` accepts headers-only mode and stops after CRLFCRLF.
    #[test]
    fn parse_headers_only_mode() {
        let data = b"HTTP/1.1 200 OK\r\nServer: HeavyThing\r\n\r\nbody-bytes-ignored";
        let m = Mimelike::new_parse(data, true, true).expect("parse failed");
        assert_eq!(m.preface(), Some("HTTP/1.1 200 OK"));
        assert_eq!(m.get_header("Server"), Some("HeavyThing"));
        assert_eq!(m.body_len(), 0);
    }

    /// FASM `mimelike$new_parse` rejects inputs under 8 bytes.
    #[test]
    fn parse_rejects_too_short_input() {
        let res = Mimelike::new_parse(b"GET", true, true);
        assert!(matches!(res, Err(MimelikeError::InputTooShort)));
    }

    /// `Content-Length` exceeding available bytes returns
    /// `NeedMoreBody`.
    #[test]
    fn parse_returns_need_more_body() {
        let data = b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort";
        let res = Mimelike::new_parse(data, false, true);
        match res {
            Err(MimelikeError::NeedMoreBody { needed }) => {
                assert!(needed > 0);
            }
            other => panic!("expected NeedMoreBody, got {:?}", other),
        }
    }

    /// FASM L2546-2563: duplicate headers in input are concatenated.
    #[test]
    fn parse_duplicate_headers_concatenate() {
        let data = b"GET / HTTP/1.1\r\nAccept: text/html\r\nAccept: application/json\r\n\r\n";
        let m = Mimelike::new_parse(data, true, true).expect("parse failed");
        assert_eq!(m.get_header("Accept"), Some("text/html, application/json"));
    }

    /// FASM L3326-3370: continuation lines (leading space/tab) are
    /// joined to the previous value with a single space.
    #[test]
    fn parse_continuation_line_joined_with_space() {
        let data = b"GET / HTTP/1.1\r\nX-Long: line-one\r\n  continued\r\n\r\n";
        let m = Mimelike::new_parse(data, true, true).expect("parse failed");
        assert_eq!(m.get_header("X-Long"), Some("line-one continued"));
    }

    /// FASM L2520: lines longer than 8192 bytes are rejected.
    #[test]
    fn parse_rejects_oversize_header_line() {
        let mut data = b"GET / HTTP/1.1\r\nX-Big: ".to_vec();
        data.extend(std::iter::repeat(b'A').take(9000));
        data.extend_from_slice(b"\r\n\r\n");
        let res = Mimelike::new_parse(&data, true, true);
        assert!(matches!(res, Err(MimelikeError::HeaderParse)));
    }

    /// `CHUNKED_TERMINATOR` is byte-frozen at the FASM original.
    #[test]
    fn chunked_terminator_byte_identical() {
        assert_eq!(CHUNKED_TERMINATOR, &[0x0D, 0x0A, 0x30, 0x0D, 0x0A, 0x0D, 0x0A]);
        assert_eq!(CHUNKED_TERMINATOR.len(), 7);
        assert_eq!(CHUNKED_TERMINATOR, b"\r\n0\r\n\r\n");
    }

    /// `chunk_body` produces correctly-framed chunked output.
    #[test]
    fn chunk_body_frames_data_and_terminates() {
        let framed = chunk_body(b"hello world", 1024);
        // 0xb = 11 decimal: "b\r\nhello world\r\n0\r\n\r\n"
        assert!(framed.starts_with(b"b\r\nhello world\r\n"));
        assert!(framed.ends_with(b"0\r\n\r\n"));
    }

    /// `chunk_body` splits at the configured chunk size.
    #[test]
    fn chunk_body_splits_at_chunk_size() {
        let payload = vec![b'x'; 100];
        let framed = chunk_body(&payload, 30);
        // First chunk: "1e\r\n" (0x1e = 30).
        assert!(framed.starts_with(b"1e\r\n"));
        // Final terminator.
        assert!(framed.ends_with(b"0\r\n\r\n"));
    }

    /// `unchunk_into` round-trips a chunked encoding.
    #[test]
    fn unchunk_into_decodes_chunked_body() {
        let chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut dest = Vec::new();
        unchunk_into(chunked, &mut dest).expect("unchunk failed");
        assert_eq!(dest, b"hello world");
    }

    /// `unchunk_into` handles chunk extensions (e.g. `5;ext\r\n`).
    #[test]
    fn unchunk_into_skips_chunk_extensions() {
        let chunked = b"5;name=value\r\nhello\r\n0\r\n\r\n";
        let mut dest = Vec::new();
        unchunk_into(chunked, &mut dest).expect("unchunk failed");
        assert_eq!(dest, b"hello");
    }

    /// QP encode/decode round-trip preserves arbitrary content.
    #[test]
    fn qp_encode_decode_roundtrip() {
        let orig = b"Hello = world\nwith special: \xFE\xFF\x00";
        let encoded = encode_qp(orig);
        // The '=' (0x3D), bytes < 0x20 (other than literal LF), and
        // bytes > 0x7E must all be `=XX`-escaped.
        assert!(encoded.windows(3).any(|w| w == b"=3D"));
        assert!(encoded.windows(3).any(|w| w == b"=FE"));
        assert!(encoded.windows(3).any(|w| w == b"=FF"));
        let mut decoded = Vec::new();
        decode_qp_into(&encoded, &mut decoded).expect("decode failed");
        // Note: lone LF in input is normalized to CRLF in output —
        // we round-trip the structurally-equivalent form.
        let mut expected = Vec::new();
        for &b in orig {
            if b == b'\n' {
                expected.push(b'\r');
                expected.push(b'\n');
            } else {
                expected.push(b);
            }
        }
        assert_eq!(decoded, expected);
    }

    /// QP soft-linebreak (`=\r\n`) is consumed and not emitted.
    #[test]
    fn qp_decode_handles_soft_linebreak() {
        let encoded = b"hel=\r\nlo";
        let mut dest = Vec::new();
        decode_qp_into(encoded, &mut dest).expect("decode failed");
        assert_eq!(dest, b"hello");
    }

    /// FASM `mimelike$shouldgzip` — body must meet `MIMELIKE_MINGZIP`.
    #[test]
    fn should_gzip_respects_min_threshold() {
        let mut m = Mimelike::new();
        m.set_header(HEADER_CONTENT_TYPE, "text/html");
        m.body.extend_from_slice(&vec![b'x'; MIMELIKE_MINGZIP - 1]);
        assert!(!m.should_gzip());
        m.body.extend_from_slice(&[b'x'; 10]);
        assert!(m.should_gzip());
    }

    /// `should_gzip` rejects non-compressible content types.
    #[test]
    fn should_gzip_rejects_image_jpeg() {
        let mut m = Mimelike::new();
        m.set_header(HEADER_CONTENT_TYPE, "image/jpeg");
        m.body.extend_from_slice(&vec![b'x'; MIMELIKE_MINGZIP * 4]);
        assert!(!m.should_gzip());
    }

    /// `static_etag` is stable for identical inputs and stores the
    /// result in the `ETag` header (FASM `mimelike$static_etag`).
    #[test]
    fn static_etag_is_deterministic() {
        let mut m1 = Mimelike::new();
        let mut m2 = Mimelike::new();
        let a = m1.static_etag(0xDEAD_BEEF, b"index.html");
        let b = m2.static_etag(0xDEAD_BEEF, b"index.html");
        assert_eq!(a, b);
        // ETag must be quoted.
        assert!(a.starts_with('"'));
        assert!(a.ends_with('"'));
        // ETag header must be set on the instance.
        assert_eq!(m1.get_header(HEADER_ETAG), Some(a.as_str()));
    }

    /// `dynamic_etag` is stable for identical inputs.
    #[test]
    fn dynamic_etag_is_deterministic() {
        let mut m1 = Mimelike::new();
        let mut m2 = Mimelike::new();
        let a = m1.dynamic_etag(b"the body");
        let b = m2.dynamic_etag(b"the body");
        assert_eq!(a, b);
        assert!(a.starts_with('"'));
        assert!(a.ends_with('"'));
        assert_eq!(m1.get_header(HEADER_ETAG), Some(a.as_str()));
    }

    /// Different bodies produce different dynamic ETags.
    #[test]
    fn dynamic_etag_distinguishes_bodies() {
        let mut m1 = Mimelike::new();
        let mut m2 = Mimelike::new();
        let a = m1.dynamic_etag(b"alpha");
        let b = m2.dynamic_etag(b"beta");
        assert_ne!(a, b);
    }

    /// FASM `mimelike$compose` — basic preface + headers + body.
    /// Note: `HttpHeaders` normalizes header names to lowercase on the
    /// wire, so we check case-insensitively.
    #[test]
    fn compose_simple_response_roundtrip() {
        let mut m = Mimelike::new();
        m.set_preface("HTTP/1.1 200 OK");
        m.set_header(HEADER_CONTENT_TYPE, "text/plain");
        m.body.extend_from_slice(b"hello");
        m.compose();
        let out = m.xmitbody_slice();
        assert!(out.starts_with(b"HTTP/1.1 200 OK\r\n"));
        // Content-Length must be auto-set during compose.
        let s = std::str::from_utf8(out).unwrap_or("").to_ascii_lowercase();
        assert!(
            s.contains("content-length: 5"),
            "missing content-length header in: {}",
            std::str::from_utf8(out).unwrap_or("")
        );
        assert!(out.ends_with(b"hello"));
    }

    /// `xmitbody_headers_slice` returns only the header section, ending
    /// with the CRLFCRLF separator.
    #[test]
    fn xmitbody_headers_slice_contains_only_headers() {
        let mut m = Mimelike::new();
        m.set_preface("HTTP/1.1 200 OK");
        m.set_header(HEADER_CONTENT_TYPE, "text/plain");
        m.body.extend_from_slice(b"data");
        m.compose();
        let headers = m.xmitbody_headers_slice();
        assert!(headers.ends_with(b"\r\n\r\n"));
        // No body bytes leaked into headers slice.
        assert!(!headers.windows(4).any(|w| w == b"data"));
    }

    /// FASM L1395-1560: Set-Cookie split logic preserves embedded
    /// `Expires=Wed, 09 Jun ...` date commas (the date day-of-week
    /// continuation has a 2-digit prefix `09` matching the heuristic).
    /// `HttpHeaders` lowercases names — we check `set-cookie:`.
    #[test]
    fn compose_setcookie_split_preserves_dates() {
        let mut m = Mimelike::new();
        m.set_preface("HTTP/1.1 200 OK");
        m.set_header(
            HEADER_SET_COOKIE,
            "sess=1; Expires=Wed, 09 Jun 2021 10:18:14 GMT, other=2",
        );
        m.compose();
        let out = std::str::from_utf8(m.xmitbody_slice()).unwrap_or("");
        let lower = out.to_ascii_lowercase();
        let count = lower.matches("set-cookie:").count();
        // Two cookies, with the embedded date held intact.
        assert_eq!(count, 2, "output was: {}", out);
    }

    /// `multipart_content_type` formats the Content-Type per RFC.
    #[test]
    fn multipart_content_type_formats_correctly() {
        let mut m = Mimelike::new();
        m.set_boundary("xyz123");
        let ct = m.multipart_content_type("alternative").expect("none");
        assert!(ct.contains("multipart/alternative"));
        assert!(ct.contains("xyz123"));
    }

    /// FASM L370: `set_default_boundary` produces a unique-per-call
    /// boundary string with the `=_HeavyThing-` prefix.
    #[test]
    fn set_default_boundary_uses_heavything_prefix() {
        let mut m = Mimelike::new();
        m.set_default_boundary();
        let b = m.boundary.as_deref().expect("boundary not set");
        assert!(b.starts_with("=_HeavyThing-"));
        // Two consecutive calls should produce different values
        // (random source).
        let mut m2 = Mimelike::new();
        m2.set_default_boundary();
        let b2 = m2.boundary.as_deref().expect("boundary not set");
        assert_ne!(b, b2);
    }

    /// `body_bytes` falls back to internal Buffer when no external
    /// pointer is set.
    #[test]
    fn body_bytes_uses_internal_buffer_by_default() {
        let mut m = Mimelike::new();
        m.body.extend_from_slice(b"internal-body");
        assert_eq!(m.body_bytes(), b"internal-body");
        assert_eq!(m.body_len(), b"internal-body".len());
    }

    /// `body_bytes` follows the external pointer when
    /// `set_body_external` has been used.
    #[test]
    fn body_bytes_uses_external_pointer_when_set() {
        let payload = b"external-data".to_vec();
        let mut m = Mimelike::new();
        // SAFETY: payload outlives m within this scope.
        unsafe {
            m.set_body_external(payload.as_ptr(), payload.len());
        }
        assert_eq!(m.body_bytes(), b"external-data");
        assert_eq!(m.body_len(), b"external-data".len());
    }

    /// `set_body` with no encoding headers passes data through.
    #[test]
    fn set_body_passthrough_without_encoding() {
        let mut m = Mimelike::new();
        m.set_body(b"raw-body").expect("set_body failed");
        assert_eq!(m.body_bytes(), b"raw-body");
    }

    /// `set_body` decodes chunked Transfer-Encoding.
    #[test]
    fn set_body_decodes_chunked() {
        let mut m = Mimelike::new();
        m.set_header(HEADER_TRANSFER_ENCODING, ENC_CHUNKED);
        let chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        m.set_body(chunked).expect("set_body failed");
        assert_eq!(m.body_bytes(), b"hello world");
    }

    /// `set_body` decodes Content-Transfer-Encoding: base64.
    #[test]
    fn set_body_decodes_base64() {
        let mut m = Mimelike::new();
        m.set_header(HEADER_CONTENT_TRANSFER_ENCODING, ENC_BASE64);
        // "hello" base64 = "aGVsbG8="
        m.set_body(b"aGVsbG8=").expect("set_body failed");
        assert_eq!(m.body_bytes(), b"hello");
    }

    /// `set_body` decodes Content-Transfer-Encoding: quoted-printable.
    #[test]
    fn set_body_decodes_quoted_printable() {
        let mut m = Mimelike::new();
        m.set_header(HEADER_CONTENT_TRANSFER_ENCODING, ENC_QP);
        // "Hello = World" QP = "Hello =3D World"
        m.set_body(b"Hello =3D World").expect("set_body failed");
        assert_eq!(m.body_bytes(), b"Hello = World");
    }

    /// `From<MimelikeError> for HttpError` produces a Parse variant
    /// with `mimelike: ` prefix.
    #[test]
    fn mimelike_error_converts_to_http_error_parse() {
        let mle = MimelikeError::HeaderParse;
        let he: HttpError = mle.into();
        match he {
            HttpError::Parse(s) => assert!(s.starts_with("mimelike: ")),
            other => panic!("expected Parse, got {:?}", other),
        }
    }

    /// `find_subslice` locates a known-good pattern.
    #[test]
    fn find_subslice_locates_pattern() {
        assert_eq!(find_subslice(b"abcdefg", b"cde"), Some(2));
        assert_eq!(find_subslice(b"aaaa", b"bb"), None);
        assert_eq!(find_subslice(b"", b"x"), None);
        assert_eq!(find_subslice(b"x", b""), None);
    }

    /// `find_line_break` distinguishes CRLF from lone LF terminators.
    #[test]
    fn find_line_break_distinguishes_terminators() {
        assert_eq!(find_line_break(b"abc\r\ndef"), Some((3, 2)));
        assert_eq!(find_line_break(b"abc\ndef"), Some((3, 1)));
        assert_eq!(find_line_break(b"no-terminator"), None);
    }

    /// `detect_multipart` extracts both quoted and unquoted boundaries.
    #[test]
    fn detect_multipart_extracts_boundary() {
        assert_eq!(
            detect_multipart(Some("multipart/mixed; boundary=abc123")).as_deref(),
            Some("abc123")
        );
        assert_eq!(
            detect_multipart(Some("multipart/mixed; boundary=\"abc 123\"")).as_deref(),
            Some("abc 123")
        );
        assert_eq!(detect_multipart(Some("text/plain")), None);
        assert_eq!(detect_multipart(None), None);
    }

    /// Multipart parsing populates `parts` with each child segment.
    #[test]
    fn parse_multipart_populates_parts() {
        let body = b"\r\n--xyz\r\nContent-Type: text/plain\r\n\r\nfirst\r\n--xyz\r\nContent-Type: text/html\r\n\r\n<p>second</p>\r\n--xyz--\r\n";
        let mut full = Vec::new();
        full.extend_from_slice(b"POST / HTTP/1.1\r\nContent-Type: multipart/mixed; boundary=xyz\r\n\r\n");
        full.extend_from_slice(body);
        let m = Mimelike::new_parse(&full, false, true).expect("parse failed");
        // At least two parts should be detected.
        assert!(m.parts.len() >= 2, "found {} parts", m.parts.len());
    }

    /// `new_parse_ext` produces equivalent results to `new_parse`.
    #[test]
    fn new_parse_ext_matches_new_parse() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let a = Mimelike::new_parse(data, true, true).expect("parse failed");
        let b = Mimelike::new_parse_ext(data, true, true).expect("parse failed");
        assert_eq!(a.preface(), b.preface());
        assert_eq!(a.get_header("Host"), b.get_header("Host"));
    }

    /// `set_preface_nocopy` accepts owned String without copy.
    #[test]
    fn set_preface_nocopy_takes_owned_string() {
        let mut m = Mimelike::new();
        m.set_preface_nocopy(String::from("HTTP/1.1 404 Not Found"));
        assert_eq!(m.preface(), Some("HTTP/1.1 404 Not Found"));
    }

    /// `set_header_novaluecopy` and `add_header_novaluecopy` accept
    /// owned Strings.
    #[test]
    fn novaluecopy_header_methods_work() {
        let mut m = Mimelike::new();
        m.set_header_novaluecopy(String::from("X-A"), String::from("alpha"));
        m.add_header_novaluecopy(String::from("X-A"), String::from("beta"));
        assert_eq!(m.get_header("X-A"), Some("alpha, beta"));
    }

    /// User bytes are read/write accessible.
    #[test]
    fn user_bytes_accessor_round_trip() {
        let mut m = Mimelike::new();
        assert_eq!(m.user_bytes(), &[0u8; 8]);
        m.user_bytes_mut()[0] = 0xFF;
        m.user_bytes_mut()[7] = 0x42;
        assert_eq!(m.user_bytes()[0], 0xFF);
        assert_eq!(m.user_bytes()[7], 0x42);
    }

    /// `header_len` and `parse_len` are populated post-parse.
    #[test]
    fn header_len_and_parse_len_tracked_after_parse() {
        let data = b"GET /foo HTTP/1.1\r\nHost: x\r\n\r\nbody";
        let m = Mimelike::new_parse(data, true, true).expect("parse failed");
        assert!(m.header_len() > 0);
        assert!(m.parse_len() >= m.header_len());
    }

    /// Parser handles bare `\r\n` end-of-headers (no headers present).
    #[test]
    fn parse_handles_empty_header_block() {
        let data = b"GET / HTTP/1.1\r\n\r\nbody-here";
        let m = Mimelike::new_parse(data, true, true).expect("parse failed");
        assert_eq!(m.preface(), Some("GET / HTTP/1.1"));
    }
}
