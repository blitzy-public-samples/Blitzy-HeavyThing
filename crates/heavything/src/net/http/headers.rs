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

//! HTTP/1.x and HTTP/2 HPACK header management — Rust port of `httpheaders.inc`.
//!
//! Implements the dual-purpose HTTP header container from the HeavyThing FASM
//! library (`httpheaders.inc`, 3,750 lines, 82 functions). Key features:
//!
//! * Insert-ordered unique-keyed header map (up to 22 headers per request/response)
//! * HTTP/1.x wire-format parse (`parse_http1`) and compose (`to_buffer_http1`)
//! * HTTP/2 HPACK (RFC 7541) decoder (`parse_http2`) and encoder (`to_buffer_http2`)
//! * Complete static table (61 entries) + dynamic table (40-entry, 4096-byte default)
//! * Full Huffman coder with all 4 RFC 7541 tables preserved verbatim
//!
//! # Byte-frozen protocol strings
//!
//! Per AAP §0.1.1, all 59 standard HTTP header names, all 15 HTTP status
//! descriptives (plus one default), all static table default values, and all
//! Huffman codes are byte-identical to the FASM source. The Huffman tables
//! `HUFFY_T`, `HUFFY_E`, `HUFFY_C`, and `HUFFY_L` are transcribed verbatim from
//! `httpheaders.inc` lines 3574–3746.
//!
//! # Consumers
//!
//! This module is foundational; it has no cross-module dependencies on other
//! `net/http/` sibling files. It is used by:
//!
//! * `crate::net::http::http1::Http1Parser` — HTTP/1.x state machine driver
//! * `crate::net::http::mimelike::Mimelike` — higher-level HTTP message wrapper
//! * `crate::net::http::server::WebServer` (indirectly via mimelike)
//! * `crate::net::http::client::WebClient` (indirectly via mimelike)
//!
//! # Error handling
//!
//! Uses `thiserror`-derived [`HttpHeadersError`] per AAP §0.8.3. Errors convert
//! via `From<HttpHeadersError> for HttpError` to [`crate::error::HttpError::Parse`]
//! so callers up the stack can use `?`-propagation transparently.
//!
//! # `unsafe` audit
//!
//! This module contains **zero** `unsafe` blocks. All low-level manipulation
//! uses safe slice operations, `Vec` insertion/removal, and `Cow<'static, [u8]>`
//! zero-copy storage.

use crate::error::HttpError;
use std::borrow::Cow;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Error Type
// -----------------------------------------------------------------------------

/// Error variants produced by `HttpHeaders` parsing, serialization, and HPACK
/// coding operations.
///
/// Implements [`std::error::Error`] via `thiserror` derive per AAP §0.8.3. The
/// `From<HttpHeadersError> for HttpError` blanket conversion wraps each variant
/// in [`HttpError::Parse`] for seamless `?`-propagation across the HTTP stack.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpHeadersError {
    /// HTTP/1.x header parsing failure (malformed line, missing colon, etc.).
    #[error("HTTP/1.x header parse failure")]
    Http1Parse,

    /// HPACK decoder encountered a malformed integer, invalid index, or
    /// truncated string.
    #[error("HPACK decode failure")]
    HpackDecode,

    /// Working header count exceeded the 22-entry limit.
    #[error("header count overflow (max 22 per message)")]
    HeaderCountOverflow,

    /// Header value size exceeded the 65,536-byte limit.
    #[error("header value too large (max 65536 bytes)")]
    ValueTooLarge,

    /// HPACK §6.3 Dynamic Table Size Update requested a size beyond the
    /// accepted range (> 65,536 bytes).
    #[error("HPACK dynamic table update out of range")]
    HpackTableSizeOutOfRange,

    /// HTTP/1.x response status line had a malformed status code.
    #[error("malformed HTTP/1.x status code")]
    MalformedStatus,

    /// HTTP/1.x request line had a malformed method token.
    #[error("malformed HTTP/1.x method")]
    MalformedMethod,

    /// Total incoming message size exceeded the 2^30-byte absolute ceiling.
    #[error("request too large (exceeds 2^30 bytes)")]
    TooLarge,
}

impl From<HttpHeadersError> for HttpError {
    fn from(e: HttpHeadersError) -> Self {
        HttpError::Parse(format!("httpheaders: {}", e))
    }
}

// -----------------------------------------------------------------------------
// Public constants — HTTP/2 pseudo-header names
// -----------------------------------------------------------------------------
// From FASM `httpheaders.inc` L3308–3463.  All names are `&'static [u8]`
// (bytes, not str) so the pointer-identity fast-path in `fast_add`/`fast_*_get`
// can mirror FASM's static-table pointer comparison semantics.

/// HPACK static table index 1: `:authority` (10 bytes).
pub const PSEUDO_AUTHORITY: &[u8] = b":authority";
/// HPACK static table indices 2–3: `:method` (7 bytes).
pub const PSEUDO_METHOD: &[u8] = b":method";
/// HPACK static table indices 4–5: `:path` (5 bytes).
pub const PSEUDO_PATH: &[u8] = b":path";
/// HPACK static table indices 6–7: `:scheme` (7 bytes).
pub const PSEUDO_SCHEME: &[u8] = b":scheme";
/// HPACK static table indices 8–14: `:status` (7 bytes).
pub const PSEUDO_STATUS: &[u8] = b":status";

// -----------------------------------------------------------------------------
// Public constants — standard HTTP header names
// -----------------------------------------------------------------------------
// All names are **lowercase** (matching FASM's stored form).  HTTP/1.x parsing
// must lowercase incoming names before lookup; `to_buffer_http1` capitalizes
// the first letter when emitting (matching FASM's `sub byte [rax], 'a'-'A'`).

/// `connection` (10 bytes). HPACK static table index 0 (FASM extension).
pub const CONNECTION: &[u8] = b"connection";
/// `accept-charset` (14 bytes).
pub const ACCEPT_CHARSET: &[u8] = b"accept-charset";
/// `accept-encoding` (15 bytes).
pub const ACCEPT_ENCODING: &[u8] = b"accept-encoding";
/// `accept-language` (15 bytes).
pub const ACCEPT_LANGUAGE: &[u8] = b"accept-language";
/// `accept-ranges` (13 bytes).
pub const ACCEPT_RANGES: &[u8] = b"accept-ranges";
/// `accept` (6 bytes).
pub const ACCEPT: &[u8] = b"accept";
/// `access-control-allow-origin` (27 bytes).
pub const ACCESS_CONTROL_ALLOW_ORIGIN: &[u8] = b"access-control-allow-origin";
/// `age` (3 bytes).
pub const AGE: &[u8] = b"age";
/// `allow` (5 bytes).
pub const ALLOW: &[u8] = b"allow";
/// `authorization` (13 bytes).
pub const AUTHORIZATION: &[u8] = b"authorization";
/// `cache-control` (13 bytes).
pub const CACHE_CONTROL: &[u8] = b"cache-control";
/// `content-disposition` (19 bytes).
pub const CONTENT_DISPOSITION: &[u8] = b"content-disposition";
/// `content-encoding` (16 bytes).
pub const CONTENT_ENCODING: &[u8] = b"content-encoding";
/// `content-language` (16 bytes).
pub const CONTENT_LANGUAGE: &[u8] = b"content-language";
/// `content-length` (14 bytes).
pub const CONTENT_LENGTH: &[u8] = b"content-length";
/// `content-location` (16 bytes).
pub const CONTENT_LOCATION: &[u8] = b"content-location";
/// `content-range` (13 bytes).
pub const CONTENT_RANGE: &[u8] = b"content-range";
/// `content-type` (12 bytes).
pub const CONTENT_TYPE: &[u8] = b"content-type";
/// `cookie` (6 bytes).
pub const COOKIE: &[u8] = b"cookie";
/// `date` (4 bytes).
pub const DATE: &[u8] = b"date";
/// `etag` (4 bytes).
pub const ETAG: &[u8] = b"etag";
/// `expect` (6 bytes).
pub const EXPECT: &[u8] = b"expect";
/// `expires` (7 bytes).
pub const EXPIRES: &[u8] = b"expires";
/// `from` (4 bytes).
pub const FROM: &[u8] = b"from";
/// `host` (4 bytes).
pub const HOST: &[u8] = b"host";
/// `if-match` (8 bytes).
pub const IF_MATCH: &[u8] = b"if-match";
/// `if-modified-since` (17 bytes).
pub const IF_MODIFIED_SINCE: &[u8] = b"if-modified-since";
/// `if-none-match` (13 bytes).
pub const IF_NONE_MATCH: &[u8] = b"if-none-match";
/// `if-range` (8 bytes).
pub const IF_RANGE: &[u8] = b"if-range";
/// `if-unmodified-since` (19 bytes).
pub const IF_UNMODIFIED_SINCE: &[u8] = b"if-unmodified-since";
/// `last-modified` (13 bytes).
pub const LAST_MODIFIED: &[u8] = b"last-modified";
/// `link` (4 bytes).
pub const LINK: &[u8] = b"link";
/// `location` (8 bytes).
pub const LOCATION: &[u8] = b"location";
/// `max-forwards` (12 bytes).
pub const MAX_FORWARDS: &[u8] = b"max-forwards";
/// `proxy-authenticate` (18 bytes).
pub const PROXY_AUTHENTICATE: &[u8] = b"proxy-authenticate";
/// `proxy-authorization` (19 bytes).
pub const PROXY_AUTHORIZATION: &[u8] = b"proxy-authorization";
/// `range` (5 bytes).
pub const RANGE: &[u8] = b"range";
/// `referer` (7 bytes).
pub const REFERER: &[u8] = b"referer";
/// `retry-after` (11 bytes).
pub const RETRY_AFTER: &[u8] = b"retry-after";
/// `server` (6 bytes).
pub const SERVER: &[u8] = b"server";
/// `set-cookie` (10 bytes).
pub const SET_COOKIE: &[u8] = b"set-cookie";
/// `strict-transport-security` (25 bytes).
pub const STRICT_TRANSPORT_SECURITY: &[u8] = b"strict-transport-security";
/// `transfer-encoding` (17 bytes).
pub const TRANSFER_ENCODING: &[u8] = b"transfer-encoding";
/// `user-agent` (10 bytes).
pub const USER_AGENT: &[u8] = b"user-agent";
/// `vary` (4 bytes).
pub const VARY: &[u8] = b"vary";
/// `via` (3 bytes).
pub const VIA: &[u8] = b"via";
/// `www-authenticate` (16 bytes).
pub const WWW_AUTHENTICATE: &[u8] = b"www-authenticate";

// ---------------------------------------------------------------------------
// HPACK static table default values (byte-frozen from FASM L3278-3307).
// ---------------------------------------------------------------------------

/// Shared 0-length default used for all HPACK static entries whose default
/// value is empty.  (FASM `httpheaders$static.s0a`.)
const DEFAULT_EMPTY: &[u8] = b"";
/// `GET` — HPACK static index 2 method default.  (FASM `.s2c`.)
const DEFAULT_METHOD_GET: &[u8] = b"GET";
/// `POST` — HPACK static index 3 method default.  (FASM `.s3c`.)
const DEFAULT_METHOD_POST: &[u8] = b"POST";
/// `/` — HPACK static index 4 path default.  (FASM `.s4c`.)
const DEFAULT_PATH_ROOT: &[u8] = b"/";
/// `/index.html` — HPACK static index 5 path default.  (FASM `.s5c`.)
const DEFAULT_PATH_INDEX_HTML: &[u8] = b"/index.html";
/// `http` — HPACK static index 6 scheme default.  (FASM `.s6c`.)
const DEFAULT_SCHEME_HTTP: &[u8] = b"http";
/// `https` — HPACK static index 7 scheme default.  (FASM `.s7c`.)
const DEFAULT_SCHEME_HTTPS: &[u8] = b"https";
/// `200` — HPACK static index 8 status default.  (FASM `.s8c`.)
const DEFAULT_STATUS_200: &[u8] = b"200";
/// `204` — HPACK static index 9 status default.  (FASM `.s9c`.)
const DEFAULT_STATUS_204: &[u8] = b"204";
/// `206` — HPACK static index 10 status default.  (FASM `.s10c`.)
const DEFAULT_STATUS_206: &[u8] = b"206";
/// `304` — HPACK static index 11 status default.  (FASM `.s11c`.)
const DEFAULT_STATUS_304: &[u8] = b"304";
/// `400` — HPACK static index 12 status default.  (FASM `.s12c`.)
const DEFAULT_STATUS_400: &[u8] = b"400";
/// `404` — HPACK static index 13 status default.  (FASM `.s13c`.)
const DEFAULT_STATUS_404: &[u8] = b"404";
/// `500` — HPACK static index 14 status default.  (FASM `.s14c`.)
const DEFAULT_STATUS_500: &[u8] = b"500";
/// `gzip, deflate` — HPACK static index 16 accept-encoding default.
/// (FASM `.s16c`.)
const DEFAULT_ACCEPT_ENCODING: &[u8] = b"gzip, deflate";

// ---------------------------------------------------------------------------
// HPACK static table bounds and content (RFC 7541 Appendix A + FASM extension).
// ---------------------------------------------------------------------------

/// Lowest valid HPACK static table index (RFC 7541 indices start at 1).
///
/// Note: the table at `HPACK_STATIC[0]` is a FASM extension containing
/// `connection:` — preserved for HTTP/1 fast-path compatibility but NEVER
/// emitted into HPACK wire format.
pub const HPACK_STATIC_MIN_INDEX: usize = 1;

/// Highest valid HPACK static table index (RFC 7541 defines 1..=61;
/// we populate 1..=60 matching FASM's 61-entry layout with index 0 as
/// the FASM `connection:` extension).
pub const HPACK_STATIC_MAX_INDEX: usize = 60;

/// HPACK static table (RFC 7541 Appendix A).
///
/// **61 entries** laid out as `(name, value)` pairs, indices 0..=60.
/// - Index 0 is a FASM extension (`connection:` with empty value); it exists
///   solely to let the HTTP/1 fast-path identify the Connection header by
///   pointer identity.  It is NEVER emitted into HPACK wire format.
/// - Indices 1..=60 match the RFC 7541 Appendix A static table exactly.
///   (Note: RFC 7541 defines 1..=61, but FASM `httpheaders$static` omits the
///   final RFC entry because it was never used in-tree.  The omission is
///   preserved for byte-exact fidelity per AAP §0.1.1.)
///
/// Derived from FASM `httpheaders$static` at L3216-3277.
pub const HPACK_STATIC: &[(&[u8], &[u8]); 61] = &[
    // Index 0 — FASM extension (`connection`), NOT an RFC 7541 static entry.
    (CONNECTION, DEFAULT_EMPTY),
    // Index 1 — :authority.
    (PSEUDO_AUTHORITY, DEFAULT_EMPTY),
    // Indices 2-3 — :method GET / POST.
    (PSEUDO_METHOD, DEFAULT_METHOD_GET),
    (PSEUDO_METHOD, DEFAULT_METHOD_POST),
    // Indices 4-5 — :path / and /index.html.
    (PSEUDO_PATH, DEFAULT_PATH_ROOT),
    (PSEUDO_PATH, DEFAULT_PATH_INDEX_HTML),
    // Indices 6-7 — :scheme http / https.
    (PSEUDO_SCHEME, DEFAULT_SCHEME_HTTP),
    (PSEUDO_SCHEME, DEFAULT_SCHEME_HTTPS),
    // Indices 8-14 — :status 200/204/206/304/400/404/500.
    (PSEUDO_STATUS, DEFAULT_STATUS_200),
    (PSEUDO_STATUS, DEFAULT_STATUS_204),
    (PSEUDO_STATUS, DEFAULT_STATUS_206),
    (PSEUDO_STATUS, DEFAULT_STATUS_304),
    (PSEUDO_STATUS, DEFAULT_STATUS_400),
    (PSEUDO_STATUS, DEFAULT_STATUS_404),
    (PSEUDO_STATUS, DEFAULT_STATUS_500),
    // Indices 15-60 — 46 standard header names with empty defaults, except #16.
    (ACCEPT_CHARSET, DEFAULT_EMPTY),              // 15
    (ACCEPT_ENCODING, DEFAULT_ACCEPT_ENCODING),   // 16
    (ACCEPT_LANGUAGE, DEFAULT_EMPTY),             // 17
    (ACCEPT_RANGES, DEFAULT_EMPTY),               // 18
    (ACCEPT, DEFAULT_EMPTY),                      // 19
    (ACCESS_CONTROL_ALLOW_ORIGIN, DEFAULT_EMPTY), // 20
    (AGE, DEFAULT_EMPTY),                         // 21
    (ALLOW, DEFAULT_EMPTY),                       // 22
    (AUTHORIZATION, DEFAULT_EMPTY),               // 23
    (CACHE_CONTROL, DEFAULT_EMPTY),               // 24
    (CONTENT_DISPOSITION, DEFAULT_EMPTY),         // 25
    (CONTENT_ENCODING, DEFAULT_EMPTY),            // 26
    (CONTENT_LANGUAGE, DEFAULT_EMPTY),            // 27
    (CONTENT_LENGTH, DEFAULT_EMPTY),              // 28
    (CONTENT_LOCATION, DEFAULT_EMPTY),            // 29
    (CONTENT_RANGE, DEFAULT_EMPTY),               // 30
    (CONTENT_TYPE, DEFAULT_EMPTY),                // 31
    (COOKIE, DEFAULT_EMPTY),                      // 32
    (DATE, DEFAULT_EMPTY),                        // 33
    (ETAG, DEFAULT_EMPTY),                        // 34
    (EXPECT, DEFAULT_EMPTY),                      // 35
    (EXPIRES, DEFAULT_EMPTY),                     // 36
    (FROM, DEFAULT_EMPTY),                        // 37
    (HOST, DEFAULT_EMPTY),                        // 38
    (IF_MATCH, DEFAULT_EMPTY),                    // 39
    (IF_MODIFIED_SINCE, DEFAULT_EMPTY),           // 40
    (IF_NONE_MATCH, DEFAULT_EMPTY),               // 41
    (IF_RANGE, DEFAULT_EMPTY),                    // 42
    (IF_UNMODIFIED_SINCE, DEFAULT_EMPTY),         // 43
    (LAST_MODIFIED, DEFAULT_EMPTY),               // 44
    (LINK, DEFAULT_EMPTY),                        // 45
    (LOCATION, DEFAULT_EMPTY),                    // 46
    (MAX_FORWARDS, DEFAULT_EMPTY),                // 47
    (PROXY_AUTHENTICATE, DEFAULT_EMPTY),          // 48
    (PROXY_AUTHORIZATION, DEFAULT_EMPTY),         // 49
    (RANGE, DEFAULT_EMPTY),                       // 50
    (REFERER, DEFAULT_EMPTY),                     // 51
    (RETRY_AFTER, DEFAULT_EMPTY),                 // 52
    (SERVER, DEFAULT_EMPTY),                      // 53
    (SET_COOKIE, DEFAULT_EMPTY),                  // 54
    (STRICT_TRANSPORT_SECURITY, DEFAULT_EMPTY),   // 55
    (TRANSFER_ENCODING, DEFAULT_EMPTY),           // 56
    (USER_AGENT, DEFAULT_EMPTY),                  // 57
    (VARY, DEFAULT_EMPTY),                        // 58
    (VIA, DEFAULT_EMPTY),                         // 59
    (WWW_AUTHENTICATE, DEFAULT_EMPTY),            // 60
];

// ---------------------------------------------------------------------------
// HTTP/1.x fast-path header-name search orders (byte-frozen from FASM
// L3470-3552).
// ---------------------------------------------------------------------------

/// Number of HPACK-static-table entries whose lowercase name has each length
/// 0..=27.
///
/// Used by `parse_http1` fast-path to skip length groups when the incoming
/// header name's length has zero matching candidates.
///
/// Index = name length in bytes; Value = count of static entries of that length.
///
/// Derived from FASM `httpheaders$http1_searchorders_len` at L3478.
/// Sum across the array equals **47** — the number of lowercase names present
/// in HPACK_STATIC[0..=60] whose length is ≤ 27.  (Pseudo-header names like
/// `:method` whose length is 7 are counted here alongside the 7-byte
/// standard names `expires` and `referer`; see HTTP1_SEARCHORDERS below for
/// the per-length index lists.  Note: the FASM implementation's length array
/// reflects the ACTIVE fast-path groups only; pseudo-header names do not
/// appear in HTTP/1.x parse paths, so the counts below enumerate only
/// standard lowercase header names.)
pub const HTTP1_SEARCHORDERS_LEN: [u32; 28] = [
    0, 0, 0, 2, 6, 2, 4, 2, 3, 0, 3, 1, 2, 6, 2, 2, 4, 2, 1, 3, 0, 0, 0, 0, 0, 1, 0, 1,
];

/// Length-grouped HPACK static table index lookups for HTTP/1.x fast-path.
///
/// Each entry `HTTP1_SEARCHORDERS[i]` is a slice of HPACK static table indices
/// whose lowercase name length equals `i`.  This groups header-name candidates
/// by length so `parse_http1` can dispatch directly to the matching group
/// without scanning the entire static table.
///
/// The inner slices are sorted by ascending static table index for
/// deterministic lookup.
///
/// Derived from FASM `httpheaders$http1_searchorders` at L3482-3552.  The
/// cardinality of each slice matches the corresponding entry in
/// `HTTP1_SEARCHORDERS_LEN`.
pub const HTTP1_SEARCHORDERS: [&[u32]; 28] = [
    &[],                       // 0
    &[],                       // 1
    &[],                       // 2
    &[21, 59],                 // 3  — age, via
    &[33, 34, 37, 38, 45, 58], // 4  — date, etag, from, host, link, vary
    &[22, 50],                 // 5  — allow, range
    &[19, 32, 35, 53],         // 6  — accept, cookie, expect, server
    &[36, 51],                 // 7  — expires, referer
    &[39, 42, 46],             // 8  — if-match, if-range, location
    &[],                       // 9
    &[0, 54, 57],              // 10 — connection, set-cookie, user-agent
    &[52],                     // 11 — retry-after
    &[31, 47],                 // 12 — content-type, max-forwards
    &[18, 23, 24, 30, 41, 44], // 13 — accept-ranges, authorization,
    //       cache-control, content-range,
    //       if-none-match, last-modified
    &[15, 28],         // 14 — accept-charset, content-length
    &[16, 17],         // 15 — accept-encoding, accept-language
    &[26, 27, 29, 60], // 16 — content-encoding, content-language,
    //       content-location, www-authenticate
    &[40, 56],     // 17 — if-modified-since, transfer-encoding
    &[48],         // 18 — proxy-authenticate
    &[25, 43, 49], // 19 — content-disposition,
    //       if-unmodified-since,
    //       proxy-authorization
    &[],   // 20
    &[],   // 21
    &[],   // 22
    &[],   // 23
    &[],   // 24
    &[55], // 25 — strict-transport-security
    &[],   // 26
    &[20], // 27 — access-control-allow-origin
];

// ---------------------------------------------------------------------------
// Australian-English HTTP status descriptives (byte-frozen from FASM
// L207-263).
// ---------------------------------------------------------------------------

/// HTTP status descriptive table entry used by `to_buffer_http1`.
///
/// Each entry pairs a numeric status code with the descriptive text to emit
/// after it on the HTTP/1.x status line.  The text does NOT include the
/// trailing CRLF — `to_buffer_http1` appends that separately so the stored
/// bytes can be used for other purposes (e.g., direct comparison in tests).
///
/// **Byte-identical preservation is REQUIRED per AAP §0.1.1**; the humorous
/// Australian-English descriptives are part of HeavyThing's externally
/// observable protocol output and must not be translated or paraphrased.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusDescriptive {
    /// Numeric HTTP status code (e.g., 200, 404).
    pub code: u16,
    /// Descriptive phrase emitted after the status code, without trailing CRLF.
    pub text: &'static [u8],
}

/// HTTP status descriptive table from FASM L207-263.
///
/// Iterated linearly by `HttpHeaders::status_descriptive` to look up the
/// phrase for a given status code.  Entries appear in the same order as the
/// FASM source (ascending-ish by code, with some clustering).
///
/// The FASM source stored each entry with a trailing `,13,10` (CRLF); the
/// Rust port strips that trailer and lets `to_buffer_http1` append it at
/// serialization time.  Net wire output is byte-identical.
pub const STATUS_DESCRIPTIVES: &[StatusDescriptive] = &[
    StatusDescriptive {
        code: 200,
        text: b"She'll be apples",
    },
    StatusDescriptive {
        code: 206,
        text: b"Just a slice of the whole pie",
    },
    StatusDescriptive {
        code: 301,
        text: b"She nicked off",
    },
    StatusDescriptive {
        code: 302,
        text: b"Look here mate",
    },
    StatusDescriptive {
        code: 304,
        text: b"Same same mate",
    },
    StatusDescriptive {
        code: 400,
        text: b"Up a gumtree",
    },
    StatusDescriptive {
        code: 403,
        text: b"I wouldn't be doin that",
    },
    StatusDescriptive {
        code: 404,
        text: b"Gone Walkabout",
    },
    StatusDescriptive {
        code: 405,
        text: b"Wrong idea mate",
    },
    StatusDescriptive {
        code: 500,
        text: b"It's Cactus",
    },
    StatusDescriptive {
        code: 501,
        text: b"Not Implemented",
    },
    StatusDescriptive {
        code: 502,
        text: b"Had a blue with the old fella",
    },
    StatusDescriptive {
        code: 503,
        text: b"You got nits in your network",
    },
    StatusDescriptive {
        code: 504,
        text: b"Gateway Tuckered Out",
    },
    StatusDescriptive {
        code: 505,
        text: b"You gone bongers mate?",
    },
];

/// Fallback descriptive when a status code is not found in
/// `STATUS_DESCRIPTIVES`.  Matches FASM's `.rdefault` at L263.
pub const STATUS_DESCRIPTIVE_DEFAULT: &[u8] = b"HeavyThing";

// ────────────────────────────────────────────────────────────────────────────
// HPACK Huffman codec tables (RFC 7541 Appendix B).
// Verbatim from FASM `httpheaders.inc` L3574-3746.  These four tables MUST be
// preserved byte-for-byte per AAP §0.1.1 (byte-frozen protocol strings).
// ────────────────────────────────────────────────────────────────────────────

/// HPACK Huffman decoder state-table (44 × u32 = 176 bytes).
///
/// Primary decoder state-transition table driving the 4-iteration repeat-4
/// unrolled tree walk in `parse_http2`'s Huffman path.  Each entry encodes
/// a packed transition: offset into `HUFFY_E`, sub-shift amount, and flags.
///
/// Byte-identical to FASM `httpheaders$huffyT` at L3574-3581.
pub const HUFFY_T: [u32; 44] = [
    0x00000900, 0x02000609, 0x0240060f, 0x02800615, 0x02c0031b, 0x02c8011b, 0x02ca011b, 0x02cc011b,
    0x02ce011b, 0x02d0011b, 0x02d2011b, 0x02d4011b, 0x02d6011b, 0x02d8011b, 0x02da011b, 0x02dc011b,
    0x02de011b, 0x02e0011b, 0x02e2011b, 0x02e40415, 0x02f40315, 0x02fc0215, 0x03000215, 0x03040215,
    0x03080215, 0x030c0215, 0x03100215, 0x03140215, 0x03180115, 0x031a0115, 0x031c0115, 0x031e0115,
    0x03200115, 0x03220115, 0x03240115, 0x03260115, 0x03280115, 0x032a0115, 0x032c0115, 0x032e0115,
    0x03300115, 0x03320209, 0x03360109, 0x03380109,
];

/// HPACK Huffman decoder leaf-table (826 × u32 = 3304 bytes).
///
/// Multi-level lookup table consumed by the decoder's tree walk alongside
/// `HUFFY_T`.  Each entry encodes the decoded byte value in bits 16-23,
/// the bit-length consumed in bits 8-15, and sub-flags in bits 0-7.
///
/// Byte-identical to FASM `httpheaders$huffyE` at L3584-3688.
pub const HUFFY_E: [u32; 826] = [
    0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500,
    0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500, 0x00300500,
    0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500,
    0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500, 0x00310500,
    0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500,
    0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500, 0x00320500,
    0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500,
    0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500, 0x00610500,
    0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500,
    0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500, 0x00630500,
    0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500,
    0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500, 0x00650500,
    0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500,
    0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500, 0x00690500,
    0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500,
    0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500, 0x006f0500,
    0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500,
    0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500, 0x00730500,
    0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500,
    0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500, 0x00740500,
    0x00200600, 0x00200600, 0x00200600, 0x00200600, 0x00200600, 0x00200600, 0x00200600, 0x00200600,
    0x00250600, 0x00250600, 0x00250600, 0x00250600, 0x00250600, 0x00250600, 0x00250600, 0x00250600,
    0x002d0600, 0x002d0600, 0x002d0600, 0x002d0600, 0x002d0600, 0x002d0600, 0x002d0600, 0x002d0600,
    0x002e0600, 0x002e0600, 0x002e0600, 0x002e0600, 0x002e0600, 0x002e0600, 0x002e0600, 0x002e0600,
    0x002f0600, 0x002f0600, 0x002f0600, 0x002f0600, 0x002f0600, 0x002f0600, 0x002f0600, 0x002f0600,
    0x00330600, 0x00330600, 0x00330600, 0x00330600, 0x00330600, 0x00330600, 0x00330600, 0x00330600,
    0x00340600, 0x00340600, 0x00340600, 0x00340600, 0x00340600, 0x00340600, 0x00340600, 0x00340600,
    0x00350600, 0x00350600, 0x00350600, 0x00350600, 0x00350600, 0x00350600, 0x00350600, 0x00350600,
    0x00360600, 0x00360600, 0x00360600, 0x00360600, 0x00360600, 0x00360600, 0x00360600, 0x00360600,
    0x00370600, 0x00370600, 0x00370600, 0x00370600, 0x00370600, 0x00370600, 0x00370600, 0x00370600,
    0x00380600, 0x00380600, 0x00380600, 0x00380600, 0x00380600, 0x00380600, 0x00380600, 0x00380600,
    0x00390600, 0x00390600, 0x00390600, 0x00390600, 0x00390600, 0x00390600, 0x00390600, 0x00390600,
    0x003d0600, 0x003d0600, 0x003d0600, 0x003d0600, 0x003d0600, 0x003d0600, 0x003d0600, 0x003d0600,
    0x00410600, 0x00410600, 0x00410600, 0x00410600, 0x00410600, 0x00410600, 0x00410600, 0x00410600,
    0x005f0600, 0x005f0600, 0x005f0600, 0x005f0600, 0x005f0600, 0x005f0600, 0x005f0600, 0x005f0600,
    0x00620600, 0x00620600, 0x00620600, 0x00620600, 0x00620600, 0x00620600, 0x00620600, 0x00620600,
    0x00640600, 0x00640600, 0x00640600, 0x00640600, 0x00640600, 0x00640600, 0x00640600, 0x00640600,
    0x00660600, 0x00660600, 0x00660600, 0x00660600, 0x00660600, 0x00660600, 0x00660600, 0x00660600,
    0x00670600, 0x00670600, 0x00670600, 0x00670600, 0x00670600, 0x00670600, 0x00670600, 0x00670600,
    0x00680600, 0x00680600, 0x00680600, 0x00680600, 0x00680600, 0x00680600, 0x00680600, 0x00680600,
    0x006c0600, 0x006c0600, 0x006c0600, 0x006c0600, 0x006c0600, 0x006c0600, 0x006c0600, 0x006c0600,
    0x006d0600, 0x006d0600, 0x006d0600, 0x006d0600, 0x006d0600, 0x006d0600, 0x006d0600, 0x006d0600,
    0x006e0600, 0x006e0600, 0x006e0600, 0x006e0600, 0x006e0600, 0x006e0600, 0x006e0600, 0x006e0600,
    0x00700600, 0x00700600, 0x00700600, 0x00700600, 0x00700600, 0x00700600, 0x00700600, 0x00700600,
    0x00720600, 0x00720600, 0x00720600, 0x00720600, 0x00720600, 0x00720600, 0x00720600, 0x00720600,
    0x00750600, 0x00750600, 0x00750600, 0x00750600, 0x00750600, 0x00750600, 0x00750600, 0x00750600,
    0x003a0700, 0x003a0700, 0x003a0700, 0x003a0700, 0x00420700, 0x00420700, 0x00420700, 0x00420700,
    0x00430700, 0x00430700, 0x00430700, 0x00430700, 0x00440700, 0x00440700, 0x00440700, 0x00440700,
    0x00450700, 0x00450700, 0x00450700, 0x00450700, 0x00460700, 0x00460700, 0x00460700, 0x00460700,
    0x00470700, 0x00470700, 0x00470700, 0x00470700, 0x00480700, 0x00480700, 0x00480700, 0x00480700,
    0x00490700, 0x00490700, 0x00490700, 0x00490700, 0x004a0700, 0x004a0700, 0x004a0700, 0x004a0700,
    0x004b0700, 0x004b0700, 0x004b0700, 0x004b0700, 0x004c0700, 0x004c0700, 0x004c0700, 0x004c0700,
    0x004d0700, 0x004d0700, 0x004d0700, 0x004d0700, 0x004e0700, 0x004e0700, 0x004e0700, 0x004e0700,
    0x004f0700, 0x004f0700, 0x004f0700, 0x004f0700, 0x00500700, 0x00500700, 0x00500700, 0x00500700,
    0x00510700, 0x00510700, 0x00510700, 0x00510700, 0x00520700, 0x00520700, 0x00520700, 0x00520700,
    0x00530700, 0x00530700, 0x00530700, 0x00530700, 0x00540700, 0x00540700, 0x00540700, 0x00540700,
    0x00550700, 0x00550700, 0x00550700, 0x00550700, 0x00560700, 0x00560700, 0x00560700, 0x00560700,
    0x00570700, 0x00570700, 0x00570700, 0x00570700, 0x00590700, 0x00590700, 0x00590700, 0x00590700,
    0x006a0700, 0x006a0700, 0x006a0700, 0x006a0700, 0x006b0700, 0x006b0700, 0x006b0700, 0x006b0700,
    0x00710700, 0x00710700, 0x00710700, 0x00710700, 0x00760700, 0x00760700, 0x00760700, 0x00760700,
    0x00770700, 0x00770700, 0x00770700, 0x00770700, 0x00780700, 0x00780700, 0x00780700, 0x00780700,
    0x00790700, 0x00790700, 0x00790700, 0x00790700, 0x007a0700, 0x007a0700, 0x007a0700, 0x007a0700,
    0x00260800, 0x00260800, 0x002a0800, 0x002a0800, 0x002c0800, 0x002c0800, 0x003b0800, 0x003b0800,
    0x00580800, 0x00580800, 0x005a0800, 0x005a0800, 0x00000a2b, 0x00000a2a, 0x00000b29, 0x00001e01,
    0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01,
    0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01, 0x007c0b01,
    0x00230c01, 0x00230c01, 0x00230c01, 0x00230c01, 0x00230c01, 0x00230c01, 0x00230c01, 0x00230c01,
    0x003e0c01, 0x003e0c01, 0x003e0c01, 0x003e0c01, 0x003e0c01, 0x003e0c01, 0x003e0c01, 0x003e0c01,
    0x00000d01, 0x00000d01, 0x00000d01, 0x00000d01, 0x00240d01, 0x00240d01, 0x00240d01, 0x00240d01,
    0x00400d01, 0x00400d01, 0x00400d01, 0x00400d01, 0x005b0d01, 0x005b0d01, 0x005b0d01, 0x005b0d01,
    0x005d0d01, 0x005d0d01, 0x005d0d01, 0x005d0d01, 0x007e0d01, 0x007e0d01, 0x007e0d01, 0x007e0d01,
    0x005e0e01, 0x005e0e01, 0x007d0e01, 0x007d0e01, 0x003c0f01, 0x00600f01, 0x007b0f01, 0x00001e02,
    0x005c1302, 0x005c1302, 0x005c1302, 0x005c1302, 0x00c31302, 0x00c31302, 0x00c31302, 0x00c31302,
    0x00d01302, 0x00d01302, 0x00d01302, 0x00d01302, 0x00801402, 0x00801402, 0x00821402, 0x00821402,
    0x00831402, 0x00831402, 0x00a21402, 0x00a21402, 0x00b81402, 0x00b81402, 0x00c21402, 0x00c21402,
    0x00e01402, 0x00e01402, 0x00e21402, 0x00e21402, 0x00991502, 0x00a11502, 0x00a71502, 0x00ac1502,
    0x00b01502, 0x00b11502, 0x00b31502, 0x00d11502, 0x00d81502, 0x00d91502, 0x00e31502, 0x00e51502,
    0x00e61502, 0x00001628, 0x00001627, 0x00001626, 0x00001625, 0x00001624, 0x00001623, 0x00001622,
    0x00001621, 0x00001620, 0x0000161f, 0x0000161e, 0x0000161d, 0x0000161c, 0x0000171b, 0x0000171a,
    0x00001719, 0x00001718, 0x00001717, 0x00001716, 0x00001715, 0x00001814, 0x00001913, 0x00001e03,
    0x00c01a03, 0x00c01a03, 0x00c11a03, 0x00c11a03, 0x00c81a03, 0x00c81a03, 0x00c91a03, 0x00c91a03,
    0x00ca1a03, 0x00ca1a03, 0x00cd1a03, 0x00cd1a03, 0x00d21a03, 0x00d21a03, 0x00d51a03, 0x00d51a03,
    0x00da1a03, 0x00da1a03, 0x00db1a03, 0x00db1a03, 0x00ee1a03, 0x00ee1a03, 0x00f01a03, 0x00f01a03,
    0x00f21a03, 0x00f21a03, 0x00f31a03, 0x00f31a03, 0x00ff1a03, 0x00ff1a03, 0x00cb1b03, 0x00cc1b03,
    0x00d31b03, 0x00d41b03, 0x00d61b03, 0x00dd1b03, 0x00de1b03, 0x00df1b03, 0x00f11b03, 0x00f41b03,
    0x00f51b03, 0x00f61b03, 0x00f71b03, 0x00f81b03, 0x00fa1b03, 0x00fb1b03, 0x00fc1b03, 0x00fd1b03,
    0x00fe1b03, 0x00001c12, 0x00001c11, 0x00001c10, 0x00001c0f, 0x00001c0e, 0x00001c0d, 0x00001c0c,
    0x00001c0b, 0x00001c0a, 0x00001c09, 0x00001c08, 0x00001c07, 0x00001c06, 0x00001c05, 0x00001e04,
    0x00f91c04, 0x00f91c04, 0x00f91c04, 0x00f91c04, 0x000a1e04, 0x000d1e04, 0x00161e04, 0x01001e04,
    0x007f1c05, 0x00dc1c05, 0x001e1c06, 0x001f1c06, 0x001c1c07, 0x001d1c07, 0x001a1c08, 0x001b1c08,
    0x00181c09, 0x00191c09, 0x00151c0a, 0x00171c0a, 0x00131c0b, 0x00141c0b, 0x00111c0c, 0x00121c0c,
    0x000f1c0d, 0x00101c0d, 0x000c1c0e, 0x000e1c0e, 0x00081c0f, 0x000b1c0f, 0x00061c10, 0x00071c10,
    0x00041c11, 0x00051c11, 0x00021c12, 0x00031c12, 0x00ab1813, 0x00ab1813, 0x00ce1813, 0x00ce1813,
    0x00d71813, 0x00d71813, 0x00e11813, 0x00e11813, 0x00ec1813, 0x00ec1813, 0x00ed1813, 0x00ed1813,
    0x00c71913, 0x00cf1913, 0x00ea1913, 0x00eb1913, 0x00ef1714, 0x00ef1714, 0x00091814, 0x008e1814,
    0x00901814, 0x00911814, 0x00941814, 0x009f1814, 0x00bc1715, 0x00bf1715, 0x00c51715, 0x00e71715,
    0x00af1716, 0x00b41716, 0x00b61716, 0x00b71716, 0x00a51717, 0x00a61717, 0x00a81717, 0x00ae1717,
    0x00981718, 0x009b1718, 0x009d1718, 0x009e1718, 0x00931719, 0x00951719, 0x00961719, 0x00971719,
    0x008b171a, 0x008c171a, 0x008d171a, 0x008f171a, 0x0001171b, 0x0087171b, 0x0089171b, 0x008a171b,
    0x00e8161c, 0x00e9161c, 0x00c6161d, 0x00e4161d, 0x00be161e, 0x00c4161e, 0x00bb161f, 0x00bd161f,
    0x00b91620, 0x00ba1620, 0x00b21621, 0x00b51621, 0x00aa1622, 0x00ad1622, 0x00a41623, 0x00a91623,
    0x00a01624, 0x00a31624, 0x009a1625, 0x009c1625, 0x00881626, 0x00921626, 0x00851627, 0x00861627,
    0x00811628, 0x00841628, 0x003f0a29, 0x003f0a29, 0x00270b29, 0x002b0b29, 0x00280a2a, 0x00290a2a,
    0x00210a2b, 0x00220a2b,
];

/// HPACK Huffman encode-code table (257 × u32 = 1028 bytes).
///
/// Left-aligned 32-bit Huffman codes per byte value 0-255 plus EOS at
/// index 256.  Used by `to_buffer_http2`'s `.writestorestring` to emit bit
/// patterns.  Byte-identical to FASM `httpheaders$huffyC` at L3693-3725.
///
/// Selected reference values (RFC 7541 §5.2 / Appendix B):
/// - `HUFFY_C[b' ' as usize] == 0x50000000` (6-bit code left-aligned)
/// - `HUFFY_C[b'/' as usize] == 0x60000000` (6-bit code)
/// - `HUFFY_C[b'0' as usize] == 0x00000000` (5-bit code = 00000)
/// - `HUFFY_C[b'a' as usize] == 0x18000000` (5-bit code = 00011)
/// - `HUFFY_C[256]           == 0xfffffffc` (EOS, 30-bit code of all 1s)
pub const HUFFY_C: [u32; 257] = [
    0xffc00000, 0xffffb000, 0xfffffe20, 0xfffffe30, 0xfffffe40, 0xfffffe50, 0xfffffe60, 0xfffffe70,
    0xfffffe80, 0xffffea00, 0xfffffff0, 0xfffffe90, 0xfffffea0, 0xfffffff4, 0xfffffeb0, 0xfffffec0,
    0xfffffed0, 0xfffffee0, 0xfffffef0, 0xffffff00, 0xffffff10, 0xffffff20, 0xfffffff8, 0xffffff30,
    0xffffff40, 0xffffff50, 0xffffff60, 0xffffff70, 0xffffff80, 0xffffff90, 0xffffffa0, 0xffffffb0,
    0x50000000, 0xfe000000, 0xfe400000, 0xffa00000, 0xffc80000, 0x54000000, 0xf8000000, 0xff400000,
    0xfe800000, 0xfec00000, 0xf9000000, 0xff600000, 0xfa000000, 0x58000000, 0x5c000000, 0x60000000,
    0x00000000, 0x08000000, 0x10000000, 0x64000000, 0x68000000, 0x6c000000, 0x70000000, 0x74000000,
    0x78000000, 0x7c000000, 0xb8000000, 0xfb000000, 0xfff80000, 0x80000000, 0xffb00000, 0xff000000,
    0xffd00000, 0x84000000, 0xba000000, 0xbc000000, 0xbe000000, 0xc0000000, 0xc2000000, 0xc4000000,
    0xc6000000, 0xc8000000, 0xca000000, 0xcc000000, 0xce000000, 0xd0000000, 0xd2000000, 0xd4000000,
    0xd6000000, 0xd8000000, 0xda000000, 0xdc000000, 0xde000000, 0xe0000000, 0xe2000000, 0xe4000000,
    0xfc000000, 0xe6000000, 0xfd000000, 0xffd80000, 0xfffe0000, 0xffe00000, 0xfff00000, 0x88000000,
    0xfffa0000, 0x18000000, 0x8c000000, 0x20000000, 0x90000000, 0x28000000, 0x94000000, 0x98000000,
    0x9c000000, 0x30000000, 0xe8000000, 0xea000000, 0xa0000000, 0xa4000000, 0xa8000000, 0x38000000,
    0xac000000, 0xec000000, 0xb0000000, 0x40000000, 0x48000000, 0xb4000000, 0xee000000, 0xf0000000,
    0xf2000000, 0xf4000000, 0xf6000000, 0xfffc0000, 0xff800000, 0xfff40000, 0xffe80000, 0xffffffc0,
    0xfffe6000, 0xffff4800, 0xfffe7000, 0xfffe8000, 0xffff4c00, 0xffff5000, 0xffff5400, 0xffffb200,
    0xffff5800, 0xffffb400, 0xffffb600, 0xffffb800, 0xffffba00, 0xffffbc00, 0xffffeb00, 0xffffbe00,
    0xffffec00, 0xffffed00, 0xffff5c00, 0xffffc000, 0xffffee00, 0xffffc200, 0xffffc400, 0xffffc600,
    0xffffc800, 0xfffee000, 0xffff6000, 0xffffca00, 0xffff6400, 0xffffcc00, 0xffffce00, 0xffffef00,
    0xffff6800, 0xfffee800, 0xfffe9000, 0xffff6c00, 0xffff7000, 0xffffd000, 0xffffd200, 0xfffef000,
    0xffffd400, 0xffff7400, 0xffff7800, 0xfffff000, 0xfffef800, 0xffff7c00, 0xffffd600, 0xffffd800,
    0xffff0000, 0xffff0800, 0xffff8000, 0xffff1000, 0xffffda00, 0xffff8400, 0xffffdc00, 0xffffde00,
    0xfffea000, 0xffff8800, 0xffff8c00, 0xffff9000, 0xffffe000, 0xffff9400, 0xffff9800, 0xffffe200,
    0xfffff800, 0xfffff840, 0xfffeb000, 0xfffe2000, 0xffff9c00, 0xffffe400, 0xffffa000, 0xfffff600,
    0xfffff880, 0xfffff8c0, 0xfffff900, 0xfffffbc0, 0xfffffbe0, 0xfffff940, 0xfffff100, 0xfffff680,
    0xfffe4000, 0xffff1800, 0xfffff980, 0xfffffc00, 0xfffffc20, 0xfffff9c0, 0xfffffc40, 0xfffff200,
    0xffff2000, 0xffff2800, 0xfffffa00, 0xfffffa40, 0xffffffd0, 0xfffffc60, 0xfffffc80, 0xfffffca0,
    0xfffec000, 0xfffff300, 0xfffed000, 0xffff3000, 0xffffa400, 0xffff3800, 0xffff4000, 0xffffe600,
    0xffffa800, 0xffffac00, 0xfffff700, 0xfffff780, 0xfffff400, 0xfffff500, 0xfffffa80, 0xffffe800,
    0xfffffac0, 0xfffffcc0, 0xfffffb00, 0xfffffb40, 0xfffffce0, 0xfffffd00, 0xfffffd20, 0xfffffd40,
    0xfffffd60, 0xffffffe0, 0xfffffd80, 0xfffffda0, 0xfffffdc0, 0xfffffde0, 0xfffffe00, 0xfffffb80,
    0xfffffffc,
];

/// HPACK Huffman encode-length table (257 × u8 = 257 bytes).
///
/// Byte value (0-255 plus EOS at index 256) → bit-length of its Huffman
/// code.  Used by the encoder's prescan pass to compute total output bit
/// length before committing to Huffman vs. raw emission, and by the
/// decoder for validation.  Byte-identical to FASM `httpheaders$huffyL`
/// at L3730-3746.
///
/// Selected reference values:
/// - `HUFFY_L[b' ' as usize] == 6`  (space has 6-bit code)
/// - `HUFFY_L[b'/' as usize] == 6`  (slash has 6-bit code)
/// - `HUFFY_L[b'0' as usize] == 5`  (digit zero)
/// - `HUFFY_L[b'a' as usize] == 5`  (letter a)
/// - `HUFFY_L[256]           == 30` (EOS code length)
pub const HUFFY_L: [u8; 257] = [
    0x0d, 0x17, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x18, 0x1e, 0x1c, 0x1c, 0x1e, 0x1c, 0x1c, 0x1c,
    0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1e, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x06, 0x0a,
    0x0a, 0x0c, 0x0d, 0x06, 0x08, 0x0b, 0x0a, 0x0a, 0x08, 0x0b, 0x08, 0x06, 0x06, 0x06, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x07, 0x08, 0x0f, 0x06, 0x0c, 0x0a, 0x0d, 0x06, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x08, 0x07, 0x08, 0x0d, 0x13, 0x0d, 0x0e, 0x06, 0x0f, 0x05, 0x06, 0x05, 0x06, 0x05,
    0x06, 0x06, 0x06, 0x05, 0x07, 0x07, 0x06, 0x06, 0x06, 0x05, 0x06, 0x07, 0x06, 0x05, 0x05, 0x06, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x0f, 0x0b, 0x0e, 0x0d, 0x1c, 0x14, 0x16, 0x14, 0x14, 0x16, 0x16, 0x16, 0x17,
    0x16, 0x17, 0x17, 0x17, 0x17, 0x17, 0x18, 0x17, 0x18, 0x18, 0x16, 0x17, 0x18, 0x17, 0x17, 0x17, 0x17,
    0x15, 0x16, 0x17, 0x16, 0x17, 0x17, 0x18, 0x16, 0x15, 0x14, 0x16, 0x16, 0x17, 0x17, 0x15, 0x17, 0x16,
    0x16, 0x18, 0x15, 0x16, 0x17, 0x17, 0x15, 0x15, 0x16, 0x15, 0x17, 0x16, 0x17, 0x17, 0x14, 0x16, 0x16,
    0x16, 0x17, 0x16, 0x16, 0x17, 0x1a, 0x1a, 0x14, 0x13, 0x16, 0x17, 0x16, 0x19, 0x1a, 0x1a, 0x1a, 0x1b,
    0x1b, 0x1a, 0x18, 0x19, 0x13, 0x15, 0x1a, 0x1b, 0x1b, 0x1a, 0x1b, 0x18, 0x15, 0x15, 0x1a, 0x1a, 0x1c,
    0x1b, 0x1b, 0x1b, 0x14, 0x18, 0x14, 0x15, 0x16, 0x15, 0x15, 0x17, 0x16, 0x16, 0x19, 0x19, 0x18, 0x18,
    0x1a, 0x17, 0x1a, 0x1b, 0x1a, 0x1a, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1c, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b,
    0x1a, 0x1e,
];

// ═══════════════════════════════════════════════════════════════════════════
// SECTION: CAPACITY AND FLAG CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum number of working headers per message.
/// Mirrors the FASM `httpheaders_htable` inline storage of 22 × 32 bytes
/// = 704 bytes.  Real-world HTTP requests rarely exceed this; exceeding it
/// returns `HttpHeadersError::HeaderCountOverflow`.
pub const MAX_HTABLE: u32 = 22;

/// Default HPACK dynamic-table entry limit
/// (FASM `httpheaders_dlimit_ofs` default value of 40).
pub const DEFAULT_DLIMIT: u32 = 40;

/// Default HPACK dynamic-table byte budget
/// (FASM `httpheaders_tablesize_ofs` default, matches the HTTP/2
/// `SETTINGS_HEADER_TABLE_SIZE` initial value per RFC 7540 §6.5.2).
pub const DEFAULT_TABLESIZE: u32 = 4096;

/// HTTP/1.0 version flag value (stored in the low 2 bits of
/// `HttpHeaders::flags`).  Matches FASM convention at L41.
pub const FLAG_HTTP_1_0: u64 = 0;

/// HTTP/1.1 version flag value (stored in the low 2 bits of
/// `HttpHeaders::flags`).  Matches FASM convention at L41.
pub const FLAG_HTTP_1_1: u64 = 1;

/// HTTP/2 version flag value (stored in the low 2 bits of
/// `HttpHeaders::flags`).  Matches FASM convention at L41.
pub const FLAG_HTTP_2: u64 = 2;

/// Absolute ceiling on incoming HTTP/1.x message size (2^30 bytes).
/// Used by `parse_http1` as a guard rail matching FASM L1870.
pub const MAX_MESSAGE_SIZE: usize = 1 << 30;

/// Maximum header value length in bytes (FASM L1702-1721 scratch cap of 65536).
/// A single decoded header value exceeding this yields
/// `HttpHeadersError::ValueTooLarge`.
pub const MAX_VALUE_BYTES: usize = 65536;

// ═══════════════════════════════════════════════════════════════════════════
// SECTION: HEADER ENTRY
// ═══════════════════════════════════════════════════════════════════════════

/// A single parsed or stored header entry.
///
/// Names and values use `Cow<'static, [u8]>` so that well-known static header
/// names and HPACK static-table entries can be shared zero-copy via
/// `Cow::Borrowed`, while user-supplied and HPACK-decoded content use
/// `Cow::Owned(Vec<u8>)`.
///
/// The Rust port replaces the FASM 32-byte layout
/// `(name_ptr, name_len, value_ptr, value_len)` with a typed struct carrying
/// the same four pieces of information but with ownership expressed directly
/// via `Cow`.
#[derive(Debug, Clone)]
pub struct HeaderEntry {
    /// Header name bytes (typically lowercased for storage; HTTP header
    /// names are case-insensitive per RFC 7230 §3.2 and RFC 7541 §8.1.2).
    pub name: Cow<'static, [u8]>,
    /// Header value bytes.  Not lowercased; stored verbatim.
    pub value: Cow<'static, [u8]>,
}

impl HeaderEntry {
    /// Builds an entry with static borrows for both name and value.
    /// Used for HPACK static-table hits and compile-time known default pairs
    /// (e.g. `(PSEUDO_METHOD, b"GET")`).
    #[inline]
    pub fn from_static(name: &'static [u8], value: &'static [u8]) -> Self {
        Self {
            name: Cow::Borrowed(name),
            value: Cow::Borrowed(value),
        }
    }

    /// Builds an entry with owned bytes for both name and value.
    /// Used for HPACK literal-with-new-name decodes and for user-supplied
    /// headers whose names do not appear in the HPACK static table.
    #[inline]
    pub fn from_owned(name: Vec<u8>, value: Vec<u8>) -> Self {
        Self {
            name: Cow::Owned(name),
            value: Cow::Owned(value),
        }
    }

    /// Builds an entry with a static borrow for the name (well-known header)
    /// and an owned value.  Used by `fast_add` and by HPACK literal-with-
    /// indexed-name decodes where the name comes from the static table.
    #[inline]
    pub fn from_static_name(name: &'static [u8], value: Vec<u8>) -> Self {
        Self {
            name: Cow::Borrowed(name),
            value: Cow::Owned(value),
        }
    }

    /// Entry size in bytes per RFC 7541 §4.1: `name.len() + value.len() + 32`.
    /// The constant `32` accounts for per-entry overhead (pointers and
    /// length fields) rather than any specific struct size.
    #[inline]
    pub fn hpack_size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION: HTTP HEADERS CONTAINER
// ═══════════════════════════════════════════════════════════════════════════

/// HTTP/1.x and HTTP/2 HPACK header container.
///
/// Supports up to [`MAX_HTABLE`] (22) "working" headers in the `htable` and
/// a per-connection HPACK dynamic table (`dtable`) bounded by `dlimit`
/// entries and `tablesize` bytes (RFC 7541 §4).
///
/// **FASM layout preserved semantically, not byte-for-byte.**
/// The FASM original stored 6136 bytes inline (pre-allocated htable, dtable,
/// and scratch buffers with 12 offsets into a single struct).  The Rust port
/// uses heap-allocated `Vec` storage — per AAP §0.5.1.6 "Data structures
/// MUST use std collections where semantically equivalent" — while enforcing
/// all the same limits (22 htable, 40 dtable, 4096 bytes, 65536 value).
///
/// **Dual-role design.**  One struct serves BOTH HTTP/1.x and HTTP/2 HPACK:
/// the distinguishing factor is which method is called (`parse_http1` /
/// `to_buffer_http1` versus `parse_http2` / `to_buffer_http2`).
/// The `htable` is per-message (cleared each message via `reset` /
/// `reset_headers`); the `dtable` is per-connection (persists across
/// message boundaries per RFC 7541).
pub struct HttpHeaders {
    /// Working header table — the current message's headers, insertion-ordered.
    /// Capped at `max_htable` entries (default 22 via [`MAX_HTABLE`]).
    htable: Vec<HeaderEntry>,

    /// HPACK dynamic table — per-connection shared table.
    /// Newest entry is at index 0 (RFC 7541 §2.3.2); oldest at tail.
    dtable: Vec<HeaderEntry>,

    /// HPACK dynamic-table entry count limit (default [`DEFAULT_DLIMIT`]).
    dlimit: u32,

    /// HPACK dynamic-table byte budget per RFC 7541 §4.1 accounting
    /// (default [`DEFAULT_TABLESIZE`]).  Updated by HPACK §6.3 size updates.
    tablesize: u32,

    /// Flag word — the low 2 bits hold the HTTP version
    /// (0 = HTTP/1.0, 1 = HTTP/1.1, 2 = HTTP/2).
    /// Matches FASM `httpheaders_flags_ofs` semantics.
    flags: u64,

    /// Working-header count cap (mirrors FASM's inline-storage limit of 22).
    max_htable: u32,
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION: LIFECYCLE
// ═══════════════════════════════════════════════════════════════════════════

impl HttpHeaders {
    /// Constructs an empty `HttpHeaders` with the default HPACK limits
    /// (40-entry / 4096-byte dynamic table) and the HTTP/1.0 version flag.
    ///
    /// The `flags = 0` initial value follows FASM `httpheaders$new` (L53-88),
    /// which zeroes the flags qword in the `globals` allocation.  Callers
    /// of `parse_http1` will see the version auto-upgraded to
    /// `FLAG_HTTP_1_1` when the request/response line contains `HTTP/1.1`.
    pub fn new() -> Self {
        Self {
            htable: Vec::with_capacity(MAX_HTABLE as usize),
            dtable: Vec::with_capacity(DEFAULT_DLIMIT as usize),
            dlimit: DEFAULT_DLIMIT,
            tablesize: DEFAULT_TABLESIZE,
            flags: FLAG_HTTP_1_0,
            max_htable: MAX_HTABLE,
        }
    }

    /// Clears working headers (`htable`) and resets the HTTP version flag.
    /// Preserves the HPACK dynamic table (`dtable`) — RFC 7541 §4.1
    /// specifies that the dynamic table is a per-connection data structure
    /// that persists across message boundaries.
    /// (FASM `httpheaders$reset` at L114.)
    pub fn reset(&mut self) {
        self.htable.clear();
        self.flags = FLAG_HTTP_1_0;
    }

    /// Clears working headers only, without touching `flags` or `dtable`.
    /// (FASM `httpheaders$reset_headers` at L153; the FASM body is a single
    /// `mov dword [rdi+httpheaders_hcount_ofs], 0` instruction.)
    pub fn reset_headers(&mut self) {
        self.htable.clear();
    }

    /// Full cleanup — clears `htable` AND the HPACK dynamic table.
    /// Used on connection close (FASM `httpheaders$cleanup` at L96 analogue).
    /// Distinct from FASM `httpheaders$destroy` which additionally frees the
    /// heap-allocated scratch buffer and the struct itself; in the Rust
    /// port, `Drop` handles struct-level cleanup automatically.
    pub fn cleanup(&mut self) {
        self.htable.clear();
        self.dtable.clear();
        self.flags = FLAG_HTTP_1_0;
    }

    /// Sets the HTTP version flag (0 = 1.0, 1 = 1.1, 2 = 2).
    /// Only the low 2 bits of `version` are used; other flag bits preserved.
    pub fn set_version(&mut self, version: u64) {
        self.flags = (self.flags & !0b11) | (version & 0b11);
    }

    /// Returns the current HTTP version flag (0, 1, or 2).
    #[inline]
    pub fn version(&self) -> u64 {
        self.flags & 0b11
    }

    /// Returns the number of working-table (`htable`) entries.
    #[inline]
    pub fn hcount(&self) -> usize {
        self.htable.len()
    }

    /// Returns the number of HPACK dynamic-table (`dtable`) entries.
    #[inline]
    pub fn dcount(&self) -> usize {
        self.dtable.len()
    }

    /// Returns the HPACK dynamic-table byte total per RFC 7541 §4.1 accounting.
    /// Equal to the sum of `HeaderEntry::hpack_size()` over all dtable entries.
    pub fn dtable_size(&self) -> usize {
        self.dtable.iter().map(|e| e.hpack_size()).sum()
    }
}

impl Default for HttpHeaders {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION: BYTE-COMPARE HELPERS (FASM strcasecmp / strlowercase equivalents)
// ═══════════════════════════════════════════════════════════════════════════

/// Case-insensitive ASCII byte-slice equality.
///
/// Mirrors FASM `httpheaders$strcasecmp` at L2612 — compares two byte slices
/// for equality treating ASCII letters as case-insensitive.  Non-ASCII bytes
/// compare by exact value.  Returns `false` on length mismatch.
#[inline]
fn bytes_eq_case_insensitive(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(&x, &y)| x.eq_ignore_ascii_case(&y))
}

/// Test whether `name` (case-insensitively) matches the stored name in `entry`.
/// Pointer-identity fast-path when both names are `Cow::Borrowed` with the
/// same address (typical for HPACK static-table hits).
#[inline]
fn name_matches_ci(entry: &HeaderEntry, name: &[u8]) -> bool {
    match &entry.name {
        Cow::Borrowed(stored) => {
            if std::ptr::eq(*stored, name) {
                return true;
            }
            bytes_eq_case_insensitive(stored, name)
        }
        Cow::Owned(stored) => bytes_eq_case_insensitive(stored.as_slice(), name),
    }
}

/// Test whether `entry.name` refers to the same static memory as `name`
/// (pointer identity) OR matches its bytes exactly (case-sensitive fallback).
/// Mirrors FASM `fast_*` accessors which operate on static-pointer equality.
#[inline]
fn name_matches_static(entry: &HeaderEntry, name: &'static [u8]) -> bool {
    match &entry.name {
        Cow::Borrowed(stored) => {
            if std::ptr::eq(*stored, name) {
                return true;
            }
            // `stored: &&'static [u8]` (match ergonomics binds through `&Cow`).
            // Dereferencing once yields `&[u8]` so the comparison uses the
            // unambiguous `PartialEq<&T> for &T` impl in `core`, avoiding the
            // multi-impl ambiguity that arises from `.as_ref()` in the presence
            // of `zerovec`/`bytes` `AsRef` and `PartialEq` impls.
            *stored == name
        }
        Cow::Owned(stored) => stored.as_slice() == name,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION: ACCESSORS (slow_* = case-insensitive; fast_* = pointer identity)
// ═══════════════════════════════════════════════════════════════════════════

impl HttpHeaders {
    /// Case-insensitive single-value lookup — returns the first matching value
    /// or `None`.  (FASM `httpheaders$slow_single_get` at L2725.)
    pub fn slow_single_get(&self, name: &[u8]) -> Option<&[u8]> {
        self.htable
            .iter()
            .find(|e| name_matches_ci(e, name))
            .map(|e| e.value.as_ref())
    }

    /// Static-pointer single-value lookup — intended for use with the header
    /// name constants (`CONTENT_TYPE`, `HOST`, etc.) whose addresses may be
    /// compared via pointer identity for the hot path.
    /// (FASM `httpheaders$fast_single_get` at L2776.)
    pub fn fast_single_get(&self, name: &'static [u8]) -> Option<&[u8]> {
        self.htable
            .iter()
            .find(|e| name_matches_static(e, name))
            .map(|e| e.value.as_ref())
    }

    /// Case-insensitive Nth-occurrence lookup.  `index` is zero-based.
    /// (FASM `httpheaders$slow_get_index` at L2808.)
    pub fn slow_get_index(&self, name: &[u8], index: usize) -> Option<&[u8]> {
        self.htable
            .iter()
            .filter(|e| name_matches_ci(e, name))
            .nth(index)
            .map(|e| e.value.as_ref())
    }

    /// Static-pointer Nth-occurrence lookup.
    /// (FASM `httpheaders$fast_get_index` at L2864.)
    pub fn fast_get_index(&self, name: &'static [u8], index: usize) -> Option<&[u8]> {
        self.htable
            .iter()
            .filter(|e| name_matches_static(e, name))
            .nth(index)
            .map(|e| e.value.as_ref())
    }

    /// Case-insensitive occurrence count.
    /// (FASM `httpheaders$slow_count` at L2911.)
    pub fn slow_count(&self, name: &[u8]) -> usize {
        self.htable.iter().filter(|e| name_matches_ci(e, name)).count()
    }

    /// Static-pointer occurrence count.
    /// (FASM `httpheaders$fast_count` at L2957.)
    pub fn fast_count(&self, name: &'static [u8]) -> usize {
        self.htable
            .iter()
            .filter(|e| name_matches_static(e, name))
            .count()
    }

    /// Iterates over `(name, value)` pairs of the working header table in
    /// insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.htable.iter().map(|e| (e.name.as_ref(), e.value.as_ref()))
    }

    /// Returns `true` if any header matches `name` case-insensitively.
    pub fn contains(&self, name: &[u8]) -> bool {
        self.htable.iter().any(|e| name_matches_ci(e, name))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION: MUTATORS (slow/fast_add, slow/fast_remove)
// ═══════════════════════════════════════════════════════════════════════════

impl HttpHeaders {
    /// Attempts to resolve a raw (possibly mixed-case) header name against the
    /// HPACK static table so we can store the entry with a zero-copy
    /// `Cow::Borrowed` name pointer.  Falls back to a lowercased owned copy
    /// when no static match exists.  Mirrors FASM `slow_add` behavior of
    /// consulting `http1_searchorders` for length-grouped fast dispatch.
    fn resolve_static_name(name: &[u8]) -> Cow<'static, [u8]> {
        let len = name.len();
        if len < HTTP1_SEARCHORDERS_LEN.len() {
            for &idx in HTTP1_SEARCHORDERS[len].iter() {
                let static_name = HPACK_STATIC[idx as usize].0;
                if bytes_eq_case_insensitive(name, static_name) {
                    return Cow::Borrowed(static_name);
                }
            }
        }
        Cow::Owned(name.iter().map(|b| b.to_ascii_lowercase()).collect())
    }

    /// Adds a header using case-insensitive comparison.  If the name matches
    /// an HPACK static-table entry (case-insensitively), the stored name
    /// uses the static pointer (zero-copy); otherwise the name is lowercased
    /// and owned.  The value is always owned.
    ///
    /// Returns `Err(HeaderCountOverflow)` when `htable` is full or
    /// `Err(ValueTooLarge)` when the value exceeds `MAX_VALUE_BYTES`.
    /// (FASM `httpheaders$slow_add` at L2356.)
    pub fn slow_add(&mut self, name: &[u8], value: &[u8]) -> Result<(), HttpHeadersError> {
        if self.htable.len() >= self.max_htable as usize {
            return Err(HttpHeadersError::HeaderCountOverflow);
        }
        if value.len() > MAX_VALUE_BYTES {
            return Err(HttpHeadersError::ValueTooLarge);
        }
        let stored_name = Self::resolve_static_name(name);
        self.htable.push(HeaderEntry {
            name: stored_name,
            value: Cow::Owned(value.to_vec()),
        });
        Ok(())
    }

    /// Adds a header using a statically-borrowed name pointer (zero-copy
    /// name).  The value is always owned.
    /// (FASM `httpheaders$fast_add` at L3114.)
    pub fn fast_add(&mut self, name: &'static [u8], value: &[u8]) -> Result<(), HttpHeadersError> {
        if self.htable.len() >= self.max_htable as usize {
            return Err(HttpHeadersError::HeaderCountOverflow);
        }
        if value.len() > MAX_VALUE_BYTES {
            return Err(HttpHeadersError::ValueTooLarge);
        }
        self.htable.push(HeaderEntry {
            name: Cow::Borrowed(name),
            value: Cow::Owned(value.to_vec()),
        });
        Ok(())
    }

    /// Removes every entry whose name matches `name` case-insensitively.
    /// Returns the number of entries removed.
    /// (FASM `httpheaders$slow_remove` at L2987.)
    pub fn slow_remove(&mut self, name: &[u8]) -> usize {
        let before = self.htable.len();
        self.htable.retain(|e| !name_matches_ci(e, name));
        before - self.htable.len()
    }

    /// Removes every entry whose name matches `name` by pointer identity
    /// (or exact byte match as a fallback).  Returns the number of entries
    /// removed.  (FASM `httpheaders$fast_remove` at L3055.)
    pub fn fast_remove(&mut self, name: &'static [u8]) -> usize {
        let before = self.htable.len();
        self.htable.retain(|e| !name_matches_static(e, name));
        before - self.htable.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION: MIMELIKE COMPATIBILITY HELPERS (Rust wrappers, no FASM analogue)
// ═══════════════════════════════════════════════════════════════════════════

impl HttpHeaders {
    /// Insert-or-replace: removes every existing entry whose name matches
    /// `name` (case-insensitively) then appends a new entry with the given
    /// name and value.  Used by `mimelike::set_header`.
    pub fn insert_replace(&mut self, name: String, value: String) {
        self.slow_remove(name.as_bytes());
        // `slow_add` only fails if the table is full or the value is too
        // large; since we just removed the previous occurrences of this
        // header, space exists unless the caller has an entirely full table
        // of other names.  Errors are swallowed to preserve the simple
        // set-or-overwrite semantics that mimelike expects.
        let _ = self.slow_add(name.as_bytes(), value.as_bytes());
    }

    /// Insert-or-append: if an entry with the given name already exists
    /// (case-insensitively), concatenates `value` onto its value separated
    /// by `sep` (typically `", "`).  Otherwise inserts a new entry.
    /// Used by `mimelike::add_header` with `sep = ", "`.
    pub fn insert_append(&mut self, name: String, value: String, sep: &str) {
        if let Some(idx) = self
            .htable
            .iter()
            .position(|e| name_matches_ci(e, name.as_bytes()))
        {
            let mut new_val: Vec<u8> =
                Vec::with_capacity(self.htable[idx].value.len() + sep.len() + value.len());
            new_val.extend_from_slice(self.htable[idx].value.as_ref());
            new_val.extend_from_slice(sep.as_bytes());
            new_val.extend_from_slice(value.as_bytes());
            self.htable[idx].value = Cow::Owned(new_val);
        } else {
            let _ = self.slow_add(name.as_bytes(), value.as_bytes());
        }
    }

    /// Case-insensitive string-valued getter.  Returns `None` when the
    /// header is absent or its value is not valid UTF-8.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.slow_single_get(name.as_bytes())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
    }

    /// Case-insensitive byte-valued getter — returns the raw header bytes.
    pub fn get_bytes(&self, name: &[u8]) -> Option<&[u8]> {
        self.slow_single_get(name)
    }

    /// Removes and returns the first matching entry's value (as a UTF-8
    /// `String` when valid).  Subsequent duplicate entries with the same
    /// name remain in the table.
    pub fn remove(&mut self, name: &str) -> Option<String> {
        if let Some(idx) = self
            .htable
            .iter()
            .position(|e| name_matches_ci(e, name.as_bytes()))
        {
            let removed = self.htable.remove(idx);
            return String::from_utf8(removed.value.into_owned()).ok();
        }
        None
    }

    /// Iterates over `(name_str, value_str)` pairs in the working header
    /// table.  Entries whose name or value is not valid UTF-8 are skipped.
    pub fn iter_pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.htable.iter().filter_map(|e| {
            let n = std::str::from_utf8(e.name.as_ref()).ok()?;
            let v = std::str::from_utf8(e.value.as_ref()).ok()?;
            Some((n, v))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION: tostring / to_buffer_http1 / parse_http1  (Phase 2l)
// ═══════════════════════════════════════════════════════════════════════════

impl HttpHeaders {
    /// Formats the working header table as a single `"name: value\r\n..."`
    /// concatenation suitable for logging.  Pseudo-headers (whose name begins
    /// with `:`) are included in insertion order so the output mirrors the
    /// order in which the caller added them.  Mirrors the debug-output shape
    /// of FASM `httpheaders$tostring` at L166 — the FASM version internally
    /// runs `tobuffer_http1` then converts to UTF-8; the Rust port emits the
    /// same human-readable debug view directly.
    pub fn tostring(&self) -> String {
        let mut out = String::new();
        for e in &self.htable {
            if let Ok(n) = std::str::from_utf8(e.name.as_ref()) {
                out.push_str(n);
            }
            out.push_str(": ");
            if let Ok(v) = std::str::from_utf8(e.value.as_ref()) {
                out.push_str(v);
            }
            out.push_str("\r\n");
        }
        out
    }

    /// Returns the Australian-English descriptive for a numeric HTTP status
    /// code, matching FASM L207-263.  When the status code does not appear in
    /// the table, returns `STATUS_DESCRIPTIVE_DEFAULT` (`"HeavyThing"`).
    fn status_descriptive(code: u16) -> &'static [u8] {
        for entry in STATUS_DESCRIPTIVES {
            if entry.code == code {
                return entry.text;
            }
        }
        STATUS_DESCRIPTIVE_DEFAULT
    }

    /// Writes a header name to `dest` capitalising only the first byte when
    /// it is lowercase ASCII.  This matches FASM's single `sub byte [rax], 'a' - 'A'`
    /// adjustment — producing `"Content-length"` rather than `"Content-Length"`.
    /// Modern HTTP clients are required to accept header names in any case,
    /// so preserving the FASM convention costs nothing and avoids creating a
    /// gratuitous divergence.
    fn emit_capitalized_name(name: &[u8], dest: &mut Vec<u8>) {
        if let Some(&first) = name.first() {
            if first.is_ascii_lowercase() {
                dest.push(first - (b'a' - b'A'));
            } else {
                dest.push(first);
            }
            dest.extend_from_slice(&name[1..]);
        }
    }

    /// Serialises the working header table into an HTTP/1.x wire-format
    /// buffer, appending to `dest` (`dest` is NOT cleared first).
    ///
    /// Detection rules:
    /// * If the pseudo-header `:method` is present, a request preface of
    ///   `"METHOD PATH HTTP/1.X\r\n"` is emitted (`X` = `0` for HTTP/1.0,
    ///   `1` for HTTP/1.1 — this includes HTTP/2 which downgrades to 1.1).
    /// * Otherwise, if `:status` is present, a response preface of
    ///   `"HTTP/1.X NNN DESCRIPTIVE\r\n"` is emitted.  The descriptive is
    ///   looked up in `STATUS_DESCRIPTIVES` (Australian-English variants) —
    ///   in production the server layer pre-sets a preface via the mimelike
    ///   layer so this fallback is exercised primarily by tests and direct
    ///   callers of `HttpHeaders`.
    /// * Otherwise no preface is emitted — raw headers only.
    ///
    /// Non-pseudo headers are then emitted as `"Name: value\r\n"` lines in
    /// insertion order.  The serialisation is terminated with a final blank
    /// `"\r\n"`.  Mirrors FASM `httpheaders$tobuffer_http1` at L191-450.
    pub fn to_buffer_http1(&self, dest: &mut Vec<u8>) -> Result<(), HttpHeadersError> {
        if self.htable.is_empty() {
            return Ok(());
        }

        let version_byte: u8 = match self.version() {
            FLAG_HTTP_1_0 => b'0',
            _ => b'1',
        };

        let method = self.fast_single_get(PSEUDO_METHOD);
        let path = self.fast_single_get(PSEUDO_PATH);
        if let (Some(method), Some(path)) = (method, path) {
            // Request preface.
            dest.extend_from_slice(method);
            dest.push(b' ');
            dest.extend_from_slice(path);
            dest.extend_from_slice(b" HTTP/1.");
            dest.push(version_byte);
            dest.extend_from_slice(b"\r\n");
        } else if let Some(status) = self.fast_single_get(PSEUDO_STATUS) {
            // Response preface.
            dest.extend_from_slice(b"HTTP/1.");
            dest.push(version_byte);
            dest.push(b' ');
            dest.extend_from_slice(status);
            dest.push(b' ');
            let status_code: u16 = if status.len() == 3 && status.iter().all(|b| b.is_ascii_digit()) {
                let s0 = (status[0] - b'0') as u16;
                let s1 = (status[1] - b'0') as u16;
                let s2 = (status[2] - b'0') as u16;
                s0 * 100 + s1 * 10 + s2
            } else {
                0
            };
            dest.extend_from_slice(Self::status_descriptive(status_code));
            dest.extend_from_slice(b"\r\n");
        }

        // Emit non-pseudo headers as "Name: value\r\n".
        for entry in &self.htable {
            // Skip pseudo-headers (those whose name begins with ':').
            if entry.name.first() == Some(&b':') {
                continue;
            }
            Self::emit_capitalized_name(&entry.name, dest);
            dest.extend_from_slice(b": ");
            dest.extend_from_slice(&entry.value);
            dest.extend_from_slice(b"\r\n");
        }

        // Final blank line terminator.
        dest.extend_from_slice(b"\r\n");

        Ok(())
    }

    /// Scans `data` for an end-of-headers marker.  Returns
    /// `Some((offset_to_marker, marker_length))` where `marker_length` is `4`
    /// for `"\r\n\r\n"` or `2` for `"\n\n"`, or `None` if no terminator is
    /// present.
    fn find_end_of_headers(data: &[u8]) -> Option<(usize, usize)> {
        let mut i = 0;
        while i + 1 < data.len() {
            if i + 3 < data.len() && &data[i..i + 4] == b"\r\n\r\n" {
                return Some((i, 4));
            }
            if &data[i..i + 2] == b"\n\n" {
                return Some((i, 2));
            }
            i += 1;
        }
        None
    }

    /// Scans `data` for a CRLF or bare LF line terminator.  Returns
    /// `Some((line_length, terminator_length))` — `terminator_length` is `2`
    /// for CRLF, `1` for bare LF.  Returns `None` if neither is found.
    fn find_line_terminator(data: &[u8]) -> Option<(usize, usize)> {
        let mut i = 0;
        while i < data.len() {
            if i + 1 < data.len() && data[i] == b'\r' && data[i + 1] == b'\n' {
                return Some((i, 2));
            }
            if data[i] == b'\n' {
                return Some((i, 1));
            }
            i += 1;
        }
        None
    }

    /// Parses the request line (`"METHOD PATH HTTP/1.X"`) for a known method.
    /// Inserts the `:method` and `:path` pseudo-headers via `fast_add` and
    /// sets the HTTP version flag.
    fn parse_request_line(&mut self, line: &[u8], method: &'static [u8]) -> Result<(), HttpHeadersError> {
        if line.len() <= method.len() || line[method.len()] != b' ' {
            return Err(HttpHeadersError::MalformedMethod);
        }
        let mut pos = method.len() + 1;
        let path_start = pos;
        while pos < line.len() && line[pos] != b' ' {
            pos += 1;
        }
        if pos == path_start || pos >= line.len() {
            return Err(HttpHeadersError::MalformedMethod);
        }
        let path = &line[path_start..pos];
        if path[0] != b'/' && path[0] != b'*' {
            return Err(HttpHeadersError::MalformedMethod);
        }
        pos += 1;
        if pos + 8 > line.len() || &line[pos..pos + 7] != b"HTTP/1." {
            return Err(HttpHeadersError::MalformedMethod);
        }
        let minor = line[pos + 7];
        match minor {
            b'1' => self.set_version(FLAG_HTTP_1_1),
            b'0' => self.set_version(FLAG_HTTP_1_0),
            _ => return Err(HttpHeadersError::MalformedMethod),
        }
        // Use `fast_add` with static pseudo-header name pointers; path is
        // copied because it came out of the caller's buffer.
        self.fast_add(PSEUDO_METHOD, method)?;
        // For well-known paths, share the HPACK static-table pointer.
        let path_cow: Cow<'static, [u8]> = match path {
            b"/" => Cow::Borrowed(DEFAULT_PATH_ROOT),
            b"/index.html" => Cow::Borrowed(DEFAULT_PATH_INDEX_HTML),
            _ => Cow::Owned(path.to_vec()),
        };
        if self.htable.len() >= self.max_htable as usize {
            return Err(HttpHeadersError::HeaderCountOverflow);
        }
        self.htable.push(HeaderEntry {
            name: Cow::Borrowed(PSEUDO_PATH),
            value: path_cow,
        });
        Ok(())
    }

    /// Parses the response line (`"HTTP/1.X NNN DESCRIPTIVE"`) into a
    /// `:status` pseudo-header and sets the HTTP version flag.
    fn parse_response_line(&mut self, line: &[u8]) -> Result<(), HttpHeadersError> {
        if line.len() < 12 || !line.starts_with(b"HTTP/1.") {
            return Err(HttpHeadersError::MalformedStatus);
        }
        let minor = line[7];
        match minor {
            b'1' => self.set_version(FLAG_HTTP_1_1),
            b'0' => self.set_version(FLAG_HTTP_1_0),
            _ => return Err(HttpHeadersError::MalformedStatus),
        }
        if line[8] != b' ' {
            return Err(HttpHeadersError::MalformedStatus);
        }
        let status_bytes = &line[9..12];
        if !status_bytes.iter().all(|b| b.is_ascii_digit()) {
            return Err(HttpHeadersError::MalformedStatus);
        }
        // Fast path: for well-known status codes, share the HPACK static
        // table's default-value pointer — zero-copy.
        let value: Cow<'static, [u8]> = match status_bytes {
            b"200" => Cow::Borrowed(DEFAULT_STATUS_200),
            b"204" => Cow::Borrowed(DEFAULT_STATUS_204),
            b"206" => Cow::Borrowed(DEFAULT_STATUS_206),
            b"304" => Cow::Borrowed(DEFAULT_STATUS_304),
            b"400" => Cow::Borrowed(DEFAULT_STATUS_400),
            b"404" => Cow::Borrowed(DEFAULT_STATUS_404),
            b"500" => Cow::Borrowed(DEFAULT_STATUS_500),
            _ => Cow::Owned(status_bytes.to_vec()),
        };
        if self.htable.len() >= self.max_htable as usize {
            return Err(HttpHeadersError::HeaderCountOverflow);
        }
        self.htable.push(HeaderEntry {
            name: Cow::Borrowed(PSEUDO_STATUS),
            value,
        });
        Ok(())
    }

    /// Parses an HTTP/1.x request or response from a byte buffer.
    ///
    /// Returns:
    /// * `Ok(0)` — incomplete; need more bytes (no end-of-headers marker
    ///   present yet, or the buffer is shorter than 16 bytes).
    /// * `Ok(n)` — `n` bytes consumed up to and including the blank line
    ///   that terminates the header block.
    /// * `Err(...)` — malformed request/response or resource-limit violation.
    ///
    /// Size gates:
    /// * `data.len() > MAX_MESSAGE_SIZE` (2<sup>30</sup> bytes) → `TooLarge`.
    /// * `data.len() < 16` → `Ok(0)` (too short to contain any complete
    ///   request line).
    ///
    /// Mirrors FASM `httpheaders$parse_http1` at L1843-2345.
    pub fn parse_http1(&mut self, data: &[u8]) -> Result<usize, HttpHeadersError> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(HttpHeadersError::TooLarge);
        }
        if data.len() < 16 {
            return Ok(0);
        }

        // Locate end-of-headers first — if not found, signal need-more.
        let (eoh_pos, eoh_len) = match Self::find_end_of_headers(data) {
            Some(pair) => pair,
            None => return Ok(0),
        };

        // Dispatch on first-line content (everything up to the first CRLF).
        let first_line_end = {
            let mut end = eoh_pos;
            let mut i = 0;
            while i < eoh_pos {
                if i + 1 < eoh_pos && data[i] == b'\r' && data[i + 1] == b'\n' {
                    end = i;
                    break;
                }
                if data[i] == b'\n' {
                    end = i;
                    break;
                }
                i += 1;
            }
            end
        };
        let first_line = &data[..first_line_end];

        if first_line.len() < 4 {
            return Err(HttpHeadersError::Http1Parse);
        }

        // Method dispatch.  The FASM implementation dispatches on the first
        // 4 bytes treated as a dword; the Rust port does pattern matches on
        // byte slices which compiles to equivalent comparisons.
        if first_line.starts_with(b"GET ") {
            self.parse_request_line(first_line, b"GET")?;
        } else if first_line.starts_with(b"HEAD ") {
            self.parse_request_line(first_line, b"HEAD")?;
        } else if first_line.starts_with(b"POST ") {
            self.parse_request_line(first_line, b"POST")?;
        } else if first_line.starts_with(b"PUT ") {
            self.parse_request_line(first_line, b"PUT")?;
        } else if first_line.starts_with(b"DELETE ") {
            self.parse_request_line(first_line, b"DELETE")?;
        } else if first_line.starts_with(b"OPTIONS ") {
            self.parse_request_line(first_line, b"OPTIONS")?;
        } else if first_line.starts_with(b"TRACE ") {
            self.parse_request_line(first_line, b"TRACE")?;
        } else if first_line.starts_with(b"CONNECT ") {
            self.parse_request_line(first_line, b"CONNECT")?;
        } else if first_line.starts_with(b"HTTP") {
            self.parse_response_line(first_line)?;
        } else {
            return Err(HttpHeadersError::MalformedMethod);
        }

        // Advance past the first line's terminator.
        let mut pos = first_line_end;
        if pos + 2 <= data.len() && &data[pos..pos + 2] == b"\r\n" {
            pos += 2;
        } else if pos < data.len() && data[pos] == b'\n' {
            pos += 1;
        }

        // Parse header lines until we reach the blank end-of-headers line.
        //
        // `find_line_terminator` only scans the slice `data[pos..eoh_pos]`,
        // which EXCLUDES the CRLF (or LF) bytes that sit at `eoh_pos` itself.
        // When the last header's terminator coincides with the eoh marker
        // (e.g., "Host: x\r\n\r\n" — the first `\r\n` IS at `eoh_pos`), the
        // slice would end without a terminator.  Per the agent_prompt Phase 17
        // reference, fall back to `(slice.len(), 0)` so the remainder is
        // treated as a complete header line with a zero-length implicit
        // terminator.  This guarantees every header between `first_line_end`
        // and `eoh_pos` is parsed.
        while pos < eoh_pos {
            let slice = &data[pos..eoh_pos];
            let (len, skip) = Self::find_line_terminator(slice).unwrap_or((slice.len(), 0));
            if len == 0 {
                // Empty line — end of headers reached early.
                // We do NOT update `pos` here because `pos` is not read after
                // this point (we break out of the loop and the function
                // returns `Ok(eoh_pos + eoh_len)`).  Assigning `pos += skip`
                // would trigger an unused-assignment warning under
                // `-D warnings`.
                break;
            }
            let line = &slice[..len];
            let colon = match line.iter().position(|&b| b == b':') {
                Some(c) => c,
                None => return Err(HttpHeadersError::Http1Parse),
            };
            let name = &line[..colon];
            if name.is_empty() {
                return Err(HttpHeadersError::Http1Parse);
            }
            let mut vstart = colon + 1;
            while vstart < line.len() && (line[vstart] == b' ' || line[vstart] == b'\t') {
                vstart += 1;
            }
            // Strip trailing whitespace (spaces, tabs, stray CR) per RFC 7230.
            let mut vend = line.len();
            while vend > vstart {
                let last = line[vend - 1];
                if last == b' ' || last == b'\t' || last == b'\r' {
                    vend -= 1;
                } else {
                    break;
                }
            }
            let value = &line[vstart..vend];
            self.slow_add(name, value)?;
            pos += len + skip;
        }

        Ok(eoh_pos + eoh_len)
    }
}

// =====================================================================
// Phase 2m — HPACK (HTTP/2) encoder: tobuffer_http2 + helpers
// Reference: RFC 7541 §6; FASM `httpheaders$tobuffer_http2` at L455-1200.
// =====================================================================

impl HttpHeaders {
    /// Serialises the working header table using HPACK (RFC 7541).  Appends
    /// encoded bytes to `dest`.
    ///
    /// Per-entry encoding dispatch (5 cases):
    /// 1. Name + value present in static table → §6.1 indexed.
    /// 2. Name + value present in dynamic table → §6.1 indexed (idx = 62 + didx).
    /// 3. Name in static table, new value → §6.2.1 literal w/ incremental
    ///    indexing (add to dtable), or §6.2.2 literal w/o indexing for
    ///    never-indexed headers.
    /// 4. Name in dynamic table, new value → same as Case 3 with idx = 62 + didx.
    /// 5. New name AND new value → literal with new name.
    ///
    /// (FASM: `httpheaders$tobuffer_http2` at L455-1200.)
    pub fn to_buffer_http2(&mut self, dest: &mut Vec<u8>) -> Result<(), HttpHeadersError> {
        // Clone htable for iteration because emit_header_http2 mutates dtable.
        let entries: Vec<HeaderEntry> = self.htable.clone();
        for entry in entries.iter() {
            self.emit_header_http2(entry, dest)?;
        }
        Ok(())
    }

    /// Returns true if the header name is in the HPACK never-indexed list.
    /// These 8 headers change frequently and are emitted via §6.2.2 to keep
    /// the dynamic table focused on stable entries.
    ///
    /// Per FASM L474 never-indexed set:
    /// `date, content-length, etag, last-modified, if-none-match,
    /// if-modified-since, content-range, range`.
    fn is_never_indexed(name: &[u8]) -> bool {
        matches!(
            name,
            b"date"
                | b"content-length"
                | b"etag"
                | b"last-modified"
                | b"if-none-match"
                | b"if-modified-since"
                | b"content-range"
                | b"range"
        )
    }

    /// Dispatches a single header entry to §6.1 / §6.2.1 / §6.2.2 per the
    /// 5-case rules above.
    fn emit_header_http2(&mut self, entry: &HeaderEntry, dest: &mut Vec<u8>) -> Result<(), HttpHeadersError> {
        let name = entry.name.as_ref();
        let value = entry.value.as_ref();

        // Case 1: name+value both in static table.
        if let Some(idx) = Self::find_static_exact(name, value) {
            Self::write_indexed(idx as u32, dest);
            return Ok(());
        }

        // Case 2: name+value both in dynamic table.
        if let Some(didx) = self.find_dtable_exact(name, value) {
            Self::write_indexed((62 + didx) as u32, dest);
            return Ok(());
        }

        let never_indexed = Self::is_never_indexed(name);
        let static_name = Self::find_static_name(name);
        let dtable_name = self.find_dtable_name(name);

        if let Some(idx) = static_name {
            // Case 3: name in static table, new value.
            if never_indexed {
                Self::write_literal_noindex_indexed_name(idx as u32, value, dest);
            } else {
                Self::write_literal_indexed_name(idx as u32, value, dest);
                self.dtable_insert(entry.clone());
            }
        } else if let Some(didx) = dtable_name {
            // Case 4: name in dynamic table, new value.
            let idx = (62 + didx) as u32;
            if never_indexed {
                Self::write_literal_noindex_indexed_name(idx, value, dest);
            } else {
                Self::write_literal_indexed_name(idx, value, dest);
                self.dtable_insert(entry.clone());
            }
        } else {
            // Case 5: new name AND new value.
            if never_indexed {
                Self::write_literal_noindex_new_name(name, value, dest);
            } else {
                Self::write_literal_new_name(name, value, dest);
                self.dtable_insert(entry.clone());
            }
        }

        Ok(())
    }

    /// Returns 1-based index into `HPACK_STATIC` where BOTH name and value match.
    /// Indices 1..=60 only (index 0 is a FASM extension, not valid HPACK).
    fn find_static_exact(name: &[u8], value: &[u8]) -> Option<usize> {
        for (idx, (n, v)) in HPACK_STATIC.iter().enumerate().skip(1) {
            if *n == name && *v == value {
                return Some(idx);
            }
        }
        None
    }

    /// Returns 1-based index into `HPACK_STATIC` where name matches.
    /// Skips index 0 (FASM extension).
    fn find_static_name(name: &[u8]) -> Option<usize> {
        for (idx, (n, _v)) in HPACK_STATIC.iter().enumerate().skip(1) {
            if *n == name {
                return Some(idx);
            }
        }
        None
    }

    /// Returns 0-based dtable index where BOTH name and value match.
    fn find_dtable_exact(&self, name: &[u8], value: &[u8]) -> Option<usize> {
        self.dtable
            .iter()
            .position(|e| e.name.as_ref() == name && e.value.as_ref() == value)
    }

    /// Returns 0-based dtable index where name matches.
    fn find_dtable_name(&self, name: &[u8]) -> Option<usize> {
        self.dtable.iter().position(|e| e.name.as_ref() == name)
    }

    /// Inserts `entry` at the HEAD of the dynamic table (index 0), evicting
    /// tail entries to maintain RFC 7541 §4.1 size and entry-count limits.
    /// (FASM: `hpack_dtable_ceiling` macro.)
    fn dtable_insert(&mut self, entry: HeaderEntry) {
        let new_size = entry.hpack_size();
        if new_size > self.tablesize as usize {
            // RFC 7541 §4.4: entry too large; clear entire dtable and bail.
            self.dtable.clear();
            return;
        }
        while self.dtable_size() + new_size > self.tablesize as usize {
            if self.dtable.pop().is_none() {
                break;
            }
        }
        while self.dtable.len() >= self.dlimit as usize {
            if self.dtable.pop().is_none() {
                break;
            }
        }
        self.dtable.insert(0, entry);
    }

    /// Writes an HPACK indexed header field (§6.1): 0x80 high-bit plus a
    /// 7-bit-prefix integer.
    fn write_indexed(idx: u32, dest: &mut Vec<u8>) {
        Self::write_integer(idx, 7, 0x80, dest);
    }

    /// Writes §6.2.1 literal header field with incremental indexing, indexed
    /// name: 0x40 high-bits plus 6-bit-prefix index, then value string.
    fn write_literal_indexed_name(idx: u32, value: &[u8], dest: &mut Vec<u8>) {
        Self::write_integer(idx, 6, 0x40, dest);
        Self::write_string(value, dest);
    }

    /// Writes §6.2.2 literal header field without indexing, indexed name:
    /// 0x00 high-bits plus 4-bit-prefix index, then value string.
    fn write_literal_noindex_indexed_name(idx: u32, value: &[u8], dest: &mut Vec<u8>) {
        Self::write_integer(idx, 4, 0x00, dest);
        Self::write_string(value, dest);
    }

    /// Writes §6.2.1 literal with incremental indexing, new name: 0x40
    /// opcode byte, then name string, then value string.
    fn write_literal_new_name(name: &[u8], value: &[u8], dest: &mut Vec<u8>) {
        dest.push(0x40);
        Self::write_string(name, dest);
        Self::write_string(value, dest);
    }

    /// Writes §6.2.2 literal without indexing, new name: 0x00 opcode byte,
    /// then name string, then value string.
    fn write_literal_noindex_new_name(name: &[u8], value: &[u8], dest: &mut Vec<u8>) {
        dest.push(0x00);
        Self::write_string(name, dest);
        Self::write_string(value, dest);
    }

    /// Writes an HPACK variable-length integer per RFC 7541 §5.1.
    /// `prefix_bits` = bits available in the low part of the first byte.
    /// `high_bits` = opcode bits OR'd into the high bits of the first byte.
    /// (FASM: `hpack_write_integer` macro.)
    fn write_integer(mut value: u32, prefix_bits: u8, high_bits: u8, dest: &mut Vec<u8>) {
        let max = (1u32 << prefix_bits) - 1;
        if value < max {
            dest.push(high_bits | (value as u8));
            return;
        }
        dest.push(high_bits | (max as u8));
        value -= max;
        while value >= 128 {
            dest.push(((value % 128) | 0x80) as u8);
            value /= 128;
        }
        dest.push(value as u8);
    }

    /// Writes an HPACK string literal: 1-bit Huffman flag plus 7-bit-prefix
    /// length plus payload bytes.  Chooses Huffman encoding when it produces
    /// strictly fewer bytes than raw; otherwise emits raw.
    ///
    /// (FASM: `.writestorestring` helper inside `tobuffer_http2`.)
    fn write_string(bytes: &[u8], dest: &mut Vec<u8>) {
        // Prescan Huffman output length using HUFFY_L.
        let total_bits: u64 = bytes.iter().map(|&b| HUFFY_L[b as usize] as u64).sum();
        let total_bytes = total_bits.div_ceil(8) as u32;

        if (total_bytes as usize) < bytes.len() {
            // Huffman wins — emit H=1 prefix plus encoded payload.
            Self::write_integer(total_bytes, 7, 0x80, dest);
            Self::huffy_encode(bytes, dest);
        } else {
            // Raw is same size or shorter — emit H=0 prefix plus raw bytes.
            Self::write_integer(bytes.len() as u32, 7, 0x00, dest);
            dest.extend_from_slice(bytes);
        }
    }

    /// Huffman-encodes `bytes` using HUFFY_C + HUFFY_L tables, appending the
    /// encoded octets to `dest`.  The trailing partial byte (if any) is padded
    /// with EOS 1-bits per RFC 7541 §5.2.
    ///
    /// Strategy: accumulate bits in a 64-bit register (MSB-first), draining
    /// complete octets to the output buffer as they fill.
    ///
    /// Invariant: `acc_bits < 8` at the top of each iteration (the inner
    /// drain loop ensures this after each code is added).
    fn huffy_encode(bytes: &[u8], dest: &mut Vec<u8>) {
        let mut acc: u64 = 0;
        let mut acc_bits: u32 = 0;
        for &b in bytes {
            let code = HUFFY_C[b as usize] as u64; // bits 31..(32-L) contain the code
            let length = HUFFY_L[b as usize] as u32;
            // Position the code so its MSB (bit 31 of the u32) lands at bit
            // (63 - acc_bits) of acc.  That requires shift = 32 - acc_bits.
            acc |= code << (32 - acc_bits);
            acc_bits += length;
            while acc_bits >= 8 {
                let byte = ((acc >> 56) & 0xff) as u8;
                dest.push(byte);
                acc <<= 8;
                acc_bits -= 8;
            }
        }
        if acc_bits > 0 {
            // Pad the trailing partial byte with low 1-bits per §5.2 (EOS).
            let pad_bits = 8 - acc_bits;
            let pad_mask: u8 = (1u8 << pad_bits) - 1;
            let byte = ((acc >> 56) as u8) | pad_mask;
            dest.push(byte);
        }
    }
}

// =====================================================================
// Phase 2n — HPACK (HTTP/2) decoder: parse_http2 + helpers
// Reference: RFC 7541 §6; FASM `httpheaders$parse_http2` at L1203-1832.
// =====================================================================

impl HttpHeaders {
    /// Decodes an HPACK header block into `self.htable` per RFC 7541 §6.
    ///
    /// First-byte dispatch:
    /// - bit 7 set (1xxxxxxx)            → §6.1 Indexed.
    /// - bits 7,6 = 01 (01xxxxxx)        → §6.2.1 Literal w/ incremental indexing.
    /// - bits 7,6,5 = 001 (001xxxxx)     → §6.3 Dynamic Table Size Update.
    /// - bits 7..4 = 0000 / 0001          → §6.2.2 Literal w/o indexing OR §6.2.3
    ///   Literal never-indexed (both 4-bit prefix).
    ///
    /// (FASM: `httpheaders$parse_http2` at L1203-1832.)
    pub fn parse_http2(&mut self, data: &[u8]) -> Result<(), HttpHeadersError> {
        let mut cursor = data;
        while !cursor.is_empty() {
            if self.htable.len() >= MAX_HTABLE as usize {
                return Err(HttpHeadersError::HeaderCountOverflow);
            }
            let first = cursor[0];
            if first & 0x80 != 0 {
                // §6.1 Indexed.
                let (idx, advanced) = Self::read_integer(cursor, 7)?;
                cursor = &cursor[advanced..];
                if idx == 0 {
                    return Err(HttpHeadersError::HpackDecode);
                }
                self.emit_indexed(idx as usize)?;
            } else if first & 0x40 != 0 {
                // §6.2.1 Literal with Incremental Indexing.
                if first == 0x40 {
                    // New name.
                    cursor = &cursor[1..];
                    let (name, n_adv) = Self::read_string(cursor)?;
                    cursor = &cursor[n_adv..];
                    let (value, v_adv) = Self::read_string(cursor)?;
                    cursor = &cursor[v_adv..];
                    self.emit_literal(name, value, true)?;
                } else {
                    // Indexed name.
                    let (idx, advanced) = Self::read_integer(cursor, 6)?;
                    cursor = &cursor[advanced..];
                    if idx == 0 {
                        return Err(HttpHeadersError::HpackDecode);
                    }
                    let (value, v_adv) = Self::read_string(cursor)?;
                    cursor = &cursor[v_adv..];
                    let name = self.lookup_name_bytes(idx as usize)?;
                    self.emit_literal(name, value, true)?;
                }
            } else if first & 0x20 != 0 {
                // §6.3 Dynamic Table Size Update.
                let (new_size, advanced) = Self::read_integer(cursor, 5)?;
                cursor = &cursor[advanced..];
                if new_size > 65536 {
                    return Err(HttpHeadersError::HpackTableSizeOutOfRange);
                }
                self.tablesize = new_size;
                self.enforce_dtable_ceiling();
            } else {
                // §6.2.2 Literal without Indexing (0x00..0x0F)
                // OR §6.2.3 Literal Never Indexed (0x10..0x1F).
                // Both use the same 4-bit prefix and do NOT add to dtable; the
                // semantic distinction is a hint for intermediaries.
                let low_nibble = first & 0x0F;
                if low_nibble == 0 {
                    // New name (opcode 0x00 or 0x10 exactly).
                    cursor = &cursor[1..];
                    let (name, n_adv) = Self::read_string(cursor)?;
                    cursor = &cursor[n_adv..];
                    let (value, v_adv) = Self::read_string(cursor)?;
                    cursor = &cursor[v_adv..];
                    self.emit_literal(name, value, false)?;
                } else {
                    // Indexed name (0x01..0x0F or 0x11..0x1F).
                    let (idx, advanced) = Self::read_integer(cursor, 4)?;
                    cursor = &cursor[advanced..];
                    if idx == 0 {
                        return Err(HttpHeadersError::HpackDecode);
                    }
                    let (value, v_adv) = Self::read_string(cursor)?;
                    cursor = &cursor[v_adv..];
                    let name = self.lookup_name_bytes(idx as usize)?;
                    self.emit_literal(name, value, false)?;
                }
            }
        }
        Ok(())
    }

    /// Emits an HPACK-indexed entry (§6.1): copies (name, value) from the
    /// static or dynamic table into htable.
    fn emit_indexed(&mut self, idx: usize) -> Result<(), HttpHeadersError> {
        if self.htable.len() >= MAX_HTABLE as usize {
            return Err(HttpHeadersError::HeaderCountOverflow);
        }
        if (HPACK_STATIC_MIN_INDEX..=HPACK_STATIC_MAX_INDEX).contains(&idx) {
            let (n, v) = HPACK_STATIC[idx];
            self.htable.push(HeaderEntry::from_static(n, v));
            Ok(())
        } else if idx >= 62 {
            let didx = idx - 62;
            if didx >= self.dtable.len() {
                return Err(HttpHeadersError::HpackDecode);
            }
            let entry = self.dtable[didx].clone();
            self.htable.push(entry);
            Ok(())
        } else {
            // idx == 0 is rejected by caller; idx == 61 is unused in FASM table;
            // any other invalid value lands here.
            Err(HttpHeadersError::HpackDecode)
        }
    }

    /// Emits a literal (name, value) into htable; if `indexing` is true,
    /// also prepends into the dynamic table with size-ceiling enforcement.
    fn emit_literal(
        &mut self,
        name: Vec<u8>,
        value: Vec<u8>,
        indexing: bool,
    ) -> Result<(), HttpHeadersError> {
        if self.htable.len() >= MAX_HTABLE as usize {
            return Err(HttpHeadersError::HeaderCountOverflow);
        }
        let entry = HeaderEntry::from_owned(name, value);
        self.htable.push(entry.clone());
        if indexing {
            self.dtable_insert(entry);
        }
        Ok(())
    }

    /// Returns an owned copy of the name stored at HPACK index `idx`.
    /// Indices 1..=60 resolve to static table entries; 62+ resolve to
    /// dynamic table entries (0-based `idx - 62`).
    fn lookup_name_bytes(&self, idx: usize) -> Result<Vec<u8>, HttpHeadersError> {
        if (HPACK_STATIC_MIN_INDEX..=HPACK_STATIC_MAX_INDEX).contains(&idx) {
            Ok(HPACK_STATIC[idx].0.to_vec())
        } else if idx >= 62 {
            let didx = idx - 62;
            if didx >= self.dtable.len() {
                return Err(HttpHeadersError::HpackDecode);
            }
            Ok(self.dtable[didx].name.as_ref().to_vec())
        } else {
            Err(HttpHeadersError::HpackDecode)
        }
    }

    /// Reads an HPACK variable-length integer per RFC 7541 §5.1.
    /// Returns (decoded value, number of bytes consumed).
    /// Bounds the decoded value at u32::MAX; further continuation bytes are
    /// treated as a protocol error.
    ///
    /// (FASM: `hpack_read_integer` macro.)
    fn read_integer(data: &[u8], prefix_bits: u8) -> Result<(u32, usize), HttpHeadersError> {
        if data.is_empty() {
            return Err(HttpHeadersError::HpackDecode);
        }
        let mask = (1u32 << prefix_bits) - 1;
        let first = (data[0] as u32) & mask;
        if first < mask {
            return Ok((first, 1));
        }
        let mut value: u64 = first as u64;
        let mut shift: u32 = 0;
        let mut i: usize = 1;
        loop {
            if i >= data.len() || shift >= 64 {
                return Err(HttpHeadersError::HpackDecode);
            }
            let b = data[i];
            let chunk = (b & 0x7f) as u64;
            let shifted = chunk << shift;
            value = value.checked_add(shifted).ok_or(HttpHeadersError::HpackDecode)?;
            i += 1;
            if b & 0x80 == 0 {
                if value > u32::MAX as u64 {
                    return Err(HttpHeadersError::HpackDecode);
                }
                return Ok((value as u32, i));
            }
            shift += 7;
        }
    }

    /// Reads an HPACK string literal: 1-bit Huffman flag, 7-bit-prefix length,
    /// and the payload.  Returns (decoded bytes, bytes consumed from `data`).
    ///
    /// (FASM: `.readstorestring` helper inside `parse_http2`.)
    fn read_string(data: &[u8]) -> Result<(Vec<u8>, usize), HttpHeadersError> {
        if data.is_empty() {
            return Err(HttpHeadersError::HpackDecode);
        }
        let huffman = data[0] & 0x80 != 0;
        let (len, len_advanced) = Self::read_integer(data, 7)?;
        let len = len as usize;
        if len > MAX_VALUE_BYTES {
            return Err(HttpHeadersError::ValueTooLarge);
        }
        let payload_start = len_advanced;
        let payload_end = payload_start
            .checked_add(len)
            .ok_or(HttpHeadersError::HpackDecode)?;
        if payload_end > data.len() {
            return Err(HttpHeadersError::HpackDecode);
        }
        let payload = &data[payload_start..payload_end];
        let decoded = if huffman {
            Self::huffy_decode(payload)?
        } else {
            payload.to_vec()
        };
        Ok((decoded, payload_end))
    }

    /// Huffman-decodes `data` per RFC 7541 Appendix B using the HUFFY_C +
    /// HUFFY_L tables directly.  Handles up-to-7-bit trailing EOS padding
    /// (all 1-bits) per §5.2.
    ///
    /// Algorithm: maintain a 64-bit accumulator with up to 56 bits of pending
    /// input bits.  For each output byte, linearly search for the unique
    /// Huffman code (codes are prefix-free) whose bit pattern matches the
    /// current top of the accumulator.
    ///
    /// Complexity: O(output_len × 256).  Preserves byte-identical decoder
    /// behaviour to FASM's 4-iteration unrolled HUFFY_T tree walk while
    /// staying simple enough to audit.
    ///
    /// (FASM: `huffy_decode` macro.)
    fn huffy_decode(data: &[u8]) -> Result<Vec<u8>, HttpHeadersError> {
        let mut out: Vec<u8> = Vec::with_capacity(data.len() * 2);
        let mut acc: u64 = 0;
        let mut acc_bits: u32 = 0;
        let mut pos: usize = 0;
        loop {
            // Refill accumulator while there's room for another byte (56-bit
            // slack leaves 8 bits headroom to absorb one more octet).
            while acc_bits <= 56 && pos < data.len() {
                acc |= (data[pos] as u64) << (56 - acc_bits);
                acc_bits += 8;
                pos += 1;
            }
            if acc_bits == 0 {
                break;
            }
            let acc_top = (acc >> 32) as u32;
            let mut matched = false;
            for byte_val in 0u32..=255 {
                let code_bits = HUFFY_L[byte_val as usize] as u32;
                if code_bits == 0 || code_bits > acc_bits {
                    continue;
                }
                let mask: u32 = if code_bits >= 32 {
                    u32::MAX
                } else {
                    !((1u32 << (32 - code_bits)) - 1)
                };
                let code = HUFFY_C[byte_val as usize];
                if (acc_top & mask) == (code & mask) {
                    out.push(byte_val as u8);
                    acc <<= code_bits;
                    acc_bits -= code_bits;
                    if out.len() > MAX_VALUE_BYTES {
                        return Err(HttpHeadersError::ValueTooLarge);
                    }
                    matched = true;
                    break;
                }
            }
            if !matched {
                // Valid end-of-stream: <8 bits remaining, all ones (EOS padding).
                if acc_bits < 8 {
                    let pad_mask: u64 = ((1u64 << acc_bits) - 1) << (64 - acc_bits);
                    if (acc & pad_mask) == pad_mask {
                        break;
                    }
                }
                return Err(HttpHeadersError::HpackDecode);
            }
        }
        Ok(out)
    }

    /// Enforces the dynamic-table size ceiling by evicting oldest (tail)
    /// entries until `dtable_size() <= tablesize`.  Used after a §6.3 size
    /// update reduces the table budget.
    /// (FASM: `hpack_dtable_ceiling` invoked with 0.)
    fn enforce_dtable_ceiling(&mut self) {
        while self.dtable_size() > self.tablesize as usize {
            if self.dtable.pop().is_none() {
                break;
            }
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================
//
// These tests exercise the full public + private API surface of the headers
// module.  They are grouped by concern:
//   * Constants & static tables
//   * HeaderEntry + HttpHeaders lifecycle
//   * Accessors (slow/fast variants)
//   * Mutators + mimelike compatibility helpers
//   * HTTP/1.x parse & compose (parse_http1, to_buffer_http1)
//   * HPACK primitives (integer, Huffman, write/read_string)
//   * HPACK encode/decode roundtrips
//   * Error conversion (HttpHeadersError -> HttpError)
//
// Private functions are accessible because the `tests` module is nested inside
// the `headers` module and uses `use super::*;`.  Functions on the impl
// `HttpHeaders` block that are private remain accessible via
// `HttpHeaders::fn_name(...)` syntax.

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // CONSTANTS & STATIC-TABLE INVARIANTS
    // ------------------------------------------------------------------------

    #[test]
    fn test_hpack_static_length_is_61() {
        assert_eq!(HPACK_STATIC.len(), 61);
    }

    #[test]
    fn test_hpack_static_index_0_is_fasm_connection_extension() {
        // FASM addition: index 0 is `connection` with empty value (NOT RFC 7541).
        assert_eq!(HPACK_STATIC[0].0, CONNECTION);
        assert_eq!(HPACK_STATIC[0].1, DEFAULT_EMPTY);
    }

    #[test]
    fn test_hpack_static_index_1_is_authority() {
        assert_eq!(HPACK_STATIC[1].0, PSEUDO_AUTHORITY);
        assert_eq!(HPACK_STATIC[1].1, DEFAULT_EMPTY);
    }

    #[test]
    fn test_hpack_static_index_2_is_method_get() {
        assert_eq!(HPACK_STATIC[2].0, PSEUDO_METHOD);
        assert_eq!(HPACK_STATIC[2].1, b"GET");
    }

    #[test]
    fn test_hpack_static_index_3_is_method_post() {
        assert_eq!(HPACK_STATIC[3].0, PSEUDO_METHOD);
        assert_eq!(HPACK_STATIC[3].1, b"POST");
    }

    #[test]
    fn test_hpack_static_index_4_is_path_root() {
        assert_eq!(HPACK_STATIC[4].0, PSEUDO_PATH);
        assert_eq!(HPACK_STATIC[4].1, b"/");
    }

    #[test]
    fn test_hpack_static_index_5_is_path_index_html() {
        assert_eq!(HPACK_STATIC[5].0, PSEUDO_PATH);
        assert_eq!(HPACK_STATIC[5].1, b"/index.html");
    }

    #[test]
    fn test_hpack_static_index_7_is_scheme_https() {
        assert_eq!(HPACK_STATIC[7].0, PSEUDO_SCHEME);
        assert_eq!(HPACK_STATIC[7].1, b"https");
    }

    #[test]
    fn test_hpack_static_index_8_is_status_200() {
        assert_eq!(HPACK_STATIC[8].0, PSEUDO_STATUS);
        assert_eq!(HPACK_STATIC[8].1, b"200");
    }

    #[test]
    fn test_hpack_static_index_16_is_accept_encoding_default() {
        assert_eq!(HPACK_STATIC[16].0, ACCEPT_ENCODING);
        assert_eq!(HPACK_STATIC[16].1, b"gzip, deflate");
    }

    #[test]
    fn test_hpack_static_min_max_index() {
        assert_eq!(HPACK_STATIC_MIN_INDEX, 1);
        assert_eq!(HPACK_STATIC_MAX_INDEX, 60);
    }

    // ------------------------------------------------------------------------
    // HEADER NAME CONSTANTS — byte lengths & lowercase invariants
    // ------------------------------------------------------------------------

    #[test]
    fn test_header_name_lengths() {
        // Spot-check selected header name lengths per FASM source.
        assert_eq!(CONNECTION.len(), 10);
        assert_eq!(ACCESS_CONTROL_ALLOW_ORIGIN.len(), 27);
        assert_eq!(STRICT_TRANSPORT_SECURITY.len(), 25);
        assert_eq!(VIA.len(), 3);
        assert_eq!(AGE.len(), 3);
        assert_eq!(DATE.len(), 4);
        assert_eq!(HOST.len(), 4);
        assert_eq!(ETAG.len(), 4);
        assert_eq!(CONTENT_TYPE.len(), 12);
        assert_eq!(CONTENT_LENGTH.len(), 14);
    }

    #[test]
    fn test_pseudo_header_lengths() {
        assert_eq!(PSEUDO_AUTHORITY.len(), 10);
        assert_eq!(PSEUDO_METHOD.len(), 7);
        assert_eq!(PSEUDO_PATH.len(), 5);
        assert_eq!(PSEUDO_SCHEME.len(), 7);
        assert_eq!(PSEUDO_STATUS.len(), 7);
    }

    #[test]
    fn test_header_names_are_all_lowercase() {
        // Every non-pseudo standard header name constant must be lowercase.
        for bytes in [
            CONNECTION,
            ACCEPT_CHARSET,
            ACCEPT_ENCODING,
            ACCEPT_LANGUAGE,
            ACCEPT_RANGES,
            ACCEPT,
            ACCESS_CONTROL_ALLOW_ORIGIN,
            AGE,
            ALLOW,
            AUTHORIZATION,
            CACHE_CONTROL,
            CONTENT_DISPOSITION,
            CONTENT_ENCODING,
            CONTENT_LANGUAGE,
            CONTENT_LENGTH,
            CONTENT_LOCATION,
            CONTENT_RANGE,
            CONTENT_TYPE,
            COOKIE,
            DATE,
            ETAG,
            EXPECT,
            EXPIRES,
            FROM,
            HOST,
            IF_MATCH,
            IF_MODIFIED_SINCE,
            IF_NONE_MATCH,
            IF_RANGE,
            IF_UNMODIFIED_SINCE,
            LAST_MODIFIED,
            LINK,
            LOCATION,
            MAX_FORWARDS,
            PROXY_AUTHENTICATE,
            PROXY_AUTHORIZATION,
            RANGE,
            REFERER,
            RETRY_AFTER,
            SERVER,
            SET_COOKIE,
            STRICT_TRANSPORT_SECURITY,
            TRANSFER_ENCODING,
            USER_AGENT,
            VARY,
            VIA,
            WWW_AUTHENTICATE,
        ] {
            for &b in bytes {
                assert!(
                    !b.is_ascii_uppercase(),
                    "header name '{}' contains uppercase byte 0x{:02x}",
                    std::str::from_utf8(bytes).unwrap_or("?"),
                    b
                );
            }
        }
    }

    // ------------------------------------------------------------------------
    // HTTP1_SEARCHORDERS_LEN: sanity check sum
    // ------------------------------------------------------------------------

    #[test]
    fn test_http1_searchorders_len_sums_to_47() {
        let total: u32 = HTTP1_SEARCHORDERS_LEN.iter().sum();
        assert_eq!(total, 47, "HTTP1_SEARCHORDERS_LEN sum mismatch");
    }

    #[test]
    fn test_http1_searchorders_consistency() {
        // For each length, inner slice length must match the count array.
        for (len, &count) in HTTP1_SEARCHORDERS_LEN.iter().enumerate() {
            let actual = HTTP1_SEARCHORDERS[len].len() as u32;
            assert_eq!(
                actual, count,
                "HTTP1_SEARCHORDERS[{}].len() = {} but LEN[{}] = {}",
                len, actual, len, count
            );
        }
    }

    // ------------------------------------------------------------------------
    // STATUS DESCRIPTIVES
    // ------------------------------------------------------------------------

    #[test]
    fn test_status_descriptives_length_is_15() {
        assert_eq!(STATUS_DESCRIPTIVES.len(), 15);
    }

    #[test]
    fn test_status_descriptive_default_is_heavything() {
        assert_eq!(STATUS_DESCRIPTIVE_DEFAULT, b"HeavyThing");
    }

    #[test]
    fn test_status_descriptive_lookup_200() {
        assert_eq!(HttpHeaders::status_descriptive(200), b"She'll be apples");
    }

    #[test]
    fn test_status_descriptive_lookup_404() {
        assert_eq!(HttpHeaders::status_descriptive(404), b"Gone Walkabout");
    }

    #[test]
    fn test_status_descriptive_lookup_500() {
        assert_eq!(HttpHeaders::status_descriptive(500), b"It's Cactus");
    }

    #[test]
    fn test_status_descriptive_lookup_unknown_falls_back() {
        assert_eq!(HttpHeaders::status_descriptive(999), STATUS_DESCRIPTIVE_DEFAULT);
        assert_eq!(HttpHeaders::status_descriptive(0), STATUS_DESCRIPTIVE_DEFAULT);
    }

    #[test]
    fn test_status_descriptive_struct_equality() {
        // StatusDescriptive derives PartialEq + Eq.
        let a = StatusDescriptive {
            code: 200,
            text: b"She'll be apples",
        };
        let b = StatusDescriptive {
            code: 200,
            text: b"She'll be apples",
        };
        assert_eq!(a, b);
    }

    // ------------------------------------------------------------------
    // HUFFMAN TABLE REFERENCE VALUES (RFC 7541 Appendix B)
    // ------------------------------------------------------------------

    #[test]
    fn test_huffman_table_lengths() {
        // Preserves FASM table cardinalities: 44/826/257/257 dwords/bytes.
        assert_eq!(HUFFY_T.len(), 44);
        assert_eq!(HUFFY_E.len(), 826);
        assert_eq!(HUFFY_C.len(), 257);
        assert_eq!(HUFFY_L.len(), 257);
    }

    #[test]
    fn test_huffman_eos_marker() {
        // RFC 7541 §5.2: EOS symbol index 256 has a 30-bit code of all-1s.
        // Left-aligned into u32 leaves the low 2 bits zero: 0xfffffffc.
        assert_eq!(HUFFY_C[256], 0xfffffffc);
        assert_eq!(HUFFY_L[256], 30);
    }

    #[test]
    fn test_huffman_lengths_ascii_printable() {
        // Reference values preserved from RFC 7541 Appendix B:
        //   ' ' (0x20)  => 6 bits
        //   '/' (0x2f)  => 6 bits
        //   '0' (0x30)  => 5 bits
        //   'a' (0x61)  => 5 bits
        assert_eq!(HUFFY_L[b' ' as usize], 6);
        assert_eq!(HUFFY_L[b'/' as usize], 6);
        assert_eq!(HUFFY_L[b'0' as usize], 5);
        assert_eq!(HUFFY_L[b'a' as usize], 5);
    }

    #[test]
    fn test_huffman_code_space() {
        // ' ' => 6-bit code 0b010100 (0x14) left-aligned into u32: 0x50000000.
        assert_eq!(HUFFY_C[b' ' as usize], 0x50000000);
    }

    #[test]
    fn test_huffman_code_slash() {
        // '/' => 6-bit code 0b011000 (0x18) left-aligned into u32: 0x60000000.
        assert_eq!(HUFFY_C[b'/' as usize], 0x60000000);
    }

    #[test]
    fn test_huffman_code_zero() {
        // '0' => 5-bit code 0b00000 left-aligned into u32: 0x00000000.
        assert_eq!(HUFFY_C[b'0' as usize], 0x00000000);
    }

    #[test]
    fn test_huffman_code_a() {
        // 'a' => 5-bit code 0b00011 (0x03) left-aligned into u32: 0x18000000.
        assert_eq!(HUFFY_C[b'a' as usize], 0x18000000);
    }

    #[test]
    fn test_huffman_code_lengths_all_in_range() {
        // RFC 7541 §5.2 constrains all code lengths to [5..=30].
        // Enforcing this on all 257 entries (bytes 0-255 plus EOS) guards
        // against accidental table corruption during source transcription.
        for (i, &len) in HUFFY_L.iter().enumerate() {
            assert!(
                (5..=30).contains(&len),
                "HUFFY_L[{}] = {} is out of RFC 7541 range [5..=30]",
                i,
                len,
            );
        }
    }

    #[test]
    fn test_huffman_code_is_left_aligned() {
        // Every non-EOS entry's Huffman code must fit in its declared length
        // and be left-aligned in the u32.  Specifically, the low (32 - length)
        // bits of HUFFY_C[i] must be zero.
        for i in 0..=255 {
            let code = HUFFY_C[i];
            let len = HUFFY_L[i] as u32;
            if len < 32 {
                let low_mask: u32 = (1u32 << (32 - len)) - 1;
                assert_eq!(
                    code & low_mask,
                    0,
                    "HUFFY_C[{}] = {:#010x} is not left-aligned for length {}",
                    i,
                    code,
                    len,
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // emit_capitalized_name: single-byte first-letter capitalization
    // ------------------------------------------------------------------

    #[test]
    fn test_emit_capitalized_lowercase_first_byte() {
        // FASM `sub byte [rax], 'a' - 'A'` uppercases ONLY the first byte.
        // "content-type" must become "Content-type" (note lowercase 't').
        let mut dest: Vec<u8> = Vec::new();
        HttpHeaders::emit_capitalized_name(b"content-type", &mut dest);
        assert_eq!(dest, b"Content-type");
    }

    #[test]
    fn test_emit_capitalized_already_uppercase_first_byte_preserved() {
        // If the first byte is already uppercase (or non-alpha), it is
        // emitted verbatim; subsequent bytes are never transformed.
        let mut dest: Vec<u8> = Vec::new();
        HttpHeaders::emit_capitalized_name(b"Content-Type", &mut dest);
        assert_eq!(dest, b"Content-Type");
    }

    #[test]
    fn test_emit_capitalized_custom_header() {
        // "x-custom-header" => "X-custom-header" (only 'x' uppercased).
        let mut dest: Vec<u8> = Vec::new();
        HttpHeaders::emit_capitalized_name(b"x-custom-header", &mut dest);
        assert_eq!(dest, b"X-custom-header");
    }

    #[test]
    fn test_emit_capitalized_empty() {
        // Empty name must NOT panic; dest remains empty.
        let mut dest: Vec<u8> = Vec::new();
        HttpHeaders::emit_capitalized_name(b"", &mut dest);
        assert!(dest.is_empty());
    }

    #[test]
    fn test_emit_capitalized_single_byte() {
        // Single-byte name: lowercase 'z' uppercases to 'Z'; the "rest"
        // (empty slice) appends nothing.
        let mut dest: Vec<u8> = Vec::new();
        HttpHeaders::emit_capitalized_name(b"z", &mut dest);
        assert_eq!(dest, b"Z");
    }

    #[test]
    fn test_emit_capitalized_non_alpha_first_byte() {
        // First byte outside a..=z is emitted verbatim (e.g., pseudo-headers).
        let mut dest: Vec<u8> = Vec::new();
        HttpHeaders::emit_capitalized_name(b":method", &mut dest);
        assert_eq!(dest, b":method");
    }

    // ------------------------------------------------------------------
    // HeaderEntry constructors + hpack_size
    // ------------------------------------------------------------------

    #[test]
    fn test_header_entry_from_static() {
        // Both name and value are Cow::Borrowed against static storage.
        let e = HeaderEntry::from_static(CONTENT_TYPE, b"text/plain");
        assert_eq!(e.name.as_ref(), b"content-type");
        assert_eq!(e.value.as_ref(), b"text/plain");
        // Verify Borrowed variant (pointer equality against static).
        match &e.name {
            Cow::Borrowed(p) => assert!(std::ptr::eq(*p, CONTENT_TYPE)),
            Cow::Owned(_) => panic!("expected Cow::Borrowed for from_static name"),
        }
        match &e.value {
            Cow::Borrowed(_) => { /* ok */ }
            Cow::Owned(_) => panic!("expected Cow::Borrowed for from_static value"),
        }
    }

    #[test]
    fn test_header_entry_from_owned() {
        // Both name and value are Cow::Owned heap-allocated bytes.
        let e = HeaderEntry::from_owned(b"x-foo".to_vec(), b"bar".to_vec());
        assert_eq!(e.name.as_ref(), b"x-foo");
        assert_eq!(e.value.as_ref(), b"bar");
        match &e.name {
            Cow::Owned(_) => { /* ok */ }
            Cow::Borrowed(_) => panic!("expected Cow::Owned for from_owned name"),
        }
        match &e.value {
            Cow::Owned(_) => { /* ok */ }
            Cow::Borrowed(_) => panic!("expected Cow::Owned for from_owned value"),
        }
    }

    #[test]
    fn test_header_entry_from_static_name() {
        // Name is Cow::Borrowed against static; value is Cow::Owned.
        let e = HeaderEntry::from_static_name(HOST, b"example.com".to_vec());
        assert_eq!(e.name.as_ref(), b"host");
        assert_eq!(e.value.as_ref(), b"example.com");
        match &e.name {
            Cow::Borrowed(p) => assert!(std::ptr::eq(*p, HOST)),
            Cow::Owned(_) => panic!("expected Cow::Borrowed for from_static_name name"),
        }
        match &e.value {
            Cow::Owned(_) => { /* ok */ }
            Cow::Borrowed(_) => panic!("expected Cow::Owned for from_static_name value"),
        }
    }

    #[test]
    fn test_header_entry_hpack_size_rfc_7541_section_4_1() {
        // RFC 7541 §4.1: size = name.len() + value.len() + 32.
        let e = HeaderEntry::from_static(CONTENT_TYPE, b"text/plain");
        // name = "content-type" (12 bytes); value = "text/plain" (10 bytes).
        // size = 12 + 10 + 32 = 54.
        assert_eq!(e.hpack_size(), 54);
    }

    #[test]
    fn test_header_entry_hpack_size_empty_value() {
        // Empty value still contributes 0 bytes; name + 32 overhead.
        let e = HeaderEntry::from_static(DATE, b"");
        // name = "date" (4 bytes); value = "" (0 bytes).
        // size = 4 + 0 + 32 = 36.
        assert_eq!(e.hpack_size(), 36);
    }

    #[test]
    fn test_header_entry_hpack_size_matches_owned() {
        // Owned vs Borrowed Cow variants must yield identical hpack_size
        // because size is derived from lengths, not storage mode.
        let e_static = HeaderEntry::from_static(HOST, b"www.example.com");
        let e_owned = HeaderEntry::from_owned(b"host".to_vec(), b"www.example.com".to_vec());
        assert_eq!(e_static.hpack_size(), e_owned.hpack_size());
    }

    #[test]
    fn test_header_entry_clone_preserves_content() {
        // HeaderEntry derives Clone; cloned entry must have equal name+value.
        let e = HeaderEntry::from_owned(b"x-foo".to_vec(), b"bar".to_vec());
        let e2 = e.clone();
        assert_eq!(e.name.as_ref(), e2.name.as_ref());
        assert_eq!(e.value.as_ref(), e2.value.as_ref());
    }

    // ------------------------------------------------------------------
    // Lifecycle: new() / reset() / reset_headers() / cleanup() / Default
    //
    // FASM byte-fidelity: new()/reset()/cleanup() all set flags=FLAG_HTTP_1_0
    // (value 0), matching httpheaders.inc L53, L114, L96.  reset_headers()
    // leaves flags UNTOUCHED (it clears only the htable, per FASM L153).
    // ------------------------------------------------------------------

    #[test]
    fn test_new_initializes_flag_http_1_0() {
        // Per AAP Phase 11 + FASM L53 byte-fidelity, new() sets flags to
        // FLAG_HTTP_1_0 (==0).  This is the baseline "no version declared
        // yet" state before any parse.
        let h = HttpHeaders::new();
        assert_eq!(h.version(), FLAG_HTTP_1_0);
    }

    #[test]
    fn test_new_hcount_zero() {
        // Fresh container has empty working-header table.
        let h = HttpHeaders::new();
        assert_eq!(h.hcount(), 0);
    }

    #[test]
    fn test_new_dcount_zero() {
        // Fresh container has empty HPACK dynamic table.
        let h = HttpHeaders::new();
        assert_eq!(h.dcount(), 0);
    }

    #[test]
    fn test_new_dtable_size_zero() {
        // dtable_size is sum of per-entry hpack_size; empty => 0.
        let h = HttpHeaders::new();
        assert_eq!(h.dtable_size(), 0);
    }

    #[test]
    fn test_default_equivalent_to_new() {
        // Per AAP Phase 11, Default::default() delegates to Self::new().
        // All observable public state must match.
        let a = HttpHeaders::new();
        let b: HttpHeaders = HttpHeaders::default();
        assert_eq!(a.hcount(), b.hcount());
        assert_eq!(a.dcount(), b.dcount());
        assert_eq!(a.dtable_size(), b.dtable_size());
        assert_eq!(a.version(), b.version());
    }

    #[test]
    fn test_reset_clears_htable() {
        // reset() must empty the working-header table.
        let mut h = HttpHeaders::new();
        h.fast_add(CONTENT_TYPE, b"text/plain").unwrap();
        h.fast_add(HOST, b"example.com").unwrap();
        assert_eq!(h.hcount(), 2);
        h.reset();
        assert_eq!(h.hcount(), 0);
    }

    #[test]
    fn test_reset_resets_version_to_flag_http_1_0() {
        // reset() must restore flags to FLAG_HTTP_1_0 (value 0) matching
        // FASM L114 behavior.  Note: agent_prompt originally proposed
        // FLAG_HTTP_1_1 but FASM byte-fidelity wins.
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_2);
        assert_eq!(h.version(), FLAG_HTTP_2);
        h.reset();
        assert_eq!(h.version(), FLAG_HTTP_1_0);
    }

    #[test]
    fn test_reset_preserves_dtable() {
        // Per RFC 7541 §2.3.2, the HPACK dynamic table is per-connection,
        // not per-message.  reset() clears htable but MUST preserve dtable.
        // Populate dtable via §6.2.1 literal-with-incremental-indexing,
        // new-name encoding (0x40 opcode):
        //   0x40              — §6.2.1, new name
        //   0x06 "x-test"     — name length=6, no Huffman
        //   0x05 "value"      — value length=5, no Huffman
        let mut h = HttpHeaders::new();
        let hpack = [
            0x40u8, 0x06, b'x', b'-', b't', b'e', b's', b't', 0x05, b'v', b'a', b'l', b'u', b'e',
        ];
        h.parse_http2(&hpack).unwrap();
        assert_eq!(h.hcount(), 1);
        assert_eq!(h.dcount(), 1);
        h.reset();
        assert_eq!(h.hcount(), 0); // htable cleared
        assert_eq!(h.dcount(), 1); // dtable preserved per RFC 7541
    }

    #[test]
    fn test_reset_headers_clears_htable_only() {
        // reset_headers() clears htable but MUST NOT touch flags or dtable.
        // This is the distinguishing behavior from reset() per FASM L153.
        let mut h = HttpHeaders::new();
        h.fast_add(CONTENT_TYPE, b"text/plain").unwrap();
        h.set_version(FLAG_HTTP_1_1);
        h.reset_headers();
        assert_eq!(h.hcount(), 0);
        // version MUST be unchanged by reset_headers.
        assert_eq!(h.version(), FLAG_HTTP_1_1);
    }

    #[test]
    fn test_reset_headers_preserves_dtable() {
        // reset_headers() must not touch the dynamic table either.
        let mut h = HttpHeaders::new();
        let hpack = [
            0x40u8, 0x06, b'x', b'-', b't', b'e', b's', b't', 0x05, b'v', b'a', b'l', b'u', b'e',
        ];
        h.parse_http2(&hpack).unwrap();
        assert_eq!(h.dcount(), 1);
        h.reset_headers();
        assert_eq!(h.hcount(), 0);
        assert_eq!(h.dcount(), 1);
    }

    #[test]
    fn test_cleanup_clears_both_tables() {
        // cleanup() is the connection-close path; it empties BOTH tables
        // and resets flags.  Matches FASM L96.
        let mut h = HttpHeaders::new();
        let hpack = [
            0x40u8, 0x06, b'x', b'-', b't', b'e', b's', b't', 0x05, b'v', b'a', b'l', b'u', b'e',
        ];
        h.parse_http2(&hpack).unwrap();
        assert_eq!(h.hcount(), 1);
        assert_eq!(h.dcount(), 1);
        h.cleanup();
        assert_eq!(h.hcount(), 0);
        assert_eq!(h.dcount(), 0);
    }

    #[test]
    fn test_cleanup_resets_version_to_flag_http_1_0() {
        // cleanup() also resets version flags to FLAG_HTTP_1_0.
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_2);
        h.cleanup();
        assert_eq!(h.version(), FLAG_HTTP_1_0);
    }

    #[test]
    fn test_set_version_0() {
        // Explicit set to FLAG_HTTP_1_0 (value 0).
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_1_0);
        assert_eq!(h.version(), FLAG_HTTP_1_0);
    }

    #[test]
    fn test_set_version_1() {
        // Explicit set to FLAG_HTTP_1_1 (value 1).
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_1_1);
        assert_eq!(h.version(), FLAG_HTTP_1_1);
    }

    #[test]
    fn test_set_version_2() {
        // Explicit set to FLAG_HTTP_2 (value 2).
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_2);
        assert_eq!(h.version(), FLAG_HTTP_2);
    }

    #[test]
    fn test_set_version_masks_to_low_2_bits() {
        // set_version applies `version & 0b11` before OR-ing into flags.
        // Passing 0xFF must store only 0b11 (== 3).
        let mut h = HttpHeaders::new();
        h.set_version(0xFFu64);
        assert_eq!(h.version(), 3); // low 2 bits of 0xFF == 0b11 == 3
    }

    #[test]
    fn test_set_version_twice_overwrites_low_bits() {
        // Repeated set_version calls must overwrite (not accumulate) the
        // low 2 bits.  Cleared via `self.flags & !0b11` per FASM semantics.
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_2);
        assert_eq!(h.version(), FLAG_HTTP_2);
        h.set_version(FLAG_HTTP_1_1);
        assert_eq!(h.version(), FLAG_HTTP_1_1);
        h.set_version(FLAG_HTTP_1_0);
        assert_eq!(h.version(), FLAG_HTTP_1_0);
    }

    #[test]
    fn test_version_returns_low_2_bits_only() {
        // version() returns `self.flags & 0b11`; result must never exceed 3.
        let mut h = HttpHeaders::new();
        h.set_version(0xDEADBEEFu64);
        assert!(h.version() <= 3);
    }

    // ----------------------------------------------------------------------
    // Accessors — slow_single_get / fast_single_get / slow_get_index /
    //             fast_get_index / slow_count / fast_count / iter / contains.
    //
    // The `slow_*` family accepts any `&[u8]` and uses case-insensitive
    // byte comparison (eq_ignore_ascii_case).  The `fast_*` family requires
    // `&'static [u8]` and uses pointer-identity comparison against
    // Cow::Borrowed entries, mirroring FASM's vtable fast-path on static
    // header name pointers.
    // ----------------------------------------------------------------------

    #[test]
    fn test_slow_single_get_case_insensitive() {
        // FASM L2725 strcasecmp-based lookup; case is ignored during byte
        // comparison.  Stored internally as lowercase; matches any case
        // variant at query time.
        let mut h = HttpHeaders::new();
        h.slow_add(b"X-Custom", b"value1").unwrap();
        assert_eq!(h.slow_single_get(b"x-custom"), Some(&b"value1"[..]));
        assert_eq!(h.slow_single_get(b"X-CUSTOM"), Some(&b"value1"[..]));
        assert_eq!(h.slow_single_get(b"X-Custom"), Some(&b"value1"[..]));
    }

    #[test]
    fn test_slow_single_get_returns_first_match() {
        // Multiple entries with same name: slow_single_get returns the FIRST.
        let mut h = HttpHeaders::new();
        h.slow_add(b"Set-Cookie", b"a=1").unwrap();
        h.slow_add(b"Set-Cookie", b"b=2").unwrap();
        assert_eq!(h.slow_single_get(b"set-cookie"), Some(&b"a=1"[..]));
    }

    #[test]
    fn test_slow_single_get_missing_returns_none() {
        let h = HttpHeaders::new();
        assert_eq!(h.slow_single_get(b"x-nope"), None);
    }

    #[test]
    fn test_fast_single_get_pointer_identity() {
        // fast_single_get requires the exact &'static [u8] pointer from
        // the HPACK_STATIC constants; compares via std::ptr::eq.
        let mut h = HttpHeaders::new();
        h.fast_add(CONTENT_TYPE, b"text/plain").unwrap();
        assert_eq!(h.fast_single_get(CONTENT_TYPE), Some(&b"text/plain"[..]));
    }

    #[test]
    fn test_fast_single_get_missing_returns_none() {
        let h = HttpHeaders::new();
        assert_eq!(h.fast_single_get(HOST), None);
    }

    #[test]
    fn test_slow_get_index_nth_match() {
        // FASM L2808: returns the Nth (0-indexed) match by name.
        let mut h = HttpHeaders::new();
        h.slow_add(b"set-cookie", b"a=1").unwrap();
        h.slow_add(b"set-cookie", b"b=2").unwrap();
        h.slow_add(b"set-cookie", b"c=3").unwrap();
        assert_eq!(h.slow_get_index(b"set-cookie", 0), Some(&b"a=1"[..]));
        assert_eq!(h.slow_get_index(b"set-cookie", 1), Some(&b"b=2"[..]));
        assert_eq!(h.slow_get_index(b"set-cookie", 2), Some(&b"c=3"[..]));
        assert_eq!(h.slow_get_index(b"set-cookie", 3), None);
    }

    #[test]
    fn test_fast_get_index_nth_match() {
        // FASM L2864: Nth match using pointer identity.
        let mut h = HttpHeaders::new();
        h.fast_add(SET_COOKIE, b"a=1").unwrap();
        h.fast_add(SET_COOKIE, b"b=2").unwrap();
        assert_eq!(h.fast_get_index(SET_COOKIE, 0), Some(&b"a=1"[..]));
        assert_eq!(h.fast_get_index(SET_COOKIE, 1), Some(&b"b=2"[..]));
        assert_eq!(h.fast_get_index(SET_COOKIE, 2), None);
    }

    #[test]
    fn test_slow_count_matches() {
        // FASM L2911: count of entries matching name (case-insensitive).
        let mut h = HttpHeaders::new();
        h.slow_add(b"accept", b"*/*").unwrap();
        h.slow_add(b"Accept", b"text/html").unwrap();
        h.slow_add(b"Host", b"example.com").unwrap();
        assert_eq!(h.slow_count(b"accept"), 2);
        assert_eq!(h.slow_count(b"host"), 1);
        assert_eq!(h.slow_count(b"x-nope"), 0);
    }

    #[test]
    fn test_fast_count_matches() {
        // FASM L2957: pointer-identity count.
        let mut h = HttpHeaders::new();
        h.fast_add(ACCEPT, b"*/*").unwrap();
        h.fast_add(ACCEPT, b"text/html").unwrap();
        h.fast_add(HOST, b"example.com").unwrap();
        assert_eq!(h.fast_count(ACCEPT), 2);
        assert_eq!(h.fast_count(HOST), 1);
        assert_eq!(h.fast_count(COOKIE), 0);
    }

    #[test]
    fn test_iter_preserves_insertion_order() {
        // iter() yields entries in FASM insertion order (htable Vec order).
        let mut h = HttpHeaders::new();
        h.fast_add(HOST, b"first.com").unwrap();
        h.fast_add(CONTENT_TYPE, b"text/plain").unwrap();
        h.fast_add(ACCEPT, b"*/*").unwrap();
        let pairs: Vec<(&[u8], &[u8])> = h.iter().collect();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0], (HOST, &b"first.com"[..]));
        assert_eq!(pairs[1], (CONTENT_TYPE, &b"text/plain"[..]));
        assert_eq!(pairs[2], (ACCEPT, &b"*/*"[..]));
    }

    #[test]
    fn test_contains_case_insensitive() {
        let mut h = HttpHeaders::new();
        h.slow_add(b"X-Foo", b"bar").unwrap();
        assert!(h.contains(b"x-foo"));
        assert!(h.contains(b"X-Foo"));
        assert!(h.contains(b"X-FOO"));
        assert!(!h.contains(b"x-bar"));
    }

    // ----------------------------------------------------------------------
    // Mutators — slow_add / fast_add / slow_remove / fast_remove.
    //
    // FASM byte-fidelity:
    //  * slow_add searches HTTP1_SEARCHORDERS for a case-insensitive name
    //    match; if found, stores the static HPACK name pointer (zero-copy).
    //    Otherwise lowercases and owns the name.
    //  * fast_add always stores Cow::Borrowed(name) — caller must supply
    //    an &'static [u8] already in the HPACK_STATIC universe.
    //  * MAX_HTABLE=22 cap rejects further adds with HeaderCountOverflow.
    //  * MAX_VALUE_BYTES=65536 cap rejects large values with ValueTooLarge.
    // ----------------------------------------------------------------------

    #[test]
    fn test_slow_add_succeeds() {
        let mut h = HttpHeaders::new();
        h.slow_add(b"X-Custom", b"value").unwrap();
        assert_eq!(h.hcount(), 1);
        assert_eq!(h.slow_single_get(b"x-custom"), Some(&b"value"[..]));
    }

    #[test]
    fn test_slow_add_resolves_to_static_name() {
        // FASM L2356: slow_add first searches HTTP1_SEARCHORDERS for a
        // case-insensitive name match; if found, stores the static HPACK
        // pointer (zero-copy).  A subsequent fast_count with the same
        // static constant then succeeds via pointer-identity comparison.
        let mut h = HttpHeaders::new();
        h.slow_add(b"Content-Type", b"text/plain").unwrap();
        assert_eq!(h.fast_count(CONTENT_TYPE), 1);
    }

    #[test]
    fn test_slow_add_non_static_owns_name() {
        // A header name not in HPACK_STATIC: lowercased and owned.  Must
        // still be retrievable case-insensitively via slow_single_get.
        let mut h = HttpHeaders::new();
        h.slow_add(b"X-Request-ID", b"abc123").unwrap();
        assert_eq!(h.hcount(), 1);
        assert_eq!(h.slow_single_get(b"x-request-id"), Some(&b"abc123"[..]));
        assert_eq!(h.slow_single_get(b"X-REQUEST-ID"), Some(&b"abc123"[..]));
    }

    #[test]
    fn test_fast_add_uses_static_pointer() {
        let mut h = HttpHeaders::new();
        h.fast_add(HOST, b"example.com").unwrap();
        assert_eq!(h.fast_count(HOST), 1);
        assert_eq!(h.fast_single_get(HOST), Some(&b"example.com"[..]));
    }

    #[test]
    fn test_slow_add_overflow_rejected() {
        // MAX_HTABLE (22) cap — 23rd add returns HeaderCountOverflow.
        let mut h = HttpHeaders::new();
        for i in 0..MAX_HTABLE {
            let value = format!("v-{}", i);
            h.slow_add(b"X-Flood", value.as_bytes()).unwrap();
        }
        assert_eq!(h.hcount(), MAX_HTABLE as usize);
        let res = h.slow_add(b"X-Flood", b"overflow");
        assert_eq!(res, Err(HttpHeadersError::HeaderCountOverflow));
    }

    #[test]
    fn test_fast_add_overflow_rejected() {
        let mut h = HttpHeaders::new();
        for _ in 0..MAX_HTABLE {
            h.fast_add(CONTENT_TYPE, b"x").unwrap();
        }
        let res = h.fast_add(CONTENT_TYPE, b"overflow");
        assert_eq!(res, Err(HttpHeadersError::HeaderCountOverflow));
    }

    #[test]
    fn test_slow_add_value_too_large_rejected() {
        // MAX_VALUE_BYTES (65536) cap on value size.  Allocating 65537
        // bytes must be rejected with ValueTooLarge.
        let mut h = HttpHeaders::new();
        let huge = vec![b'x'; MAX_VALUE_BYTES + 1];
        let res = h.slow_add(b"X-Big", &huge);
        assert_eq!(res, Err(HttpHeadersError::ValueTooLarge));
    }

    #[test]
    fn test_fast_add_value_too_large_rejected() {
        let mut h = HttpHeaders::new();
        let huge = vec![b'x'; MAX_VALUE_BYTES + 1];
        let res = h.fast_add(CONTENT_TYPE, &huge);
        assert_eq!(res, Err(HttpHeadersError::ValueTooLarge));
    }

    #[test]
    fn test_slow_add_value_at_exact_limit_succeeds() {
        // Boundary check: value.len() == MAX_VALUE_BYTES (not `>`) accepts.
        let mut h = HttpHeaders::new();
        let at_limit = vec![b'x'; MAX_VALUE_BYTES];
        let res = h.slow_add(b"X-Limit", &at_limit);
        assert!(res.is_ok());
        assert_eq!(h.hcount(), 1);
    }

    #[test]
    fn test_slow_remove_returns_removed_count() {
        // FASM L2987: removes all entries matching (case-insensitive).
        let mut h = HttpHeaders::new();
        h.slow_add(b"set-cookie", b"a=1").unwrap();
        h.slow_add(b"Set-Cookie", b"b=2").unwrap();
        h.slow_add(b"Y-Keep", b"keep").unwrap();
        assert_eq!(h.slow_remove(b"set-cookie"), 2);
        assert_eq!(h.hcount(), 1);
        assert_eq!(h.slow_single_get(b"y-keep"), Some(&b"keep"[..]));
    }

    #[test]
    fn test_slow_remove_no_match_returns_zero() {
        let mut h = HttpHeaders::new();
        h.slow_add(b"X-Keep", b"value").unwrap();
        assert_eq!(h.slow_remove(b"x-nope"), 0);
        assert_eq!(h.hcount(), 1);
    }

    #[test]
    fn test_fast_remove_returns_removed_count() {
        // FASM L3055: removes all entries matching (pointer-identity).
        let mut h = HttpHeaders::new();
        h.fast_add(SET_COOKIE, b"a=1").unwrap();
        h.fast_add(SET_COOKIE, b"b=2").unwrap();
        h.fast_add(CONTENT_TYPE, b"text/html").unwrap();
        assert_eq!(h.fast_remove(SET_COOKIE), 2);
        assert_eq!(h.hcount(), 1);
        assert_eq!(h.fast_single_get(CONTENT_TYPE), Some(&b"text/html"[..]));
    }

    #[test]
    fn test_fast_remove_no_match_returns_zero() {
        let mut h = HttpHeaders::new();
        h.fast_add(CONTENT_TYPE, b"text/html").unwrap();
        assert_eq!(h.fast_remove(HOST), 0);
        assert_eq!(h.hcount(), 1);
    }

    // ----------------------------------------------------------------------
    // Mimelike compatibility helpers — insert_replace, insert_append,
    // get, get_bytes, remove, iter_pairs.
    //
    // These are Rust-only wrappers required by mimelike.rs / server.rs /
    // client.rs for idiomatic use.  They layer on top of the case-
    // insensitive slow_* accessors/mutators to provide String-typed
    // convenience.
    // ----------------------------------------------------------------------

    #[test]
    fn test_insert_replace_replaces_existing() {
        // Sequential insert_replace overrides the prior value; hcount stays 1.
        let mut h = HttpHeaders::new();
        h.insert_replace("Content-Type".into(), "text/html".into());
        h.insert_replace("Content-Type".into(), "application/json".into());
        assert_eq!(h.hcount(), 1);
        assert_eq!(h.get("Content-Type"), Some("application/json"));
    }

    #[test]
    fn test_insert_replace_on_empty_adds_new() {
        let mut h = HttpHeaders::new();
        h.insert_replace("Host".into(), "example.com".into());
        assert_eq!(h.hcount(), 1);
        assert_eq!(h.get("Host"), Some("example.com"));
    }

    #[test]
    fn test_insert_append_concatenates_with_separator() {
        // Each append on existing name concatenates via `sep`.
        let mut h = HttpHeaders::new();
        h.insert_append("Via".into(), "proxy1".into(), ", ");
        h.insert_append("Via".into(), "proxy2".into(), ", ");
        h.insert_append("Via".into(), "proxy3".into(), ", ");
        assert_eq!(h.hcount(), 1);
        assert_eq!(h.get("Via"), Some("proxy1, proxy2, proxy3"));
    }

    #[test]
    fn test_insert_append_on_empty_adds_without_separator() {
        // First append on empty htable must NOT prepend separator.
        let mut h = HttpHeaders::new();
        h.insert_append("Accept".into(), "text/html".into(), ", ");
        assert_eq!(h.get("Accept"), Some("text/html"));
    }

    #[test]
    fn test_get_returns_utf8_str() {
        let mut h = HttpHeaders::new();
        h.slow_add(b"X-Custom", b"utf8-value").unwrap();
        assert_eq!(h.get("X-Custom"), Some("utf8-value"));
    }

    #[test]
    fn test_get_missing_returns_none() {
        let h = HttpHeaders::new();
        assert_eq!(h.get("X-Missing"), None);
    }

    #[test]
    fn test_get_bytes_returns_slice() {
        let mut h = HttpHeaders::new();
        h.slow_add(b"X-Bin", b"\xde\xad\xbe\xef").unwrap();
        let v = h.get_bytes(b"x-bin").unwrap();
        assert_eq!(v, b"\xde\xad\xbe\xef");
    }

    #[test]
    fn test_remove_returns_first_value() {
        // remove() returns the first entry's value; subsequent remove is None.
        let mut h = HttpHeaders::new();
        h.slow_add(b"X-Key", b"first").unwrap();
        assert_eq!(h.remove("X-Key"), Some("first".to_string()));
        assert_eq!(h.remove("X-Key"), None);
    }

    #[test]
    fn test_remove_missing_returns_none() {
        let mut h = HttpHeaders::new();
        assert_eq!(h.remove("X-Nope"), None);
    }

    #[test]
    fn test_iter_pairs_returns_utf8_tuples() {
        // iter_pairs yields (&str, &str) in insertion order; ASCII-clean
        // fixtures guarantee valid UTF-8 decoding via filter_map.
        let mut h = HttpHeaders::new();
        h.slow_add(b"content-type", b"text/plain").unwrap();
        h.slow_add(b"host", b"example.com").unwrap();
        let pairs: Vec<(&str, &str)> = h.iter_pairs().collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("content-type", "text/plain"));
        assert_eq!(pairs[1], ("host", "example.com"));
    }

    // =================================================================
    // Batch 5 — Phase 2l tests (tostring, status_descriptive,
    // emit_capitalized_name, find_end_of_headers, find_line_terminator,
    // parse_request_line, parse_response_line, parse_http1,
    // to_buffer_http1)
    // =================================================================

    // ---------- tostring (FASM L166) ----------

    #[test]
    fn test_tostring_empty_htable_returns_empty_string() {
        let h = HttpHeaders::new();
        assert_eq!(h.tostring(), "");
    }

    #[test]
    fn test_tostring_single_entry_formats_with_colon_space_and_crlf() {
        let mut h = HttpHeaders::new();
        h.fast_add(HOST, b"example.com").expect("add");
        assert_eq!(h.tostring(), "host: example.com\r\n");
    }

    #[test]
    fn test_tostring_multiple_entries_preserves_insertion_order() {
        let mut h = HttpHeaders::new();
        h.fast_add(HOST, b"example.com").expect("add");
        h.fast_add(CONTENT_TYPE, b"text/plain").expect("add");
        h.fast_add(USER_AGENT, b"test/1.0").expect("add");
        assert_eq!(
            h.tostring(),
            "host: example.com\r\ncontent-type: text/plain\r\nuser-agent: test/1.0\r\n"
        );
    }

    #[test]
    fn test_tostring_non_utf8_value_is_gracefully_skipped_but_separators_emitted() {
        let mut h = HttpHeaders::new();
        // Insert a header whose value contains invalid UTF-8 (continuation byte without lead).
        h.slow_add(b"x-raw", &[0x80u8, 0xff, 0x80]).expect("add");
        // Name is valid UTF-8; value is not.  Expected output: "x-raw: \r\n"
        assert_eq!(h.tostring(), "x-raw: \r\n");
    }

    // ---------- status_descriptive (FASM L207-263) ----------

    #[test]
    fn test_status_descriptive_200_returns_shell_be_apples() {
        assert_eq!(HttpHeaders::status_descriptive(200), b"She'll be apples");
    }

    #[test]
    fn test_status_descriptive_206_returns_slice_of_pie() {
        assert_eq!(
            HttpHeaders::status_descriptive(206),
            b"Just a slice of the whole pie"
        );
    }

    #[test]
    fn test_status_descriptive_301_returns_she_nicked_off() {
        assert_eq!(HttpHeaders::status_descriptive(301), b"She nicked off");
    }

    #[test]
    fn test_status_descriptive_302_returns_look_here_mate() {
        assert_eq!(HttpHeaders::status_descriptive(302), b"Look here mate");
    }

    #[test]
    fn test_status_descriptive_304_returns_same_same_mate() {
        assert_eq!(HttpHeaders::status_descriptive(304), b"Same same mate");
    }

    #[test]
    fn test_status_descriptive_400_returns_up_a_gumtree() {
        assert_eq!(HttpHeaders::status_descriptive(400), b"Up a gumtree");
    }

    #[test]
    fn test_status_descriptive_403_returns_i_wouldnt_be_doin_that() {
        assert_eq!(HttpHeaders::status_descriptive(403), b"I wouldn't be doin that");
    }

    #[test]
    fn test_status_descriptive_404_returns_gone_walkabout() {
        assert_eq!(HttpHeaders::status_descriptive(404), b"Gone Walkabout");
    }

    #[test]
    fn test_status_descriptive_500_returns_its_cactus() {
        assert_eq!(HttpHeaders::status_descriptive(500), b"It's Cactus");
    }

    #[test]
    fn test_status_descriptive_502_returns_had_a_blue() {
        assert_eq!(
            HttpHeaders::status_descriptive(502),
            b"Had a blue with the old fella"
        );
    }

    #[test]
    fn test_status_descriptive_505_returns_you_gone_bongers() {
        assert_eq!(HttpHeaders::status_descriptive(505), b"You gone bongers mate?");
    }

    #[test]
    fn test_status_descriptive_unknown_returns_heavything_default() {
        assert_eq!(HttpHeaders::status_descriptive(999), b"HeavyThing");
        assert_eq!(HttpHeaders::status_descriptive(0), b"HeavyThing");
        assert_eq!(HttpHeaders::status_descriptive(418), b"HeavyThing");
        assert_eq!(HttpHeaders::status_descriptive(300), b"HeavyThing");
    }

    // ---------- emit_capitalized_name (FASM single-byte capitalization) ----------

    #[test]
    fn test_emit_capitalized_name_lowercase_first_byte_uppercased() {
        let mut dest = Vec::new();
        HttpHeaders::emit_capitalized_name(b"content-type", &mut dest);
        assert_eq!(dest, b"Content-type");
    }

    #[test]
    fn test_emit_capitalized_name_already_uppercase_unchanged() {
        let mut dest = Vec::new();
        HttpHeaders::emit_capitalized_name(b"Accept", &mut dest);
        assert_eq!(dest, b"Accept");
    }

    #[test]
    fn test_emit_capitalized_name_digit_first_byte_unchanged() {
        let mut dest = Vec::new();
        HttpHeaders::emit_capitalized_name(b"0example", &mut dest);
        assert_eq!(dest, b"0example");
    }

    #[test]
    fn test_emit_capitalized_name_symbol_first_byte_unchanged() {
        let mut dest = Vec::new();
        HttpHeaders::emit_capitalized_name(b":method", &mut dest);
        assert_eq!(dest, b":method");
    }

    #[test]
    fn test_emit_capitalized_name_single_lowercase_byte() {
        let mut dest = Vec::new();
        HttpHeaders::emit_capitalized_name(b"a", &mut dest);
        assert_eq!(dest, b"A");
    }

    #[test]
    fn test_emit_capitalized_name_empty_name_writes_nothing() {
        let mut dest = Vec::new();
        HttpHeaders::emit_capitalized_name(b"", &mut dest);
        assert_eq!(dest, b"");
        assert!(dest.is_empty());
    }

    #[test]
    fn test_emit_capitalized_name_preserves_fasm_quirk_only_first_byte() {
        // FASM quirk: `sub byte [rax], 'a' - 'A'` only uppercases first byte.
        // "content-length" -> "Content-length" (NOT "Content-Length").
        let mut dest = Vec::new();
        HttpHeaders::emit_capitalized_name(b"content-length", &mut dest);
        assert_eq!(dest, b"Content-length");
        // Explicitly verify the 'l' after the hyphen remains lowercase.
        assert_eq!(dest[8], b'l');
    }

    #[test]
    fn test_emit_capitalized_name_appends_to_non_empty_dest() {
        let mut dest = b"prefix:".to_vec();
        HttpHeaders::emit_capitalized_name(b"host", &mut dest);
        assert_eq!(dest, b"prefix:Host");
    }

    // ---------- find_end_of_headers ----------

    #[test]
    fn test_find_end_of_headers_crlf_crlf_at_start() {
        let data = b"\r\n\r\n";
        assert_eq!(HttpHeaders::find_end_of_headers(data), Some((0, 4)));
    }

    #[test]
    fn test_find_end_of_headers_crlf_crlf_later() {
        let data = b"header: value\r\n\r\nbody";
        assert_eq!(HttpHeaders::find_end_of_headers(data), Some((13, 4)));
    }

    #[test]
    fn test_find_end_of_headers_lf_lf_only() {
        let data = b"header: value\n\nbody";
        assert_eq!(HttpHeaders::find_end_of_headers(data), Some((13, 2)));
    }

    #[test]
    fn test_find_end_of_headers_crlf_crlf_priority_over_lf_lf() {
        // CRLF-CRLF appears first; should return 4-byte marker.
        let data = b"a\r\n\r\nb\n\nc";
        assert_eq!(HttpHeaders::find_end_of_headers(data), Some((1, 4)));
    }

    #[test]
    fn test_find_end_of_headers_no_marker_returns_none() {
        let data = b"header: value\r\nmore: stuff\r\n";
        assert_eq!(HttpHeaders::find_end_of_headers(data), None);
    }

    #[test]
    fn test_find_end_of_headers_empty_returns_none() {
        assert_eq!(HttpHeaders::find_end_of_headers(b""), None);
    }

    #[test]
    fn test_find_end_of_headers_single_lf_returns_none() {
        let data = b"header: value\n";
        assert_eq!(HttpHeaders::find_end_of_headers(data), None);
    }

    #[test]
    fn test_find_end_of_headers_single_crlf_returns_none() {
        let data = b"header: value\r\n";
        assert_eq!(HttpHeaders::find_end_of_headers(data), None);
    }

    #[test]
    fn test_find_end_of_headers_short_buffer_returns_none() {
        assert_eq!(HttpHeaders::find_end_of_headers(b"a"), None);
    }

    // ---------- find_line_terminator ----------

    #[test]
    fn test_find_line_terminator_crlf_at_start() {
        let data = b"\r\n";
        assert_eq!(HttpHeaders::find_line_terminator(data), Some((0, 2)));
    }

    #[test]
    fn test_find_line_terminator_crlf_later() {
        let data = b"Host: example.com\r\n";
        assert_eq!(HttpHeaders::find_line_terminator(data), Some((17, 2)));
    }

    #[test]
    fn test_find_line_terminator_bare_lf() {
        let data = b"Host: example.com\n";
        assert_eq!(HttpHeaders::find_line_terminator(data), Some((17, 1)));
    }

    #[test]
    fn test_find_line_terminator_crlf_priority_over_lf() {
        // CRLF appears first; should be preferred over bare LF later.
        let data = b"a\r\nb\n";
        assert_eq!(HttpHeaders::find_line_terminator(data), Some((1, 2)));
    }

    #[test]
    fn test_find_line_terminator_bare_cr_alone_is_not_terminator() {
        // A lone CR without following LF is not treated as a terminator
        // (function requires CRLF pair or bare LF).
        let data = b"Host: x\r";
        assert_eq!(HttpHeaders::find_line_terminator(data), None);
    }

    #[test]
    fn test_find_line_terminator_no_terminator() {
        let data = b"Host: example.com";
        assert_eq!(HttpHeaders::find_line_terminator(data), None);
    }

    #[test]
    fn test_find_line_terminator_empty_returns_none() {
        assert_eq!(HttpHeaders::find_line_terminator(b""), None);
    }

    // ---------- parse_request_line (FASM L1843-2345 — error paths) ----------

    #[test]
    fn test_parse_request_line_ok_for_simple_get() {
        let mut h = HttpHeaders::new();
        h.parse_request_line(b"GET / HTTP/1.1", b"GET").expect("ok");
        assert_eq!(h.version(), FLAG_HTTP_1_1);
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"GET"[..]));
        assert_eq!(h.fast_single_get(PSEUDO_PATH), Some(&b"/"[..]));
    }

    #[test]
    fn test_parse_request_line_ok_for_http_1_0() {
        let mut h = HttpHeaders::new();
        h.parse_request_line(b"GET / HTTP/1.0", b"GET").expect("ok");
        assert_eq!(h.version(), FLAG_HTTP_1_0);
    }

    #[test]
    fn test_parse_request_line_uses_static_path_root() {
        // Verify the `b"/"` optimization borrows DEFAULT_PATH_ROOT.
        let mut h = HttpHeaders::new();
        h.parse_request_line(b"GET / HTTP/1.1", b"GET").expect("ok");
        // Two entries: :method and :path.
        assert_eq!(h.hcount(), 2);
    }

    #[test]
    fn test_parse_request_line_uses_static_path_index_html() {
        let mut h = HttpHeaders::new();
        h.parse_request_line(b"GET /index.html HTTP/1.1", b"GET")
            .expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_PATH), Some(&b"/index.html"[..]));
    }

    #[test]
    fn test_parse_request_line_arbitrary_path_is_owned() {
        let mut h = HttpHeaders::new();
        h.parse_request_line(b"GET /foo/bar?q=1 HTTP/1.1", b"GET")
            .expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_PATH), Some(&b"/foo/bar?q=1"[..]));
    }

    #[test]
    fn test_parse_request_line_asterisk_path_for_options() {
        let mut h = HttpHeaders::new();
        h.parse_request_line(b"OPTIONS * HTTP/1.1", b"OPTIONS")
            .expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"OPTIONS"[..]));
        assert_eq!(h.fast_single_get(PSEUDO_PATH), Some(&b"*"[..]));
    }

    #[test]
    fn test_parse_request_line_err_line_too_short() {
        // Predicate 1: `line.len() <= method.len() || line[method.len()] != b' '`
        let mut h = HttpHeaders::new();
        let res = h.parse_request_line(b"GET", b"GET");
        assert_eq!(res, Err(HttpHeadersError::MalformedMethod));
    }

    #[test]
    fn test_parse_request_line_err_no_space_after_method() {
        // Predicate 1: no space after method byte.
        let mut h = HttpHeaders::new();
        let res = h.parse_request_line(b"GETX / HTTP/1.1", b"GET");
        assert_eq!(res, Err(HttpHeadersError::MalformedMethod));
    }

    #[test]
    fn test_parse_request_line_err_empty_path() {
        // Predicate 2: `pos == path_start` — two spaces in a row means empty path.
        let mut h = HttpHeaders::new();
        let res = h.parse_request_line(b"GET  HTTP/1.1", b"GET");
        assert_eq!(res, Err(HttpHeadersError::MalformedMethod));
    }

    #[test]
    fn test_parse_request_line_err_no_space_after_path() {
        // Predicate 2: `pos >= line.len()` — no space to terminate path.
        let mut h = HttpHeaders::new();
        let res = h.parse_request_line(b"GET /foo", b"GET");
        assert_eq!(res, Err(HttpHeadersError::MalformedMethod));
    }

    #[test]
    fn test_parse_request_line_err_bad_path_prefix() {
        // Predicate 3: path[0] is neither `/` nor `*`.
        let mut h = HttpHeaders::new();
        let res = h.parse_request_line(b"GET foo HTTP/1.1", b"GET");
        assert_eq!(res, Err(HttpHeadersError::MalformedMethod));
    }

    #[test]
    fn test_parse_request_line_err_missing_http_version_prefix() {
        // Predicate 4: `pos + 8 > line.len()` — too short for "HTTP/1.X".
        let mut h = HttpHeaders::new();
        let res = h.parse_request_line(b"GET / HTTP", b"GET");
        assert_eq!(res, Err(HttpHeadersError::MalformedMethod));
    }

    #[test]
    fn test_parse_request_line_err_bad_http_version_prefix() {
        // Predicate 4: bytes do not match "HTTP/1.".
        let mut h = HttpHeaders::new();
        let res = h.parse_request_line(b"GET / HTTP/2.0", b"GET");
        assert_eq!(res, Err(HttpHeadersError::MalformedMethod));
    }

    #[test]
    fn test_parse_request_line_err_bad_http_minor_version() {
        // Predicate 5: minor byte not `0` or `1`.
        let mut h = HttpHeaders::new();
        let res = h.parse_request_line(b"GET / HTTP/1.5", b"GET");
        assert_eq!(res, Err(HttpHeadersError::MalformedMethod));
    }

    // ---------- parse_response_line (error paths + well-known codes) ----------

    #[test]
    fn test_parse_response_line_ok_200() {
        let mut h = HttpHeaders::new();
        h.parse_response_line(b"HTTP/1.1 200 OK").expect("ok");
        assert_eq!(h.version(), FLAG_HTTP_1_1);
        assert_eq!(h.fast_single_get(PSEUDO_STATUS), Some(&b"200"[..]));
    }

    #[test]
    fn test_parse_response_line_ok_404_well_known() {
        let mut h = HttpHeaders::new();
        h.parse_response_line(b"HTTP/1.1 404 Not Found").expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_STATUS), Some(&b"404"[..]));
    }

    #[test]
    fn test_parse_response_line_ok_500_well_known() {
        let mut h = HttpHeaders::new();
        h.parse_response_line(b"HTTP/1.1 500 Server Error").expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_STATUS), Some(&b"500"[..]));
    }

    #[test]
    fn test_parse_response_line_ok_http_1_0() {
        let mut h = HttpHeaders::new();
        h.parse_response_line(b"HTTP/1.0 200 OK").expect("ok");
        assert_eq!(h.version(), FLAG_HTTP_1_0);
    }

    #[test]
    fn test_parse_response_line_ok_arbitrary_code_418() {
        // 418 is not a well-known optimisation — must become Cow::Owned.
        let mut h = HttpHeaders::new();
        h.parse_response_line(b"HTTP/1.1 418 I'm a teapot").expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_STATUS), Some(&b"418"[..]));
    }

    #[test]
    fn test_parse_response_line_err_too_short() {
        // Predicate 1a: `line.len() < 12`.
        let mut h = HttpHeaders::new();
        let res = h.parse_response_line(b"HTTP/1.1 20");
        assert_eq!(res, Err(HttpHeadersError::MalformedStatus));
    }

    #[test]
    fn test_parse_response_line_err_bad_prefix() {
        // Predicate 1b: does not start with "HTTP/1.".
        let mut h = HttpHeaders::new();
        let res = h.parse_response_line(b"GET / HTTP/1.1__");
        assert_eq!(res, Err(HttpHeadersError::MalformedStatus));
    }

    #[test]
    fn test_parse_response_line_err_bad_minor_version() {
        // Predicate 2: minor byte not `0` or `1`.
        let mut h = HttpHeaders::new();
        let res = h.parse_response_line(b"HTTP/1.5 200 OK");
        assert_eq!(res, Err(HttpHeadersError::MalformedStatus));
    }

    #[test]
    fn test_parse_response_line_err_no_space_before_status() {
        // Predicate 3: `line[8] != b' '`.
        let mut h = HttpHeaders::new();
        let res = h.parse_response_line(b"HTTP/1.1X200 OK");
        assert_eq!(res, Err(HttpHeadersError::MalformedStatus));
    }

    #[test]
    fn test_parse_response_line_err_nondigit_in_status() {
        // Predicate 4: status bytes not all ASCII digits.
        let mut h = HttpHeaders::new();
        let res = h.parse_response_line(b"HTTP/1.1 2X0 OK");
        assert_eq!(res, Err(HttpHeadersError::MalformedStatus));
    }

    // ---------- parse_http1 entry guards ----------

    #[test]
    fn test_parse_http1_needmore_short_buffer() {
        let mut h = HttpHeaders::new();
        let res = h.parse_http1(b"GET / HTT").expect("ok");
        assert_eq!(res, 0);
    }

    #[test]
    fn test_parse_http1_needmore_empty_buffer() {
        let mut h = HttpHeaders::new();
        let res = h.parse_http1(b"").expect("ok");
        assert_eq!(res, 0);
    }

    #[test]
    fn test_parse_http1_needmore_no_eoh_marker() {
        let mut h = HttpHeaders::new();
        // 16+ bytes but no CRLFCRLF/LFLF.
        let data = b"GET /foo HTTP/1.1\r\nHost: x\r\n";
        let res = h.parse_http1(data).expect("ok");
        assert_eq!(res, 0);
    }

    #[test]
    fn test_parse_http1_too_large_returns_error() {
        let mut h = HttpHeaders::new();
        // Create a buffer larger than MAX_MESSAGE_SIZE.
        // Use a reference-only vector via with_capacity to avoid giant allocation.
        let data: Vec<u8> = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let res = h.parse_http1(&data);
        assert_eq!(res, Err(HttpHeadersError::TooLarge));
    }

    // ---------- parse_http1 dispatch (9 method branches + fallback) ----------

    #[test]
    fn test_parse_http1_dispatch_get() {
        let mut h = HttpHeaders::new();
        let data = b"GET / HTTP/1.1\r\n\r\n";
        let n = h.parse_http1(data).expect("ok");
        assert_eq!(n, data.len());
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"GET"[..]));
    }

    #[test]
    fn test_parse_http1_dispatch_head() {
        let mut h = HttpHeaders::new();
        let data = b"HEAD / HTTP/1.1\r\n\r\n";
        h.parse_http1(data).expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"HEAD"[..]));
    }

    #[test]
    fn test_parse_http1_dispatch_post() {
        let mut h = HttpHeaders::new();
        let data = b"POST / HTTP/1.1\r\n\r\n";
        h.parse_http1(data).expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"POST"[..]));
    }

    #[test]
    fn test_parse_http1_dispatch_put() {
        let mut h = HttpHeaders::new();
        let data = b"PUT / HTTP/1.1\r\n\r\n";
        h.parse_http1(data).expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"PUT"[..]));
    }

    #[test]
    fn test_parse_http1_dispatch_delete() {
        let mut h = HttpHeaders::new();
        let data = b"DELETE / HTTP/1.1\r\n\r\n";
        h.parse_http1(data).expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"DELETE"[..]));
    }

    #[test]
    fn test_parse_http1_dispatch_options() {
        let mut h = HttpHeaders::new();
        let data = b"OPTIONS * HTTP/1.1\r\n\r\n";
        h.parse_http1(data).expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"OPTIONS"[..]));
        assert_eq!(h.fast_single_get(PSEUDO_PATH), Some(&b"*"[..]));
    }

    #[test]
    fn test_parse_http1_dispatch_trace() {
        let mut h = HttpHeaders::new();
        let data = b"TRACE / HTTP/1.1\r\n\r\n";
        h.parse_http1(data).expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"TRACE"[..]));
    }

    #[test]
    fn test_parse_http1_dispatch_connect() {
        // CONNECT with path `/` — the method+path is accepted because
        // validation requires `/` or `*` prefix.
        let mut h = HttpHeaders::new();
        let data = b"CONNECT / HTTP/1.1\r\n\r\n";
        h.parse_http1(data).expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"CONNECT"[..]));
    }

    #[test]
    fn test_parse_http1_dispatch_response() {
        let mut h = HttpHeaders::new();
        let data = b"HTTP/1.1 200 OK\r\n\r\n";
        h.parse_http1(data).expect("ok");
        assert_eq!(h.fast_single_get(PSEUDO_STATUS), Some(&b"200"[..]));
    }

    #[test]
    fn test_parse_http1_dispatch_unknown_method_is_malformed() {
        let mut h = HttpHeaders::new();
        let data = b"BREW /potion HTTP/1.1\r\n\r\n";
        let res = h.parse_http1(data);
        assert_eq!(res, Err(HttpHeadersError::MalformedMethod));
    }

    // ---------- parse_http1 Http1Parse error paths ----------

    #[test]
    fn test_parse_http1_err_missing_colon_in_header() {
        let mut h = HttpHeaders::new();
        let data = b"GET / HTTP/1.1\r\nbad_header_no_colon\r\n\r\n";
        let res = h.parse_http1(data);
        assert_eq!(res, Err(HttpHeadersError::Http1Parse));
    }

    #[test]
    fn test_parse_http1_err_empty_header_name() {
        let mut h = HttpHeaders::new();
        let data = b"GET / HTTP/1.1\r\n: value\r\n\r\n";
        let res = h.parse_http1(data);
        assert_eq!(res, Err(HttpHeadersError::Http1Parse));
    }

    // ---------- parse_http1 full request/response roundtrip ----------

    #[test]
    fn test_parse_http1_full_request_with_multiple_headers() {
        let mut h = HttpHeaders::new();
        let data =
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nUser-Agent: rust/1.0\r\n\r\n";
        let n = h.parse_http1(data).expect("ok");
        assert_eq!(n, data.len());
        assert_eq!(h.version(), FLAG_HTTP_1_1);
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"GET"[..]));
        assert_eq!(h.fast_single_get(PSEUDO_PATH), Some(&b"/index.html"[..]));
        assert_eq!(h.slow_single_get(b"host"), Some(&b"example.com"[..]));
        assert_eq!(h.slow_single_get(b"accept"), Some(&b"*/*"[..]));
        assert_eq!(h.slow_single_get(b"user-agent"), Some(&b"rust/1.0"[..]));
    }

    #[test]
    fn test_parse_http1_full_response_with_headers() {
        let mut h = HttpHeaders::new();
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n";
        let n = h.parse_http1(data).expect("ok");
        assert_eq!(n, data.len());
        assert_eq!(h.fast_single_get(PSEUDO_STATUS), Some(&b"200"[..]));
        assert_eq!(h.slow_single_get(b"content-type"), Some(&b"text/plain"[..]));
        assert_eq!(h.slow_single_get(b"content-length"), Some(&b"5"[..]));
    }

    // ---------- parse_http1 RFC 7230 whitespace handling ----------

    #[test]
    fn test_parse_http1_strips_leading_whitespace_from_value() {
        let mut h = HttpHeaders::new();
        let data = b"GET / HTTP/1.1\r\nHost:    example.com\r\n\r\n";
        h.parse_http1(data).expect("ok");
        assert_eq!(h.slow_single_get(b"host"), Some(&b"example.com"[..]));
    }

    #[test]
    fn test_parse_http1_strips_leading_tab_whitespace_from_value() {
        let mut h = HttpHeaders::new();
        let data = b"GET / HTTP/1.1\r\nHost:\texample.com\r\n\r\n";
        h.parse_http1(data).expect("ok");
        assert_eq!(h.slow_single_get(b"host"), Some(&b"example.com"[..]));
    }

    #[test]
    fn test_parse_http1_strips_trailing_whitespace_from_value() {
        let mut h = HttpHeaders::new();
        let data = b"GET / HTTP/1.1\r\nHost: example.com   \r\n\r\n";
        h.parse_http1(data).expect("ok");
        assert_eq!(h.slow_single_get(b"host"), Some(&b"example.com"[..]));
    }

    #[test]
    fn test_parse_http1_strips_value_surrounding_whitespace() {
        let mut h = HttpHeaders::new();
        let data = b"GET / HTTP/1.1\r\nX-Foo: \t value \t \r\n\r\n";
        h.parse_http1(data).expect("ok");
        assert_eq!(h.slow_single_get(b"x-foo"), Some(&b"value"[..]));
    }

    // ---------- parse_http1 LAST HEADER PRESERVATION TEST (validates bug fix) ----------

    #[test]
    fn test_parse_http1_preserves_last_header_when_terminator_coincides_with_eoh() {
        // This test specifically validates the bug fix applied to the header
        // parse loop.  Input: "GET / HTTP/1.1\r\nHost: x\r\n\r\n" (27 bytes).
        // The last header's trailing CRLF is the SAME CRLF that kicks off
        // the eoh marker.  Previously the loop broke on `None` terminator
        // and dropped "Host: x" — the fix uses `.unwrap_or((len, 0))` so
        // the final header is always parsed.
        let mut h = HttpHeaders::new();
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let n = h.parse_http1(data).expect("ok");
        assert_eq!(n, data.len());
        // Three entries: :method, :path, host.
        assert_eq!(h.hcount(), 3);
        assert_eq!(h.slow_single_get(b"host"), Some(&b"x"[..]));
    }

    #[test]
    fn test_parse_http1_preserves_last_header_with_lf_only_terminator() {
        // Same pattern but using bare LF line-endings throughout.
        let mut h = HttpHeaders::new();
        let data = b"GET / HTTP/1.1\nHost: y\n\n";
        let n = h.parse_http1(data).expect("ok");
        assert_eq!(n, data.len());
        assert_eq!(h.hcount(), 3);
        assert_eq!(h.slow_single_get(b"host"), Some(&b"y"[..]));
    }

    #[test]
    fn test_parse_http1_multiple_last_headers_preserved() {
        // Verify multiple consecutive headers before eoh are all preserved.
        let mut h = HttpHeaders::new();
        let data = b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n";
        let n = h.parse_http1(data).expect("ok");
        assert_eq!(n, data.len());
        assert_eq!(h.hcount(), 5); // :method, :path, a, b, c
        assert_eq!(h.slow_single_get(b"a"), Some(&b"1"[..]));
        assert_eq!(h.slow_single_get(b"b"), Some(&b"2"[..]));
        assert_eq!(h.slow_single_get(b"c"), Some(&b"3"[..]));
    }

    // ---------- to_buffer_http1 (FASM L191-450) ----------

    #[test]
    fn test_to_buffer_http1_empty_htable_returns_ok_without_modifying_dest() {
        let h = HttpHeaders::new();
        let mut dest = b"preserved".to_vec();
        h.to_buffer_http1(&mut dest).expect("ok");
        assert_eq!(dest, b"preserved");
    }

    #[test]
    fn test_to_buffer_http1_request_preface_emitted() {
        // FASM byte-fidelity: `httpheaders$new` (see httpheaders.inc L53-88) sets
        // flags=0 (HTTP/1.0). `tobuffer_http1` (L190-300) uses `cmp flags_ofs, 1 /
        // cmove` → emits '1' only when flags==1. The test asserts HTTP/1.1, so the
        // caller must explicitly upgrade via `set_version(FLAG_HTTP_1_1)` — which
        // mirrors the normal code path where `parse_http1` auto-upgrades on
        // receipt of an `HTTP/1.1` request/response line.
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_1_1);
        h.fast_add(PSEUDO_METHOD, b"GET").expect("add");
        h.fast_add(PSEUDO_PATH, b"/").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");
        let s = std::str::from_utf8(&dest).expect("utf8");
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_to_buffer_http1_request_preface_with_headers() {
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_1_1);
        h.fast_add(PSEUDO_METHOD, b"GET").expect("add");
        h.fast_add(PSEUDO_PATH, b"/index.html").expect("add");
        h.fast_add(HOST, b"example.com").expect("add");
        h.fast_add(USER_AGENT, b"rust/1.0").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");
        let s = std::str::from_utf8(&dest).expect("utf8");
        assert!(s.starts_with("GET /index.html HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
        assert!(s.contains("User-agent: rust/1.0\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
        // Pseudo-headers MUST NOT appear in the HTTP/1 wire format.
        assert!(!s.contains(":method"));
        assert!(!s.contains(":path"));
    }

    #[test]
    fn test_to_buffer_http1_response_preface_with_known_code_200() {
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_1_1);
        h.fast_add(PSEUDO_STATUS, b"200").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");
        let s = std::str::from_utf8(&dest).expect("utf8");
        assert!(s.starts_with("HTTP/1.1 200 She'll be apples\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_to_buffer_http1_response_preface_with_known_code_404() {
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_1_1);
        h.fast_add(PSEUDO_STATUS, b"404").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");
        let s = std::str::from_utf8(&dest).expect("utf8");
        assert!(s.starts_with("HTTP/1.1 404 Gone Walkabout\r\n"));
    }

    #[test]
    fn test_to_buffer_http1_response_preface_with_unknown_code_falls_back_to_heavything() {
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_1_1);
        h.fast_add(PSEUDO_STATUS, b"418").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");
        let s = std::str::from_utf8(&dest).expect("utf8");
        assert!(s.starts_with("HTTP/1.1 418 HeavyThing\r\n"));
    }

    #[test]
    fn test_to_buffer_http1_response_preface_non_3_digit_status_uses_heavything() {
        // Status bytes ≠ 3 digits — code parsing yields 0, which maps to HeavyThing.
        let mut h = HttpHeaders::new();
        h.fast_add(PSEUDO_STATUS, b"2").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");
        let s = std::str::from_utf8(&dest).expect("utf8");
        assert!(s.contains("HeavyThing"));
    }

    #[test]
    fn test_to_buffer_http1_response_preface_with_headers() {
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_1_1);
        h.fast_add(PSEUDO_STATUS, b"200").expect("add");
        h.fast_add(CONTENT_TYPE, b"text/plain").expect("add");
        h.fast_add(CONTENT_LENGTH, b"11").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");
        let s = std::str::from_utf8(&dest).expect("utf8");
        assert!(s.starts_with("HTTP/1.1 200 She'll be apples\r\n"));
        assert!(s.contains("Content-type: text/plain\r\n"));
        assert!(s.contains("Content-length: 11\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_to_buffer_http1_version_byte_for_http_1_0() {
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_1_0);
        h.fast_add(PSEUDO_STATUS, b"200").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");
        let s = std::str::from_utf8(&dest).expect("utf8");
        assert!(s.starts_with("HTTP/1.0 200"));
    }

    #[test]
    fn test_to_buffer_http1_version_byte_for_http_1_1() {
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_1_1);
        h.fast_add(PSEUDO_STATUS, b"200").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");
        let s = std::str::from_utf8(&dest).expect("utf8");
        assert!(s.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn test_to_buffer_http1_http_2_version_maps_to_1() {
        // version_byte match: FLAG_HTTP_1_0 -> b'0', any other -> b'1'.
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_2);
        h.fast_add(PSEUDO_STATUS, b"200").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");
        let s = std::str::from_utf8(&dest).expect("utf8");
        assert!(s.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn test_to_buffer_http1_pseudo_headers_not_emitted_in_body() {
        // All pseudo-headers (starting with `:`) must be filtered out of the
        // non-preface header body.
        let mut h = HttpHeaders::new();
        h.set_version(FLAG_HTTP_1_1);
        h.fast_add(PSEUDO_METHOD, b"GET").expect("add");
        h.fast_add(PSEUDO_PATH, b"/").expect("add");
        h.fast_add(PSEUDO_SCHEME, b"https").expect("add");
        h.fast_add(PSEUDO_AUTHORITY, b"example.com").expect("add");
        h.fast_add(HOST, b"example.com").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");
        let s = std::str::from_utf8(&dest).expect("utf8");
        // Preface contains method+path.
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        // Pseudo-headers filtered from body.
        assert!(!s.contains(":scheme"));
        assert!(!s.contains(":authority"));
        assert!(!s.contains(":method:"));
        assert!(!s.contains(":path:"));
        // Regular header preserved with capitalized first letter.
        assert!(s.contains("Host: example.com\r\n"));
    }

    #[test]
    fn test_to_buffer_http1_only_method_no_path_no_preface() {
        // Request preface requires BOTH :method AND :path.  Without :path,
        // the function falls through to response preface check; without
        // :status either, NO preface is emitted.  Per the impl, it only
        // emits headers body + final "\r\n".
        let mut h = HttpHeaders::new();
        h.fast_add(PSEUDO_METHOD, b"GET").expect("add");
        h.fast_add(HOST, b"example.com").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");
        let s = std::str::from_utf8(&dest).expect("utf8");
        assert!(!s.starts_with("GET"));
        assert!(!s.starts_with("HTTP/"));
        assert!(s.starts_with("Host: example.com\r\n"));
    }

    #[test]
    fn test_to_buffer_http1_roundtrip_with_parse_http1() {
        // Serialize a response then parse it back.
        let mut h = HttpHeaders::new();
        h.fast_add(PSEUDO_STATUS, b"200").expect("add");
        h.fast_add(CONTENT_TYPE, b"text/plain").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http1(&mut dest).expect("ok");

        // Now parse.
        let mut h2 = HttpHeaders::new();
        let n = h2.parse_http1(&dest).expect("parse");
        assert_eq!(n, dest.len());
        assert_eq!(h2.fast_single_get(PSEUDO_STATUS), Some(&b"200"[..]));
        assert_eq!(h2.slow_single_get(b"content-type"), Some(&b"text/plain"[..]));
    }

    // ───────────────────────────────────────────────────────────────
    // Batch 6: HPACK codec integration.
    //
    // HPACK integer codec roundtrips, Huffman codec roundtrips and
    // error paths, string codec H=0/H=1 selection, 5-case
    // emit_header_http2 dispatch via the public to_buffer_http2 path,
    // parse_http2 opcode dispatch and size-update edge cases,
    // dtable_insert's 3 eviction paths, is_never_indexed matrix, and
    // HttpHeadersError -> HttpError::Parse conversion.
    // ───────────────────────────────────────────────────────────────

    // --- HPACK integer codec (write_integer / read_integer) ---

    #[test]
    fn test_write_integer_zero_prefix4() {
        // 0 < 15 (STRICT) -> single-byte path; high_bits|0 = 0x00.
        let mut buf = Vec::new();
        HttpHeaders::write_integer(0, 4, 0x00, &mut buf);
        assert_eq!(buf, vec![0x00]);
        let (val, adv) = HttpHeaders::read_integer(&buf, 4).expect("read");
        assert_eq!(val, 0);
        assert_eq!(adv, 1);
    }

    #[test]
    fn test_write_integer_boundary_14_prefix4() {
        // 14 < 15 (STRICT) -> single-byte path; high_bits|14 = 0x0E.
        let mut buf = Vec::new();
        HttpHeaders::write_integer(14, 4, 0x00, &mut buf);
        assert_eq!(buf, vec![0x0E]);
        let (val, adv) = HttpHeaders::read_integer(&buf, 4).expect("read");
        assert_eq!(val, 14);
        assert_eq!(adv, 1);
    }

    #[test]
    fn test_write_integer_boundary_127_prefix7() {
        // 127 == max -> STRICT less-than FALSE -> multi-byte [0x7F, 0x00].
        let mut buf = Vec::new();
        HttpHeaders::write_integer(127, 7, 0x00, &mut buf);
        assert_eq!(buf, vec![0x7F, 0x00]);
        let (val, adv) = HttpHeaders::read_integer(&buf, 7).expect("read");
        assert_eq!(val, 127);
        assert_eq!(adv, 2);
    }

    #[test]
    fn test_write_integer_boundary_128_prefix7() {
        // 128 > max -> multi-byte [0x7F, 0x01].
        let mut buf = Vec::new();
        HttpHeaders::write_integer(128, 7, 0x00, &mut buf);
        assert_eq!(buf, vec![0x7F, 0x01]);
        let (val, adv) = HttpHeaders::read_integer(&buf, 7).expect("read");
        assert_eq!(val, 128);
        assert_eq!(adv, 2);
    }

    #[test]
    fn test_write_integer_1337_prefix5() {
        // 1337 with 5-bit prefix: [0x1F, 0x9A, 0x0A].
        // Derivation:
        //   max=31; 1337>=31 -> multi-byte.
        //   push 0x00|31 = 0x1F.
        //   value = 1337-31 = 1306.
        //   loop: 1306%128=26 -> push 26|0x80 = 0x9A; value = 1306/128 = 10.
        //   10<128 -> final push 0x0A.
        let mut buf = Vec::new();
        HttpHeaders::write_integer(1337, 5, 0x00, &mut buf);
        assert_eq!(buf, vec![0x1F, 0x9A, 0x0A]);
        let (val, adv) = HttpHeaders::read_integer(&buf, 5).expect("read");
        assert_eq!(val, 1337);
        assert_eq!(adv, 3);
    }

    #[test]
    fn test_write_integer_1048576_prefix7() {
        // 1,048,576 with 7-bit prefix: [0x7F, 0x81, 0xFF, 0x3F].
        let mut buf = Vec::new();
        HttpHeaders::write_integer(1_048_576, 7, 0x00, &mut buf);
        assert_eq!(buf, vec![0x7F, 0x81, 0xFF, 0x3F]);
        let (val, adv) = HttpHeaders::read_integer(&buf, 7).expect("read");
        assert_eq!(val, 1_048_576);
        assert_eq!(adv, 4);
    }

    #[test]
    fn test_read_integer_empty_errors() {
        let result = HttpHeaders::read_integer(&[], 7);
        assert_eq!(result, Err(HttpHeadersError::HpackDecode));
    }

    #[test]
    fn test_read_integer_truncated_multibyte_errors() {
        // [0x7F, 0x80]: first hits max (=127) and continuation byte has
        // 0x80 set but no further continuation byte is provided.
        let result = HttpHeaders::read_integer(&[0x7F, 0x80], 7);
        assert_eq!(result, Err(HttpHeadersError::HpackDecode));
    }

    // --- HPACK Huffman codec (huffy_encode / huffy_decode) ---

    #[test]
    fn test_huffy_roundtrip_single_a() {
        // 'a' code is 0b00011 (5 bits, HUFFY_C[97]=0x18000000).
        // Encode: 5 bits 00011 + 3-bit EOS pad 111 = 0b00011_111 = 0x1F.
        let mut buf = Vec::new();
        HttpHeaders::huffy_encode(b"a", &mut buf);
        assert_eq!(buf, vec![0x1F]);
        let decoded = HttpHeaders::huffy_decode(&buf).expect("decode");
        assert_eq!(decoded, b"a");
    }

    #[test]
    fn test_huffy_roundtrip_www_example_com() {
        // Per RFC 7541 Appendix C.4.1, "www.example.com" Huffman encodes to
        // exactly 12 bytes (89 bits -> ceil(89/8)=12).
        let mut buf = Vec::new();
        HttpHeaders::huffy_encode(b"www.example.com", &mut buf);
        assert_eq!(buf.len(), 12);
        let decoded = HttpHeaders::huffy_decode(&buf).expect("decode");
        assert_eq!(decoded, b"www.example.com");
    }

    #[test]
    fn test_huffy_roundtrip_empty() {
        let mut buf = Vec::new();
        HttpHeaders::huffy_encode(b"", &mut buf);
        assert_eq!(buf, Vec::<u8>::new());
        let decoded = HttpHeaders::huffy_decode(&buf).expect("decode");
        assert_eq!(decoded, Vec::<u8>::new());
    }

    #[test]
    fn test_huffy_decode_invalid_padding_errors() {
        // After matching 'a' from 0x18, the remaining accumulator holds 3
        // zero-bits.  Valid RFC 7541 §5.2 padding requires all trailing
        // bits to be 1s, so this is an invalid encoding.
        let result = HttpHeaders::huffy_decode(&[0x18]);
        assert_eq!(result, Err(HttpHeadersError::HpackDecode));
    }

    #[test]
    fn test_huffy_roundtrip_abcdef() {
        let original = b"abcdef";
        let mut buf = Vec::new();
        HttpHeaders::huffy_encode(original, &mut buf);
        let decoded = HttpHeaders::huffy_decode(&buf).expect("decode");
        assert_eq!(decoded, original);
    }

    // --- HPACK string literal codec (write_string / read_string) ---

    #[test]
    fn test_write_string_single_a_raw_chosen() {
        // 'a' Huffman = 1 byte, raw = 1 byte.  STRICT less-than FALSE -> raw.
        let mut buf = Vec::new();
        HttpHeaders::write_string(b"a", &mut buf);
        assert_eq!(buf, vec![0x01, 0x61]);
        let (decoded, adv) = HttpHeaders::read_string(&buf).expect("read");
        assert_eq!(decoded, b"a");
        assert_eq!(adv, 2);
    }

    #[test]
    fn test_write_string_long_huffman_chosen() {
        // "www.example.com" Huffman = 12 bytes < raw = 15 -> H=1 path.
        // Length prefix: write_integer(12, 7, 0x80) -> 0x8C.
        let mut buf = Vec::new();
        HttpHeaders::write_string(b"www.example.com", &mut buf);
        assert_eq!(buf[0], 0x8C);
        assert_eq!(buf.len(), 1 + 12);
        let (decoded, adv) = HttpHeaders::read_string(&buf).expect("read");
        assert_eq!(decoded, b"www.example.com");
        assert_eq!(adv, buf.len());
    }

    #[test]
    fn test_write_string_empty() {
        // Empty: Huffman 0 == raw 0 -> STRICT less-than FALSE -> raw (H=0).
        let mut buf = Vec::new();
        HttpHeaders::write_string(b"", &mut buf);
        assert_eq!(buf, vec![0x00]);
        let (decoded, adv) = HttpHeaders::read_string(&buf).expect("read");
        assert_eq!(decoded, Vec::<u8>::new());
        assert_eq!(adv, 1);
    }

    #[test]
    fn test_read_string_truncated_payload_errors() {
        // Length claim = 100 (0x64), H=0, but only 3 payload bytes follow.
        let data = [0x64, 0x01, 0x02, 0x03];
        let result = HttpHeaders::read_string(&data);
        assert_eq!(result, Err(HttpHeadersError::HpackDecode));
    }

    #[test]
    fn test_read_string_empty_input_errors() {
        let result = HttpHeaders::read_string(&[]);
        assert_eq!(result, Err(HttpHeadersError::HpackDecode));
    }

    // --- HPACK opcode emission (via public to_buffer_http2 API) ---

    #[test]
    fn test_emit_http2_indexed_static_method_get() {
        // :method=GET is HPACK static index 2 -> pure indexed [0x82].
        let mut h = HttpHeaders::new();
        h.fast_add(PSEUDO_METHOD, b"GET").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http2(&mut dest).expect("ok");
        assert_eq!(dest, vec![0x82]);
    }

    #[test]
    fn test_emit_http2_indexed_static_method_post() {
        // :method=POST is HPACK static index 3 -> [0x83].
        let mut h = HttpHeaders::new();
        h.fast_add(PSEUDO_METHOD, b"POST").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http2(&mut dest).expect("ok");
        assert_eq!(dest, vec![0x83]);
    }

    #[test]
    fn test_emit_http2_indexed_static_scheme_https() {
        // :scheme=https is HPACK static index 7 -> [0x87].
        let mut h = HttpHeaders::new();
        h.fast_add(PSEUDO_SCHEME, b"https").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http2(&mut dest).expect("ok");
        assert_eq!(dest, vec![0x87]);
    }

    #[test]
    fn test_emit_http2_indexed_static_path_root() {
        // :path=/ is HPACK static index 4 -> [0x84].
        let mut h = HttpHeaders::new();
        h.fast_add(PSEUDO_PATH, b"/").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http2(&mut dest).expect("ok");
        assert_eq!(dest, vec![0x84]);
    }

    #[test]
    fn test_emit_http2_literal_indexed_name_accept_charset() {
        // accept-charset name at idx 15 (default value is empty);
        // supplying "utf-8" triggers Case 3 (literal incremental index,
        // indexed name).  Prefix: write_integer(15, 6, 0x40) = 0x4F.
        let mut h = HttpHeaders::new();
        h.fast_add(ACCEPT_CHARSET, b"utf-8").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http2(&mut dest).expect("ok");
        assert_eq!(dest[0], 0x4F);
        assert_eq!(h.dcount(), 1);
    }

    #[test]
    fn test_emit_http2_literal_new_name_x_custom() {
        // 'x-custom' is not in static or dynamic table and not never-indexed.
        // Case 5 (literal incremental index, new name): dest[0]=0x40.
        let mut h = HttpHeaders::new();
        h.slow_add(b"x-custom", b"value").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http2(&mut dest).expect("ok");
        assert_eq!(dest[0], 0x40);
        assert_eq!(h.dcount(), 1);
    }

    #[test]
    fn test_emit_http2_never_indexed_date() {
        // date is never-indexed; static name idx 33.
        // write_integer(33, 4, 0x00): 33>=15 -> push 0x0F; residual 18 -> push 0x12.
        // dtable must NOT grow.
        let mut h = HttpHeaders::new();
        h.fast_add(DATE, b"Thu, 01 Jan 1970 00:00:00 GMT").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http2(&mut dest).expect("ok");
        assert_eq!(dest[0], 0x0F);
        assert_eq!(dest[1], 0x12);
        assert_eq!(h.dcount(), 0);
    }

    #[test]
    fn test_emit_http2_never_indexed_content_length() {
        // content-length is never-indexed; static name idx 28.
        // write_integer(28, 4, 0x00): 28>=15 -> push 0x0F; residual 13 -> push 0x0D.
        let mut h = HttpHeaders::new();
        h.fast_add(CONTENT_LENGTH, b"42").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http2(&mut dest).expect("ok");
        assert_eq!(dest[0], 0x0F);
        assert_eq!(dest[1], 0x0D);
        assert_eq!(h.dcount(), 0);
    }

    #[test]
    fn test_emit_http2_indexed_dtable_roundtrip() {
        // Step 1: insert x-custom=test -> Case 5 inserts at dtable head idx 0.
        // Step 2 (after reset_headers): re-emit same header -> Case 2
        // write_indexed(62) -> single byte 0xBE.
        let mut h = HttpHeaders::new();
        h.slow_add(b"x-custom", b"test").expect("add");
        {
            let mut first = Vec::new();
            h.to_buffer_http2(&mut first).expect("ok");
        }
        assert_eq!(h.dcount(), 1);
        h.reset_headers();
        h.slow_add(b"x-custom", b"test").expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http2(&mut dest).expect("ok");
        assert_eq!(dest, vec![0xBE]);
    }

    // --- parse_http2 opcode dispatch ---

    #[test]
    fn test_parse_http2_indexed_method_get() {
        // [0x82] -> indexed idx=2 -> :method=GET registered in htable.
        let mut h = HttpHeaders::new();
        h.parse_http2(&[0x82]).expect("parse");
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"GET"[..]));
    }

    #[test]
    fn test_parse_http2_indexed_zero_errors() {
        // Index 0 is reserved/invalid per RFC 7541.
        let mut h = HttpHeaders::new();
        let result = h.parse_http2(&[0x80]);
        assert_eq!(result, Err(HttpHeadersError::HpackDecode));
    }

    #[test]
    fn test_parse_http2_indexed_out_of_range_errors() {
        // Index 70 with empty dtable -> out of valid range.
        let mut h = HttpHeaders::new();
        let result = h.parse_http2(&[0x80 | 70]);
        assert_eq!(result, Err(HttpHeadersError::HpackDecode));
    }

    #[test]
    fn test_parse_http2_literal_with_indexing_new_name() {
        // 0x40 = §6.2.1 new name.  Raw-encoded name 'a' (len 1) + value 'b'.
        let mut h = HttpHeaders::new();
        h.parse_http2(&[0x40, 0x01, b'a', 0x01, b'b']).expect("parse");
        assert_eq!(h.slow_single_get(b"a"), Some(&b"b"[..]));
        assert_eq!(h.dcount(), 1);
    }

    #[test]
    fn test_parse_http2_literal_with_indexing_indexed_name() {
        // 0x4F = §6.2.1 indexed name 15 (=accept-charset); value 'utf-8' raw.
        let mut h = HttpHeaders::new();
        h.parse_http2(&[0x4F, 0x05, b'u', b't', b'f', b'-', b'8'])
            .expect("parse");
        assert_eq!(h.slow_single_get(b"accept-charset"), Some(&b"utf-8"[..]));
        assert_eq!(h.dcount(), 1);
    }

    #[test]
    fn test_parse_http2_literal_without_indexing_indexed_name() {
        // 0x02 = §6.2.2 indexed name 2 (=:method); value 'PUT' raw.
        // dtable must NOT grow.
        let mut h = HttpHeaders::new();
        h.parse_http2(&[0x02, 0x03, b'P', b'U', b'T']).expect("parse");
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"PUT"[..]));
        assert_eq!(h.dcount(), 0);
    }

    #[test]
    fn test_parse_http2_literal_never_indexed_indexed_name() {
        // 0x12 = §6.2.3 indexed name 2.  Our decoder unifies §6.2.2 and
        // §6.2.3 (both skip dtable insertion) while name lookup still
        // resolves to :method.
        let mut h = HttpHeaders::new();
        h.parse_http2(&[0x12, 0x03, b'P', b'U', b'T']).expect("parse");
        assert_eq!(h.fast_single_get(PSEUDO_METHOD), Some(&b"PUT"[..]));
        assert_eq!(h.dcount(), 0);
    }

    #[test]
    fn test_parse_http2_size_update_ok() {
        // [0x3F, 0xE1, 0x1F] encodes dynamic table size update to 4096.
        let mut h = HttpHeaders::new();
        h.parse_http2(&[0x3F, 0xE1, 0x1F]).expect("parse");
        assert_eq!(h.tablesize, 4096);
    }

    #[test]
    fn test_parse_http2_size_update_over_limit_errors() {
        // 65537 > 65536 -> HpackTableSizeOutOfRange.
        let mut h = HttpHeaders::new();
        let result = h.parse_http2(&[0x3F, 0xE2, 0xFF, 0x03]);
        assert_eq!(result, Err(HttpHeadersError::HpackTableSizeOutOfRange));
    }

    #[test]
    fn test_parse_http2_encode_decode_roundtrip() {
        // Encode a representative request block then parse it back.
        let mut encoder = HttpHeaders::new();
        encoder.fast_add(PSEUDO_METHOD, b"GET").expect("add");
        encoder.fast_add(PSEUDO_PATH, b"/index.html").expect("add");
        encoder.fast_add(PSEUDO_SCHEME, b"https").expect("add");
        encoder.fast_add(PSEUDO_AUTHORITY, b"example.com").expect("add");
        encoder.fast_add(ACCEPT_ENCODING, b"gzip, deflate").expect("add");
        let mut encoded = Vec::new();
        encoder.to_buffer_http2(&mut encoded).expect("encode");

        let mut decoder = HttpHeaders::new();
        decoder.parse_http2(&encoded).expect("parse");
        assert_eq!(decoder.fast_single_get(PSEUDO_METHOD), Some(&b"GET"[..]));
        assert_eq!(decoder.fast_single_get(PSEUDO_PATH), Some(&b"/index.html"[..]));
        assert_eq!(decoder.fast_single_get(PSEUDO_SCHEME), Some(&b"https"[..]));
        assert_eq!(
            decoder.fast_single_get(PSEUDO_AUTHORITY),
            Some(&b"example.com"[..])
        );
        assert_eq!(
            decoder.fast_single_get(ACCEPT_ENCODING),
            Some(&b"gzip, deflate"[..])
        );
    }

    // --- Dynamic table eviction (dtable_insert 3 paths + ceiling) ---

    #[test]
    fn test_dtable_insert_oversize_clears_table() {
        // tablesize=40; incoming entry size = 20+20+32 = 72 > 40 -> clear.
        let mut h = HttpHeaders::new();
        h.tablesize = 40;
        h.dtable
            .push(HeaderEntry::from_owned(b"a".to_vec(), b"b".to_vec()));
        assert_eq!(h.dcount(), 1);
        let big_name = vec![b'x'; 20];
        let big_value = vec![b'y'; 20];
        h.slow_add(&big_name, &big_value).expect("add");
        let mut dest = Vec::new();
        h.to_buffer_http2(&mut dest).expect("ok");
        assert_eq!(h.dcount(), 0);
    }

    #[test]
    fn test_dtable_insert_size_based_eviction() {
        // tablesize=100; each entry size = 10+10+32 = 52 bytes.
        // Second entry (52+52=104 > 100) evicts the first.
        let mut h = HttpHeaders::new();
        h.tablesize = 100;
        h.slow_add(b"aaaaaaaaaa", b"bbbbbbbbbb").expect("add");
        {
            let mut first = Vec::new();
            h.to_buffer_http2(&mut first).expect("ok");
        }
        assert_eq!(h.dcount(), 1);
        h.reset_headers();
        h.slow_add(b"cccccccccc", b"dddddddddd").expect("add");
        {
            let mut second = Vec::new();
            h.to_buffer_http2(&mut second).expect("ok");
        }
        assert_eq!(h.dcount(), 1);
        assert_eq!(h.dtable[0].name.as_ref(), b"cccccccccc");
    }

    #[test]
    fn test_dtable_insert_count_based_eviction() {
        // dlimit=2 with spacious tablesize: 3rd insert evicts oldest (tail).
        let mut h = HttpHeaders::new();
        h.dlimit = 2;
        h.tablesize = 4096;
        h.slow_add(b"k1", b"v1").expect("add");
        {
            let mut d = Vec::new();
            h.to_buffer_http2(&mut d).expect("ok");
        }
        h.reset_headers();
        h.slow_add(b"k2", b"v2").expect("add");
        {
            let mut d = Vec::new();
            h.to_buffer_http2(&mut d).expect("ok");
        }
        h.reset_headers();
        assert_eq!(h.dcount(), 2);
        h.slow_add(b"k3", b"v3").expect("add");
        {
            let mut d = Vec::new();
            h.to_buffer_http2(&mut d).expect("ok");
        }
        assert_eq!(h.dcount(), 2);
        assert_eq!(h.dtable[0].name.as_ref(), b"k3");
        assert_eq!(h.dtable[1].name.as_ref(), b"k2");
    }

    #[test]
    fn test_enforce_dtable_ceiling_via_size_update() {
        // Populate dtable then shrink via §6.3 size update to 0 ->
        // enforce_dtable_ceiling must evict every entry.
        let mut h = HttpHeaders::new();
        h.slow_add(b"k1", b"v1").expect("add");
        h.slow_add(b"k2", b"v2").expect("add");
        {
            let mut d = Vec::new();
            h.to_buffer_http2(&mut d).expect("ok");
        }
        assert_eq!(h.dcount(), 2);
        h.reset_headers();
        // [0x20] = size update with value 0.
        h.parse_http2(&[0x20]).expect("parse");
        assert_eq!(h.tablesize, 0);
        assert_eq!(h.dcount(), 0);
    }

    // --- is_never_indexed sensitivity matrix ---

    #[test]
    fn test_is_never_indexed_true_for_all_eight() {
        // All 8 entries from the Phase 2m matches! macro.
        assert!(HttpHeaders::is_never_indexed(b"date"));
        assert!(HttpHeaders::is_never_indexed(b"content-length"));
        assert!(HttpHeaders::is_never_indexed(b"etag"));
        assert!(HttpHeaders::is_never_indexed(b"last-modified"));
        assert!(HttpHeaders::is_never_indexed(b"if-none-match"));
        assert!(HttpHeaders::is_never_indexed(b"if-modified-since"));
        assert!(HttpHeaders::is_never_indexed(b"content-range"));
        assert!(HttpHeaders::is_never_indexed(b"range"));
    }

    #[test]
    fn test_is_never_indexed_false_for_ordinary_headers() {
        assert!(!HttpHeaders::is_never_indexed(b"content-type"));
        assert!(!HttpHeaders::is_never_indexed(b"host"));
        assert!(!HttpHeaders::is_never_indexed(b"authorization"));
        assert!(!HttpHeaders::is_never_indexed(b"accept"));
        assert!(!HttpHeaders::is_never_indexed(b"cookie"));
        // Byte-exact (case-sensitive) match: upper-case variants do NOT
        // register as never-indexed.  Callers are responsible for
        // lowercasing before consulting this helper.
        assert!(!HttpHeaders::is_never_indexed(b"Date"));
        assert!(!HttpHeaders::is_never_indexed(b"CONTENT-LENGTH"));
    }

    // --- Error conversion HttpHeadersError -> HttpError::Parse ---

    #[test]
    fn test_error_conversion_http1parse() {
        let err: HttpError = HttpHeadersError::Http1Parse.into();
        assert!(matches!(err, HttpError::Parse(ref s) if s.starts_with("httpheaders:")));
    }

    #[test]
    fn test_error_conversion_hpack_decode() {
        let err: HttpError = HttpHeadersError::HpackDecode.into();
        assert!(matches!(err, HttpError::Parse(ref s) if s.starts_with("httpheaders:")));
    }

    #[test]
    fn test_error_conversion_header_count_overflow() {
        let err: HttpError = HttpHeadersError::HeaderCountOverflow.into();
        assert!(matches!(err, HttpError::Parse(ref s) if s.starts_with("httpheaders:")));
    }

    #[test]
    fn test_error_conversion_value_too_large() {
        let err: HttpError = HttpHeadersError::ValueTooLarge.into();
        assert!(matches!(err, HttpError::Parse(ref s) if s.starts_with("httpheaders:")));
    }

    #[test]
    fn test_error_conversion_hpack_table_size_out_of_range() {
        let err: HttpError = HttpHeadersError::HpackTableSizeOutOfRange.into();
        assert!(matches!(err, HttpError::Parse(ref s) if s.starts_with("httpheaders:")));
    }

    #[test]
    fn test_error_conversion_malformed_status() {
        let err: HttpError = HttpHeadersError::MalformedStatus.into();
        assert!(matches!(err, HttpError::Parse(ref s) if s.starts_with("httpheaders:")));
    }

    #[test]
    fn test_error_conversion_malformed_method() {
        let err: HttpError = HttpHeadersError::MalformedMethod.into();
        assert!(matches!(err, HttpError::Parse(ref s) if s.starts_with("httpheaders:")));
    }

    #[test]
    fn test_error_conversion_too_large() {
        let err: HttpError = HttpHeadersError::TooLarge.into();
        assert!(matches!(err, HttpError::Parse(ref s) if s.starts_with("httpheaders:")));
    }
}
