// ------------------------------------------------------------------------
// HeavyThing Rust port — FastCGI client
// Copyright © 2015 2 Ton Digital, Jeff Marrison <jeff@2ton.com.au>
// Rust port © 2026 Blitzy HeavyThing Translators
// Homepage: https://2ton.com.au/
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
//
// fcgi.rs: FastCGI client tied to the tokio runtime; port of fcgiclient.inc
//
// This module is a faithful translation of the FASM `fcgiclient.inc`
// (18,305 bytes) source file. The original assembly comment described it
// as "a quick and dirty fastcgi client, tied to epoll directly (instead
// of being an io layer)" — the same architectural choice is preserved
// here: `FcgiClient` does NOT implement the `IoChain` trait. Instead, it
// owns its own tokio task that drives the entire request lifecycle and
// communicates the outcome back to the caller via a one-shot callback.
//
// Wire protocol: FastCGI 1.0
// (https://fastcgi-archives.github.io/FastCGI_Specification.html)
//
// Records used:
//   - FCGI_BEGIN_REQUEST (1) — sent first, role=Responder, flags=0
//   - FCGI_PARAMS (4)        — CGI environment variables (e.g. REQUEST_METHOD)
//   - FCGI_STDIN (5)         — request body (POST data)
//   - FCGI_STDOUT (6)        — response body (parsed back into Mimelike)
//   - FCGI_STDERR (7)        — captured into errbuf or forwarded to syslog
//   - FCGI_END_REQUEST (3)   — triggers the result callback
//
// Used by the webserver crate when the `-fastcgi <pattern> <addr>` rule
// matches an inbound HTTP request, to proxy the request to an upstream
// FastCGI backend such as PHP-FPM over either a Unix domain socket or
// TCP.

use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::{BufMut, Bytes, BytesMut};
use once_cell::sync::Lazy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::time::{timeout, Duration};

use crate::config::{EPOLL_NODELAY, HTTP_IDLE_TIMEOUT_SECS, WEBSERVER_FASTCGI_POSTPROCESS};
use crate::ds::Buffer;
use crate::error::{HttpError, NetError};
use crate::net::dns::DnsResolver;
use crate::net::http::mimelike::Mimelike;
use crate::net::runtime::{TeardownReason, TimerAction};
use crate::net::url::Url;
use crate::util::syslog;

// ---------------------------------------------------------------------------
// FastCGI 1.0 wire-protocol constants
// ---------------------------------------------------------------------------

/// FastCGI protocol version (the only version defined by the spec).
const FCGI_VERSION_1: u8 = 1;

/// Record-type byte values per FastCGI 1.0 §8.
const FCGI_BEGIN_REQUEST: u8 = 1;
#[allow(dead_code)] // retained for completeness; not used in the responder path
const FCGI_ABORT_REQUEST: u8 = 2;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;
#[allow(dead_code)]
const FCGI_DATA: u8 = 8;

/// FastCGI roles (we only use Responder, role=1).
const FCGI_RESPONDER: u16 = 1;

/// We always use request-id 1 because every `FcgiClient` owns one transport
/// connection and runs exactly one request on it before tearing down.
const FCGI_REQUEST_ID: u16 = 1;

/// The header is exactly 8 bytes: version(1), type(1), request_id(2 BE),
/// content_length(2 BE), padding_length(1), reserved(1).
const FCGI_HEADER_LEN: usize = 8;

/// The largest payload that fits in one record (the `content_length` field
/// is u16, so the maximum is 65535). PARAMS and STDIN payloads bigger than
/// this must be split across multiple records.
const FCGI_MAX_BODY: usize = 65_535;

/// Default upstream port used when the URL does not specify one (matches
/// PHP-FPM's typical default).
const FCGI_DEFAULT_TCP_PORT: u16 = 9000;

/// Static FCGI_PARAMS payload that every FastCGI request includes — these
/// three values are constant for every HeavyThing request and are pre-packed
/// here as raw bytes (length byte, length byte, name, value) per the FastCGI
/// 1.0 spec §3.4 nv-pair encoding (1-byte form, since all lengths are <128).
///
/// The exact byte layout matches the FASM `.staticparams` declaration at
/// `fcgiclient.inc` line ~750:
///   db 15,8, "SERVER_PROTOCOL", "HTTP/1.1",
///      17,7, "GATEWAY_INTERFACE", "CGI/1.1",
///      15,10, "SERVER_SOFTWARE", "HeavyThing"
const STATIC_PARAMS: &[u8] = b"\x0f\x08\
SERVER_PROTOCOLHTTP/1.1\
\x11\x07\
GATEWAY_INTERFACECGI/1.1\
\x0f\x0a\
SERVER_SOFTWAREHeavyThing";

// ---------------------------------------------------------------------------
// Static pre-built initial record (BEGIN_REQUEST)
// ---------------------------------------------------------------------------

/// Pre-built FCGI_BEGIN_REQUEST record (16 bytes total: 8-byte header + 8-byte
/// body). Caching this avoids rebuilding identical bytes on every spawn —
/// preserves the `fcgiclient$initial_buffer` optimization noted in the FASM
/// source.
///
/// Bytes:
///   [0]   0x01   version = 1
///   [1]   0x01   record type = FCGI_BEGIN_REQUEST
///   [2..4] 00 01 request_id = 1 (big-endian)
///   [4..6] 00 08 content_length = 8 (big-endian)
///   [6]   0x00   padding_length = 0
///   [7]   0x00   reserved
///   [8..10] 00 01 role = FCGI_RESPONDER (big-endian)
///   [10]  0x00   flags = 0
///   [11..16] 00 00 00 00 00  reserved
pub(crate) fn initial_buffer() -> &'static Bytes {
    static INITIAL: Lazy<Bytes> = Lazy::new(|| {
        let mut buf = BytesMut::with_capacity(16);
        // 8-byte BEGIN_REQUEST record header
        buf.put_u8(FCGI_VERSION_1);
        buf.put_u8(FCGI_BEGIN_REQUEST);
        buf.put_u16(FCGI_REQUEST_ID);
        buf.put_u16(8); // content length (the body is exactly 8 bytes)
        buf.put_u8(0); // padding length
        buf.put_u8(0); // reserved
                       // 8-byte BEGIN_REQUEST body
        buf.put_u16(FCGI_RESPONDER);
        buf.put_u8(0); // flags
        buf.put_slice(&[0u8; 5]); // reserved
        debug_assert_eq!(buf.len(), 16);
        buf.freeze()
    });
    &INITIAL
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Outcome of a FastCGI request, delivered to the caller's [`FcgiCallback`].
///
/// The three variants mirror the three terminal states of the FASM source:
///   - `Response`: the backend completed normally and we parsed (or simply
///     accumulated) its `FCGI_STDOUT` stream.
///   - `TransportError`: a connect / read / write / DNS / timeout failure.
///   - `ProtocolError`: the backend sent malformed FastCGI framing
///     (version != 1, unknown record type, truncated body, etc.).
pub enum FcgiResult {
    /// Backend completed successfully. When [`WEBSERVER_FASTCGI_POSTPROCESS`]
    /// is true, this carries a fully-parsed [`Mimelike`]; when false (the
    /// default), the carried [`Mimelike`] holds the raw stdout bytes in its
    /// body and an empty header set, leaving downstream parsing to the
    /// caller (this matches the FASM "stream-through" mode).
    Response(Mimelike),
    /// Transport-level failure: DNS resolution, TCP/Unix connect, read, write,
    /// or idle-timeout expiry. The contained [`NetError`] preserves the
    /// underlying [`std::io::Error`] kind for caller inspection.
    TransportError(NetError),
    /// Protocol-level failure: the backend's bytes did not parse as a valid
    /// FastCGI 1.0 stream.
    ProtocolError(HttpError),
}

/// One-shot callback signature delivered when the request completes.
///
/// Arguments:
///   1. `callback_arg` — the opaque `usize` provided to [`FcgiClient::spawn`].
///      Mirrors `fcgiclient_callbackarg_ofs` from the FASM source.
///   2. `result` — the [`FcgiResult`] outcome.
///   3. `elapsed_ms` — milliseconds elapsed since the [`FcgiClient::spawn`]
///      call (replaces the FASM `rdtsc`-based timing).
///
/// The callback is `FnOnce` because each `FcgiClient` fires it at most once.
/// Implementations MUST NOT call [`drop`] on the originating `FcgiClient` from
/// inside the callback (this matches the FASM caveat); to release any caller
/// state, schedule a follow-up via `tokio::spawn`.
pub type FcgiCallback = Box<dyn FnOnce(usize, FcgiResult, u64) + Send>;

// ---------------------------------------------------------------------------
// Internal: param-length encoding helpers
// ---------------------------------------------------------------------------

/// Append a FastCGI 1.0 nv-pair length value to `buf`.
///
/// Per the FastCGI 1.0 spec §3.4: lengths under 128 use the 1-byte form
/// (single byte = length); lengths 128 and above use the 4-byte form (length
/// stored as a 32-bit big-endian unsigned, with the high bit of the first byte
/// set to 1 to distinguish it from the 1-byte form).
///
/// This mirrors the FASM `addparam` four-way dispatch (bothsmall, bigname,
/// bigvalue, bothbig) and the `bswap eax | or eax, 0x80` pattern used to
/// produce the 4-byte big-endian form.
fn put_param_len(buf: &mut BytesMut, len: usize) {
    if len < 128 {
        buf.put_u8(len as u8);
    } else {
        // 4-byte form: high bit of first byte set, remainder is 32-bit BE.
        // Safe cast: len is bounded by Mimelike header size limits well below
        // u32::MAX (FastCGI maximum is 2^31-1 since the high bit is the flag).
        let v = (len as u32) | 0x8000_0000;
        buf.put_u32(v);
    }
}

/// Append a single name/value pair to a FastCGI PARAMS payload.
///
/// `name` MUST be ASCII (CGI variable names are restricted to upper-case
/// letters, digits, and `_`); `value` may contain any bytes.
fn append_nv_pair(buf: &mut BytesMut, name: &[u8], value: &[u8]) {
    put_param_len(buf, name.len());
    put_param_len(buf, value.len());
    buf.put_slice(name);
    buf.put_slice(value);
}

// ---------------------------------------------------------------------------
// Internal: HTTP request → FastCGI request encoding
// ---------------------------------------------------------------------------

/// Extract the HTTP request method (GET / HEAD / POST / etc.) from a
/// [`Mimelike`] request. The FASM source stored a method code in
/// `mimelike_user_ofs` (0 = GET, 1 = HEAD, 2 = POST). The Rust port checks
/// `user_bytes()[0]` for that code first; if it is one of the three known
/// values we use the canonical uppercase string. Otherwise we fall back to
/// parsing the request line (preface) and extracting the method token.
///
/// Returns `("GET", false)` when the method cannot be determined; callers use
/// the boolean to decide whether to emit CONTENT_LENGTH / CONTENT_TYPE
/// headers (which are only meaningful on POST-style requests).
fn request_method_for(req: &Mimelike) -> (&'static str, bool /* is_post */) {
    let code = req.user_bytes()[0];
    match code {
        0 => return ("GET", false),
        1 => return ("HEAD", false),
        2 => return ("POST", true),
        _ => { /* fallthrough: try preface parse */ }
    }
    // Fallback: parse the request line preface, e.g. "GET /path HTTP/1.1".
    if let Some(line) = req.preface() {
        let token = line.split([' ', '\t']).next().unwrap_or("");
        // Map known methods to their static interned forms; unknown methods
        // are treated as GET-equivalent for FastCGI purposes (no body).
        match token {
            "GET" => ("GET", false),
            "HEAD" => ("HEAD", false),
            "POST" => ("POST", true),
            "PUT" => ("PUT", true),
            "DELETE" => ("DELETE", false),
            "PATCH" => ("PATCH", true),
            "OPTIONS" => ("OPTIONS", false),
            _ => ("GET", false),
        }
    } else {
        ("GET", false)
    }
}

/// Convert an HTTP header name to its CGI environment-variable form per
/// RFC 3875 §4.1.18: prepend "HTTP_", uppercase ASCII letters, replace `-`
/// with `_`. Result is appended to `out` to avoid extra allocations.
///
/// Mirrors the FASM `.addheader` routine which built `HTTP_` + uppercase +
/// dash-to-underscore in-place.
fn append_cgi_header_name(out: &mut Vec<u8>, name: &str) {
    out.clear();
    out.extend_from_slice(b"HTTP_");
    for byte in name.bytes() {
        let mapped = match byte {
            b'-' => b'_',
            b'a'..=b'z' => byte - 0x20, // ASCII to upper
            other => other,
        };
        out.push(mapped);
    }
}

/// Build the complete FastCGI PARAMS payload (without record headers — the
/// caller wraps the bytes in records and applies length / padding).
///
/// The CGI variable set matches the FASM source (`fcgiclient.inc` lines
/// ~80–375): SCRIPT_FILENAME, SCRIPT_NAME, DOCUMENT_URI, REQUEST_URI,
/// QUERY_STRING, REQUEST_METHOD, optional CONTENT_TYPE/CONTENT_LENGTH on POST,
/// optional REMOTE_ADDR/REMOTE_PORT (drained from the request headers),
/// SERVER_NAME, SERVER_PORT, optional HTTPS=on, then HTTP_* headers.
fn build_params_payload(url: &Url, request: &Mimelike) -> BytesMut {
    let mut buf = BytesMut::with_capacity(1024);
    let mut name_scratch: Vec<u8> = Vec::with_capacity(64);

    // ---- Static prefix (SERVER_PROTOCOL, GATEWAY_INTERFACE, SERVER_SOFTWARE)
    //
    // These three values are constant for every request; the FASM source
    // pre-packs them into a 78-byte literal. We reuse the same literal here
    // for byte-identical wire output.
    buf.put_slice(STATIC_PARAMS);

    // ---- DOCUMENT_ROOT, SCRIPT_FILENAME, SCRIPT_NAME, DOCUMENT_URI, REQUEST_URI
    //
    // The webserver layer is expected to have populated DOCUMENT_ROOT into
    // the request headers before invoking the FastCGI client (the FASM
    // comment states this explicitly: "DOCUMENT_ROOT got added to our
    // request object before the call to here"). If it is missing we
    // synthesize an empty value to keep wire framing intact.
    let doc_root = request.get_header("DOCUMENT_ROOT").unwrap_or("");
    append_nv_pair(&mut buf, b"DOCUMENT_ROOT", doc_root.as_bytes());

    // SCRIPT_FILENAME = DOCUMENT_ROOT + url.file()
    let url_file = url.file();
    let mut script_filename = Vec::with_capacity(doc_root.len() + url_file.len());
    script_filename.extend_from_slice(doc_root.as_bytes());
    script_filename.extend_from_slice(url_file.as_bytes());
    append_nv_pair(&mut buf, b"SCRIPT_FILENAME", &script_filename);

    // SCRIPT_NAME and DOCUMENT_URI are both the URL file component.
    append_nv_pair(&mut buf, b"SCRIPT_NAME", url_file.as_bytes());
    append_nv_pair(&mut buf, b"DOCUMENT_URI", url_file.as_bytes());

    // REQUEST_URI = url.file() + "?" + query (when query is non-empty).
    let query = url.query();
    if query.is_empty() {
        append_nv_pair(&mut buf, b"REQUEST_URI", url_file.as_bytes());
    } else {
        let mut request_uri = Vec::with_capacity(url_file.len() + 1 + query.len());
        request_uri.extend_from_slice(url_file.as_bytes());
        request_uri.push(b'?');
        request_uri.extend_from_slice(query.as_bytes());
        append_nv_pair(&mut buf, b"REQUEST_URI", &request_uri);
    }

    // QUERY_STRING (always emitted, possibly empty).
    append_nv_pair(&mut buf, b"QUERY_STRING", query.as_bytes());

    // REQUEST_METHOD
    let (method, is_post) = request_method_for(request);
    append_nv_pair(&mut buf, b"REQUEST_METHOD", method.as_bytes());

    // CONTENT_TYPE / CONTENT_LENGTH — populated on POST (and POST-like) when
    // the request body has a value; otherwise emitted as empty values to
    // satisfy CGI environment expectations.
    if is_post {
        let ctype = request.get_header("Content-Type").unwrap_or("");
        append_nv_pair(&mut buf, b"CONTENT_TYPE", ctype.as_bytes());
        let clen = request.get_header("Content-Length").unwrap_or("");
        append_nv_pair(&mut buf, b"CONTENT_LENGTH", clen.as_bytes());
    } else {
        append_nv_pair(&mut buf, b"CONTENT_TYPE", b"");
        append_nv_pair(&mut buf, b"CONTENT_LENGTH", b"");
    }

    // REMOTE_ADDR / REMOTE_PORT — when the webserver layer has injected them
    // into the request headers we use them; otherwise we leave them empty.
    let remote_addr = request.get_header("REMOTE_ADDR").unwrap_or("");
    append_nv_pair(&mut buf, b"REMOTE_ADDR", remote_addr.as_bytes());
    let remote_port = request.get_header("REMOTE_PORT").unwrap_or("");
    append_nv_pair(&mut buf, b"REMOTE_PORT", remote_port.as_bytes());

    // SERVER_NAME / SERVER_PORT come straight from the URL. Note: we use
    // `url.port()` (the explicit port, possibly 0) rather than
    // `url.effective_port()` (which would substitute scheme defaults like 80
    // / 443) because the FASM source reads the explicit field at
    // `url_port_ofs` directly and converts it to its decimal-string form.
    append_nv_pair(&mut buf, b"SERVER_NAME", url.host().as_bytes());
    let port_str = format!("{}", url.port());
    append_nv_pair(&mut buf, b"SERVER_PORT", port_str.as_bytes());

    // HTTPS = "on" when the URL scheme indicates TLS. The FASM source
    // checked `url_protocol_ofs == "https"` exactly; we replicate that
    // case-sensitive comparison here.
    if url.protocol() == "https" {
        append_nv_pair(&mut buf, b"HTTPS", b"on");
    }

    // HTTP_* headers — every request header except the ones we consumed
    // above (DOCUMENT_ROOT, REMOTE_ADDR, REMOTE_PORT, Content-Type,
    // Content-Length) gets emitted with the HTTP_ prefix and case
    // normalization applied.
    for (header_name, header_value) in request.headers.iter_pairs() {
        // Skip headers that are already represented by dedicated CGI vars;
        // matching is case-insensitive per RFC 7230.
        if header_name.eq_ignore_ascii_case("Content-Type")
            || header_name.eq_ignore_ascii_case("Content-Length")
            || header_name.eq_ignore_ascii_case("REMOTE_ADDR")
            || header_name.eq_ignore_ascii_case("REMOTE_PORT")
            || header_name.eq_ignore_ascii_case("DOCUMENT_ROOT")
        {
            continue;
        }
        append_cgi_header_name(&mut name_scratch, header_name);
        append_nv_pair(&mut buf, &name_scratch, header_value.as_bytes());
    }

    buf
}

/// Wrap a raw payload in one or more FastCGI records of the given `record_type`
/// (PARAMS or STDIN), appending each record (header + body + padding) to
/// `out`. Splits at [`FCGI_MAX_BODY`] (65,535) so even oversized payloads are
/// emitted correctly.
///
/// After the payload chunks, an empty record of the same type is appended to
/// signal end-of-stream — this is the FastCGI convention that PHP-FPM and
/// other backends use to know that no further bytes will follow on this
/// stream.
fn append_stream_records(out: &mut BytesMut, record_type: u8, payload: &[u8]) {
    let mut remaining = payload;
    while !remaining.is_empty() {
        let chunk_len = remaining.len().min(FCGI_MAX_BODY);
        // Safe cast: chunk_len <= 65_535 fits in u16.
        let clen = chunk_len as u16;
        let plen = padding_for(clen);
        put_record_header(out, record_type, clen, plen);
        out.put_slice(&remaining[..chunk_len]);
        if plen > 0 {
            // SAFETY: BytesMut has reserve() available; we use put_slice
            // with a static zero buffer (max 7 bytes) to keep the math simple.
            out.put_slice(&[0u8; 7][..plen as usize]);
        }
        remaining = &remaining[chunk_len..];
    }
    // Empty terminating record (zero-length signals end-of-stream).
    put_record_header(out, record_type, 0, 0);
}

/// Encode the entire FastCGI request stream that will be written to the
/// upstream backend as a single byte sequence:
///   1. BEGIN_REQUEST (16 bytes — pre-built and cloned from `initial_buffer()`)
///   2. PARAMS records (CGI environment, possibly multi-record + empty
///      terminator)
///   3. STDIN records (only when the request has a body — possibly
///      multi-record + empty terminator; for non-POST requests we send an
///      immediate empty-STDIN terminator).
fn encode_request(url: &Url, request: &Mimelike) -> BytesMut {
    let params_payload = build_params_payload(url, request);

    // Optimistic capacity: BEGIN(16) + PARAMS(payload + 8 header * ceil(N/65535)
    // + 8 terminator + padding) + STDIN(body + headers + terminator).
    let body = request.body_bytes();
    let cap = 16 + params_payload.len() + 16 + body.len() + 16 + 64; // small slack for padding
    let mut out = BytesMut::with_capacity(cap);

    // 1. BEGIN_REQUEST — clone the pre-built static.
    out.put_slice(initial_buffer());

    // 2. PARAMS stream
    append_stream_records(&mut out, FCGI_PARAMS, &params_payload);

    // 3. STDIN stream — emit body chunks (if any), then empty terminator.
    //    Non-POST requests still get an empty STDIN terminator so the backend
    //    knows the body stream is closed.
    let (_, is_post) = request_method_for(request);
    if is_post && !body.is_empty() {
        append_stream_records(&mut out, FCGI_STDIN, body);
    } else {
        // Just the empty terminator.
        put_record_header(&mut out, FCGI_STDIN, 0, 0);
    }

    out
}
// ---------------------------------------------------------------------------
// Internal: record-header helpers
// ---------------------------------------------------------------------------

/// Build an 8-byte FastCGI record header with the supplied parameters.
///
/// `padding_len` is computed by the caller to make the (header + body +
/// padding) length a multiple of 8 bytes — the spec recommends but does not
/// require padding; the FASM source aligns every record to 8 bytes (preserved
/// here) for parity with downstream PHP-FPM behavior under load.
fn put_record_header(buf: &mut BytesMut, record_type: u8, content_len: u16, padding_len: u8) {
    buf.put_u8(FCGI_VERSION_1);
    buf.put_u8(record_type);
    buf.put_u16(FCGI_REQUEST_ID);
    buf.put_u16(content_len);
    buf.put_u8(padding_len);
    buf.put_u8(0); // reserved
}

/// Compute the padding bytes required so that (8 + content_len) is a multiple
/// of 8. Returns a value in 0..=7.
fn padding_for(content_len: u16) -> u8 {
    // The header is already 8 bytes (a multiple of 8) so padding only depends
    // on `content_len`. Total = 8 + content_len + padding ≡ 0 (mod 8).
    let rem = (content_len & 7) as u8;
    if rem == 0 {
        0
    } else {
        8 - rem
    }
}

// ---------------------------------------------------------------------------
// Internal: inbound record parsing
// ---------------------------------------------------------------------------

/// A single decoded FastCGI record extracted from the inbound byte stream.
///
/// `payload` borrows from the parser's accumulator; the caller copies it into
/// the appropriate destination buffer (stdout / stderr) before resuming.
struct ParsedRecord<'a> {
    record_type: u8,
    payload: &'a [u8],
    /// Total bytes consumed (8 header + content + padding) — used by the
    /// caller to advance the accumulator.
    consumed: usize,
}

/// Outcome of attempting to parse one record from an accumulator.
enum ParseOutcome<'a> {
    /// A complete record was decoded.
    Record(ParsedRecord<'a>),
    /// Not enough bytes — caller should read more from the transport.
    NeedMore,
    /// Frame is malformed (version != 1 or other structural error).
    Invalid(&'static str),
}

/// Attempt to parse a single FastCGI record from the start of `accumulator`.
/// On `Record`, the caller is responsible for advancing the accumulator by
/// `record.consumed` bytes after handling the payload.
fn parse_record(accumulator: &[u8]) -> ParseOutcome<'_> {
    if accumulator.len() < FCGI_HEADER_LEN {
        return ParseOutcome::NeedMore;
    }
    // The FASM source enforces version == 1 strictly:
    //     cmp byte [r12], 1
    //     jne .error
    if accumulator[0] != FCGI_VERSION_1 {
        return ParseOutcome::Invalid("invalid FastCGI version");
    }
    let record_type = accumulator[1];
    // request_id at [2..4] is ignored — we only ever issue request_id=1 and
    // the FASM source likewise didn't validate it on the inbound path.
    let content_len = u16::from_be_bytes([accumulator[4], accumulator[5]]) as usize;
    let padding_len = accumulator[6] as usize;
    // accumulator[7] is reserved.
    let total = FCGI_HEADER_LEN + content_len + padding_len;
    if accumulator.len() < total {
        return ParseOutcome::NeedMore;
    }
    let payload = &accumulator[FCGI_HEADER_LEN..FCGI_HEADER_LEN + content_len];
    ParseOutcome::Record(ParsedRecord {
        record_type,
        payload,
        consumed: total,
    })
}

/// Internal state of an inbound parser. Accumulates raw bytes from the
/// transport and produces parsed records as they become available; tracks
/// stdout / stderr byte streams separately and reports when an
/// `FCGI_END_REQUEST` has been observed.
struct InboundState {
    /// Bytes received from the transport but not yet parsed (or, partially
    /// parsed at the trailing edge).
    accumulator: Vec<u8>,
    /// FCGI_STDOUT bytes accumulated for this request.
    stdout: Buffer,
    /// FCGI_STDERR bytes accumulated for this request. When
    /// [`WEBSERVER_FASTCGI_POSTPROCESS`] is `false` (the default) these bytes
    /// are also forwarded line-by-line to syslog as warnings.
    errbuf: Buffer,
    /// True once an `FCGI_END_REQUEST` record has been observed; signals the
    /// driver loop to stop reading and fire the callback.
    end_seen: bool,
}

impl InboundState {
    fn new() -> Self {
        Self {
            accumulator: Vec::with_capacity(8 * 1024),
            stdout: Buffer::new(),
            errbuf: Buffer::new(),
            end_seen: false,
        }
    }

    /// Feed a freshly-read byte chunk into the parser, advancing internal
    /// state. Returns `Ok(())` on success, `Err(HttpError::FastCgi)` on a
    /// malformed frame.
    fn feed(&mut self, chunk: &[u8]) -> Result<(), HttpError> {
        if chunk.is_empty() {
            return Ok(());
        }
        self.accumulator.extend_from_slice(chunk);

        // Drain as many complete records as we have. We track a cursor and
        // only retain trailing partial bytes for the next read.
        let mut cursor = 0usize;
        loop {
            let view = &self.accumulator[cursor..];
            match parse_record(view) {
                ParseOutcome::NeedMore => break,
                ParseOutcome::Invalid(msg) => {
                    return Err(HttpError::FastCgi(msg.to_string()));
                }
                ParseOutcome::Record(record) => {
                    let advance = record.consumed;
                    match record.record_type {
                        FCGI_STDOUT => {
                            self.stdout.extend_from_slice(record.payload);
                        }
                        FCGI_STDERR => {
                            self.errbuf.extend_from_slice(record.payload);
                            // Stream-through mode: when the post-process flag
                            // is OFF (the HeavyThing default), forward stderr
                            // to syslog so backend warnings/errors land in
                            // /var/log without requiring a separate audit
                            // path. Best-effort; failure of syslog is silent.
                            if !WEBSERVER_FASTCGI_POSTPROCESS {
                                forward_stderr_to_syslog(record.payload);
                            }
                        }
                        FCGI_END_REQUEST => {
                            // Per the FASM source, the body of an
                            // FCGI_END_REQUEST record carries `appStatus`
                            // (4 bytes BE) and `protocolStatus` (1 byte).
                            // The FASM comment explicitly stated:
                            //     "we don't really care what the exit code
                            //      is from the fastcgi layer, just pass it
                            //      off to our callback"
                            // — so we simply mark end-seen and stop.
                            self.end_seen = true;
                            cursor += advance;
                            break;
                        }
                        // Anything else (including ABORT_REQUEST=2 echoed,
                        // PARAMS=4, STDIN=5, DATA=8, or unknown record types)
                        // is invalid inbound from the FASM source's view.
                        _ => {
                            return Err(HttpError::FastCgi(format!(
                                "unexpected inbound record type {}",
                                record.record_type
                            )));
                        }
                    }
                    cursor += advance;
                }
            }
        }

        // Drop the consumed prefix; retain any trailing partial bytes for the
        // next feed() call.
        if cursor > 0 {
            self.accumulator.drain(..cursor);
        }
        Ok(())
    }
}

/// Forward a chunk of FCGI_STDERR bytes to syslog as one or more warning-level
/// log entries, splitting on `\n` so that multiline backend output (e.g. PHP
/// error stack traces) lands as discrete syslog records. UTF-8 decode is
/// best-effort; any invalid sequences are replaced with U+FFFD via
/// [`String::from_utf8_lossy`]. Empty trailing lines are skipped.
fn forward_stderr_to_syslog(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for line in text.split('\n') {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() {
            continue;
        }
        syslog::warning(trimmed);
    }
}

// ---------------------------------------------------------------------------
// Internal: transport abstraction (TCP vs Unix socket)
// ---------------------------------------------------------------------------

/// Wraps the two possible upstream transports behind a single read/write
/// surface so the request-driver code does not have to be generic over the
/// concrete `tokio::net::*Stream` type. Mirrors the FASM source's transparent
/// handling of either transport via the epoll_inbuf abstraction.
enum Transport {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Transport {
    /// Send the entire byte slice to the backend, returning on success only
    /// when every byte has been written. Maps the `tokio` `io::Error` into a
    /// [`NetError::Io`] for caller convenience.
    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), NetError> {
        match self {
            Self::Tcp(s) => s.write_all(bytes).await.map_err(NetError::Io),
            Self::Unix(s) => s.write_all(bytes).await.map_err(NetError::Io),
        }
    }

    /// Best-effort flush before close. Failures are mapped through
    /// `NetError::Io` but most transports are connection-oriented and flush
    /// is typically a no-op.
    async fn flush(&mut self) -> Result<(), NetError> {
        match self {
            Self::Tcp(s) => s.flush().await.map_err(NetError::Io),
            Self::Unix(s) => s.flush().await.map_err(NetError::Io),
        }
    }

    /// Read up to `buf.len()` bytes from the backend, returning the number of
    /// bytes actually read. A return of `Ok(0)` indicates clean EOF.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        match self {
            Self::Tcp(s) => s.read(buf).await.map_err(NetError::Io),
            Self::Unix(s) => s.read(buf).await.map_err(NetError::Io),
        }
    }
}

/// Resolve the URL into a connected [`Transport`], applying the
/// [`EPOLL_NODELAY`] flag on the TCP path for parity with the FASM
/// `epoll$add` initialization that did the same on every accepted/connected
/// socket. Selection logic mirrors the agent prompt's "Transport Selection"
/// section:
///   * `unix`           → connect to `url.path()` as a Unix domain socket
///   * `fcgi` / `tcp` / `""` → connect over TCP after DNS resolution of
///     `url.host():url.effective_port()`
///   * anything else    → return [`HttpError::FastCgi`]
async fn connect_upstream(url: &Url) -> Result<Transport, NetError> {
    let scheme = url.protocol();
    if scheme == "unix" {
        // Unix domain socket — url.path() carries the filesystem path
        // (e.g. /var/run/php-fpm.sock).
        let raw_path = url.path();
        // url::Path returns the path with a leading slash already; pass
        // through as-is.
        let path: &Path = Path::new(raw_path);
        let stream = UnixStream::connect(path).await.map_err(NetError::Io)?;
        return Ok(Transport::Unix(stream));
    }
    if scheme.is_empty() || scheme == "fcgi" || scheme == "tcp" {
        // TCP — resolve the hostname, default to FCGI_DEFAULT_TCP_PORT (9000)
        // when the URL omits an explicit port.
        let host = url.host();
        let url_port = url.port();
        let port = if url_port == 0 {
            FCGI_DEFAULT_TCP_PORT
        } else {
            url_port
        };
        let resolver = DnsResolver::new();
        let addrs: Vec<SocketAddr> = resolver.lookup_host(host, port).await?;
        if addrs.is_empty() {
            return Err(NetError::Dns(format!(
                "no addresses resolved for upstream FastCGI host '{}'",
                host
            )));
        }
        // Use the first resolved address — matches the FASM source which
        // also took the first DNS result.
        let stream = TcpStream::connect(addrs[0]).await.map_err(NetError::Io)?;
        if EPOLL_NODELAY {
            // Best-effort; failure to set TCP_NODELAY is not fatal.
            let _ = stream.set_nodelay(true);
        }
        return Ok(Transport::Tcp(stream));
    }
    Err(NetError::Http(HttpError::FastCgi(format!(
        "unsupported FastCGI URL scheme '{}'",
        scheme
    ))))
}

// ---------------------------------------------------------------------------
// FcgiClient struct
// ---------------------------------------------------------------------------

/// Lock-protected mutable state of an `FcgiClient`. We use `std::sync::Mutex`
/// rather than `tokio::sync::Mutex` because every critical section is short
/// (a `take()` of an `Option`, a slice copy, or a flag flip) and never
/// crosses an `.await` point — the synchronous mutex avoids the overhead of
/// the async one.
struct Inner {
    /// Once the request completes, the driver task or `Drop` impl takes the
    /// callback and invokes it with the appropriate [`FcgiResult`]. After
    /// the callback fires, the slot is left as `None` to enforce one-shot
    /// firing semantics.
    callback: Option<FcgiCallback>,
    /// Pre-encoded outbound byte stream (BEGIN_REQUEST + PARAMS + STDIN +
    /// terminators). Built once during [`FcgiClient::spawn`] and consumed in
    /// the driver task during the connect-and-write phase.
    outbound: BytesMut,
    /// Accumulated FCGI_STDOUT bytes used by the API-parity
    /// [`FcgiClient::on_received`] hook. The real driver task accumulates
    /// stdout in a task-local [`InboundState`] instead, but this field
    /// preserves the FASM `buffer_ofs` slot so callers writing custom
    /// drive loops (e.g. integration tests) can observe the bytes that
    /// they have fed in. Inspect via [`FcgiClient::stdout_bytes`].
    stdout: Buffer,
    /// Accumulated FCGI_STDERR bytes (mirrors the FASM `errbuf_ofs` field).
    /// In the default mode ([`WEBSERVER_FASTCGI_POSTPROCESS`] = `false`)
    /// stderr also streams to syslog as warnings; the buffer is retained
    /// here for potential post-process inspection. Read via
    /// [`FcgiClient::errbuf_bytes`].
    errbuf: Buffer,
    /// Caller-extensible field — the FASM source named this `user_ofs`. The
    /// Rust port preserves the field for API parity but does not interpret
    /// its value. Callers may set it via [`FcgiClient::set_user`].
    user: usize,
}

/// FastCGI client that proxies a single HTTP request to an upstream FastCGI
/// backend (typically PHP-FPM) over either a TCP connection or a Unix domain
/// socket and delivers the outcome to a one-shot callback.
///
/// Construction: call [`FcgiClient::spawn`]. The returned `Arc<FcgiClient>`
/// is detached — the caller may drop it immediately and the spawned task
/// will continue to drive the request to completion (the callback fires
/// regardless of whether the caller still holds a reference).
///
/// Lifecycle: see the FASM `fcgiclient.inc` source for the canonical state
/// machine. In one-line summary:
///   spawn → connect → write(BEGIN+PARAMS+STDIN) → read(STDOUT/STDERR) →
///   END_REQUEST → callback → drop
///
/// Thread safety: `FcgiClient` is `Send + Sync` because all mutable state is
/// behind an internal `Mutex`. Multiple threads may hold `Arc` references but
/// only the driver task ever touches the inner state.
///
/// Drop semantics: if the `Arc` is dropped while a request is in-flight (i.e.
/// before the callback has fired), the [`Drop`] impl synthesizes a
/// `FcgiResult::TransportError(NetError::Io(ConnectionReset))` and fires the
/// callback. This guarantees that callers holding a result-sender via
/// `callback_arg` always receive exactly one notification.
pub struct FcgiClient {
    /// The upstream backend URL.
    url: Arc<Url>,
    /// The HTTP request being proxied.
    #[allow(dead_code)] // Retained for caller introspection / future feature gates.
    request: Arc<Mimelike>,
    /// Mutable state (callback, output buffers, stderr accumulator, user
    /// extension field).
    inner: Mutex<Inner>,
    /// Opaque value passed back to the callback as its first argument.
    /// Mirrors the FASM `fcgiclient_callbackarg_ofs` field.
    callback_arg: usize,
    /// Wall-clock instant of [`FcgiClient::spawn`], used to compute the
    /// `elapsed_ms` argument passed to the callback. Replaces the FASM
    /// `rdtsc` cycle counter pattern with millisecond resolution.
    start_time: Instant,
}

// SAFETY: All mutable state is wrapped in a `Mutex<Inner>` and the
// `callback_arg`/`start_time` fields are `Copy`/`Sync` already. The
// `Arc<Url>` and `Arc<Mimelike>` fields are `Send + Sync` because their
// underlying types are. Callbacks are `FnOnce + Send` (see [`FcgiCallback`]).
// The auto-derived `Send + Sync` bounds therefore hold without further
// `unsafe impl` declarations.

impl FcgiClient {
    /// Create a new FastCGI client and spawn its driver task.
    ///
    /// Arguments:
    ///   * `url` — backend address (`unix:///path/to/socket`, `fcgi://host:port`,
    ///     `tcp://host:port`, or schemeless `host:port`).
    ///   * `request` — the HTTP request to proxy. Its method, URI, headers,
    ///     and body are encoded into the FastCGI environment and stdin.
    ///   * `callback` — one-shot result handler. Invoked exactly once with
    ///     `(callback_arg, result, elapsed_ms)`.
    ///   * `callback_arg` — opaque value forwarded as the callback's first
    ///     argument.
    ///
    /// Returns an `Arc<FcgiClient>` for caller introspection (set/get
    /// extensible `user` field, observe URL). The driver task holds its own
    /// `Arc` clone, so the caller may drop the returned value immediately
    /// without affecting the in-flight request.
    ///
    /// Errors: this function only returns `Err` for synchronous setup
    /// failures (none today, since transport setup happens inside the task).
    /// All transport / DNS / protocol errors are delivered asynchronously
    /// via the callback as `FcgiResult::TransportError` or
    /// `FcgiResult::ProtocolError`.
    pub fn spawn(
        url: Arc<Url>,
        request: Arc<Mimelike>,
        callback: FcgiCallback,
        callback_arg: usize,
    ) -> Result<Arc<Self>, NetError> {
        // Encode the entire outbound byte stream up-front. This mirrors the
        // FASM `fcgiclient$new` strategy of pre-building `buffer_ofs` so the
        // connect callback can dispatch the request in a single write.
        let outbound = encode_request(&url, &request);

        let client = Arc::new(Self {
            url,
            request,
            inner: Mutex::new(Inner {
                callback: Some(callback),
                outbound,
                stdout: Buffer::with_capacity(8 * 1024),
                errbuf: Buffer::new(),
                user: 0,
            }),
            callback_arg,
            start_time: Instant::now(),
        });

        // Spawn the driver task. It holds an `Arc` clone of the client so the
        // request continues even if the caller drops the returned handle.
        let task_client = Arc::clone(&client);
        tokio::spawn(async move {
            let outcome = Self::drive_request(&task_client).await;
            // Fire the callback exactly once with whatever outcome we
            // accumulated. If the callback was already taken (e.g. by the
            // Drop impl in a racey shutdown), this is a no-op.
            task_client.fire_callback(outcome);
        });

        Ok(client)
    }

    /// Caller-facing accessor for the configured upstream URL. Useful for
    /// tracing / logging. Returns the `Arc<Url>` so callers can clone cheaply.
    #[must_use]
    pub fn url(&self) -> Arc<Url> {
        Arc::clone(&self.url)
    }

    /// Set the extensible `user` field. Mirrors the FASM `user_ofs` slot.
    /// Callers may use this to attach a request-id or other diagnostic value
    /// that they want surfaced via the callback's `callback_arg` semantics.
    pub fn set_user(&self, user: usize) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.user = user;
        }
    }

    /// Read the extensible `user` field.
    #[must_use]
    pub fn user(&self) -> usize {
        self.inner.lock().map(|g| g.user).unwrap_or(0)
    }

    /// Read the bytes accumulated via [`FcgiClient::on_received`]. Useful
    /// for integration tests that drive the FastCGI parser manually rather
    /// than letting the spawned task handle the transport. Returns an empty
    /// `Vec` if the inner mutex is poisoned (extremely rare).
    #[must_use]
    pub fn stdout_bytes(&self) -> Vec<u8> {
        match self.inner.lock() {
            Ok(g) => g.stdout.as_slice().to_vec(),
            Err(_) => Vec::new(),
        }
    }

    /// Read the bytes accumulated in the stderr buffer (FCGI_STDERR record
    /// payload from the upstream backend). Even when the
    /// [`WEBSERVER_FASTCGI_POSTPROCESS`] flag forwards stderr to syslog,
    /// this method returns the same bytes for caller inspection.
    #[must_use]
    pub fn errbuf_bytes(&self) -> Vec<u8> {
        match self.inner.lock() {
            Ok(g) => g.errbuf.as_slice().to_vec(),
            Err(_) => Vec::new(),
        }
    }

    /// Connect-completion hook. The FASM source's `fcgiclient$connected`
    /// dispatched the queued buffer to the upstream socket. In the Rust port
    /// the equivalent happens inside [`drive_request`]; this method is
    /// retained as a `pub(crate)` API-parity slot per the [`FcgiClient`]
    /// schema.
    ///
    /// Calling this method on a live `FcgiClient` is a no-op — the driver
    /// task has already taken responsibility for the connect-and-write
    /// sequence.
    pub(crate) async fn on_connected(&self) -> Result<(), NetError> {
        // Intentionally a no-op. The FASM source emitted the buffer here;
        // the Rust async driver handles connect + write inline.
        Ok(())
    }

    /// Inbound-data hook. The FASM source's `fcgiclient$received` parsed
    /// records from the inbound buffer and dispatched STDOUT / STDERR /
    /// END_REQUEST. The Rust port routes inbound data through
    /// [`InboundState::feed`] inside the driver loop; this method is
    /// retained as a `pub(crate)` API-parity slot per the [`FcgiClient`]
    /// schema.
    ///
    /// `chunk` is appended to the client's stdout accumulator without
    /// further interpretation; this method is *not* a substitute for the
    /// real protocol parser. It exists so that callers writing their own
    /// drive loop (e.g. for testing) can mock the inbound side.
    #[allow(dead_code)] // API-parity slot for the FASM 7-method vtable; exercised by unit tests below.
    pub(crate) async fn on_received(&self, chunk: &[u8]) -> Result<(), NetError> {
        if let Ok(mut guard) = self.inner.lock() {
            guard.stdout.extend_from_slice(chunk);
        }
        Ok(())
    }

    /// Transport-error hook. Mirrors `fcgiclient$error` from the FASM source:
    /// fires the callback with [`FcgiResult::TransportError`] carrying the
    /// supplied [`NetError`], so the caller can distinguish backend-
    /// unreachable from backend-misbehaving conditions.
    #[allow(dead_code)] // API-parity slot; exercised by unit tests below.
    pub(crate) async fn on_error(&self, err: NetError) {
        self.fire_callback(FcgiResult::TransportError(err));
    }

    /// Idle-timeout hook. Returns [`TimerAction::Teardown`] with
    /// [`TeardownReason::IdleTimeout`] when the read-idle window has elapsed
    /// — the [`drive_request`] caller maps this back to a
    /// `NetError::Io(TimedOut)` and tears the connection down. Returns
    /// [`TimerAction::Reset`] otherwise (today: never, but the slot exists
    /// for symmetry with the FASM `io$timeout` 7th vmethod entry).
    #[allow(dead_code)] // API-parity slot; exercised by unit tests below.
    pub(crate) fn on_timeout(&self) -> TimerAction {
        TimerAction::Teardown(TeardownReason::IdleTimeout)
    }

    /// Internal: take the callback (if still present) and invoke it with the
    /// supplied result and the elapsed time since spawn. After this returns,
    /// the callback slot is empty, guaranteeing the one-shot semantics.
    fn fire_callback(&self, result: FcgiResult) {
        let cb_opt = self.inner.lock().ok().and_then(|mut guard| guard.callback.take());
        if let Some(cb) = cb_opt {
            // u64::MAX cap protects callers that compute downstream u64
            // arithmetic from rare clock skew or very long-running requests.
            let elapsed_ms = self.start_time.elapsed().as_millis().min(u64::MAX as u128) as u64;
            cb(self.callback_arg, result, elapsed_ms);
        }
    }

    /// Internal: drive the entire FastCGI request lifecycle on the spawned
    /// task. Returns the outcome (Response / TransportError / ProtocolError)
    /// so the caller (the spawn closure) can fire the callback uniformly.
    async fn drive_request(client: &Arc<Self>) -> FcgiResult {
        // Step 1: connect to the upstream backend.
        let mut transport = match connect_upstream(&client.url).await {
            Ok(t) => t,
            Err(NetError::Http(http_err)) => {
                // Scheme-validation failure surfaces as ProtocolError so the
                // caller can distinguish "we never got off the ground" from
                // the more typical "we got bytes back but they were wrong".
                return FcgiResult::ProtocolError(http_err);
            }
            Err(other) => return FcgiResult::TransportError(other),
        };

        // Step 2: invoke the API-parity hook (no-op today, see comments).
        if let Err(e) = client.on_connected().await {
            return FcgiResult::TransportError(e);
        }

        // Step 3: send the entire pre-encoded request stream. We take() the
        // outbound bytes from `inner` so the buffer is freed once the write
        // completes — this matches the FASM `buffer$reset` after
        // `epoll$send` in `fcgiclient$connected`.
        let outbound: Bytes = {
            let mut guard = match client.inner.lock() {
                Ok(g) => g,
                Err(_) => {
                    return FcgiResult::TransportError(NetError::Io(IoError::other(
                        "fcgi inner mutex poisoned",
                    )));
                }
            };
            // Replace with empty BytesMut to free memory.
            std::mem::take(&mut guard.outbound).freeze()
        };

        if let Err(e) = transport.write_all(&outbound).await {
            return FcgiResult::TransportError(e);
        }
        if let Err(e) = transport.flush().await {
            return FcgiResult::TransportError(e);
        }

        // Step 4: read inbound records until FCGI_END_REQUEST. Each read is
        // bounded by HTTP_IDLE_TIMEOUT_SECS (default 30s) and a
        // `tokio::time::timeout` is wrapped around it; expiry maps back to
        // a `NetError::Io(TimedOut)` per the FASM idle-timeout convention.
        let mut parser = InboundState::new();
        let idle = Duration::from_secs(HTTP_IDLE_TIMEOUT_SECS);
        let mut read_buf = vec![0u8; 16 * 1024];
        loop {
            let read_result = timeout(idle, transport.read(&mut read_buf)).await;
            let n = match read_result {
                // Timeout expired → map to Io(TimedOut). Mirrors the FASM
                // io$timeout returning non-zero (teardown) on idle expiry.
                Err(_) => {
                    return FcgiResult::TransportError(NetError::Io(IoError::new(
                        ErrorKind::TimedOut,
                        "FastCGI backend idle timeout",
                    )));
                }
                Ok(Err(e)) => return FcgiResult::TransportError(e),
                Ok(Ok(0)) => {
                    // Clean EOF before END_REQUEST → backend closed early.
                    if parser.end_seen {
                        break;
                    }
                    return FcgiResult::ProtocolError(HttpError::FastCgi(
                        "FastCGI backend closed connection before END_REQUEST".to_string(),
                    ));
                }
                Ok(Ok(n)) => n,
            };
            if let Err(http_err) = parser.feed(&read_buf[..n]) {
                return FcgiResult::ProtocolError(http_err);
            }
            if parser.end_seen {
                break;
            }
        }

        // Step 5: synthesize the response Mimelike from the accumulated
        // stdout, then stash the stderr accumulator into `inner` so callers
        // observing the client via Arc can inspect it after the callback
        // returns. Note: `parser.stdout` is consumed by `build_response` so
        // we move `parser.errbuf` independently — Rust's field-level move
        // semantics make this safe.
        let response = Self::build_response(parser.stdout, &parser.errbuf);
        if let Ok(mut guard) = client.inner.lock() {
            guard.errbuf = parser.errbuf;
        }
        FcgiResult::Response(response)
    }

    /// Build the response [`Mimelike`] from the accumulated stdout. The two
    /// modes mirror the [`WEBSERVER_FASTCGI_POSTPROCESS`] toggle:
    ///
    /// * `false` (default): stream-through — produce a Mimelike that simply
    ///   carries the raw stdout bytes in its body. Callers downstream do the
    ///   final HTTP framing.
    /// * `true`: parse — feed the stdout bytes to [`Mimelike::new_parse`]
    ///   which produces a fully-decoded HTTP response. On parse failure,
    ///   fall back to the stream-through Mimelike to preserve at least the
    ///   raw bytes for caller inspection.
    fn build_response(stdout: Buffer, _errbuf: &Buffer) -> Mimelike {
        let bytes_vec: Vec<u8> = stdout.into();
        if WEBSERVER_FASTCGI_POSTPROCESS {
            // Try the strict parse first; if the backend produced something
            // that does not match the Mimelike grammar (rare but possible
            // when the backend is misconfigured), degrade gracefully.
            match Mimelike::new_parse(&bytes_vec, false, false) {
                Ok(parsed) => parsed,
                Err(_) => Self::raw_body_mimelike(&bytes_vec),
            }
        } else {
            Self::raw_body_mimelike(&bytes_vec)
        }
    }

    /// Build a "stream-through" [`Mimelike`] whose body is the raw stdout
    /// bytes — used when post-processing is disabled or when the strict
    /// parse fails. The result has no preface and no headers; downstream
    /// code is expected to understand that the body carries an unparsed
    /// FastCGI stdout payload.
    fn raw_body_mimelike(bytes: &[u8]) -> Mimelike {
        let mut m = Mimelike::new();
        // `set_body` is fallible because it allocates; on alloc failure the
        // best we can do is hand back an empty Mimelike — callers will see
        // a zero-length body and can react accordingly.
        let _ = m.set_body(bytes);
        m
    }
}

// ---------------------------------------------------------------------------
// Drop impl — fires the callback with ConnectionReset if not yet fired
// ---------------------------------------------------------------------------

impl Drop for FcgiClient {
    /// If the callback has not yet been fired (e.g. the driver task panicked
    /// or was cancelled before reaching FCGI_END_REQUEST), invoke it with a
    /// synthesized [`FcgiResult::TransportError(NetError::Io(ConnectionReset))`]
    /// so the caller's result-sender is always notified exactly once.
    ///
    /// Per the FASM caveat (preserved from `fcgiclient.inc`):
    /// callers MUST NOT trigger drop of the originating `FcgiClient` from
    /// inside the callback itself; doing so risks reentry into this code
    /// while a callback is mid-flight.
    fn drop(&mut self) {
        // We cannot call `fire_callback` here because that takes `&self` and
        // `Drop` only gets `&mut self` — but that's fine, we already have
        // direct access to `inner` via the &mut reference.
        let cb_opt = self.inner.get_mut().ok().and_then(|inner| inner.callback.take());
        if let Some(cb) = cb_opt {
            let synthesized = FcgiResult::TransportError(NetError::Io(IoError::new(
                ErrorKind::ConnectionReset,
                "FcgiClient dropped before request completion",
            )));
            let elapsed_ms = self.start_time.elapsed().as_millis().min(u64::MAX as u128) as u64;
            cb(self.callback_arg, synthesized, elapsed_ms);
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! In-file unit tests covering the wire-format primitives, the inbound
    //! parser, and the API-parity hooks. These tests are intentionally
    //! self-contained — they do not open sockets or fork worker processes.
    //! Live network coverage lives in `crates/heavything/tests/net_integration.rs`
    //! per AAP §0.3.1.2.

    use super::*;

    // --- Test 1: initial_buffer() returns 16 bytes of valid BEGIN_REQUEST.

    #[test]
    fn initial_buffer_layout() {
        let bytes = initial_buffer();
        assert_eq!(bytes.len(), 16, "initial_buffer must be exactly 16 bytes");
        // Header (8 bytes): version=1, type=BEGIN_REQUEST(1), request_id=1 BE,
        //                   content_length=8 BE, padding=0, reserved=0.
        assert_eq!(bytes[0], FCGI_VERSION_1);
        assert_eq!(bytes[1], FCGI_BEGIN_REQUEST);
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), FCGI_REQUEST_ID);
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 8);
        assert_eq!(bytes[6], 0);
        assert_eq!(bytes[7], 0);
        // Body (8 bytes): role=Responder(1) BE, flags=0, reserved 5 bytes.
        assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), FCGI_RESPONDER);
        assert_eq!(bytes[10], 0); // flags
        assert_eq!(&bytes[11..16], &[0u8; 5]);
    }

    // --- Test 2: PARAMS length encoding switches between 1-byte and 4-byte forms.

    #[test]
    fn put_param_len_one_byte_form() {
        // Lengths 0..=127 use the 1-byte form (high bit clear).
        let mut buf = BytesMut::new();
        put_param_len(&mut buf, 0);
        put_param_len(&mut buf, 1);
        put_param_len(&mut buf, 127);
        assert_eq!(&buf[..], &[0x00, 0x01, 0x7F]);
    }

    #[test]
    fn put_param_len_four_byte_form_at_128() {
        // Length 128 is the smallest value that requires the 4-byte form.
        // Encoding: high bit set on first byte; 32-bit big-endian remainder.
        // 128 | 0x8000_0000 = 0x8000_0080 → bytes 0x80 0x00 0x00 0x80.
        let mut buf = BytesMut::new();
        put_param_len(&mut buf, 128);
        assert_eq!(&buf[..], &[0x80, 0x00, 0x00, 0x80]);
    }

    #[test]
    fn put_param_len_four_byte_form_large() {
        // Length 1000 = 0x3E8. Encoding: 0x8000_0000 | 0x3E8 = 0x800003E8 →
        // bytes 0x80 0x00 0x03 0xE8.
        let mut buf = BytesMut::new();
        put_param_len(&mut buf, 1000);
        assert_eq!(&buf[..], &[0x80, 0x00, 0x03, 0xE8]);
    }

    #[test]
    fn append_nv_pair_short_short() {
        // Both name (3) and value (5) under 128 → 1+1+3+5 = 10 bytes.
        let mut buf = BytesMut::new();
        append_nv_pair(&mut buf, b"FOO", b"hello");
        assert_eq!(&buf[..], b"\x03\x05FOOhello");
    }

    #[test]
    fn append_nv_pair_long_short() {
        // Name length 200, value length 5 → 4+1+200+5 = 210 bytes.
        let name: Vec<u8> = std::iter::repeat(b'X').take(200).collect();
        let mut buf = BytesMut::new();
        append_nv_pair(&mut buf, &name, b"hello");
        // First 4 bytes: 0x80 0x00 0x00 0xC8 (200).
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x00);
        assert_eq!(buf[3], 0xC8);
        // Then 1 byte for value length: 5.
        assert_eq!(buf[4], 0x05);
        // Then 200 'X' bytes.
        assert_eq!(&buf[5..205], &name[..]);
        // Then "hello".
        assert_eq!(&buf[205..210], b"hello");
    }

    // --- Test 3: Record header round-trip — encode then parse a known PARAMS
    //     block back into the same fields.

    #[test]
    fn record_header_round_trip() {
        // Build a PARAMS record with a single nv-pair "A=B".
        let mut payload = BytesMut::new();
        append_nv_pair(&mut payload, b"A", b"B");
        assert_eq!(&payload[..], b"\x01\x01AB");

        let mut wire = BytesMut::new();
        // Manually wrap (no padding for the test — content_len=4, padding=4).
        let clen = payload.len() as u16;
        let plen = padding_for(clen);
        put_record_header(&mut wire, FCGI_PARAMS, clen, plen);
        wire.put_slice(&payload);
        if plen > 0 {
            wire.put_slice(&[0u8; 7][..plen as usize]);
        }
        assert_eq!(wire.len(), 8 + clen as usize + plen as usize);

        // Parse it back.
        match parse_record(&wire) {
            ParseOutcome::Record(rec) => {
                assert_eq!(rec.record_type, FCGI_PARAMS);
                assert_eq!(rec.payload, b"\x01\x01AB");
                assert_eq!(rec.consumed, wire.len());
            }
            other => panic!(
                "expected ParseOutcome::Record, got something else: {}",
                match other {
                    ParseOutcome::NeedMore => "NeedMore",
                    ParseOutcome::Invalid(_) => "Invalid",
                    ParseOutcome::Record(_) => unreachable!(),
                }
            ),
        }
    }

    #[test]
    fn padding_for_alignment() {
        // (8 + content + padding) must be a multiple of 8.
        for content in [0u16, 1, 2, 7, 8, 9, 15, 16, 31, 64, 65, 100, 128, 511, 512, 1024] {
            let pad = padding_for(content);
            assert!(
                pad < 8,
                "padding must be 0..=7, got {} for content={}",
                pad,
                content
            );
            let total = 8 + (content as usize) + (pad as usize);
            assert_eq!(
                total % 8,
                0,
                "total {} is not 8-aligned for content={}",
                total,
                content
            );
        }
    }

    // --- Test 4: Inbound parser produces error on malformed records.

    #[test]
    fn parse_record_rejects_invalid_version() {
        // First byte is 0x99 instead of 1 → must be Invalid.
        let bytes = [0x99u8, 6, 0, 1, 0, 4, 0, 0, b'A', b'B', b'C', b'D'];
        match parse_record(&bytes) {
            ParseOutcome::Invalid(msg) => assert!(msg.contains("version")),
            _ => panic!("expected Invalid for non-1 version byte"),
        }
    }

    #[test]
    fn parse_record_needs_more_when_truncated() {
        // Only 5 bytes — header is 8.
        let bytes = [1u8, 6, 0, 1, 0];
        match parse_record(&bytes) {
            ParseOutcome::NeedMore => {}
            _ => panic!("expected NeedMore for truncated header"),
        }
    }

    #[test]
    fn parse_record_needs_more_when_payload_truncated() {
        // Header says content_length=4, but we only have 2 payload bytes.
        let bytes = [1u8, 6, 0, 1, 0, 4, 0, 0, b'A', b'B'];
        match parse_record(&bytes) {
            ParseOutcome::NeedMore => {}
            _ => panic!("expected NeedMore for truncated payload"),
        }
    }

    #[test]
    fn inbound_state_feeds_stdout() {
        // Construct an FCGI_STDOUT record carrying "<html>" and feed it.
        let payload = b"<html>";
        let clen = payload.len() as u16;
        let plen = padding_for(clen);
        let mut wire = BytesMut::new();
        put_record_header(&mut wire, FCGI_STDOUT, clen, plen);
        wire.put_slice(payload);
        if plen > 0 {
            wire.put_slice(&[0u8; 7][..plen as usize]);
        }

        let mut state = InboundState::new();
        state.feed(&wire).expect("feed should accept valid stdout");
        assert!(!state.end_seen);
        assert_eq!(state.stdout.as_slice(), payload);
    }

    #[test]
    fn inbound_state_rejects_malformed() {
        let mut state = InboundState::new();
        let bytes = [0x99u8, 6, 0, 1, 0, 4, 0, 0, b'A', b'B', b'C', b'D'];
        match state.feed(&bytes) {
            Err(HttpError::FastCgi(msg)) => assert!(msg.contains("version")),
            other => panic!("expected FastCgi error, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn inbound_state_detects_end_request() {
        // FCGI_END_REQUEST body is 8 bytes (appStatus + protocolStatus +
        // 3 reserved). We just send the canonical "0,0" body for the test.
        let payload = [0u8; 8];
        let mut wire = BytesMut::new();
        put_record_header(&mut wire, FCGI_END_REQUEST, payload.len() as u16, 0);
        wire.put_slice(&payload);

        let mut state = InboundState::new();
        state.feed(&wire).expect("feed should accept valid end_request");
        assert!(state.end_seen);
    }

    #[test]
    fn inbound_state_handles_partial_chunks() {
        // Send a 6-byte STDOUT record split across two feed() calls — the
        // parser must hold onto the partial bytes until the second feed.
        let payload = b"abc";
        let clen = payload.len() as u16;
        let plen = padding_for(clen);
        let mut wire = BytesMut::new();
        put_record_header(&mut wire, FCGI_STDOUT, clen, plen);
        wire.put_slice(payload);
        if plen > 0 {
            wire.put_slice(&[0u8; 7][..plen as usize]);
        }
        let total_len = wire.len();
        let split = 5; // mid-header split

        let mut state = InboundState::new();
        state.feed(&wire[..split]).expect("partial-1 feed");
        // Nothing accumulated yet because the record is not complete.
        assert!(state.stdout.is_empty());
        state.feed(&wire[split..]).expect("partial-2 feed");
        assert_eq!(state.stdout.as_slice(), payload);
        // The partial bytes have all been consumed.
        assert!(
            state.accumulator.is_empty(),
            "accumulator had {} bytes left",
            state.accumulator.len()
        );
        let _ = total_len; // documented above; silence unused-var lint.
    }

    // --- Encoding integration: the request encoder produces a byte stream
    //     that begins with the BEGIN_REQUEST header and contains the static
    //     SERVER_PROTOCOL value.

    fn make_minimal_url() -> Url {
        // url::Url::parse("fcgi://127.0.0.1:9000/").unwrap_or_else(|_| Url::new())
        // — but Url::new() is the reliable fallback if parse rejects fcgi.
        match Url::parse("fcgi://127.0.0.1:9000/") {
            Ok(u) => u,
            Err(_) => Url::new(),
        }
    }

    fn make_get_request() -> Mimelike {
        let mut m = Mimelike::new();
        m.set_preface_nocopy("GET / HTTP/1.1".to_string());
        // Set method code = 0 (GET) at user_bytes()[0]
        let user = m.user_bytes_mut();
        user[0] = 0;
        m
    }

    #[test]
    fn encode_request_starts_with_begin_request() {
        let url = make_minimal_url();
        let req = make_get_request();
        let bytes = encode_request(&url, &req);
        assert!(bytes.len() >= 16, "encoded request too small");
        // First 16 bytes must equal initial_buffer().
        assert_eq!(&bytes[..16], &initial_buffer()[..]);
    }

    #[test]
    fn encode_request_includes_static_params() {
        let url = make_minimal_url();
        let req = make_get_request();
        let bytes = encode_request(&url, &req);
        // The PARAMS payload should contain the SERVER_PROTOCOL nv-pair.
        // Use a substring search; the exact offset depends on URL/header
        // contents but the static prefix (15-8-"SERVER_PROTOCOL"-"HTTP/1.1")
        // appears verbatim.
        let needle = b"SERVER_PROTOCOLHTTP/1.1";
        let found = bytes.windows(needle.len()).any(|w| w == needle);
        assert!(found, "encoded request did not contain SERVER_PROTOCOL=HTTP/1.1");
    }

    #[test]
    fn encode_request_terminates_stdin() {
        // For a non-POST request, the encoder must emit an empty STDIN
        // record at the end of the stream.
        let url = make_minimal_url();
        let req = make_get_request();
        let bytes = encode_request(&url, &req);
        // The last 8 bytes must be a record header for FCGI_STDIN with
        // content_length=0 and padding=0.
        let n = bytes.len();
        assert!(n >= 8);
        let tail = &bytes[n - 8..];
        assert_eq!(tail[0], FCGI_VERSION_1);
        assert_eq!(tail[1], FCGI_STDIN);
        assert_eq!(u16::from_be_bytes([tail[2], tail[3]]), FCGI_REQUEST_ID);
        assert_eq!(u16::from_be_bytes([tail[4], tail[5]]), 0);
        assert_eq!(tail[6], 0);
        assert_eq!(tail[7], 0);
    }

    #[test]
    fn encode_request_post_with_body() {
        // Construct a Mimelike with method code 2 (POST) and a body, verify
        // the encoder includes a non-empty STDIN record before the empty
        // terminator.
        let url = make_minimal_url();
        let mut req = Mimelike::new();
        req.set_preface_nocopy("POST /upload HTTP/1.1".to_string());
        let user = req.user_bytes_mut();
        user[0] = 2;
        let body = b"hello=world&foo=bar";
        let _ = req.set_body(body);

        let bytes = encode_request(&url, &req);
        // The body bytes must appear in the encoded request (they are inside
        // the FCGI_STDIN record's payload).
        let found = bytes.windows(body.len()).any(|w| w == body);
        assert!(found, "encoded POST request did not contain the body bytes");
    }

    // --- API-parity method exercise

    #[test]
    fn request_method_for_known_codes() {
        let mut m = Mimelike::new();
        let user = m.user_bytes_mut();
        user[0] = 0;
        let (method, is_post) = request_method_for(&m);
        assert_eq!(method, "GET");
        assert!(!is_post);

        let user = m.user_bytes_mut();
        user[0] = 1;
        let (method, is_post) = request_method_for(&m);
        assert_eq!(method, "HEAD");
        assert!(!is_post);

        let user = m.user_bytes_mut();
        user[0] = 2;
        let (method, is_post) = request_method_for(&m);
        assert_eq!(method, "POST");
        assert!(is_post);
    }

    #[test]
    fn request_method_for_falls_back_to_preface() {
        let mut m = Mimelike::new();
        // user_bytes()[0] starts at zero (= GET) so we override with an
        // unknown code (255) to force the preface fallback path.
        let user = m.user_bytes_mut();
        user[0] = 255;
        m.set_preface_nocopy("DELETE /resource HTTP/1.1".to_string());
        let (method, is_post) = request_method_for(&m);
        assert_eq!(method, "DELETE");
        assert!(!is_post);
    }

    #[test]
    fn append_cgi_header_name_normalizes() {
        let mut out = Vec::new();
        append_cgi_header_name(&mut out, "User-Agent");
        assert_eq!(out, b"HTTP_USER_AGENT");

        append_cgi_header_name(&mut out, "x-custom-header");
        assert_eq!(out, b"HTTP_X_CUSTOM_HEADER");

        append_cgi_header_name(&mut out, "Accept");
        assert_eq!(out, b"HTTP_ACCEPT");
    }

    #[tokio::test]
    async fn on_received_appends_to_stdout() {
        // Spawn an FcgiClient that will fail to connect (bogus URL) but the
        // on_received hook is independent of the spawned task. We construct
        // it manually for this test.
        let url = Arc::new(make_minimal_url());
        let request = Arc::new(make_get_request());
        let client = Arc::new(FcgiClient {
            url,
            request,
            inner: Mutex::new(Inner {
                callback: None,
                outbound: BytesMut::new(),
                stdout: Buffer::new(),
                errbuf: Buffer::new(),
                user: 0,
            }),
            callback_arg: 0,
            start_time: Instant::now(),
        });
        client.on_received(b"hello").await.expect("on_received ok");
        client.on_received(b" world").await.expect("on_received ok");
        assert_eq!(client.stdout_bytes(), b"hello world");
    }

    #[test]
    fn on_timeout_returns_teardown() {
        let url = Arc::new(make_minimal_url());
        let request = Arc::new(make_get_request());
        let client = FcgiClient {
            url,
            request,
            inner: Mutex::new(Inner {
                callback: None,
                outbound: BytesMut::new(),
                stdout: Buffer::new(),
                errbuf: Buffer::new(),
                user: 0,
            }),
            callback_arg: 0,
            start_time: Instant::now(),
        };
        match client.on_timeout() {
            TimerAction::Teardown(TeardownReason::IdleTimeout) => { /* expected */ }
            other => panic!("expected Teardown(IdleTimeout), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn on_error_fires_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let fired = Arc::new(AtomicBool::new(false));
        let fired_for_cb = Arc::clone(&fired);

        let url = Arc::new(make_minimal_url());
        let request = Arc::new(make_get_request());
        let cb: FcgiCallback = Box::new(move |arg, result, _elapsed| {
            assert_eq!(arg, 42);
            match result {
                FcgiResult::TransportError(_) => fired_for_cb.store(true, Ordering::SeqCst),
                _ => panic!("expected TransportError"),
            }
        });
        let client = FcgiClient {
            url,
            request,
            inner: Mutex::new(Inner {
                callback: Some(cb),
                outbound: BytesMut::new(),
                stdout: Buffer::new(),
                errbuf: Buffer::new(),
                user: 0,
            }),
            callback_arg: 42,
            start_time: Instant::now(),
        };
        let err = NetError::Io(IoError::new(ErrorKind::ConnectionRefused, "test"));
        client.on_error(err).await;
        assert!(fired.load(Ordering::SeqCst), "callback should have fired");
    }

    #[test]
    fn drop_fires_callback_when_unfired() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let fired = Arc::new(AtomicBool::new(false));
        let fired_for_cb = Arc::clone(&fired);

        let url = Arc::new(make_minimal_url());
        let request = Arc::new(make_get_request());
        let cb: FcgiCallback = Box::new(move |arg, result, _elapsed| {
            assert_eq!(arg, 7);
            match result {
                FcgiResult::TransportError(NetError::Io(io_err)) => {
                    assert_eq!(io_err.kind(), ErrorKind::ConnectionReset);
                    fired_for_cb.store(true, Ordering::SeqCst);
                }
                _ => panic!("expected TransportError(Io(ConnectionReset))"),
            }
        });
        {
            let _client = FcgiClient {
                url,
                request,
                inner: Mutex::new(Inner {
                    callback: Some(cb),
                    outbound: BytesMut::new(),
                    stdout: Buffer::new(),
                    errbuf: Buffer::new(),
                    user: 0,
                }),
                callback_arg: 7,
                start_time: Instant::now(),
            };
            // _client is dropped at the end of this block.
        }
        assert!(fired.load(Ordering::SeqCst), "Drop should fire callback");
    }

    #[test]
    fn user_field_round_trip() {
        let url = Arc::new(make_minimal_url());
        let request = Arc::new(make_get_request());
        let client = FcgiClient {
            url,
            request,
            inner: Mutex::new(Inner {
                callback: None,
                outbound: BytesMut::new(),
                stdout: Buffer::new(),
                errbuf: Buffer::new(),
                user: 0,
            }),
            callback_arg: 0,
            start_time: Instant::now(),
        };
        assert_eq!(client.user(), 0);
        client.set_user(0xCAFE_BABE);
        assert_eq!(client.user(), 0xCAFE_BABE);
    }

    #[test]
    fn forward_stderr_to_syslog_handles_multiline() {
        // This test merely exercises the function — syslog itself gracefully
        // degrades to a no-op when /dev/log is unreachable (per
        // util::syslog::log() semantics), so we only verify that no panic
        // occurs across various line-ending shapes.
        forward_stderr_to_syslog(b"first line\nsecond line\n");
        forward_stderr_to_syslog(b"only one line");
        forward_stderr_to_syslog(b"\r\nempty\r\nlines\n\n");
        forward_stderr_to_syslog(b""); // empty input must be a no-op
    }
}
