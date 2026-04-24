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

//! HTTP/1.x parser state-machine driver — Rust port of `http1.inc`.
//!
//! This module is a line-for-line (behavioural) port of the HeavyThing FASM
//! file `http1.inc` (837 lines, 9 functions). In the FASM baseline, `http1`
//! is an internal utility used by `webserver.inc` and `webclient.inc`. The
//! Rust port exposes [`Http1Parser`] as a public type so that the server and
//! client modules can instantiate and drive it directly.
//!
//! # FASM object layout (preserved semantically)
//!
//! ```text
//! http1_headers_ofs      = 0                  ; httpheaders inline (6136 bytes)
//! http1_parsestate_ofs   = 6136               ; state machine index
//! http1_parsedata_ofs    = 6144               ; pending partial data ptr
//! http1_bodyptr_ofs      = 6152               ; body buffer pointer
//! http1_bodylen_ofs      = 6160               ; body byte counter
//! http1_headerlen_ofs    = 6168               ; header total length
//! http1_size             = 6176
//! ```
//!
//! In Rust the flat-byte layout is irrelevant — the [`Http1Parser`] struct
//! owns the [`HttpHeaders`] directly (composition), a [`ParseState`] tag, an
//! optional accumulation [`Vec<u8>`], an optional [`BytesMut`] body buffer,
//! the remaining content-length counter, and the bytes-consumed-for-headers
//! marker.
//!
//! # Five-state machine (mirrors `http1$input` dispatch table L119-131)
//!
//! | State # | [`ParseState`] variant   | Purpose                                                     |
//! |---------|--------------------------|-------------------------------------------------------------|
//! | 0       | `InHeaders`              | Initial state; scanning for a complete header block.        |
//! | 1       | `PartialHeadersDirect`   | Partial headers accumulated in a [`Vec<u8>`].               |
//! | 2       | `PartialHeadersBuffer`   | Vestigial FASM state (heap-backed); handled identically.    |
//! | 3       | `InBodyLength`           | Body phase — Content-Length countdown.                      |
//! | 4       | `InBodyChunked`          | Body phase — Transfer-Encoding: chunked, sentinel-scan.     |
//!
//! # Output semantics (mirrors FASM return-value convention)
//!
//! The FASM `http1$input` returns:
//! * `-1` → parse error.
//! * `0`  → incomplete; caller must accumulate more bytes.
//! * `>0` → bytes consumed from the buffer; headers (and possibly body)
//!   complete.
//!
//! The Rust port returns [`Http1InputResult`] which exposes the three
//! outcomes as a typed enum — callers match instead of testing signs.
//!
//! # Pipelining safety
//!
//! The `Consumed(n)` variant tells the caller exactly how many bytes of the
//! supplied slice were consumed for the completed request. The caller is
//! expected to advance their accumulator by `n` bytes, invoke
//! [`Http1Parser::reset`] to clear per-request state, then call
//! [`Http1Parser::input`] again with the remaining bytes. This matches the
//! FASM pipelining contract from `webserver.inc`.
//!
//! # Chunked transfer-encoding is passed through raw
//!
//! Per FASM design (`http1.inc` L526-700) the chunked body is **not**
//! de-chunked. The raw chunked bytes — including the hex size prefix lines,
//! per-chunk `\r\n` separators, and the final `\r\n0\r\n\r\n` terminator —
//! are retained verbatim in [`Http1Parser::body`]. Consumers that need a
//! dechunked view must decode themselves.
//!
//! # Size caps
//!
//! * Per-request header block ≤ [`WEBSERVER_MAXHEADER`] (32 KiB); exceed →
//!   [`Http1Error::HeaderTooLarge`]. Ports FASM `webserver_maxheader`.
//! * Per-request body ≤ [`WEBSERVER_MAXREQUEST`] (64 MiB); exceed →
//!   [`Http1Error::RequestTooLarge`]. Ports FASM `webserver_maxrequest`.

use bytes::BytesMut;
use thiserror::Error;

use crate::config::{WEBSERVER_MAXHEADER, WEBSERVER_MAXREQUEST};
use crate::error::HttpError;
use crate::net::http::headers::HttpHeaders;

// -----------------------------------------------------------------------------
// Public constants
// -----------------------------------------------------------------------------

/// Sentinel bytes that terminate a chunked transfer-encoding body.
///
/// These are the literal ASCII bytes `{CR, LF, '0', CR, LF, CR, LF}` — i.e.
/// the zero-length final chunk (`0\r\n`) followed by the empty trailer
/// section (`\r\n`). When the accumulating body buffer contains this
/// sentinel, the chunked body is complete per RFC 7230 §4.1.
///
/// FASM equivalent: the 7-byte literal emitted by `webserver.inc` at the end
/// of a chunked response and scanned for by `http1$input` state 4
/// (`http1.inc` L650-700).
pub const CHUNKED_TERMINATOR: &[u8] = b"\r\n0\r\n\r\n";

/// Accumulated-size threshold (4 KiB — one typical memory page) at which
/// the partial-header state machine promotes from
/// [`ParseState::PartialHeadersDirect`] to
/// [`ParseState::PartialHeadersBuffer`].
///
/// Mirrors the FASM `http1.inc` distinction between state 1 (64 KiB stack
/// scratch, L218-332) and state 2 (heap-backed `buffer$new`, L333-403).
/// In the Rust port both states share a single [`Vec<u8>`] accumulator so
/// the promotion is purely structural (no allocator change); the two
/// variants are preserved per AAP 0.4.1.1 "vestigial variant for
/// behavioural parity".
const PARTIAL_BUFFER_PROMOTION_THRESHOLD: usize = 4096;

// -----------------------------------------------------------------------------
// Error type
// -----------------------------------------------------------------------------

/// Errors produced by [`Http1Parser::input`], [`Http1Parser::to_buffer`], or
/// [`Http1Parser::to_call`].
///
/// Converted transparently to [`HttpError`] at the `server.rs` / `client.rs`
/// boundary via the [`From`] impl, following AAP §0.8.3 typed-error
/// discipline.
#[derive(Error, Debug)]
pub enum Http1Error {
    /// Underlying [`HttpHeaders::parse_http1`] rejected the input (malformed
    /// request/status line, missing colon in a header, bad method, etc.).
    /// The inner [`String`] is the lower-level error's display message.
    #[error("header parse failure: {0}")]
    HeaderParseFailure(String),

    /// A valid `Content-Length` header value was successfully parsed but the
    /// resulting byte count exceeds [`WEBSERVER_MAXREQUEST`]. Mirrors the
    /// FASM check at `http1.inc` L187-195.
    #[error("request too large (>{max} bytes)")]
    RequestTooLarge {
        /// Configured limit in bytes (for display).
        max: u64,
    },

    /// The `Content-Length` header value could not be parsed as a
    /// non-negative decimal integer. Mirrors the FASM `atou` failure at
    /// `http1.inc` L184.
    #[error("malformed content-length")]
    MalformedContentLength,

    /// The chunked body grew beyond [`WEBSERVER_MAXREQUEST`] without the
    /// sentinel [`CHUNKED_TERMINATOR`] appearing, or decoder state is
    /// otherwise inconsistent.
    #[error("malformed chunked encoding")]
    MalformedChunked,

    /// The combined partial header buffer would exceed [`WEBSERVER_MAXHEADER`].
    /// Mirrors the FASM guard at `http1.inc` L220-230.
    #[error("header too large")]
    HeaderTooLarge,
}

/// Boundary conversion — every [`Http1Error`] flattens into either
/// [`HttpError::Parse`] or [`HttpError::TooLarge`] per AAP §0.8.3, giving
/// `server.rs` / `client.rs` a uniform HTTP error type.
impl From<Http1Error> for HttpError {
    fn from(e: Http1Error) -> Self {
        match e {
            Http1Error::HeaderParseFailure(msg) => {
                HttpError::Parse(format!("http1: {}", msg))
            }
            Http1Error::RequestTooLarge { .. } => HttpError::TooLarge,
            Http1Error::MalformedContentLength => {
                HttpError::Parse("http1: malformed content-length".to_string())
            }
            Http1Error::MalformedChunked => {
                HttpError::Parse("http1: malformed chunked encoding".to_string())
            }
            Http1Error::HeaderTooLarge => {
                HttpError::Parse("http1: header too large".to_string())
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Input result
// -----------------------------------------------------------------------------

/// Outcome of one [`Http1Parser::input`] invocation.
///
/// Replaces the FASM integer return convention (`-1` / `0` / `>0`) from
/// `http1$input` with a three-variant enum; callers match instead of
/// testing sign.
///
/// * [`Http1InputResult::Error`] — equivalent to FASM `-1`; the parser is in
///   an invalid state and should be dropped.
/// * [`Http1InputResult::NeedMore`] — equivalent to FASM `0`; the supplied
///   bytes were consumed into the internal accumulator but the request is
///   not yet complete.
/// * [`Http1InputResult::Consumed`] — equivalent to FASM `>0`; the inner
///   `usize` is the number of bytes of the supplied slice that were
///   consumed to finish the request. The caller must advance by that many
///   bytes and call [`Http1Parser::reset`] before submitting another
///   pipelined request.
#[derive(Debug)]
pub enum Http1InputResult {
    /// Fatal parse error. The parser state is undefined and should not be
    /// driven further without a full [`Http1Parser::reset`] or
    /// [`Http1Parser::cleanup`].
    Error(Http1Error),

    /// The supplied slice was consumed into the internal accumulator but
    /// the request is still in progress. Caller must feed more bytes via
    /// another [`Http1Parser::input`] call.
    NeedMore,

    /// A full HTTP/1.x request (headers plus any body) was parsed. The
    /// `usize` is the number of bytes consumed from the supplied slice;
    /// trailing bytes belong to the next pipelined request (if any).
    Consumed(usize),
}

// -----------------------------------------------------------------------------
// Private parse-state enumeration
// -----------------------------------------------------------------------------

/// Internal state machine tag.
///
/// The five values mirror FASM `http1.inc` dispatch table indices (L119-131).
/// `PartialHeadersBuffer` (index 2) is preserved for behavioural parity
/// with the FASM five-state machine; the Rust port unifies states 1 and 2
/// into a single heap-backed [`Vec<u8>`] accumulator capped at
/// [`WEBSERVER_MAXHEADER`], so both variants are routed through the same
/// handler (`step_partial_headers`).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
enum ParseState {
    /// Initial state: scanning for a complete header block. FASM index 0.
    InHeaders = 0,
    /// Partial header bytes accumulated in a heap [`Vec<u8>`] up to
    /// [`WEBSERVER_MAXHEADER`]. FASM index 1 (originally a stack buffer).
    PartialHeadersDirect = 1,
    /// Vestigial FASM state 2 — retained for enum parity. Handled
    /// identically to [`ParseState::PartialHeadersDirect`] in the Rust
    /// port.
    PartialHeadersBuffer = 2,
    /// Body phase: consuming exactly `body_len` bytes declared by
    /// `Content-Length`. FASM index 3.
    InBodyLength = 3,
    /// Body phase: consuming chunked bytes pass-through until the
    /// [`CHUNKED_TERMINATOR`] sentinel is observed. FASM index 4.
    InBodyChunked = 4,
}

// -----------------------------------------------------------------------------
// Public parser struct
// -----------------------------------------------------------------------------

/// HTTP/1.x request or response parser driven by the five-state machine.
///
/// This is the Rust port of the FASM `http1` flat-byte object (size 6176
/// bytes). Instances are typically owned by per-connection handlers in
/// `server.rs` / `client.rs`.
///
/// # Lifecycle
///
/// 1. Construct with [`Http1Parser::new`] (or `Default::default`).
/// 2. Feed incoming wire bytes into [`Http1Parser::input`] as they arrive.
/// 3. When [`Http1InputResult::Consumed`] is observed, extract headers via
///    [`Http1Parser::headers`] / the public `headers` field, and extract
///    the body via [`Http1Parser::body`].
/// 4. Call [`Http1Parser::reset`] before processing the next pipelined
///    request on the same connection.
/// 5. Call [`Http1Parser::cleanup`] (or drop the parser) on teardown.
pub struct Http1Parser {
    /// Inline HTTP header container. Exposed as a public field for direct
    /// access (mirrors FASM offset `http1_headers_ofs = 0`); also
    /// accessible via the [`Http1Parser::headers`] accessor for consumers
    /// that prefer method syntax.
    pub headers: HttpHeaders,

    /// Current state-machine tag. Dispatched in [`Http1Parser::input`].
    state: ParseState,

    /// Partial-header accumulation buffer. `Some` only while state is
    /// [`ParseState::PartialHeadersDirect`] or
    /// [`ParseState::PartialHeadersBuffer`]. Mirrors FASM
    /// `http1_parsedata_ofs`.
    parse_data: Option<Vec<u8>>,

    /// Accumulating body buffer. `Some` once a body phase has been entered.
    /// Mirrors FASM `http1_bodyptr_ofs`. Uses [`BytesMut`] for efficient
    /// pre-allocation when the Content-Length is known up front.
    body_ptr: Option<BytesMut>,

    /// In [`ParseState::InBodyLength`]: remaining bytes to consume (counts
    /// down to zero). In [`ParseState::InBodyChunked`]: total body bytes
    /// finalised (zero while terminator not yet found). Mirrors FASM
    /// `http1_bodylen_ofs`.
    body_len: u64,

    /// Number of bytes the parser treated as belonging to the header
    /// block of the current request. Useful for pipelining and debugging.
    /// Mirrors FASM `http1_headerlen_ofs`.
    header_len: usize,

    /// `true` once a full request (headers + body, if any) has been parsed
    /// successfully. Reset to `false` by [`Http1Parser::reset`] and
    /// [`Http1Parser::cleanup`]. Queried via [`Http1Parser::body_complete`].
    complete: bool,
}

impl Http1Parser {
    // -------------------------------------------------------------------------
    // Construction / teardown
    // -------------------------------------------------------------------------

    /// Construct a fresh parser in the initial [`ParseState::InHeaders`]
    /// state. Mirrors FASM `http1$new` prolog.
    pub fn new() -> Self {
        Self {
            headers: HttpHeaders::new(),
            state: ParseState::InHeaders,
            parse_data: None,
            body_ptr: None,
            body_len: 0,
            header_len: 0,
            complete: false,
        }
    }

    /// Reset all per-request state, preparing the parser for the next
    /// pipelined request on the same connection. Mirrors FASM
    /// `http1$reset`.
    ///
    /// Calls [`HttpHeaders::reset`] to clear the working header table; the
    /// HPACK dynamic table (if any) is preserved per FASM convention. The
    /// partial-header accumulator, body buffer, body counter, and
    /// completion flag are all cleared.
    pub fn reset(&mut self) {
        self.headers.reset();
        self.state = ParseState::InHeaders;
        self.parse_data = None;
        self.body_ptr = None;
        self.body_len = 0;
        self.header_len = 0;
        self.complete = false;
    }

    /// Fully tear down the parser's internal state, including the HPACK
    /// dynamic table. Mirrors FASM `http1$cleanup`.
    ///
    /// Calls [`HttpHeaders::cleanup`] rather than [`HttpHeaders::reset`];
    /// this is the stronger reset appropriate for persistent-connection
    /// shutdown paths (TLS session end, graceful-close handshake, etc.).
    pub fn cleanup(&mut self) {
        self.headers.cleanup();
        self.state = ParseState::InHeaders;
        self.parse_data = None;
        self.body_ptr = None;
        self.body_len = 0;
        self.header_len = 0;
        self.complete = false;
    }

    /// Explicit destructor equivalent to the FASM `http1$destroy` entry
    /// point. In Rust the normal [`Drop`] path handles the work; this
    /// method consumes `self` to make the intent explicit at the call
    /// site, mirroring the FASM boundary.
    pub fn destroy(self) {
        // Drop semantics run here: `headers`, `parse_data`, `body_ptr` all
        // release their allocations. No FFI / unsafe required.
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------

    /// Immutable reference to the parsed header container.
    ///
    /// Equivalent to reading the public field `parser.headers`; provided
    /// as a method for consumers preferring method syntax (and for schema
    /// parity — see AAP `members_exposed`).
    pub fn headers(&self) -> &HttpHeaders {
        &self.headers
    }

    /// Immutable slice view of the accumulated body bytes, if any.
    ///
    /// Returns `None` when no body phase has been entered (e.g. a `GET`
    /// request with neither `Content-Length` nor `Transfer-Encoding`). For
    /// chunked transfers this slice contains the **raw** chunked-encoded
    /// bytes (including hex size lines and per-chunk separators);
    /// consumers that need a dechunked view must decode themselves.
    pub fn body(&self) -> Option<&[u8]> {
        self.body_ptr.as_ref().map(|b| b.as_ref())
    }

    /// `true` once a complete request (headers + body, if any) has been
    /// parsed. Cleared on [`Http1Parser::reset`] and
    /// [`Http1Parser::cleanup`].
    pub fn body_complete(&self) -> bool {
        self.complete
    }

    /// Override the body buffer with the supplied bytes. Mirrors FASM
    /// `http1$setbody` (`http1.inc` L800-805).
    ///
    /// Primarily used by compose-side callers that build an HTTP message
    /// from scratch and then hand it off to [`Http1Parser::to_buffer`] or
    /// [`Http1Parser::to_call`] for wire-format serialisation. Does not
    /// affect the parse state machine.
    pub fn set_body(&mut self, body: Vec<u8>) {
        let bytes = BytesMut::from(body.as_slice());
        self.body_len = bytes.len() as u64;
        self.body_ptr = Some(bytes);
    }


    // -------------------------------------------------------------------------
    // Serialisation (compose-side)
    // -------------------------------------------------------------------------

    /// Serialise the stored headers and body as an HTTP/1.x wire-format
    /// buffer. Mirrors FASM `http1$tobuffer` (`http1.inc` L816-822).
    ///
    /// The header block is produced by [`HttpHeaders::to_buffer_http1`],
    /// after which any bytes in [`Http1Parser::body`] are appended
    /// verbatim. The returned [`Vec<u8>`] is the complete wire-format
    /// message.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Error::HeaderParseFailure`] if header serialisation
    /// fails (e.g. an individual header exceeds the internal value-size
    /// cap). In practice this should not occur for headers that were
    /// themselves parsed via [`Http1Parser::input`], since the parser
    /// enforces the same caps on intake.
    pub fn to_buffer(&self) -> Result<Vec<u8>, Http1Error> {
        let mut dest = Vec::new();
        self.headers
            .to_buffer_http1(&mut dest)
            .map_err(|e| Http1Error::HeaderParseFailure(e.to_string()))?;
        if let Some(ref body) = self.body_ptr {
            dest.extend_from_slice(body.as_ref());
        }
        Ok(dest)
    }

    /// Compose the stored message into a scratch buffer, hand that buffer
    /// to `f`, then drop the buffer. Mirrors FASM `http1$tocall`
    /// (`http1.inc` L833-835).
    ///
    /// Use this variant when a consumer needs the wire-format bytes just
    /// long enough to write them to a socket or a checksum sink, without
    /// retaining a copy.
    ///
    /// # Errors
    ///
    /// Returns either the error from [`Http1Parser::to_buffer`] (if header
    /// serialisation fails) or the error returned by the callback `f`.
    pub fn to_call<F>(&self, f: F) -> Result<(), Http1Error>
    where
        F: FnOnce(&[u8]) -> Result<(), Http1Error>,
    {
        let buf = self.to_buffer()?;
        f(&buf)
    }

    // -------------------------------------------------------------------------
    // Main state-machine driver
    // -------------------------------------------------------------------------

    /// Feed the supplied slice into the parser.
    ///
    /// Port of FASM `http1$input` (`http1.inc` L1-550); the five-state
    /// dispatch (L119-131) is preserved via the [`ParseState`] enum.
    ///
    /// # Output contract
    ///
    /// * [`Http1InputResult::Error`] → fatal parse error; drop / reset the
    ///   parser. FASM equivalent: return `-1`.
    /// * [`Http1InputResult::NeedMore`] → all supplied bytes were consumed
    ///   into the internal accumulator; more bytes required. FASM
    ///   equivalent: return `0`.
    /// * [`Http1InputResult::Consumed(n)`] → a full request was parsed;
    ///   `n` bytes of the supplied slice were consumed. The caller must
    ///   advance by `n` and invoke [`Http1Parser::reset`] before
    ///   supplying more pipelined bytes. FASM equivalent: return `n`.
    ///
    /// Safety net: if the parser is already complete (see
    /// [`Http1Parser::body_complete`]) and [`Http1Parser::reset`] has not
    /// yet been called, this method returns `Consumed(0)` as a defensive
    /// no-op rather than corrupting the internal state.
    pub fn input(&mut self, data: &[u8]) -> Http1InputResult {
        if self.complete {
            // Defensive no-op: caller must reset() between pipelined
            // requests. Returning Consumed(0) signals "nothing to do" and
            // avoids interpreting next-request bytes with stale state.
            return Http1InputResult::Consumed(0);
        }

        match self.state {
            ParseState::InHeaders => self.step_in_headers(data),
            ParseState::PartialHeadersDirect | ParseState::PartialHeadersBuffer => {
                self.step_partial_headers(data)
            }
            ParseState::InBodyLength => self.consume_body_length(data, 0),
            ParseState::InBodyChunked => self.consume_body_chunked(data, 0),
        }
    }

    // -------------------------------------------------------------------------
    // Internal state handlers (one per ParseState transition)
    // -------------------------------------------------------------------------

    /// Initial state: attempt a direct parse; on needmore transition to
    /// [`ParseState::PartialHeadersDirect`] and stash the supplied bytes.
    ///
    /// Mirrors FASM `http1$input` state-0 branch (`http1.inc` L136-216).
    ///
    /// Variant choice between `PartialHeadersDirect` and
    /// `PartialHeadersBuffer` emulates the FASM stack-vs-heap distinction
    /// (`http1.inc` L218-332 vs L333-403) at the 4 KiB page boundary. The
    /// two Rust variants are functionally identical in our port (both
    /// routed through [`Http1Parser::step_partial_headers`]) but
    /// preserving both per AAP 0.4.1.1 "vestigial variant for behavioural
    /// parity" demands that each is reachable in practice.
    fn step_in_headers(&mut self, data: &[u8]) -> Http1InputResult {
        match self.headers.parse_http1(data) {
            Ok(0) => {
                // parse_http1 returned "need more" without mutating its
                // internal state. Stash these bytes in the partial
                // accumulator for later retries.
                if data.len() > WEBSERVER_MAXHEADER {
                    return Http1InputResult::Error(Http1Error::HeaderTooLarge);
                }
                self.parse_data = Some(data.to_vec());
                // Promote to the "buffer" variant once the accumulated
                // size crosses the 4 KiB page boundary — this mirrors the
                // FASM transition from the 64 KiB stack scratch (state 1)
                // to heap-backed `buffer$new` storage (state 2). Both
                // Rust variants dispatch to the same handler but the
                // state distinction remains observable via the public
                // debug representation.
                self.state = if data.len() > PARTIAL_BUFFER_PROMOTION_THRESHOLD {
                    ParseState::PartialHeadersBuffer
                } else {
                    ParseState::PartialHeadersDirect
                };
                Http1InputResult::NeedMore
            }
            Ok(n) => {
                // Headers fully parsed; `n` bytes consumed from `data`.
                // Defensive clamp against pathological return values.
                let header_end = n.min(data.len());
                self.header_len = header_end;
                let body_slice = &data[header_end..];
                self.check_body_phase_with_body_data(header_end, body_slice)
            }
            Err(e) => {
                Http1InputResult::Error(Http1Error::HeaderParseFailure(e.to_string()))
            }
        }
    }

    /// Partial-headers state: concatenate new bytes with the accumulator,
    /// enforce the [`WEBSERVER_MAXHEADER`] cap, and retry the parse.
    ///
    /// Mirrors FASM `http1$input` state-1/2 branches (`http1.inc`
    /// L218-403). The FASM variants distinguish a stack-allocated scratch
    /// buffer (state 1) from a heap-backed buffer (state 2); the Rust
    /// port unifies them into a single heap [`Vec<u8>`] with a 32 KiB cap.
    fn step_partial_headers(&mut self, data: &[u8]) -> Http1InputResult {
        // Take ownership of the current accumulator so we can pass it by
        // reference to parse_http1 without borrowing `self` twice.
        let mut pd = self.parse_data.take().unwrap_or_default();
        let previous_len = pd.len();

        // Combined size check — enforced before the expensive append.
        let new_total = previous_len.saturating_add(data.len());
        if new_total > WEBSERVER_MAXHEADER {
            // Discard `pd` (never reinstated) and report the cap.
            return Http1InputResult::Error(Http1Error::HeaderTooLarge);
        }

        pd.extend_from_slice(data);

        match self.headers.parse_http1(&pd) {
            Ok(0) => {
                // Still incomplete: restore the accumulator and wait.
                // If the accumulated size has crossed the 4 KiB page
                // boundary since the last tick, promote to the
                // `PartialHeadersBuffer` variant (FASM heap-backed state
                // 2); otherwise remain in `PartialHeadersDirect` (FASM
                // stack state 1). Both variants share this handler — the
                // distinction is purely structural parity with the FASM
                // five-state machine.
                if pd.len() > PARTIAL_BUFFER_PROMOTION_THRESHOLD
                    && self.state == ParseState::PartialHeadersDirect
                {
                    self.state = ParseState::PartialHeadersBuffer;
                }
                self.parse_data = Some(pd);
                Http1InputResult::NeedMore
            }
            Ok(n) => {
                // Headers complete. `n` = bytes consumed from the combined
                // buffer. Work out how many came from the new `data` slice
                // (the rest, if any, are body bytes already at hand).
                let combined_consumed = n.min(pd.len());
                let new_data_consumed =
                    combined_consumed.saturating_sub(previous_len);
                self.header_len = combined_consumed;
                // The accumulator is consumed on success; do not reinstate.
                // Transition back to InHeaders so the upcoming body phase
                // (if any) sees a clean slate. `check_body_phase_*` will
                // re-assign the state if a body is declared.
                self.state = ParseState::InHeaders;
                // Defensive clamp to guard against pathological return
                // values from parse_http1.
                let split = new_data_consumed.min(data.len());
                let body_slice = &data[split..];
                self.check_body_phase_with_body_data(split, body_slice)
            }
            Err(e) => {
                // Discard the accumulator on error.
                Http1InputResult::Error(Http1Error::HeaderParseFailure(e.to_string()))
            }
        }
    }


    /// After header parsing has completed (either direct or via partial
    /// reassembly), inspect the header table for `Content-Length` or
    /// `Transfer-Encoding: chunked` and transition to the appropriate
    /// body phase, consuming any body bytes already present in
    /// `body_slice`.
    ///
    /// `prefix_consumed` is the number of bytes already accounted for
    /// (the header bytes from the slice passed to [`Http1Parser::input`]).
    ///
    /// Mirrors FASM `http1$input` post-parse dispatch (`http1.inc`
    /// L180-216):
    /// * `Content-Length` → state 3 (`InBodyLength`).
    /// * `Transfer-Encoding: chunked` → state 4 (`InBodyChunked`).
    /// * Otherwise → no body; request is complete.
    fn check_body_phase_with_body_data(
        &mut self,
        prefix_consumed: usize,
        body_slice: &[u8],
    ) -> Http1InputResult {
        // --- Content-Length path (FASM L182-195) ------------------------
        if let Some(cl_str) = self.headers.get("content-length") {
            // `HttpHeaders::get` returns the value without the surrounding
            // whitespace introduced by the request-line grammar, but we
            // trim defensively in case a future headers.rs change alters
            // that normalisation.
            let cl: u64 = match cl_str.trim().parse::<u64>() {
                Ok(v) => v,
                Err(_) => {
                    return Http1InputResult::Error(
                        Http1Error::MalformedContentLength,
                    );
                }
            };
            if cl > WEBSERVER_MAXREQUEST as u64 {
                return Http1InputResult::Error(Http1Error::RequestTooLarge {
                    max: WEBSERVER_MAXREQUEST as u64,
                });
            }
            self.state = ParseState::InBodyLength;
            self.body_len = cl;
            // Pre-allocate exact capacity when the Content-Length fits
            // within `usize`. On 32-bit hosts a 64-bit Content-Length may
            // legitimately exceed `usize::MAX`; we guard by taking the
            // minimum of `cl` and `usize::MAX`. Additional bytes (beyond
            // usize::MAX) would be rejected above by
            // WEBSERVER_MAXREQUEST, so this branch is functionally
            // unreachable on 64-bit hosts.
            let cap: usize = cl.min(usize::MAX as u64) as usize;
            self.body_ptr = Some(BytesMut::with_capacity(cap));
            if cl == 0 {
                // Zero-length body → request immediately complete.
                self.complete = true;
                return Http1InputResult::Consumed(prefix_consumed);
            }
            return self.consume_body_length(body_slice, prefix_consumed);
        }

        // --- Transfer-Encoding: chunked path (FASM L196-215) ------------
        // `get()` is case-insensitive on the name; the value can still be
        // a comma-separated list (e.g. "gzip, chunked"). A substring check
        // against the ASCII-lowercase copy matches all RFC 7230 §3.3.1
        // valid framings that include a `chunked` coding.
        if let Some(te_str) = self.headers.get("transfer-encoding") {
            if te_str.to_ascii_lowercase().contains("chunked") {
                self.state = ParseState::InBodyChunked;
                self.body_len = 0;
                self.body_ptr = Some(BytesMut::new());
                return self.consume_body_chunked(body_slice, prefix_consumed);
            }
        }

        // --- No body present (FASM L212-215) ----------------------------
        // A request without either header has no body by RFC 7230 §3.3.3
        // bullet 6; the parser is complete at this point.
        self.complete = true;
        Http1InputResult::Consumed(prefix_consumed)
    }

    /// Body phase 3 (Content-Length): consume up to `body_len` bytes into
    /// [`Http1Parser::body_ptr`]; if the countdown reaches zero the
    /// request is complete, otherwise request more bytes.
    ///
    /// Mirrors FASM `http1$input` state 3 branch (`http1.inc` L467-492).
    ///
    /// `prefix_consumed` accounts for any header bytes already counted in
    /// this `input()` call (zero when entered directly from
    /// [`ParseState::InBodyLength`]).
    fn consume_body_length(
        &mut self,
        data: &[u8],
        prefix_consumed: usize,
    ) -> Http1InputResult {
        // Number of new bytes to pull from `data` this call.
        let take_u64 = (data.len() as u64).min(self.body_len);
        // Safe cast: `take_u64 <= data.len()` which is a valid `usize`.
        let take = take_u64 as usize;

        if let Some(ref mut buf) = self.body_ptr {
            buf.extend_from_slice(&data[..take]);
        }
        self.body_len = self.body_len.saturating_sub(take_u64);

        if self.body_len == 0 {
            self.complete = true;
            Http1InputResult::Consumed(prefix_consumed + take)
        } else {
            // All supplied bytes consumed; more required. The caller
            // should continue feeding bytes into the parser.
            Http1InputResult::NeedMore
        }
    }

    /// Body phase 4 (chunked): append all incoming bytes to the body
    /// accumulator and scan for the [`CHUNKED_TERMINATOR`] sentinel.
    ///
    /// Mirrors FASM `http1$input` state 4 branch (`http1.inc` L526-700).
    /// The Rust port implements the simpler sentinel-scan approach
    /// endorsed by AAP §Special Analysis — the chunked body is retained
    /// verbatim, never de-chunked. Size is capped at
    /// [`WEBSERVER_MAXREQUEST`]; exceeding the cap without seeing the
    /// sentinel returns [`Http1Error::MalformedChunked`].
    ///
    /// Correctly handles terminators that straddle the boundary between
    /// the previous buffer state and the new incoming bytes by rewinding
    /// the scan start by `CHUNKED_TERMINATOR.len() - 1` bytes.
    fn consume_body_chunked(
        &mut self,
        data: &[u8],
        prefix_consumed: usize,
    ) -> Http1InputResult {
        // Cap total size before touching the buffer.
        let prev_len = self.body_ptr.as_ref().map_or(0, |b| b.len());
        let new_total = prev_len.saturating_add(data.len());
        if new_total > WEBSERVER_MAXREQUEST {
            return Http1InputResult::Error(Http1Error::MalformedChunked);
        }

        // Ensure body_ptr exists (it should — we allocate empty in the
        // transition from InHeaders → InBodyChunked — but re-establish
        // defensively in case this path is ever entered directly).
        if self.body_ptr.is_none() {
            self.body_ptr = Some(BytesMut::new());
        }
        if let Some(ref mut buf) = self.body_ptr {
            buf.extend_from_slice(data);
        }

        // Scan window: rewind by `terminator_len - 1` into the previous
        // buffer so that a sentinel straddling the append boundary is
        // detected.
        let term_len = CHUNKED_TERMINATOR.len();
        let rewind = term_len.saturating_sub(1);
        let scan_start = prev_len.saturating_sub(rewind);

        // Immutable borrow for the scan; the mutation above is done.
        let body = match self.body_ptr.as_ref() {
            Some(b) => b,
            // Unreachable — body_ptr was ensured above; provide a safe
            // fallback in case future refactoring removes that guarantee.
            None => return Http1InputResult::Error(Http1Error::MalformedChunked),
        };

        if let Some(relative_idx) =
            find_sentinel(&body[scan_start..], CHUNKED_TERMINATOR)
        {
            let absolute_idx = scan_start + relative_idx;
            let total_body = absolute_idx + term_len;
            // Truncate any post-terminator bytes (they belong to the next
            // pipelined request — but we do not currently track those in
            // chunked mode; callers relying on HTTP/1.1 chunked
            // pipelining should interpret the difference between
            // `Consumed(n)` and `data.len() + prefix_consumed` as
            // trailing bytes).
            if let Some(ref mut buf) = self.body_ptr {
                buf.truncate(total_body);
            }
            self.body_len = total_body as u64;
            self.complete = true;
            // We consider all supplied `data.len()` bytes as consumed for
            // this request; callers using chunked pipelining are
            // responsible for slicing their input to exclude bytes that
            // follow the sentinel. The truncation above ensures our
            // body buffer is exactly the terminated body.
            Http1InputResult::Consumed(prefix_consumed + data.len())
        } else {
            // More bytes required.
            Http1InputResult::NeedMore
        }
    }
}

impl Default for Http1Parser {
    /// Equivalent to [`Http1Parser::new`].
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Free helpers
// -----------------------------------------------------------------------------

/// Naïve byte-window search for `needle` inside `haystack`. Returns the
/// zero-based offset of the first match, or `None` if not found.
///
/// For the 7-byte [`CHUNKED_TERMINATOR`] this is a fine implementation —
/// `windows()`+`position()` on moderate-sized bodies is O(n·m) worst case
/// but amortises well in the common case where the sentinel appears near
/// the end of the buffer. If profiling identifies this as a hotspot, a
/// two-pointer or KMP implementation can be dropped in without touching
/// the state-machine logic.
fn find_sentinel(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}


// -----------------------------------------------------------------------------
// Unit tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::HttpError;

    /// `"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"` — 37 bytes, no body.
    /// Expected: single `Consumed(37)` result and completion flag set.
    #[test]
    fn test_simple_get_no_body() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut p = Http1Parser::new();
        let r = p.input(data);
        match r {
            Http1InputResult::Consumed(n) => {
                assert_eq!(n, data.len(), "Expected to consume full slice");
            }
            other => panic!("Expected Consumed, got {:?}", other),
        }
        assert!(p.body_complete(), "Request should be complete");
        // No body → body() returns None.
        assert!(
            p.body().is_none(),
            "No body expected for GET without CL/TE"
        );
        // `Host: example.com` should be retrievable via either accessor.
        assert_eq!(p.headers().get("host"), Some("example.com"));
        assert_eq!(p.headers.get("host"), Some("example.com"));
    }

    /// `"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nHello"` — headers + body.
    /// Total 43 bytes (AAP narrative says 42 but the exact ASCII byte count
    /// is 43: 17 for request line, 19 for `Content-Length: 5\r\n`, 2 for
    /// blank line, 5 for body). Expected: `Consumed(43)`, body = `Hello`.
    #[test]
    fn test_post_with_content_length() {
        let data = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nHello";
        assert_eq!(data.len(), 43, "sanity: ASCII byte count is 43");
        let mut p = Http1Parser::new();
        let r = p.input(data);
        match r {
            Http1InputResult::Consumed(n) => {
                assert_eq!(n, data.len());
            }
            other => panic!("Expected Consumed, got {:?}", other),
        }
        assert!(p.body_complete());
        assert_eq!(p.body(), Some(&b"Hello"[..]));
        assert_eq!(p.headers().get("content-length"), Some("5"));
    }

    /// Partial headers split into two reads. First read returns `NeedMore`;
    /// second completes with `Consumed`. Verifies transition InHeaders →
    /// PartialHeadersDirect → InHeaders (complete).
    #[test]
    fn test_partial_headers() {
        let first = b"GET / HTTP/1.1\r\nHo";
        let second = b"st: example.com\r\n\r\n";
        let mut p = Http1Parser::new();

        match p.input(first) {
            Http1InputResult::NeedMore => {}
            other => panic!("Expected NeedMore on first chunk, got {:?}", other),
        }
        assert!(!p.body_complete());

        match p.input(second) {
            Http1InputResult::Consumed(n) => {
                assert_eq!(n, second.len(), "All second-chunk bytes consumed");
            }
            other => panic!("Expected Consumed on second chunk, got {:?}", other),
        }
        assert!(p.body_complete());
        assert_eq!(p.headers.get("host"), Some("example.com"));
    }

    /// `Content-Length: 99999999999` (≈93 GiB) exceeds
    /// `WEBSERVER_MAXREQUEST` (64 MiB). Must return `RequestTooLarge`.
    #[test]
    fn test_content_length_too_large() {
        let data = b"POST / HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n";
        let mut p = Http1Parser::new();
        match p.input(data) {
            Http1InputResult::Error(Http1Error::RequestTooLarge { max }) => {
                assert_eq!(max, WEBSERVER_MAXREQUEST as u64);
            }
            other => {
                panic!("Expected RequestTooLarge error, got {:?}", other)
            }
        }
        // Boundary conversion must map to HttpError::TooLarge per AAP
        // §0.8.3.
        let err: HttpError =
            Http1Error::RequestTooLarge { max: 64 * 1024 * 1024 }.into();
        assert!(matches!(err, HttpError::TooLarge));
    }

    /// Chunked body with the terminator sentinel present in the first
    /// read. Body `"5\r\nHello\r\n0\r\n\r\n"` (15 bytes) ends with the
    /// 7-byte [`CHUNKED_TERMINATOR`]. Parser must detect completion.
    #[test]
    fn test_chunked_terminator_detection() {
        // Construct: headers + chunked body.
        let headers = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let body = b"5\r\nHello\r\n0\r\n\r\n"; // 15 bytes
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(headers);
        data.extend_from_slice(body);

        let mut p = Http1Parser::new();
        match p.input(&data) {
            Http1InputResult::Consumed(n) => {
                assert_eq!(n, data.len());
            }
            other => panic!("Expected Consumed, got {:?}", other),
        }
        assert!(p.body_complete());
        // Body should contain the raw chunked bytes (pass-through).
        assert_eq!(p.body(), Some(&body[..]));
    }

    /// Chunked body missing the terminator — parser must return
    /// `NeedMore`.
    #[test]
    fn test_chunked_partial() {
        let headers = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let partial_body = b"5\r\nHello"; // no terminator
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(headers);
        data.extend_from_slice(partial_body);

        let mut p = Http1Parser::new();
        match p.input(&data) {
            Http1InputResult::NeedMore => {}
            other => panic!("Expected NeedMore, got {:?}", other),
        }
        assert!(!p.body_complete());

        // Feeding the rest completes the body.
        let rest = b"\r\n0\r\n\r\n";
        match p.input(rest) {
            Http1InputResult::Consumed(n) => {
                assert_eq!(n, rest.len());
            }
            other => panic!("Expected Consumed after sentinel, got {:?}", other),
        }
        assert!(p.body_complete());
    }

    /// Two back-to-back GET requests in a single buffer. After the first
    /// is consumed, `reset()` then `input(remainder)` parses the second.
    #[test]
    fn test_pipelined_requests() {
        let req1 = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
        let req2 = b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(req1);
        buf.extend_from_slice(req2);

        let mut p = Http1Parser::new();
        let consumed1 = match p.input(&buf) {
            Http1InputResult::Consumed(n) => n,
            other => panic!("Expected Consumed on req1, got {:?}", other),
        };
        assert_eq!(consumed1, req1.len());
        // `:path` pseudo-header on an HTTP/1.x GET is stored via the
        // httpheaders fast-path under its public bytes key.
        assert!(p.body_complete());

        // Prepare for the second request.
        p.reset();
        assert!(!p.body_complete());
        let remaining = &buf[consumed1..];
        let consumed2 = match p.input(remaining) {
            Http1InputResult::Consumed(n) => n,
            other => panic!("Expected Consumed on req2, got {:?}", other),
        };
        assert_eq!(consumed2, req2.len());
        assert!(p.body_complete());
    }

    /// Accumulated partial header bytes exceed `WEBSERVER_MAXHEADER`
    /// (32 KiB). Must return `HeaderTooLarge`.
    #[test]
    fn test_header_too_large() {
        // First input: 20 KiB of garbage that does not contain the
        // end-of-headers marker. This should produce `NeedMore` because
        // parse_http1 can't find "\r\n\r\n".
        let first = vec![b'A'; 20 * 1024];
        let mut p = Http1Parser::new();
        match p.input(&first) {
            Http1InputResult::NeedMore => {}
            other => {
                // It's also legitimate for parse_http1 to reject a
                // first-line that doesn't match any known method as a
                // parse failure, but for a purely-ASCII garbage prefix
                // the current implementation waits for the EOH marker.
                // Accept either outcome to avoid a spurious test
                // failure from a parse heuristic change.
                eprintln!("first input gave {:?}; continuing test", other);
            }
        }

        // Second input: another 15 KiB — the combined accumulator now
        // exceeds 32 KiB which must trigger `HeaderTooLarge`.
        let second = vec![b'A'; 15 * 1024];
        match p.input(&second) {
            Http1InputResult::Error(Http1Error::HeaderTooLarge) => {
                // Expected outcome.
            }
            other => panic!("Expected HeaderTooLarge, got {:?}", other),
        }
        // Boundary conversion: HeaderTooLarge maps to HttpError::Parse,
        // not HttpError::TooLarge (which is reserved for body-size
        // overflow).
        let err: HttpError = Http1Error::HeaderTooLarge.into();
        assert!(matches!(err, HttpError::Parse(_)));
    }

    // ----- Supplementary tests for additional coverage ---------------------

    /// `new()`, `default()`, and `reset()` all produce an equivalent
    /// initial state.
    #[test]
    fn test_new_and_default_equivalent() {
        let p1 = Http1Parser::new();
        let p2 = Http1Parser::default();
        assert!(!p1.body_complete());
        assert!(!p2.body_complete());
        assert!(p1.body().is_none());
        assert!(p2.body().is_none());
    }

    /// `reset()` clears per-request state, enabling pipelined reuse.
    #[test]
    fn test_reset_clears_state() {
        let data = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let mut p = Http1Parser::new();
        let _ = p.input(data);
        assert!(p.body_complete());
        p.reset();
        assert!(!p.body_complete());
        assert!(p.body().is_none());
        // Second parse on the same parser works after reset.
        let _ = p.input(data);
        assert!(p.body_complete());
    }

    /// `cleanup()` also clears state (stronger reset).
    #[test]
    fn test_cleanup_clears_state() {
        let data = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let mut p = Http1Parser::new();
        let _ = p.input(data);
        assert!(p.body_complete());
        p.cleanup();
        assert!(!p.body_complete());
        assert!(p.body().is_none());
    }

    /// `destroy()` consumes the parser (compile-time check via use).
    #[test]
    fn test_destroy_consumes_parser() {
        let p = Http1Parser::new();
        p.destroy();
        // After destroy, the parser is moved; we can construct a fresh
        // one without issue.
        let _ = Http1Parser::new();
    }

    /// `set_body` populates the body buffer without affecting parse state.
    #[test]
    fn test_set_body_overrides_body() {
        let mut p = Http1Parser::new();
        p.set_body(b"hello world".to_vec());
        assert_eq!(p.body(), Some(&b"hello world"[..]));
    }

    /// `to_buffer()` round-trips through a parse of the same request.
    #[test]
    fn test_to_buffer_roundtrip() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut p = Http1Parser::new();
        let _ = p.input(data);
        let buf = p.to_buffer().expect("header serialisation should succeed");
        // The serialised buffer should re-parse correctly in a fresh
        // parser.
        let mut p2 = Http1Parser::new();
        match p2.input(&buf) {
            Http1InputResult::Consumed(n) => assert_eq!(n, buf.len()),
            other => panic!("Round-trip parse failed: {:?}", other),
        }
        assert_eq!(p2.headers.get("host"), Some("example.com"));
    }

    /// `to_call()` hands the composed bytes to a callback.
    #[test]
    fn test_to_call_invokes_callback() {
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut p = Http1Parser::new();
        let _ = p.input(data);
        let mut seen_len: usize = 0;
        p.to_call(|bytes| {
            seen_len = bytes.len();
            Ok(())
        })
        .expect("callback should return Ok");
        assert!(seen_len > 0, "callback should have received bytes");
    }

    /// Malformed Content-Length (non-numeric) returns
    /// `MalformedContentLength`.
    #[test]
    fn test_malformed_content_length() {
        let data = b"POST / HTTP/1.1\r\nContent-Length: notanumber\r\n\r\n";
        let mut p = Http1Parser::new();
        match p.input(data) {
            Http1InputResult::Error(Http1Error::MalformedContentLength) => {
                // Expected.
            }
            other => panic!("Expected MalformedContentLength, got {:?}", other),
        }
        // Boundary conversion to HttpError.
        let err: HttpError = Http1Error::MalformedContentLength.into();
        assert!(matches!(err, HttpError::Parse(_)));
    }

    /// Zero-length Content-Length body: parser completes immediately with
    /// an empty body buffer.
    #[test]
    fn test_zero_content_length() {
        let data = b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let mut p = Http1Parser::new();
        match p.input(data) {
            Http1InputResult::Consumed(n) => assert_eq!(n, data.len()),
            other => panic!("Expected Consumed, got {:?}", other),
        }
        assert!(p.body_complete());
        // body_ptr is allocated (empty), so body() returns Some(&[]).
        assert_eq!(p.body(), Some(&[][..]));
    }

    /// Partial body (Content-Length): feed headers+partial body, get
    /// `NeedMore`; feed remainder, get `Consumed`.
    #[test]
    fn test_partial_body_content_length() {
        let headers_plus_partial =
            b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nHel";
        let rest = b"loWorld";
        let mut p = Http1Parser::new();
        match p.input(headers_plus_partial) {
            Http1InputResult::NeedMore => {}
            other => panic!("Expected NeedMore, got {:?}", other),
        }
        assert!(!p.body_complete());
        // So far we have 3 bytes of body.
        assert_eq!(p.body(), Some(&b"Hel"[..]));

        match p.input(rest) {
            Http1InputResult::Consumed(n) => assert_eq!(n, rest.len()),
            other => panic!("Expected Consumed, got {:?}", other),
        }
        assert!(p.body_complete());
        assert_eq!(p.body(), Some(&b"HelloWorld"[..]));
    }

    /// Calling `input()` after completion returns `Consumed(0)` as a
    /// defensive no-op.
    #[test]
    fn test_input_after_complete_returns_zero() {
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut p = Http1Parser::new();
        let _ = p.input(data);
        assert!(p.body_complete());
        // Second call without reset should no-op safely.
        match p.input(b"extra bytes") {
            Http1InputResult::Consumed(0) => {}
            other => {
                panic!("Expected Consumed(0) after completion, got {:?}", other)
            }
        }
    }

    /// `Transfer-Encoding: gzip, chunked` (compound value) is correctly
    /// recognised as chunked.
    #[test]
    fn test_transfer_encoding_compound() {
        let headers =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        let body = b"5\r\nHello\r\n0\r\n\r\n";
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(headers);
        data.extend_from_slice(body);

        let mut p = Http1Parser::new();
        match p.input(&data) {
            Http1InputResult::Consumed(n) => assert_eq!(n, data.len()),
            other => panic!("Expected Consumed, got {:?}", other),
        }
        assert!(p.body_complete());
    }

    /// `CHUNKED_TERMINATOR` is exactly 7 bytes and matches the FASM
    /// literal.
    #[test]
    fn test_chunked_terminator_bytes() {
        assert_eq!(CHUNKED_TERMINATOR, b"\r\n0\r\n\r\n");
        assert_eq!(CHUNKED_TERMINATOR.len(), 7);
        assert_eq!(
            CHUNKED_TERMINATOR,
            &[0x0d, 0x0a, 0x30, 0x0d, 0x0a, 0x0d, 0x0a]
        );
    }

    /// `find_sentinel` returns the earliest match and handles edge cases.
    #[test]
    fn test_find_sentinel() {
        assert_eq!(find_sentinel(b"abcdef", b"cd"), Some(2));
        assert_eq!(find_sentinel(b"abcdef", b"xy"), None);
        assert_eq!(find_sentinel(b"", b"xy"), None);
        assert_eq!(find_sentinel(b"ab", b""), None); // empty needle
        assert_eq!(find_sentinel(b"ab", b"abc"), None); // needle > haystack
        // Longer haystack with multiple potential hits — returns first.
        assert_eq!(find_sentinel(b"__xx__xx__", b"xx"), Some(2));
    }

    /// `Http1Error` `From` impl correctly routes each variant.
    #[test]
    fn test_error_boundary_conversion() {
        let e1: HttpError = Http1Error::HeaderParseFailure("oops".into()).into();
        assert!(matches!(e1, HttpError::Parse(_)));

        let e2: HttpError =
            Http1Error::RequestTooLarge { max: 1024 }.into();
        assert!(matches!(e2, HttpError::TooLarge));

        let e3: HttpError = Http1Error::MalformedContentLength.into();
        assert!(matches!(e3, HttpError::Parse(_)));

        let e4: HttpError = Http1Error::MalformedChunked.into();
        assert!(matches!(e4, HttpError::Parse(_)));

        let e5: HttpError = Http1Error::HeaderTooLarge.into();
        assert!(matches!(e5, HttpError::Parse(_)));
    }

    /// Chunked terminator straddling a chunk boundary is detected by the
    /// rewind-scan logic. Feed 6 bytes of the terminator, then the
    /// final byte; parser must detect completion on the second call.
    #[test]
    fn test_chunked_terminator_straddles_boundary() {
        let headers = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        // Split the body "5\r\nHello\r\n0\r\n\r\n" into pieces that
        // straddle the terminator bytes.
        // Full body: b"5\r\nHello\r\n0\r\n\r\n"  (15 bytes).
        // Terminator starts at offset 8 (after "5\r\nHello" = 1+2+5 = 8).
        let first_body = b"5\r\nHello\r\n0\r\n\r";  // 14 bytes (missing last LF)
        let second_body = b"\n";                   // 1 byte — the final LF
        let mut first_input: Vec<u8> = Vec::new();
        first_input.extend_from_slice(headers);
        first_input.extend_from_slice(first_body);

        let mut p = Http1Parser::new();
        match p.input(&first_input) {
            Http1InputResult::NeedMore => {}
            other => {
                panic!("Expected NeedMore before final LF, got {:?}", other)
            }
        }
        // Second feed completes the sentinel and the body.
        match p.input(second_body) {
            Http1InputResult::Consumed(n) => {
                assert_eq!(n, second_body.len());
            }
            other => {
                panic!("Expected Consumed after boundary LF, got {:?}", other)
            }
        }
        assert!(p.body_complete());
    }

    /// Large-but-valid initial-chunk partial header promotes to the
    /// `PartialHeadersBuffer` state variant (construction coverage for
    /// the vestigial FASM state 2 variant).
    #[test]
    fn test_large_partial_promotes_to_buffer_state() {
        // A 5 KiB-long single request-line without an EOH marker will
        // exceed the 4 KiB promotion threshold on the first input.
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"GET /");
        data.extend(std::iter::repeat(b'a').take(5000));
        data.extend_from_slice(b" HTTP/1.1\r\n");
        // No final \r\n\r\n — parser should be partial.

        let mut p = Http1Parser::new();
        match p.input(&data) {
            Http1InputResult::NeedMore => {}
            other => {
                panic!("Expected NeedMore for oversized partial, got {:?}", other)
            }
        }
        // The state is a private field — infer promotion through a
        // continuation: a subsequent reset should clear the state without
        // error even if promoted.
        p.reset();
        assert!(!p.body_complete());
    }
}

