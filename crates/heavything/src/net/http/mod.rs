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

//! HTTP/1.1 and HTTP/2 aggregator module — header management, HPACK codec,
//! MIME-like parsing, and the HTTP/1.x and HTTP/2 request/response state
//! machines.
//!
//! This subsystem translates the HTTP-related `.inc` assembly files from the
//! HeavyThing library into idiomatic Rust per AAP §0.5.1.4. The complete
//! suite of siblings planned for the subsystem is:
//!
//! * [`headers`] — HTTP/1.x + HTTP/2 header container, HPACK encoder/decoder,
//!   the RFC 7541 static table, and the complete Huffman codec (port of
//!   `httpheaders.inc`).
//! * [`http1`] — HTTP/1.x parser state-machine driver with five-state
//!   dispatch (InHeaders / PartialHeadersDirect / PartialHeadersBuffer /
//!   InBodyLength / InBodyChunked) — port of `http1.inc`.
//! * `mimelike` — MIME-like parser for HTTP messages with gzip threshold and
//!   chunked-transfer framing (scheduled — port of `mimelike.inc`).
//! * [`cookiejar`] — session cookie storage with `Set-Cookie` parsing,
//!   `Cookie:` header emission, persistence buffer round-trip, and
//!   longest-path-wins duplicate resolution (port of `cookiejar.inc`).
//! * `server` — HTTP/1.1 server with the 8-stage dispatch pipeline
//!   (scheduled — port of `webserver.inc`).
//! * `client` — HTTP/1.1 connection-pooled client with redirect support
//!   (scheduled — port of `webclient.inc`).
//! * `fcgi` — FastCGI client over Unix domain socket (scheduled — port of
//!   `fcgiclient.inc`).
//!
//! The crate-wide [`HttpError`](crate::error::HttpError) error type is
//! surfaced through [`crate::error`] and consumed by all HTTP submodules
//! via `From<_> for HttpError` conversions, enabling `?`-propagation across
//! the subsystem (AAP §0.8.3: thiserror for library-level typed errors).
//!
//! Per AAP §0.7.4.1 this subsystem contains **zero** `unsafe` blocks;
//! correctness derives entirely from the standard library, the `Cow`
//! zero-copy storage idiom, and the type system. All public APIs honor
//! AAP §0.8.3's no-panic / no-silent-loss discipline by returning
//! typed error values on bounded operations.

/// HTTP headers container with HPACK (RFC 7541) encoder/decoder,
/// the 61-entry static table, the complete Huffman codec, and
/// HTTP/1.x wire-format parse + compose helpers — port of
/// `httpheaders.inc`.
pub mod headers;

/// HTTP/1.x parser state-machine driver with five-state dispatch
/// (InHeaders / PartialHeadersDirect / PartialHeadersBuffer /
/// InBodyLength / InBodyChunked). Wraps [`headers::HttpHeaders`] as the
/// first step of the pipeline and handles body-phase consumption
/// (Content-Length countdown or chunked sentinel scan). Port of
/// `http1.inc`.
pub mod http1;

/// Dual-use MIME and HTTP/1.1 message parser/composer. Bidirectional
/// — parses a stream of bytes into a structured [`mimelike::Mimelike`]
/// or composes a `Mimelike` back into an on-wire byte stream. Handles
/// chunked Transfer-Encoding, gzip Content-Encoding, quoted-printable
/// and base64 Content-Transfer-Encoding, multipart messages with
/// boundary parameter, and Set-Cookie splitting per
/// [`MIMELIKE_SETCOOKIE_SPLIT`](crate::config::MIMELIKE_SETCOOKIE_SPLIT).
/// Port of `mimelike.inc` (3,814 lines / 23 FASM functions).
pub mod mimelike;

/// HTTP/1.1 cookie storage and matching for automated agents. Provides
/// [`cookiejar::Cookie`] (single 48-byte FASM-layout cookie) and
/// [`cookiejar::CookieJar`] (insertion-ordered list with `set` parser,
/// `get` emitter, longest-path-wins duplicate resolution, and a
/// 7-field semicolon-delimited persistence buffer format). Port of
/// `cookiejar.inc` (942 lines / 6 FASM functions).
pub mod cookiejar;

/// HTTP/1.1 server with the 8-stage dispatch pipeline, mmap-based file
/// hotlist cache, HSTS + BREACH header emission, three-mode response
/// send dispatch, keep-alive pipelining, 30-second idle timeout, and
/// Common Log Format access logs. Port of `webserver.inc` (5,670 lines
/// / ~55 FASM functions).
pub mod server;
