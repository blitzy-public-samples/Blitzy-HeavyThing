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
//! * `http1` — HTTP/1.1 request/response state machine (scheduled — port of
//!   `http1.inc`).
//! * `mimelike` — MIME-like parser for HTTP messages with gzip threshold and
//!   chunked-transfer framing (scheduled — port of `mimelike.inc`).
//! * `cookiejar` — session cookie storage (scheduled — port of
//!   `cookiejar.inc`).
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
