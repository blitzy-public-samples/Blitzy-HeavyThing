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

//! HTTP/1.x and HTTP/2 subsystem for HeavyThing.
//!
//! This module aggregates the six HTTP-related submodules that collectively
//! port the FASM HeavyThing HTTP stack:
//!
//! - [`cookiejar`] — port of `cookiejar.inc`: session cookie storage for the
//!   webclient (automated-agent-focused; not security-minded per FASM comment).
//!
//! - [`headers`] — port of `httpheaders.inc`: HTTP/1.x header parse/compose plus
//!   full HPACK (RFC 7541) encoder/decoder with all 4 Huffman tables preserved
//!   byte-identically from FASM.  Provides 59 standard header name constants,
//!   the 61-entry HPACK static table, and the [`headers::HttpHeaders`] container.
//!
//! - [`http1`] — port of `http1.inc`: HTTP/1.x state-machine driver that
//!   consumes bytes from an [`crate::net::io::IoChain`] and produces parsed
//!   request or response messages.
//!
//! - [`mimelike`] — port of `mimelike.inc`: dual-use MIME + HTTP/1.x message
//!   parser (author's 20-year-refined parser).  Handles fixed-length,
//!   chunked, and multipart bodies, plus gzip/deflate encoding and quoted-
//!   printable decoding.  [`mimelike::Mimelike`] is the canonical message
//!   container used by both [`server`] and [`client`].
//!
//! - [`client`] — port of `webclient.inc`: browser-style persistent HTTP/1.1
//!   client with host-based connection pooling, cookie jar integration,
//!   automatic redirect following, and DNS caching.
//!
//! - [`server`] — port of `webserver.inc`: HTTP/1.1 server with the full
//!   8-stage dispatch pipeline (Method → MIME parse → Size → Host → FuncMap →
//!   FastCGI → Redirect → File serve), mmap file hotlist cache, HSTS header
//!   emission, and BREACH mitigation via the X-NB header.
//!
//! # Architectural note
//!
//! Per AAP §0.5.2.1, this module deliberately does NOT re-export any of its
//! children's types via `pub use`.  Consumers access types via the fully-
//! qualified paths (`crate::net::http::server::WebServer`, etc.) to keep
//! use-sites self-documenting.
//!
//! # Dependency flow within this subsystem
//!
//! ```text
//!            headers (foundational leaf — no intra-subsystem deps)
//!               ▲
//!               │
//!           mimelike (uses headers)
//!               ▲
//!               │
//!      ┌────────┴────────┐
//!   client                 server
//!   (uses mimelike,        (uses mimelike,
//!    headers, http1,       headers, http1,
//!    cookiejar,            plus memmap2 + rng)
//!    dns, url)
//! ```
//!
//! [`crate::net::io::IoChain`]: crate::net::io::IoChain

pub mod client;
pub mod cookiejar;
pub mod headers;
pub mod http1;
pub mod mimelike;
pub mod server;
