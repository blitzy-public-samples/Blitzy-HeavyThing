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

//! Utility subsystem — aggregator module for foundational helpers.
//!
//! This subsystem translates the 22 utility `.inc` assembly files into
//! idiomatic Rust wrappers around `std`, `flate2`, `base64`, `serde_json`,
//! `png`, `crc32fast`, `memmap2`, `libc`, and `nix`. It provides foundational
//! building blocks consumed by the `net`, `tui`, and (indirectly) `crypto`
//! subsystems. See AAP §0.5.1.7 for the per-module source mapping.
//!
//! # Deferred integration
//!
//! The `util/` port is delivered across several checkpoints. This file
//! declares only the submodules that have already landed source files in
//! this repository; declarations for any remaining planned modules will
//! be added by later checkpoints alongside their implementations.
//! Declaring a `pub mod foo;` without a backing source file is a hard
//! compile error (rustc E0583), so premature declarations would break
//! the whole workspace build — see AAP §0.8.3 and Gate 2's
//! `RUSTFLAGS="-D warnings"` discipline.

/// Base64 (RFC 4648) encode/decode — port of `base64_latin1.inc`.
pub mod base64;

/// CRC-32 IEEE 802.3 (gzip/PNG polynomial) — port of `crc.inc`.
pub mod crc;

/// RFC 1123 / RFC 3164 date/time formatting — port of `date.inc`.
pub mod date;

/// Directory enumeration helpers — port of `dir.inc`.
pub mod dir;

/// File I/O helpers (stat, read, write, append, rename, remove) —
/// port of `file.inc`.
pub mod file;

/// Printf-like reusable output formatter — port of `formatter.inc`.
pub mod formatter;

/// JSON parsing/serialization via `serde_json` — port of `json.inc`.
pub mod json;

/// mmap-backed file access — port of `mapped.inc`.
pub mod mapped;

/// Heap-over-mmap allocator used by TLS session cache; port of `mappedheap.inc`.
pub mod mappedheap;

/// Basic math helpers — port of `math.inc`.
pub mod math;

/// PNG image decoding (wraps the `png` crate) — port of `png.inc`.
pub mod png;

/// Private (`MAP_PRIVATE`) mmap variant with filename/mtime/ETag —
/// port of `privmapped.inc`.
pub mod privmapped;

/// Lightweight timing wrapper over `std::time::Instant` — port of `profiler.inc`.
pub mod profiler;

/// Synchronous and asynchronous sleep helpers — port of `sleeps.inc`.
pub mod sleeps;

/// String utilities wrapping Rust `String`/`&str` — consolidates
/// `string32.inc` and `string16.inc`.
pub mod string;

/// Arbitrary-precision decimal string arithmetic — port of `string_math.inc`.
pub mod string_math;

/// System information helpers (`uname(2)`, CPU count) — port of `sysinfo.inc`.
pub mod sysinfo;

/// RFC 3164 syslog messages over `AF_UNIX`/`SOCK_DGRAM` to `/dev/log` —
/// port of `syslog.inc`.
pub mod syslog;

/// Unicode case-mapping helpers — port of `unicodecase.inc`.
pub mod unicodecase;

/// vDSO fast-time API-parity wrapper — port of `vdso.inc`.
pub mod vdso;

/// zlib / gzip / raw-deflate encoding and decoding via `flate2` —
/// port of `zlib_deflate.inc` + `zlib_inflate.inc`.
pub mod zlib;
