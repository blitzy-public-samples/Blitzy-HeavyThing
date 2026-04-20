// ------------------------------------------------------------------------
// HeavyThing x86_64 assembly language library — Rust translation
// Copyright © 2015-2018 2 Ton Digital
// Homepage: https://2ton.com.au/
// Author: Jeff Marrison <jeff@2ton.com.au>
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

//! Utility primitives subsystem for the `heavything` library.
//!
//! This subsystem translates the 22 utility `.inc` assembly files into idiomatic
//! Rust wrappers around `std`, `flate2`, `base64`, `serde_json`, `png`, `crc32fast`,
//! `memmap2`, `libc`, and `nix`. It provides foundational building blocks consumed
//! by the `net`, `tui`, and (indirectly) `crypto` subsystems.
//!
//! See `AAP §0.5.1.7` for the per-module source mapping.

/// Base64 encoding/decoding (wraps the `base64` crate); port of `base64_latin1.inc`.
pub mod base64;

/// CRC-32 IEEE 802.3 (wraps the `crc32fast` crate); port of `crc.inc`.
pub mod crc;

/// Date/time helpers using truncated Julian Date as `f64`; port of `date.inc`.
pub mod date;

/// Directory enumeration via `std::fs::read_dir`; port of `dir.inc`.
pub mod dir;

/// File I/O helpers; port of `file.inc`.
pub mod file;

/// Printf-like output formatter; port of `formatter.inc`.
pub mod formatter;

/// JSON parsing and serialisation (wraps `serde_json`); port of `json.inc`.
pub mod json;

/// mmap-backed file access (wraps `memmap2`); port of `mapped.inc`.
pub mod mapped;

/// Heap-over-mmap allocator used by TLS session cache; port of `mappedheap.inc`.
pub mod mappedheap;

/// Math helpers (GCD, LCM, FP constants); port of `math.inc`.
pub mod math;

/// PNG image parsing (wraps the `png` crate); port of `png.inc`.
pub mod png;

/// `MAP_PRIVATE` mmap-backed file access (wraps `memmap2`); port of `privmapped.inc`.
pub mod privmapped;

/// API-preservation stub for the FASM profiler; port of `profiler.inc`.
pub mod profiler;

/// Sleep wrappers for blocking and async contexts; port of `sleeps.inc`.
pub mod sleeps;

/// Rust `String`/`&str` helpers; port of `string32.inc` + `string16.inc`.
pub mod string;

/// Arbitrary-precision decimal string math; port of `string_math.inc`.
pub mod string_math;

/// `uname(2)` and `/proc/cpuinfo` wrappers; port of `sysinfo.inc`.
pub mod sysinfo;

/// RFC 3164 syslog over `AF_UNIX`/`SOCK_DGRAM` to `/dev/log`; port of `syslog.inc`.
pub mod syslog;

/// Unicode case mapping tables; port of `unicodecase.inc`.
pub mod unicodecase;

/// vDSO wrapper (API-preservation stub); port of `vdso.inc`.
pub mod vdso;

/// zlib deflate/inflate (wraps the `flate2` crate); port of `zlib_deflate.inc` + `zlib_inflate.inc`.
pub mod zlib;
