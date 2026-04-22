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
//! this repository; declarations for the remaining 12 planned modules
//! (`base64`, `crc`, `date`, `file`, `formatter`, `json`,
//! `mappedheap`, `png`, `privmapped`, `string`, `syslog`, `zlib`) will be
//! added by later checkpoints alongside their implementations. Declaring
//! a `pub mod foo;` without a backing source file is a hard compile error
//! (rustc E0583), so premature declarations would break the whole
//! workspace build — see AAP §0.8.3 and Gate 2's `RUSTFLAGS="-D warnings"`
//! discipline.

/// Directory enumeration helpers — port of `dir.inc`.
pub mod dir;

/// mmap-backed file access — port of `mapped.inc`.
pub mod mapped;

/// Basic math helpers — port of `math.inc`.
pub mod math;

/// Lightweight timing wrapper over `std::time::Instant` — port of `profiler.inc`.
pub mod profiler;

/// Synchronous and asynchronous sleep helpers — port of `sleeps.inc`.
pub mod sleeps;

/// Arbitrary-precision decimal string arithmetic — port of `string_math.inc`.
pub mod string_math;

/// System information helpers (`uname(2)`, CPU count) — port of `sysinfo.inc`.
pub mod sysinfo;

/// Unicode case-mapping helpers — port of `unicodecase.inc`.
pub mod unicodecase;

/// vDSO fast-time API-parity wrapper — port of `vdso.inc`.
pub mod vdso;
