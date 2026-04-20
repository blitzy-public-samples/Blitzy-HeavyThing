// Rust translation © 2026, licensed under GPL-3.0-or-later.
//
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

//! `heavything` — Rust translation of the HeavyThing x86_64 FASM
//! assembly library (crypto, async networking, TUI, data structures,
//! and utilities) per AAP §0.1.1.
//!
//! **This file is an in-progress scaffold.** It currently declares:
//!
//! * The four FASM exit-code constants
//!   ([`EXIT_HEAP_MMAP_FAIL`], [`EXIT_PROFILER_OVERFLOW`],
//!   [`EXIT_ULIMIT_TOO_LOW`], [`EXIT_EPOLL_CREATE_FAIL`]) from
//!   `ht.inc` lines 38–41, which [`error::InitError::exit_code`]
//!   depends on.
//! * The [`config`] module — direct port of `ht_defaults.inc`
//!   exposing every compile-time configuration constant as
//!   `pub const` (AAP §0.5.1.2 / §0.5.2.3).
//! * The [`error`] module — crate-wide typed error taxonomy.
//! * A `pub use` re-export of [`error::InitError`] for ergonomic
//!   access from binary crates.
//!
//! Sibling agents will expand this file with `init()` / `init_args()`
//! and the remaining subsystem module tree (`cpu`, `crypto`, `net`,
//! `tui`, `ds`, `util`) per AAP §0.5.1.2.

/// Exit code when the heap allocator's underlying `mmap(2)` or
/// `mremap(2)` syscall fails. Mirrors `ht.inc` line 38.
///
/// Retained for API parity with the FASM exit-code convention even
/// though the Rust port delegates allocation to `std`.
pub const EXIT_HEAP_MMAP_FAIL: i32 = 99;

/// Exit code when the profiler sample stack overruns its capacity.
/// Mirrors `ht.inc` line 39.
pub const EXIT_PROFILER_OVERFLOW: i32 = 98;

/// Exit code when `RLIMIT_NOFILE` cannot be raised to at least
/// `EPOLL_MINFDS` (4096) via `setrlimit(2)`. Mirrors `ht.inc` line 40.
pub const EXIT_ULIMIT_TOO_LOW: i32 = 97;

/// Exit code when `epoll_create(2)` / Tokio `Runtime::new` fails
/// during startup. Mirrors `ht.inc` line 41.
pub const EXIT_EPOLL_CREATE_FAIL: i32 = 96;

pub mod config;
pub mod error;
pub mod util;

pub use crate::error::InitError;
