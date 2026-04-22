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

//! Data-structures subsystem — aggregator module for foundational containers.
//!
//! This subsystem translates the four data-structure `.inc` assembly files
//! (`buffer.inc`, `list.inc`, `maps.inc`, `memfuncs.inc`) into idiomatic Rust
//! wrappers over the standard-library collections per AAP §0.5.1.6 and
//! §0.8.9 (MUST use std collections where semantically equivalent). The
//! submodules provide:
//!
//! * [`buffer`] — byte buffer with capacity-preserving `clear`, deflate-ready
//!   `extend_from_slice`, and bounds-checked mutation (port of `buffer.inc`).
//! * [`list`] — deque-like `List<T>` wrapping `std::collections::VecDeque`,
//!   preserving the assembly `list$foreach` callback idiom (port of `list.inc`).
//! * [`maps`] — `StringMap<V>` over `HashMap` for request/header lookups and
//!   `OrderedMap<K: Ord, V>` over `BTreeMap` for epoll timer AVL walks
//!   (port of `maps.inc`).
//! * [`memfuncs`] — safe slice copy/fill/compare/XOR helpers matching the
//!   assembly `memcpy`/`memset`/`memcmp` surface (port of `memfuncs.inc`).
//!
//! The crate-wide [`DsError`](crate::error::DsError) error type (with
//! `BufferOverflow { requested, capacity }` and `KeyNotFound` variants) is
//! surfaced through [`crate::error`] and consumed by this subsystem's fallible
//! APIs, e.g. [`buffer::Buffer::truncate`], [`list::List::insert`],
//! [`maps::StringMap::get_required`], and [`memfuncs::copy`].
//!
//! Per AAP §0.7.4.1 this subsystem contains **zero** `unsafe` blocks;
//! correctness derives entirely from the standard library and the type
//! system. All public APIs honor AAP §0.8.3's no-panic / no-silent-loss
//! discipline by returning [`DsError`](crate::error::DsError) on bounded
//! operations.

/// Byte buffer with capacity-preserving `clear` and file I/O helpers —
/// port of `buffer.inc`.
pub mod buffer;

/// Deque-like linked list wrapping `std::collections::VecDeque` —
/// port of `list.inc`.
pub mod list;

/// `StringMap<V>` + `OrderedMap<K: Ord, V>` over `HashMap` / `BTreeMap` —
/// port of `maps.inc`.
pub mod maps;

/// Safe slice copy / fill / compare / XOR helpers — port of `memfuncs.inc`.
pub mod memfuncs;

// Flat re-exports of the primary container types so consumers can write
// `use heavything::ds::{Buffer, List, OrderedMap, StringMap};` rather than
// the longer submodule-qualified paths. These are the types named in the
// AAP §0.5.1.6 compliance matrix and exercised by the `ds_integration`
// integration-test target.
pub use buffer::Buffer;
pub use list::List;
pub use maps::{OrderedMap, StringMap};
