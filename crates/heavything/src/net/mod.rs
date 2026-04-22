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

//! Networking subsystem — aggregator module for the async I/O stack.
//!
//! This subsystem translates the twelve networking `.inc` assembly files
//! (`io.inc`, `epoll.inc`, `epoll_child.inc`, `epoll_dns.inc`, `blacklist.inc`,
//! `url.inc`, `http1.inc`, `httpheaders.inc`, `mimelike.inc`, `webserver.inc`,
//! `webclient.inc`, `fcgiclient.inc`, `cookiejar.inc`, `tls.inc`, `ssh.inc`)
//! into idiomatic Rust modules layered on top of `tokio`, `rustls`, and
//! friends per AAP §0.5.1.4 and §0.7.1.
//!
//! # Foundational abstraction: [`io`]
//!
//! The entire subsystem is built on the [`IoChain`](io::IoChain) trait,
//! which replaces the hand-rolled 7-method virtual-method table from
//! `io.inc` (AAP §0.4.3, §0.7.1.1) with a `dyn`-object-safe Rust trait
//! whose dispatch goes through the compiler-generated vtable of
//! `Arc<dyn IoChain>`. Every concrete protocol layer (TCP socket, TLS
//! handshake, SSH transport, HTTP/1.1 framing) implements [`IoChain`];
//! layers are stacked by calling [`io::link`] which wires the strong
//! `Arc<child>` link and the weak `Weak<parent>` back-link. The
//! directional-dispatch contract (`destroy`/`clone_chain`/`send` walk
//! forward toward the kernel; `connected`/`receive`/`error`/`timeout`
//! walk backward toward the application) is documented in the [`io`]
//! module's rustdoc with an ASCII diagram.
//!
//! # Submodules present
//!
//! * [`blacklist`] — IP blacklist with time-based expiry for throttling
//!   misbehaving TLS / SSH peers (port of `blacklist.inc`; AAP §0.5.1.4).
//! * [`child`] — Fork-and-socketpair helpers for master↔worker IPC
//!   channels, typed [`LinkMessage`](child::LinkMessage) records, global
//!   child-PID registry, and `SIGTERM`-on-exit cleanup (port of
//!   `epoll_child.inc`; AAP §0.5.1.4, §0.7.4.2).
//! * [`io`] — [`IoChain`](io::IoChain) trait, [`IoLinks`](io::IoLinks)
//!   parent/child state, [`IoBase`](io::IoBase) no-op layer, the
//!   [`link`](io::link) helper, and the six `default_*` behavioural
//!   helpers (port of `io.inc`; AAP §0.5.1.4).
//! * [`url`] — RFC 3986 URL parser/encoder/decoder with the FASM-style
//!   10-field accessor surface used by `webclient` and `webserver`
//!   (port of `url.inc`; AAP §0.5.1.7). Wraps the `url` crate.
//!
//! Additional networking submodules (`runtime`, `dns`, `http`, `fcgi`,
//! `tls`, `ssh`) are scheduled in subsequent translation checkpoints
//! per AAP §0.5.1.4 and are not yet declared here. Declaring a
//! `pub mod foo;` without a backing source file is a hard compile
//! error (rustc E0583), so premature declarations would break the
//! whole workspace build under the Gate 2 `RUSTFLAGS="-D warnings"`
//! discipline (AAP §0.8.3).
//!
//! # Error handling
//!
//! All fallible networking APIs surface the crate-wide
//! [`NetError`](crate::error::NetError) enum (see [`crate::error`]).
//! [`IoChain::send`](io::IoChain::send) returns
//! `BoxFuture<Result<(), NetError>>` and
//! [`IoChain::error`](io::IoChain::error) takes `NetError` as its
//! argument, so the backward-propagating error path delivers a fully
//! typed error to every upstream layer (AAP §0.7.1.1).
//!
//! # `unsafe` audit
//!
//! The [`io`], [`blacklist`], and [`url`] submodules contribute **zero**
//! `unsafe` blocks to the crate's
//! [`UNSAFE_AUDIT.md`](../../../../UNSAFE_AUDIT.md) tally
//! (AAP §0.7.4.1). Correctness derives entirely from `Arc`, `Weak`,
//! `Mutex`, the standard collections, and safe-Rust wrappers around
//! the `url` crate.
//!
//! The [`child`] submodule contributes **three** `unsafe` sites to the
//! crate tally, all FFI-nix / raw-fd boundaries per AAP §0.7.4.2:
//! `nix::unistd::fork` in [`spawn_child`](child::spawn_child) plus two
//! `std::os::unix::net::UnixStream::from_raw_fd` calls that take
//! ownership of the two halves of the `socketpair(2)` return value.
//! Each site has a matching `// SAFETY:` rationale comment, an entry
//! in [`UNSAFE_AUDIT.md`](../../../../UNSAFE_AUDIT.md), and a
//! corresponding integration test in `tests/ffi_boundary.rs`.

/// IP blacklist with time-based expiry — port of `blacklist.inc`.
pub mod blacklist;

/// Fork-and-socketpair helpers for master↔worker IPC channels — port of
/// `epoll_child.inc`.
pub mod child;

/// IO chain trait, parent/child link state, no-op base layer, and the
/// six directional-dispatch default helpers — port of `io.inc`.
pub mod io;

/// RFC 3986 URL parser/encoder/decoder with FASM-style accessors —
/// port of `url.inc`.
pub mod url;

/// Re-export of the most commonly used items from the [`child`] module so
/// that callers (notably `crates/webserver/src/master.rs`) can write
/// `use heavything::net::{ChildProcess, LinkMessage};` without an extra
/// module hop. Matches the export surface declared in AAP §0.3.1.2 for
/// `crates/heavything/src/net/child.rs`.
pub use self::child::{ChildProcess, LinkMessage};
