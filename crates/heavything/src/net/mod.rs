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
//! * [`dns`] — Async DNS resolution via the system resolver
//!   ([`tokio::net::lookup_host`]), plus a Tier 2 manual UDP-based
//!   resolver that reads `/etc/resolv.conf`, scrambles query IDs,
//!   and supports roundrobin server selection (port of
//!   `epoll_dns.inc`; AAP §0.5.1.4).
//! * [`http`] — HTTP/1.1 and HTTP/2 header containers, HPACK codec,
//!   and line-oriented wire-format parser/serializer (port of
//!   `httpheaders.inc`, with `http1.inc`, `mimelike.inc`,
//!   `webserver.inc`, `webclient.inc`, `fcgiclient.inc`, `cookiejar.inc`
//!   scheduled as sibling files within the same `http` submodule;
//!   AAP §0.5.1.4).
//! * [`io`] — [`IoChain`](io::IoChain) trait, [`IoLinks`](io::IoLinks)
//!   parent/child state, [`IoBase`](io::IoBase) no-op layer, the
//!   [`link`](io::link) helper, and the six `default_*` behavioural
//!   helpers (port of `io.inc`; AAP §0.5.1.4).
//! * [`url`] — RFC 3986 URL parser/encoder/decoder with the FASM-style
//!   10-field accessor surface used by `webclient` and `webserver`
//!   (port of `url.inc`; AAP §0.5.1.7). Wraps the `url` crate.
//!
//! * [`runtime`] — Async runtime construction, Stage 10
//!   `RLIMIT_NOFILE` check, socket-default helpers, periodic-timer
//!   spawn helpers, generic accept loop, and cooperative
//!   graceful-shutdown primitive (port of `epoll.inc`; AAP §0.5.1.4,
//!   §0.7.1). Replaces the 3,512-line hand-rolled epoll event loop
//!   with a thin orchestrator over `tokio::runtime::Runtime` whose
//!   internal `mio` backend already provides `epoll` on Linux.
//!
//! Additional networking submodules (`fcgi`, `tls`, `ssh`) are
//! scheduled in subsequent translation checkpoints per AAP §0.5.1.4
//! and are not yet declared here. Declaring a `pub mod foo;` without
//! a backing source file is a hard compile error (rustc E0583), so
//! premature declarations would break the whole workspace build under
//! the Gate 2 `RUSTFLAGS="-D warnings"` discipline (AAP §0.8.3).
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
//! The [`blacklist`], [`http`], [`io`], and [`url`] submodules contribute
//! **zero** `unsafe` blocks to the crate's
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
//!
//! The [`runtime`] submodule contributes **two** `unsafe` sites per
//! AAP §0.7.4.1 expected budget: one in
//! [`runtime::check_ulimit`] grouping `libc::getrlimit` /
//! `libc::setrlimit`, and one in
//! [`runtime::apply_stream_defaults`] grouping two
//! `libc::setsockopt` calls (`SO_LINGER`, `SO_KEEPALIVE`).
//!
//! Each site has a matching `// SAFETY:` rationale comment, an entry
//! in [`UNSAFE_AUDIT.md`](../../../../UNSAFE_AUDIT.md), and a
//! corresponding integration test in `tests/ffi_boundary.rs`.

/// IP blacklist with time-based expiry — port of `blacklist.inc`.
pub mod blacklist;

/// Fork-and-socketpair helpers for master↔worker IPC channels — port of
/// `epoll_child.inc`.
pub mod child;

/// Async DNS resolution — port of `epoll_dns.inc`. Provides Tier 1
/// system-resolver wrappers ([`dns::lookup_host`], [`dns::lookup_ipv4`],
/// [`dns::lookup_host_cached`]) plus the Tier 2 manual UDP-based
/// resolver ([`dns::Dns`]) and the schema-required public façade
/// ([`dns::DnsResolver`]).
pub mod dns;

/// HTTP/1.1 and HTTP/2 aggregator module — contains the header container,
/// HPACK codec, and sibling submodules for MIME-like parsing, HTTP/1.x
/// state machines, and server/client request handling. Ports the
/// `httpheaders.inc` family of FASM files.
pub mod http;

/// IO chain trait, parent/child link state, no-op base layer, and the
/// six directional-dispatch default helpers — port of `io.inc`.
pub mod io;

/// Async runtime and event-loop orchestration — port of `epoll.inc`.
/// Provides [`runtime::build`] / [`runtime::build_current_thread`] /
/// [`runtime::run`] for constructing the tokio runtime that drives
/// the async network stack; [`runtime::check_ulimit`] for the Stage
/// 10 `RLIMIT_NOFILE ≥ EPOLL_MINFDS` init check (AAP §0.7.1.1);
/// [`runtime::apply_stream_defaults`] for the accepted-socket option
/// bundle (`SO_KEEPALIVE` / `SO_LINGER` / `TCP_NODELAY`);
/// [`runtime::accept_loop`] / [`runtime::spawn_periodic`] /
/// [`runtime::spawn_periodic_async`] / [`runtime::install_shutdown_signals`]
/// for the common event-loop building blocks; and the
/// [`runtime::timers`] sub-module exposing the eight canonical
/// integration-point `Duration` constants.
pub mod runtime;

/// RFC 3986 URL parser/encoder/decoder with FASM-style accessors —
/// port of `url.inc`.
pub mod url;

/// Re-export of the most commonly used items from the [`child`] module so
/// that callers (notably `crates/webserver/src/master.rs`) can write
/// `use heavything::net::{ChildProcess, LinkMessage};` without an extra
/// module hop. Matches the export surface declared in AAP §0.3.1.2 for
/// `crates/heavything/src/net/child.rs`.
pub use self::child::{ChildProcess, LinkMessage};

/// Re-export of the public DNS-resolution API surface so callers can
/// write `use heavything::net::{DnsResolver, DnsError};` without an
/// extra module hop. Matches the export surface declared in AAP
/// §0.3.1.2 for `crates/heavything/src/net/dns.rs`.
pub use self::dns::{DnsError, DnsResolver};
