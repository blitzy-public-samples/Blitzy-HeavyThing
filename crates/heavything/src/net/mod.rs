// HeavyThing x86_64 assembly language library — Rust translation.
//
// Rust translation © 2026, licensed under GPL-3.0-or-later.
// Derived from the HeavyThing assembly library:
//   Copyright © 2015–2018 2 Ton Digital, Jeff Marrison <info@2ton.com.au>
//
// This module aggregates the Rust translations of the following FASM
// sources collectively (no single `.inc` file maps 1:1 to this aggregator):
//
//   io.inc            epoll.inc          epoll_child.inc    epoll_dns.inc
//   blacklist.inc     url.inc            fcgiclient.inc     tls.inc
//   ssh.inc           webserver.inc      webclient.inc      httpheaders.inc
//   mimelike.inc      cookiejar.inc      http1.inc
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

//! # Networking Subsystem
//!
//! Top-level aggregator for the `heavything` net subsystem. This subsystem
//! replaces the hand-rolled 131,445-line FASM `epoll.inc` event loop and its
//! associated IO/TLS/SSH/HTTP stack with idiomatic Rust built on:
//!
//! - [`tokio`] runtime (which uses `mio` → `epoll` on Linux)
//! - [`rustls`] for TLS 1.2 and TLS 1.3
//! - [`ring`], [`aes`], [`cbc`] for SSH transport crypto
//! - [`flate2`] for zlib (HTTP gzip, SSH compression)
//! - [`nix`] for `fork(2)`, `setuid(2)`, `setgid(2)`, `prctl(2)`, socketpair
//! - [`memmap2`] for mmap-backed file caches
//!
//! ## Module Layout
//!
//! | Module        | FASM Source                                                                                       | Role                                                            |
//! |---------------|---------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
//! | [`io`]        | `io.inc`                                                                                          | [`IoChain`] trait — the 7-method vtable foundation              |
//! | [`runtime`]   | `epoll.inc`                                                                                       | tokio runtime build + ulimit checks + timer constants           |
//! | [`dns`]       | `epoll_dns.inc`                                                                                   | Async DNS resolver                                              |
//! | [`child`]     | `epoll_child.inc`                                                                                 | Master↔worker IPC via fork+socketpair                           |
//! | [`blacklist`] | `blacklist.inc`                                                                                   | Time-decayed IP blacklist                                       |
//! | [`url`]       | `url.inc`                                                                                         | URL parsing / encode / decode                                   |
//! | [`fcgi`]      | `fcgiclient.inc`                                                                                  | FastCGI client                                                  |
//! | [`tls`]       | `tls.inc`                                                                                         | TLS server/client wrapper over rustls                           |
//! | [`ssh`]       | `ssh.inc`                                                                                         | SSH2 server/transport                                           |
//! | [`http`]      | `webserver.inc`, `webclient.inc`, `httpheaders.inc`, `mimelike.inc`, `cookiejar.inc`, `http1.inc` | HTTP/1.1 server + client                                        |
//!
//! ## Directional Dispatch (from [`io`])
//!
//! Every protocol layer implements [`IoChain`] and is wired into a doubly-
//! linked chain by [`io::link`]. Method invocations split into two
//! directional groups preserved verbatim from the FASM `io.inc` comment:
//!
//! ```text
//! Application   <- receive / connected / error / timeout   (BACKWARD)
//!      │  ▲
//!    parent
//!      │  │
//!    child
//!      ▼  │
//! Kernel / epoll / socket   -> destroy / clone / send      (FORWARD)
//! ```
//!
//! - **FORWARD methods** ([`IoChain::destroy`], [`IoChain::clone_chain`],
//!   [`IoChain::send`]) walk *down* toward the kernel-facing socket.
//! - **BACKWARD methods** ([`IoChain::connected`], [`IoChain::receive`],
//!   [`IoChain::error`], [`IoChain::timeout`]) walk *up* toward the
//!   application layer.
//!
//! ## Cross-Subsystem Integration Contracts
//!
//! - **`tui::widgets::ssh::SshTransport`**: trait defined in `tui/`, MUST be
//!   implemented by a handle exported from [`ssh`] so TUI widgets can drive
//!   the SSH channel (AAP §0.4.4).
//! - **`crate::crypto::rng::reseed()`**: MUST be called in every child worker
//!   post-fork (see [`child::ChildProcess`]) per AAP §0.7.4.2.
//! - **[`crate::error::NetError`]**: all subsystem errors convert via
//!   `#[from]` to this top-level type. The four protocol-specific sub-errors
//!   ([`HttpError`], [`SshError`], [`TlsError`], plus DNS / IO variants on
//!   `NetError` itself) are re-exported below for ergonomic consumer code.
//!
//! ## Re-exports
//!
//! These types are the stable public surface of the `net` subsystem.
//! External consumers should prefer these re-exports over the fully-qualified
//! `net::<submodule>::<Type>` paths. Only the most commonly-consumed surface
//! is flattened — sub-namespaces with rich type ecosystems (notably
//! [`http`] and [`ssh`]) intentionally remain accessible only via their
//! sub-module paths so the top-level [`net`](self) namespace stays clean.
//!
//! ## Feature Gate
//!
//! The entire `net` module is gated on `feature = "net"` in `lib.rs`
//! (AAP §0.4.1.3). It implicitly depends on the `crypto`, `ds`, and `util`
//! features being enabled (they are in the default feature set per AAP
//! §0.6.1, and `net` declares an explicit `crypto` dependency in
//! `Cargo.toml`).
//!
//! ## `unsafe` Audit Summary
//!
//! See `UNSAFE_AUDIT.md` for the per-site inventory. Aggregator counts:
//!
//! | Submodule    | `unsafe` sites | Category                                    |
//! |--------------|---------------:|---------------------------------------------|
//! | [`blacklist`]|              0 | (pure safe Rust)                            |
//! | [`child`]    |              3 | `nix::fork` + 2× `UnixStream::from_raw_fd`  |
//! | [`dns`]      |              0 | (`tokio::net::UdpSocket` only)              |
//! | [`fcgi`]     |              0 | (pure safe Rust over `tokio::net`)          |
//! | [`http`]     |              0 | (pure safe Rust)                            |
//! | [`io`]       |              0 | (pure safe Rust)                            |
//! | [`runtime`]  |              2 | `libc::getrlimit`/`setrlimit` + `setsockopt`|
//! | [`ssh`]      |              0 | (pure safe Rust over `aes`/`cbc`/`ring`)    |
//! | [`tls`]      |              0 | (pure safe Rust over `rustls`)              |
//! | [`url`]      |              0 | (pure safe Rust over `::url` crate)         |
//!
//! Total: 5 `unsafe` sites for the `net` subsystem — well within the
//! crate-wide budget of 50 (AAP §0.7.4.1). Each site has a matching
//! `// SAFETY:` rationale comment, an `UNSAFE_AUDIT.md` entry, and a
//! corresponding integration test in `tests/ffi_boundary.rs`
//! (AAP §0.7.4.4).

// -- Submodule declarations (alphabetical) ---------------------------------
//
// Alphabetical ordering matches `rustfmt`'s default `reorder_modules = true`
// behaviour and ensures deterministic code review across PRs. Per the
// agent_prompt for this file, the per-module FASM-source mapping is
// documented in the module-level rustdoc table above (and NOT inline as
// `// blacklist.inc` comments) so the declaration list stays clean and
// machine-readable.

pub mod blacklist;
pub mod child;
pub mod dns;
pub mod fcgi;
pub mod http;
pub mod io;
pub mod runtime;
pub mod ssh;
pub mod tls;
pub mod url;

// -- Public re-exports -----------------------------------------------------
//
// These re-exports form the stable public surface of `net`. Adding to or
// removing from this list is a breaking change for downstream consumers
// (the three binary crates `sshtalk`, `hnwatch`, `webserver`, plus other
// `heavything` subsystems such as `tui::widgets::ssh`).
//
// The `tests::re_exports_resolve` unit test below is a compile-time check
// that every name in this list continues to resolve at the expected path —
// it will fail to compile if any sibling module silently drops a re-exported
// type, catching accidental API removal during refactors.

// Core IO chain abstraction (from `net::io`).
pub use self::io::{link, BoxFuture, IoBase, IoChain, IoLinks};

// IP blacklist (from `net::blacklist`).
pub use self::blacklist::Blacklist;

// URL parsing (from `net::url`).
pub use self::url::{Url, UrlError};

// DNS resolver (from `net::dns`).
pub use self::dns::{DnsError, DnsResolver};

// Master↔worker IPC (from `net::child`).
pub use self::child::{ChildProcess, LinkMessage};

// Tokio runtime + ulimit + cooperative shutdown (from `net::runtime`).
//
// `runtime::build` is renamed to `build_runtime` at the `net::` level so
// the call site reads as `net::build_runtime()` self-documentingly in
// binary crates' `main.rs` files. The fully-qualified `net::runtime::build`
// path remains available for callers who prefer it.
pub use self::runtime::{build as build_runtime, check_ulimit, Shutdown};

// Crate-wide protocol error types (from `crate::error`).
//
// Re-exporting here lets consumers write `use heavything::net::NetError;`
// rather than remembering that the error lives at
// `heavything::error::NetError`. This matches the FASM pattern where every
// protocol-specific error was accessible via its subsystem include.
//
// The `net::ssh::SshError` re-export inside `ssh/mod.rs` is the same
// `crate::error::SshError` type; both paths resolve to the canonical
// definition in `crate::error` so there is no type-identity divergence.
pub use crate::error::{HttpError, NetError, SshError, TlsError};

#[cfg(test)]
mod tests {
    //! Aggregator-level tests verify that re-exports resolve at the expected
    //! path. Functional tests live in the sibling modules.
    //!
    //! The single test below uses [`std::any::TypeId::of`] to construct a
    //! compile-time reference to every re-exported type. The references
    //! live inside an unreachable closure (`let _: fn() -> ()`) so no
    //! runtime work is performed; the assertion is purely the fact that the
    //! function compiles. If any sibling module drops or renames a
    //! re-exported type, this file will fail to build, surfacing the
    //! breakage at compile time rather than at distant call sites.

    #[test]
    fn re_exports_resolve() {
        // The closure is never invoked — its existence is the assertion.
        // Each `TypeId::of::<…>()` call requires the referenced path to
        // resolve to a `'static` type, which exercises the `pub use`
        // declarations above as a compile-time check.
        let _verify_paths_compile: fn() -> () = || {
            let _ = std::any::TypeId::of::<super::Blacklist>();
            let _ = std::any::TypeId::of::<super::IoBase>();
            let _ = std::any::TypeId::of::<super::IoLinks>();
            let _ = std::any::TypeId::of::<super::Url>();
            let _ = std::any::TypeId::of::<super::UrlError>();
            let _ = std::any::TypeId::of::<super::DnsError>();
            let _ = std::any::TypeId::of::<super::NetError>();
            let _ = std::any::TypeId::of::<super::TlsError>();
            let _ = std::any::TypeId::of::<super::SshError>();
            let _ = std::any::TypeId::of::<super::HttpError>();
            let _ = std::any::TypeId::of::<super::Shutdown>();
            let _ = std::any::TypeId::of::<super::LinkMessage>();
            let _ = std::any::TypeId::of::<super::ChildProcess>();
        };

        // Verify the function-typed re-exports also resolve. `link` is a
        // free function; `build_runtime` is the `runtime::build` alias.
        // These use type-coercion to function pointers rather than
        // `TypeId::of` because function items are zero-sized types whose
        // identity is checked via their function-pointer signature.
        let _link_fn: fn(&std::sync::Arc<dyn super::IoChain>, std::sync::Arc<dyn super::IoChain>) =
            super::link;
        let _build_fn: fn() -> std::io::Result<tokio::runtime::Runtime> = super::build_runtime;
        let _ulimit_fn: fn() -> Result<(), crate::error::InitError> = super::check_ulimit;
    }

    /// Smoke test: construct a [`Blacklist`] via the re-exported path. The
    /// actual blacklist semantics are covered by
    /// `crate::net::blacklist::tests::*`; this test only confirms that
    /// `net::Blacklist::new(...)` resolves and produces the expected
    /// `Arc<Blacklist>` without requiring callers to import
    /// `net::blacklist::Blacklist` from the sub-module path.
    ///
    /// `Blacklist::new` takes a per-call default `expiry: Duration` (see
    /// `net::blacklist`); the value chosen here is irrelevant to the
    /// re-export check.
    #[test]
    fn blacklist_re_export_constructible() {
        use std::sync::Arc;
        use std::time::Duration;
        let _bl: Arc<super::Blacklist> = super::Blacklist::new(Duration::from_secs(86_400));
    }

    /// Smoke test: construct an [`IoBase`] via the re-exported path. This
    /// verifies that the foundational [`IoChain`] vtable type is reachable
    /// from `net::IoBase` without going through `net::io::IoBase`.
    ///
    /// `IoBase::new` returns `Arc<Self>` rather than `Self` because every
    /// `IoChain` method takes `self: Arc<Self>` (see `net::io::IoChain`).
    #[test]
    fn io_base_re_export_constructible() {
        use std::sync::Arc;
        let _base: Arc<super::IoBase> = super::IoBase::new();
    }

    /// Smoke test: construct a [`Shutdown`] coordinator via the re-exported
    /// path. The cooperative-cancellation primitive is one of the most
    /// commonly consumed types from `net::` in binary crates' `main.rs`,
    /// so its re-export resolution is verified explicitly.
    #[test]
    fn shutdown_re_export_constructible() {
        let _sd: super::Shutdown = super::Shutdown::new();
    }
}
