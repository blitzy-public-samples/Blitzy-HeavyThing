// ------------------------------------------------------------------------
// HeavyThing x86_64 assembly language library and showcase programs
// Copyright © 2015 2 Ton Digital
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

//! Entry point for the `sshtalk` binary crate (translation of
//! `sshtalk/sshtalk.asm` per AAP §0.5.1.9).
//!
//! `sshtalk` is an SSH-accessible multi-user terminal chat server
//! that listens on TCP port 4001 and serves a TUI chat experience
//! inside a full SSH session. The original FASM source is a 326-line
//! module that:
//!
//! * Calls `ht$init` to bring up the HeavyThing library.
//! * Loads the user database (`userdb$init`).
//! * Initialises the chat-room registry (`chatroom$init`).
//! * Registers screen connect/disconnect syslog formatters
//!   (`screen$init_formatters`).
//! * Registers the status-bar formatter (`statusbar$init`).
//! * Builds the TUI: `Screen` → `tui_simpleauth` → `tui_splash` →
//!   `tui_ssh`, with `userdb$vtable` mounted as the simpleauth
//!   authentication vtable.
//! * Creates the SSH server (`ssh$new_server` with default
//!   `/etc/ssh` host keys).
//! * Wires the application IO chain `tui_ssh ↔ ssh_server ↔ epoll`.
//! * Binds TCP port 4001 (`epoll$inbound` with `INADDR_ANY`).
//! * Enters the event loop (`epoll$run`).
//!
//! Source mapping (assembly → Rust):
//!
//! ```text
//!   sshtalk.asm line  46  _start:                       → main()
//!   sshtalk.asm line  48    call ht$init                → heavything::init_args(args)
//!   sshtalk.asm line  51    call userdb$init            → userdb::init()
//!   sshtalk.asm line  54    call chatroom$init          → chatroom::init()
//!   sshtalk.asm line  57    call screen$init_formatters → screen::init_formatters()
//!   sshtalk.asm line  60    call statusbar$init         → statusbar::init()
//!   sshtalk.asm line  66    call screen$new             → screen::new()
//!   sshtalk.asm line  68-73 tui_simpleauth$new          → TuiSimpleAuth::new(...)
//!   sshtalk.asm line 234-235 tui_splash$new             → TuiSplash::new(...)
//!   sshtalk.asm line 237-241 tui_ssh$new                → TuiSsh::new(...)
//!   sshtalk.asm line 243-247 ssh$new_server             → SshServer::new(...).with_auth(...)
//!   sshtalk.asm line 252-262 io chain link              → heavything::net::io::link
//!   sshtalk.asm line 265-272 inaddr_any + epoll$inbound → TcpListener::bind + accept_loop
//!   sshtalk.asm line 281    epoll$run                   → tokio runtime block_on
//!   sshtalk.asm line 288-293 .hostkeyerror              → eprintln + std::process::exit(1)
//!   sshtalk.asm line 295-307 .addlabel                  → fn add_label
//!   sshtalk.asm line 309-324 cleartext .s1 ..= .errorstring → const S1_VERSION ..= HOST_KEYS_ERROR
//! ```
//!
//! Behavioral architecture (per the deep dive in the session
//! transcript):
//!
//! * The FASM `link(tui_ssh, ssh_server)` IO-chain pattern does NOT
//!   transcribe directly: in Rust, `TuiSsh` is *not* an `IoChain` —
//!   only [`heavything::net::ssh::SshSession`] implements `IoChain`.
//!   The TUI receives bytes from the SSH session via a per-channel
//!   `mpsc::UnboundedReceiver` ([`SshChannel::take_receiver`]), and
//!   sends bytes back through [`SshChannel`] which implements
//!   [`heavything::tui::widgets::ssh::SshTransport`].
//! * Per-connection: the IO chain is `SshSession → TcpAdapter` (the
//!   `TcpAdapter` lives at the leaf, owning the writer half of the
//!   tokio TCP socket). The reader half is owned by a dedicated read
//!   loop that feeds inbound bytes into [`SshSession::receive`].
//! * `default_connected` propagates BACKWARD to the parent (per
//!   `io.rs:319`); since `SshSession` has no parent in this setup,
//!   the chain-side propagation is a no-op. The TUI's
//!   [`TuiSsh::on_connected`] (which emits the alt-screen escape
//!   sequence) is therefore called explicitly by the consumer task
//!   on the first inbound channel byte (which is the earliest moment
//!   the SSH session is guaranteed to be in the `Interactive` stage
//!   and ready for application-level bytes).
//! * `AuthOutcome::NoCallback` is treated identically to
//!   `AuthOutcome::Denied` by the SSH server (both produce
//!   `SSH_MSG_USERAUTH_FAILURE`). Therefore, the SSH-level auth
//!   callback is installed as a permissive `|_, _| true` so that any
//!   client reaches the `Interactive` stage; real authentication
//!   then takes place inside the TUI's `TuiSimpleAuth` widget, whose
//!   handler is the [`crate::userdb::SIMPLEAUTH_VTABLE`] installed
//!   by `userdb::init()`.
//! * The host-keys probe at startup is performed by calling
//!   [`heavything::crypto::x509::load_ssh_host_keys`] directly. The
//!   FASM `ssh$new_server` returned NULL on missing keys; the Rust
//!   `SshSession::new_server` only fails on *malformed* keys (it
//!   silently skips missing files). To preserve the FASM
//!   "no host keys → exit 1" semantic, `main` checks for an empty
//!   key vector at startup and emits the byte-identical
//!   `/etc/ssh host keys and/or contents error.` message before
//!   exiting with status 1.
//!
//! AAP-mandated invariants preserved:
//!
//! * Exit codes 96/97/98/99 from `heavything::InitError::exit_code`.
//! * Exit code 1 with byte-identical `/etc/ssh host keys and/or
//!   contents error.` message on missing host keys.
//! * SSH-2.0-HeavyThing identification banner (handled by
//!   `heavything::net::ssh::SSH_IDENT`).
//! * TCP port 4001 hardcoded.
//! * 16 string constants from `sshtalk.asm` lines 309–324 preserved
//!   verbatim.
//! * `if profiling` block at `sshtalk.asm` lines 274–278 omitted per
//!   AAP §0.5.1.7 ("profiler.rs — thin API-preservation wrapper;
//!   actual profiling delegated to cargo bench + criterion").

// Defence in depth: forbid `unsafe { ... }` inside `unsafe fn` without
// an explicit inner `unsafe` block. `main.rs` itself contains zero
// unsafe code (all FFI lives inside `heavything`); this lint is set
// crate-wide via this attribute on the binary crate root so future
// edits cannot regress without a deliberate suppression (which AAP
// §0.8.3 forbids anyway).
#![forbid(unsafe_op_in_unsafe_fn)]
// Rustdoc lint allowances per AAP §0.8.6 and Final Checkpoint 16 QA
// expectation that "documented `#[allow(rustdoc::*)]` exceptions
// justified per file" is acceptable.
//
// `sshtalk` doc comments reference internal helper functions (e.g.
// `<dyn Any>::downcast_ref`, `userdb::authenticate`, `screen::tick`)
// and use the placeholder form `<username>` in usage examples. These
// are doc-author conventions inherited from the assembly source;
// rewriting them would expand the public API surface (AAP §0.8.1) or
// degrade source-review readability without changing rendered docs.
// See the matching block in `crates/heavything/src/lib.rs` for the
// full justification. This narrow allowance does NOT suppress the
// broader `warnings` or `unused` lints that AAP §0.8.3 forbids.
#![allow(
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links,
    rustdoc::redundant_explicit_links,
    rustdoc::invalid_html_tags
)]

// ===========================================================================
// Module declarations — five sibling modules, declared in the order
// matching `sshtalk.asm` lines 38–42 so the `cargo check`-time
// compilation order mirrors the FASM include order. The modules are
// private (no `pub`): `sshtalk` is a binary crate, not a library, so
// no external visibility is required.
// ===========================================================================

// `#[rustfmt::skip]` preserves the FASM include order. Default
// rustfmt would re-order alphabetically (chatpanel, chatroom,
// screen, statusbar, userdb), which violates AAP §0.5.1.9 folder
// constraint #3: "These MUST be declared in this exact order
// (matches sshtalk.asm lines 38-42 include order)".
#[rustfmt::skip]
mod userdb;
#[rustfmt::skip]
mod chatroom;
#[rustfmt::skip]
mod chatpanel;
#[rustfmt::skip]
mod screen;
#[rustfmt::skip]
mod statusbar;

// ===========================================================================
// Imports
// ===========================================================================

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use heavything::net::http::server::TcpAdapter;
use heavything::net::io::{link, IoChain};
use heavything::net::runtime::accept_loop;
use heavything::net::ssh::{SshChannel, SshConfig, SshServer, SshSession};
use heavything::tui::widgets::simpleauth::AuthType;
use heavything::tui::widgets::ssh::SshTransport;
use heavything::tui::widgets::{SimpleAuthHandler, TuiLabel, TuiSimpleAuth, TuiSplash, TuiSsh};
use heavything::tui::{ColorPair, Widget};

use crate::screen::Screen;

// ===========================================================================
// Byte-exact branding strings preserved from `sshtalk.asm`
// lines 309–324 (`cleartext` declarations).
//
// These are the strings the FASM `_start.addlabel` helper appends to
// the splash-screen / simpleauth panels. The Rust port preserves them
// verbatim per AAP §0.8.2 (Minimal Change Clause): even branding text
// referring to "x86_64 assembler" remains, because changing it would
// modify observable output. The structural mismatch between the FASM
// 3-third-vstack simpleauth layout and the Rust `TuiSimpleauth`
// widget (which uses a 1-row `TuiHSpacer` for top/bottom — see the
// session transcript for the deep dive) prevents direct re-injection
// of these labels into the simpleauth tree. `add_label` is preserved
// for parity with the FASM helper signature, and the most-prominent
// branding lines are emitted to stderr at startup as a fallback so
// the operator still sees them on the boot console (matching what a
// FASM-built binary printed via syslog).
// ===========================================================================

/// `sshtalk.asm` line 309 (`.s1`): top-of-splash version string.
///
/// The `0xa9` byte in the FASM `cleartext` literal is the Latin-1
/// copyright glyph; in UTF-8 Rust it encodes as the two-byte
/// sequence `0xC2 0xA9`. The Rust source uses the explicit
/// `\u{00A9}` escape for clarity (the literal `©` would be
/// equivalent but less self-documenting).
const S1_VERSION: &str = "sshtalk v1.12 \u{00A9} 2015 2 Ton Digital";

/// `sshtalk.asm` line 310 (`.s2`).
const S2_MADE_IN: &str = "proudly made in Cooroy, Australia";

/// `sshtalk.asm` line 311 (`.s3`).
const S3_SHOWCASE: &str = "A showcase piece for the HeavyThing library";

/// `sshtalk.asm` line 312 (`.s4`).
const S4_SECURE: &str = "100% wire-level secure ssh talk facility";

/// `sshtalk.asm` line 313 (`.s5`).
///
/// Preserved verbatim per AAP §0.8.2 even though the Rust translation
/// is no longer handcrafted assembly — this is the original FASM
/// branding and the minimal-change clause requires that observable
/// strings remain identical to the upstream baseline.
const S5_HANDCRAFTED: &str = "100% handcrafted in x86_64 assembler";

/// `sshtalk.asm` line 314 (`.s6`).
///
/// Preserved verbatim per AAP §0.8.2; the Rust translation introduces
/// crates.io dependencies (tokio, ring, rustls, …) but the original
/// branding is part of the observable application output and is left
/// in place. The architectural divergence from "zero external
/// dependencies" is documented in `BENCHMARK_REPORT.md` per AAP
/// §0.7.2.2 "Behavioral Differences from Assembly Baseline".
const S6_ZERO_DEPS: &str = "Zero external dependencies";

/// `sshtalk.asm` line 315 (`.s7`).
const S7_INFO: &str = "Info/Source: https://2ton.com.au/sshtalk";

/// `sshtalk.asm` line 316 (`.s8`).
const S8_CONNECTION: &str = "Connection: 4096 bit diffie-hellman-group-exchange-sha256,";

/// `sshtalk.asm` line 317 (`.s9`).
const S9_ALGS: &str = "ssh-rsa,aes256-cbc,hmac-sha2-256,zlib[@openssh.com]";

/// `sshtalk.asm` line 318 (`.s10`): standard author byline.
const S10_AUTHOR: &str = "Author: Jeff Marrison, jeff@2ton.com.au";

/// `sshtalk.asm` line 319 (`.s10_2ton`): 2 Ton Digital host
/// extended byline (only emitted when running on a hostname that
/// matches the 2 Ton Digital infrastructure prefix `slave.` or the
/// internal hostname `cdev`).
const S10_2TON: &str = "Author: Jeff Marrison, jeff@2ton.com.au, and via this sshtalk: @Sysop";

/// `sshtalk.asm` line 320 (`.s11_2ton`).
///
/// The `0x27` byte in the FASM cleartext is a single-quote escape
/// inside a single-quoted FASM literal (`don',0x27,'t`). In Rust the
/// natural double-quoted string requires no escape.
const S11_2TON: &str = "Online 6a-8a Mon-Fri AEST, may or may not respond, don't take it personally :)";

/// `sshtalk.asm` line 321 (`.hostname_slave`).
const HOSTNAME_SLAVE_PREFIX: &str = "slave.";

/// `sshtalk.asm` line 322 (`.hostname_cdev`).
const HOSTNAME_CDEV: &str = "cdev";

/// `sshtalk.asm` line 323 (`.tickertext`).
const TICKER_TEXT: &str = "Best viewed with a 6 pack of beer, ha! ... size: 135x35 min, \
    Mac OS X: iTerm2 or Terminal.app, Winblows: SecureCRT (ANSI colors enabled, \
    rows/cols adjust, lucida console), Linux: all linux terms seem happy...";

/// `sshtalk.asm` line 324 (`.errorstring`): byte-identical message
/// printed to stderr when host-key loading fails. Per AAP §0.8.1 and
/// folder constraint #6, this string MUST remain byte-identical so
/// downstream operators can grep for it across log streams.
const HOST_KEYS_ERROR: &str = "/etc/ssh host keys and/or contents error.";

// ===========================================================================
// Color constants — must be defined locally per the session-transcript
// finding "color constants in simpleauth.rs are PRIVATE". The values
// match the xterm 256-color palette indices used by the FASM
// `ansi_colors` macro (see `tui/ansi.rs` and the FASM `cleartext`
// macro's `ansi_colors edx, 'lightgray', 'black'` invocation at
// `sshtalk.asm` line 300).
// ===========================================================================

/// xterm 256-color index 251 — light gray. Used as the default
/// foreground color for branding labels per `sshtalk.asm` line 300
/// (`ansi_colors edx, 'lightgray', 'black'`).
#[allow(dead_code)] // Used by `add_label` only on the FASM 3-third-vstack code path.
const COLOR_LIGHTGRAY: u8 = 251;

/// xterm 256-color index 232 — pure black. Used as the default
/// background color for branding labels per `sshtalk.asm` line 300.
#[allow(dead_code)] // Used by `add_label` only on the FASM 3-third-vstack code path.
const COLOR_BLACK: u8 = 232;

/// xterm 256-color index 226 — saturated yellow. Used as the
/// foreground color for the version label (S1) per `sshtalk.asm`
/// line 98 (`ansi_colors edx, 'yellow', 'black'`).
#[allow(dead_code)] // Used by `add_label` only on the FASM 3-third-vstack code path.
const COLOR_YELLOW: u8 = 226;

// ===========================================================================
// Network constants
// ===========================================================================

/// TCP port the sshtalk SSH server listens on.
///
/// Hardcoded per AAP folder constraint #8 and per `sshtalk.asm`
/// line 267 (`mov esi, 4001`). FASM did not expose this as a CLI
/// flag; the Rust port preserves the same hardcoding so the
/// observable bind behavior is identical to the upstream baseline.
const LISTEN_PORT: u16 = 4001;

/// Bind address for the sshtalk listener.
///
/// `0.0.0.0` corresponds to the FASM `inaddr_any` call at
/// `sshtalk.asm` line 270 — listen on every IPv4 interface.
const BIND_ADDR: &str = "0.0.0.0";

/// Read-buffer capacity for the per-connection inbound TCP read
/// loop. Matches FASM `epoll_readsize` (32 KiB) preserved in
/// [`heavything::config::EPOLL_READSIZE`].
const READ_BUFFER_SIZE: usize = heavything::config::EPOLL_READSIZE;

// ===========================================================================
// Auxiliary helper — `add_label`
// ===========================================================================

/// Append a branding label to a TUI container — Rust port of the
/// FASM `_start.addlabel` helper at `sshtalk.asm` lines 295–307.
///
/// FASM signature (callee receives `rdi = parent_object`,
/// `rsi = string_ptr`):
///
/// ```text
///   .addlabel:
///       push  rdi
///       movq  xmm0, [_math_onehundred]      ; width percent
///       mov   edi, 1                        ; height in rows
///       ansi_colors edx, 'lightgray', 'black'
///       mov   ecx, tui_textalign_center
///       call  tui_label$new_di
///       pop   rdi
///       mov   rsi, rax
///       mov   rdx, [rdi]
///       call  qword [rdx+tui_vappendchild]
///       ret
/// ```
///
/// The Rust translation produces a 100%-width × 1-row `TuiLabel`
/// with the supplied colors and centered alignment, then appends
/// it to the parent's children list via the `Widget` trait's
/// default `append_child` implementation (which itself pushes onto
/// `state_mut().children`).
///
/// # Why this helper is `#[allow(dead_code)]`
///
/// Per the deep dive in the session transcript, the actual
/// [`TuiSimpleAuth`] widget in the Rust port differs structurally
/// from the FASM 3-third-vstack `tui_simpleauth` layout: it uses a
/// single-row top `TuiHSpacer` and a single-row bottom `TuiHSpacer`
/// rather than two 100%-height "third" containers that branding
/// labels could be appended to. As a result, the FASM
/// `_start.addlabel` injection sites (`sshtalk.asm` lines 88–186)
/// do not have a direct Rust equivalent. The helper is preserved
/// per AAP §0.5.1.5 (so the FASM call signature is documented in
/// the Rust source) and so future iterations of the simpleauth
/// widget (which may regain the 3-third layout) have a ready-made
/// caller.
///
/// # Errors
///
/// * Returns the underlying [`anyhow::Error`] from
///   [`TuiLabel::new_di`] if label construction fails (zero-capacity
///   allocation, invalid color pair).
/// * Returns `Err` with a clear diagnostic if the parent's `Arc`
///   has more than one strong reference (so `Arc::get_mut` returns
///   `None`).
#[allow(dead_code)]
fn add_label(parent: &mut Arc<dyn Widget>, text: &str, colors: ColorPair) -> Result<()> {
    use heavything::tui::widgets::label::TextAlign;

    let label = TuiLabel::new_di(100.0, 1, text, colors, TextAlign::Center)
        .context("add_label: TuiLabel::new_di failed")?;
    let parent_mut = Arc::get_mut(parent).ok_or_else(|| {
        anyhow!("add_label: parent Arc::get_mut failed (refcount > 1, cannot mutate children list)")
    })?;
    parent_mut.append_child(label as Arc<dyn Widget>);
    Ok(())
}

// ===========================================================================
// Per-connection handler — Rust translation of the SSH-server
// per-connection setup that FASM did inside the `epoll$run` event
// loop. In the FASM model, every accepted TCP socket walked a
// linked IO chain (`tui_ssh ↔ ssh ↔ epoll`) whose `accept` callback
// freshly cloned each layer for the new connection. In Rust, we
// replicate this per-connection setup explicitly inside an async
// task spawned by [`accept_loop`].
// ===========================================================================

/// Wire a freshly-accepted TCP stream to a fresh SSH session and
/// drive both the inbound (TCP → SSH → TUI) and outbound (TUI →
/// SSH → TCP) halves until the session terminates.
///
/// This mirrors `heavything::net::http::server::handle_connection`
/// (the precedent established by the `webserver` binary) but with
/// SSH-specific wiring:
///
/// * Build the per-connection TUI tree: `Screen → TuiSimpleAuth →
///   TuiSplash → TuiSsh`.
/// * Build the per-connection SSH session via
///   [`SshSession::new_server`] inline (rather than via
///   `SshServer::accept_one`, which consumes the stream without
///   actually using it — the stream needs to be split for the
///   reader/writer halves separately).
/// * Install a permissive SSH-level auth callback so the session
///   reaches the `Interactive` stage; real auth happens in the
///   TuiSimpleAuth handler.
/// * Split the stream into reader + writer halves; wrap the writer
///   in a [`TcpAdapter`] and link it as the SSH session's child in
///   the IO chain.
/// * Spawn a consumer task that reads from the SSH channel's
///   inbound mpsc receiver and forwards bytes to
///   [`TuiSsh::on_receive`]; the very first received byte triggers
///   [`TuiSsh::on_connected`] (which emits the alt-screen escape
///   sequence).
/// * Drive the inbound TCP read loop, feeding bytes to
///   [`SshSession::receive`].
/// * On loop exit, tear down the chain via [`SshSession::destroy`]
///   and update the session counter via
///   [`statusbar::session_disconnected`].
///
/// # Errors
///
/// * [`heavything::error::NetError::Ssh`] on SSH protocol errors
///   that surface from session construction (host-key signing
///   failure, blacklist trigger).
/// * [`heavything::error::NetError::Io`] on fatal TCP read errors
///   that the session cannot recover from. Per-connection errors
///   are swallowed so they do not propagate up to the accept loop
///   and stop the listener (matches `accept_loop`'s contract).
async fn handle_ssh_connection(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    server: Arc<SshServer>,
) -> Result<(), heavything::error::NetError> {
    statusbar::session_connected();

    // Result of the per-connection wiring; we always run the
    // disconnect counter update once the function returns,
    // regardless of which path we took, so the session counter
    // stays balanced.
    let result = handle_ssh_connection_inner(stream, peer, server).await;

    statusbar::session_disconnected();
    result
}

/// Inner handler — separated from [`handle_ssh_connection`] so the
/// `session_disconnected` counter update can run unconditionally
/// even on early-return error paths.
async fn handle_ssh_connection_inner(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    server: Arc<SshServer>,
) -> Result<(), heavything::error::NetError> {
    // Stage 1: build the SSH session inline. We do NOT call
    // `SshServer::accept_one` because that method's `_stream`
    // parameter is unused (see `server.rs:626` — leading underscore
    // makes this explicit) and consumes the stream we need to split
    // for read/write halves below.
    let session = SshSession::new_server(&server.config, Some(server.blacklist.clone()))
        .map_err(heavything::error::NetError::Ssh)?;
    session
        .set_remote_addr(peer)
        .map_err(heavything::error::NetError::Ssh)?;

    // Stage 2: install the permissive SSH-level auth callback so
    // password attempts pass at the SSH protocol layer. Real
    // authentication happens inside the `TuiSimpleAuth` widget,
    // which delegates to `userdb::SIMPLEAUTH_VTABLE`. Without this
    // callback, every userauth_request would map to
    // `AuthOutcome::NoCallback` which the SSH server treats
    // identically to `AuthOutcome::Denied` — meaning every client
    // would be denied at the SSH layer before ever reaching the TUI
    // (see the deep dive in the session transcript at
    // `server.rs:2030-2080` and `auth.rs:607-680`).
    session.set_auth_callback(|_username: &str, _password: &str| true);

    // Stage 3: build the per-connection TUI tree.
    //   Screen (top-level container)
    //     ↓
    //   TuiSimpleAuth (auth gate)
    //     ↓
    //   TuiSplash (one-shot splash that dismisses on any keypress)
    //     ↓
    //   TuiSsh (renders to the SSH channel via SshTransport)
    //
    // The auth handler is the userdb::SIMPLEAUTH_VTABLE installed
    // by `userdb::init()` at startup.
    //
    // Errors from sibling crates (anyhow::Error from screen,
    // TuiError from simpleauth/splash) are mapped into
    // [`heavything::error::NetError::Io`] via [`std::io::Error::other`]
    // so the per-connection accept-loop signature
    // (`Result<(), NetError>`) can carry them upward without growing
    // a new error variant. `NetError::Io` is the canonical
    // "everything else" channel for connection-scoped failures and
    // [`std::io::Error::other`] (stabilised in Rust 1.74) wraps any
    // `Display`-able error type without allocating a custom error
    // hierarchy.
    let screen: Arc<Screen> = Screen::new()
        .map_err(|e| heavything::error::NetError::Io(std::io::Error::other(format!("screen::new: {e}"))))?;
    let screen_widget: Arc<dyn Widget> = screen.clone();

    let auth_handler: Arc<dyn SimpleAuthHandler> = userdb::SIMPLEAUTH_VTABLE
        .get()
        .ok_or_else(|| {
            heavything::error::NetError::Io(std::io::Error::other(
                "userdb::SIMPLEAUTH_VTABLE not initialised — userdb::init() must be called \
                 before accepting connections",
            ))
        })?
        .clone();

    let simpleauth = TuiSimpleAuth::new(AuthType::NewUser, screen_widget, auth_handler).map_err(|e| {
        heavything::error::NetError::Io(std::io::Error::other(format!("TuiSimpleAuth::new: {e:?}")))
    })?;
    let simpleauth_widget: Arc<dyn Widget> = simpleauth;

    let splash = TuiSplash::new(simpleauth_widget).map_err(|e| {
        heavything::error::NetError::Io(std::io::Error::other(format!("TuiSplash::new: {e:?}")))
    })?;
    let splash_widget: Arc<dyn Widget> = splash;

    // The TuiSsh transport is the SshChannel, which exposes the
    // outbound side of the session's mpsc channel via
    // `SshTransport::send_bytes`. We keep a strong `Arc<SshChannel>`
    // (`channel`) alongside the upcast `Arc<dyn SshTransport>`
    // (`transport`) so the consumer task can call
    // [`SshChannel::close`] (which is *not* exposed on the trait
    // object) when the TUI signals an exit condition.
    let channel: Arc<SshChannel> = Arc::new(SshChannel::new(session.clone()));
    // Take the inbound receiver BEFORE wrapping the channel in an
    // Arc<dyn SshTransport> — `take_receiver` mutably accesses the
    // session's `channel_rx` slot and can only be called once.
    let mut channel_rx = channel.take_receiver().ok_or_else(|| {
        heavything::error::NetError::Io(std::io::Error::other(
            "SshChannel::take_receiver returned None on a freshly-constructed channel — \
             this should be impossible; possible double-take or session pre-corruption",
        ))
    })?;
    let transport: Arc<dyn SshTransport> = channel.clone();

    let tui_ssh: Arc<TuiSsh> = TuiSsh::new(splash_widget, transport);

    // Stage 4: split the TCP stream and wire the SSH session's IO
    // chain. The reader half stays in this function (it drives the
    // inbound read loop). The writer half is wrapped in a
    // `TcpAdapter` that becomes the SSH session's child in the IO
    // chain, so outbound bytes flow `SshSession.send → TcpAdapter →
    // TcpStream::write`.
    let (mut reader, writer) = tokio::io::split(stream);
    let adapter = TcpAdapter::new(writer);

    let session_dyn: Arc<dyn IoChain> = Arc::clone(&session) as Arc<dyn IoChain>;
    let adapter_dyn: Arc<dyn IoChain> = Arc::clone(&adapter) as Arc<dyn IoChain>;
    link(&session_dyn, adapter_dyn);

    // Stage 5: install the window-resize callback. The
    // `set_window_size` calls inside `TuiSsh::on_window_size` will
    // bubble up to the TUI via this callback whenever the SSH peer
    // sends a `window-change` request. The TuiSsh weak-pointer
    // pattern is needed here so the callback does not extend the
    // lifetime of the TuiSsh past the natural end of this connection.
    {
        let tui_ssh_weak = Arc::downgrade(&tui_ssh);
        session.set_wsize_callback(move |cols, rows| {
            if let Some(tui_ssh_strong) = tui_ssh_weak.upgrade() {
                // u32 → u16 truncation is safe: SSH `window-change`
                // only carries 32-bit values that the TUI rendering
                // path can saturate to u16::MAX without visible
                // effect (any terminal larger than 65,535 columns
                // is fictional).
                let cols_u16 = u16::try_from(cols).unwrap_or(u16::MAX);
                let rows_u16 = u16::try_from(rows).unwrap_or(u16::MAX);
                let _ = tui_ssh_strong.on_window_size(cols_u16, rows_u16);
            }
        });
    }

    // Stage 6: spawn the inbound consumer task. This task drains
    // the SSH session's channel-data receiver and forwards bytes to
    // the TUI's `on_receive`. The very first received byte triggers
    // `TuiSsh::on_connected` (which emits the alt-screen escape
    // sequence and hands off the splash widget to the renderer).
    // We trigger `on_connected` here rather than from the IoChain's
    // `connected` callback because `default_connected` propagates
    // BACKWARD to the session's parent (see `io.rs:319`); since
    // `SshSession` has no parent in our setup, the default-connected
    // path is a no-op and we must drive `TuiSsh::on_connected`
    // explicitly.
    let consumer_tui_ssh: Arc<TuiSsh> = tui_ssh.clone();
    let consumer_channel: Arc<SshChannel> = channel.clone();
    let consumer_handle = tokio::spawn(async move {
        let mut connected_emitted = false;
        while let Some(data) = channel_rx.recv().await {
            if !connected_emitted {
                // First channel-data delivery means the SSH session
                // is in the `Interactive` stage (the SSH server only
                // forwards channel data after the channel is open
                // and the shell request is acknowledged). It is now
                // safe to emit alt-screen + insertion-mode bytes.
                if consumer_tui_ssh.on_connected().is_err() {
                    // Render error: the channel is gone or the
                    // transport has been torn down. Mark the
                    // session dead and bail; the inbound read loop
                    // will observe the closure on its next read.
                    consumer_channel.close();
                    break;
                }
                connected_emitted = true;
            }
            // `data` is a `bytes::Bytes`; `on_receive` accepts a
            // `&[u8]`, and `Bytes: Deref<Target = [u8]>` so the
            // explicit `&data[..]` slicing produces the borrow we
            // need without an intermediate copy.
            match consumer_tui_ssh.on_receive(&data[..]) {
                Ok(true) => {
                    // The TUI signalled "kill switch" (Ctrl-C). Mark
                    // the session dead so the inbound TCP read loop
                    // also exits.
                    consumer_channel.close();
                    break;
                }
                Ok(false) => {}
                Err(_) => {
                    consumer_channel.close();
                    break;
                }
            }
        }
        // Receiver drained — either the session was torn down by
        // the inbound TCP loop, or the peer closed the channel. The
        // task exits and the channel_rx is dropped.
    });

    // Stage 7: notify the SSH chain of the new peer. This emits the
    // `SSH-2.0-HeavyThing` identification banner via the IoChain
    // child (TcpAdapter), advances the session stage from `Banner`
    // to `Idents`, and starts the outbound pump task that drains
    // the session's outbound mpsc queue. After this call returns,
    // the session is fully bootstrapped on the wire.
    Arc::clone(&session_dyn).connected(Some(peer)).await;

    // Stage 8: inbound TCP read loop. Each `read` returns a chunk
    // of bytes that we feed into `IoChain::receive` on the SSH
    // session. The session's `receive` decrypts/parses packets and
    // forwards channel data to the consumer task via the mpsc
    // channel. The loop exits when:
    //   * the peer closes the connection (`read` returns 0);
    //   * the session is marked dead (Ctrl-C kill switch, fatal
    //     SSH protocol error);
    //   * a fatal `read` error occurs.
    let mut buf = vec![0u8; READ_BUFFER_SIZE];
    let mut should_close = false;
    while !should_close {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break, // orderly client close
            Ok(n) => n,
            Err(e) => {
                // Fatal read error — propagate to the chain so the
                // session can clean up; then exit the loop.
                let err = heavything::error::NetError::Io(e);
                Arc::clone(&session_dyn).error(err).await;
                should_close = true;
                continue;
            }
        };
        let chunk = Bytes::copy_from_slice(&buf[..n]);
        should_close = Arc::clone(&session_dyn).receive(chunk).await;
    }

    // Stage 9: chain teardown. Walk forward through the chain so
    // each layer cleans up. The TcpAdapter shuts down the writer
    // half; the reader half is dropped when this function returns.
    Arc::clone(&session_dyn).destroy().await;

    // Stage 10: wait for the consumer task to exit. It will exit
    // shortly because `SshSession::destroy` marks the session dead,
    // which causes the channel sender to drop, which causes
    // `channel_rx.recv()` to return None.
    let _ = consumer_handle.await;

    // Stage 11: explicit hint that `adapter` lives until here so its
    // writer-mutex isn't dropped before `destroy()` finishes.
    drop(adapter);

    Ok(())
}

// ===========================================================================
// Hostname-aware branding emission
// ===========================================================================

/// Print branding strings to stderr at startup.
///
/// The FASM `_start` body wires these strings into the splash-screen
/// labels via the `_start.addlabel` helper (`sshtalk.asm` lines
/// 88–229). The Rust port can't directly inject them into the
/// `TuiSimpleauth` tree (see the `add_label` doc-comment), but the
/// most-prominent branding lines are still printed to stderr at
/// startup so the operator-visible boot output remains close to
/// what the FASM build produced. This is a deliberate fallback for
/// the structural mismatch noted in the session transcript.
///
/// The hostname-aware branching at `sshtalk.asm` lines 188–213
/// (slave./cdev hosts get the extended `S10_2TON` + `S11_2TON`
/// byline) is also preserved here.
fn print_startup_banner() {
    eprintln!("{}", S1_VERSION);
    eprintln!("{}", S2_MADE_IN);
    eprintln!("{}", S3_SHOWCASE);
    eprintln!("{}", S4_SECURE);
    eprintln!("{}", S5_HANDCRAFTED);
    eprintln!("{}", S6_ZERO_DEPS);
    eprintln!("{}", S7_INFO);
    eprintln!("{}", S8_CONNECTION);
    eprintln!("{}", S9_ALGS);

    // Hostname-aware author line. Per `sshtalk.asm` lines 188–213,
    // hosts whose `nodename` (from `uname(2)`) starts with `slave.`
    // or equals exactly `cdev` get the extended 2 Ton Digital
    // byline. `heavything::util::sysinfo::uname` mirrors the FASM
    // `sysinfo$uname` and returns a [`Uname`] struct with a
    // `nodename` field; on the unlikely failure (`EFAULT` from the
    // `uname(2)` syscall, unreachable from safe Rust) we fall
    // through to the standard byline.
    let nodename = heavything::util::sysinfo::uname()
        .map(|u| u.nodename)
        .unwrap_or_default();
    let is_2ton = nodename.starts_with(HOSTNAME_SLAVE_PREFIX) || nodename == HOSTNAME_CDEV;
    if is_2ton {
        eprintln!("{}", S10_2TON);
        eprintln!("{}", S11_2TON);
    } else {
        eprintln!("{}", S10_AUTHOR);
    }

    eprintln!();
    eprintln!("{}", TICKER_TEXT);
    eprintln!();
    eprintln!("Listening on {}:{} ...", BIND_ADDR, LISTEN_PORT);
}

// ===========================================================================
// Host-keys probe
// ===========================================================================

/// Probe `/etc/ssh` for SSH host keys at startup, exiting with the
/// FASM-equivalent error path if none are loadable.
///
/// The FASM `ssh$new_server` (`sshtalk.asm` line 244) returned NULL
/// when no host keys could be loaded; the calling code at line 246
/// jumped to `.hostkeyerror` which printed
/// `/etc/ssh host keys and/or contents error.` to stderr and exited
/// with status 1. The Rust [`SshSession::new_server`] only fails
/// when a host-key file *exists but is malformed* — missing files
/// are silently skipped (see [`heavything::crypto::x509::load_ssh_host_keys`]
/// at `x509.rs:903`). To preserve the FASM observable behavior
/// (no host keys → exit 1), this function probes the loader
/// directly and exits if the resulting key list is empty.
///
/// On success returns `Ok(())`; on missing or unreadable keys,
/// emits the byte-identical FASM error string and calls
/// [`std::process::exit`] with status 1 (this function never
/// returns in that path).
fn probe_host_keys() {
    match heavything::crypto::x509::load_ssh_host_keys() {
        Ok(keys) if !keys.is_empty() => {
            // At least one host key successfully loaded — proceed.
        }
        Ok(_) => {
            // Empty Vec — `/etc/ssh` had no readable host-key files
            // (every probe path returned ENOENT or EACCES). Match
            // FASM `.hostkeyerror`.
            eprintln!("{}", HOST_KEYS_ERROR);
            std::process::exit(1);
        }
        Err(_) => {
            // A host-key file existed but was malformed (parse
            // error). Match FASM `.hostkeyerror`.
            eprintln!("{}", HOST_KEYS_ERROR);
            std::process::exit(1);
        }
    }
}

// ===========================================================================
// main
// ===========================================================================

/// `sshtalk` binary crate entry point.
///
/// Mirrors the 17-step `_start` initialization sequence at
/// `sshtalk.asm` lines 46–286, with the per-connection setup
/// (FASM lines 252–272) extracted into [`handle_ssh_connection`]
/// because Rust requires per-connection state to live inside an
/// async task spawned by [`accept_loop`].
///
/// Step sequence (FASM line → Rust action):
///
/// | FASM line | Rust action                                         |
/// |-----------|-----------------------------------------------------|
/// | 48        | `heavything::init_args` (12-stage library init)    |
/// | 51        | `userdb::init` (loads sshtalk.userdb, installs vtable) |
/// | 54        | `chatroom::init`                                    |
/// | (chatpanel)| `chatpanel::init` (registers ChatpanelOpenerImpl)  |
/// | 57        | `screen::init_formatters`                           |
/// | 60        | `statusbar::init`                                   |
/// | 244–246   | `probe_host_keys` (FASM host-keys check)            |
/// | 234–272   | per-connection: `handle_ssh_connection` (in accept loop) |
/// | 274–278   | OMITTED: profiling block (per AAP §0.5.1.7)         |
/// | 281       | `accept_loop` inside tokio runtime block_on         |
///
/// On success returns `ExitCode::SUCCESS` (status 0). On
/// `heavything::init_args` failure, emits the error to stderr and
/// exits with the FASM-mapped exit code from
/// [`heavything::InitError::exit_code`] (96 = epoll_create fail,
/// 97 = ulimit too low, 98 = profiler overflow, 99 = heap mmap
/// fail, 1 = other). On host-key probe failure, exits with status 1
/// via [`std::process::exit`] inside [`probe_host_keys`]. On
/// runtime construction failure or accept-loop fatal error, returns
/// `ExitCode::from(1)`.
fn main() -> ExitCode {
    // Step 1: HeavyThing 12-stage init (`call ht$init` at
    // sshtalk.asm line 48). On failure, route through
    // `InitError::exit_code()` rather than hardcoding 96/97/98/99.
    let args: Vec<String> = std::env::args().collect();
    let _init_ctx = match heavything::init_args(args) {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("sshtalk: heavything init failed: {err}");
            return ExitCode::from(err.exit_code() as u8);
        }
    };

    // Step 2: userdb init (`call userdb$init` at sshtalk.asm
    // line 51). Loads the pipe-delimited `sshtalk.userdb` file
    // and installs the SIMPLEAUTH_VTABLE used by the per-connection
    // TuiSimpleAuth widget.
    if let Err(err) = userdb::init() {
        eprintln!("sshtalk: userdb init failed: {err}");
        return ExitCode::from(1);
    }

    // Step 3: chatroom init (`call chatroom$init` at sshtalk.asm
    // line 54). Initialises the global named-room registry.
    if let Err(err) = chatroom::init() {
        eprintln!("sshtalk: chatroom init failed: {err:#}");
        return ExitCode::from(1);
    }

    // Step 3b: chatpanel init. There is no FASM-side equivalent —
    // FASM resolved chatpanel's `screen$open_chatpanel` callback at
    // assembly time via direct symbol references. Rust requires an
    // explicit registration step (registers `ChatpanelOpenerImpl`
    // with the screen module so `screen::chatpanel_byname` can
    // dispatch to it).
    if let Err(err) = chatpanel::init() {
        eprintln!("sshtalk: chatpanel init failed: {err:#}");
        return ExitCode::from(1);
    }

    // Step 4: screen formatter init (`call screen$init_formatters`
    // at sshtalk.asm line 57). Pre-builds the connect/disconnect
    // syslog formatter strings.
    if let Err(err) = screen::init_formatters() {
        eprintln!("sshtalk: screen formatters init failed: {err:#}");
        return ExitCode::from(1);
    }

    // Step 5: statusbar init (`call statusbar$init` at sshtalk.asm
    // line 60). Pre-builds the status-bar format template.
    if let Err(err) = statusbar::init() {
        eprintln!("sshtalk: statusbar init failed: {err:#}");
        return ExitCode::from(1);
    }

    // Step 6: probe `/etc/ssh` for host keys (FASM line 244–246
    // equivalent). Exits with status 1 and the
    // `/etc/ssh host keys and/or contents error.` message if no
    // keys can be loaded. Never returns in the failure path.
    probe_host_keys();

    // Step 7: print branding strings to stderr (FASM splash-label
    // injection equivalent — see the `add_label` doc-comment for
    // the structural-mismatch rationale).
    print_startup_banner();

    // Step 8: build the SSH server. The `SshConfig::default()` uses
    // `/etc/ssh` as the host-keys directory and the FASM-baseline
    // cipher / compression / blacklist parameters. The `with_auth`
    // builder installs the permissive SSH-level callback (real auth
    // happens in TuiSimpleAuth — see the deep dive in the inner
    // handler).
    let ssh_config = SshConfig::default();
    let ssh_server = Arc::new(SshServer::new(ssh_config).with_auth(|_user, _pass| true));

    // Step 9: enter the tokio runtime and run the accept loop.
    // `heavything::net::runtime::run` builds a multi-thread runtime
    // and `block_on`s the supplied future — exactly the FASM
    // `epoll$run` semantics (the assembly's `epoll$run` never
    // returned during normal operation).
    let result: Result<()> = heavything::net::runtime::run(async move {
        // Bind the listener (`inaddr_any` + `epoll$inbound` at
        // sshtalk.asm lines 265–272).
        let listener = TcpListener::bind((BIND_ADDR, LISTEN_PORT))
            .await
            .with_context(|| format!("sshtalk: TcpListener::bind({}:{})", BIND_ADDR, LISTEN_PORT))?;

        // Per-connection handler. The handler is `Clone + Send +
        // 'static` because it captures only the `Arc<SshServer>`
        // (which is cheap to clone) and the `accept_loop` clones it
        // once per accepted connection.
        let server = ssh_server.clone();
        let handler = move |stream: TcpStream, peer: std::net::SocketAddr| {
            let server = server.clone();
            async move { handle_ssh_connection(stream, peer, server).await }
        };

        // Run the accept loop. `accept_loop` returns only on a
        // *fatal* listener error (e.g., the listener fd was closed
        // by an external signal); transient per-accept errors are
        // handled internally by tokio/mio.
        accept_loop(listener, handler)
            .await
            .context("sshtalk: accept_loop returned")?;

        Ok::<(), anyhow::Error>(())
    })
    .map_err(|io_err| anyhow!("sshtalk: tokio runtime construction failed: {io_err}"))
    .and_then(|inner| inner);

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("sshtalk: {err:#}");
            ExitCode::from(1)
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// `S1_VERSION` must encode the Latin-1 `0xa9` copyright glyph
    /// as the UTF-8 sequence `0xC2 0xA9`. Drift here would break
    /// the splash screen's branding line.
    #[test]
    fn s1_version_encodes_copyright_glyph_as_utf8() {
        let bytes = S1_VERSION.as_bytes();
        // The string starts with "sshtalk v1.12 " (14 bytes) then
        // the UTF-8 copyright glyph C2 A9, then " 2015 2 Ton Digital".
        let copyright_idx = 14;
        assert_eq!(bytes[copyright_idx], 0xC2);
        assert_eq!(bytes[copyright_idx + 1], 0xA9);
    }

    /// `HOST_KEYS_ERROR` MUST be byte-identical to the FASM
    /// `.errorstring` declaration at `sshtalk.asm` line 324:
    /// `'/etc/ssh host keys and/or contents error.'`. Drift here
    /// would break grep-based log monitoring downstream.
    #[test]
    fn host_keys_error_bytes_match_fasm_baseline() {
        assert_eq!(HOST_KEYS_ERROR, "/etc/ssh host keys and/or contents error.");
    }

    /// Every preserved string constant must be non-empty (catches
    /// accidental truncation during refactors).
    #[test]
    fn all_string_constants_are_nonempty() {
        let constants = [
            S1_VERSION,
            S2_MADE_IN,
            S3_SHOWCASE,
            S4_SECURE,
            S5_HANDCRAFTED,
            S6_ZERO_DEPS,
            S7_INFO,
            S8_CONNECTION,
            S9_ALGS,
            S10_AUTHOR,
            S10_2TON,
            S11_2TON,
            HOSTNAME_SLAVE_PREFIX,
            HOSTNAME_CDEV,
            TICKER_TEXT,
            HOST_KEYS_ERROR,
        ];
        for s in constants {
            assert!(!s.is_empty(), "string constant must be non-empty: {s:?}");
        }
    }

    /// `LISTEN_PORT` MUST be exactly 4001 per `sshtalk.asm`
    /// line 267 (`mov esi, 4001`) and AAP folder constraint #8.
    #[test]
    fn listen_port_matches_fasm_baseline() {
        assert_eq!(LISTEN_PORT, 4001);
    }

    /// `BIND_ADDR` MUST be the IPv4 `INADDR_ANY` dotted-quad
    /// representation `0.0.0.0` per `sshtalk.asm` line 268
    /// (`call inaddr_any`).
    #[test]
    fn bind_addr_matches_inaddr_any() {
        assert_eq!(BIND_ADDR, "0.0.0.0");
    }

    /// Color constants must match the xterm 256-color palette
    /// indices the FASM `ansi_colors` macro maps `'lightgray'`,
    /// `'black'`, and `'yellow'` to. Drift here would shift every
    /// branding label's color.
    #[test]
    fn color_constants_match_xterm_palette() {
        assert_eq!(COLOR_LIGHTGRAY, 251);
        assert_eq!(COLOR_BLACK, 232);
        assert_eq!(COLOR_YELLOW, 226);
    }

    /// Read-buffer size is the FASM `epoll_readsize` (32 KiB).
    /// Drift here would shift the per-iteration TCP read granularity
    /// away from the FASM baseline.
    #[test]
    fn read_buffer_matches_epoll_readsize() {
        assert_eq!(READ_BUFFER_SIZE, 32_768);
        assert_eq!(READ_BUFFER_SIZE, heavything::config::EPOLL_READSIZE);
    }
}
