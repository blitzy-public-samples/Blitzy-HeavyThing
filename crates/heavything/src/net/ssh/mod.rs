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

//! SSH 2.0 transport-layer subsystem — aggregator module.
//!
//! This subsystem translates the SSH 2.0 wire-protocol fragments of
//! `ssh.inc` into idiomatic Rust per AAP §0.5.1.4. The FASM author's
//! design pinned exactly one cipher suite for the entire SSH stack
//! (`ssh.inc` lines 42–61):
//!
//! | Layer            | Algorithm                                  |
//! |------------------|--------------------------------------------|
//! | Key exchange     | `diffie-hellman-group-exchange-sha256`     |
//! | Host key         | `ssh-rsa` / `ssh-dss`                      |
//! | Encryption       | `aes256-cbc`                               |
//! | MAC              | `hmac-sha2-256`                            |
//! | Compression      | `zlib` (forced when `ssh_force_compression`) |
//!
//! and the Rust port preserves that exact suite.
//!
//! # Submodules
//!
//! Sub-protocol layers each live in their own file:
//!
//! * [`auth`] — SSH 2.0 authentication-protocol layer: `SSH_MSG_*`
//!   constants, server-side `handle_userauth_request` / client-side
//!   `build_client_userauth_request` frame construction, the
//!   `AuthCallback` type registered by server applications (port of
//!   the authentication fragments of `ssh.inc`, AAP §0.5.1.4).
//! * [`cipher`] — AES-256-CBC encryption + HMAC-SHA-256 MAC computation
//!   per packet (port of the cipher / MAC fragments of `ssh.inc`,
//!   AAP §0.5.1.4). Owns [`CipherState`](cipher::CipherState) plus
//!   the wire-format constants and packet-framing helpers.
//! * [`compression`] — zlib deflate/inflate for the SSH transport
//!   layer, including the four-valued `CompressionState` state machine
//!   that implements both `zlib` (immediate) and `zlib@openssh.com`
//!   (delayed-until-userauth) negotiation behaviours (port of the
//!   compression fragments of `ssh.inc`, AAP §0.5.1.4).
//!
//! Other SSH submodules (`kex`, `server`) are scheduled in subsequent
//! translation checkpoints per AAP §0.5.1.4 and are not yet declared
//! here. Declaring `pub mod foo;` without a backing source file is a
//! hard compile error (rustc E0583), so premature declarations would
//! break the whole workspace build under the Gate 2
//! `RUSTFLAGS="-D warnings"` discipline (AAP §0.8.3).
//!
//! # Error handling
//!
//! All fallible SSH APIs surface the crate-wide
//! [`NetError`](crate::error::NetError) enum (see [`crate::error`]),
//! wrapping the more specific [`SshError`](crate::error::SshError)
//! variant where appropriate. The cipher / MAC layer in particular
//! returns [`NetError::Ssh`](crate::error::NetError::Ssh) wrapping
//! [`SshError::Cipher`](crate::error::SshError::Cipher) on alignment
//! errors, MAC verification failures, and packet-framing overflow per
//! AAP §0.7 CBC-oracle attack-surface mitigation.
//!
//! # `unsafe` audit
//!
//! None of the three currently-wired submodules ([`auth`], [`cipher`],
//! [`compression`]) contribute any `unsafe` blocks to the crate's
//! [`UNSAFE_AUDIT.md`](../../../../UNSAFE_AUDIT.md) tally
//! (AAP §0.7.4.1). Correctness of the cipher / MAC layer derives
//! entirely from `aes` (raw AES-256 block cipher), `ring::hmac`
//! (HMAC-SHA-256), and `ring::constant_time::verify_slices_are_equal`
//! (timing-safe MAC comparison). Correctness of the authentication
//! layer derives from safe slice indexing and the crate-internal RNG.
//! Correctness of the compression layer derives from the `flate2`
//! crate's safe streaming API.

/// SSH 2.0 authentication protocol — userauth frame parsing, callback
/// invocation, and frame construction — port of the authentication
/// fragments of `ssh.inc` (`.got_userauth_*`, `.got_service*`,
/// `.got_ignore`, and callback registration `ssh$set_authcb`).
pub mod auth;

/// AES-256-CBC encryption + HMAC-SHA-256 MAC for the SSH transport
/// layer — port of the cipher / MAC fragments of `ssh.inc`.
pub mod cipher;

/// zlib compression/decompression for the SSH transport layer —
/// port of the compression fragments of `ssh.inc`, implementing both
/// `zlib` (immediate) and `zlib@openssh.com` (delayed) negotiation.
pub mod compression;
