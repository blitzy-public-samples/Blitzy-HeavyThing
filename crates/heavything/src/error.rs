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

//! Crate-wide error types.
//!
//! Every subsystem module produces a dedicated typed error enum
//! ([`CryptoError`], [`NetError`], [`TlsError`], [`SshError`],
//! [`HttpError`], [`TuiError`], [`DsError`], [`UtilError`]) using
//! `thiserror::Error`. The public top-level [`InitError`] type
//! wraps these where relevant for the startup path and carries an
//! [`InitError::exit_code`] method so binary crates can translate
//! errors back into the FASM exit-code convention documented in
//! `ht.inc` lines 38–41:
//!
//! | FASM exit | Meaning                                          |
//! |-----------|--------------------------------------------------|
//! |  `99`     | Heap allocator `mmap`/`mremap` failed            |
//! |  `98`     | Profiler sample stack overrun                    |
//! |  `97`     | `RLIMIT_NOFILE` below `config::EPOLL_MINFDS`     |
//! |  `96`     | `epoll_create` / runtime build failed            |
//!
//! Per AAP §0.8.3, this crate uses `thiserror` for library errors;
//! `anyhow` is used only by the binary crates (`sshtalk`, `hnwatch`,
//! `webserver`) for end-user error reporting.

use thiserror::Error;

// ============================================================================
// InitError — top-level startup error type.
// ============================================================================

/// Error returned from `crate::init` / `crate::init_args`.
///
/// Each variant corresponds to a stage of the `ht$init_args` sequence
/// (`ht.inc` lines 316–604). The [`InitError::exit_code`] method maps
/// variants back to the `ht.inc` exit-code convention (96/97/98/99)
/// documented in the [module-level docs](self).
#[derive(Debug, Error)]
pub enum InitError {
    /// `uname(2)` syscall failed during Stage 6.
    #[error("uname(2) failed: {0}")]
    Uname(#[source] nix::Error),

    /// `RLIMIT_NOFILE` is below `crate::config::EPOLL_MINFDS` and could
    /// not be raised. Maps to exit code `97`.
    #[error("RLIMIT_NOFILE below minimum required for epoll")]
    UlimitTooLow,

    /// `epoll_create` / Tokio `Runtime::new` failed. Maps to exit
    /// code `96`.
    #[error("epoll_create / tokio runtime build failed: {0}")]
    EpollCreateFail(#[source] std::io::Error),

    /// Profiler sample stack overrun. Maps to exit code `98`.
    ///
    /// In the Rust port this variant preserves API parity with the FASM
    /// exit convention; actual profiling is delegated to `cargo bench`
    /// (per AAP §0.5.1.7 / profiler.rs notes) so this path is rarely
    /// reachable but MUST continue to map to 98 when surfaced.
    #[error("profiler sample stack overrun")]
    ProfilerOverflow,

    /// Heap `mmap`/`mremap` failed. Maps to exit code `99`.
    ///
    /// In the Rust port the crate uses the standard allocator, so this
    /// variant is effectively unreachable; it is retained for API parity
    /// with the `ht.inc` exit-code convention (line 38).
    #[error("heap allocator mmap/mremap failed: {0}")]
    HeapMmapFail(#[source] std::io::Error),

    /// Syslog initialization failed during Stage 8.
    ///
    /// The `#[from]` conversion here is load-bearing: it lets `lib.rs`
    /// Stage 8 propagate `UtilError` via the `?` operator directly into
    /// an `InitError::Syslog` variant.
    #[error("syslog initialization failed: {0}")]
    Syslog(#[from] UtilError),

    /// RNG initialization failed during Stage 9.
    ///
    /// Uses `#[source]` (NOT `#[from]`) on purpose: a `CryptoError`
    /// should NOT be silently promoted to an `InitError` in non-init
    /// contexts. Call sites in `lib.rs` use `.map_err(InitError::Rng)`
    /// explicitly.
    #[error("RNG initialization failed: {0}")]
    Rng(#[source] CryptoError),

    /// Miscellaneous startup failure. Maps to exit code `1`.
    #[error("initialization failed: {0}")]
    Other(String),
}

impl InitError {
    /// Exit code to pass to `std::process::exit` on fatal init
    /// failure.
    ///
    /// Maps each variant to the `ht.inc` exit-code convention
    /// (lines 38–41). This mapping is part of the observable interface
    /// per AAP §0.1.1 and MUST NOT change.
    ///
    /// | Variant                  | Exit |
    /// |--------------------------|------|
    /// | [`InitError::HeapMmapFail`]    | `99` |
    /// | [`InitError::ProfilerOverflow`]| `98` |
    /// | [`InitError::UlimitTooLow`]    | `97` |
    /// | [`InitError::EpollCreateFail`] | `96` |
    /// | Other variants           | `1`  |
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            InitError::HeapMmapFail(_) => crate::EXIT_HEAP_MMAP_FAIL,
            InitError::ProfilerOverflow => crate::EXIT_PROFILER_OVERFLOW,
            InitError::UlimitTooLow => crate::EXIT_ULIMIT_TOO_LOW,
            InitError::EpollCreateFail(_) => crate::EXIT_EPOLL_CREATE_FAIL,
            InitError::Uname(_) | InitError::Syslog(_) | InitError::Rng(_) | InitError::Other(_) => 1,
        }
    }
}

// ============================================================================
// CryptoError — failures produced by the `crate::crypto` subsystem.
// ============================================================================

/// Errors produced by the `crate::crypto` subsystem.
///
/// Wraps failure modes from AES, SHA/MD5 digests, HMAC/HMAC-DRBG,
/// PBKDF2/scrypt, RNG, bignum arithmetic, X.509 parsing, and DH
/// key exchange (AAP §0.5.1.3). Strings are used where upstream
/// crates expose opaque failure tags (e.g., `ring::error::Unspecified`).
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AES encryption/decryption failure.
    #[error("AES operation failed: {0}")]
    Aes(String),

    /// Digest computation failure (SHA-1, SHA-2, MD5).
    #[error("digest operation failed: {0}")]
    Digest(String),

    /// HMAC / HMAC-DRBG failure.
    #[error("HMAC operation failed: {0}")]
    Hmac(String),

    /// PBKDF2 / scrypt key derivation failure.
    #[error("key derivation failed: {0}")]
    Kdf(String),

    /// Random number generation failure
    /// (e.g., `/dev/urandom` unavailable).
    #[error("RNG failure: {0}")]
    Rng(#[source] std::io::Error),

    /// Big-integer arithmetic failure
    /// (e.g., modular inverse undefined).
    #[error("bignum arithmetic failure: {0}")]
    Bignum(String),

    /// X.509 parsing / validation failure.
    #[error("X.509 parse error: {0}")]
    X509(String),

    /// Diffie–Hellman key exchange failure.
    #[error("DH exchange failure: {0}")]
    Dh(String),
}

// ============================================================================
// NetError — aggregate error type for the `crate::net` subsystem.
// ============================================================================

/// Errors produced by the `crate::net` subsystem.
///
/// Aggregates TLS, SSH, and HTTP failures along with raw I/O, DNS,
/// bind, and privilege-drop errors. `From` impls for [`TlsError`],
/// [`SshError`], [`HttpError`], and `std::io::Error` enable
/// idiomatic `?`-propagation through the networking stack.
#[derive(Debug, Error)]
pub enum NetError {
    /// Underlying I/O failure.
    #[error("network I/O failure: {0}")]
    Io(#[from] std::io::Error),

    /// DNS resolution timed out. Mirrors the 10-second default from
    /// `crate::config::DNS_TIMEOUT_MSECS`
    /// (per AAP §0.5.1.4 `epoll_dns.inc` translation).
    #[error("DNS lookup timed out")]
    DnsTimeout,

    /// DNS resolution failure (non-timeout).
    #[error("DNS lookup failed: {0}")]
    Dns(String),

    /// `bind(2)` failed (e.g., `EADDRINUSE`).
    #[error("bind failed: {0}")]
    Bind(#[source] std::io::Error),

    /// `fork(2)` failed during worker spawn.
    #[error("fork failed: {0}")]
    Fork(#[source] nix::Error),

    /// Privilege-drop ordering violated: the mandated
    /// `bind → setgid → setuid → fork` sequence (AAP §0.1.1) could
    /// not be completed — usually `setuid(2)` or `setgid(2)` failure.
    #[error("privilege drop failed: {0}")]
    PrivDrop(#[source] nix::Error),

    /// TLS error; see [`TlsError`] for details.
    #[error("TLS error: {0}")]
    Tls(#[from] TlsError),

    /// SSH error; see [`SshError`] for details.
    #[error("SSH error: {0}")]
    Ssh(#[from] SshError),

    /// HTTP error; see [`HttpError`] for details.
    #[error("HTTP error: {0}")]
    Http(#[from] HttpError),

    /// A code path that is not implemented in this baseline port has
    /// been reached. Used by defensive stubs (e.g. `Wsbp` back-path
    /// proxy methods in `crate::net::http::server`) where the FASM
    /// reference includes a feature that is out-of-scope for the
    /// three in-scope showcase binaries (`sshtalk`, `hnwatch`,
    /// `webserver`).
    ///
    /// Producing a typed error rather than panicking via `todo!()`
    /// or `unimplemented!()` lets a crafted input or accidental
    /// configuration surface as a graceful runtime failure instead
    /// of a process abort, in line with secure-by-default
    /// principles. The static string identifies the unimplemented
    /// site so the caller can log or surface it diagnostically.
    #[error("feature not implemented: {0}")]
    NotImplemented(&'static str),
}

// ============================================================================
// TlsError — rustls-backed TLS failure modes.
// ============================================================================

/// Errors produced by the `crate::net::tls` module (rustls-backed TLS
/// handshake and session management).
///
/// Covers the four observable failure paths from `tls.inc` translated
/// in AAP §0.5.1.4 and §0.7.2: handshake failure, PEM parsing,
/// OCSP stapling refresh, and session cache encrypt/decrypt.
#[derive(Debug, Error)]
pub enum TlsError {
    /// rustls handshake failure.
    #[error("TLS handshake failed: {0}")]
    Handshake(String),

    /// PEM parsing failure during certificate or private-key load.
    #[error("PEM parse failed: {0}")]
    Pem(String),

    /// OCSP stapling fetch or parse failure.
    #[error("OCSP failure: {0}")]
    Ocsp(String),

    /// TLS session cache failure (AES-256 encrypt/decrypt of
    /// session-blob entries per AAP §0.7.2.4).
    #[error("session cache failure: {0}")]
    SessionCache(String),
}

// ============================================================================
// SshError — SSH2 protocol failure modes.
// ============================================================================

/// Errors produced by the `crate::net::ssh` module.
///
/// Covers the five observable failure paths from `ssh.inc` translated
/// in AAP §0.5.1.4: key-exchange negotiation, authentication,
/// cipher/HMAC verification (triggers blacklist), zlib compression,
/// and missing host keys.
#[derive(Debug, Error)]
pub enum SshError {
    /// Key-exchange failure
    /// (`diffie-hellman-group-exchange-sha256` only).
    #[error("SSH key exchange failed: {0}")]
    KeyExchange(String),

    /// Authentication failed (user/password or callback rejection).
    #[error("SSH authentication failed")]
    Auth,

    /// Invalid MAC / decryption failure
    /// (triggers IP blacklist per AAP §0.4.1.1 / `blacklist.inc`).
    #[error("SSH cipher/HMAC failure")]
    Cipher,

    /// zlib compression negotiation or inflate failure.
    #[error("SSH compression failure: {0}")]
    Compression(String),

    /// Missing or invalid host key(s) in `/etc/ssh/`
    /// (`sshtalk` exits 1 if host keys are missing per AAP §0.5.1.9).
    #[error("missing host keys: {0}")]
    HostKeys(String),
}

// ============================================================================
// HttpError — HTTP server/client failure modes.
// ============================================================================

/// Errors produced by the `crate::net::http` module (server and client).
///
/// Mirrors the observable HTTP failure paths from `webserver.inc`
/// and `webclient.inc` translated in AAP §0.5.1.4.
#[derive(Debug, Error)]
pub enum HttpError {
    /// Request line or headers could not be parsed.
    #[error("HTTP parse failure: {0}")]
    Parse(String),

    /// Request exceeded `crate::config::WEBSERVER_MAXREQUEST`
    /// (64 MiB default) or headers exceeded
    /// `crate::config::WEBSERVER_MAXHEADER` (32 KiB default).
    #[error("HTTP request too large")]
    TooLarge,

    /// Method not supported by the dispatch pipeline.
    #[error("HTTP method not supported: {0}")]
    UnsupportedMethod(String),

    /// Client exceeded the redirect-follow cap configured for
    /// `crate::net::http::client::WebClient`.
    #[error("HTTP redirect loop detected")]
    RedirectLoop,

    /// FastCGI upstream dispatch failure.
    #[error("FastCGI failure: {0}")]
    FastCgi(String),
}

// ============================================================================
// TuiError — terminal / rendering failure modes.
// ============================================================================

/// Errors produced by the `crate::tui` subsystem.
///
/// All three variants carry an `std::io::Error` as source because
/// raw-mode transitions, `TIOCGWINSZ`, and escape-code writes each
/// ultimately surface via the `libc` termios / ioctl / write paths
/// documented in AAP §0.7.3.
#[derive(Debug, Error)]
pub enum TuiError {
    /// Terminal raw-mode transition failed
    /// (`tcgetattr`/`cfmakeraw`/`tcsetattr`).
    #[error("terminal raw mode failed: {0}")]
    Termios(#[source] std::io::Error),

    /// `TIOCGWINSZ` ioctl failed.
    #[error("terminal winsize query failed: {0}")]
    Winsize(#[source] std::io::Error),

    /// Rendering failure (e.g., write to terminal FD).
    #[error("render failure: {0}")]
    Render(#[source] std::io::Error),
}

// ============================================================================
// DsError — data-structure failure modes.
// ============================================================================

/// Errors produced by the `crate::ds` subsystem.
///
/// Covers the two semantic failure modes that survive translation
/// from `buffer.inc` and `maps.inc` — capacity overflow and missing
/// key lookups. Most other `ds` operations return `Option` directly
/// rather than an error type.
#[derive(Debug, Error)]
pub enum DsError {
    /// Buffer capacity exceeded.
    #[error("buffer overflow: requested {requested}, capacity {capacity}")]
    BufferOverflow {
        /// Number of bytes the caller attempted to append / reserve.
        requested: usize,
        /// Current buffer capacity in bytes.
        capacity: usize,
    },

    /// Map key lookup failed when a value was required.
    #[error("map key not found")]
    KeyNotFound,
}

// ============================================================================
// UtilError — miscellaneous utility failure modes.
// ============================================================================

/// Errors produced by the `crate::util` subsystem.
///
/// Covers the translation surfaces from `zlib_{deflate,inflate}.inc`,
/// `base64_latin1.inc`, `json.inc`, direct filesystem I/O,
/// `mapped.inc`/`privmapped.inc`, `syslog.inc`, and `crc.inc` /
/// `png.inc` (AAP §0.5.1.7).
#[derive(Debug, Error)]
pub enum UtilError {
    /// zlib (de)compression failure.
    #[error("zlib failure: {0}")]
    Zlib(String),

    /// base64 decode failure.
    #[error("base64 decode failure: {0}")]
    Base64(String),

    /// JSON parse failure.
    #[error("JSON parse failure: {0}")]
    Json(String),

    /// Filesystem error.
    #[error("file I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// mmap failure (`memmap2::Mmap::map` or direct `mmap(2)`).
    #[error("mmap failure: {0}")]
    Mmap(String),

    /// Syslog socket connect / send failure.
    #[error("syslog failure: {0}")]
    Syslog(String),

    /// CRC mismatch (e.g., in PNG chunk validation).
    #[error("CRC mismatch")]
    CrcMismatch,
}

// ============================================================================
// Unit tests.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_exit_codes_match_ht_inc() {
        // Use `std::io::Error::other` (stable since Rust 1.74) to
        // satisfy `clippy::io_other_error` under `-D warnings`. Any
        // arbitrary `io::Error` suffices — the test only exercises
        // `exit_code()`, which does not inspect the payload.
        assert_eq!(
            InitError::HeapMmapFail(std::io::Error::other("x")).exit_code(),
            99
        );
        assert_eq!(InitError::ProfilerOverflow.exit_code(), 98);
        assert_eq!(InitError::UlimitTooLow.exit_code(), 97);
        assert_eq!(
            InitError::EpollCreateFail(std::io::Error::other("x")).exit_code(),
            96
        );
        assert_eq!(InitError::Other("x".into()).exit_code(), 1);
    }

    #[test]
    fn net_error_wraps_io() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope");
        let ne: NetError = io.into();
        assert!(matches!(ne, NetError::Io(_)));
    }

    #[test]
    fn net_error_wraps_tls() {
        let t = TlsError::Handshake("bad proto".into());
        let ne: NetError = t.into();
        assert!(matches!(ne, NetError::Tls(_)));
    }

    #[test]
    fn net_error_not_implemented_carries_static_message() {
        let ne = NetError::NotImplemented("wsbp::send_request");
        assert!(matches!(ne, NetError::NotImplemented(_)));
        // The Display impl from `thiserror` should include the static
        // site identifier so logs / diagnostics can identify the
        // unimplemented call site without panic / abort semantics.
        let rendered = ne.to_string();
        assert!(rendered.contains("wsbp::send_request"));
        assert!(rendered.contains("not implemented"));
    }

    #[test]
    fn util_error_wraps_io() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let ue: UtilError = io.into();
        assert!(matches!(ue, UtilError::Io(_)));
    }
}
