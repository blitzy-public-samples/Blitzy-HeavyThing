// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of the Rust port of the HeavyThing library.
//
// The Rust port is Copyright (C) 2026 and is distributed under the terms
// of the GNU General Public License version 3 (or any later version).
//
// It is a direct translation of the FASM source file `ht_defaults.inc`,
// which is Copyright (C) 2015-2018 2 Ton Digital, Jeff Marrison, and is
// likewise distributed under the GNU General Public License version 3.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Compile-time configuration constants.
//!
//! Direct port of the FASM source file `ht_defaults.inc` (523 lines of
//! `name = value` assignment directives). Every `pub const` in this module
//! corresponds 1:1 to a FASM symbol in the original source, with
//! identical default values.
//!
//! Constants are organized into themed sections (System and alignment,
//! Profiling, Heap, RNG, Strings/Unicode, Optimization, epoll, DNS,
//! Mimelike/HTTP, TUI, Syslog, Formatter, Bigint, DSA, DH, TLS,
//! X.509 / `OCSP`, TLS session cache encryption, scrypt, SSH, zlib,
//! privmapped, Webserver, Webclient) mirroring the source-file section
//! markers.
//!
//! # Why constants rather than runtime configuration
//!
//! Every FASM knob in `ht_defaults.inc` is a compile-time value. The
//! HeavyThing library relies on this for dead-code elimination and for
//! predictable behavior across binaries. Runtime overrides, where needed
//! (for example the `-hsts` flag on `webserver`), flow through the
//! application's CLI parsing in the binary crates rather than by mutating
//! these constants.
//!
//! # Units and naming
//!
//! - Byte sizes use `usize` (for example `PAGE_SIZE: usize = 4096`).
//! - Second counts use `u64` (for example `TLS_SERVER_SESSIONCACHE: u64 = 3600`).
//! - Millisecond counts use `u64` (for example `DNS_TIMEOUT_MSECS: u64 = 10000`).
//! - Boolean flags use `bool` (for example `WEBSERVER_HSTS: bool = true`).
//! - Counts of iterations or rounds use `u32` (for example
//!   `MILLER_RABIN_ERROR_RATE: u32 = 64`).
//! - Every constant is `SCREAMING_SNAKE_CASE` per rustc and clippy convention.
//!
//! # Protocol strings
//!
//! Two string constants, [`HSTS_HEADER_VALUE`] and [`SSH_IDENT_STRING`],
//! are byte-for-byte frozen per AAP §0.1.1 — they MUST match the FASM
//! baseline exactly so HTTPS clients and OpenSSH peers continue to see
//! the same wire-level bytes.
//!
//! # Exit codes are in the crate root (not in this module)
//!
//! The four process exit-code constants (mirroring FASM `ht.inc`
//! lines 38-41) are declared in the crate root `lib.rs`, not in this
//! module, because they derive from `ht.inc` rather than
//! `ht_defaults.inc` and because crate-root placement is more
//! prominent for binary-crate consumers. See:
//!
//! - [`crate::EXIT_HEAP_MMAP_FAIL`] (99 — heap mmap failure),
//! - [`crate::EXIT_PROFILER_OVERFLOW`] (98 — profiler buffer overflow),
//! - [`crate::EXIT_ULIMIT_TOO_LOW`] (97 — `RLIMIT_NOFILE` below
//!   [`EPOLL_MINFDS`]),
//! - [`crate::EXIT_EPOLL_CREATE_FAIL`] (96 — `epoll_create`/tokio
//!   runtime construction failure).
//!
//! Per AAP §0.7.1.2 these four codes are part of HeavyThing's
//! externally observable interface and MUST be produced under
//! equivalent failure conditions.

// ============================================================================
// System and alignment
// ============================================================================

/// Virtual memory page size in bytes. Mirrors FASM `page_size`.
pub const PAGE_SIZE: usize = 4096;

/// Whether function entry points are aligned. Mirrors FASM `align_functions`.
pub const ALIGN_FUNCTIONS: bool = true;

/// Whether return instructions are aligned. Mirrors FASM `align_returns`.
pub const ALIGN_RETURNS: bool = false;

/// Whether instructions immediately following a `call` are aligned.
/// Mirrors FASM `align_callreturns`.
pub const ALIGN_CALLRETURNS: bool = false;

/// Whether inner hot loops are aligned. Mirrors FASM `align_inner`.
pub const ALIGN_INNER: bool = true;

/// Whether data sections are aligned. Mirrors FASM `align_data`.
pub const ALIGN_DATA: bool = true;

/// Function alignment in bytes. Mirrors FASM `function_alignment`.
pub const FUNCTION_ALIGNMENT: usize = 16;

/// Inner-loop alignment in bytes. Mirrors FASM `inner_alignment`.
pub const INNER_ALIGNMENT: usize = 16;

/// Data alignment in bytes. Mirrors FASM `data_alignment`.
pub const DATA_ALIGNMENT: usize = 16;

/// Whether frame pointers are preserved for debugging. Mirrors FASM
/// `framepointers`.
pub const FRAMEPOINTERS: bool = true;

/// Whether assembly symbols are exported as public. Mirrors FASM
/// `public_funcs`.
pub const PUBLIC_FUNCS: bool = true;

// ============================================================================
// Profiling
// ============================================================================

/// Master profiling switch. Mirrors FASM `profiling`.
pub const PROFILING: bool = false;

/// Whether the profiler uses integer cycle counts. Mirrors FASM
/// `cpc_integers`.
pub const CPC_INTEGERS: bool = true;

/// Number of profiler records retained in memory. Mirrors FASM
/// `profiler_recordcount`.
pub const PROFILER_RECORDCOUNT: usize = 16_384;

/// Whether the profiler captures call-trace edges. Mirrors FASM
/// `calltracing`.
pub const CALLTRACING: bool = false;

// ============================================================================
// Heap
// ============================================================================

/// Whether generated code is preloaded (touched) on startup to warm the
/// instruction cache. Mirrors FASM `code_preload`.
pub const CODE_PRELOAD: bool = true;

/// Whether the heap allocator performs per-bin consistency checks.
/// Mirrors FASM `heap_bincheck`.
pub const HEAP_BINCHECK: bool = false;

/// Whether the heap allocator inserts guard barriers around allocations.
/// Mirrors FASM `heap_barriers`.
pub const HEAP_BARRIERS: bool = false;

// ============================================================================
// RNG
// ============================================================================

/// Whether the RNG performs its heavy initial reseed. Mirrors FASM
/// `rng_heavy_init`.
pub const RNG_HEAVY_INIT: bool = true;

/// Whether the RNG reads from `/dev/random` (paranoid mode) instead of
/// `/dev/urandom`. Mirrors FASM `rng_paranoid`.
pub const RNG_PARANOID: bool = false;

// ============================================================================
// Strings / Unicode
// ============================================================================

/// Width of the internal string codepoint representation in bits. The
/// Rust port uses native UTF-8 strings; this constant is preserved for
/// API parity with the FASM original (`string_bits`).
pub const STRING_BITS: u32 = 32;

/// Whether the case-folding tables include extended (locale-specific)
/// mappings. Mirrors FASM `extendedcase`.
pub const EXTENDED_CASE: bool = false;

/// Whether UTF validation is strict (rejecting surrogates, overlong
/// encodings, etc.). Mirrors FASM `strict_utf`.
pub const STRICT_UTF: bool = false;

/// Whether the base64 encoder inserts line breaks in its output.
/// Mirrors FASM `base64_linebreaks`.
pub const BASE64_LINEBREAKS: bool = true;

/// Maximum output line length (in characters) for the base64 encoder
/// when line breaks are enabled. Mirrors FASM `base64_maxline`.
pub const BASE64_MAXLINE: usize = 76;

// ============================================================================
// Optimization
// ============================================================================

/// Whether generated code uses the `MOVBE` (byte-swap-on-load)
/// instruction for endian conversions. Mirrors FASM `use_movbe`.
pub const USE_MOVBE: bool = false;

// ============================================================================
// epoll
// ============================================================================

/// Minimum required `RLIMIT_NOFILE` soft limit. The runtime exits with
/// status 97 if the current limit is below this threshold. Mirrors FASM
/// `epoll_minfds`.
pub const EPOLL_MINFDS: u64 = 4_096;

/// Whether the accept loop drains all pending connections per wakeup.
/// Mirrors FASM `epoll_multiple_accepts`.
pub const EPOLL_MULTIPLE_ACCEPTS: bool = true;

/// Whether `SO_KEEPALIVE` is enabled on accepted TCP sockets. Mirrors
/// FASM `epoll_keepalive`.
pub const EPOLL_KEEPALIVE: bool = true;

/// Whether `SO_LINGER` is enabled on accepted TCP sockets. Mirrors FASM
/// `epoll_linger`.
pub const EPOLL_LINGER: bool = false;

/// Whether `TCP_NODELAY` is enabled on accepted TCP sockets. Mirrors
/// FASM `epoll_nodelay`.
pub const EPOLL_NODELAY: bool = true;

/// Whether sockets are switched to non-blocking mode via `FIONBIO`
/// (rather than `O_NONBLOCK` via `fcntl`). Mirrors FASM `epoll_fionbio`.
pub const EPOLL_FIONBIO: bool = true;

/// `SO_LINGER` timeout value in seconds. Mirrors FASM
/// `epoll_linger_time`.
pub const EPOLL_LINGER_TIME: i32 = 30;

/// Stack size hint for per-connection tasks. Mirrors FASM
/// `epoll_stacksize`.
pub const EPOLL_STACKSIZE: i32 = 4_096;

/// Per-read buffer size in bytes. Mirrors FASM `epoll_readsize`.
pub const EPOLL_READSIZE: usize = 32_768;

/// Whether `EPOLL_CTL_DEL` is explicitly invoked before `close()` on a
/// socket. Mirrors FASM `epoll_del_before_close`.
pub const EPOLL_DEL_BEFORE_CLOSE: bool = false;

/// Whether outbound (client) sockets are created with `SOCK_CLOEXEC`.
/// Mirrors FASM `epoll_outbound_cloexec`.
pub const EPOLL_OUTBOUND_CLOEXEC: bool = false;

/// Whether Unix-domain connects to nonexistent sockets are forgiven
/// (treated as a soft failure). Mirrors FASM
/// `epoll_unixconnect_forgiving`.
pub const EPOLL_UNIXCONNECT_FORGIVING: bool = true;

// ============================================================================
// DNS
// ============================================================================

/// DNS resolution timeout in milliseconds. Mirrors FASM
/// `dns_timeout_msecs`.
pub const DNS_TIMEOUT_MSECS: u64 = 10_000;

// ============================================================================
// Mimelike / HTTP
// ============================================================================

/// Minimum response body size (in bytes) above which gzip encoding is
/// considered. Mirrors FASM `mimelike_mingzip`.
pub const MIMELIKE_MINGZIP: usize = 1_024;

/// Minimum response body size (in bytes) above which chunked transfer
/// encoding is considered. Zero means chunking decisions rely on other
/// signals. Mirrors FASM `mimelike_minchunked`.
pub const MIMELIKE_MINCHUNKED: usize = 0;

/// Chunk size in bytes for chunked transfer encoding. Mirrors FASM
/// `mimelike_chunksize`.
pub const MIMELIKE_CHUNKSIZE: usize = 65_535;

/// Whether multiple `Set-Cookie` headers are emitted as separate lines
/// rather than a single comma-joined value. Mirrors FASM
/// `mimelike_setcookie_split`.
pub const MIMELIKE_SETCOOKIE_SPLIT: bool = true;

// ============================================================================
// TUI
// ============================================================================

/// Whether the terminal backend uses the alternate-screen buffer
/// (`ESC[?1049h` / `ESC[?1049l`). Mirrors FASM
/// `terminal_alternatescreen`.
pub const TERMINAL_ALTERNATESCREEN: bool = true;

/// Whether the SSH TUI renderer uses the alternate-screen buffer.
/// Mirrors FASM `tui_ssh_alternatescreen`.
pub const TUI_SSH_ALTERNATESCREEN: bool = true;

/// Whether VT100 Alternate Character Set line drawing is used for
/// borders and rules. Mirrors FASM `acs_linechars`.
pub const ACS_LINECHARS: bool = true;

/// Whether a failed new-user registration inside `tui_simpleauth` exits
/// the process rather than returning to the login prompt. Mirrors FASM
/// `tui_simpleauth_newuserfail_exit`.
pub const TUI_SIMPLEAUTH_NEWUSERFAIL_EXIT: bool = false;

// ============================================================================
// Syslog
// ============================================================================

/// Syslog facility numeric code. The FASM original writes this as
/// `1 * 8`, i.e. facility number 1 (user-level messages) encoded per
/// RFC 3164 / RFC 5424 where the PRI value places the facility in the
/// high bits. The resolved value is `8`. Mirrors FASM `syslog_facility`.
pub const SYSLOG_FACILITY: u8 = 8;

/// Whether syslog output is also mirrored to stderr. Mirrors FASM
/// `syslog_stderr`.
pub const SYSLOG_STDERR: bool = false;

// ============================================================================
// Formatter
// ============================================================================

/// Whether date/time formatting includes fractional seconds. Mirrors
/// FASM `formatter_datetime_fractional`.
pub const FORMATTER_DATETIME_FRACTIONAL: bool = false;

// ============================================================================
// Bigint
// ============================================================================

/// Maximum number of 64-bit words in a `BigInt`. The FASM implementation
/// pre-allocates fixed-size arrays of this capacity; the Rust port uses
/// `num-bigint` internally but preserves this as a policy cap. Mirrors
/// FASM `bigint_maxwords`.
pub const BIGINT_MAXWORDS: usize = 512;

/// Loop unroll size for bulk `BigInt` operations. Mirrors FASM
/// `bigint_unrollsize`.
pub const BIGINT_UNROLLSIZE: usize = 16;

/// Number of Miller-Rabin witnesses used for primality testing. Mirrors
/// FASM `millerrabinerrorrate`.
pub const MILLER_RABIN_ERROR_RATE: u32 = 64;

// ============================================================================
// DSA
// ============================================================================

/// DSA modulus size in bits. Mirrors FASM `dsa_size`.
pub const DSA_SIZE: usize = 3_072;

/// DSA subgroup (q) size in bits. Mirrors FASM `dsa_subgroup_size`.
pub const DSA_SUBGROUP_SIZE: usize = 256;

// ============================================================================
// DH
// ============================================================================

/// Diffie-Hellman modulus size in bits for generated parameters.
/// Mirrors FASM `dh_bits`.
pub const DH_BITS: usize = 2_048;

/// Diffie-Hellman private exponent size in bits. Mirrors FASM
/// `dh_privatekey_size`.
pub const DH_PRIVATEKEY_SIZE: usize = 256;

// ============================================================================
// TLS
// ============================================================================

/// Whether the server advertises cipher suites in server-preference
/// order (as opposed to client-preference order). Mirrors FASM
/// `tls_server_cipher_order`.
pub const TLS_SERVER_CIPHER_ORDER: bool = true;

/// Interval (in seconds) between PEM certificate reloads. Mirrors FASM
/// `tls_pem_refresh_interval`.
pub const TLS_PEM_REFRESH_INTERVAL: u64 = 3_600;

/// Whether only Perfect Forward Secrecy cipher suites are offered.
/// Mirrors FASM `tls_perfect_forward_secrecy_only`.
pub const TLS_PFS_ONLY: bool = false;

/// Whether RSA operations use blinding (a side-channel mitigation with
/// a performance cost). Mirrors FASM `tls_server_rsa_blinding`.
pub const TLS_SERVER_RSA_BLINDING: bool = false;

/// Whether the TLS stack is compiled in the "minimalist" variant
/// (stripped-down cipher set). Mirrors FASM `tls_minimalist`.
pub const TLS_MINIMALIST: bool = false;

/// Whether the client verifies server-supplied DH `p` parameters for
/// safe-prime properties. Mirrors FASM `tls_clientside_dh_p_verify`.
pub const TLS_CLIENTSIDE_DH_P_VERIFY: bool = false;

/// Duration (in seconds) for which an IP is blacklisted following a
/// TLS cryptographic fault. Mirrors FASM `tls_blacklist`.
pub const TLS_BLACKLIST: u64 = 86_400;

/// Server-side TLS session cache lifetime in seconds. Mirrors FASM
/// `tls_server_sessioncache`.
pub const TLS_SERVER_SESSIONCACHE: u64 = 3_600;

/// Whether the server staples `OCSP` responses to its `Certificate`
/// messages. Mirrors FASM `tls_server_ocsp_stapling`.
pub const TLS_SERVER_OCSP_STAPLING: bool = true;

/// Whether the `OCSP` responder is queried with SHA-256 (rather than
/// SHA-1) identifiers. Mirrors FASM `X509_ocsp_sha256`.
pub const X509_OCSP_SHA256: bool = false;

// ============================================================================
// X.509 / OCSP
// ============================================================================

/// `OCSP` staple refresh interval in milliseconds (two hours). Mirrors
/// FASM `X509_ocsp_refresh`.
pub const X509_OCSP_REFRESH: u64 = 7_200_000;

/// `OCSP` staple retry interval (after a failed fetch) in milliseconds
/// (five minutes). Mirrors FASM `X509_ocsp_retry`.
pub const X509_OCSP_RETRY: u64 = 300_000;

/// Whether `OCSP` fetch activity is logged to syslog. Mirrors FASM
/// `X509_ocsp_syslog`.
pub const X509_OCSP_SYSLOG: bool = true;

// ============================================================================
// TLS session cache encryption
// ============================================================================

/// Whether server-side TLS session cache entries are AES-256 encrypted
/// at rest. Mirrors FASM `tls_server_encryptcache`.
pub const TLS_SERVER_ENCRYPTCACHE: bool = true;

/// Client-side TLS session cache lifetime in seconds. Mirrors FASM
/// `tls_client_sessioncache`.
pub const TLS_CLIENT_SESSIONCACHE: u64 = 3_600;

/// Whether client-side TLS session cache entries are AES-256 encrypted
/// at rest. Mirrors FASM `tls_client_encryptcache`.
pub const TLS_CLIENT_ENCRYPTCACHE: bool = true;

// ============================================================================
// scrypt
// ============================================================================

/// Whether the scrypt variant uses SHA-512 (rather than SHA-256) as its
/// underlying PRF. Mirrors FASM `scrypt_sha512`.
pub const SCRYPT_SHA512: bool = true;

/// scrypt cost parameter `N` (memory / time). Mirrors FASM `scrypt_N`.
pub const SCRYPT_N: u64 = 1_024;

/// scrypt block-size parameter `r`. Mirrors FASM `scrypt_r`.
pub const SCRYPT_R: u32 = 1;

/// scrypt parallelization parameter `p`. Mirrors FASM `scrypt_p`.
pub const SCRYPT_P: u32 = 1;

// ============================================================================
// SSH
// ============================================================================

/// Whether the SSH server uses dynamically generated DH group parameters
/// (as opposed to the static pool). Mirrors FASM `ssh_dh_dynamic`.
pub const SSH_DH_DYNAMIC: bool = false;

/// Whether the SSH server offers zlib compression at all. Mirrors FASM
/// `ssh_do_compression`.
pub const SSH_DO_COMPRESSION: bool = true;

/// Whether the SSH server requires zlib compression (refusing clients
/// that do not offer it). Mirrors FASM `ssh_force_compression`.
pub const SSH_FORCE_COMPRESSION: bool = true;

/// Duration (in seconds) for which an IP is blacklisted following an
/// SSH authentication fault. Mirrors FASM `ssh_blacklist`.
pub const SSH_BLACKLIST: u64 = 86_400;

// ============================================================================
// zlib
// ============================================================================

/// zlib deflate compression level. `0` is `Z_NO_COMPRESSION`, `1` is
/// `Z_BEST_SPEED`, `9` is `Z_BEST_COMPRESSION`, and `6` is zlib's
/// default. Mirrors FASM `zlib_deflate_level`.
pub const ZLIB_DEFLATE_LEVEL: u32 = 6;

/// Bytes automatically reserved in the output buffer when deflate is
/// invoked. Mirrors FASM `zlib_deflate_reserve`.
pub const ZLIB_DEFLATE_RESERVE: usize = 16_384;

// ============================================================================
// privmapped
// ============================================================================

/// Whether private mmaps open files with `O_NOATIME`. When the process
/// is not the file owner, `O_NOATIME` can cause `EPERM`, so it is off
/// by default. Mirrors FASM `privmapped_noatime`.
pub const PRIVMAPPED_NOATIME: bool = false;

// ============================================================================
// Webserver
// ============================================================================

/// `max-age` (in seconds) advertised in `Cache-Control` headers for
/// file-based serving. `s-maxage` is this value times three. Mirrors
/// FASM `webserver_filecache_time`.
pub const WEBSERVER_FILECACHE_TIME: u64 = 300;

/// Maximum accepted HTTP request-header size in bytes. Mirrors FASM
/// `webserver_maxheader`.
pub const WEBSERVER_MAXHEADER: usize = 32_768;

/// Maximum accepted HTTP request size in bytes (64 MiB). Mirrors FASM
/// `webserver_maxrequest`.
pub const WEBSERVER_MAXREQUEST: usize = 64 * 1_048_576;

/// File-size threshold (in bytes, 32 MiB) above which auto-gzip and
/// chunking are disabled and the file is streamed as-is. Mirrors FASM
/// `webserver_bigfile`.
pub const WEBSERVER_BIGFILE: usize = 32 * 1_048_576;

/// Whether on-the-fly gzip compression is applied to eligible responses
/// below the big-file threshold. Mirrors FASM `webserver_autogzip`.
pub const WEBSERVER_AUTOGZIP: bool = true;

/// Initial fill size (in bytes) pushed into the epoll send buffer.
/// Mirrors FASM `webserver_initialsend`.
pub const WEBSERVER_INITIALSEND: usize = 262_144;

/// Subsequent refill size (in bytes) for the epoll send buffer after
/// draining. Mirrors FASM `webserver_subsequentsend`.
pub const WEBSERVER_SUBSEQUENTSEND: usize = 262_144;

/// Interval (in seconds) between `stat()` revalidations of cached
/// file-serving mmaps. Must be less than [`WEBSERVER_HOTLIST_TIME`].
/// Mirrors FASM `webserver_hotlist_statfreq`.
pub const WEBSERVER_HOTLIST_STATFREQ: u64 = 120;

/// Lifetime (in seconds) of cached file-serving mmaps before eviction.
/// Mirrors FASM `webserver_hotlist_time`.
pub const WEBSERVER_HOTLIST_TIME: u64 = 900;

/// Whether the HTTP server emits the HSTS header (`Strict-Transport-
/// Security: max-age=31536000; includeSubDomains`) on TLS responses.
/// Mirrors FASM `webserver_hsts`.
pub const WEBSERVER_HSTS: bool = true;

/// Upper bound (in bytes) on the random `X-NB` padding header emitted
/// on auto-gzipped TLS responses as a BREACH-attack mitigation. Mirrors
/// FASM `webserver_breach_mitigation`.
pub const WEBSERVER_BREACH_MITIGATION: u32 = 48;

/// Whether FastCGI maps are hooked via the epoll post-process hook
/// rather than inline. Mirrors FASM `webserver_fastcgi_postprocess`.
pub const WEBSERVER_FASTCGI_POSTPROCESS: bool = false;

// ============================================================================
// Webclient
// ============================================================================

/// Maximum number of simultaneous webclient connections per hostname.
/// Mirrors FASM `webclient_maxconns`.
pub const WEBCLIENT_MAXCONNS: u32 = 4;

/// Webclient read-idle timeout in milliseconds (two minutes). Resets on
/// every byte received. Mirrors FASM `webclient_readtimeout`.
pub const WEBCLIENT_READTIMEOUT: u64 = 120_000;

/// Whether the webclient follows HTTP 301/302 redirects automatically.
/// Mirrors FASM `webclient_follow_redirects`.
pub const WEBCLIENT_FOLLOW_REDIRECTS: bool = true;

/// Whether a process-wide DNS cache is shared across all webclient
/// objects. Mirrors FASM `webclient_global_dnscache`.
pub const WEBCLIENT_GLOBAL_DNSCACHE: bool = true;

// ============================================================================
// Additional timer intervals (AAP §0.1.1)
// ============================================================================

/// Log-flush interval (in milliseconds) used by the master ↔ worker IPC
/// log relay path. Matches the fixed 1.5-second cadence in the FASM
/// `webserver.inc` / `rwasa/master.inc` baseline; see AAP §0.1.1.
pub const LOG_FLUSH_INTERVAL_MS: u64 = 1_500;

/// HTTP idle-connection timeout in seconds. Matches the fixed
/// 30-second cadence in the FASM `webserver.inc` baseline; see AAP
/// §0.1.1.
pub const HTTP_IDLE_TIMEOUT_SECS: u64 = 30;

// ============================================================================
// Preserved protocol strings (AAP §0.1.1 — byte-identical requirement)
// ============================================================================

/// Exact byte sequence emitted by the HTTP server when
/// [`WEBSERVER_HSTS`] is enabled. AAP §0.1.1 requires this string remain
/// byte-for-byte identical to the FASM baseline so existing HTTPS
/// clients observe the same wire-level bytes.
pub const HSTS_HEADER_VALUE: &str = "max-age=31536000; includeSubDomains";

/// SSH server identification banner. AAP §0.8.1 and §0.8.9 require this
/// string remain byte-for-byte identical to the FASM baseline so
/// OpenSSH 8.x+ interoperability is preserved.
pub const SSH_IDENT_STRING: &str = "SSH-2.0-HeavyThing";

// ============================================================================
// Compile-time invariants
// ============================================================================
//
// The following `const _: () = assert!(...)` statements enforce the
// subset of AAP §0.1.1 invariants whose expressions reduce to constant
// values. Because clippy's `assertions_on_constants` lint forbids
// `assert!(const_expr)` inside regular code, expressing the invariants
// as anonymous compile-time constants is the idiomatic solution: it
// both eliminates the lint and makes the checks strictly stronger
// than test-time assertions — every `cargo check` / `cargo build`
// evaluates them, not just `cargo test`. If a future edit ever flips
// one of these values, the crate will fail to compile with the
// message below.

const _: () = assert!(
    SCRYPT_SHA512,
    "scrypt MUST use SHA-512 per FASM default in ht_defaults.inc",
);

const _: () = assert!(
    BASE64_LINEBREAKS,
    "Base64 output line-break insertion MUST be enabled per FASM default",
);

const _: () = assert!(
    WEBSERVER_HOTLIST_STATFREQ < WEBSERVER_HOTLIST_TIME,
    "WEBSERVER_HOTLIST_STATFREQ must be strictly less than WEBSERVER_HOTLIST_TIME \
     (otherwise stat rechecks would fire after cache entries had already expired)",
);

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsts_value_is_exact() {
        assert_eq!(HSTS_HEADER_VALUE, "max-age=31536000; includeSubDomains");
    }

    #[test]
    fn ssh_ident_is_exact() {
        assert_eq!(SSH_IDENT_STRING, "SSH-2.0-HeavyThing");
    }

    #[test]
    fn epoll_minfds_is_4096() {
        assert_eq!(EPOLL_MINFDS, 4_096);
    }

    #[test]
    fn webserver_maxrequest_is_64mib() {
        assert_eq!(WEBSERVER_MAXREQUEST, 64 * 1_048_576);
    }

    #[test]
    fn webserver_bigfile_is_32mib() {
        assert_eq!(WEBSERVER_BIGFILE, 32 * 1_048_576);
    }

    #[test]
    fn scrypt_defaults() {
        assert_eq!(SCRYPT_N, 1_024);
        assert_eq!(SCRYPT_R, 1);
        assert_eq!(SCRYPT_P, 1);
        // SCRYPT_SHA512 is asserted at compile time via the module-level
        // `const _: () = assert!(SCRYPT_SHA512, ...)` invariant above.
    }

    #[test]
    fn miller_rabin_64_rounds() {
        assert_eq!(MILLER_RABIN_ERROR_RATE, 64);
    }

    #[test]
    fn timer_intervals() {
        assert_eq!(TLS_PEM_REFRESH_INTERVAL, 3_600);
        assert_eq!(TLS_SERVER_SESSIONCACHE, 3_600);
        assert_eq!(TLS_CLIENT_SESSIONCACHE, 3_600);
        assert_eq!(X509_OCSP_REFRESH, 7_200_000);
        assert_eq!(X509_OCSP_RETRY, 300_000);
        assert_eq!(TLS_BLACKLIST, 86_400);
        assert_eq!(SSH_BLACKLIST, 86_400);
        assert_eq!(WEBSERVER_HOTLIST_TIME, 900);
        assert_eq!(WEBSERVER_HOTLIST_STATFREQ, 120);
        assert_eq!(WEBSERVER_FILECACHE_TIME, 300);
        assert_eq!(LOG_FLUSH_INTERVAL_MS, 1_500);
        assert_eq!(HTTP_IDLE_TIMEOUT_SECS, 30);
        assert_eq!(DNS_TIMEOUT_MSECS, 10_000);
        assert_eq!(WEBCLIENT_READTIMEOUT, 120_000);
    }

    // Invariant: `webserver_hotlist_statfreq` must be strictly less than
    // `webserver_hotlist_time` — otherwise the stat recheck would happen
    // after the cached entry had already expired. This invariant is
    // enforced at compile time via the module-level `const _: () =
    // assert!(WEBSERVER_HOTLIST_STATFREQ < WEBSERVER_HOTLIST_TIME, ...)`
    // statement above.

    #[test]
    fn syslog_facility_is_user_level() {
        // RFC 3164: facility 1 (user-level messages) encoded as `1 * 8 == 8`
        assert_eq!(SYSLOG_FACILITY, 8);
    }

    #[test]
    fn alignment_values_are_sixteen() {
        assert_eq!(FUNCTION_ALIGNMENT, 16);
        assert_eq!(INNER_ALIGNMENT, 16);
        assert_eq!(DATA_ALIGNMENT, 16);
    }

    #[test]
    fn page_size_is_4kib() {
        assert_eq!(PAGE_SIZE, 4_096);
    }

    #[test]
    fn epoll_readsize_is_32kib() {
        assert_eq!(EPOLL_READSIZE, 32_768);
    }

    #[test]
    fn base64_line_width_is_76() {
        assert_eq!(BASE64_MAXLINE, 76);
        // BASE64_LINEBREAKS is asserted at compile time via the
        // module-level `const _: () = assert!(BASE64_LINEBREAKS, ...)`
        // invariant above.
    }

    #[test]
    fn dh_parameters_match_fasm() {
        assert_eq!(DH_BITS, 2_048);
        assert_eq!(DH_PRIVATEKEY_SIZE, 256);
        assert_eq!(DSA_SIZE, 3_072);
        assert_eq!(DSA_SUBGROUP_SIZE, 256);
    }

    #[test]
    fn zlib_defaults_match_fasm() {
        assert_eq!(ZLIB_DEFLATE_LEVEL, 6);
        assert_eq!(ZLIB_DEFLATE_RESERVE, 16_384);
    }

    #[test]
    fn breach_mitigation_padding_is_48() {
        assert_eq!(WEBSERVER_BREACH_MITIGATION, 48);
    }

    #[test]
    fn webclient_maxconns_is_4() {
        assert_eq!(WEBCLIENT_MAXCONNS, 4);
    }
}
