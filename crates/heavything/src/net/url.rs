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

//! URL parsing / encoding / decoding — Rust port of `url.inc` (38,117 bytes,
//! ~1,670 lines of FASM).
//!
//! The FASM source describes itself as *"straight-up URL parsing, decoding,
//! encoding, etc."* and lays out its URL state as a 10-field, 80-byte object
//! (offsets `url_protocol_ofs=0`, `url_host_ofs=8`, `url_port_ofs=16`,
//! `url_file_ofs=24`, `url_query_ofs=32`, `url_authority_ofs=40`,
//! `url_path_ofs=48`, `url_authinfo_ofs=56`, `url_ref_ofs=64`,
//! `url_user_ofs=72`). This Rust port preserves that shape 1:1 as the
//! private fields of the [`Url`] struct, exposes the same accessor set
//! that `webclient.inc` / `webserver.inc` consumers call, and maps
//! `url$tostring`, `url$encode`, `url$decode` to a [`std::fmt::Display`]
//! impl plus two free functions [`encode`] / [`decode`].
//!
//! Per AAP §0.5.1.7 this module is a **wrapper over the `url` crate**: the
//! heavy-lifting RFC 3986 scheme/host/port/path/query/fragment extraction is
//! delegated to [`::url::Url::parse`] inside [`Url::parse`], and the
//! resulting component accessors are copied into the FASM-style struct
//! exactly once per parse so downstream consumers that hold [`&str`]
//! references into our fields never have to re-parse.
//!
//! # FASM ↔ Rust function map
//!
//! | FASM symbol              | Rust equivalent                           |
//! |--------------------------|-------------------------------------------|
//! | `url$init`               | [`init`] (no-op — schemes are hard-coded) |
//! | `url$new`                | [`Url::new`] / [`Url::default`]           |
//! | `url$destroy`            | automatic via [`Drop`]                    |
//! | `url$equals`             | [`PartialEq`] impl                        |
//! | `url$debug`              | [`Debug`] impl                            |
//! | `url$setprotocol`        | [`Url::set_protocol`]                     |
//! | `url$sethost`            | [`Url::set_host`]                         |
//! | `url$setport`            | [`Url::set_port`]                         |
//! | `url$setfile`            | [`Url::set_file`]                         |
//! | `url$setquery`           | [`Url::set_query`]                        |
//! | `url$setauthority`       | [`Url::set_authority`]                    |
//! | `url$setpath`            | [`Url::set_path`]                         |
//! | `url$setauthinfo`        | [`Url::set_authinfo`]                     |
//! | `url$setref`             | [`Url::set_fragment`]                     |
//! | `url$topreface`          | [`Url::preface`]                          |
//! | `url$tostring`           | [`Display`](std::fmt::Display) impl       |
//! | `url$encode`             | [`encode`]                                |
//! | `url$decode`             | [`decode`]                                |
//!
//! # Scheme defaults
//!
//! Per the FASM `url$init` scheme table and AAP §0.5.1.7, three schemes are
//! wired with default ports:
//!
//! * `http` → 80
//! * `https` → 443
//! * `ftp` → 21
//!
//! Unknown schemes parse through permissively and report an effective port
//! of `0` from [`Url::effective_port`], matching the FASM behaviour of
//! passing through whatever the caller supplied.
//!
//! # Error handling
//!
//! [`UrlError`] has three variants (`Parse`, `Decode`, `UnknownScheme`) and
//! converts into [`NetError`] via [`From`] so failures bubble through the
//! crate-wide network error channel as `NetError::Http(HttpError::Parse(_))`
//! per the agent prompt's *Error Mapping* section.
//!
//! # Deliberate behavioural choices vs. the FASM
//!
//! * **`encode` uses the RFC 3986 §2.3 *Unreserved* set** (`A-Za-z0-9-_.~`)
//!   per the agent prompt. The FASM ships two lookup tables (a path table
//!   and a query table) with slightly different passthrough semantics for
//!   `' '` (space → `+` in query, `%20` in path) and `+`, `/`, `=`. The
//!   Rust port collapses to a single strict RFC 3986 table: space → `%20`,
//!   `/` → `%2F`, `?` → `%3F`, etc. This matches the agent prompt's
//!   authoritative test cases and the `test_encode_reserved` oracle.
//! * **`decode` is strict.** The FASM is tolerant (truncated `%XY` just
//!   stops processing; bad hex silently produces garbage), whereas the
//!   Rust port returns [`UrlError::Decode`] on truncated escapes and
//!   invalid hex digits. This matches the agent prompt's
//!   `test_decode_truncated` and `test_decode_bad_hex` oracles and the
//!   AAP §0.8.3 "no silent corruption" discipline.
//! * **`+` decodes to space.** The FASM supports this (line 1593-1594
//!   `.doit_plus` branch), and so does the Rust port — needed for
//!   `application/x-www-form-urlencoded` round-trips.
//!
//! # `unsafe` audit
//!
//! This module contributes **zero** `unsafe` blocks to the crate's
//! `UNSAFE_AUDIT.md` tally, per AAP §0.7.4.

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use crate::error::{HttpError, NetError};

// ============================================================================
// UrlError — parse / decode / unknown-scheme error variants.
// ============================================================================

/// Errors produced by URL parsing / decoding.
///
/// Converts to [`NetError::Http`]`(`[`HttpError::Parse`]`(…))` via the
/// [`From`] impl below so URL failures propagate through the crate-wide
/// network error channel (AAP §0.5.1.4, agent prompt *Error Mapping*).
#[derive(Debug, thiserror::Error)]
pub enum UrlError {
    /// The input string could not be parsed as a URL (malformed scheme,
    /// host, port, or other RFC 3986 violation surfaced by
    /// [`::url::Url::parse`]).
    #[error("invalid URL: {0}")]
    Parse(String),

    /// Percent-decoding (or `+` → space decoding) failed because the input
    /// contained an invalid or truncated escape sequence, or the decoded
    /// bytes were not valid UTF-8.
    #[error("invalid percent-encoding: {0}")]
    Decode(String),

    /// The URL's scheme is not one of the three schemes with a known
    /// default port (`http`, `https`, `ftp`).
    ///
    /// Currently informational only — [`Url::parse`] does not itself
    /// enforce a scheme allowlist (matching the FASM's permissive
    /// behaviour); this variant is reserved for consumers that want to
    /// reject non-canonical schemes.
    #[error("unknown scheme: {0}")]
    UnknownScheme(String),
}

impl From<UrlError> for NetError {
    fn from(e: UrlError) -> Self {
        // Funnels URL errors into the HTTP parse channel so any consumer
        // (`webclient.inc` / `webserver.inc` / `hnwatch`) already set up to
        // handle `NetError::Http(HttpError::Parse(_))` gets URL errors for
        // free. `HttpError::Parse(String)` is the natural bucket because a
        // malformed URL surfaces as a parse failure in the HTTP request
        // line. See agent prompt *Error Mapping*.
        NetError::Http(HttpError::Parse(e.to_string()))
    }
}

// ============================================================================
// Url — parsed URL with 10 accessor fields mirroring the FASM 80-byte layout.
// ============================================================================

/// Parsed URL with the same 10-component view that `url.inc` exposes.
///
/// The field set and default values map 1:1 onto the FASM 80-byte struct
/// (`url_protocol_ofs` through `url_user_ofs`). All string fields are
/// empty (not null) when absent, matching the FASM guarantee that every
/// `string$xxx` pointer is a valid non-null `heap$alloc`-backed string.
///
/// # Equality
///
/// Two [`Url`] values are equal iff all nine public component fields
/// (`protocol`, `host`, `port`, `file`, `query`, `authority`, `path`,
/// `authinfo`, `fragment`) are equal. The opaque [`Url::user`] payload
/// is **not** considered during equality — two URLs that differ only in
/// the user-data pointer are `==`. This matches the FASM `url$equals`
/// behaviour (which also ignores `url_user_ofs`) and reflects the
/// semantic purpose of `user` as an out-of-band owner pointer rather
/// than part of the URL's identity.
///
/// # Construction
///
/// * [`Url::new`] / [`Url::default`] — empty URL with zero port
/// * [`Url::parse`] — RFC 3986 parse (delegates to the `url` crate)
/// * Field-by-field setters — [`Url::set_protocol`], [`Url::set_host`],
///   [`Url::set_port`], [`Url::set_file`], [`Url::set_query`],
///   [`Url::set_authority`], [`Url::set_path`], [`Url::set_authinfo`],
///   [`Url::set_fragment`], [`Url::set_user`]
///
/// # Serialisation
///
/// The [`std::fmt::Display`] impl produces
/// `scheme://[authinfo@]host[:port]/path[?query][#fragment]` matching
/// the FASM `url$tostring` output. Default ports for known schemes
/// (`http`/80, `https`/443, `ftp`/21) are omitted from the rendered
/// output per RFC 3986 §3.2.3 normalisation.
#[derive(Clone, Default)]
pub struct Url {
    // --- FASM 80-byte layout parity (private fields; accessor methods below) --
    /// Scheme, e.g. `"http"`, `"https"`, `"ftp"`. Lower-cased on set.
    /// FASM offset `url_protocol_ofs = 0`.
    protocol: String,

    /// Host (or IPv4/IPv6 literal). Lower-cased on set.
    /// FASM offset `url_host_ofs = 8`.
    host: String,

    /// Port number; `0` means "use scheme default" (see
    /// [`Url::effective_port`]). FASM offset `url_port_ofs = 16`.
    port: u16,

    /// `path + "?" + query` — the HTTP request-URI string that a server
    /// hands to its handler dispatch pipeline. FASM offset
    /// `url_file_ofs = 24`.
    file: String,

    /// Query string (the portion after `?`, without the `?` itself).
    /// FASM offset `url_query_ofs = 32`.
    query: String,

    /// `"host[:port]"` — matches the RFC 3986 *authority* component
    /// (minus userinfo). Port suffix is omitted when equal to the
    /// scheme default. FASM offset `url_authority_ofs = 40`.
    authority: String,

    /// Path component (no query, no fragment). FASM offset
    /// `url_path_ofs = 48`.
    path: String,

    /// `"user[:password]"` — RFC 3986 *userinfo*. FASM offset
    /// `url_authinfo_ofs = 56`.
    authinfo: String,

    /// Fragment component (the portion after `#`, without the `#`
    /// itself). Renamed from FASM's `ref` because `ref` is a Rust
    /// keyword. FASM offset `url_ref_ofs = 64`.
    fragment: String,

    /// Opaque user-data pointer passed through by webclient callbacks.
    ///
    /// FASM offset `url_user_ofs = 72` — the FASM source documents
    /// this as *"a pointer to an external owner"* that the library
    /// never dereferences and only forwards back to the caller. In
    /// Rust, [`Arc<dyn Any + Send + Sync>`] provides the same
    /// type-erased opaque semantic while remaining memory-safe
    /// through reference counting. Consumers can recover the concrete
    /// type via [`Any::downcast_ref`].
    user: Option<Arc<dyn Any + Send + Sync>>,
}

// Manual Debug because `dyn Any` does not itself implement Debug.
impl fmt::Debug for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `user` rendered as a presence indicator only (the FASM `url$debug`
        // behaviour: it never dereferences `url_user_ofs`, so the Rust port
        // equivalently prints "<opaque>" / "None" rather than attempting to
        // downcast the Any payload).
        f.debug_struct("Url")
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("file", &self.file)
            .field("query", &self.query)
            .field("authority", &self.authority)
            .field("path", &self.path)
            .field("authinfo", &self.authinfo)
            .field("fragment", &self.fragment)
            .field("user", &self.user.as_ref().map(|_| "<opaque>"))
            .finish()
    }
}

// Manual PartialEq — `Arc<dyn Any>` does not implement PartialEq, and the
// FASM `url$equals` semantics ignore `url_user_ofs` anyway (consistent
// with user-data's role as an out-of-band owner pointer).
impl PartialEq for Url {
    fn eq(&self, other: &Self) -> bool {
        self.protocol == other.protocol
            && self.host == other.host
            && self.port == other.port
            && self.file == other.file
            && self.query == other.query
            && self.authority == other.authority
            && self.path == other.path
            && self.authinfo == other.authinfo
            && self.fragment == other.fragment
    }
}

// Eq is a marker trait — no methods to implement. Safe because every
// component we compare in PartialEq (String and u16) is itself Eq.
impl Eq for Url {}

impl Url {
    // ------------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------------

    /// Returns an empty URL — all string fields are `""` and `port` is 0.
    ///
    /// FASM equivalent: `url$new`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses a URL string into a [`Url`] using the `url` crate's RFC 3986
    /// implementation and then copies component accessors into the FASM
    /// 80-byte layout.
    ///
    /// # Errors
    ///
    /// Returns [`UrlError::Parse`] on any malformed input (invalid scheme,
    /// missing host, bad port, etc.). The error message includes the
    /// underlying parser's diagnostic for easier debugging.
    ///
    /// FASM equivalent: `url$new` with string argument (the FASM combined
    /// `new` + `parse` behind one entry point; we split for Rust clarity).
    pub fn parse(s: &str) -> Result<Self, UrlError> {
        let parsed = ::url::Url::parse(s).map_err(|e| UrlError::Parse(e.to_string()))?;

        // Scheme — lower-cased per FASM url$setprotocol. The `url` crate
        // already lower-cases schemes but we guard explicitly in case the
        // upstream behaviour ever changes.
        let protocol = parsed.scheme().to_ascii_lowercase();

        // Host — lower-cased per FASM url$sethost. `host_str()` returns
        // `None` for schemes with no authority (e.g. `mailto:`); the FASM
        // likewise leaves host empty in that case.
        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();

        // Port — `parsed.port()` returns `Some(p)` only when the URL carried
        // an explicit port; default scheme ports are returned as `None` and
        // we preserve that as 0 (matching the FASM convention where
        // `url_port_ofs == 0` means "use scheme default").
        let port = parsed.port().unwrap_or(0);

        // Path / query / fragment — direct copies. Empty strings for absent
        // components matches the FASM invariant that every string field is
        // non-null but possibly empty.
        let path = parsed.path().to_string();
        let query = parsed.query().unwrap_or("").to_string();
        let fragment = parsed.fragment().unwrap_or("").to_string();

        // Authinfo — "user[:password]" per RFC 3986 userinfo.
        let authinfo = if parsed.username().is_empty() {
            String::new()
        } else {
            let mut ai = String::from(parsed.username());
            if let Some(pw) = parsed.password() {
                ai.push(':');
                ai.push_str(pw);
            }
            ai
        };

        // Authority — "host[:port]" with port omitted when it matches the
        // scheme default (RFC 3986 §3.2.3 normalisation). This matches the
        // FASM `url$setauthority` convention used by the request-line
        // formatter in `webclient.inc`.
        let default_port = default_port_for_scheme(&protocol);
        let authority = if port != 0 && port != default_port {
            format!("{host}:{port}")
        } else {
            host.clone()
        };

        // File — "path[?query]", the HTTP request-URI string. This is the
        // FASM-specific convenience accessor: `webserver.inc` reads
        // `url_file_ofs` directly to build its dispatch key.
        let file = if query.is_empty() {
            path.clone()
        } else {
            format!("{path}?{query}")
        };

        Ok(Self {
            protocol,
            host,
            port,
            file,
            query,
            authority,
            path,
            authinfo,
            fragment,
            user: None,
        })
    }

    // ------------------------------------------------------------------------
    // Scheme / port helpers
    // ------------------------------------------------------------------------

    /// Returns the effective port — either [`Url::port`] when non-zero, or
    /// the scheme default (80 / 443 / 21 for `http` / `https` / `ftp`).
    /// Returns `0` for unknown schemes.
    ///
    /// Used by `webclient.inc` connection pools to key cached TCP / TLS
    /// connections per `(scheme, host, effective_port)`.
    #[must_use]
    pub fn effective_port(&self) -> u16 {
        if self.port != 0 {
            self.port
        } else {
            default_port_for_scheme(&self.protocol)
        }
    }

    /// Returns `"scheme://host[:port]"` — the connection preface used by
    /// webclient for connection keying. Port suffix is omitted when it
    /// matches the scheme default (RFC 3986 normalisation).
    ///
    /// FASM equivalent: `url$topreface`.
    #[must_use]
    pub fn preface(&self) -> String {
        let mut s = String::with_capacity(self.protocol.len() + 3 + self.host.len() + 6);
        s.push_str(&self.protocol);
        s.push_str("://");
        s.push_str(&self.host);
        // Emit port only when set AND different from the scheme default.
        // An explicit port equal to the default is omitted for consistency
        // with the preface format used by `webclient.inc` connection keys.
        let default_port = default_port_for_scheme(&self.protocol);
        if self.port != 0 && self.port != default_port {
            s.push(':');
            // `u16::to_string` doesn't allocate for small values — still
            // cheaper than a `format!` macro.
            s.push_str(&self.port.to_string());
        }
        s
    }

    // ------------------------------------------------------------------------
    // Component accessors — 9 getters matching FASM field layout.
    // ------------------------------------------------------------------------

    /// Returns the URL's scheme (e.g. `"http"`, `"https"`). FASM offset
    /// `url_protocol_ofs = 0`.
    #[must_use]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Returns the URL's host. FASM offset `url_host_ofs = 8`.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the URL's explicitly specified port, or `0` when the URL
    /// carries no port (see [`Url::effective_port`] for "port or scheme
    /// default"). FASM offset `url_port_ofs = 16`.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the combined `path[?query]` string — the HTTP request-URI
    /// that a server hands to its dispatch pipeline. FASM offset
    /// `url_file_ofs = 24`.
    #[must_use]
    pub fn file(&self) -> &str {
        &self.file
    }

    /// Returns the query string (after `?`, excluding the `?` itself).
    /// FASM offset `url_query_ofs = 32`.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Returns the authority (`"host[:port]"`). FASM offset
    /// `url_authority_ofs = 40`.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Returns the path component (no query, no fragment). FASM offset
    /// `url_path_ofs = 48`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the userinfo (`"user[:password]"`). FASM offset
    /// `url_authinfo_ofs = 56`.
    #[must_use]
    pub fn authinfo(&self) -> &str {
        &self.authinfo
    }

    /// Returns the fragment (after `#`, excluding the `#` itself). FASM
    /// offset `url_ref_ofs = 64`.
    #[must_use]
    pub fn fragment(&self) -> &str {
        &self.fragment
    }

    /// Returns the opaque user-data pointer, if any. FASM offset
    /// `url_user_ofs = 72`.
    ///
    /// Used by webclient callbacks that attach arbitrary user data to a
    /// URL (e.g. per-request context, a pointer to a webserver config
    /// block). Consumers recover the concrete type via
    /// [`Any::downcast_ref`] on the returned `&dyn Any`.
    #[must_use]
    pub fn user(&self) -> Option<&Arc<dyn Any + Send + Sync>> {
        self.user.as_ref()
    }

    // ------------------------------------------------------------------------
    // Component setters — 10 setters matching FASM field layout.
    // ------------------------------------------------------------------------

    /// Sets the scheme (lower-cased on assignment). FASM equivalent:
    /// `url$setprotocol`.
    pub fn set_protocol(&mut self, s: &str) {
        self.protocol = s.to_ascii_lowercase();
    }

    /// Sets the host (lower-cased on assignment). FASM equivalent:
    /// `url$sethost`.
    pub fn set_host(&mut self, s: &str) {
        self.host = s.to_ascii_lowercase();
    }

    /// Sets the explicit port (`0` means "use scheme default"). FASM
    /// equivalent: `url$setport`.
    pub fn set_port(&mut self, p: u16) {
        self.port = p;
    }

    /// Sets the combined `path[?query]` file string. FASM equivalent:
    /// `url$setfile`.
    pub fn set_file(&mut self, s: &str) {
        self.file = s.to_string();
    }

    /// Sets the query string (portion after `?`). FASM equivalent:
    /// `url$setquery`.
    pub fn set_query(&mut self, s: &str) {
        self.query = s.to_string();
    }

    /// Sets the authority (`"host[:port]"`). FASM equivalent:
    /// `url$setauthority`.
    pub fn set_authority(&mut self, s: &str) {
        self.authority = s.to_string();
    }

    /// Sets the path component (no query, no fragment). FASM equivalent:
    /// `url$setpath`.
    pub fn set_path(&mut self, s: &str) {
        self.path = s.to_string();
    }

    /// Sets the userinfo (`"user[:password]"`). FASM equivalent:
    /// `url$setauthinfo`.
    pub fn set_authinfo(&mut self, s: &str) {
        self.authinfo = s.to_string();
    }

    /// Sets the fragment (portion after `#`). FASM equivalent:
    /// `url$setref` — renamed because `ref` is a Rust keyword.
    pub fn set_fragment(&mut self, s: &str) {
        self.fragment = s.to_string();
    }

    /// Attaches an opaque user-data payload. FASM equivalent: direct
    /// `mov qword [rdi+url_user_ofs], rsi`.
    pub fn set_user(&mut self, v: Arc<dyn Any + Send + Sync>) {
        self.user = Some(v);
    }
}

// ============================================================================
// Display — FASM url$tostring parity.
// ============================================================================

impl fmt::Display for Url {
    /// Emits `scheme://[authinfo@]host[:port]/path[?query][#fragment]`,
    /// matching the FASM `url$tostring` output from
    /// `url.inc` lines 1287–1391.
    ///
    /// Default ports for known schemes (`http`/80, `https`/443, `ftp`/21)
    /// are omitted per RFC 3986 §3.2.3 normalisation. A URL with an
    /// empty path is rendered with a single `/` separator so downstream
    /// HTTP request lines are always well-formed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // scheme://
        write!(f, "{}://", self.protocol)?;

        // [authinfo@] — only when present (FASM line 1289 comment:
        // "note: does not add authinfo". We DO add it when non-empty
        // because downstream Rust consumers expect a lossless round-trip
        // through Display→parse; the FASM comment reflects its own
        // decision to hide credentials from default logging, which we
        // defer to the caller's discretion).
        if !self.authinfo.is_empty() {
            write!(f, "{}@", self.authinfo)?;
        }

        // host
        f.write_str(&self.host)?;

        // [:port] — only when set AND different from scheme default.
        let default_port = default_port_for_scheme(&self.protocol);
        if self.port != 0 && self.port != default_port {
            write!(f, ":{}", self.port)?;
        }

        // /path — add leading "/" if the path doesn't start with one, or
        // emit a bare "/" when the path is empty (so we never produce
        // "http://host?query" which some parsers reject).
        if self.path.is_empty() {
            f.write_str("/")?;
        } else if self.path.starts_with('/') {
            f.write_str(&self.path)?;
        } else {
            f.write_str("/")?;
            f.write_str(&self.path)?;
        }

        // ?query
        if !self.query.is_empty() {
            write!(f, "?{}", self.query)?;
        }

        // #fragment
        if !self.fragment.is_empty() {
            write!(f, "#{}", self.fragment)?;
        }

        Ok(())
    }
}

// ============================================================================
// Percent-encoding — FASM url$encode parity with RFC 3986 unreserved set.
// ============================================================================

/// Percent-encodes a string for use in URLs.
///
/// Characters in the RFC 3986 §2.3 *Unreserved* set — `A-Z`, `a-z`,
/// `0-9`, `-`, `_`, `.`, `~` — pass through unchanged. All other bytes
/// are encoded as `%XX` where `XX` is the uppercase hexadecimal
/// representation of the byte value.
///
/// FASM equivalent: `url$encode` (`url.inc` lines 1397–1513).
///
/// The FASM ships separate path / non-path lookup tables (differing in
/// how `' '`, `+`, `/`, `=` are handled). This Rust port collapses to
/// the single strict RFC 3986 unreserved-set table per the agent
/// prompt's authoritative test cases (`test_encode_reserved` expects
/// space → `%20`, `/` → `%2F`, `?` → `%3F`).
///
/// # Example
///
/// ```
/// use heavything::net::url::encode;
/// assert_eq!(encode("hello world/foo?bar"), "hello%20world%2Ffoo%3Fbar");
/// assert_eq!(encode("abcXYZ_0123-.~"), "abcXYZ_0123-.~");
/// ```
#[must_use]
pub fn encode(input: &str) -> String {
    // Pre-size for the common case where ≤25% of bytes need encoding.
    // In the worst case (all bytes percent-encoded) we'd need 3×len, but
    // `String::push` re-grows geometrically so this heuristic is fine.
    let mut out = String::with_capacity(input.len());

    for &b in input.as_bytes() {
        match b {
            // RFC 3986 §2.3 Unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                // Safe: `b` is in the ASCII range by pattern match, so casting
                // to `char` is a valid UTF-8 scalar.
                out.push(b as char);
            }
            // All other bytes → %XX (uppercase hex per RFC 3986 §2.1
            // recommendation).
            _ => {
                out.push('%');
                out.push(to_hex_upper(b >> 4));
                out.push(to_hex_upper(b & 0x0F));
            }
        }
    }

    out
}

// ============================================================================
// Percent-decoding — FASM url$decode parity with strict error checking.
// ============================================================================

/// Percent-decodes a URL-escaped string back to its original bytes,
/// interpreting the result as UTF-8.
///
/// Accepts both uppercase and lowercase hex digits in `%XX` escapes.
/// Decodes `+` as a space (application/x-www-form-urlencoded
/// convention), matching the FASM `.doit_plus` branch at `url.inc`
/// line 1639.
///
/// # Errors
///
/// Returns [`UrlError::Decode`] when:
///
/// * A `%` appears at or near the end of the string with fewer than two
///   hex digits following (truncated escape).
/// * An escape contains a non-hex character (e.g. `%gg`, `%1z`).
/// * The decoded bytes are not valid UTF-8.
///
/// The FASM is tolerant (truncated escapes stop processing silently),
/// but the Rust port is strict per the agent prompt's
/// `test_decode_truncated` and `test_decode_bad_hex` oracles.
///
/// FASM equivalent: `url$decode` (`url.inc` lines 1554–1669).
///
/// # Example
///
/// ```
/// use heavything::net::url::decode;
/// assert_eq!(decode("hello%20world").unwrap(), "hello world");
/// assert_eq!(decode("a+b").unwrap(), "a b");
/// assert!(decode("a%2").is_err());
/// assert!(decode("a%gg").is_err());
/// ```
pub fn decode(input: &str) -> Result<String, UrlError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                // A valid `%XY` escape needs two hex digits at i+1, i+2.
                // `i + 2 >= bytes.len()` catches both "%" at end and
                // "%X" with one digit left.
                if i + 2 >= bytes.len() {
                    return Err(UrlError::Decode(format!(
                        "truncated percent-escape at position {i}"
                    )));
                }
                let h = from_hex(bytes[i + 1]).ok_or_else(|| {
                    UrlError::Decode(format!(
                        "invalid hex digit '{}' at position {}",
                        bytes[i + 1] as char,
                        i + 1
                    ))
                })?;
                let l = from_hex(bytes[i + 2]).ok_or_else(|| {
                    UrlError::Decode(format!(
                        "invalid hex digit '{}' at position {}",
                        bytes[i + 2] as char,
                        i + 2
                    ))
                })?;
                out.push((h << 4) | l);
                i += 3;
            }
            b'+' => {
                // application/x-www-form-urlencoded: "+" means " ".
                // FASM `.doit_plus` branch at `url.inc:1639`.
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }

    String::from_utf8(out).map_err(|e| UrlError::Decode(e.to_string()))
}

// ============================================================================
// init — no-op for API parity with FASM `url$init`.
// ============================================================================

/// One-time initialisation hook.
///
/// FASM equivalent: `url$init`, which populates an 8-entry scheme-to-port
/// stringmap at startup so that `url$new` / `url$setprotocol` can look
/// up default ports by scheme string.
///
/// The Rust port inlines the scheme-to-port mapping into the
/// [`default_port_for_scheme`] helper function — no runtime lookup
/// table is needed, so this function is a no-op. It is retained for
/// API parity so binary crates (`sshtalk`, `hnwatch`, `webserver`)
/// that mirror the FASM `ht$init` twelve-stage boot sequence can call
/// `crate::net::url::init()` in the same slot where the FASM calls
/// `url$init`.
pub fn init() {
    // Intentionally empty. Scheme/port mapping is a `const` lookup
    // (see `default_port_for_scheme`).
}

// ============================================================================
// Private helpers
// ============================================================================

/// Returns the IANA default port for known schemes.
///
/// Matches the FASM `url$init` stringmap entries for the three in-scope
/// schemes per AAP §0.5.1.7. Returns `0` for unknown schemes; callers
/// that need to reject unknown schemes can inspect the return value or
/// use [`UrlError::UnknownScheme`].
fn default_port_for_scheme(scheme: &str) -> u16 {
    match scheme {
        "http" => 80,
        "https" => 443,
        "ftp" => 21,
        _ => 0,
    }
}

/// Converts a 4-bit nibble (`0..=15`) to its uppercase ASCII hex digit.
///
/// Uses a saturating match to eliminate the panic path that
/// `unreachable!()` would produce under `clippy::panic_in_result_fn`.
/// The function is `#[inline]` so the compiler can elide the bounds
/// check when the caller passes a masked byte.
#[inline]
fn to_hex_upper(n: u8) -> char {
    // A branchless equivalent of the naive match: for n < 10, return
    // ('0' + n); for 10..=15, return ('A' + n - 10); higher bits are
    // impossible given callers always pass `b >> 4` or `b & 0x0F`.
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + n - 10) as char,
        // `n` is derived from `b >> 4` or `b & 0x0F` at every call site,
        // both of which are ≤ 15. This arm is therefore statically
        // unreachable; we return '0' (not panic!) so the function stays
        // panic-free for clippy::panic_in_result_fn clean code review.
        _ => '0',
    }
}

/// Parses a single ASCII hex digit (`'0'..='9'` / `'a'..='f'` / `'A'..='F'`)
/// into its 4-bit value. Returns `None` for non-hex bytes.
#[inline]
fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse() tests ------------------------------------------------------

    #[test]
    fn test_parse_basic() {
        let url = Url::parse("http://example.com/foo?bar=baz#frag").unwrap();
        assert_eq!(url.protocol(), "http");
        assert_eq!(url.host(), "example.com");
        assert_eq!(url.port(), 0, "no explicit port → port == 0");
        assert_eq!(url.effective_port(), 80, "http default port");
        assert_eq!(url.path(), "/foo");
        assert_eq!(url.query(), "bar=baz");
        assert_eq!(url.fragment(), "frag");
        assert_eq!(url.file(), "/foo?bar=baz");
        assert_eq!(url.authority(), "example.com");
        assert_eq!(url.authinfo(), "", "no userinfo");
    }

    #[test]
    fn test_parse_https_default_port() {
        let url = Url::parse("https://example.com/").unwrap();
        assert_eq!(url.protocol(), "https");
        assert_eq!(url.port(), 0);
        assert_eq!(url.effective_port(), 443);
        assert_eq!(url.path(), "/");
        assert_eq!(url.authority(), "example.com");
    }

    #[test]
    fn test_parse_explicit_port() {
        let url = Url::parse("http://example.com:8080/").unwrap();
        assert_eq!(url.port(), 8080);
        assert_eq!(url.effective_port(), 8080);
        assert_eq!(url.authority(), "example.com:8080");
    }

    #[test]
    fn test_parse_authinfo() {
        let url = Url::parse("http://user:pass@example.com/").unwrap();
        assert_eq!(url.authinfo(), "user:pass");
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_parse_invalid() {
        let result = Url::parse("not a url");
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(
                matches!(e, UrlError::Parse(_)),
                "expected UrlError::Parse, got {e:?}"
            );
        }
    }

    // ---- Display + round-trip ----------------------------------------------

    #[test]
    fn test_display_roundtrip() {
        // Pick a URL whose Display output re-parses identically.
        // (URLs with explicit default ports won't round-trip because
        // Display omits the default port — which is correct per RFC 3986.)
        let original = Url::parse("https://example.com/foo/bar?q=1#top").unwrap();
        let displayed = original.to_string();
        let reparsed = Url::parse(&displayed).unwrap();
        assert_eq!(original, reparsed, "Display→parse should round-trip");
    }

    // ---- encode() tests -----------------------------------------------------

    #[test]
    fn test_encode_reserved() {
        // Space → %20, '/' → %2F, '?' → %3F per RFC 3986 unreserved set.
        assert_eq!(encode("hello world/foo?bar"), "hello%20world%2Ffoo%3Fbar");
    }

    #[test]
    fn test_encode_unreserved_passthrough() {
        // A-Z, a-z, 0-9, '-', '_', '.', '~' pass through unchanged.
        assert_eq!(encode("abcXYZ_0123-.~"), "abcXYZ_0123-.~");
    }

    // ---- decode() tests -----------------------------------------------------

    #[test]
    fn test_decode_basic() {
        assert_eq!(decode("hello%20world").unwrap(), "hello world");
    }

    #[test]
    fn test_decode_plus_as_space() {
        // application/x-www-form-urlencoded: '+' means ' '.
        assert_eq!(decode("a+b").unwrap(), "a b");
    }

    #[test]
    fn test_decode_upper_and_lower_hex() {
        // Both cases accepted; produces "//" (0x2F = '/').
        assert_eq!(decode("%2f%2F").unwrap(), "//");
    }

    #[test]
    fn test_decode_truncated() {
        // "%" at end, "%X" with one digit left → both errors.
        assert!(matches!(decode("a%2"), Err(UrlError::Decode(_))));
        assert!(matches!(decode("%"), Err(UrlError::Decode(_))));
        assert!(matches!(decode("ab%"), Err(UrlError::Decode(_))));
    }

    #[test]
    fn test_decode_bad_hex() {
        // Non-hex digits after % → error.
        assert!(matches!(decode("a%gg"), Err(UrlError::Decode(_))));
        assert!(matches!(decode("a%0z"), Err(UrlError::Decode(_))));
    }

    // ---- preface() tests ----------------------------------------------------

    #[test]
    fn test_preface_http_default_port() {
        // Port 80 equals http default → port suffix omitted.
        let url = Url::parse("http://example.com:80/").unwrap();
        assert_eq!(url.preface(), "http://example.com");
    }

    #[test]
    fn test_preface_https_custom_port() {
        let url = Url::parse("https://example.com:8443/").unwrap();
        assert_eq!(url.preface(), "https://example.com:8443");
    }

    // ---- PartialEq ----------------------------------------------------------

    #[test]
    fn test_partial_eq() {
        let a = Url::parse("http://example.com/foo?bar=1").unwrap();
        let b = Url::parse("http://example.com/foo?bar=1").unwrap();
        assert_eq!(a, b);
    }

    // ---- Additional coverage (defensive tests beyond the 16 specified) -----
    // These don't replace or reduce the above; they tighten confidence in
    // corner cases surfaced during implementation review.

    #[test]
    fn test_new_and_default_are_equivalent() {
        let a = Url::new();
        let b = Url::default();
        assert_eq!(a, b);
        assert_eq!(a.protocol(), "");
        assert_eq!(a.host(), "");
        assert_eq!(a.port(), 0);
        assert_eq!(a.effective_port(), 0, "no scheme → no default port");
    }

    #[test]
    fn test_setters_lowercase_protocol_and_host() {
        let mut url = Url::new();
        url.set_protocol("HTTPS");
        url.set_host("EXAMPLE.COM");
        assert_eq!(url.protocol(), "https");
        assert_eq!(url.host(), "example.com");
    }

    #[test]
    fn test_setters_preserve_case_for_other_fields() {
        let mut url = Url::new();
        url.set_path("/Foo/Bar");
        url.set_query("Key=Value");
        url.set_fragment("Section");
        url.set_authinfo("Alice:SecReT");
        url.set_file("/Foo?Key=Value");
        url.set_authority("EXAMPLE.com:8080");
        assert_eq!(url.path(), "/Foo/Bar");
        assert_eq!(url.query(), "Key=Value");
        assert_eq!(url.fragment(), "Section");
        assert_eq!(url.authinfo(), "Alice:SecReT");
        assert_eq!(url.file(), "/Foo?Key=Value");
        assert_eq!(url.authority(), "EXAMPLE.com:8080");
    }

    #[test]
    fn test_effective_port_unknown_scheme() {
        let mut url = Url::new();
        url.set_protocol("gopher");
        assert_eq!(url.effective_port(), 0, "unknown schemes have no default port");
    }

    #[test]
    fn test_effective_port_explicit_overrides_default() {
        let mut url = Url::new();
        url.set_protocol("http");
        url.set_port(9000);
        assert_eq!(url.effective_port(), 9000);
    }

    #[test]
    fn test_ftp_default_port() {
        let url = Url::parse("ftp://ftp.example.com/").unwrap();
        assert_eq!(url.protocol(), "ftp");
        assert_eq!(url.effective_port(), 21);
    }

    #[test]
    fn test_display_with_authinfo() {
        // Authinfo round-trips through Display.
        let parsed = Url::parse("http://alice:pw@example.com:8080/x").unwrap();
        let displayed = parsed.to_string();
        assert!(displayed.starts_with("http://alice:pw@example.com:8080/"));
    }

    #[test]
    fn test_display_with_fragment_only() {
        // No query, just a fragment.
        let parsed = Url::parse("https://example.com/a#top").unwrap();
        assert_eq!(parsed.to_string(), "https://example.com/a#top");
    }

    #[test]
    fn test_display_omits_default_ports() {
        // http:80, https:443, ftp:21 are all omitted by Display.
        let u1 = Url::parse("http://example.com:80/").unwrap();
        let u2 = Url::parse("https://example.com:443/").unwrap();
        assert_eq!(u1.to_string(), "http://example.com/");
        assert_eq!(u2.to_string(), "https://example.com/");
    }

    #[test]
    fn test_encode_all_bytes_roundtrip() {
        // Every byte that encode() touches should decode back to itself
        // (except control characters that cannot appear in a Rust &str
        // input — we test the subset of valid UTF-8 bytes).
        let input = "Hello, World! @#$%^&*()_+-={}[]|\\:;\"'<>,.?/`~";
        let encoded = encode(input);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, input, "encode→decode should round-trip printable ASCII");
    }

    #[test]
    fn test_encode_utf8() {
        // Non-ASCII UTF-8 is percent-encoded as its raw byte sequence.
        // "é" = 0xC3 0xA9 in UTF-8 → "%C3%A9".
        assert_eq!(encode("café"), "caf%C3%A9");
        // And decode recovers the original UTF-8 string.
        assert_eq!(decode("caf%C3%A9").unwrap(), "café");
    }

    #[test]
    fn test_decode_bad_utf8() {
        // `%FF` is a valid percent-escape but produces a byte that's not a
        // valid UTF-8 sequence on its own — should surface as an error.
        let result = decode("abc%FFxyz");
        assert!(matches!(result, Err(UrlError::Decode(_))));
    }

    #[test]
    fn test_url_error_to_net_error() {
        // From<UrlError> for NetError — required by the schema's
        // members_accessed contract.
        let url_err = UrlError::Parse("bad scheme".to_string());
        let net_err: NetError = url_err.into();
        assert!(matches!(net_err, NetError::Http(HttpError::Parse(_))));
    }

    #[test]
    fn test_url_error_decode_to_net_error() {
        let url_err = UrlError::Decode("truncated".to_string());
        let net_err: NetError = url_err.into();
        assert!(matches!(net_err, NetError::Http(HttpError::Parse(_))));
    }

    #[test]
    fn test_url_error_unknown_scheme_to_net_error() {
        let url_err = UrlError::UnknownScheme("gopher".to_string());
        let net_err: NetError = url_err.into();
        assert!(matches!(net_err, NetError::Http(HttpError::Parse(_))));
    }

    #[test]
    fn test_init_is_noop() {
        // `init()` is a no-op retained for API parity with FASM `url$init`.
        // Calling it multiple times must be safe.
        init();
        init();
        init();
    }

    #[test]
    fn test_user_data_roundtrip() {
        // set_user accepts any Arc<dyn Any + Send + Sync>; user() returns
        // the same Arc so downcast_ref recovers the concrete type.
        let mut url = Url::new();
        let payload: Arc<dyn Any + Send + Sync> = Arc::new(42_u64);
        url.set_user(payload);
        let got = url.user().unwrap();
        let recovered: &u64 = got.downcast_ref::<u64>().expect("downcast succeeds");
        assert_eq!(*recovered, 42);
    }

    #[test]
    fn test_user_data_ignored_by_partial_eq() {
        // Two URLs that differ ONLY in their opaque user-data payload
        // must still compare equal (FASM url$equals semantics).
        let mut a = Url::parse("http://example.com/").unwrap();
        let mut b = Url::parse("http://example.com/").unwrap();
        a.set_user(Arc::new(1_u32) as Arc<dyn Any + Send + Sync>);
        b.set_user(Arc::new("hello".to_string()) as Arc<dyn Any + Send + Sync>);
        assert_eq!(a, b);
    }

    #[test]
    fn test_debug_includes_all_fields_without_panicking() {
        // Debug must work on a URL with a user-data payload (the manual
        // Debug impl prints "<opaque>" for user, never attempting to
        // downcast).
        let mut url = Url::parse("http://example.com/").unwrap();
        url.set_user(Arc::new(vec![1_u8, 2, 3]) as Arc<dyn Any + Send + Sync>);
        let s = format!("{url:?}");
        assert!(s.contains("Url"));
        assert!(s.contains("opaque"));
    }

    #[test]
    fn test_clone_preserves_user_data() {
        // Clone increments the Arc refcount; both clones see the same
        // payload.
        let mut url = Url::parse("http://example.com/").unwrap();
        let payload: Arc<dyn Any + Send + Sync> = Arc::new(99_u64);
        url.set_user(payload);
        let cloned = url.clone();
        let got = cloned.user().unwrap();
        let recovered: &u64 = got.downcast_ref::<u64>().unwrap();
        assert_eq!(*recovered, 99);
    }

    #[test]
    fn test_parse_query_only_no_path() {
        // The `url` crate normalises "" path to "/" in the authority form.
        let u = Url::parse("http://example.com?x=1").unwrap();
        assert_eq!(u.path(), "/");
        assert_eq!(u.query(), "x=1");
        assert_eq!(u.file(), "/?x=1");
    }

    #[test]
    fn test_preface_no_port_no_default() {
        // Unknown scheme + explicit port → port is non-default so it's
        // always emitted.
        let mut url = Url::new();
        url.set_protocol("custom");
        url.set_host("h");
        url.set_port(1234);
        assert_eq!(url.preface(), "custom://h:1234");
    }

    #[test]
    fn test_authority_normalised_default_port() {
        // Explicit default port in the input → authority strips it to
        // just the host per RFC 3986 normalisation.
        let u = Url::parse("http://example.com:80/").unwrap();
        assert_eq!(u.authority(), "example.com");
    }
}
