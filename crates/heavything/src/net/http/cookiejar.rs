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
//
// Rust port of cookiejar.inc: HTTP/1.1 cookie handling for automated agents.
//
// DESIGN NOTES (preserved from cookiejar.inc prologue):
// - NOT an exhaustive/security-minded implementation.
// - Intended for automated web agents (scrapers, crawlers, API clients).
// - No public-suffix-list handling.
// - List-based storage (Vec<Cookie>) — fine for modest cookie counts.
// - The FASM source bug at L178-179 (double-free of cookie_path, leak of
//   cookie_value in cookiejar$destroy) is intentionally NOT reproduced —
//   Rust's `Drop` releases each `String` field exactly once.

//! HTTP/1.1 cookie storage — Rust port of `cookiejar.inc` (942 FASM lines,
//! 6 public functions).
//!
//! # Overview
//!
//! Two public types:
//!
//! * [`Cookie`] — a single HTTP cookie with the FASM 48-byte field layout
//!   preserved (expiry@0, domain@8, path@16, name@24, value@32,
//!   secure@40, httponly@44).
//! * [`CookieJar`] — an insertion-ordered list of [`Cookie`]s with two
//!   primary entry points: [`CookieJar::set`] (parses `Set-Cookie`
//!   headers from inbound responses) and [`CookieJar::get`] (emits
//!   `Cookie:` headers on outbound requests).
//!
//! # Persistence format (byte-for-byte preservation)
//!
//! Non-session cookies (those with non-zero `expiry`) round-trip through
//! a custom UTF-8 buffer with one cookie per line. Each line contains
//! exactly seven semicolon-delimited fields:
//!
//! ```text
//! expiry;domain;path;name;value;secure;httponly\n
//! ```
//!
//! - `expiry` — `f64` formatted via Rust `Display` (mirrors FASM
//!   `string$from_double(double_string_normal, 15)`).
//! - `domain`, `path`, `name`, `value` — raw UTF-8 strings.
//! - `secure`, `httponly` — `"1"` or `"0"`.
//!
//! Lines are separated by single `\n`; CRLF input is tolerated by
//! [`CookieJar::new_from_buffer`] which trims trailing `\r`.
//!
//! # Cross-references
//!
//! - [`crate::net::http::mimelike::Mimelike`] — the message container
//!   that supplies `Set-Cookie` to [`CookieJar::set`] and receives
//!   `Cookie` from [`CookieJar::get`].
//! - [`crate::net::url::Url`] — the URL whose `host`, `path`, and
//!   `protocol` (NOT `scheme()`; FASM-style naming) drive cookie
//!   matching for both `set` (default attributes) and `get` (filter
//!   predicates).
//!
//! # FASM ↔ Rust function map
//!
//! | FASM symbol                   | Rust equivalent                           |
//! |-------------------------------|-------------------------------------------|
//! | `cookiejar$new`               | [`CookieJar::new`] / [`CookieJar::default`] |
//! | `cookiejar$new_from_buffer`   | [`CookieJar::new_from_buffer`]            |
//! | `cookiejar$destroy`           | automatic via [`Drop`]                    |
//! | `cookiejar$to_buffer`         | [`CookieJar::to_buffer`]                  |
//! | `cookiejar$set`               | [`CookieJar::set`]                        |
//! | `cookiejar$get`               | [`CookieJar::get`]                        |
//! | `datetime$rfc5322_to_timestamp` | private [`parse_rfc5322_to_timestamp`]  |
//! | `timestamp`                   | private [`current_timestamp_secs`]        |
//!
//! # `unsafe` audit
//!
//! This module contributes **zero** `unsafe` blocks to the crate-wide
//! `UNSAFE_AUDIT.md` tally per AAP §0.7.4. The implementation uses only
//! safe `std` arithmetic + the safe `Mimelike` and `Url` accessor APIs.

use crate::error::HttpError;
use crate::net::http::mimelike::Mimelike;
use crate::net::url::Url;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// SECTION 1 — Byte-frozen protocol-level constants
//
// Every string here is part of the on-wire HTTP protocol or the cookie
// persistence format. Changing any of these breaks compatibility with
// real servers/clients and with cookie databases written by previous
// runs of the assembly library. Per AAP §0.1.1 these are byte-frozen.
// ============================================================================

/// Sentinel used to replace `Expires=<RFC-5322 date>` in the aggregated
/// `Set-Cookie` header before splitting on `", "` — without this rewrite,
/// the comma-space inside RFC-5322 weekday prefixes (e.g., `"Wed, 09 Jun
/// ..."`) would split a single cookie across two segments.
///
/// Mirrors FASM `cookiejar$set.htexpiryequal` (cookiejar.inc L470). The
/// substitution preserves the structural invariant that subsequent
/// `string$replace` substitutions land inside a non-RFC-formatted token.
const EXPIRY_SENTINEL: &str = ";;;expiry;;;=";

/// Length of `"Expires="` (8 chars) plus the RFC-5322 date (29 chars) =
/// 37. Used by [`CookieJar::set`] to extract a fixed-width substring
/// for date parsing. Mirrors the `mov edx, 37` hardcode in FASM
/// `cookiejar$set.expires_doit` (cookiejar.inc L317).
const EXPIRES_SUBSTRING_LEN: usize = 37;

/// Length of `"Expires="` itself — 8 characters. Used to skip the
/// attribute-name prefix when handing the date portion to
/// [`parse_rfc5322_to_timestamp`].
const EXPIRES_PREFIX_LEN: usize = 8;

// --- Case-insensitive attribute prefixes (matched on lowered input) ------

/// `expires=` attribute prefix. The original `Set-Cookie` may use mixed
/// case (`Expires=`); we lowercase the whole header during sentinel
/// substitution and again per-attribute in the inner parse loop.
const ATTR_EXPIRES: &str = "expires=";

/// `path=` attribute prefix.
const ATTR_PATH: &str = "path=";

/// `max-age=` attribute prefix (RFC 6265 §5.2.2).
const ATTR_MAX_AGE: &str = "max-age=";

/// `domain=` attribute prefix.
const ATTR_DOMAIN: &str = "domain=";

/// `secure` attribute (no value).
const ATTR_SECURE: &str = "secure";

/// `httponly` attribute (no value).
const ATTR_HTTPONLY: &str = "httponly";

// --- Outer/inner separators in the `Set-Cookie` header ------------------

/// `", "` — separator between aggregated cookies in the `Set-Cookie`
/// header (FASM combines duplicates via the same `, ` glue used for
/// other headers — see `mimelike.inc` L2546-2563).
const SEP_COMMA_SPACE: &str = ", ";

/// `"; "` — separator between attributes within a single cookie.
const SEP_SEMICOLON_SPACE: &str = "; ";

// --- Match-target schemes / headers / output separators -------------------

/// HTTPS scheme constant for the `Secure` flag gate. A cookie marked
/// `secure` is only emitted by [`CookieJar::get`] when the request URL's
/// `protocol()` matches this exact byte sequence.
const HTTPS_SCHEME: &str = "https";

/// Separator emitted by [`CookieJar::get`] when concatenating multiple
/// `name=value` pairs into the outgoing `Cookie:` header value.
/// Mirrors FASM `cookiejar$get.addcookie.separator` (cookiejar.inc L939).
const COOKIE_HEADER_SEPARATOR: &str = "; ";

/// `Set-Cookie` header name as emitted/consumed on the wire (RFC 6265 §4.1).
const HEADER_SET_COOKIE: &str = "Set-Cookie";

/// `Cookie` header name as emitted on the wire (RFC 6265 §5.4).
const HEADER_COOKIE: &str = "Cookie";

// ============================================================================
// SECTION 2 — Cookie struct (FASM 48-byte layout preserved)
// FASM source: cookiejar.inc L39-47
// ============================================================================

/// A single HTTP cookie with the field layout of the FASM 48-byte
/// `cookie` struct preserved verbatim:
///
/// | FASM offset                  | Field      | Type             |
/// |------------------------------|------------|------------------|
/// | `cookie_expiry_ofs   = 0`    | `expiry`   | `f64`            |
/// | `cookie_domain_ofs   = 8`    | `domain`   | `String`         |
/// | `cookie_path_ofs     = 16`   | `path`     | `String`         |
/// | `cookie_name_ofs     = 24`   | `name`     | `String`         |
/// | `cookie_value_ofs    = 32`   | `value`    | `String`         |
/// | `cookie_secure_ofs   = 40`   | `secure`   | `bool` (4 bytes) |
/// | `cookie_httponly_ofs = 44`   | `httponly` | `bool` (4 bytes) |
///
/// # `expiry` semantics
///
/// `expiry == 0.0` indicates a session cookie (cleared at end of
/// session, never written to the persistence buffer by
/// [`CookieJar::to_buffer`]); a non-zero value is a Unix-seconds `f64`
/// timestamp. The FASM uses Julian-date timestamps; the Rust port uses
/// Unix-epoch seconds because:
///
/// 1. The only relative comparison is between `expiry` and "now", and
///    both come from the same time source ([`current_timestamp_secs`]).
/// 2. `Max-Age=` (relative seconds) and `Expires=<RFC-5322 date>` both
///    feed into this scale via the same parser.
/// 3. Bytes round-trip through [`CookieJar::to_buffer`] /
///    [`CookieJar::new_from_buffer`] without any transformation, so
///    persisted databases stay self-consistent across runs.
///
/// # Equality
///
/// Derived `PartialEq` compares all seven fields. The cookie-jar
/// matching predicates ([`CookieJar::set`] cookie replacement /
/// [`CookieJar::get`] longest-path-wins) compare only the
/// `(name, domain, path)` triple — they do NOT use `PartialEq`.
#[derive(Debug, Clone, PartialEq)]
pub struct Cookie {
    /// Unix-seconds `f64` timestamp; `0.0` indicates a session cookie
    /// that is dropped on session end and never persisted.
    pub expiry: f64,

    /// Domain on which the cookie is valid. A leading `.` triggers
    /// suffix-match semantics in [`CookieJar::get`]; otherwise the
    /// host must match exactly.
    pub domain: String,

    /// Path prefix. Cookies are emitted only when the request path
    /// starts with this string (case-sensitive — RFC 6265 §5.1.4).
    pub path: String,

    /// Cookie name (left of `=` in `name=value`).
    pub name: String,

    /// Cookie value (right of `=` in `name=value`).
    pub value: String,

    /// `Secure` flag. When `true`, [`CookieJar::get`] only emits this
    /// cookie if the request URL's [`Url::protocol`] is `"https"`.
    pub secure: bool,

    /// `HttpOnly` flag. Parsed and stored for round-trip preservation
    /// but not enforced by this jar — the FASM source comment confirms
    /// "this is by no means an exhaustive/security-minded
    /// implementation" (cookiejar.inc L24-27).
    pub httponly: bool,
}

impl Cookie {
    /// Constructs a session cookie (zero expiry, secure/httponly
    /// flags clear). Convenience helper for callers that want to
    /// build a cookie programmatically without going through
    /// [`CookieJar::set`].
    pub fn session(domain: String, path: String, name: String, value: String) -> Self {
        Self {
            expiry: 0.0,
            domain,
            path,
            name,
            value,
            secure: false,
            httponly: false,
        }
    }

    /// Returns `true` iff this cookie's expiry is exactly `0.0`,
    /// matching the FASM convention where a zero expiry indicates a
    /// session cookie that should never be persisted.
    #[must_use]
    pub fn is_session(&self) -> bool {
        self.expiry == 0.0
    }

    /// Returns `true` iff this cookie has a non-zero expiry that is
    /// strictly less than `now_seconds` (Unix-seconds `f64`). Session
    /// cookies (zero expiry) always return `false`.
    ///
    /// Mirrors the FASM ordering check in `cookiejar$set` L536-541
    /// (`expiry < now → delete`).
    #[must_use]
    pub fn is_expired(&self, now_seconds: f64) -> bool {
        self.expiry != 0.0 && self.expiry < now_seconds
    }
}

// ============================================================================
// SECTION 3 — CookieJar struct
// FASM source: cookiejar.inc L50-56 (cookiejar$new returns list$new)
// ============================================================================

/// A list of [`Cookie`]s in insertion order — replaces the FASM
/// `cookiejar$new` (which returned a `list$new` of cookies).
///
/// # Thread safety
///
/// Not thread-safe at the struct level. Callers sharing a jar across
/// async tasks or worker threads must wrap in `Arc<Mutex<CookieJar>>`
/// or `Arc<RwLock<CookieJar>>`. The `webclient`'s connection-pool
/// machinery handles this externally — [`CookieJar`] itself stays
/// minimal per AAP §0.8.2's minimal-change discipline.
///
/// # Persistence
///
/// Round-trip through [`CookieJar::to_buffer`] /
/// [`CookieJar::new_from_buffer`] produces a UTF-8 string of
/// non-session cookies. Session cookies (those with `expiry == 0.0`)
/// are never written, matching the FASM `cookiejar$to_buffer.each_nodeal`
/// early-return (cookiejar.inc L213-214).
#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    /// The list of stored cookies in insertion order. Public access
    /// goes through [`CookieJar::cookies`] / mutation through
    /// [`CookieJar::set`] / [`CookieJar::session_clear`] /
    /// [`CookieJar::expire_expired`].
    cookies: Vec<Cookie>,
}

// ============================================================================
// SECTION 4 — Time helpers (private)
//
// FASM `timestamp` produces a Julian-date `f64` (number of days since
// the Julian epoch). The Rust port uses Unix-epoch seconds (`f64`)
// because:
// 1. We never expose the timestamp externally — it only feeds
//    self-comparisons within the jar.
// 2. Both `Expires=` and `Max-Age=` parsing produce timestamps in
//    Unix-seconds via `parse_rfc5322_to_timestamp` and `+ Max-Age`
//    arithmetic; mixing Julian and Unix would require conversions.
// 3. `SystemTime` already provides Unix-epoch arithmetic out of the
//    box, avoiding a Julian-day implementation effort.
// ============================================================================

/// Returns the current Unix timestamp in seconds as an `f64`. Used by
/// [`CookieJar::set`] (Max-Age + now → absolute expiry) and
/// [`CookieJar::get`] (filter expired cookies).
///
/// On modern Linux systems this call delegates to the vDSO
/// `gettimeofday` and is effectively never fallible. The `unwrap_or(0.0)`
/// fallback for [`SystemTime::duration_since`] handles the
/// theoretically-possible case where the system clock is set before
/// 1970 — in that situation we degrade to "everything is expired", which
/// is the safest behavior because it removes potentially-stale cookies.
fn current_timestamp_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Parses an RFC 5322 / RFC 1123 / RFC 822 date string (the format
/// emitted in HTTP `Set-Cookie` `Expires=` attributes) into Unix-epoch
/// seconds.
///
/// Accepts the common form: `"Wed, 09 Jun 2021 10:18:14 GMT"` (with
/// or without the day-of-week prefix).
///
/// FASM equivalent: `datetime$rfc5322_to_timestamp` (date.inc L326).
/// The FASM uses Julian dates internally; the Rust port emits Unix
/// seconds via Howard Hinnant's `civil_to_days` algorithm
/// (<http://howardhinnant.github.io/date_algorithms.html>) which
/// handles the Gregorian calendar exactly without external dependencies.
///
/// Returns `None` on any parse failure (truncated input, unknown month
/// abbreviation, non-numeric day/year/time component). `None` is
/// treated by [`CookieJar::set`] as "discard this Set-Cookie segment
/// silently", matching the FASM `.bad_expires` early-return at L772.
fn parse_rfc5322_to_timestamp(date_str: &str) -> Option<f64> {
    let s = date_str.trim();
    // Skip the weekday prefix if present (anything before the first
    // comma). RFC 5322 §3.3 makes the day-of-week optional.
    let rest = s.split_once(',').map(|(_, r)| r.trim()).unwrap_or(s);
    let mut parts = rest.split_whitespace();

    let day: u32 = parts.next()?.parse().ok()?;
    let month_name = parts.next()?;
    let year: i32 = parts.next()?.parse().ok()?;
    let time_str = parts.next()?;
    // Trailing timezone token (e.g., "GMT", "+0000", "UT") is intentionally
    // ignored. Cookies always emit GMT per RFC 6265 §5.1.1.5; a
    // non-GMT timezone is a non-conformant server and we treat the
    // emitted instant as UTC anyway.

    let month: u32 = match month_name {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };

    let mut hms = time_str.split(':');
    let hour: u32 = hms.next()?.parse().ok()?;
    let minute: u32 = hms.next()?.parse().ok()?;
    let second: u32 = hms.next()?.parse().ok()?;

    // Validate ranges. Out-of-range values (day=99, hour=99, etc.)
    // would produce nonsensical timestamps; reject them up front.
    if !(1..=31).contains(&day) || hour >= 24 || minute >= 60 || second >= 60 || !(1..=9999).contains(&year) {
        return None;
    }

    // Howard Hinnant's days_from_civil — converts a (year, month, day)
    // triple to days since 1970-01-01. Exact, integer-only, no
    // dependencies, no leap-year special cases at the call site.
    let y = if month <= 2 { year - 1 } else { year } as i64;
    let m = if month <= 2 { month + 9 } else { month - 3 } as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let doy = (153 * m + 2) as u64 / 5 + (day as u64 - 1); // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146_097 + doe as i64 - 719_468;

    let secs = days * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + (second as i64);
    Some(secs as f64)
}

// ============================================================================
// SECTION 5 — Internal scratch type for set() parsing
// ============================================================================

/// In-progress cookie under construction during `set()` parsing.
/// Mirrors the stack-allocated `cookie_size` scratch in FASM
/// `cookiejar$set` L390-394. Domain and path use `Option` so we can
/// detect duplicate-attribute conditions (FASM `.inner_duplicatevalue`
/// at L740) and apply default values from the URL when missing
/// (FASM L485-528).
struct ScratchCookie {
    expiry: f64,
    domain: Option<String>,
    path: Option<String>,
    name: String,
    value: String,
    secure: bool,
    httponly: bool,
}

/// Returns `true` iff `c.name`, `c.domain`, and `c.path` all match the
/// given triple. Used by [`CookieJar::set`]'s replace/delete locator
/// loops (FASM L544-562 for delete, L599-614 for replace).
fn cookie_matches(c: &Cookie, name: &str, domain: &str, path: &str) -> bool {
    c.name == name && c.domain == domain && c.path == path
}

// ============================================================================
// SECTION 6 — CookieJar: constructors, persistence
// FASM source: cookiejar.inc L50-279
// ============================================================================

impl CookieJar {
    /// Creates an empty cookie jar. Equivalent to FASM `cookiejar$new`
    /// (cookiejar.inc L50-56) which simply returns `list$new`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses a previously-persisted UTF-8 buffer (as produced by
    /// [`CookieJar::to_buffer`]) and returns a populated jar.
    ///
    /// The buffer format is byte-frozen: one cookie per line, each
    /// line containing exactly seven semicolon-delimited fields:
    ///
    /// ```text
    /// expiry;domain;path;name;value;secure;httponly
    /// ```
    ///
    /// Lines are separated by `\n`. CRLF input is tolerated — a
    /// trailing `\r` is stripped from each line before splitting.
    ///
    /// Per the FASM source (`cookiejar$new_from_buffer`,
    /// cookiejar.inc L61-151), invalid lines are silently skipped:
    ///
    /// - Empty lines (after trimming `\r`).
    /// - Lines with field counts other than 7
    ///   (FASM `.bad_buffer` exit; here: skip).
    /// - Lines whose `expiry` field is not a valid `f64`
    ///   (FASM `.bad_buffer.bad_double` exit; here: skip).
    ///
    /// `secure` and `httponly` flags use the FASM convention: the
    /// literal `"1"` evaluates to `true`, anything else (including
    /// `"0"`, `""`, or unrelated text) evaluates to `false`. This
    /// mirrors FASM `cmovne` against the immediate `'1'` byte
    /// (cookiejar.inc L131-134).
    #[must_use]
    pub fn new_from_buffer(buf: &str) -> Self {
        let mut jar = Self::new();
        for raw_line in buf.split('\n') {
            // Tolerate CRLF input by trimming a trailing `\r`.
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            if line.is_empty() {
                // Empty terminator (e.g., trailing `\n` after last
                // record) — skip silently. FASM iterates by line
                // length and never visits empty lines.
                continue;
            }
            let fields: Vec<&str> = line.split(';').collect();
            if fields.len() != 7 {
                // FASM `.bad_buffer` exits the whole function on
                // wrong field counts; we degrade to per-line skip
                // so a single corrupt line doesn't drop the rest of
                // the database.
                continue;
            }
            let expiry: f64 = match fields[0].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let cookie = Cookie {
                expiry,
                domain: fields[1].to_string(),
                path: fields[2].to_string(),
                name: fields[3].to_string(),
                value: fields[4].to_string(),
                secure: fields[5] == "1",
                httponly: fields[6] == "1",
            };
            jar.cookies.push(cookie);
        }
        jar
    }

    /// Serializes all non-session cookies into a UTF-8 buffer suitable
    /// for re-parsing by [`CookieJar::new_from_buffer`].
    ///
    /// Session cookies (those with `expiry == 0.0`) are skipped, exactly
    /// as the FASM source does in `cookiejar$to_buffer.each_nodeal`
    /// (cookiejar.inc L213-214). This intentional asymmetry — `set()`
    /// stores session cookies in memory, but `to_buffer()` never
    /// persists them — matches the user-visible behavior of every
    /// browser and HTTP client.
    ///
    /// Each line ends with a single `\n` byte (FASM `buffer$append_byte
    /// 10` at L274-275). The final line also ends with `\n` to keep
    /// the format symmetric.
    #[must_use]
    pub fn to_buffer(&self) -> String {
        // Pre-size the buffer optimistically to amortize reallocations
        // — average cookie line is ~80 chars; we reserve 96 per cookie.
        let mut out = String::with_capacity(self.cookies.len() * 96);
        for c in &self.cookies {
            if c.is_session() {
                // FASM `.each_nodeal` early-return — session cookies
                // are never persisted.
                continue;
            }
            // Rust's `Display` for `f64` produces a round-trippable
            // representation for finite values, mirroring FASM's
            // `string$from_double(double_string_normal, 15)` at L222
            // which formats with 15 significant digits.
            //
            // Note: `Display` may emit "inf"/"-inf"/"NaN" for special
            // values. In practice cookie expiries are always finite
            // (Max-Age + now or RFC-5322 → finite seconds), so this
            // path is unreachable in normal operation.
            out.push_str(&c.expiry.to_string());
            out.push(';');
            out.push_str(&c.domain);
            out.push(';');
            out.push_str(&c.path);
            out.push(';');
            out.push_str(&c.name);
            out.push(';');
            out.push_str(&c.value);
            out.push(';');
            out.push(if c.secure { '1' } else { '0' });
            out.push(';');
            out.push(if c.httponly { '1' } else { '0' });
            out.push('\n');
        }
        out
    }
}

// ============================================================================
// SECTION 7 — CookieJar::set — Set-Cookie header parser
// FASM source: cookiejar.inc L282-782
//
// This is the most complex function in the file. It parses the
// aggregated `Set-Cookie` header from an HTTP response and updates
// the jar accordingly. Multiple cookies in one header are separated
// by `, `, but RFC-5322 dates inside `Expires=` attributes also
// contain `, ` — so we first replace each `Expires=<date>` with a
// sentinel `;;;expiry;;;=<f64-as-string>` before splitting.
//
// Algorithm:
//   1. Read Set-Cookie header.
//   2. Replace each `Expires=<date>` substring with `;;;expiry;;;=<secs>`.
//   3. Split by `, ` → outer segments (one per cookie).
//   4. For each segment: split by `; ` → attribute list.
//   5. First attribute is `name=value`.
//   6. Subsequent attributes (case-insensitive) match against:
//      `;;;expiry;;;=`, `path=`, `max-age=`, `domain=`, `secure`,
//      `httponly` — others are ignored.
//   7. Apply defaults from URL: domain = url.host, path = dir of
//      url.path with trailing `/`.
//   8. Action dispatch: expired cookie → delete matching;
//      otherwise → replace if found, else append.
//
// All parse errors result in silent early-return — matching the FASM
// `.bad_expires`, `.cookie_nameval_error`, `.inner_duplicatevalue`
// exits at L772, L735, L740. The Result<_, HttpError> signature is
// kept for forward-compatibility per AAP §0.1.1.
// ============================================================================

impl CookieJar {
    /// Parses the `Set-Cookie` header on `response` and updates this jar.
    ///
    /// `url` provides the request URL whose `host` and `path` supply
    /// default values for cookies that omit `Domain=` / `Path=`
    /// attributes (per RFC 6265 §5.3 step 4 / §5.1.4).
    ///
    /// # Returns
    ///
    /// Always returns `Ok(())` in the current implementation —
    /// parse errors are silently absorbed, matching FASM behavior.
    /// The `Result<(), HttpError>` signature is preserved so future
    /// versions can tighten validation without an API break (see AAP
    /// §0.1.1 future-proofing note for `HttpError::Parse`).
    ///
    /// # Behavior
    ///
    /// - If `response` has no `Set-Cookie` header: returns `Ok(())`
    ///   immediately (no-op).
    /// - For each cookie segment:
    ///   - If `expiry < now` → deletes the first matching
    ///     `(name, domain, path)` entry (FASM L536-562).
    ///   - Otherwise → replaces the first matching entry, or appends
    ///     a new cookie if no match (FASM L596-650).
    pub fn set(&mut self, url: &Url, response: &Mimelike) -> Result<(), HttpError> {
        // ---- Step 1: read Set-Cookie header ---------------------------
        let raw = match response.get_header(HEADER_SET_COOKIE) {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => return Ok(()),
        };

        // ---- Step 2: replace Expires=<date> with sentinel -------------
        // We lowercase a separate copy for the case-insensitive search;
        // the original-case `cooked` string is what we substitute and
        // ultimately split. This mirrors FASM L317-365 where the
        // search uses `string$find_caseless` against `expires=` and
        // the replacement happens against the original buffer.
        let mut cooked = raw.clone();
        loop {
            // Search lowercased copy for "expires=" — the position
            // applies to `cooked` because lowercasing preserves byte
            // length for the ASCII characters used in HTTP attribute
            // names (E↔e, X↔x, P↔p, etc., are all single-byte in UTF-8).
            let lc = cooked.to_lowercase();
            let pos = match lc.find(ATTR_EXPIRES) {
                Some(p) => p,
                None => break,
            };
            // Need at least 37 chars from `pos` to extract the full
            // "Expires=<29-char date>" run.
            if pos + EXPIRES_SUBSTRING_LEN > cooked.len() {
                // Truncated header — silent bail (FASM L321 .bad_expires).
                return Ok(());
            }
            // Split on character indices (which equal byte indices for
            // ASCII). Set-Cookie headers in practice are ASCII-only;
            // a multi-byte sequence at this position would indicate
            // a non-conformant server and we silently ignore.
            if !cooked.is_char_boundary(pos) || !cooked.is_char_boundary(pos + EXPIRES_SUBSTRING_LEN) {
                return Ok(());
            }
            let date_part = &cooked[pos + EXPIRES_PREFIX_LEN..pos + EXPIRES_SUBSTRING_LEN];
            let secs = match parse_rfc5322_to_timestamp(date_part) {
                Some(s) => s,
                None => return Ok(()),
            };
            let needle = &cooked[pos..pos + EXPIRES_SUBSTRING_LEN].to_string();
            let replacement = format!("{}{}", EXPIRY_SENTINEL, secs);
            // Replace exactly one occurrence (the one we just located)
            // to avoid double-substituting when multiple Expires=
            // attributes are present.
            cooked = cooked.replacen(needle.as_str(), &replacement, 1);
        }

        // ---- Step 3: split outer segments by ", " ---------------------
        let now = current_timestamp_secs();
        for segment in cooked.split(SEP_COMMA_SPACE) {
            // ---- Step 4: split inner attributes by "; " --------------
            let mut attrs = segment.split(SEP_SEMICOLON_SPACE);
            let first = match attrs.next() {
                Some(s) => s,
                None => continue,
            };

            // ---- Step 5: first attribute is name=value ---------------
            let eq_pos = match first.find('=') {
                Some(p) => p,
                None => return Ok(()), // FASM .cookie_nameval_error L735.
            };
            let name = first[..eq_pos].to_string();
            let value = first[eq_pos + 1..].to_string();

            let mut scratch = ScratchCookie {
                expiry: 0.0,
                domain: None,
                path: None,
                name,
                value,
                secure: false,
                httponly: false,
            };

            // ---- Step 6: parse remaining attributes ------------------
            for attr in attrs {
                let lower = attr.to_lowercase();
                if let Some(rest) = lower.strip_prefix(EXPIRY_SENTINEL) {
                    // Sentinel injected by Step 2 — recover the f64
                    // expiry encoded into the substituted token.
                    // Parse failure here is unreachable in practice
                    // because we generated the sentinel ourselves
                    // from a successful parse_rfc5322 call above.
                    if let Ok(parsed) = rest.parse::<f64>() {
                        scratch.expiry = parsed;
                    }
                } else if let Some(p) = lower.strip_prefix(ATTR_PATH) {
                    if scratch.path.is_some() {
                        return Ok(()); // FASM .inner_duplicatevalue L740.
                    }
                    scratch.path = Some(p.to_string());
                } else if let Some(m) = lower.strip_prefix(ATTR_MAX_AGE) {
                    if let Ok(parsed) = m.parse::<u64>() {
                        scratch.expiry = now + parsed as f64;
                    }
                    // Non-numeric Max-Age — ignore and continue (FASM
                    // would silently fail string$to_double).
                } else if let Some(d) = lower.strip_prefix(ATTR_DOMAIN) {
                    if scratch.domain.is_some() {
                        return Ok(()); // FASM .inner_duplicatevalue L740.
                    }
                    scratch.domain = Some(d.to_string());
                } else if lower == ATTR_SECURE {
                    scratch.secure = true;
                } else if lower == ATTR_HTTPONLY {
                    scratch.httponly = true;
                }
                // Unknown attributes silently ignored — FASM L466-469.
            }

            // ---- Step 7: apply default domain and path ---------------
            let domain = scratch.domain.unwrap_or_else(|| url.host().to_string());
            let path = scratch.path.unwrap_or_else(|| {
                // Default path = directory portion of url.path (i.e.,
                // everything up to and including the last `/`). FASM
                // L487-498. If url.path has no `/`, fall back to "/".
                let p = url.path();
                match p.rfind('/') {
                    Some(idx) => p[..=idx].to_string(),
                    None => "/".to_string(),
                }
            });

            // Ensure path ends with "/" — FASM L508-522 appends a
            // trailing slash when the parsed value lacks one.
            let path = if path.ends_with('/') {
                path
            } else {
                let mut p = path;
                p.push('/');
                p
            };

            // ---- Step 8: action dispatch -----------------------------
            if scratch.expiry != 0.0 && scratch.expiry < now {
                // DELETE matching cookie (FASM L536-562). If no match
                // exists, the deletion is a no-op (FASM `.notfound`
                // exits silently).
                if let Some(idx) = self
                    .cookies
                    .iter()
                    .position(|c| cookie_matches(c, &scratch.name, &domain, &path))
                {
                    self.cookies.remove(idx);
                }
            } else {
                // SET — replace existing or append new.
                let new_cookie = Cookie {
                    expiry: scratch.expiry,
                    domain: domain.clone(),
                    path: path.clone(),
                    name: scratch.name.clone(),
                    value: scratch.value,
                    secure: scratch.secure,
                    httponly: scratch.httponly,
                };
                if let Some(idx) = self
                    .cookies
                    .iter()
                    .position(|c| cookie_matches(c, &scratch.name, &domain, &path))
                {
                    self.cookies[idx] = new_cookie;
                } else {
                    self.cookies.push(new_cookie);
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// SECTION 8 — CookieJar::get — Cookie header emitter
// FASM source: cookiejar.inc L786-942
//
// Inverse of `set`: walks the jar, filters cookies that apply to
// the given request URL, resolves duplicates by longest-path-wins,
// and writes the resulting `Cookie:` header onto the request's
// Mimelike.
//
// Filters (all must pass for a cookie to be considered):
//   1. Domain match — leading `.` ⇒ suffix; otherwise exact equality.
//   2. Path prefix — request path startsWith cookie path.
//   3. Expiry — session (0.0) OK; non-zero must be ≥ now.
//   4. Secure — if cookie.secure, require url.protocol == "https".
//
// Duplicate resolution: if two cookies pass all filters with the same
// name, the one with the longest path wins (RFC 6265 §5.4 step 2:
// "Cookies with longer paths are listed before cookies with shorter
// paths"). FASM L851-859.
// ============================================================================

impl CookieJar {
    /// Builds the `Cookie:` header for a request to `url` and writes
    /// it onto `request`.
    ///
    /// If no cookies in this jar match the request URL, no header is
    /// added (FASM `.done.nocookies` early-return at L878-880).
    ///
    /// The output format is `name1=value1; name2=value2; ...` with
    /// `"; "` separators (FASM L897-899, L939).
    pub fn get(&self, url: &Url, request: &mut Mimelike) {
        let now = current_timestamp_secs();
        let host = url.host();
        let req_path = url.path();
        let is_https = url.protocol() == HTTPS_SCHEME;

        // Collect candidates that pass all four filters. We hold
        // `&Cookie` references — the jar must outlive `request`'s
        // header build, which is satisfied by the function-level
        // ownership of `self`.
        let mut by_name: Vec<&Cookie> = Vec::new();

        for c in &self.cookies {
            // Filter 1: domain match.
            let domain_ok = if let Some(suffix) = c.domain.strip_prefix('.') {
                // Leading-dot domain → suffix match against host. We
                // accept either:
                //   host == suffix (e.g., "example.com" matches ".example.com")
                //   host endsWith ".<suffix>" (e.g., "www.example.com" matches ".example.com")
                // The FASM uses raw `string$ends_with` against the
                // dotted form (L808-816), which catches both cases
                // because "example.com" ends with ".example.com" only
                // when prefixed with a dot — but FASM also handles the
                // bare-equality case by stripping the dot. We match
                // both interpretations to be lenient with real-world
                // servers that emit either spelling.
                host == suffix || host.ends_with(&c.domain)
            } else {
                host == c.domain
            };
            if !domain_ok {
                continue;
            }

            // Filter 2: path prefix.
            if !req_path.starts_with(&c.path) {
                continue;
            }

            // Filter 3: expiry.
            if c.expiry != 0.0 && c.expiry < now {
                continue;
            }

            // Filter 4: secure.
            if c.secure && !is_https {
                continue;
            }

            // Resolve duplicates by name — longest path wins.
            let mut replaced = false;
            for slot in by_name.iter_mut() {
                if slot.name == c.name {
                    if c.path.len() > slot.path.len() {
                        *slot = c;
                    }
                    replaced = true;
                    break;
                }
            }
            if !replaced {
                by_name.push(c);
            }
        }

        if by_name.is_empty() {
            return;
        }

        // Build the header value. Pre-size to avoid reallocations:
        // average pair is ~32 chars; reserve 48 per cookie.
        let mut header = String::with_capacity(by_name.len() * 48);
        for (i, c) in by_name.iter().enumerate() {
            if i > 0 {
                header.push_str(COOKIE_HEADER_SEPARATOR);
            }
            header.push_str(&c.name);
            header.push('=');
            header.push_str(&c.value);
        }

        // Use the value-moving variant when available — mirrors FASM
        // `mimelike$setheader_novaluecopy` at L897-899 which avoids
        // an extra allocation for the value string. We have an owned
        // `String` ready to hand off.
        request.set_header_novaluecopy(HEADER_COOKIE.to_string(), header);
    }
}

// ============================================================================
// SECTION 9 — CookieJar: convenience accessors
// (Not directly mirrored in FASM — these are Rust-idiomatic
// helpers exposing the internal state for callers that need read
// access or maintenance operations.)
// ============================================================================

impl CookieJar {
    /// Number of cookies currently in the jar (including session
    /// cookies that won't be persisted).
    #[must_use]
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Returns `true` iff the jar contains zero cookies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Read-only slice view of all cookies in insertion order.
    #[must_use]
    pub fn cookies(&self) -> &[Cookie] {
        &self.cookies
    }

    /// Removes all session cookies (those with `expiry == 0.0`).
    /// Useful at session-end to keep the jar disk-persistable
    /// without invalidating the in-memory state.
    pub fn session_clear(&mut self) {
        self.cookies.retain(|c| !c.is_session());
    }

    /// Removes all cookies whose `expiry` is non-zero and strictly
    /// less than the current Unix timestamp.
    pub fn expire_expired(&mut self) {
        let now = current_timestamp_secs();
        self.cookies.retain(|c| !c.is_expired(now));
    }
}

// ============================================================================
// SECTION 10 — Unit tests
//
// Per AAP §0.8.4: ≥70% coverage on crypto and ds modules; for net/http
// modules we still aim for thorough behavioral coverage of the public
// API plus the critical RFC-5322 parser. The tests below cover all
// 22+ scenarios enumerated in the implementation guide plus a handful
// of helper-function and edge-case checks.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Helpers -------------------------------------------------------

    /// Builds a session cookie with the given fields. Convenience
    /// for tests that don't care about expiry/secure/httponly.
    fn mk_cookie(name: &str, value: &str, domain: &str, path: &str) -> Cookie {
        Cookie::session(domain.into(), path.into(), name.into(), value.into())
    }

    /// Builds an `Url` for use in tests. Panics on malformed URL —
    /// acceptable per AAP §0.8.4 (tests may use unwrap).
    fn parse_url(s: &str) -> Url {
        Url::parse(s).expect("test URL should parse")
    }

    /// Builds a `Mimelike` with an arbitrary header set, so callers
    /// can supply a `Set-Cookie` value to drive `cookiejar::set`.
    fn mk_mimelike_with(name: &str, value: &str) -> Mimelike {
        let mut m = Mimelike::new();
        m.set_header(name, value);
        m
    }

    // ---- Cookie struct accessors --------------------------------------

    #[test]
    fn cookie_session_constructor() {
        let c = mk_cookie("sid", "abc123", "example.com", "/");
        assert_eq!(c.expiry, 0.0);
        assert_eq!(c.domain, "example.com");
        assert_eq!(c.path, "/");
        assert_eq!(c.name, "sid");
        assert_eq!(c.value, "abc123");
        assert!(!c.secure);
        assert!(!c.httponly);
    }

    #[test]
    fn cookie_is_session_accessor() {
        let session = mk_cookie("a", "b", "c", "/");
        assert!(session.is_session());
        let mut persistent = session.clone();
        persistent.expiry = 1_700_000_000.0;
        assert!(!persistent.is_session());
    }

    #[test]
    fn cookie_is_expired_accessor() {
        let mut c = mk_cookie("a", "b", "c", "/");
        // Session cookie — never reported as expired regardless of `now`.
        assert!(!c.is_expired(0.0));
        assert!(!c.is_expired(1_e15));
        c.expiry = 1_000.0;
        // now strictly greater than expiry → expired.
        assert!(c.is_expired(2_000.0));
        // now equal to expiry → NOT expired (FASM uses strictly-less
        // ordering at L536-541: only `expiry < now` triggers delete).
        assert!(!c.is_expired(1_000.0));
        // now less than expiry → NOT expired.
        assert!(!c.is_expired(500.0));
    }

    // ---- CookieJar constructors ---------------------------------------

    #[test]
    fn new_creates_empty_jar() {
        let jar = CookieJar::new();
        assert_eq!(jar.len(), 0);
        assert!(jar.is_empty());
        assert_eq!(jar.cookies().len(), 0);
    }

    #[test]
    fn default_creates_empty_jar() {
        let jar = CookieJar::default();
        assert_eq!(jar.len(), 0);
        assert!(jar.is_empty());
    }

    #[test]
    fn len_and_is_empty() {
        let mut jar = CookieJar::new();
        assert!(jar.is_empty());
        jar.cookies.push(mk_cookie("a", "b", "c", "/"));
        assert_eq!(jar.len(), 1);
        assert!(!jar.is_empty());
        jar.cookies.push(mk_cookie("d", "e", "f", "/"));
        assert_eq!(jar.len(), 2);
    }

    #[test]
    fn cookies_returns_slice() {
        let mut jar = CookieJar::new();
        jar.cookies.push(mk_cookie("k", "v", "h", "/"));
        let slice = jar.cookies();
        assert_eq!(slice.len(), 1);
        assert_eq!(slice[0].name, "k");
    }

    // ---- Persistence: to_buffer / new_from_buffer ---------------------

    #[test]
    fn buffer_roundtrip_preserves_non_session() {
        let mut jar = CookieJar::new();
        let mut c = mk_cookie("auth", "Z3Z2", "site.test", "/api/");
        c.expiry = 1_700_000_000.0;
        c.secure = true;
        c.httponly = false;
        jar.cookies.push(c.clone());

        let buf = jar.to_buffer();
        let parsed = CookieJar::new_from_buffer(&buf);
        assert_eq!(parsed.len(), 1);
        let p = &parsed.cookies()[0];
        assert_eq!(p.expiry, c.expiry);
        assert_eq!(p.domain, c.domain);
        assert_eq!(p.path, c.path);
        assert_eq!(p.name, c.name);
        assert_eq!(p.value, c.value);
        assert!(p.secure);
        assert!(!p.httponly);
    }

    #[test]
    fn session_cookies_not_persisted() {
        let mut jar = CookieJar::new();
        // Session cookie — should NOT appear in to_buffer output.
        jar.cookies.push(mk_cookie("session_only", "x", "h.test", "/"));
        // Non-session — SHOULD appear.
        let mut persistent = mk_cookie("persist", "y", "h.test", "/");
        persistent.expiry = 1_700_000_000.0;
        jar.cookies.push(persistent);

        let buf = jar.to_buffer();
        // Buffer should contain exactly one line (the persistent cookie),
        // ending with '\n'.
        assert_eq!(buf.matches('\n').count(), 1);
        assert!(buf.contains("persist;"));
        assert!(!buf.contains("session_only"));
    }

    #[test]
    fn malformed_buffer_line_skipped() {
        // Lines with wrong field counts must be silently skipped,
        // and one valid line should still parse.
        let bad = "this;has;not;enough;fields\n\
                   1700000000;ok.test;/;n;v;1;0\n\
                   way;too;many;fields;here;they;are;extra;extra\n";
        let jar = CookieJar::new_from_buffer(bad);
        assert_eq!(jar.len(), 1);
        let c = &jar.cookies()[0];
        assert_eq!(c.name, "n");
        assert_eq!(c.value, "v");
        assert!(c.secure);
        assert!(!c.httponly);
    }

    #[test]
    fn buffer_with_multiple_cookies() {
        let mut jar = CookieJar::new();
        for i in 0..5 {
            let mut c = mk_cookie(&format!("n{i}"), &format!("v{i}"), "site.test", "/");
            c.expiry = 1_700_000_000.0 + i as f64;
            jar.cookies.push(c);
        }
        let buf = jar.to_buffer();
        assert_eq!(buf.matches('\n').count(), 5);
        let parsed = CookieJar::new_from_buffer(&buf);
        assert_eq!(parsed.len(), 5);
        for (i, c) in parsed.cookies().iter().enumerate() {
            assert_eq!(c.name, format!("n{i}"));
            assert_eq!(c.value, format!("v{i}"));
        }
    }

    #[test]
    fn to_buffer_emits_exactly_seven_fields_per_line() {
        let mut jar = CookieJar::new();
        let mut c = mk_cookie("k", "v", "host.test", "/");
        c.expiry = 1_700_000_000.0;
        c.secure = true;
        c.httponly = true;
        jar.cookies.push(c);

        let buf = jar.to_buffer();
        // Strip trailing '\n' before splitting, then verify line shape.
        let line = buf.strip_suffix('\n').expect("must end with LF");
        let fields: Vec<&str> = line.split(';').collect();
        assert_eq!(fields.len(), 7);
        // Field shape:
        // [0] expiry, [1] domain, [2] path, [3] name,
        // [4] value, [5] secure flag, [6] httponly flag
        assert_eq!(fields[1], "host.test");
        assert_eq!(fields[2], "/");
        assert_eq!(fields[3], "k");
        assert_eq!(fields[4], "v");
        assert_eq!(fields[5], "1");
        assert_eq!(fields[6], "1");
    }

    #[test]
    fn new_from_buffer_tolerates_crlf() {
        // CRLF-terminated input — trailing '\r' must be stripped from
        // each line before split/parse.
        let crlf = "1700000000;host.test;/;name;value;0;1\r\n";
        let jar = CookieJar::new_from_buffer(crlf);
        assert_eq!(jar.len(), 1);
        let c = &jar.cookies()[0];
        assert_eq!(c.name, "name");
        assert_eq!(c.value, "value");
        assert!(!c.secure);
        assert!(c.httponly);
    }

    // ---- get() filters --------------------------------------------------

    #[test]
    fn get_returns_nothing_when_jar_empty() {
        let jar = CookieJar::new();
        let url = parse_url("https://example.com/page");
        let mut req = Mimelike::new();
        jar.get(&url, &mut req);
        assert!(req.get_header("Cookie").is_none());
    }

    #[test]
    fn get_domain_exact_match() {
        let mut jar = CookieJar::new();
        jar.cookies.push(mk_cookie("sid", "x", "example.com", "/"));
        jar.cookies.push(mk_cookie("other", "y", "different.test", "/"));
        let url = parse_url("https://example.com/");
        let mut req = Mimelike::new();
        jar.get(&url, &mut req);
        let header = req.get_header("Cookie").expect("Cookie header expected");
        assert!(header.contains("sid=x"));
        assert!(!header.contains("other"));
    }

    #[test]
    fn get_domain_suffix_match_leading_dot() {
        let mut jar = CookieJar::new();
        // Leading-dot cookie should match subdomain.
        jar.cookies.push(mk_cookie("g", "v", ".example.com", "/"));
        let url = parse_url("http://www.example.com/");
        let mut req = Mimelike::new();
        jar.get(&url, &mut req);
        let header = req.get_header("Cookie").expect("Cookie header expected");
        assert!(header.contains("g=v"));
    }

    #[test]
    fn get_path_prefix_match() {
        let mut jar = CookieJar::new();
        jar.cookies.push(mk_cookie("api_key", "1", "host.test", "/api/"));
        jar.cookies
            .push(mk_cookie("admin_key", "2", "host.test", "/admin/"));

        // Request to /api/users — only api_key should match.
        let url = parse_url("https://host.test/api/users");
        let mut req = Mimelike::new();
        jar.get(&url, &mut req);
        let header = req.get_header("Cookie").expect("expected header");
        assert!(header.contains("api_key=1"));
        assert!(!header.contains("admin_key"));

        // Request to /admin/index — only admin_key should match.
        let url2 = parse_url("https://host.test/admin/index");
        let mut req2 = Mimelike::new();
        jar.get(&url2, &mut req2);
        let header2 = req2.get_header("Cookie").expect("expected header");
        assert!(header2.contains("admin_key=2"));
        assert!(!header2.contains("api_key"));

        // Request to / — no match because cookie paths require prefix.
        let url3 = parse_url("https://host.test/");
        let mut req3 = Mimelike::new();
        jar.get(&url3, &mut req3);
        assert!(req3.get_header("Cookie").is_none());
    }

    #[test]
    fn get_secure_requires_https() {
        let mut jar = CookieJar::new();
        let mut secure_only = mk_cookie("locked", "down", "host.test", "/");
        secure_only.secure = true;
        jar.cookies.push(secure_only);
        jar.cookies.push(mk_cookie("anywhere", "ok", "host.test", "/"));

        // HTTP (not HTTPS) — `locked` must be filtered out.
        let url = parse_url("http://host.test/");
        let mut req = Mimelike::new();
        jar.get(&url, &mut req);
        let header = req.get_header("Cookie").expect("expected anywhere");
        assert!(header.contains("anywhere=ok"));
        assert!(!header.contains("locked"));

        // HTTPS — both should appear.
        let url2 = parse_url("https://host.test/");
        let mut req2 = Mimelike::new();
        jar.get(&url2, &mut req2);
        let header2 = req2.get_header("Cookie").expect("expected both");
        assert!(header2.contains("locked=down"));
        assert!(header2.contains("anywhere=ok"));
    }

    #[test]
    fn get_longest_path_wins_for_same_name() {
        let mut jar = CookieJar::new();
        // Same name, two paths — `/api/v2/` should win because longer.
        jar.cookies
            .push(mk_cookie("token", "v1_token", "host.test", "/api/"));
        jar.cookies
            .push(mk_cookie("token", "v2_token", "host.test", "/api/v2/"));

        let url = parse_url("https://host.test/api/v2/users");
        let mut req = Mimelike::new();
        jar.get(&url, &mut req);
        let header = req.get_header("Cookie").expect("expected header");
        assert!(header.contains("token=v2_token"));
        assert!(!header.contains("token=v1_token"));
    }

    #[test]
    fn get_longest_path_wins_independent_of_insertion_order() {
        // Same as above but cookies inserted in reverse — verifies the
        // longest-path-wins rule isn't a positional accident.
        let mut jar = CookieJar::new();
        jar.cookies
            .push(mk_cookie("token", "v2_token", "host.test", "/api/v2/"));
        jar.cookies
            .push(mk_cookie("token", "v1_token", "host.test", "/api/"));

        let url = parse_url("https://host.test/api/v2/users");
        let mut req = Mimelike::new();
        jar.get(&url, &mut req);
        let header = req.get_header("Cookie").expect("expected header");
        assert!(header.contains("token=v2_token"));
        assert!(!header.contains("token=v1_token"));
    }

    #[test]
    fn get_excludes_expired_cookies() {
        let mut jar = CookieJar::new();
        // Expired cookie (expiry=100, ~year 1970).
        let mut expired = mk_cookie("old", "stale", "host.test", "/");
        expired.expiry = 100.0;
        jar.cookies.push(expired);
        // Future cookie (expiry far in the future).
        let mut future = mk_cookie("fresh", "new", "host.test", "/");
        future.expiry = current_timestamp_secs() + 86_400.0;
        jar.cookies.push(future);
        // Session cookie (expiry == 0.0 → never expires).
        jar.cookies.push(mk_cookie("session", "ok", "host.test", "/"));

        let url = parse_url("https://host.test/");
        let mut req = Mimelike::new();
        jar.get(&url, &mut req);
        let header = req.get_header("Cookie").expect("expected header");
        assert!(!header.contains("old"));
        assert!(header.contains("fresh=new"));
        assert!(header.contains("session=ok"));
    }

    #[test]
    fn get_emits_separator_correctly() {
        // Verify the `"; "` separator placement between pairs.
        let mut jar = CookieJar::new();
        jar.cookies.push(mk_cookie("a", "1", "host.test", "/"));
        jar.cookies.push(mk_cookie("b", "2", "host.test", "/"));
        let url = parse_url("https://host.test/");
        let mut req = Mimelike::new();
        jar.get(&url, &mut req);
        let header = req.get_header("Cookie").expect("expected header");
        // Order is insertion order for distinct names, so we expect
        // "a=1; b=2".
        assert_eq!(header, "a=1; b=2");
    }

    // ---- set() parsing -----------------------------------------------

    #[test]
    fn set_with_plain_set_cookie() {
        let mut jar = CookieJar::new();
        let url = parse_url("https://host.test/");
        let resp = mk_mimelike_with("Set-Cookie", "sid=abc");
        jar.set(&url, &resp).expect("set should succeed");
        assert_eq!(jar.len(), 1);
        let c = &jar.cookies()[0];
        assert_eq!(c.name, "sid");
        assert_eq!(c.value, "abc");
        assert_eq!(c.domain, "host.test");
        assert_eq!(c.path, "/");
        assert!(c.is_session());
    }

    #[test]
    fn set_with_no_set_cookie_header_is_noop() {
        let mut jar = CookieJar::new();
        let url = parse_url("https://host.test/");
        let resp = Mimelike::new(); // no Set-Cookie at all
        jar.set(&url, &resp).expect("set should succeed");
        assert_eq!(jar.len(), 0);
    }

    #[test]
    fn set_with_empty_set_cookie_is_noop() {
        let mut jar = CookieJar::new();
        let url = parse_url("https://host.test/");
        let resp = mk_mimelike_with("Set-Cookie", "");
        jar.set(&url, &resp).expect("set should succeed");
        assert_eq!(jar.len(), 0);
    }

    #[test]
    fn set_parses_expires() {
        let mut jar = CookieJar::new();
        let url = parse_url("https://host.test/");
        let resp = mk_mimelike_with(
            "Set-Cookie",
            "sess=42; Expires=Wed, 09 Jun 2099 10:18:14 GMT; Path=/",
        );
        jar.set(&url, &resp).expect("set should succeed");
        assert_eq!(jar.len(), 1);
        let c = &jar.cookies()[0];
        // 2099-06-09 10:18:14 UTC is well into the future — strictly > now.
        assert!(c.expiry > current_timestamp_secs());
        assert_eq!(c.name, "sess");
        assert_eq!(c.value, "42");
        // Path attribute supplied — should be "/" (already trailing-/).
        assert_eq!(c.path, "/");
    }

    #[test]
    fn set_parses_max_age() {
        let mut jar = CookieJar::new();
        let url = parse_url("https://host.test/");
        let resp = mk_mimelike_with("Set-Cookie", "tok=z9; Max-Age=3600");
        jar.set(&url, &resp).expect("set should succeed");
        assert_eq!(jar.len(), 1);
        let c = &jar.cookies()[0];
        let now = current_timestamp_secs();
        // Expiry must be ~3600 seconds from now, allowing a generous
        // tolerance for timer skew between calls.
        assert!(c.expiry >= now + 3500.0);
        assert!(c.expiry <= now + 3700.0);
    }

    #[test]
    fn set_with_secure_flag() {
        let mut jar = CookieJar::new();
        let url = parse_url("https://host.test/");
        let resp = mk_mimelike_with("Set-Cookie", "k=v; Secure; HttpOnly");
        jar.set(&url, &resp).expect("set should succeed");
        assert_eq!(jar.len(), 1);
        let c = &jar.cookies()[0];
        assert!(c.secure);
        assert!(c.httponly);
    }

    #[test]
    fn set_default_path_from_url() {
        let mut jar = CookieJar::new();
        // URL path is /folder/page — default cookie path should be /folder/
        let url = parse_url("https://host.test/folder/page");
        let resp = mk_mimelike_with("Set-Cookie", "k=v");
        jar.set(&url, &resp).expect("set should succeed");
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].path, "/folder/");
    }

    #[test]
    fn set_default_domain_from_url() {
        let mut jar = CookieJar::new();
        let url = parse_url("https://example.com/page");
        let resp = mk_mimelike_with("Set-Cookie", "k=v");
        jar.set(&url, &resp).expect("set should succeed");
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].domain, "example.com");
    }

    #[test]
    fn set_path_normalizes_trailing_slash() {
        // Cookie sent with Path=/api (no trailing slash) — should be
        // stored as "/api/" per FASM L508-522.
        let mut jar = CookieJar::new();
        let url = parse_url("https://host.test/");
        let resp = mk_mimelike_with("Set-Cookie", "k=v; Path=/api");
        jar.set(&url, &resp).expect("set should succeed");
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].path, "/api/");
    }

    #[test]
    fn set_expired_cookie_deletes_matching() {
        let mut jar = CookieJar::new();
        // Pre-populate a matching cookie.
        let mut existing = mk_cookie("sid", "live", "host.test", "/");
        existing.expiry = current_timestamp_secs() + 86_400.0;
        jar.cookies.push(existing);
        assert_eq!(jar.len(), 1);

        // Server tells us the cookie is expired (year-1990 expiry).
        let url = parse_url("https://host.test/");
        let resp = mk_mimelike_with(
            "Set-Cookie",
            "sid=anything; Expires=Mon, 01 Jan 1990 00:00:00 GMT",
        );
        jar.set(&url, &resp).expect("set should succeed");
        // The expired Set-Cookie should have removed the existing entry.
        assert_eq!(jar.len(), 0);
    }

    #[test]
    fn set_replaces_same_name_domain_path() {
        let mut jar = CookieJar::new();
        // Pre-populate.
        jar.cookies.push(mk_cookie("auth", "old_token", "host.test", "/"));

        let url = parse_url("https://host.test/");
        let resp = mk_mimelike_with("Set-Cookie", "auth=new_token");
        jar.set(&url, &resp).expect("set should succeed");
        // Should still be 1 cookie, but with new value.
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].value, "new_token");
    }

    #[test]
    fn set_first_attribute_without_eq_is_silent_bail() {
        // First attribute lacks `=` → FASM .cookie_nameval_error returns
        // silently. Our port also returns Ok(()) without modification.
        let mut jar = CookieJar::new();
        let url = parse_url("https://host.test/");
        let resp = mk_mimelike_with("Set-Cookie", "no_equals_here");
        jar.set(&url, &resp).expect("set should succeed");
        assert_eq!(jar.len(), 0);
    }

    #[test]
    fn set_unknown_attributes_silently_ignored() {
        let mut jar = CookieJar::new();
        let url = parse_url("https://host.test/");
        let resp = mk_mimelike_with("Set-Cookie", "k=v; SameSite=Lax; Foo=Bar");
        jar.set(&url, &resp).expect("set should succeed");
        // Cookie still set, unknown attrs absorbed silently.
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].name, "k");
        assert_eq!(jar.cookies()[0].value, "v");
    }

    // ---- session_clear / expire_expired -------------------------------

    #[test]
    fn session_clear_removes_session_only() {
        let mut jar = CookieJar::new();
        jar.cookies.push(mk_cookie("session", "x", "h.test", "/"));
        let mut persistent = mk_cookie("persist", "y", "h.test", "/");
        persistent.expiry = 1_700_000_000.0;
        jar.cookies.push(persistent);

        jar.session_clear();
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].name, "persist");
    }

    #[test]
    fn expire_expired_removes_only_expired() {
        let mut jar = CookieJar::new();
        // Session cookie — kept.
        jar.cookies.push(mk_cookie("session", "x", "h.test", "/"));
        // Future cookie — kept.
        let mut future = mk_cookie("fresh", "y", "h.test", "/");
        future.expiry = current_timestamp_secs() + 86_400.0;
        jar.cookies.push(future);
        // Expired cookie — removed.
        let mut stale = mk_cookie("old", "z", "h.test", "/");
        stale.expiry = 1_000.0;
        jar.cookies.push(stale);

        jar.expire_expired();
        assert_eq!(jar.len(), 2);
        let names: Vec<&str> = jar.cookies().iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"session"));
        assert!(names.contains(&"fresh"));
        assert!(!names.contains(&"old"));
    }

    // ---- RFC 5322 parser ----------------------------------------------

    #[test]
    fn rfc5322_parse_canonical_example() {
        // "Wed, 09 Jun 2021 10:18:14 GMT" — well-known reference value.
        // 2021-06-09 10:18:14 UTC → 1623233894 Unix seconds.
        let ts = parse_rfc5322_to_timestamp("Wed, 09 Jun 2021 10:18:14 GMT")
            .expect("canonical RFC-5322 should parse");
        assert!((ts - 1_623_233_894.0).abs() < 1.0);
    }

    #[test]
    fn rfc5322_parse_no_weekday_prefix() {
        // RFC 5322 §3.3 makes the day-of-week optional.
        let ts =
            parse_rfc5322_to_timestamp("09 Jun 2021 10:18:14 GMT").expect("dateless prefix should parse");
        assert!((ts - 1_623_233_894.0).abs() < 1.0);
    }

    #[test]
    fn rfc5322_parse_unix_epoch() {
        // 1970-01-01 00:00:00 GMT → 0 seconds.
        let ts = parse_rfc5322_to_timestamp("Thu, 01 Jan 1970 00:00:00 GMT").expect("epoch should parse");
        assert_eq!(ts, 0.0);
    }

    #[test]
    fn rfc5322_parse_post_2000() {
        // 2000-01-01 00:00:00 GMT → 946684800 Unix seconds (well-known).
        let ts = parse_rfc5322_to_timestamp("Sat, 01 Jan 2000 00:00:00 GMT").expect("Y2K should parse");
        assert_eq!(ts, 946_684_800.0);
    }

    #[test]
    fn rfc5322_parse_invalid_month_returns_none() {
        assert!(parse_rfc5322_to_timestamp("Wed, 09 Xxx 2021 10:18:14 GMT").is_none());
    }

    #[test]
    fn rfc5322_parse_truncated_returns_none() {
        assert!(parse_rfc5322_to_timestamp("").is_none());
        assert!(parse_rfc5322_to_timestamp("Wed,").is_none());
        assert!(parse_rfc5322_to_timestamp("Wed, 09 Jun").is_none());
    }

    #[test]
    fn rfc5322_parse_out_of_range_returns_none() {
        // Hour 25 → reject.
        assert!(parse_rfc5322_to_timestamp("Wed, 09 Jun 2021 25:18:14 GMT").is_none());
        // Day 0 → reject.
        assert!(parse_rfc5322_to_timestamp("Wed, 00 Jun 2021 10:18:14 GMT").is_none());
        // Minute 60 → reject.
        assert!(parse_rfc5322_to_timestamp("Wed, 09 Jun 2021 10:60:14 GMT").is_none());
    }

    // ---- Helper: cookie_matches -----------------------------------

    #[test]
    fn cookie_matches_helper() {
        let c = mk_cookie("k", "v", "host.test", "/api/");
        assert!(cookie_matches(&c, "k", "host.test", "/api/"));
        assert!(!cookie_matches(&c, "different", "host.test", "/api/"));
        assert!(!cookie_matches(&c, "k", "other.host", "/api/"));
        assert!(!cookie_matches(&c, "k", "host.test", "/"));
    }

    // ---- current_timestamp_secs sanity ---------------------------------

    #[test]
    fn current_timestamp_is_in_post_2020() {
        // Sanity check: the implementation should produce a value
        // greater than 2020-01-01 (~1577836800) when run on any
        // modern system.
        let ts = current_timestamp_secs();
        assert!(ts > 1_577_836_800.0);
        // And less than year 3000 for sanity.
        assert!(ts < 32_503_680_000.0);
    }
}
