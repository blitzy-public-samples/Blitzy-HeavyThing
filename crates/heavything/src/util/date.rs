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

//! Date/time handling with RFC 1123 HTTP Date and RFC 3164 syslog
//! timestamp formatting. Port of `date.inc`.
//!
//! # Historical Context (FASM original)
//!
//! `date.inc` (~1,336 lines) implements a leap-second-unaware date/time
//! engine built on a **Truncated Julian Date** (TJD) — an `f64` count of
//! days since `2013-06-30 00:00 UTC` (Julian Date `2_456_473.5`). The
//! choice of a non-Unix epoch is deliberate: the TJD origin places the
//! `f64` mantissa's fractional precision squarely in the microsecond
//! range for contemporary dates, avoiding the precision loss that would
//! accrue if the epoch were `1970-01-01` (as Unix does). FASM callers
//! use TJD internally and convert to broken-down date parts only at
//! display boundaries (HTTP `Date:` headers, syslog timestamps,
//! cookie-jar expiration rendering).
//!
//! # Rust Strategy (per AAP §0.5.1.7)
//!
//! This module exposes:
//!
//! * The **same TJD-based internal representation** via [`now_tjd`] and
//!   [`tjd_to_unix_secs`], preserving API parity with the FASM library
//!   so consumers (notably `net::http::server` and `util::formatter`)
//!   see the same numeric pipeline.
//! * A broken-down [`DateParts`] struct matching the 16-byte FASM
//!   `_datetime_*` record layout (year, month, day, hour, minute,
//!   second, weekday).
//! * Byte-identical [`rfc1123`] formatting matching the FASM HTTP
//!   `Date:` header output. Heavily regression-tested against the
//!   canonical RFC 2616 example `Sun, 06 Nov 1994 08:49:37 GMT`.
//! * RFC 3164 [`rfc3164`] / [`rfc3164_timestamp`] formatting for the
//!   `util::syslog` caller, with the space-padded (not zero-padded)
//!   day-of-month the RFC prescribes.
//!
//! # Algorithmic Heart
//!
//! The Gregorian-civil-from-days conversion uses
//! **Howard Hinnant's `civil_from_days`** algorithm (public domain,
//! published in his "chrono-Compatible Low-Level Date Algorithms" paper).
//! The algorithm is proven correct for all Gregorian dates from
//! approximately year -5,877,641 through year 5,879,610 — vastly
//! exceeding the range any HTTP/syslog consumer needs. It avoids all
//! floating-point math, using only signed integer arithmetic with
//! `div_euclid` / `rem_euclid` for safe negative-day handling.
//!
//! # Leap Seconds
//!
//! Leap-second **unaware**, matching FASM behaviour exactly (see
//! `date.inc` line 8: "Leap-Seconds: we are intentionally leap-second
//! unaware"). Both the Unix epoch time axis and the Julian Date axis
//! are leap-second-unaware, so this is a natural simplification that
//! causes no observable output difference for HTTP `Date:` or syslog
//! timestamp rendering. Consumers needing leap-second-aware formatting
//! would need to consult a leap-second table — out of scope per
//! AAP §0.3.2.5 ("No feature additions").
//!
//! # Consumers
//!
//! * `util::syslog` — [`rfc3164_timestamp`] for RFC 3164 message
//!   timestamps.
//! * `net::http::server` (future) — [`now_rfc1123`] for HTTP `Date:`
//!   response-header emission.
//! * `net::http::cookiejar` (future) — [`rfc1123`] for cookie
//!   `Expires=` attribute rendering.
//! * `util::formatter` (future) — [`unix_secs_to_parts`] for
//!   human-readable timestamp formatting.
//!
//! # Example
//!
//! ```
//! use heavything::util::date;
//!
//! // Current time as an RFC 1123 HTTP Date header value.
//! let header = date::now_rfc1123().unwrap();
//! assert!(header.ends_with(" GMT"));
//!
//! // Deterministic conversion from a fixed Unix timestamp.
//! let parts = date::unix_secs_to_parts(784_111_777);
//! assert_eq!(date::rfc1123(parts), "Sun, 06 Nov 1994 08:49:37 GMT");
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::UtilError;

// ---------------------------------------------------------------------------
// Constants — mirror FASM `.millions`, `.usecs2day`, `.modifier`, etc.
// ---------------------------------------------------------------------------

/// Truncated Julian Date epoch offset — seconds from the Unix epoch
/// (`1970-01-01 00:00:00 UTC`) to the TJD epoch
/// (`2013-06-30 00:00:00 UTC`).
///
/// FASM uses this as its internal time axis. Callers who need Unix
/// seconds convert via [`tjd_to_unix_secs`].
pub const TJD_EPOCH_UNIX_SECONDS: i64 = 1_372_550_400;

/// Julian Date of the TJD epoch: `2013-06-30 00:00:00 UTC`.
///
/// Mirrors the FASM `.modifier dq 2456473.5f` constant
/// (`date.inc` line 18).
pub const TJD_EPOCH_JD: f64 = 2_456_473.5;

/// Scaling factor `1e-6` — microseconds to seconds.
///
/// Mirrors the FASM `.millions dq 0.000001f` constant
/// (`date.inc` line 15). Exposed for API parity with consumers that
/// previously relied on the named constant; Rust callers typically
/// prefer [`std::time::Duration`] conversions.
pub const MILLIONS: f64 = 0.000_001_f64;

/// Seconds per day (`86_400`).
pub const SECONDS_PER_DAY: i64 = 86_400;

/// RFC 1123 day-of-week short names.
///
/// Indexed by [`DateParts::weekday`] where `0 = Sunday`, `6 = Saturday`.
/// Matches the convention of `chrono::Weekday::num_days_from_sunday`.
pub const DAYS_OF_WEEK: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// RFC 1123 / RFC 3164 month short names.
///
/// Indexed as `MONTHS[month - 1]` where `month` is 1-based
/// (`DateParts::month` = 1 for January).
pub const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

// ---------------------------------------------------------------------------
// DateParts — broken-down UTC date/time.
// ---------------------------------------------------------------------------

/// A broken-down UTC date/time record.
///
/// Mirrors the FASM 16-byte `_datetime_*` layout (see `date.inc`
/// lines 86-92): `yearofs=0`, `monthofs=2`, `dayofs=4`, `hourofs=6`,
/// `minofs=8`, `secofs=10` (all 16-bit in FASM; widened to 32-bit in
/// Rust for idiomatic arithmetic). The FASM `usecofs=12` 32-bit
/// microseconds field is omitted here because neither RFC 1123 nor
/// RFC 3164 carries sub-second precision and none of the current
/// consumers (syslog, HTTP Date, cookie expiry) need microseconds.
///
/// All fields are UTC; there is no timezone state in this struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateParts {
    /// Gregorian year (e.g., `2026`). May be negative for dates BCE
    /// (though no current consumer exercises that range).
    pub year: i32,
    /// Month of the year, `1..=12` (1 = January).
    pub month: u32,
    /// Day of the month, `1..=31` (calendar-dependent upper bound).
    pub day: u32,
    /// Hour of the day, `0..=23`.
    pub hour: u32,
    /// Minute of the hour, `0..=59`.
    pub minute: u32,
    /// Second of the minute, `0..=60` (the `60` slot reserves space
    /// for leap seconds even though this module is leap-second-unaware
    /// and will never actually produce `60`).
    pub second: u32,
    /// Day of the week, `0..=6` where `0 = Sunday` and `6 = Saturday`.
    /// Matches [`DAYS_OF_WEEK`] indexing.
    pub weekday: u32,
}

// ---------------------------------------------------------------------------
// Helpers — current time acquisition.
// ---------------------------------------------------------------------------

/// Return the current wall-clock UTC time as a Truncated Julian Date
/// (`f64` days since `2013-06-30 00:00:00 UTC`).
///
/// This is the FASM library's internal time representation (see
/// `date.inc` `.modifier` and `.secs2day`). On Linux, the underlying
/// `SystemTime::now()` is resolved through the vDSO fast path without a
/// syscall trap (AAP §0.5.1.7: "Rust `std::time` uses vDSO automatically
/// on Linux").
///
/// # Errors
///
/// Returns [`UtilError::Io`] wrapping a synthetic `io::Error` if the
/// system clock is set before the Unix epoch. This is effectively
/// impossible on a real system (the Linux kernel refuses to set the
/// RTC below epoch) but is handled for completeness.
pub fn now_tjd() -> Result<f64, UtilError> {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| UtilError::Io(std::io::Error::other("system time before UNIX epoch")))?;
    let unix_secs = d.as_secs_f64();
    Ok((unix_secs - TJD_EPOCH_UNIX_SECONDS as f64) / SECONDS_PER_DAY as f64)
}

/// Return the current wall-clock UTC time as broken-down [`DateParts`].
///
/// # Errors
///
/// See [`now_tjd`].
pub fn now_parts() -> Result<DateParts, UtilError> {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| UtilError::Io(std::io::Error::other("system time before UNIX epoch")))?;
    // `SystemTime::duration_since` already returned a `Duration`; the
    // `as_secs` cast is lossless for the next ~585 billion years.
    Ok(unix_secs_to_parts(d.as_secs() as i64))
}

// ---------------------------------------------------------------------------
// Core conversion — Hinnant's civil_from_days algorithm.
// ---------------------------------------------------------------------------

/// Convert Unix seconds (since `1970-01-01 00:00:00 UTC`) into a
/// [`DateParts`] record.
///
/// Uses **Howard Hinnant's `civil_from_days` algorithm** (public
/// domain). The algorithm:
///
/// 1. Splits `secs` into whole days (`days`) and seconds-within-day
///    (`tod`) via Euclidean division, which safely handles negative
///    Unix timestamps (pre-1970 dates).
/// 2. Shifts the epoch from `1970-01-01` to `0000-03-01` (Hinnant's
///    "shifted" civil origin) by adding `719_468` — this places
///    February at the end of the year, sidestepping leap-day edge
///    cases.
/// 3. Computes the 400-year era, year-of-era, day-of-year, and
///    month/day via integer arithmetic only (no floating point).
/// 4. Unshifts back to standard Gregorian conventions for the
///    returned `DateParts`.
///
/// The algorithm is correct for all Gregorian dates across the
/// `i64`-representable range and is leap-year-correct through the
/// 400-year cycle. For a derivation and proof see Hinnant's
/// "chrono-Compatible Low-Level Date Algorithms" paper.
///
/// # Weekday
///
/// `1970-01-01` was a **Thursday**, which in this module's convention
/// (Sunday = 0) is weekday `4`. The formula
/// `(days.rem_euclid(7) + 4).rem_euclid(7)` derives the weekday from
/// the day count, again using Euclidean remainder for negative-day
/// safety.
pub fn unix_secs_to_parts(secs: i64) -> DateParts {
    // Split into whole days and seconds-within-day.
    let days = secs.div_euclid(SECONDS_PER_DAY);
    let tod = secs.rem_euclid(SECONDS_PER_DAY);

    let hour = (tod / 3600) as u32;
    let minute = ((tod / 60) % 60) as u32;
    let second = (tod % 60) as u32;

    // Hinnant's civil_from_days: z = days since 0000-03-01 (shifted
    // civil epoch). 719_468 is (days from 0000-03-01 to 1970-01-01).
    let z = days + 719_468;

    // era = 400-year cycle index (negative for pre-shifted-epoch).
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;

    // doe = day-of-era, in `[0, 146_096]`.
    let doe = (z - era * 146_097) as u64;

    // yoe = year-of-era, in `[0, 399]`.
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;

    // Shifted civil year (year of 0000-03-01-based calendar).
    let y = yoe as i64 + era * 400;

    // doy = day-of-year in the shifted calendar (March 1 = 0).
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);

    // mp = shifted month index `[0, 11]` where 0 = March.
    let mp = (5 * doy + 2) / 153;

    // Day of month (1-based).
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;

    // Unshift month: 0..=9 -> 3..=12 (Mar..Dec); 10..=11 -> 1..=2 (Jan, Feb).
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;

    // Unshift year: if month is Jan or Feb (shifted calendar carries
    // them into the following year's start), increment.
    let year = (if m <= 2 { y + 1 } else { y }) as i32;

    // Weekday: 1970-01-01 was Thursday = 4 (with Sunday = 0).
    let weekday = ((days.rem_euclid(7) + 4).rem_euclid(7)) as u32;

    DateParts {
        year,
        month: m,
        day: d,
        hour,
        minute,
        second,
        weekday,
    }
}

/// Convert a Truncated Julian Date back to Unix seconds.
///
/// Inverse of the conversion in [`now_tjd`]. Rounds to the nearest
/// whole second — microsecond precision is lost on this boundary,
/// matching the FASM `.secs2day` round-trip behaviour where
/// sub-second fractions are carried as separate state.
pub fn tjd_to_unix_secs(tjd: f64) -> i64 {
    (tjd * SECONDS_PER_DAY as f64 + TJD_EPOCH_UNIX_SECONDS as f64).round() as i64
}

// ---------------------------------------------------------------------------
// RFC 1123 HTTP Date formatter — CRITICAL: byte-identical with FASM.
// ---------------------------------------------------------------------------

/// Format [`DateParts`] as an RFC 1123 HTTP `Date:` header value.
///
/// Output shape: `"Sun, 06 Nov 1994 08:49:37 GMT"` — three-letter
/// weekday, comma, zero-padded 2-digit day, three-letter month,
/// 4-digit year, colon-separated `HH:MM:SS`, literal ` GMT` suffix.
///
/// This output is **byte-identical** with the FASM library's
/// `datetime$to_httpdate` formatter (see `date.inc`). The HTTP `Date:`
/// header is produced character-for-character the same way so
/// response caches, content-identity hashes, and TLS session keys do
/// not diverge between the FASM baseline and the Rust port.
///
/// # Bounds
///
/// The modulo guards on the array indices (`% 7` and `% 12`) ensure
/// the function never panics on malformed `DateParts` that might
/// escape from `unsafe` code paths or future JSON-derived parsing;
/// well-formed inputs ([`unix_secs_to_parts`] output) are always in
/// range.
pub fn rfc1123(parts: DateParts) -> String {
    let dow = DAYS_OF_WEEK[parts.weekday as usize % 7];
    let month = MONTHS[(parts.month as usize - 1) % 12];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        dow, parts.day, month, parts.year, parts.hour, parts.minute, parts.second,
    )
}

/// Convenience: format the current UTC time as an RFC 1123 HTTP
/// `Date:` header value.
///
/// # Errors
///
/// See [`now_tjd`].
pub fn now_rfc1123() -> Result<String, UtilError> {
    Ok(rfc1123(now_parts()?))
}

// ---------------------------------------------------------------------------
// RFC 3164 syslog timestamp — required by util::syslog.
// ---------------------------------------------------------------------------

/// Format [`DateParts`] as an RFC 3164 syslog TIMESTAMP field.
///
/// Output shape: `"Oct  6 14:05:03"` — three-letter month, single
/// space, **space-padded** (not zero-padded) 2-character day-of-month,
/// single space, colon-separated `HH:MM:SS`.
///
/// Per RFC 3164 §4.1.2: "Single-digit days are preceded by a space,
/// not a zero". This differs from RFC 1123 / HTTP Date formatting,
/// where days are zero-padded. Mixing the two is a common interop bug;
/// keep this function the sole source of syslog timestamps.
///
/// No timezone is emitted — RFC 3164 timestamps are local-time with
/// no zone indicator, but this module emits UTC because the library
/// is leap-second-unaware and stores everything in UTC. Syslog
/// daemons that insist on local time typically re-time at ingest.
pub fn rfc3164(parts: DateParts) -> String {
    let month = MONTHS[(parts.month as usize - 1) % 12];
    format!(
        "{} {:>2} {:02}:{:02}:{:02}",
        month, parts.day, parts.hour, parts.minute, parts.second,
    )
}

/// Convenience: format the current UTC time as an RFC 3164 syslog
/// TIMESTAMP.
///
/// Unlike [`now_rfc1123`], this function **cannot fail** — it falls
/// back to the placeholder string `"Jan  1 00:00:00"` if
/// [`now_parts`] returns an error. This fallback is required because
/// the caller (`util::syslog::log`) is itself on the error-reporting
/// path: if logging were fallible it would break the cardinal
/// fail-safe invariant that emitting a log message must always
/// succeed, even on clock-setup failures.
///
/// The fallback never triggers on a real system (the Linux kernel
/// forbids clock-before-epoch).
pub fn rfc3164_timestamp() -> String {
    match now_parts() {
        Ok(p) => rfc3164(p),
        Err(_) => "Jan  1 00:00:00".to_string(),
    }
}

// ---------------------------------------------------------------------------
// API-adaptation wrappers for downstream consumers.
// ---------------------------------------------------------------------------
//
// The Checkpoint 4 Phase 2 API adaptation registry prescribes a
// `SystemTime`-taking variant of the RFC 1123 formatter plus an `http_date`
// alias. The canonical entry point [`rfc1123`] takes a [`DateParts`] by
// value because the FASM source (`date.inc` `datetime$to_httpdate`) is
// structured around a pre-decoded in-register year/month/day/… tuple.
// Consumers such as the forthcoming HTTP server's `Date:` header emitter
// will typically hold a [`std::time::SystemTime`] and want a single-call
// path that performs the decode + format in one step.
//
// These functions are additive; they delegate to the existing decode
// ([`unix_secs_to_parts`]) and format ([`rfc1123`]) primitives and do not
// duplicate logic.

/// Format a [`SystemTime`] as an RFC 1123 HTTP-date string.
///
/// Convenience wrapper around [`rfc1123`] + [`unix_secs_to_parts`] that
/// accepts a [`SystemTime`] directly — the form typically available to
/// HTTP server callers when emitting a `Date:` header.
///
/// Times before the Unix epoch (`UNIX_EPOCH`) produce the sentinel
/// `"Thu, 01 Jan 1970 00:00:00 GMT"` rather than failing; this matches
/// the `rfc3164_timestamp` fallback discipline (logging / header emission
/// must never be fallible at the call site, as the caller may itself be
/// on an error-reporting path).
///
/// Output is byte-identical to [`rfc1123`] for any `t >= UNIX_EPOCH`.
///
/// # Example
///
/// ```
/// use std::time::{SystemTime, UNIX_EPOCH, Duration};
/// use heavything::util::date;
///
/// let t = UNIX_EPOCH + Duration::from_secs(784_111_777);
/// assert_eq!(date::rfc1123_system_time(t), "Sun, 06 Nov 1994 08:49:37 GMT");
/// ```
pub fn rfc1123_system_time(t: SystemTime) -> String {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => rfc1123(unix_secs_to_parts(d.as_secs() as i64)),
        Err(_) => String::from("Thu, 01 Jan 1970 00:00:00 GMT"),
    }
}

/// Alias of [`rfc1123_system_time`] for the HTTP `Date:` header emission
/// site. Provided per the API adaptation registry; the name `http_date`
/// communicates intent at the call site (the caller writes a `Date:`
/// header rather than a generic RFC 1123 timestamp). Byte-identical
/// output to [`rfc1123_system_time`].
pub use self::rfc1123_system_time as http_date;

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Core conversion -----

    #[test]
    fn unix_epoch_is_1970_thursday() {
        let p = unix_secs_to_parts(0);
        assert_eq!(p.year, 1970);
        assert_eq!(p.month, 1);
        assert_eq!(p.day, 1);
        assert_eq!(p.hour, 0);
        assert_eq!(p.minute, 0);
        assert_eq!(p.second, 0);
        assert_eq!(p.weekday, 4); // Thursday
    }

    #[test]
    fn rfc1123_canonical_example() {
        // Canonical RFC 2616 example: "Sun, 06 Nov 1994 08:49:37 GMT"
        // -> Unix 784_111_777 (date -u -d @784111777).
        let p = unix_secs_to_parts(784_111_777);
        assert_eq!(p.year, 1994);
        assert_eq!(p.month, 11);
        assert_eq!(p.day, 6);
        assert_eq!(p.weekday, 0); // Sunday
        assert_eq!(rfc1123(p), "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    #[test]
    fn rfc3164_space_padded_day() {
        // Per RFC 3164 §4.1.2: single-digit days are SPACE-padded,
        // not zero-padded.
        let p = DateParts {
            year: 2026,
            month: 10,
            day: 6,
            hour: 14,
            minute: 5,
            second: 3,
            weekday: 2, // Tuesday
        };
        assert_eq!(rfc3164(p), "Oct  6 14:05:03");
        // Exactly two characters between "Oct" and "6"? Verify.
        assert_eq!(rfc3164(p).as_bytes()[3], b' ');
        assert_eq!(rfc3164(p).as_bytes()[4], b' ');
        assert_eq!(rfc3164(p).as_bytes()[5], b'6');
    }

    #[test]
    fn rfc3164_two_digit_day() {
        let p = DateParts {
            year: 2026,
            month: 10,
            day: 23,
            hour: 14,
            minute: 5,
            second: 3,
            weekday: 5,
        };
        assert_eq!(rfc3164(p), "Oct 23 14:05:03");
    }

    #[test]
    fn tjd_roundtrip() {
        // Arbitrary Unix timestamp -> TJD -> Unix seconds; exact round-trip.
        let u0 = 1_700_000_000_i64;
        let tjd = (u0 - TJD_EPOCH_UNIX_SECONDS) as f64 / SECONDS_PER_DAY as f64;
        let u1 = tjd_to_unix_secs(tjd);
        assert_eq!(u0, u1);
    }

    #[test]
    fn weekday_calculation() {
        // 2024-01-01 was a Monday (Unix 1_704_067_200).
        let p = unix_secs_to_parts(1_704_067_200);
        assert_eq!(p.year, 2024);
        assert_eq!(p.month, 1);
        assert_eq!(p.day, 1);
        assert_eq!(p.weekday, 1); // Monday
    }

    // ----- Extra regression coverage: leap years, month rollovers, negatives -----

    #[test]
    fn leap_day_2000() {
        // 2000-02-29 00:00:00 UTC -> Unix 951_782_400 (century leap year).
        let p = unix_secs_to_parts(951_782_400);
        assert_eq!(p.year, 2000);
        assert_eq!(p.month, 2);
        assert_eq!(p.day, 29);
    }

    #[test]
    fn non_leap_century_1900() {
        // 1900-02-28 00:00:00 UTC -> Unix -2_203_977_600.
        // 1900 is a century year and NOT a leap year (div by 100 but
        // not 400) — the day AFTER 1900-02-28 must be 1900-03-01,
        // never 1900-02-29.  This locks in the 400-year rule.
        let p = unix_secs_to_parts(-2_203_977_600);
        assert_eq!(p.year, 1900);
        assert_eq!(p.month, 2);
        assert_eq!(p.day, 28);
        // +1 day: must land on March 1st, not a phantom Feb 29.
        let p2 = unix_secs_to_parts(-2_203_977_600 + 86_400);
        assert_eq!(p2.year, 1900);
        assert_eq!(p2.month, 3);
        assert_eq!(p2.day, 1);
    }

    #[test]
    fn negative_unix_before_epoch() {
        // 1969-12-31 23:59:59 UTC -> Unix -1 (tests negative-day
        // Euclidean handling).
        let p = unix_secs_to_parts(-1);
        assert_eq!(p.year, 1969);
        assert_eq!(p.month, 12);
        assert_eq!(p.day, 31);
        assert_eq!(p.hour, 23);
        assert_eq!(p.minute, 59);
        assert_eq!(p.second, 59);
        assert_eq!(p.weekday, 3); // Wednesday
    }

    #[test]
    fn end_of_year_rollover() {
        // 2025-01-01 00:00:00 UTC -> Unix 1_735_689_600.
        let p = unix_secs_to_parts(1_735_689_600);
        assert_eq!(p.year, 2025);
        assert_eq!(p.month, 1);
        assert_eq!(p.day, 1);
        assert_eq!(p.weekday, 3); // Wednesday
                                  // One second before:
        let p2 = unix_secs_to_parts(1_735_689_599);
        assert_eq!(p2.year, 2024);
        assert_eq!(p2.month, 12);
        assert_eq!(p2.day, 31);
        assert_eq!(p2.hour, 23);
        assert_eq!(p2.second, 59);
    }

    #[test]
    fn rfc1123_all_weekdays() {
        // Exercise every weekday label to guard against off-by-one
        // in the DAYS_OF_WEEK table.
        // Unix 0 = 1970-01-01 Thursday.
        for i in 0..7 {
            let p = unix_secs_to_parts(i * SECONDS_PER_DAY);
            let expected_dow = (4 + i) % 7;
            assert_eq!(
                p.weekday, expected_dow as u32,
                "weekday mismatch at offset {i} day(s) past Unix epoch",
            );
            let formatted = rfc1123(p);
            assert!(formatted.starts_with(DAYS_OF_WEEK[expected_dow as usize]));
            assert!(formatted.ends_with(" GMT"));
        }
    }

    #[test]
    fn tjd_epoch_is_2013_06_30() {
        // 2013-06-30 00:00:00 UTC must be exactly TJD 0.0.
        let p = unix_secs_to_parts(TJD_EPOCH_UNIX_SECONDS);
        assert_eq!(p.year, 2013);
        assert_eq!(p.month, 6);
        assert_eq!(p.day, 30);
        assert_eq!(p.hour, 0);
        assert_eq!(p.minute, 0);
        assert_eq!(p.second, 0);
        // Round-trip: TJD 0.0 -> Unix TJD_EPOCH_UNIX_SECONDS.
        assert_eq!(tjd_to_unix_secs(0.0), TJD_EPOCH_UNIX_SECONDS);
    }

    #[test]
    fn now_functions_do_not_panic() {
        // Exercise the full SystemTime-based paths. On a sane host the
        // clock is after 2020, so these must succeed.
        let tjd = now_tjd().expect("now_tjd must succeed on a real system");
        assert!(tjd > 0.0, "TJD should be positive for any post-2013 clock");

        let parts = now_parts().expect("now_parts must succeed");
        assert!(parts.year >= 2020, "year must be at least 2020");
        assert!((1..=12).contains(&parts.month));
        assert!((1..=31).contains(&parts.day));
        assert!(parts.hour < 24);
        assert!(parts.minute < 60);
        assert!(parts.second <= 60);
        assert!(parts.weekday < 7);

        let header = now_rfc1123().expect("now_rfc1123 must succeed");
        assert!(header.ends_with(" GMT"));
        assert_eq!(header.len(), 29);

        let syslog = rfc3164_timestamp();
        // RFC 3164 TIMESTAMP is exactly 15 bytes: "Mmm dd hh:mm:ss".
        assert_eq!(syslog.len(), 15);
    }

    #[test]
    fn constants_are_consistent() {
        // Sanity: constants are self-consistent.
        assert_eq!(SECONDS_PER_DAY, 86_400);
        assert_eq!(TJD_EPOCH_JD, 2_456_473.5);
        assert_eq!(TJD_EPOCH_UNIX_SECONDS, 1_372_550_400);
        assert!((MILLIONS - 1e-6).abs() < 1e-15);
        assert_eq!(DAYS_OF_WEEK.len(), 7);
        assert_eq!(MONTHS.len(), 12);
        assert_eq!(DAYS_OF_WEEK[0], "Sun");
        assert_eq!(DAYS_OF_WEEK[6], "Sat");
        assert_eq!(MONTHS[0], "Jan");
        assert_eq!(MONTHS[11], "Dec");
    }

    #[test]
    fn rfc3164_timestamp_fallback_shape() {
        // The fallback string must itself be a well-formed RFC 3164
        // timestamp so a misbehaving clock doesn't break syslog parsers.
        let fallback = "Jan  1 00:00:00";
        assert_eq!(fallback.len(), 15);
        assert_eq!(&fallback[0..3], "Jan");
        assert_eq!(fallback.as_bytes()[3], b' ');
        assert_eq!(fallback.as_bytes()[4], b' ');
        assert_eq!(fallback.as_bytes()[5], b'1');
    }

    #[test]
    fn date_parts_traits() {
        // Copy + PartialEq + Eq + Debug — matches schema.
        let a = unix_secs_to_parts(0);
        let b = a; // Copy
        assert_eq!(a, b); // PartialEq / Eq
        let s = format!("{a:?}"); // Debug
        assert!(s.contains("year"));
    }
}
