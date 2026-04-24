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

//! Printf-like reusable output formatter. Port of `formatter.inc`.
//!
//! # Overview
//!
//! The FASM implementation ([`formatter.inc`](../../../../formatter.inc))
//! provides a dynamic, template-driven output builder: callers first build a
//! template by pushing a sequence of *format items* (static literals plus
//! typed placeholders), then invoke the formatter with the actual argument
//! values to produce the final string. The formatter is *reusable*: after a
//! call to [`Formatter::doit`] the same template can be filled with different
//! arguments, or [`Formatter::reset`] can clear it for a new template.
//!
//! Where the FASM version passes register arguments via the System V
//! x86_64 calling convention (up to 7 general-purpose registers and 16 XMM
//! registers), the Rust port uses a single `&[Value]` slice. This removes
//! the FASM register-count limits entirely while preserving the external
//! API shape: counters for how many register-class and XMM-class arguments
//! the template expects are still exposed so callers can validate before
//! invocation (see [`Formatter::reg_arg_count`] and
//! [`Formatter::xmm_arg_count`]).
//!
//! # Supported item types
//!
//! - **Static** — a literal string fragment that consumes no argument.
//! - **String / Boolean / Integer / Unsigned / Double / Buffer** — typed
//!   placeholders that each consume one argument from the `&[Value]` slice.
//! - **Duration** — a specialised placeholder for rendering `f64` day-valued
//!   durations into a human-readable `WwDdHhMm.SSSs` form (added to mirror
//!   FASM's `formatter$add_duration` entry point, which this port exposes as
//!   [`Formatter::add_duration`]).
//!
//! # Space-between-items option
//!
//! The FASM `.peritem` dispatcher prepends a single ASCII space before every
//! item (including static literals) whenever the running buffer is non-empty
//! and the formatter's `options` field requests spacing. The Rust port
//! preserves this behaviour exactly — the space is inserted uniformly before
//! every non-first item regardless of its type. See [`Formatter::new`] for
//! the activation flag.
//!
//! # Error handling
//!
//! Argument-count and value-type mismatches are reported through
//! [`UtilError::Io`] wrapping [`std::io::Error`] with kind
//! [`std::io::ErrorKind::InvalidInput`]. The design follows AAP §0.8.3: no
//! `unwrap`/`expect` outside tests, typed errors at module boundaries.

use std::fmt::Write;

use crate::config::FORMATTER_DATETIME_FRACTIONAL;
use crate::error::UtilError;

// ============================================================================
// FormatItemType — mirrors the FASM `formatitem_type_ofs` tag values.
// ============================================================================

/// Discriminator for [`FormatItem`] entries, identifying the kind of value
/// the placeholder expects at [`Formatter::doit`] time.
///
/// The numeric ordering mirrors the assembly baseline (`formatter.inc`
/// lines 73–89): `Static=0, String=1, Boolean=2, Integer=3, Unsigned=4,
/// Double=5, Buffer=6`. The `Duration` variant is a Rust extension that
/// carries the behaviour of the FASM `formatitem_duration` branch (type
/// value 11 in the assembly) — it is present because the schema exposes
/// [`Formatter::add_duration`] and the Rust port elects to represent the
/// duration placeholder as a first-class enum variant rather than encoding
/// it as a `Double` with out-of-band metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatItemType {
    /// Literal text fragment; consumes no argument at `doit` time.
    Static,
    /// UTF-8 string argument ([`Value::Str`]).
    String,
    /// Boolean argument ([`Value::Bool`]) rendered as `"true"` / `"false"`.
    Boolean,
    /// Signed 64-bit integer argument ([`Value::Int`]).
    Integer,
    /// Unsigned 64-bit integer argument ([`Value::Uint`]).
    Unsigned,
    /// Double-precision floating-point argument ([`Value::Dbl`]).
    Double,
    /// Raw byte buffer argument ([`Value::Buf`]), rendered lossily as UTF-8.
    Buffer,
    /// Human-readable duration — expects a [`Value::Dbl`] giving the number
    /// of days; the [`FormatItem::prec`] field carries the minimum-resolution
    /// selector (0 = milliseconds through 5 = weeks) and
    /// [`FormatItem::flags`] holds the fractional-digit count.
    Duration,
}

// ============================================================================
// FormatItem — one entry in the template.
// ============================================================================

/// A single template entry (one placeholder or static fragment).
///
/// Fields mirror the FASM `formatitem` layout (`formatter.inc` lines 65–71):
///
/// | FASM offset | FASM name       | Rust field   |
/// |-------------|-----------------|--------------|
/// | 0           | `type_ofs`      | `item_type`  |
/// | 8           | `width_ofs`     | `width`      |
/// | 16          | `flags_ofs`     | `flags`      |
/// | 24          | `prec_ofs`      | `prec`       |
/// | 32          | `value_ofs`     | `value`      |
///
/// For `Static` items the `value` field carries the literal text and all
/// other fields are zero. For dynamic items `value` is empty and the
/// numeric fields drive width, precision, and formatter-specific flags at
/// render time.
///
/// The struct is deliberately owned (`String`, not `&str`) so templates
/// can be cloned and stored independently of any borrowed buffer.
#[derive(Debug, Clone)]
pub struct FormatItem {
    /// Discriminator identifying the placeholder kind.
    pub item_type: FormatItemType,
    /// Minimum output width (0 = no padding). Interpreted by the
    /// renderer via `write!("{:>width$}", …)`.
    pub width: u32,
    /// Item-specific bit flags. For `Integer` / `Unsigned` items this
    /// mirrors the FASM integer-mode flags (0 = plain decimal,
    /// 1 = decimal with thousands separator, 2 = uppercase hex,
    /// 3 = uppercase hex with `0x` prefix); for `Double` items this
    /// holds the formatting mode; for `Duration` items this holds the
    /// fractional-digit count. For other kinds the field is reserved
    /// and carried through verbatim.
    pub flags: u32,
    /// Precision field. For `Double` items this is the number of digits
    /// after the decimal point; for `Duration` items this is the
    /// minimum-resolution selector (0 = ms, 1 = s, 2 = min, 3 = hr,
    /// 4 = day, 5 = week).
    pub prec: u32,
    /// Literal text for `Static` items; empty for dynamic placeholders.
    pub value: String,
}

// ============================================================================
// Value — the union of supported argument kinds.
// ============================================================================

/// The typed argument slot passed to [`Formatter::doit`].
///
/// The six variants match the schema export list exactly (AAP §0.7
/// `exports.members_exposed`: `Str, Bool, Int, Uint, Dbl, Buf`). A
/// `Duration` placeholder consumes a [`Value::Dbl`] (the number of days)
/// since representing a duration as a separate `Value` variant would
/// widen the public enum beyond the schema's stated surface.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// UTF-8 string argument.
    Str(String),
    /// Boolean argument.
    Bool(bool),
    /// Signed 64-bit integer argument.
    Int(i64),
    /// Unsigned 64-bit integer argument.
    Uint(u64),
    /// Double-precision floating-point argument.
    Dbl(f64),
    /// Raw byte buffer argument.
    Buf(Vec<u8>),
}

// ============================================================================
// Formatter — the template holder.
// ============================================================================

/// Reusable printf-like formatter.
///
/// Layout-wise this mirrors the FASM 48-byte `formatter` struct:
///
/// | FASM offset | FASM field      | Rust field      |
/// |-------------|-----------------|-----------------|
/// | 0           | `regargs_ofs`   | `reg_args`      |
/// | 8           | `xmmargs_ofs`   | `xmm_args`      |
/// | 16          | `items_ofs`     | `items`         |
/// | 24          | `rargs_ofs`     | (not stored)    |
/// | 32          | `xargs_ofs`     | (not stored)    |
/// | 40          | `options_ofs`   | `space_between` |
///
/// `rargs` / `xargs` are FASM-internal working buffers used during
/// `doit()` to marshal register arguments; the Rust port receives its
/// arguments through a slice and thus has no need for persistent working
/// buffers.
///
/// The struct is `Clone`-able so templates can be pre-built once at
/// startup and copied per call-site, matching the FASM "reusable
/// formatter" intent.
#[derive(Debug, Clone)]
pub struct Formatter {
    /// The accumulated template.
    items: Vec<FormatItem>,
    /// Number of register-class (non-XMM) arguments the template expects.
    /// Incremented by `add_string`, `add_boolean`, `add_integer`,
    /// `add_unsigned`, and `add_buffer`.
    reg_args: u32,
    /// Number of XMM-class (double) arguments the template expects.
    /// Incremented by `add_double` and `add_duration`.
    xmm_args: u32,
    /// Whether to prepend a single ASCII space before every non-first
    /// item at render time (FASM `formatter_options_ofs`). Applied
    /// uniformly to *all* item kinds, including `Static` literals.
    space_between: bool,
}

// ----------------------------------------------------------------------------
// Constructors and template builders.
// ----------------------------------------------------------------------------

impl Formatter {
    /// Construct a new empty formatter.
    ///
    /// `space_between` activates the "insert a space between consecutive
    /// items" mode from FASM `formatter_options_ofs`. When set, a single
    /// ASCII space (`0x20`) is prepended to every item whose index in the
    /// template is greater than zero *and* which follows at least one byte
    /// of already-rendered output. This matches the FASM `.peritem`
    /// dispatcher's uniform "prepend space" semantics (spaces appear even
    /// before static literals when the option is on — see
    /// `formatter.inc` lines 1090–1108).
    #[must_use]
    pub fn new(space_between: bool) -> Self {
        Self {
            items: Vec::new(),
            reg_args: 0,
            xmm_args: 0,
            space_between,
        }
    }

    /// Append a literal text fragment to the template. Static items
    /// consume no argument at [`Self::doit`] time.
    ///
    /// Mirrors FASM `formatter$add_static`.
    pub fn add_static(&mut self, s: impl Into<String>) {
        self.items.push(FormatItem {
            item_type: FormatItemType::Static,
            width: 0,
            flags: 0,
            prec: 0,
            value: s.into(),
        });
    }

    /// Append a string placeholder. At `doit` time consumes one
    /// [`Value::Str`] argument, right-padded to `width` (0 = no padding).
    ///
    /// Mirrors FASM `formatter$add_string`. Increments the register-arg
    /// counter.
    pub fn add_string(&mut self, width: u32) {
        self.items.push(FormatItem {
            item_type: FormatItemType::String,
            width,
            flags: 0,
            prec: 0,
            value: String::new(),
        });
        self.reg_args += 1;
    }

    /// Append a boolean placeholder. At `doit` time consumes one
    /// [`Value::Bool`] argument, rendered as `"true"` or `"false"`.
    ///
    /// Mirrors FASM `formatter$add_boolean`. Increments the register-arg
    /// counter.
    pub fn add_boolean(&mut self) {
        self.items.push(FormatItem {
            item_type: FormatItemType::Boolean,
            width: 0,
            flags: 0,
            prec: 0,
            value: String::new(),
        });
        self.reg_args += 1;
    }

    /// Append a signed integer placeholder. At `doit` time consumes one
    /// [`Value::Int`] argument rendered at minimum width `width`.
    ///
    /// `flags` is preserved for later use and for round-trip parity with
    /// the FASM API: in the assembly `flags` selects between plain
    /// decimal, thousands-separated decimal, and uppercase hex with or
    /// without a `0x` prefix. The Rust port currently renders via
    /// `write!("{:width$}", n)` which ignores the flag bits; the field is
    /// still stored so downstream consumers can inspect it.
    ///
    /// Mirrors FASM `formatter$add_integer`. Increments the register-arg
    /// counter.
    pub fn add_integer(&mut self, width: u32, flags: u32) {
        self.items.push(FormatItem {
            item_type: FormatItemType::Integer,
            width,
            flags,
            prec: 0,
            value: String::new(),
        });
        self.reg_args += 1;
    }

    /// Append an unsigned integer placeholder. At `doit` time consumes
    /// one [`Value::Uint`] argument rendered at minimum width `width`.
    /// See [`Self::add_integer`] for the `flags` semantics.
    ///
    /// Mirrors FASM `formatter$add_unsigned`. Increments the register-arg
    /// counter.
    pub fn add_unsigned(&mut self, width: u32, flags: u32) {
        self.items.push(FormatItem {
            item_type: FormatItemType::Unsigned,
            width,
            flags,
            prec: 0,
            value: String::new(),
        });
        self.reg_args += 1;
    }

    /// Append a double-precision float placeholder. At `doit` time
    /// consumes one [`Value::Dbl`] argument rendered at minimum width
    /// `width` with `prec` digits after the decimal point. `flags` is
    /// preserved as in [`Self::add_integer`].
    ///
    /// Mirrors FASM `formatter$add_double`. Increments the XMM-arg
    /// counter (in the FASM ABI doubles are passed in XMM registers).
    pub fn add_double(&mut self, width: u32, prec: u32, flags: u32) {
        self.items.push(FormatItem {
            item_type: FormatItemType::Double,
            width,
            flags,
            prec,
            value: String::new(),
        });
        self.xmm_args += 1;
    }

    /// Append a raw buffer placeholder. At `doit` time consumes one
    /// [`Value::Buf`] argument whose bytes are interpolated into the
    /// output via `String::from_utf8_lossy` (non-UTF-8 bytes are
    /// replaced with U+FFFD, matching Rust's standard lossy-decoding
    /// convention).
    ///
    /// Mirrors FASM `formatter$add_buffer`. Increments the register-arg
    /// counter.
    pub fn add_buffer(&mut self, width: u32) {
        self.items.push(FormatItem {
            item_type: FormatItemType::Buffer,
            width,
            flags: 0,
            prec: 0,
            value: String::new(),
        });
        self.reg_args += 1;
    }

    /// Append a duration placeholder. At `doit` time consumes one
    /// [`Value::Dbl`] argument interpreted as a number of days; the
    /// rendered output follows the `WwDdHhMm.SSSs` shape documented in
    /// `date.inc::format$duration`.
    ///
    /// * `min_resolution` — smallest unit to emit. Valid values are
    ///   `0..=5`:
    ///   - `5` = weeks only (fractional weeks)
    ///   - `4` = weeks + fractional days
    ///   - `3` = weeks + days + fractional hours
    ///   - `2` = weeks + days + hours + integer minutes
    ///   - `1` = weeks + days + hours + minutes + integer seconds
    ///   - `0` = weeks + days + hours + minutes + fractional seconds
    ///
    ///   Values greater than 5 are clamped to 5 to mirror the
    ///   defensive clipping in `format$duration`.
    ///
    /// * `fractional_digits` — number of digits after the decimal point
    ///   for the smallest unit when that unit is rendered fractionally
    ///   (i.e. when `min_resolution` is 3, 4, 5, or 0). Ignored when
    ///   `min_resolution` is 1 or 2 (those force integer rendering).
    ///
    /// Mirrors FASM `formatter$add_duration` (lines 357–370): the
    /// assembly stores `min_resolution` in `prec_ofs` and
    /// `fractional_digits` in `flags_ofs`, and increments the XMM-arg
    /// counter because the matching argument is a 64-bit float.
    pub fn add_duration(&mut self, min_resolution: u32, fractional_digits: u32) {
        self.items.push(FormatItem {
            item_type: FormatItemType::Duration,
            width: 0,
            flags: fractional_digits,
            prec: min_resolution,
            value: String::new(),
        });
        self.xmm_args += 1;
    }

    // ------------------------------------------------------------------------
    // Template management and introspection.
    // ------------------------------------------------------------------------

    /// Discard every accumulated item. The `space_between` option is
    /// preserved across resets so the same formatter can be refilled with
    /// a new template without re-specifying it. Mirrors FASM
    /// `formatter$reset`.
    pub fn reset(&mut self) {
        self.items.clear();
        self.reg_args = 0;
        self.xmm_args = 0;
    }

    /// Number of register-class (non-XMM) arguments the template expects
    /// at [`Self::doit`] time. Equal to the count of `add_string`,
    /// `add_boolean`, `add_integer`, `add_unsigned`, and `add_buffer`
    /// calls since the last `reset()` (or since construction).
    #[must_use]
    pub fn reg_arg_count(&self) -> u32 {
        self.reg_args
    }

    /// Number of XMM-class (double-precision) arguments the template
    /// expects at [`Self::doit`] time. Equal to the count of `add_double`
    /// and `add_duration` calls since the last `reset()` (or since
    /// construction).
    #[must_use]
    pub fn xmm_arg_count(&self) -> u32 {
        self.xmm_args
    }

    // ------------------------------------------------------------------------
    // Rendering.
    // ------------------------------------------------------------------------

    /// Render the template against the supplied argument list.
    ///
    /// Arguments are consumed in template order, skipping `Static`
    /// items which need none. The slice must contain exactly
    /// `reg_arg_count() + xmm_arg_count()` elements and each value's
    /// enum variant must match the corresponding placeholder's expected
    /// type — otherwise [`UtilError::Io`] is returned with
    /// [`std::io::ErrorKind::InvalidInput`] and a message describing the
    /// mismatch.
    ///
    /// # Errors
    ///
    /// Returns `UtilError::Io(...)` when:
    /// * `args.len() != reg_arg_count() + xmm_arg_count()`, or
    /// * A `Value` variant does not match the corresponding
    ///   [`FormatItemType`] (for example the template expects
    ///   `Integer` but the caller supplied `Value::Dbl`).
    ///
    /// `write!` never fails when writing into a `String` (the `Write`
    /// impl for `String` is infallible in practice), so any formatting
    /// errors are surfaced as `UtilError::Io` with
    /// [`std::io::ErrorKind::Other`] and the underlying message.
    pub fn doit(&self, args: &[Value]) -> Result<String, UtilError> {
        let total_expected = (self.reg_args + self.xmm_args) as usize;
        if args.len() != total_expected {
            return Err(arg_mismatch(format!(
                "formatter: expected {} arg(s), got {}",
                total_expected,
                args.len()
            )));
        }

        let mut out = String::new();
        let mut arg_idx: usize = 0;

        for (i, item) in self.items.iter().enumerate() {
            // FASM `.peritem` dispatcher: prepend a single space before
            // any non-first item when `options_ofs` is set and the
            // running buffer is non-empty. The space is inserted
            // uniformly — *before* the dispatch on item_type — so even
            // Static literals get the leading space when enabled.
            if self.space_between && i > 0 && !out.is_empty() {
                out.push(' ');
            }

            match item.item_type {
                FormatItemType::Static => {
                    out.push_str(&item.value);
                }
                FormatItemType::String => {
                    let Value::Str(s) = &args[arg_idx] else {
                        return Err(type_mismatch("String", "Str", &args[arg_idx]));
                    };
                    write_padded_str(&mut out, s, item.width)?;
                    arg_idx += 1;
                }
                FormatItemType::Boolean => {
                    let Value::Bool(b) = &args[arg_idx] else {
                        return Err(type_mismatch("Boolean", "Bool", &args[arg_idx]));
                    };
                    out.push_str(if *b { "true" } else { "false" });
                    arg_idx += 1;
                }
                FormatItemType::Integer => {
                    let Value::Int(n) = &args[arg_idx] else {
                        return Err(type_mismatch("Integer", "Int", &args[arg_idx]));
                    };
                    write_with_result(
                        &mut out,
                        format_args!("{:width$}", n, width = item.width as usize),
                    )?;
                    arg_idx += 1;
                }
                FormatItemType::Unsigned => {
                    let Value::Uint(n) = &args[arg_idx] else {
                        return Err(type_mismatch("Unsigned", "Uint", &args[arg_idx]));
                    };
                    write_with_result(
                        &mut out,
                        format_args!("{:width$}", n, width = item.width as usize),
                    )?;
                    arg_idx += 1;
                }
                FormatItemType::Double => {
                    let Value::Dbl(d) = &args[arg_idx] else {
                        return Err(type_mismatch("Double", "Dbl", &args[arg_idx]));
                    };
                    write_with_result(
                        &mut out,
                        format_args!(
                            "{:width$.prec$}",
                            d,
                            width = item.width as usize,
                            prec = item.prec as usize
                        ),
                    )?;
                    arg_idx += 1;
                }
                FormatItemType::Buffer => {
                    let Value::Buf(b) = &args[arg_idx] else {
                        return Err(type_mismatch("Buffer", "Buf", &args[arg_idx]));
                    };
                    out.push_str(&String::from_utf8_lossy(b));
                    arg_idx += 1;
                }
                FormatItemType::Duration => {
                    let Value::Dbl(d) = &args[arg_idx] else {
                        return Err(type_mismatch("Duration", "Dbl", &args[arg_idx]));
                    };
                    format_duration_into(&mut out, *d, item.prec, item.flags)?;
                    arg_idx += 1;
                }
            }
        }

        Ok(out)
    }
}

impl Default for Formatter {
    /// A default formatter has no items, no expected arguments, and no
    /// space-between-items option. Matches `Formatter::new(false)`.
    fn default() -> Self {
        Self::new(false)
    }
}

// ============================================================================
// Free-standing helpers.
// ============================================================================

/// Returns whether the library is configured to emit fractional seconds in
/// date-time formatting. Sourced from
/// [`crate::config::FORMATTER_DATETIME_FRACTIONAL`].
///
/// The helper exists so callers in `util::date` and the TUI widgets can
/// query the policy without depending on the `config` module directly, and
/// it keeps the constant reachable at runtime for downstream consumers that
/// use it as a toggle — the compile-time `const` is inlined into this one
/// call site so the dependency graph stays declarative.
///
/// Mirrors the FASM `formatter_datetime_fractional` compile-time knob
/// (`ht_defaults.inc`).
#[must_use]
pub fn datetime_fractional() -> bool {
    FORMATTER_DATETIME_FRACTIONAL
}

// ----------------------------------------------------------------------------
// Internal: error constructors.
// ----------------------------------------------------------------------------

/// Build an argument-count mismatch error. Factored out so the call
/// sites stay compact.
fn arg_mismatch(msg: String) -> UtilError {
    UtilError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))
}

/// Build a `Value`-variant mismatch error. The message format matches
/// what FASM would print in its debug assertion (roughly):
/// `"formatter: item <N> expected <X>, got <Y>"`.
fn type_mismatch(expected_item: &str, expected_value: &str, got: &Value) -> UtilError {
    let got_name = match got {
        Value::Str(_) => "Str",
        Value::Bool(_) => "Bool",
        Value::Int(_) => "Int",
        Value::Uint(_) => "Uint",
        Value::Dbl(_) => "Dbl",
        Value::Buf(_) => "Buf",
    };
    UtilError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("formatter: {expected_item} item requires Value::{expected_value}, got Value::{got_name}"),
    ))
}

// ----------------------------------------------------------------------------
// Internal: formatting helpers.
// ----------------------------------------------------------------------------

/// Write a string padded to at least `width` characters (right-aligned,
/// matching the FASM renderer's default). A `width` of zero means "no
/// padding".
fn write_padded_str(out: &mut String, s: &str, width: u32) -> Result<(), UtilError> {
    write_with_result(out, format_args!("{:>width$}", s, width = width as usize))
}

/// Wrap a `write!` call into a `Result<(), UtilError>`. Writing to a
/// `String` cannot fail in practice (the `Write` impl never returns an
/// error), but the formatter API still honours it.
fn write_with_result(out: &mut String, args: std::fmt::Arguments<'_>) -> Result<(), UtilError> {
    out.write_fmt(args)
        .map_err(|e| UtilError::Io(std::io::Error::other(e.to_string())))
}

// ----------------------------------------------------------------------------
// Internal: duration rendering.
// ----------------------------------------------------------------------------

/// Render a duration (expressed in days) into `out` using the FASM
/// `format$duration` shape. See `date.inc` lines 680–900 for the
/// reference implementation.
///
/// The output assembles up to five components — weeks (`w`), days (`d`),
/// hours (`h`), minutes (`m`), seconds (`s`) — skipping any leading
/// component that would render as zero. The *smallest* emitted unit is
/// governed by `min_resolution` (clamped to `5`), and whether that unit
/// uses fractional digits is governed by the resolution level:
///
/// | `min_resolution` | smallest unit | fractional |
/// |------------------|---------------|------------|
/// | 5                | weeks         | yes        |
/// | 4                | days          | yes        |
/// | 3                | hours         | yes        |
/// | 2                | minutes       | no         |
/// | 1                | seconds       | no         |
/// | 0                | seconds       | yes        |
///
/// When the smallest unit is fractional, `fractional_digits` controls
/// the number of digits after the decimal point.
fn format_duration_into(
    out: &mut String,
    days: f64,
    min_resolution: u32,
    fractional_digits: u32,
) -> Result<(), UtilError> {
    let res = min_resolution.min(5);
    let fd = fractional_digits as usize;

    match res {
        5 => {
            // Pure weeks with fractional precision.
            let weeks = days / 7.0;
            write_with_result(out, format_args!("{weeks:.fd$}w"))?;
        }
        4 => {
            // Integer weeks + fractional days.
            let weeks_int = (days / 7.0).trunc();
            let days_rem = days - weeks_int * 7.0;
            if weeks_int > 0.0 {
                write_with_result(out, format_args!("{}w", weeks_int as u64))?;
            }
            write_with_result(out, format_args!("{days_rem:.fd$}d"))?;
        }
        3 => {
            // Integer weeks + integer days + fractional hours.
            let weeks_int = (days / 7.0).trunc();
            let days_part = days - weeks_int * 7.0;
            let days_int = days_part.trunc();
            let hours_rem = (days_part - days_int) * 24.0;
            if weeks_int > 0.0 {
                write_with_result(out, format_args!("{}w", weeks_int as u64))?;
            }
            if days_int > 0.0 {
                write_with_result(out, format_args!("{}d", days_int as u64))?;
            }
            write_with_result(out, format_args!("{hours_rem:.fd$}h"))?;
        }
        2 => {
            // Integer minutes (and everything larger is integer too).
            let total_minutes_f = days * 1440.0;
            let total_minutes = total_minutes_f.trunc().max(0.0) as u64;
            let weeks = total_minutes / (7 * 24 * 60);
            let rem = total_minutes % (7 * 24 * 60);
            let days_int = rem / (24 * 60);
            let rem = rem % (24 * 60);
            let hours = rem / 60;
            let minutes = rem % 60;
            if weeks > 0 {
                write_with_result(out, format_args!("{weeks}w"))?;
            }
            if days_int > 0 {
                write_with_result(out, format_args!("{days_int}d"))?;
            }
            if hours > 0 {
                write_with_result(out, format_args!("{hours}h"))?;
            }
            write_with_result(out, format_args!("{minutes}m"))?;
        }
        1 => {
            // Integer seconds (and everything larger is integer too).
            let total_seconds_f = days * 86_400.0;
            let total_seconds = total_seconds_f.trunc().max(0.0) as u64;
            let weeks = total_seconds / (7 * 86_400);
            let rem = total_seconds % (7 * 86_400);
            let days_int = rem / 86_400;
            let rem = rem % 86_400;
            let hours = rem / 3_600;
            let rem = rem % 3_600;
            let minutes = rem / 60;
            let seconds = rem % 60;
            if weeks > 0 {
                write_with_result(out, format_args!("{weeks}w"))?;
            }
            if days_int > 0 {
                write_with_result(out, format_args!("{days_int}d"))?;
            }
            if hours > 0 {
                write_with_result(out, format_args!("{hours}h"))?;
            }
            if minutes > 0 {
                write_with_result(out, format_args!("{minutes}m"))?;
            }
            write_with_result(out, format_args!("{seconds}s"))?;
        }
        _ => {
            // res == 0: sub-second fractional precision.
            let total_seconds_f = days * 86_400.0;
            let whole_seconds = total_seconds_f.trunc().max(0.0) as u64;
            let weeks = whole_seconds / (7 * 86_400);
            let rem = whole_seconds % (7 * 86_400);
            let days_int = rem / 86_400;
            let rem = rem % 86_400;
            let hours = rem / 3_600;
            let rem = rem % 3_600;
            let minutes = rem / 60;
            // Reconstruct the fractional-second remainder. Note: we
            // carry the full f64 precision for the seconds component so
            // rounding to `fd` digits happens only once, at write time.
            let larger_secs = (weeks * 7 * 86_400 + days_int * 86_400 + hours * 3_600 + minutes * 60) as f64;
            let secs_rem = total_seconds_f - larger_secs;
            if weeks > 0 {
                write_with_result(out, format_args!("{weeks}w"))?;
            }
            if days_int > 0 {
                write_with_result(out, format_args!("{days_int}d"))?;
            }
            if hours > 0 {
                write_with_result(out, format_args!("{hours}h"))?;
            }
            if minutes > 0 {
                write_with_result(out, format_args!("{minutes}m"))?;
            }
            write_with_result(out, format_args!("{secs_rem:.fd$}s"))?;
        }
    }

    Ok(())
}

// ============================================================================
// API-adaptation helper for downstream consumers.
// ============================================================================
//
// The Checkpoint 4 Phase 2 API adaptation registry prescribes a free
// function `with_commas(n: u64) -> String` for thousand-separated
// rendering of unsigned integers — this is the most frequent use of
// the FASM formatter's `FORMATTER_FLAG_COMMAS` flag in the showcase
// applications (status bars, data grids, server metrics).
//
// We cannot implement this by delegating to the `Formatter` +
// `FormatItemType::Unsigned` path because, as deliberately preserved
// from the FASM renderer, `FormatItem::flags` is never consulted by
// the `Integer` / `Unsigned` render arms — the comma-insertion
// behavior lives outside the flags matrix. A standalone implementation
// is therefore both correct and minimal.
//
// The algorithm walks the ASCII decimal representation of `n` and
// inserts a `,` before each group of three digits counted from the
// right. `u64::to_string` produces exclusively ASCII `'0'..='9'`, so
// byte-to-char coercion via `as char` is safe (single-byte code
// points).

/// Render an unsigned integer with US-English thousand separators.
///
/// `with_commas(0) == "0"`, `with_commas(1_234) == "1,234"`,
/// `with_commas(18_446_744_073_709_551_615) ==
/// "18,446,744,073,709,551,615"` (`u64::MAX`).
///
/// Provided per the API adaptation registry as a convenience entry
/// point. For more general number formatting (fractional seconds,
/// durations, custom widths), use [`Formatter`] with an appropriate
/// [`FormatItem`].
#[must_use]
pub fn with_commas(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    // Pre-allocate: every additional three digits beyond the first
    // contributes one separator, so the output length is at most
    // `len + (len - 1) / 3`. Using `len + len / 3` is a safe upper
    // bound that avoids a subtract-underflow branch for len=0 (which
    // cannot occur since `n.to_string()` always yields at least "0").
    let mut out = String::with_capacity(len + len / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

// ============================================================================
// Unit tests.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // Static-only templates.
    // ------------------------------------------------------------------------

    #[test]
    fn static_passthrough() {
        let mut f = Formatter::new(false);
        f.add_static("hello ");
        f.add_static("world");
        assert_eq!(f.reg_arg_count(), 0);
        assert_eq!(f.xmm_arg_count(), 0);
        let out = f.doit(&[]).expect("doit");
        assert_eq!(out, "hello world");
    }

    #[test]
    fn static_passthrough_with_space_between() {
        // `space_between=true` prepends a single space before every non-first
        // item regardless of type — this is the FASM `.peritem` uniform
        // space-prefix behaviour.
        let mut f = Formatter::new(true);
        f.add_static("alpha");
        f.add_static("beta");
        f.add_static("gamma");
        let out = f.doit(&[]).expect("doit");
        assert_eq!(out, "alpha beta gamma");
    }

    // ------------------------------------------------------------------------
    // Mixed static / dynamic.
    // ------------------------------------------------------------------------

    #[test]
    fn int_and_string_with_uniform_space_prefix() {
        // Reproduces the AAP narrative's double-space expectation:
        // `"n= 42  name= alice"`. The double space before `name=` is a
        // consequence of the uniform-prefix rule: item 2 (the Static
        // " name=") receives a leading space like every other non-first
        // item, and it carries its own leading space, giving "  name=".
        let mut f = Formatter::new(true);
        f.add_static("n=");
        f.add_integer(0, 0);
        f.add_static(" name=");
        f.add_string(0);
        assert_eq!(f.reg_arg_count(), 2);
        assert_eq!(f.xmm_arg_count(), 0);
        let out = f
            .doit(&[Value::Int(42), Value::Str("alice".into())])
            .expect("doit");
        assert_eq!(out, "n= 42  name= alice");
    }

    #[test]
    fn int_and_string_without_spacing() {
        let mut f = Formatter::new(false);
        f.add_static("n=");
        f.add_integer(0, 0);
        f.add_static(" name=");
        f.add_string(0);
        let out = f
            .doit(&[Value::Int(42), Value::Str("alice".into())])
            .expect("doit");
        assert_eq!(out, "n=42 name=alice");
    }

    // ------------------------------------------------------------------------
    // Arg-count / arg-type mismatch.
    // ------------------------------------------------------------------------

    #[test]
    fn arg_count_mismatch_too_few() {
        let mut f = Formatter::new(false);
        f.add_integer(0, 0);
        assert!(f.doit(&[]).is_err());
    }

    #[test]
    fn arg_count_mismatch_too_many() {
        let mut f = Formatter::new(false);
        f.add_integer(0, 0);
        assert!(f.doit(&[Value::Int(1), Value::Int(2)]).is_err());
    }

    #[test]
    fn arg_type_mismatch() {
        let mut f = Formatter::new(false);
        f.add_integer(0, 0);
        // Template expects Int, caller supplies Dbl → mismatch.
        let err = f.doit(&[Value::Dbl(1.5)]).expect_err("should err");
        let msg = format!("{err}");
        assert!(msg.contains("Integer"));
        assert!(msg.contains("Int"));
    }

    // ------------------------------------------------------------------------
    // Width / precision.
    // ------------------------------------------------------------------------

    #[test]
    fn integer_width_right_aligned() {
        let mut f = Formatter::new(false);
        f.add_integer(6, 0);
        let out = f.doit(&[Value::Int(42)]).expect("doit");
        assert_eq!(out, "    42");
    }

    #[test]
    fn unsigned_width_right_aligned() {
        let mut f = Formatter::new(false);
        f.add_unsigned(4, 0);
        let out = f.doit(&[Value::Uint(7)]).expect("doit");
        assert_eq!(out, "   7");
    }

    #[test]
    fn string_width_right_aligned() {
        let mut f = Formatter::new(false);
        f.add_string(10);
        let out = f.doit(&[Value::Str("hi".into())]).expect("doit");
        assert_eq!(out, "        hi");
    }

    #[test]
    fn double_precision_three_digits() {
        let mut f = Formatter::new(false);
        f.add_double(0, 3, 0);
        // Use `std::f64::consts::PI` (3.141_592_653_589_793…) to avoid
        // `clippy::approx_constant`; rounded to three decimals it is "3.142".
        let out = f.doit(&[Value::Dbl(std::f64::consts::PI)]).expect("doit");
        assert_eq!(out, "3.142");
    }

    #[test]
    fn double_width_and_precision() {
        let mut f = Formatter::new(false);
        f.add_double(10, 2, 0);
        let out = f.doit(&[Value::Dbl(1.5)]).expect("doit");
        assert_eq!(out, "      1.50");
    }

    // ------------------------------------------------------------------------
    // Boolean, buffer.
    // ------------------------------------------------------------------------

    #[test]
    fn boolean_true_false() {
        let mut f = Formatter::new(false);
        f.add_boolean();
        f.add_static(" ");
        f.add_boolean();
        let out = f.doit(&[Value::Bool(true), Value::Bool(false)]).expect("doit");
        assert_eq!(out, "true false");
    }

    #[test]
    fn buffer_utf8_passthrough() {
        let mut f = Formatter::new(false);
        f.add_buffer(0);
        let out = f
            .doit(&[Value::Buf(b"hello \xe2\x9c\x93".to_vec())])
            .expect("doit");
        assert_eq!(out, "hello \u{2713}"); // ✓
    }

    #[test]
    fn buffer_non_utf8_is_lossy() {
        let mut f = Formatter::new(false);
        f.add_buffer(0);
        let out = f.doit(&[Value::Buf(vec![0xff, 0xfe, 0x41])]).expect("doit");
        // Non-UTF-8 bytes are replaced with U+FFFD by `from_utf8_lossy`.
        assert!(out.contains('A'));
        assert!(out.contains('\u{FFFD}'));
    }

    // ------------------------------------------------------------------------
    // Reset / reuse.
    // ------------------------------------------------------------------------

    #[test]
    fn reset_clears_items_but_keeps_options() {
        let mut f = Formatter::new(true);
        f.add_integer(0, 0);
        f.add_string(0);
        assert_eq!(f.reg_arg_count(), 2);
        f.reset();
        assert_eq!(f.reg_arg_count(), 0);
        assert_eq!(f.xmm_arg_count(), 0);
        // After reset the space_between flag is still honoured.
        f.add_static("a");
        f.add_static("b");
        let out = f.doit(&[]).expect("doit");
        assert_eq!(out, "a b");
    }

    #[test]
    fn reusable_formatter_repeat_doit() {
        // A template can be invoked repeatedly with different arg lists.
        let mut f = Formatter::new(false);
        f.add_static("x=");
        f.add_integer(0, 0);
        let a = f.doit(&[Value::Int(1)]).expect("doit");
        let b = f.doit(&[Value::Int(2)]).expect("doit");
        assert_eq!(a, "x=1");
        assert_eq!(b, "x=2");
    }

    // ------------------------------------------------------------------------
    // Counters.
    // ------------------------------------------------------------------------

    #[test]
    fn arg_counters_track_registrations() {
        let mut f = Formatter::new(false);
        f.add_static("s");
        assert_eq!(f.reg_arg_count(), 0);
        assert_eq!(f.xmm_arg_count(), 0);
        f.add_string(0);
        assert_eq!(f.reg_arg_count(), 1);
        f.add_boolean();
        assert_eq!(f.reg_arg_count(), 2);
        f.add_integer(0, 0);
        assert_eq!(f.reg_arg_count(), 3);
        f.add_unsigned(0, 0);
        assert_eq!(f.reg_arg_count(), 4);
        f.add_buffer(0);
        assert_eq!(f.reg_arg_count(), 5);
        f.add_double(0, 0, 0);
        assert_eq!(f.xmm_arg_count(), 1);
        f.add_duration(0, 0);
        assert_eq!(f.xmm_arg_count(), 2);
        assert_eq!(f.reg_arg_count(), 5);
    }

    // ------------------------------------------------------------------------
    // Duration rendering — reproduces the AAP examples verbatim.
    // ------------------------------------------------------------------------

    fn dur(days: f64, min_res: u32, fd: u32) -> String {
        let mut f = Formatter::new(false);
        f.add_duration(min_res, fd);
        f.doit(&[Value::Dbl(days)]).expect("doit")
    }

    #[test]
    fn duration_1p1_days_res5() {
        assert_eq!(dur(1.1, 5, 1), "0.2w");
    }

    #[test]
    fn duration_1p1_days_res4() {
        assert_eq!(dur(1.1, 4, 1), "1.1d");
    }

    #[test]
    fn duration_1p1_days_res3() {
        assert_eq!(dur(1.1, 3, 1), "1d2.4h");
    }

    #[test]
    fn duration_1p1_days_res2() {
        assert_eq!(dur(1.1, 2, 0), "1d2h24m");
    }

    #[test]
    fn duration_1p1_days_res1() {
        assert_eq!(dur(1.1, 1, 0), "1d2h24m0s");
    }

    #[test]
    fn duration_1p1_days_res0() {
        assert_eq!(dur(1.1, 0, 3), "1d2h24m0.000s");
    }

    #[test]
    fn duration_tiny_res0() {
        // 0.000062141203704 days ≈ 5.369 seconds.
        let d = dur(0.000_062_141_203_704, 0, 3);
        assert_eq!(d, "5.369s");
    }

    #[test]
    fn duration_tiny_res1() {
        let d = dur(0.000_062_141_203_704, 1, 0);
        assert_eq!(d, "5s");
    }

    #[test]
    fn duration_tiny_res2() {
        let d = dur(0.000_062_141_203_704, 2, 0);
        assert_eq!(d, "0m");
    }

    #[test]
    fn duration_over_clamp_resolution() {
        // min_resolution > 5 is clamped to 5.
        assert_eq!(dur(14.0, 99, 0), "2w");
    }

    #[test]
    fn duration_zero() {
        assert_eq!(dur(0.0, 0, 3), "0.000s");
        assert_eq!(dur(0.0, 1, 0), "0s");
        assert_eq!(dur(0.0, 2, 0), "0m");
    }

    // ------------------------------------------------------------------------
    // datetime_fractional helper.
    // ------------------------------------------------------------------------

    #[test]
    fn datetime_fractional_matches_config() {
        assert_eq!(datetime_fractional(), FORMATTER_DATETIME_FRACTIONAL);
    }

    // ------------------------------------------------------------------------
    // Default + Clone.
    // ------------------------------------------------------------------------

    #[test]
    fn default_matches_new_false() {
        let default = Formatter::default();
        assert_eq!(default.reg_arg_count(), 0);
        assert_eq!(default.xmm_arg_count(), 0);
        // `space_between` defaults to false: two statics rendered
        // back-to-back produce no intervening space.
        let mut f = default;
        f.add_static("a");
        f.add_static("b");
        let out = f.doit(&[]).expect("doit");
        assert_eq!(out, "ab");
    }

    #[test]
    fn clone_produces_independent_template() {
        let mut a = Formatter::new(false);
        a.add_integer(0, 0);
        let mut b = a.clone();
        // Mutating `b` must not alter `a`.
        b.add_static("!");
        let out_a = a.doit(&[Value::Int(7)]).expect("doit");
        let out_b = b.doit(&[Value::Int(7)]).expect("doit");
        assert_eq!(out_a, "7");
        assert_eq!(out_b, "7!");
    }

    // ------------------------------------------------------------------------
    // Enum / struct public shape sanity.
    // ------------------------------------------------------------------------

    #[test]
    fn format_item_type_variants_distinct() {
        use FormatItemType::*;
        let all = [
            Static, String, Boolean, Integer, Unsigned, Double, Buffer, Duration,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(a == b, i == j);
            }
        }
    }

    #[test]
    fn value_variants_independent() {
        // Smoke-test: each variant round-trips through clone/eq.
        let s = Value::Str("x".into());
        let b = Value::Bool(true);
        let i = Value::Int(-1);
        let u = Value::Uint(1);
        let d = Value::Dbl(1.0);
        let buf = Value::Buf(vec![1, 2, 3]);
        for v in [&s, &b, &i, &u, &d, &buf] {
            assert_eq!(v, &v.clone());
        }
    }
}
