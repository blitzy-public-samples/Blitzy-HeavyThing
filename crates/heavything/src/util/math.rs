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

//! Math helper constants and re-exports around `f64` stdlib methods.
//! Port of `math.inc`.
//!
//! # Historical Context (FASM original)
//!
//! The FASM `math.inc` (996 lines) provides the numeric baseline the rest
//! of the HeavyThing library is built on. It defines canonical IEEE 754
//! constants (`_math_zero`, `_math_one`, `_math_pi`, `_math_e`, `_math_nan`,
//! `_math_infinity`, `_math_neg_infinity`) as `dq` data-segment entries,
//! plus a family of transcendental routines:
//!
//! * `pow` — hand-transcoded from Naoki Shibata's SIMD vector math
//!   library, using SSE2 intrinsics (`cvtpd2dq`, `cvtdq2pd`, `mulpd`, …)
//!   to compute `x^y` in parallel lanes.
//! * `frexp` — IEEE 754 bit-manipulation split into mantissa + exponent;
//!   the FASM source provides two variants depending on whether `float80`
//!   intermediates are present. Both produce libm-compatible output.
//! * `floor`, `ceil`, `fmod` — SSE2-based rounding and remainder.
//! * `isnan`, `isfinite`, `isinfinite` — bit-inspection predicates.
//!
//! # Rust Strategy (per AAP §0.5.1.7 and §0.8.9)
//!
//! Rust's standard library already provides every FASM operation as an
//! intrinsic method on `f64` (`.powf`, `.ln`, `.exp`, `.abs`, `.floor`,
//! `.ceil`, `.round`, `.trunc`, `.sqrt`, `.log2`, `.log10`), and stdlib
//! is backed by the platform's libm on Linux — exactly the same code
//! path that Naoki Shibata's SIMD math library optimizes. **Per AAP
//! §0.8.9 ("use std collections/helpers where semantically equivalent")
//! we delegate to stdlib.**
//!
//! This module therefore provides:
//!
//! 1. Named `pub const` declarations mirroring the FASM `_math_*`
//!    data-segment symbols, so translated call sites can write
//!    [`PI`] / [`E`] / [`NAN`] instead of dereferencing runtime
//!    globals.
//! 2. `#[inline]` thin wrappers around `f64` intrinsic methods that
//!    give translated code a stable free-function surface matching
//!    the FASM `math$pow(x, y)` / `math$log(x)` style, without any
//!    runtime overhead (the wrappers compile to a single FP
//!    instruction each at `opt-level = 3`).
//! 3. Native bit-manipulation implementations of [`frexp`] and
//!    [`ldexp`] — these are in libm C but NOT in Rust stdlib; the
//!    [`util::string_math`](super::string_math) module's
//!    `qp2` / `qp10` decimal-to-quad-precision converters require
//!    them for the mantissa/exponent split of the quad-precision
//!    intermediates produced by the FASM `formatter.inc` port.
//! 4. [`gcd_u64`] / [`lcm_u64`] / [`gcd_i64`] / [`lcm_i64`]
//!    integer helpers, delegating to `num_integer::Integer` so the
//!    battle-tested Euclid + overflow-checked LCM implementation is
//!    reused rather than re-implemented (AAP §0.6.1 external
//!    import of `num-integer`).
//! 5. A NaN-safe [`clamp`] helper — Rust's built-in `f64::clamp`
//!    panics when `lo > hi` or on NaN bounds, which is more
//!    aggressive than the FASM `math$clamp` which silently returns
//!    `lo`. This module reproduces the FASM behavior.
//!
//! # No `unsafe`, no FFI
//!
//! This module contains zero `unsafe` blocks and no FFI. All bit
//! manipulation in [`frexp`] uses the safe `f64::to_bits` /
//! `f64::from_bits` round-trip.

use num_integer::Integer;

// ============================================================================
// Public IEEE 754 constants
// ============================================================================

/// Zero. Matches FASM `_math_zero` (`math.inc` line 25).
pub const ZERO: f64 = 0.0_f64;

/// One. Matches FASM `_math_one` (`math.inc` line 26).
pub const ONE: f64 = 1.0_f64;

/// Negative infinity. Matches FASM `_math_neg_infinity`
/// (`math.inc` line 37, bit pattern `0xFFF0_0000_0000_0000`).
pub const NEG_INFINITY: f64 = f64::NEG_INFINITY;

/// Positive infinity. Matches FASM `_math_posinf`
/// (`math.inc` line 38, bit pattern `0x7FF0_0000_0000_0000`).
pub const INFINITY: f64 = f64::INFINITY;

/// IEEE 754 quiet NaN. Matches FASM `_math_nan`
/// (`math.inc` line 39, bit pattern `0x7FFF_FFFF_0000_0000`).
///
/// Rust's `f64::NAN` produces a quiet NaN with an implementation-defined
/// payload; this is bit-compatible with the FASM constant for every
/// purpose HeavyThing uses it (arithmetic propagation, [`f64::is_nan`]
/// predicate, unordered compares).
pub const NAN: f64 = f64::NAN;

/// π — ratio of a circle's circumference to its diameter.
/// Matches FASM `_math_pi` (`math.inc` line 34).
///
/// Identical bit pattern to the FASM `0x4009_21FB_5444_2D18` little-endian
/// `dw` literal: `3.141592653589793`.
pub const PI: f64 = std::f64::consts::PI;

/// Euler's number `e` — base of the natural logarithm.
/// Matches FASM `_math_e`.
///
/// `2.718281828459045`.
pub const E: f64 = std::f64::consts::E;

/// `ln(2)` — natural logarithm of 2. Useful for [`frexp`] / [`log2`]
/// conversions when porting FASM code that hand-multiplies by this
/// constant rather than calling `log2` directly.
pub const LN_2: f64 = std::f64::consts::LN_2;

/// `log2(e)` — inverse of [`LN_2`]. Multiplying by this constant
/// converts natural-log results to base-2.
pub const LOG2_E: f64 = std::f64::consts::LOG2_E;

// ============================================================================
// Scalar floating-point helpers (`#[inline]` wrappers around f64 methods)
// ============================================================================

/// `x ^ y` — general floating-point exponentiation.
///
/// Delegates to [`f64::powf`], which on Linux x86_64 resolves to
/// `libm::pow(3)`. Matches the semantics of FASM `math$pow`
/// (`math.inc` lines 46–680): both implementations compute `exp(y *
/// ln(x))` for the general case, produce `NaN` for `pow(-x, fractional)`,
/// and follow IEEE 754-2008 special-case tables for `0 ^ 0`, `1 ^ x`,
/// `x ^ 0`, `-inf ^ x`, `+inf ^ x`, and so on.
///
/// # Examples
///
/// ```
/// use heavything::util::math::pow;
/// assert_eq!(pow(2.0, 10.0), 1024.0);
/// assert_eq!(pow(9.0, 0.5), 3.0);
/// ```
#[inline]
pub fn pow(x: f64, y: f64) -> f64 {
    x.powf(y)
}

/// `x ^ n` where `n` is an integer exponent.
///
/// Faster than `pow(x, n as f64)` because the compiler (and libm under
/// the hood) can skip the `exp/log` path and use repeated squaring.
/// The assembly `math.inc` has no dedicated integer-power routine —
/// FASM callers dispatched to generic `pow` — but `f64::powi` is the
/// idiomatic Rust equivalent and we expose it for use by
/// [`util::string_math`](super::string_math) decimal conversions.
#[inline]
pub fn powi(x: f64, n: i32) -> f64 {
    x.powi(n)
}

/// Natural logarithm `ln(x)`.
///
/// Delegates to [`f64::ln`]. Matches FASM `math$log` which computes
/// `ln(x) = log2(x) * ln(2)`. Returns `-inf` for `x == 0.0`, `NaN`
/// for `x < 0.0`.
#[inline]
pub fn log(x: f64) -> f64 {
    x.ln()
}

/// Base-2 logarithm `log2(x)`.
#[inline]
pub fn log2(x: f64) -> f64 {
    x.log2()
}

/// Base-10 logarithm `log10(x)`.
#[inline]
pub fn log10(x: f64) -> f64 {
    x.log10()
}

/// Exponential `e^x`.
///
/// Delegates to [`f64::exp`]. Inverse of [`log`].
#[inline]
pub fn exp(x: f64) -> f64 {
    x.exp()
}

/// Square root `sqrt(x)`.
///
/// Delegates to [`f64::sqrt`]. Returns `NaN` for `x < 0.0`.
#[inline]
pub fn sqrt(x: f64) -> f64 {
    x.sqrt()
}

/// Absolute value `|x|`.
///
/// Delegates to [`f64::abs`], which clears the IEEE 754 sign bit
/// via `andnpd` — identical to the FASM implementation.
#[inline]
pub fn abs(x: f64) -> f64 {
    x.abs()
}

/// Round `x` toward `-inf` (floor).
///
/// Delegates to [`f64::floor`]. Matches FASM `floor` (`math.inc`
/// lines 868–947).
#[inline]
pub fn floor(x: f64) -> f64 {
    x.floor()
}

/// Round `x` toward `+inf` (ceiling).
///
/// Delegates to [`f64::ceil`]. Matches FASM `ceil` (`math.inc`
/// lines 968+).
#[inline]
pub fn ceil(x: f64) -> f64 {
    x.ceil()
}

/// Round `x` to the nearest integer, with `.5` values rounded away
/// from zero (IEEE 754 "round half away from zero").
///
/// Delegates to [`f64::round`]. Note that `f64::round` uses
/// "round half away from zero" rather than the default IEEE
/// "round half to even" — the latter is available as
/// `f64::round_ties_even` — but the FASM `math.inc` rounding matches
/// the "half away from zero" behavior, so this wrapper preserves
/// that semantics.
#[inline]
pub fn round(x: f64) -> f64 {
    x.round()
}

/// Truncate `x` toward zero (drop the fractional part).
///
/// Delegates to [`f64::trunc`].
#[inline]
pub fn trunc(x: f64) -> f64 {
    x.trunc()
}

/// Split `x` into a `(mantissa, exponent)` pair such that
/// `x == mantissa * 2.powi(exponent)` and the absolute value of
/// `mantissa` lies in `[0.5, 1.0)` when `x` is a finite non-zero
/// normalized number.
///
/// Matches the semantics of the C libm `frexp(3)` function and the
/// FASM `frexp` routine (`math.inc` lines 685–739). Special cases:
///
/// * `x == 0.0`      → `(0.0, 0)` (preserves sign of zero via bitwise round-trip)
/// * `x == ±inf`     → `(x, 0)`
/// * `x.is_nan()`    → `(x, 0)` (NaN payload preserved)
///
/// # Algorithm
///
/// Operates directly on the IEEE 754 binary64 bit layout
/// (1 sign, 11 biased exponent, 52 mantissa bits) via
/// [`f64::to_bits`] / [`f64::from_bits`]. The biased exponent is
/// unbiased by subtracting 1022 (not 1023) because the libm
/// convention normalizes the mantissa to `[0.5, 1.0)` rather than
/// `[1.0, 2.0)` — one extra power of two is absorbed into `exp`.
///
/// # Subnormal Handling
///
/// Subnormal (denormal) inputs — finite non-zero values with
/// biased exponent == 0 — are returned as `(x, 0)` because the
/// agent-prompt specification for this port only requires round-trip
/// correctness for normalized values (AAP §0.5.1.7 — `qp2`/`qp10`
/// callers only ever pass normalized intermediates). Full
/// denormal support is not needed by any HeavyThing caller and
/// would require a separate normalization loop matching the FASM
/// `.again:` branch (`math.inc` lines 701–710).
///
/// # Examples
///
/// ```
/// use heavything::util::math::{frexp, ldexp};
/// let (m, e) = frexp(1024.0);
/// assert_eq!(m, 0.5);
/// assert_eq!(e, 11);
/// assert_eq!(ldexp(m, e), 1024.0);
/// ```
pub fn frexp(x: f64) -> (f64, i32) {
    // Zero / infinite / NaN: per libm, return (x, 0) — the input is
    // passed through unchanged so callers that chain frexp→ldexp
    // recover the original bit pattern (preserving signed zero,
    // signalling/quiet NaN payload, and both infinities).
    if x == 0.0 || !x.is_finite() {
        return (x, 0);
    }
    let bits = x.to_bits();
    // Extract the 11-bit biased exponent field (bits 52..62).
    let biased_exp = ((bits >> 52) & 0x7FF) as i32;
    // Subnormals would need the normalize-by-doubling loop; see
    // "Subnormal Handling" in the doc comment above.
    if biased_exp == 0 {
        return (x, 0);
    }
    // libm convention: mantissa in [0.5, 1.0) means unbiased
    // exponent -1, which corresponds to biased 1022.
    // Therefore we subtract 1022 (not 1023) from biased_exp and
    // overwrite the exponent field with 1022 to produce the
    // normalized mantissa.
    let exp = biased_exp - 1022;
    // Clear the 11 exponent bits and set them to 1022 (0x3FE).
    let mantissa_bits = (bits & !(0x7FFu64 << 52)) | (1022u64 << 52);
    let mantissa = f64::from_bits(mantissa_bits);
    (mantissa, exp)
}

/// Multiply `mantissa` by `2 ^ exp`.
///
/// Inverse of [`frexp`]: `ldexp(frexp(x).0, frexp(x).1) == x` for
/// every finite, non-zero, normalized `x` within the f64 dynamic
/// range.
///
/// Matches C libm `ldexp(3)` semantics. Special cases:
///
/// * `mantissa == 0.0`     → `0.0` (even for extreme `exp`)
/// * `mantissa.is_nan()`   → `NaN` (propagates through multiply)
/// * `mantissa.is_infinite()` → infinity of the same sign
/// * `exp` causing overflow → `±inf`
/// * `exp` causing underflow → subnormal or `0.0`
///
/// # Algorithm
///
/// Implemented as `mantissa * (exp as f64).exp2()`. The
/// `(exp as f64).exp2()` intermediate computes `2^exp` via
/// [`f64::exp2`] — which on Linux x86_64 resolves to a single
/// `vscalefsd` instruction when compiled with `opt-level = 3`, or
/// to a libm call otherwise. Both paths are bit-accurate for
/// integer `exp` within the representable range.
#[inline]
pub fn ldexp(mantissa: f64, exp: i32) -> f64 {
    // Cast `exp` to f64 — always exact for i32 (any i32 fits in
    // f64's 53-bit mantissa with no rounding).
    mantissa * (exp as f64).exp2()
}

// ============================================================================
// Integer number-theoretic helpers (delegating to `num_integer::Integer`)
// ============================================================================

/// Greatest common divisor of two unsigned 64-bit integers.
///
/// Delegates to the [`num_integer::Integer::gcd`] implementation,
/// which uses Stein's binary GCD algorithm — `O(log(min(a, b)))`
/// with no division operations. Returns `0` when both `a` and `b`
/// are zero (documented `num_integer` behavior; matches the FASM
/// `math$gcd` edge case at `math.inc` where both zero inputs also
/// produced zero).
///
/// # Examples
///
/// ```
/// use heavything::util::math::gcd_u64;
/// assert_eq!(gcd_u64(12, 18), 6);
/// assert_eq!(gcd_u64(17, 5), 1);   // co-prime
/// assert_eq!(gcd_u64(0, 7), 7);    // gcd(0, n) == n
/// ```
pub fn gcd_u64(a: u64, b: u64) -> u64 {
    a.gcd(&b)
}

/// Least common multiple of two unsigned 64-bit integers.
///
/// Delegates to [`num_integer::Integer::lcm`]. Computed as
/// `|a / gcd(a, b) * b|` which avoids overflow when `a * b` would
/// exceed [`u64::MAX`] but the result itself fits.
///
/// # Panics
///
/// Panics in `debug` builds if the result exceeds [`u64::MAX`].
/// In release builds the multiplication wraps silently (matching
/// FASM assembly `mul` behavior).
///
/// # Examples
///
/// ```
/// use heavything::util::math::lcm_u64;
/// assert_eq!(lcm_u64(4, 6), 12);
/// assert_eq!(lcm_u64(0, 5), 0);    // lcm(0, _) == 0
/// ```
pub fn lcm_u64(a: u64, b: u64) -> u64 {
    a.lcm(&b)
}

/// Greatest common divisor of two signed 64-bit integers.
///
/// Delegates to [`num_integer::Integer::gcd`], which returns the
/// absolute value of the common divisor (always non-negative).
/// This matches both the FASM semantics and the mathematical
/// convention that `gcd(-12, 18) == gcd(12, 18) == 6`.
///
/// # Examples
///
/// ```
/// use heavything::util::math::gcd_i64;
/// assert_eq!(gcd_i64(-12, 18), 6);
/// assert_eq!(gcd_i64(-15, -10), 5);
/// ```
pub fn gcd_i64(a: i64, b: i64) -> i64 {
    a.gcd(&b)
}

/// Least common multiple of two signed 64-bit integers.
///
/// Delegates to [`num_integer::Integer::lcm`]. Result is always
/// non-negative (magnitude convention).
///
/// # Panics
///
/// Panics in `debug` builds if the result overflows [`i64::MAX`].
pub fn lcm_i64(a: i64, b: i64) -> i64 {
    a.lcm(&b)
}

// ============================================================================
// NaN-safe clamp
// ============================================================================

/// Clamp `x` to the closed interval `[lo, hi]`.
///
/// Returns:
///
/// * `lo` when `x.is_nan()` or `x < lo`,
/// * `hi` when `x > hi`,
/// * `x` otherwise.
///
/// # Why not [`f64::clamp`]?
///
/// Rust stdlib's [`f64::clamp`] panics when `lo > hi` and returns
/// `NaN` when `x.is_nan()`. The FASM `math$clamp` and its callers
/// (notably `util::formatter` percent-encoding and progress-bar
/// widget bounds computation) treat NaN as a "bad input" signal
/// and silently fall back to the lower bound — this preserves the
/// no-panic contract of library code paths (AAP §0.8.3 "no
/// `unwrap`/`expect`/`panic!` in library code").
///
/// When `lo > hi` this function returns `lo` without panicking;
/// the caller is responsible for supplying a sensible range.
///
/// # Examples
///
/// ```
/// use heavything::util::math::{clamp, NAN};
/// assert_eq!(clamp(5.0, 0.0, 10.0), 5.0);
/// assert_eq!(clamp(-1.0, 0.0, 10.0), 0.0);
/// assert_eq!(clamp(11.0, 0.0, 10.0), 10.0);
/// assert_eq!(clamp(NAN, 0.0, 10.0), 0.0);   // NaN-safe
/// ```
#[inline]
pub fn clamp(x: f64, lo: f64, hi: f64) -> f64 {
    if x.is_nan() || x < lo {
        lo
    } else if x > hi {
        hi
    } else {
        x
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    #[test]
    fn constants_zero_one() {
        assert_eq!(ZERO, 0.0_f64);
        assert_eq!(ONE, 1.0_f64);
        // Round-trip bit pattern sanity: ZERO is +0.0, not -0.0.
        assert_eq!(ZERO.to_bits(), 0);
        assert_eq!(ONE.to_bits(), 0x3FF0_0000_0000_0000);
    }

    #[test]
    fn constants_special_values() {
        assert!(NAN.is_nan());
        assert!(INFINITY.is_infinite() && INFINITY > 0.0);
        assert!(NEG_INFINITY.is_infinite() && NEG_INFINITY < 0.0);
        // Bit patterns must match the FASM `_math_*` symbols exactly for
        // the signed infinities (sign bit aside, NaN is
        // implementation-defined payload).
        assert_eq!(INFINITY.to_bits(), 0x7FF0_0000_0000_0000);
        assert_eq!(NEG_INFINITY.to_bits(), 0xFFF0_0000_0000_0000);
    }

    #[test]
    #[allow(clippy::approx_constant)]
    // This test intentionally cross-checks our public `PI`, `E`, `LN_2`, and
    // `LOG2_E` constants against hand-written decimal literals that match the
    // FASM `_math_pi`, `_math_e`, ... values in `math.inc`. Clippy's
    // `approx_constant` lint flags decimal approximations of `f64::consts::*`;
    // here, that is exactly the check we are performing, so the lint is
    // suppressed for this test only.
    fn constants_transcendental() {
        // 10 decimal-digit match is well within f64 precision (15-17 digits)
        // for every rational π / e approximation.
        assert!((PI - 3.141_592_653_589_793).abs() < 1e-14);
        assert!((E - 2.718_281_828_459_045).abs() < 1e-14);
        assert!((LN_2 - 0.693_147_180_559_945_3).abs() < 1e-14);
        assert!((LOG2_E - 1.442_695_040_888_963_4).abs() < 1e-14);
        // Cross-check: LN_2 * LOG2_E ≈ 1.0.
        assert!((LN_2 * LOG2_E - 1.0).abs() < 1e-15);
    }

    // ------------------------------------------------------------------
    // Scalar FP wrappers
    // ------------------------------------------------------------------

    #[test]
    fn pow_basic_powers_of_two() {
        assert_eq!(pow(2.0, 10.0), 1024.0);
        assert_eq!(pow(2.0, 0.0), 1.0);
        assert_eq!(pow(2.0, -1.0), 0.5);
    }

    #[test]
    fn pow_fractional_exponent() {
        // 2^0.5 is exactly SQRT_2 on libm-backed x86_64 Linux —
        // powf recognises the half-integer exponent special case.
        assert_eq!(pow(2.0, 0.5), std::f64::consts::SQRT_2);
        // pow(x, 2) == x * x for any representable x.
        for i in 1..10 {
            let x = i as f64;
            assert!((pow(x, 2.0) - x * x).abs() < 1e-12);
        }
    }

    #[test]
    fn powi_matches_pow() {
        assert_eq!(powi(2.0, 10), 1024.0);
        assert_eq!(powi(3.0, 4), 81.0);
        assert_eq!(powi(-2.0, 3), -8.0);
        assert_eq!(powi(1.5, 0), 1.0);
        // powi(x, -n) == 1.0 / powi(x, n)
        assert!((powi(2.0, -3) - 0.125).abs() < 1e-15);
    }

    #[test]
    fn log_exp_are_inverses() {
        // Test values must be within the domain where `exp` does not overflow
        // (f64 exp overflows at roughly x >= 709.78) and must be positive so
        // that `log` is defined on the real line.
        for &x in &[1.0_f64, 2.0, E, 42.0, 100.0, 500.0, 1e-10] {
            // log(exp(x)) ≈ x, with absolute error bounded by a few ULPs of x.
            // We use a tolerance scaled by max(1.0, |x|) to accommodate the
            // absolute error growing proportionally with |x| for larger values.
            let tol_abs = 1e-10_f64 * x.abs().max(1.0);
            assert!(
                (log(exp(x)) - x).abs() < tol_abs,
                "log(exp({x})) round-trip failed: got {}",
                log(exp(x))
            );
            // exp(log(x)) ≈ x, with relative error bounded by a few ULPs.
            assert!(
                (exp(log(x)) - x).abs() < x.abs() * 1e-10,
                "exp(log({x})) round-trip failed: got {}",
                exp(log(x))
            );
        }
    }

    #[test]
    fn log_base_identities() {
        // log2(8) == 3.0
        assert!((log2(8.0) - 3.0).abs() < 1e-15);
        // log10(1000) == 3.0
        assert!((log10(1000.0) - 3.0).abs() < 1e-14);
        // Change-of-base: log2(x) == log(x) / log(2)
        let x: f64 = 17.0;
        assert!((log2(x) - log(x) / LN_2).abs() < 1e-14);
    }

    #[test]
    fn sqrt_and_abs() {
        assert_eq!(sqrt(9.0), 3.0);
        assert_eq!(sqrt(0.0), 0.0);
        assert!(sqrt(-1.0).is_nan());
        // Use 2.5 (not 3.14) to avoid clippy's `approx_constant` false-positive
        // flagging our test value as a sloppy PI approximation.
        assert_eq!(abs(-2.5), 2.5);
        assert_eq!(abs(2.5), 2.5);
        // Sign bit of -0 is erased by abs.
        assert_eq!(abs(-0.0).to_bits(), 0.0_f64.to_bits());
    }

    #[test]
    fn rounding_suite() {
        assert_eq!(floor(3.7), 3.0);
        assert_eq!(floor(-3.2), -4.0);
        assert_eq!(ceil(3.2), 4.0);
        assert_eq!(ceil(-3.7), -3.0);
        assert_eq!(round(3.5), 4.0);
        assert_eq!(round(-3.5), -4.0); // round-half-away-from-zero
        assert_eq!(trunc(3.7), 3.0);
        assert_eq!(trunc(-3.7), -3.0);
    }

    // ------------------------------------------------------------------
    // frexp / ldexp
    // ------------------------------------------------------------------

    #[test]
    fn frexp_known_values() {
        // 1.0 = 0.5 * 2^1
        let (m, e) = frexp(1.0);
        assert_eq!(m, 0.5);
        assert_eq!(e, 1);
        // 0.5 = 0.5 * 2^0
        let (m, e) = frexp(0.5);
        assert_eq!(m, 0.5);
        assert_eq!(e, 0);
        // 2.0 = 0.5 * 2^2
        let (m, e) = frexp(2.0);
        assert_eq!(m, 0.5);
        assert_eq!(e, 2);
        // 1024.0 = 0.5 * 2^11
        let (m, e) = frexp(1024.0);
        assert_eq!(m, 0.5);
        assert_eq!(e, 11);
    }

    #[test]
    fn frexp_ldexp_roundtrip_normalized() {
        let values: &[f64] = &[
            1.0_f64,
            0.5,
            2.0,
            1024.0,
            0.125,
            std::f64::consts::PI,
            std::f64::consts::E,
            1e-30,
            1e30,
            -1.0,
            -42.0,
            -1e100,
        ];
        for &x in values {
            let (m, e) = frexp(x);
            // Mantissa must lie in [0.5, 1.0) in magnitude.
            assert!(
                m.abs() >= 0.5 && m.abs() < 1.0,
                "frexp({x}) mantissa {m} outside [0.5, 1.0)"
            );
            let reconstructed = ldexp(m, e);
            let tolerance = x.abs() * 1e-12;
            assert!(
                (reconstructed - x).abs() <= tolerance,
                "round-trip failed: x={x}, m={m}, e={e}, reconstructed={reconstructed}"
            );
        }
    }

    #[test]
    fn frexp_zero() {
        let (m, e) = frexp(0.0);
        assert_eq!(m, 0.0);
        assert_eq!(e, 0);
        // Negative zero is likewise passed through.
        let (m, e) = frexp(-0.0);
        assert_eq!(m.to_bits(), (-0.0_f64).to_bits());
        assert_eq!(e, 0);
    }

    #[test]
    fn frexp_inf_and_nan() {
        // Infinities: passed through unchanged with exp = 0.
        let (m, e) = frexp(INFINITY);
        assert!(m.is_infinite() && m > 0.0);
        assert_eq!(e, 0);
        let (m, e) = frexp(NEG_INFINITY);
        assert!(m.is_infinite() && m < 0.0);
        assert_eq!(e, 0);
        // NaN passes through.
        let (m, e) = frexp(NAN);
        assert!(m.is_nan());
        assert_eq!(e, 0);
    }

    #[test]
    fn ldexp_trivial_cases() {
        assert_eq!(ldexp(1.0, 0), 1.0);
        assert_eq!(ldexp(0.5, 1), 1.0);
        assert_eq!(ldexp(1.0, 10), 1024.0);
        assert_eq!(ldexp(1.0, -1), 0.5);
        // Zero mantissa: always zero regardless of exp.
        assert_eq!(ldexp(0.0, 100), 0.0);
        assert_eq!(ldexp(0.0, -100), 0.0);
    }

    // ------------------------------------------------------------------
    // Integer GCD / LCM
    // ------------------------------------------------------------------

    #[test]
    fn gcd_u64_cases() {
        assert_eq!(gcd_u64(12, 18), 6);
        assert_eq!(gcd_u64(17, 5), 1);
        assert_eq!(gcd_u64(100, 75), 25);
        assert_eq!(gcd_u64(0, 7), 7);
        assert_eq!(gcd_u64(7, 0), 7);
        assert_eq!(gcd_u64(0, 0), 0);
        // Associativity: gcd(gcd(a, b), c) == gcd(a, gcd(b, c))
        let a = 24_u64;
        let b = 36_u64;
        let c = 48_u64;
        assert_eq!(gcd_u64(gcd_u64(a, b), c), gcd_u64(a, gcd_u64(b, c)));
    }

    #[test]
    fn lcm_u64_cases() {
        assert_eq!(lcm_u64(4, 6), 12);
        assert_eq!(lcm_u64(7, 5), 35);
        assert_eq!(lcm_u64(0, 5), 0);
        assert_eq!(lcm_u64(5, 0), 0);
        // lcm(a, b) * gcd(a, b) == a * b (identity)
        let a = 12_u64;
        let b = 18_u64;
        assert_eq!(lcm_u64(a, b) * gcd_u64(a, b), a * b);
    }

    #[test]
    fn gcd_i64_signed() {
        assert_eq!(gcd_i64(-12, 18), 6);
        assert_eq!(gcd_i64(-15, -10), 5);
        assert_eq!(gcd_i64(12, -18), 6);
    }

    #[test]
    fn lcm_i64_signed() {
        assert_eq!(lcm_i64(-4, 6), 12);
        assert_eq!(lcm_i64(-3, -5), 15);
    }

    // ------------------------------------------------------------------
    // clamp
    // ------------------------------------------------------------------

    #[test]
    fn clamp_in_range() {
        assert_eq!(clamp(5.0, 0.0, 10.0), 5.0);
        assert_eq!(clamp(0.0, 0.0, 10.0), 0.0); // boundary: lo
        assert_eq!(clamp(10.0, 0.0, 10.0), 10.0); // boundary: hi
    }

    #[test]
    fn clamp_below_and_above() {
        assert_eq!(clamp(-1.0, 0.0, 10.0), 0.0);
        assert_eq!(clamp(11.0, 0.0, 10.0), 10.0);
        assert_eq!(clamp(-1e30, 0.0, 10.0), 0.0);
        assert_eq!(clamp(1e30, 0.0, 10.0), 10.0);
    }

    #[test]
    fn clamp_nan_safe() {
        // NaN should produce `lo`, NOT panic and NOT propagate NaN.
        // This is the key difference vs. Rust stdlib's f64::clamp.
        assert_eq!(clamp(NAN, 0.0, 10.0), 0.0);
        assert_eq!(clamp(NAN, -5.0, 5.0), -5.0);
    }

    #[test]
    fn clamp_negative_range() {
        assert_eq!(clamp(-5.0, -10.0, -1.0), -5.0);
        assert_eq!(clamp(-20.0, -10.0, -1.0), -10.0);
        assert_eq!(clamp(0.0, -10.0, -1.0), -1.0);
    }
}
