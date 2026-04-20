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

//! Double-to-string conversion math helpers. Port of `string_math.inc`.
//!
//! The FASM original implements the low-level math scaffolding (`string$frexp`,
//! `string$qp2`, `string$qp10`) that an assembly-language decimal-to-binary
//! conversion engine needs because assembly has no native Ryu/Grisu formatter.
//! Rust, by contrast, ships IEEE 754-compliant `f64` formatting in `std::fmt`
//! (via the Ryu algorithm), so this module intentionally stays thin:
//!
//! * [`frexp_adjusted`], [`qp2`], and [`qp10`] are retained as public helpers
//!   for API parity with the FASM library — callers that genuinely need raw
//!   powers of two or ten or an integer mantissa/exponent split can use them.
//! * [`f64_to_string`] and [`string_to_f64`] delegate directly to `std::fmt` /
//!   `str::parse`, replacing the ~2000 lines of `stringbi_*` helpers that sat
//!   below `string$frexp` in the FASM source.
//!
//! The `stringbi_*` 32-bit helpers in `string_math.inc` beyond line ~100 are
//! intentionally **not** ported — the original author noted they would one
//! day be replaced, and Ryu fills that role fully in Rust.

/// Split a finite `f64` into an integer mantissa and a binary exponent such
/// that `mantissa × 2ⁿ == x` (where `n == *exp_out`).
///
/// This matches the FASM `string$frexp` contract: after a standard IEEE 754
/// `frexp` extraction (mantissa in `[0.5, 1.0)`), the FASM helper rescales the
/// mantissa by `2⁵³` and subtracts `53` from the exponent, producing an
/// integer mantissa suitable for the decimal-conversion math downstream.
///
/// The implementation uses bit extraction on `f64::to_bits()` rather than
/// calling `libm::frexp` so that subnormals and the sign bit are handled
/// without a floating-point multiplication. The `-52` in the exponent
/// computation (rather than `-53`) accounts for the fact that we fold the
/// implicit leading `1` bit directly into `full_mantissa`, so only 52 bits of
/// rescaling remain. The invariant `mantissa × 2ⁿ == x` holds bit-for-bit for
/// every finite non-zero input.
///
/// # Edge cases
///
/// * Zero (either sign) → returns `0` with `*exp_out = 0`.
/// * Infinity / NaN → returns `0` with `*exp_out = 0` (the FASM caller never
///   invokes this path with non-finite inputs; defining deterministic zeros
///   avoids propagating undefined behavior).
/// * Subnormals → the implicit leading bit is *not* folded in, and the
///   effective exponent is `-1074` for the smallest positive subnormal.
/// * Negative finite values → the returned mantissa carries the sign.
pub fn frexp_adjusted(x: f64, exp_out: &mut i32) -> i64 {
    // Fast exit for zero (either sign) and non-finite values. IEEE `frexp`
    // leaves these undefined on the C side; defining them as (0, 0) gives
    // callers a predictable result.
    if x == 0.0 || !x.is_finite() {
        *exp_out = 0;
        return 0;
    }
    let bits = x.to_bits();
    let raw_exp = ((bits >> 52) & 0x7FF) as i32;
    let mantissa_bits = bits & 0x000F_FFFF_FFFF_FFFF;
    // Unbias the exponent. For subnormals the IEEE convention is to treat the
    // biased exponent `0` as if it were `1`, so the effective unbiased value
    // is `-1022` — matching how a subnormal's numeric value is actually
    // computed.
    let unbiased = if raw_exp == 0 { 1 - 1023 } else { raw_exp - 1023 };
    // Shift by -52 rather than the FASM source's -53 because we add the
    // implicit leading `1` to the mantissa below, promoting it one bit into
    // integer space. The product of these two adjustments is exactly the
    // FASM "multiply by 2^53 then subtract 53 from the exponent" identity.
    *exp_out = unbiased - 52;
    // Subnormals do not have an implicit leading bit; normals do.
    let full_mantissa = if raw_exp == 0 {
        mantissa_bits
    } else {
        mantissa_bits | (1u64 << 52)
    };
    // `full_mantissa` is at most (2^53 - 1) so it always fits signed without
    // overflow, and its negation is well-defined for every possible value.
    if (bits >> 63) & 1 == 1 {
        -(full_mantissa as i64)
    } else {
        full_mantissa as i64
    }
}

/// Compute `2.0_f64.powi(exp as i32)` with a cheap fast path.
///
/// For strictly positive exponents below 64, `1u64 << exp` yields the exact
/// integer power of two, which then converts losslessly to `f64` (because
/// `2⁶³ < 2⁶⁴` and every single power of two is exactly representable in
/// `f64`). For every other input — non-positive, or 64+ — we defer to
/// `f64::powi`. This mirrors the FASM `string$qp2` fast/slow-path split at
/// exactly the same boundaries (`exp > 0 && exp < 64`).
pub fn qp2(exp: i64) -> f64 {
    if exp > 0 && exp < 64 {
        (1u64 << exp) as f64
    } else {
        2.0_f64.powi(exp as i32)
    }
}

/// Compute `10.0_f64.powi(exp as i32)` with a 23-entry lookup-table fast path.
///
/// `POWERS_OF_TEN[k]` holds the exact nearest-rounded `f64` representation of
/// `10^k` for `k ∈ 0..=22`. These are the only powers of ten whose decimal
/// value is representable exactly in `f64` (the next, `10^23`, would require
/// 77 mantissa bits). For every exponent outside this range — negative, or
/// 23 or greater — we defer to `f64::powi`, matching the FASM `string$qp10`
/// slow-path boundaries verbatim.
pub fn qp10(exp: i64) -> f64 {
    const POWERS_OF_TEN: [f64; 23] = [
        1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16, 1e17,
        1e18, 1e19, 1e20, 1e21, 1e22,
    ];
    if exp >= 0 && (exp as usize) < POWERS_OF_TEN.len() {
        POWERS_OF_TEN[exp as usize]
    } else {
        10.0_f64.powi(exp as i32)
    }
}

/// Render a finite `f64` as a decimal string.
///
/// When `max_digits == 0` the output uses Rust's default `Display` formatter
/// (Ryu), producing the shortest round-tripping decimal. Otherwise the output
/// has exactly `max_digits` fractional digits after the decimal point,
/// matching the `%.*f` C-library convention that the FASM decimal engine
/// ultimately emulates.
///
/// Non-finite inputs (`NaN`, `inf`, `-inf`) format through Rust's default
/// rules (`"NaN"`, `"inf"`, `"-inf"`).
pub fn f64_to_string(x: f64, max_digits: usize) -> String {
    if max_digits == 0 {
        format!("{x}")
    } else {
        format!("{x:.max_digits$}")
    }
}

/// Parse a decimal string into `f64`.
///
/// Returns `None` when the input is empty or cannot be parsed. Delegates
/// directly to `str::parse::<f64>()`, which uses the same correctly-rounded
/// conversion path as Rust's other `f64::from_str` entry points and handles
/// scientific notation (`1.5e3`), hex literals prefixed with `0x` are *not*
/// supported (matching standard `f64::from_str` behavior).
pub fn string_to_f64(s: &str) -> Option<f64> {
    s.parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- qp2 ----------

    #[test]
    fn qp2_fast_path_boundaries() {
        // exp == 0 falls into the slow path (powi) because the condition is
        // `exp > 0`, but the result must still be 1.0.
        assert_eq!(qp2(0), 1.0);
        assert_eq!(qp2(1), 2.0);
        assert_eq!(qp2(10), 1024.0);
        // Largest exponent that stays in the fast path.
        assert_eq!(qp2(63), (1u64 << 63) as f64);
        // One step past the fast-path boundary.
        assert_eq!(qp2(64), 2.0_f64.powi(64));
        // Mantissa exact-representation boundary for `f64`.
        assert_eq!(qp2(53), 9_007_199_254_740_992.0);
    }

    #[test]
    fn qp2_slow_path_positive() {
        let expected = 2.0_f64.powi(100);
        assert_eq!(qp2(100), expected);
    }

    #[test]
    fn qp2_slow_path_negative() {
        assert_eq!(qp2(-10), 1.0 / 1024.0);
        assert_eq!(qp2(-1), 0.5);
    }

    // ---------- qp10 ----------

    #[test]
    fn qp10_table_boundaries() {
        assert_eq!(qp10(0), 1e0);
        assert_eq!(qp10(5), 1e5);
        // Last entry in the lookup table.
        assert_eq!(qp10(22), 1e22);
    }

    #[test]
    fn qp10_slow_path_positive() {
        // `1e23` is not representable exactly in IEEE 754 doubles — neither
        // the literal nor the repeated-multiply result of `powi(23)` lands on
        // the true mathematical 10^23. Compare with a relative tolerance
        // sized to a few ULPs at this magnitude.
        let v = qp10(23);
        let rel_err = (v - 1e23).abs() / 1e23;
        assert!(rel_err < 1e-14, "qp10(23) = {v}, rel_err = {rel_err}");
    }

    #[test]
    fn qp10_slow_path_negative() {
        // powi(-2) produces the same bit pattern as the literal 0.01 on
        // conforming libm implementations; validate with a tight tolerance
        // rather than exact equality to stay portable.
        assert!((qp10(-2) - 0.01).abs() < 1e-12);
        assert!((qp10(-1) - 0.1).abs() < 1e-12);
    }

    // ---------- frexp_adjusted ----------

    /// Reconstruct `x` from the `(mantissa, exp)` pair and compare.
    fn reconstruct(m: i64, e: i32) -> f64 {
        (m as f64) * 2.0_f64.powi(e)
    }

    #[test]
    fn frexp_roundtrip_one() {
        let mut e = 0i32;
        let m = frexp_adjusted(1.0, &mut e);
        // 1.0 == 2^52 × 2^-52
        assert_eq!(m, 1i64 << 52);
        assert_eq!(e, -52);
    }

    #[test]
    fn frexp_roundtrip_two() {
        let mut e = 0i32;
        let m = frexp_adjusted(2.0, &mut e);
        assert_eq!(m, 1i64 << 52);
        assert_eq!(e, -51);
        assert_eq!(reconstruct(m, e), 2.0);
    }

    #[test]
    fn frexp_roundtrip_half() {
        let mut e = 0i32;
        let m = frexp_adjusted(0.5, &mut e);
        assert_eq!(m, 1i64 << 52);
        assert_eq!(e, -53);
        assert_eq!(reconstruct(m, e), 0.5);
    }

    #[test]
    fn frexp_roundtrip_one_and_a_half() {
        let mut e = 0i32;
        let m = frexp_adjusted(1.5, &mut e);
        // 1.5 = (2^52 + 2^51) × 2^-52
        assert_eq!(m, (1i64 << 52) + (1i64 << 51));
        assert_eq!(e, -52);
        assert_eq!(reconstruct(m, e), 1.5);
    }

    #[test]
    fn frexp_negative_carries_sign() {
        let mut e = 0i32;
        let m = frexp_adjusted(-1.0, &mut e);
        assert_eq!(m, -(1i64 << 52));
        assert_eq!(e, -52);
        assert_eq!(reconstruct(m, e), -1.0);
    }

    #[test]
    fn frexp_zero_positive() {
        let mut e = 7i32; // sentinel to verify it gets overwritten
        let m = frexp_adjusted(0.0, &mut e);
        assert_eq!(m, 0);
        assert_eq!(e, 0);
    }

    #[test]
    fn frexp_zero_negative() {
        let mut e = 7i32;
        let m = frexp_adjusted(-0.0, &mut e);
        assert_eq!(m, 0);
        assert_eq!(e, 0);
    }

    #[test]
    fn frexp_infinity_is_zero() {
        let mut e = 42i32;
        let m = frexp_adjusted(f64::INFINITY, &mut e);
        assert_eq!(m, 0);
        assert_eq!(e, 0);
    }

    #[test]
    fn frexp_negative_infinity_is_zero() {
        let mut e = 42i32;
        let m = frexp_adjusted(f64::NEG_INFINITY, &mut e);
        assert_eq!(m, 0);
        assert_eq!(e, 0);
    }

    #[test]
    fn frexp_nan_is_zero() {
        let mut e = 42i32;
        let m = frexp_adjusted(f64::NAN, &mut e);
        assert_eq!(m, 0);
        assert_eq!(e, 0);
    }

    #[test]
    fn frexp_smallest_subnormal() {
        // f64::MIN_POSITIVE_SUBNORMAL isn't stable on older toolchains; use
        // `f64::from_bits(1)` which is the exact smallest positive subnormal.
        let x = f64::from_bits(1);
        let mut e = 0i32;
        let m = frexp_adjusted(x, &mut e);
        // Subnormal: mantissa == 1, exponent == 1 - 1023 - 52 == -1074
        assert_eq!(m, 1);
        assert_eq!(e, -1074);
    }

    #[test]
    fn frexp_reconstructs_various_values() {
        // Exercise the reconstruct invariant over a spread of finite doubles.
        // Values chosen to cover normals of varying magnitudes and signs; no
        // approximation of mathematical constants is intended.
        for &x in &[1.0_f64, 3.5, -4.75, 1e10, 1e-10, 12345.6789] {
            let mut e = 0i32;
            let m = frexp_adjusted(x, &mut e);
            let reconstructed = reconstruct(m, e);
            let rel_err = (reconstructed - x).abs() / x.abs().max(1.0);
            assert!(
                rel_err < 1e-12,
                "reconstruction of {x} gave {reconstructed} (m={m}, e={e})"
            );
        }
    }

    // ---------- f64_to_string / string_to_f64 ----------

    #[test]
    fn string_roundtrip_fixed_digits() {
        // Arbitrary decimal with a trailing 9 that exercises the rounding path
        // of `format!("{:.*}")`. Not an approximation of any math constant.
        let x = 1.23459_f64;
        let s = f64_to_string(x, 5);
        assert_eq!(s, "1.23459");
        let parsed = string_to_f64(&s);
        assert!(parsed.is_some());
        let y = parsed.unwrap_or(0.0);
        assert!((x - y).abs() < 1e-9);
    }

    #[test]
    fn string_default_formatting() {
        // max_digits == 0 uses Rust's default Display (Ryu), producing the
        // shortest round-tripping representation.
        let s = f64_to_string(2.5, 0);
        assert_eq!(s, "2.5");
    }

    #[test]
    fn string_to_f64_accepts_scientific() {
        let y = string_to_f64("1.5e3");
        assert!(y.is_some());
        assert_eq!(y.unwrap_or(0.0), 1500.0);
    }

    #[test]
    fn string_to_f64_rejects_garbage() {
        assert!(string_to_f64("").is_none());
        assert!(string_to_f64("not-a-number").is_none());
        assert!(string_to_f64("1.2.3").is_none());
    }

    #[test]
    fn string_to_f64_accepts_negative() {
        let y = string_to_f64("-42.5");
        assert!(y.is_some());
        assert_eq!(y.unwrap_or(0.0), -42.5);
    }
}
