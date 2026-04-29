// Rust translation © 2026, licensed under GPL-3.0-or-later.
//
// Derived from the HeavyThing assembly library:
//   Copyright © 2015–2018 2 Ton Digital, Jeff Marrison <info@2ton.com.au>
//
// Portions of the underlying FASM routines were inspired by Agner Fog's
// asmlib (© 2003–2012 Agner Fog, GPL-3.0-or-later). See the comment
// header at the top of `memfuncs.inc` in the repository root for the
// verbatim asmlib copyright notice.
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

//! Memory function primitives — port of `memfuncs.inc` (1,822 lines of
//! FASM assembly).
//!
//! This module provides thin, safe wrappers around `core::slice`
//! primitives that mirror the `memfuncs.inc` API
//! (`strlen_latin1` / `memset` / `memset16` / `memset32` / `memcmp` /
//! `memcmp16` / `memcmp32` / `memmove` / `memcpy` / `memreverse` /
//! `memxor`). Per AAP §0.5.1.6 — *"Slice copy / fill / compare
//! wrappers; largely thin re-exports of [`<[T]>::copy_from_slice`],
//! [`<[T]>::fill`], [`<[T]>::eq`]"* — the Rust port delegates to
//! LLVM-optimised stdlib routines rather than hand-rolling the
//! 32/16/8/4/2/1-byte chunked unrolled loops present in the FASM
//! sources. On `x86_64-unknown-linux-gnu` (the sole target per
//! AAP §0.3.2) LLVM emits SSE2 / AVX code for these patterns at
//! `opt-level = 3`, matching or exceeding the hand-written assembly's
//! throughput.
//!
//! The three FASM `memset*` width variants collapse to a single
//! generic [`fill`] thanks to monomorphisation; likewise the three
//! `memcmp*` width variants collapse to [`eq`] (equality) and [`cmp`]
//! (signed order). The FASM `memcpy` / `memmove` distinction is
//! preserved through the separate [`copy`] and [`copy_within`]
//! entry points, where `copy` targets disjoint buffers and
//! `copy_within` correctly handles overlapping ranges inside a single
//! slice (AAP §0.5.1.6).
//!
//! Per AAP §0.8.9 (*"MUST use std collections where semantically
//! equivalent"*) and the `ds`-folder std-only rule, this file pulls
//! in **no third-party crates** and contains **zero `unsafe` blocks**
//! (the `ds` subsystem's unsafe budget is `0–1` sites; this file meets
//! the preferred `0`).
//!
//! # Constant-time comparison
//!
//! [`constant_time_eq`] is a lightweight, best-effort constant-time
//! byte-slice equality helper for the few call sites in `ds` /
//! adjacent subsystems that need time-independent comparison without
//! pulling `ring` into the `ds` layer. **For cryptographic code
//! paths** (TLS MAC verification, SSH HMAC checks, scrypt tag
//! checks), callers SHOULD use
//! [`ring::constant_time::verify_slices_are_equal`](https://docs.rs/ring)
//! per AAP §0.7.4, which uses inline assembly to guarantee constant
//! time on supported targets.

use crate::error::DsError;

/// Fills `slice` with `value`.
///
/// Unified replacement for the FASM `memset` / `memset16` / `memset32`
/// triplet — Rust's generic [`<[T]>::fill`] handles every element
/// width via monomorphisation. LLVM emits SSE2 `movdqa` /
/// `pshufd`-equivalent code for `u8` / `u16` / `u32` under the
/// default `x86_64-unknown-linux-gnu` target, matching the FASM
/// hand-rolled SIMD loop (`memfuncs.inc` lines 95–551).
#[inline]
pub fn fill<T: Copy>(slice: &mut [T], value: T) {
    slice.fill(value);
}

/// Copies `src` into the beginning of `dst`.
///
/// Returns [`DsError::BufferOverflow`] if `dst.len() < src.len()` —
/// the length-checked counterpart to the FASM `memcpy` routine
/// (`memfuncs.inc` lines 1349–1737), which assumes the caller has
/// pre-validated the sizes.
///
/// Internally delegates to [`<[T]>::copy_from_slice`]; LLVM emits
/// `rep movsb` / vectorised copy code for the non-overlapping case.
/// For overlapping copies within a single slice, use
/// [`copy_within`] instead.
#[inline]
pub fn copy<T: Copy>(dst: &mut [T], src: &[T]) -> Result<(), DsError> {
    if dst.len() < src.len() {
        return Err(DsError::BufferOverflow {
            requested: src.len(),
            capacity: dst.len(),
        });
    }
    dst[..src.len()].copy_from_slice(src);
    Ok(())
}

/// Copies a range within a single slice, correctly handling
/// overlapping regions.
///
/// Equivalent to the FASM `memmove` routine (`memfuncs.inc` lines
/// 935–1349), which picks forward or backward copy direction based
/// on the relative positions of source and destination to preserve
/// correctness on overlap. [`<[T]>::copy_within`] makes the same
/// decision internally.
///
/// The `src` range uses any Rust range syntax (`a..b`, `a..=b`,
/// `..b`, `a..`, `..`) via [`std::ops::RangeBounds`].
///
/// # Panics
///
/// Panics if the source range is out of bounds for `slice`, or if
/// `dst + (src.end - src.start) > slice.len()`. These mirror the
/// panics of [`<[T]>::copy_within`].
#[inline]
pub fn copy_within<T: Copy, R: std::ops::RangeBounds<usize>>(slice: &mut [T], src: R, dst: usize) {
    slice.copy_within(src, dst);
}

/// Returns `true` if `a` and `b` are element-for-element equal.
///
/// Equivalent to the FASM `memcmp` / `memcmp16` / `memcmp32` routines
/// (`memfuncs.inc` lines 551–935) specialised to the boolean-equality
/// case. Delegates to the slice [`PartialEq`] impl, which
/// short-circuits on the first mismatch — this is **not
/// constant-time**. For cryptographic comparisons use
/// [`constant_time_eq`] (or preferably
/// [`ring::constant_time::verify_slices_are_equal`](https://docs.rs/ring)
/// per AAP §0.7.4).
#[inline]
pub fn eq<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    a == b
}

/// Lexicographic order of two slices.
///
/// Returns [`std::cmp::Ordering::Less`] / `Equal` / `Greater` matching
/// the sign convention of the FASM `memcmp` routine (`memfuncs.inc`
/// lines 551–676), which returns the signed difference of the first
/// mismatching byte. Delegates to the slice [`Ord`] impl.
#[inline]
pub fn cmp<T: Ord>(a: &[T], b: &[T]) -> std::cmp::Ordering {
    a.cmp(b)
}

/// Reverses `slice` in-place.
///
/// Equivalent to the FASM `memreverse` routine (`memfuncs.inc` lines
/// 1737–1760), which performs an inward two-pointer swap from each
/// end toward the middle. Delegates to [`<[T]>::reverse`].
#[inline]
pub fn reverse<T>(slice: &mut [T]) {
    slice.reverse();
}

/// XORs `src` into `dst` element-wise — `dst[i] ^= src[i]` for
/// `i` in `0..src.len()`.
///
/// Returns [`DsError::BufferOverflow`] if `dst.len() < src.len()`.
/// Rust translation of the FASM `memxor` routine (`memfuncs.inc`
/// lines 1760–1822); LLVM auto-vectorises the `.zip()` loop into
/// SSE2 / AVX XOR instructions, matching the FASM 32-byte unrolled
/// loop's throughput.
#[inline]
pub fn xor_in_place(dst: &mut [u8], src: &[u8]) -> Result<(), DsError> {
    if dst.len() < src.len() {
        return Err(DsError::BufferOverflow {
            requested: src.len(),
            capacity: dst.len(),
        });
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
    Ok(())
}

/// Returns the byte offset of the first NUL byte (`0x00`) in
/// `bytes`, or [`None`] if none is present.
///
/// Rust translation of the FASM `strlen_latin1` routine
/// (`memfuncs.inc` lines 58–94), which scans NUL-terminated Latin-1
/// buffers using the classic word-at-a-time magic-constant trick
/// (`x - 0x01010101) & ~x & 0x80808080`). Delegates to
/// [`<[u8]>::iter`] + [`Iterator::position`]; LLVM emits a
/// vectorised search on modern targets.
///
/// Callers holding true C-style NUL-terminated strings SHOULD
/// prefer [`core::ffi::CStr::from_bytes_until_nul`] for higher-level
/// string handling; this helper is provided for direct parity with
/// `strlen_latin1` call sites that expect an `Option<usize>` index.
#[inline]
pub fn find_nul(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|&b| b == 0)
}

/// Best-effort constant-time byte-slice equality.
///
/// Returns `true` iff `a` and `b` have identical lengths and
/// identical contents. The core loop always runs to completion —
/// it does **not** short-circuit on mismatch — so the function's
/// timing does not leak the position of the first differing byte
/// via data-dependent control flow. The initial length check is a
/// cheap early-out on metadata only (lengths are almost always
/// public).
///
/// # Limitations
///
/// Rust's optimiser is permitted, in principle, to recover a
/// short-circuit once it proves the loop's accumulator is
/// deterministic, which would defeat the constant-time property.
/// For this reason the function is deliberately **not** marked
/// `#[inline]`, and cryptographic call sites (TLS MAC, SSH HMAC,
/// scrypt tag, etc.) MUST instead use
/// [`ring::constant_time::verify_slices_are_equal`](https://docs.rs/ring)
/// per AAP §0.7.4, which is implemented in inline assembly and
/// provides a much stronger guarantee.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DsError;

    // ---- fill ---------------------------------------------------------------

    #[test]
    fn test_fill_u8() {
        let mut buf = [0u8; 64];
        fill(&mut buf, 0xAA);
        assert!(buf.iter().all(|&b| b == 0xAA), "all bytes should be 0xAA");
    }

    #[test]
    fn test_fill_u32() {
        let mut buf = [0u32; 16];
        fill(&mut buf, 0xDEAD_BEEF);
        assert!(
            buf.iter().all(|&w| w == 0xDEAD_BEEF),
            "all dwords should be 0xDEADBEEF"
        );
    }

    #[test]
    fn test_fill_empty() {
        let mut buf: [u8; 0] = [];
        fill(&mut buf, 0xFF);
        // must not panic on empty input
    }

    // ---- copy ---------------------------------------------------------------

    #[test]
    fn test_copy_ok() {
        let src = [7u8; 32];
        let mut dst = [0u8; 64];
        let result = copy(&mut dst, &src);
        assert!(result.is_ok());
        assert_eq!(&dst[..32], &src[..]);
        assert!(dst[32..].iter().all(|&b| b == 0), "tail untouched");
    }

    #[test]
    fn test_copy_overflow() {
        let src = [1u8; 64];
        let mut dst = [0u8; 16];
        let result = copy(&mut dst, &src);
        match result {
            Err(DsError::BufferOverflow { requested, capacity }) => {
                assert_eq!(requested, 64);
                assert_eq!(capacity, 16);
            }
            other => panic!("expected BufferOverflow, got {other:?}"),
        }
    }

    #[test]
    fn test_copy_exact_fit() {
        let src = [9u8; 8];
        let mut dst = [0u8; 8];
        assert!(copy(&mut dst, &src).is_ok());
        assert_eq!(dst, src);
    }

    // ---- copy_within --------------------------------------------------------

    #[test]
    fn test_copy_within_overlap() {
        let mut buf = [0u8, 1, 2, 3, 4, 5];
        copy_within(&mut buf, 1..5, 0);
        assert_eq!(buf, [1, 2, 3, 4, 4, 5]);
    }

    #[test]
    fn test_copy_within_backward_overlap() {
        let mut buf = [0u8, 1, 2, 3, 4, 5];
        copy_within(&mut buf, 0..4, 2);
        assert_eq!(buf, [0, 1, 0, 1, 2, 3]);
    }

    // ---- eq -----------------------------------------------------------------

    #[test]
    fn test_eq_true() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        assert!(eq(&a, &b));
    }

    #[test]
    fn test_eq_false() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert!(!eq(&a, &b));
    }

    #[test]
    fn test_eq_different_lengths() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3, 4];
        assert!(!eq(&a, &b));
    }

    // ---- cmp ----------------------------------------------------------------

    #[test]
    fn test_cmp_less() {
        assert_eq!(cmp(b"abc", b"abd"), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_cmp_equal() {
        assert_eq!(cmp(b"hello", b"hello"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_cmp_greater() {
        assert_eq!(cmp(b"abd", b"abc"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_cmp_prefix_shorter_is_less() {
        assert_eq!(cmp(b"abc", b"abcd"), std::cmp::Ordering::Less);
    }

    // ---- reverse ------------------------------------------------------------

    #[test]
    fn test_reverse() {
        let mut buf = [1u8, 2, 3, 4];
        reverse(&mut buf);
        assert_eq!(buf, [4, 3, 2, 1]);
    }

    #[test]
    fn test_reverse_odd_length() {
        let mut buf = [1u8, 2, 3, 4, 5];
        reverse(&mut buf);
        assert_eq!(buf, [5, 4, 3, 2, 1]);
    }

    #[test]
    fn test_reverse_empty() {
        let mut buf: [u8; 0] = [];
        reverse(&mut buf);
        // must not panic
    }

    // ---- xor_in_place -------------------------------------------------------

    #[test]
    fn test_xor_in_place_ok() {
        let mut dst = [0xFFu8; 4];
        let src = [0x0Fu8; 4];
        assert!(xor_in_place(&mut dst, &src).is_ok());
        assert_eq!(dst, [0xF0u8; 4]);
    }

    #[test]
    fn test_xor_in_place_shorter_src() {
        // dst larger than src: only src.len() bytes are XORed.
        let mut dst = [0xAAu8; 8];
        let src = [0x0Fu8; 4];
        assert!(xor_in_place(&mut dst, &src).is_ok());
        assert_eq!(dst[..4], [0xA5u8; 4]);
        assert_eq!(dst[4..], [0xAAu8; 4], "tail unchanged");
    }

    #[test]
    fn test_xor_in_place_overflow() {
        let mut dst = [0u8; 3];
        let src = [1u8; 8];
        let result = xor_in_place(&mut dst, &src);
        match result {
            Err(DsError::BufferOverflow { requested, capacity }) => {
                assert_eq!(requested, 8);
                assert_eq!(capacity, 3);
            }
            other => panic!("expected BufferOverflow, got {other:?}"),
        }
    }

    #[test]
    fn test_xor_in_place_self_inverse() {
        // XORing the same value twice returns the original.
        let mut buf = [0x5Au8; 16];
        let key = [0xA5u8; 16];
        let original = buf;
        assert!(xor_in_place(&mut buf, &key).is_ok());
        assert!(xor_in_place(&mut buf, &key).is_ok());
        assert_eq!(buf, original);
    }

    // ---- find_nul -----------------------------------------------------------

    #[test]
    fn test_find_nul_some() {
        assert_eq!(find_nul(b"abc\0def"), Some(3));
    }

    #[test]
    fn test_find_nul_at_start() {
        assert_eq!(find_nul(b"\0rest"), Some(0));
    }

    #[test]
    fn test_find_nul_none() {
        assert_eq!(find_nul(b"abc"), None);
    }

    #[test]
    fn test_find_nul_empty() {
        assert_eq!(find_nul(b""), None);
    }

    // ---- constant_time_eq ---------------------------------------------------

    #[test]
    fn test_constant_time_eq_true() {
        let a = [0x5Au8, 0xA5, 0x33, 0xCC, 0x00, 0xFF];
        let b = [0x5Au8, 0xA5, 0x33, 0xCC, 0x00, 0xFF];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_false() {
        let a = [0x5Au8, 0xA5, 0x33, 0xCC];
        let b = [0x5Au8, 0xA5, 0x33, 0xCD];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_length_mismatch() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3, 4];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_empty_both() {
        let a: [u8; 0] = [];
        let b: [u8; 0] = [];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_first_byte_differs() {
        let a = [0x00u8, 0, 0, 0, 0, 0, 0, 0];
        let b = [0xFFu8, 0, 0, 0, 0, 0, 0, 0];
        assert!(!constant_time_eq(&a, &b));
    }
}
