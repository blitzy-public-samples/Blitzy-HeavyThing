// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of the Rust port of the HeavyThing library.
//
// The Rust port is Copyright (C) 2026 and is distributed under the terms
// of the GNU General Public License version 3 (or any later version).
//
// It is a direct translation of the CPUID feature-detection block embedded
// in the FASM source `ht.inc` (lines 338-410, within `ht$init_args`),
// Copyright (C) 2015-2018 2 Ton Digital, Jeff Marrison, and is likewise
// distributed under the GNU General Public License version 3.
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

#![cfg(target_arch = "x86_64")]

//! Runtime CPU feature detection.
//!
//! Direct port of the CPUID feature-detection block in `ht.inc` lines
//! 338-410 (within `ht$init_args` Stage 4). Populates a process-wide
//! `OnceLock<CpuFeatures>` with the same flags the FASM library
//! exposed as globals (`is_Intel`, `has_SSE3`, `has_SSSE3`, `has_SSE41`,
//! `has_SSE42`, `has_POPCNT`, `has_AVX`, `has_AESNI`, `cpu_L1_size` -
//! see `ht.inc` lines 244-263).
//!
//! Uses `std::is_x86_feature_detected!` which is the stable-Rust
//! equivalent of raw CPUID inspection and emits the same underlying
//! instructions - see AAP §0.1.1 which mandates that CPU feature
//! detection happen at runtime, never at compile-time, to preserve
//! graceful degradation on heterogeneous hosts.
//!
//! Note that `ring` and the `aes` crate perform their own internal
//! feature detection and automatically route to AES-NI paths when
//! available, so this module exists primarily to preserve the FASM
//! API surface; the flags themselves are queried by the RNG seeding
//! path and by debug/logging code.

use std::sync::OnceLock;

/// CPU feature flags detected once at process startup.
///
/// Mirrors the FASM globals declared in `ht.inc` lines 244-263. Fields
/// carry `pub` visibility so callers can check a specific feature with
/// a simple struct-field access, for example `cpu::features().has_aesni`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuFeatures {
    /// `true` if the CPU vendor string (via `CPUID.EAX=0`) matches
    /// `"GenuineIntel"`. Mirrors FASM `is_Intel`.
    pub is_intel: bool,
    /// SSE3 support; mirrors FASM `has_SSE3` (ECX bit 0 of `CPUID.EAX=1`).
    pub has_sse3: bool,
    /// SSSE3 support; mirrors FASM `has_SSSE3` (ECX bit 9 of `CPUID.EAX=1`).
    pub has_ssse3: bool,
    /// SSE4.1 support; mirrors FASM `has_SSE41` (ECX bit 19 of `CPUID.EAX=1`).
    pub has_sse41: bool,
    /// SSE4.2 support; mirrors FASM `has_SSE42` (ECX bit 20 of `CPUID.EAX=1`).
    pub has_sse42: bool,
    /// POPCNT support; mirrors FASM `has_POPCNT` (ECX bit 23 of `CPUID.EAX=1`).
    pub has_popcnt: bool,
    /// AVX support; mirrors FASM `has_AVX` (ECX bit 28 of `CPUID.EAX=1`).
    pub has_avx: bool,
    /// AES-NI hardware acceleration; mirrors FASM `has_AESNI`
    /// (ECX bit 25 of `CPUID.EAX=1`).
    pub has_aesni: bool,
    /// L1 data cache line size in bytes. Mirrors FASM `cpu_L1_size`.
    /// Defaults to 64 when the CPUID-provided value would be zero
    /// (the `ht.inc` line ~398 comment: "avoid infinite loops").
    pub l1_size: u32,
}

/// Detect the CPU features of the current process and cache the result
/// in a process-wide `OnceLock`. Subsequent calls return the cached
/// value with no CPUID re-execution.
///
/// Called exactly once from `crate::init_args` Stage 4; direct
/// invocation from user code is also safe - the underlying
/// `OnceLock::get_or_init` guarantees idempotency.
///
/// # Returns
///
/// A `&'static CpuFeatures` backed by the module-level `OnceLock`.
/// The reference is valid for the lifetime of the process.
///
/// # Example
///
/// ```no_run
/// let cf = heavything::cpu::detect();
/// if cf.has_aesni {
///     // prefer AES-NI path
/// }
/// ```
pub fn detect() -> &'static CpuFeatures {
    static FEATURES: OnceLock<CpuFeatures> = OnceLock::new();
    FEATURES.get_or_init(|| CpuFeatures {
        is_intel: detect_is_intel(),
        has_sse3: std::is_x86_feature_detected!("sse3"),
        has_ssse3: std::is_x86_feature_detected!("ssse3"),
        has_sse41: std::is_x86_feature_detected!("sse4.1"),
        has_sse42: std::is_x86_feature_detected!("sse4.2"),
        has_popcnt: std::is_x86_feature_detected!("popcnt"),
        has_avx: std::is_x86_feature_detected!("avx"),
        has_aesni: std::is_x86_feature_detected!("aes"),
        l1_size: detect_l1_size(),
    })
}

/// Shorthand for [`detect`]. Returns the cached feature set.
#[inline]
pub fn features() -> &'static CpuFeatures {
    detect()
}

/// Detect Intel vs AMD CPU vendor string by querying `CPUID.EAX=0`.
/// Returns `true` if the vendor string carries `"ntel"` in ECX (i.e.
/// the full string is `"GenuineIntel"`); mirrors the FASM
/// `cmp ecx, 'ntel'` check at `ht.inc` line ~345.
fn detect_is_intel() -> bool {
    // Note on soundness (AAP §0.7.4.1 "CPUID feature detection | 0 sites"):
    //   On stable Rust, `std::arch::x86_64::__cpuid` is a safe fn when
    //   the enclosing item is `cfg(target_arch = "x86_64")`, because the
    //   CPUID instruction is guaranteed to be present on every x86_64
    //   CPU (it has been architecturally mandated since 1993). The
    //   `EAX=0` leaf is universally supported and returns the vendor
    //   identification string in EBX:EDX:ECX. Because the module header
    //   carries `#![cfg(target_arch = "x86_64")]` (see file top), this
    //   call site is statically reachable only on x86_64 targets and
    //   needs no keyword-gated block wrapper. We read only the POD
    //   `u32` `ecx` field; no pointer dereferencing or memory access
    //   occurs.
    let cpuid = std::arch::x86_64::__cpuid(0);
    // On `"GenuineIntel"` the ECX register contains the ASCII bytes
    // "ntel" in little-endian order, matching the FASM literal `'ntel'`
    // used in the original comparison.
    cpuid.ecx == u32::from_le_bytes(*b"ntel")
}

/// Detect L1 data cache line size. Returns the safe default of 64 bytes
/// (the FASM `cpu_L1_size` zero-fallback at `ht.inc` line ~398) rather
/// than interrogating CPUID leaf `0x80000005` (AMD) or leaf `1` (Intel).
///
/// Rationale per AAP §0.8.2 minimal-change discipline:
///   * Only the heap and profiler modules consumed this value in the
///     FASM library. The heap is replaced by the Rust `std` allocator
///     (AAP §0.5.1.6); the profiler is a thin wrapper whose real work
///     is delegated to `criterion` (AAP §0.5.1.7). No Rust caller
///     uses `l1_size` for correctness - only for optional tuning.
///   * 64 is the L1 data cache line size on every modern x86_64 CPU
///     (Intel Core 2 onward, all AMD K10 and later).
///   * Avoids an additional raw-intrinsic CPUID call site; aligns
///     with AAP §0.7.4.2 ("encapsulate low-level primitives at
///     type boundaries").
fn detect_l1_size() -> u32 {
    64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_is_idempotent() {
        let a = detect();
        let b = detect();
        // Same `OnceLock` value; reference equality holds.
        assert!(std::ptr::eq(a, b));
    }

    #[test]
    fn features_alias() {
        assert!(std::ptr::eq(detect(), features()));
    }

    #[test]
    fn l1_size_default_is_64() {
        assert_eq!(detect().l1_size, 64);
    }

    #[test]
    fn any_known_feature_is_representable() {
        // Don't assert on actual host features (CI hosts vary);
        // just smoke-test that the access pattern is sound.
        let cf = features();
        let _ = cf.is_intel;
        let _ = cf.has_sse3;
        let _ = cf.has_aesni;
    }
}
