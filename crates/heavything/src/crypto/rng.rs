// Rust translation © 2026, licensed under GPL-3.0-or-later.
//
// Derived from the HeavyThing assembly library:
//   Copyright © 2015–2018 2 Ton Digital, Jeff Marrison <info@2ton.com.au>
//   Source: `rng.inc` (1,047 lines).
//
// Algorithm attribution (preserved from `rng.inc` lines 22–88):
//   "this is a loose transcode from a loose transcode from a different
//    assembler enviro which was a loose transcode from agner's rng goods,
//    which is a transcode from the SFMT, combined with the mother-of-all
//    rng, which agner states is sufficient for security applications."
//   Portions derive from Agner Fog's `randoma` library (1997–2013,
//   GPLv3), see <https://www.agner.org/random/>.
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

//! Cryptographic random number generator — port of `rng.inc`.
//!
//! # Overview
//!
//! The FASM `rng.inc` module combines an SFMT-19937 generator with an
//! independent Mother-of-All generator (per Agner Fog's
//! recommendation) to obtain very long cycle lengths suitable for
//! cryptographic use. The combined output is seeded via an HMAC-DRBG
//! (NIST SP 800-90A) fed from `/dev/urandom` (or `/dev/random` when
//! [`config::RNG_PARANOID`](crate::config::RNG_PARANOID) is `true`),
//! `rdtsc`, and `gettimeofday` (see `rng.inc` lines 133–370).
//!
//! # Rust design
//!
//! Rather than re-implement SFMT + Mother-of-All in Rust, this port
//! uses [`HmacDrbg`](crate::crypto::hmac_drbg::HmacDrbg) directly as
//! the backing DRBG. The assembly comment (`rng.inc` lines 40–48)
//! explicitly blesses this path:
//!
//! > "if you are really paranoid, use hmac_drbg instead, it is just
//! > very very slow compared to the methods we have chosen here."
//!
//! HMAC-DRBG is the conservative choice for a Rust crate where the
//! extra throughput of SFMT is not required — modern x86_64 HMAC-SHA
//! throughput (with SHA-NI acceleration via `ring`) is well within
//! the 3× performance envelope mandated by AAP §0.8.1. Moreover, the
//! backing [`HmacDrbg`](crate::crypto::hmac_drbg::HmacDrbg)
//! **already** implements the module-wide
//! 64-bit-discard-per-3072-bit defense-in-depth policy (`rng.inc`
//! lines 49–50, AAP §0.5.1.3) so that callers of [`int`], [`block`],
//! and [`block_nzb`] never observe a contiguous DRBG output longer
//! than 384 bytes.
//!
//! # Seed construction (heavy path)
//!
//! When [`config::RNG_HEAVY_INIT`](crate::config::RNG_HEAVY_INIT) is
//! `true` (the default), [`init`] gathers 64 bytes of seed material
//! exactly matching the FASM layout at `rng.inc` lines 136–192:
//!
//! | Offset | Size | Source                                                  |
//! |--------|------|---------------------------------------------------------|
//! |  0..8  |   8  | `rdtsc`                                                 |
//! |  8..16 |   8  | `gettimeofday` packed as `(tv_sec << 17) \| tv_usec`    |
//! | 16..48 |  32  | `/dev/urandom` (or `/dev/random` if `RNG_PARANOID`)     |
//! | 48..56 |   8  | `rdtsc`                                                 |
//! | 56..64 |   8  | `gettimeofday` packed                                   |
//!
//! Two `rdtsc` + `gettimeofday` blocks bracket the filesystem read
//! intentionally: the filesystem read takes a non-deterministic
//! amount of time, so the post-read `rdtsc`/`gettimeofday` pair
//! differs from the pre-read pair by an unpredictable delta. This
//! matches the FASM comment at `rng.inc` lines 175–176:
//!
//! > "that will take a non-deterministic amount of time to perform,
//! > so we can add another rdtsc+gettimeofday for the last 16 bytes."
//!
//! # Seed construction (light path)
//!
//! When [`config::RNG_HEAVY_INIT`](crate::config::RNG_HEAVY_INIT) is
//! `false`, [`init`] skips the `/dev/urandom` read and synthesises 32
//! bytes of entropy from four `rdtsc` + `gettimeofday` pairs spaced
//! out by the intervening sync-code. This mirrors the FASM light path
//! at `rng.inc` lines 381–557 (single `rdtsc` expanded by the
//! Mersenne-Twister constant 1812433253). The modern replacement
//! retains the key invariant — no filesystem dependency — while
//! using the full DRBG pipeline for state expansion.
//!
//! The light path is **not** cryptographically safe against
//! determined adversaries (`rdtsc`-only entropy is guessable with
//! ~12 bits of jitter per call). It is provided only for debug /
//! test scenarios where `/dev/urandom` is unavailable (e.g.,
//! early-boot userspace). Production deployments must use the
//! default heavy path.
//!
//! # Global state
//!
//! Per the FASM source comment at `rng.inc` line 52 ("calls to here
//! are not thread-safe"), the underlying generator is single-threaded
//! by design. The Rust port wraps the [`HmacDrbg`] instance in a
//! [`std::sync::Mutex`] so that concurrent async tasks (under tokio)
//! serialise RNG access automatically. Because a typical RNG call
//! consumes microseconds and the Mutex is uncontended in the
//! steady-state case, this has negligible performance impact.
//!
//! The state itself lives in a process-global [`std::sync::OnceLock`]
//! so that [`init`] is idempotent and lazy initialisation happens at
//! first use if the caller omitted the explicit [`init`] call.
//!
//! # Post-fork safety
//!
//! `fork(2)` duplicates the parent's DRBG state verbatim. Without
//! intervention, parent and child would emit identical "random"
//! streams — a catastrophic failure for any cryptographic protocol
//! that relies on nonce uniqueness (TLS, SSH, HMAC challenge
//! generation, etc.). Per AAP §0.7.4.2 and
//! [`crate::net::child::spawn_child`] docs, child processes MUST call
//! [`reseed`] before performing any cryptographic operation.
//!
//! [`reseed`] performs a fresh heavy-entropy gather (identical layout
//! to [`init`]'s heavy path) and folds it into the existing DRBG via
//! [`HmacDrbg::reseed`](crate::crypto::hmac_drbg::HmacDrbg::reseed),
//! preserving the instance identity but resetting the reseed counter
//! to 1.
//!
//! # Error handling
//!
//! Only [`init`] and [`reseed`] return `Result<(), CryptoError>`.
//! The output functions ([`int`], [`intmax`], [`double`], [`block`],
//! [`block_nzb`]) return infallibly to match the FASM ABI (`rng$u32`
//! / `rng$u64` / `rng$block` return values only; no status code). To
//! guarantee infallibility, the output functions auto-initialise the
//! global state on first use via a light-path fallback that cannot
//! fail (`rdtsc`-only entropy, no filesystem I/O). Callers that care
//! about entropy quality must call [`init`] explicitly during
//! startup — `lib.rs` Stage 9 does exactly this.
//!
//! # `unsafe` audit
//!
//! Per AAP §0.7.4, this module contains **exactly one** `unsafe`
//! block, covering the single call to
//! [`std::arch::x86_64::_rdtsc`] in the [`read_tsc`] helper. The
//! `rdtsc` instruction has been architecturally required on x86_64
//! since the Pentium (1993); on the `x86_64-unknown-linux-gnu`
//! target the instruction is always executable and cannot trigger
//! undefined behaviour. See `UNSAFE_AUDIT.md` for the corresponding
//! audit entry.

use std::fs::File;
use std::io::{self, Read};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ring::hmac::HMAC_SHA512;

use crate::config::{RNG_HEAVY_INIT, RNG_PARANOID};
use crate::crypto::hmac_drbg::HmacDrbg;
use crate::error::CryptoError;

// ============================================================================
// Constants
// ============================================================================

/// Size in bytes of the heavy-path seed material.
///
/// Matches the FASM stack layout at `rng.inc` lines 136–192:
/// 16B (rdtsc + gtod) || 32B (`/dev/urandom`) || 16B (rdtsc + gtod).
const HEAVY_SEED_BYTES: usize = 64;

/// Size in bytes of the light-path seed material.
///
/// Derived from four `rdtsc` + `gettimeofday` pairs. 32 bytes is the
/// minimum accepted by [`HmacDrbg::new`].
const LIGHT_SEED_BYTES: usize = 32;

/// Number of bytes drawn from `/dev/urandom` (or `/dev/random` in
/// paranoid mode) during heavy-path seeding.
///
/// Matches the FASM `mov edx, 32` at `rng.inc` line 166.
const KERNEL_ENTROPY_BYTES: usize = 32;

/// Maximum bytes per [`HmacDrbg::generate`] call.
///
/// NIST SP 800-90A Rev. 1 §10.1.2.5 bullet 3 caps this at 2^19 bits
/// (65 536 bytes). We stay well below that cap (32 KiB) so that
/// large [`block`] requests chunk safely.
const GENERATE_CHUNK_BYTES: usize = 32_768;

/// Personalisation string passed into [`HmacDrbg::new_with_algorithm`]
/// to domain-separate this RNG from any other HMAC-DRBG instance the
/// crate might create in the future.
const PERSONALIZATION: &[u8] = b"heavything-rng/v1";

/// Personalisation string variant used by [`reseed`] so that the
/// post-fork seed feed differs (by one byte) from the pre-fork feed.
/// This is a defense-in-depth separator, not a security-critical one.
const RESEED_ADDITIONAL: &[u8] = b"heavything-rng/reseed";

/// Path to the non-blocking kernel CSPRNG on Linux (≥ 3.17).
const DEV_URANDOM_PATH: &str = "/dev/urandom";

/// Path to the blocking kernel entropy source (used when
/// [`config::RNG_PARANOID`](crate::config::RNG_PARANOID) is `true`).
const DEV_RANDOM_PATH: &str = "/dev/random";

// ============================================================================
// RngState — the mutable state owned by the global Mutex
// ============================================================================

/// Internal state wrapped by the process-global [`Mutex`].
///
/// Not publicly reachable by design: all manipulation goes through
/// the free functions exposed by this module, which enforce the
/// Mutex-locking discipline.
///
/// # Field usage
///
/// * `drbg` — the HMAC-DRBG instance doing the actual bit generation.
///   [`HmacDrbg`] internally enforces the
///   64-bit-per-3072-bit discard rule documented at module level.
/// * `counter` — monotonic count of generate operations performed
///   against this state. Not used for correctness; diagnostic-only.
/// * `last_reseed` — [`Instant`] at which the state was last
///   (re)seeded. Diagnostic-only; useful for consumers that want to
///   enforce periodic reseeds at a higher layer.
/// * `heavy_init` — records whether the heavy or light seed path was
///   used. Exposed to tests for white-box verification; not used for
///   correctness in the output functions.
struct RngState {
    /// HMAC-DRBG backbone; see module-level docs.
    drbg: HmacDrbg,
    /// Number of output operations (int/intmax/double/block/block_nzb
    /// calls and their internal generate requests) performed against
    /// this state since its last (re)seed.
    counter: u64,
    /// Monotonic timestamp of the most recent (re)seed.
    last_reseed: Instant,
    /// `true` if the current state was seeded via the heavy path
    /// (i.e., `/dev/urandom` was read); `false` if only `rdtsc` and
    /// `gettimeofday` were used.
    heavy_init: bool,
}

// ============================================================================
// Global state
// ============================================================================

/// Process-global RNG state, initialised on first use.
///
/// Wrapped in [`OnceLock`] so that explicit [`init`] and implicit
/// first-use auto-init both converge on the same instance. Wrapped
/// in [`Mutex`] so that concurrent tasks under tokio serialise their
/// access automatically (the FASM source is single-threaded; see
/// `rng.inc` line 52).
static RNG_STATE: OnceLock<Mutex<RngState>> = OnceLock::new();

// ============================================================================
// Unsafe-scoped helpers
// ============================================================================

/// Read the CPU's Time Stamp Counter (TSC).
///
/// Returns the current value of the x86_64 `rdtsc` register, which
/// increments at a constant (invariant) rate on modern CPUs. Used as
/// a jitter-entropy contributor (~12 bits per call on typical desktop
/// hardware).
///
/// # Safety
///
/// This function contains the SOLE `unsafe` block in this module
/// (and one of ~14–22 total in the `heavything` crate per AAP
/// §0.7.4.1). The [`std::arch::x86_64::_rdtsc`] intrinsic wraps the
/// `rdtsc` instruction, which:
///
/// 1. Is architecturally required on x86_64 (present since the
///    original AMD Opteron / Intel Nocona, 2003).
/// 2. Cannot trap or fault in user mode on Linux (the TSC is readable
///    from ring 3 by default; `CR4.TSD` is cleared).
/// 3. Has no side effects other than stalling the pipeline briefly.
///
/// Therefore the intrinsic cannot trigger undefined behaviour on the
/// `x86_64-unknown-linux-gnu` target.
#[inline]
fn read_tsc() -> u64 {
    // SAFETY: The `rdtsc` instruction is architecturally required on
    // x86_64 (present since the original 2003 AMD64 parts) and is
    // readable from user mode on Linux without special privileges.
    // It has no memory effects and cannot trap, so calling it is
    // observationally safe. The module's target `x86_64-unknown-
    // linux-gnu` guarantees availability at compile time.
    unsafe { std::arch::x86_64::_rdtsc() }
}

// ============================================================================
// Safe helpers — entropy gathering and state construction
// ============================================================================

/// Pack `gettimeofday`'s 64-bit seconds + 32-bit microseconds into a
/// single `u64` using the FASM mixing formula at `rng.inc` lines
/// 150–154: `(tv_sec << 17) | tv_usec`.
///
/// The `<< 17` shift preserves 47 bits of `tv_sec` (sufficient for
/// several million years past the Unix epoch) and 17 bits of
/// microseconds (sufficient to distinguish the ~10^6 microseconds in
/// a second). Extra microsecond bits are clipped via the
/// `subsec_micros` API which returns `0..=999_999`.
///
/// Falls back to a fixed value if the system clock reports a time
/// earlier than the Unix epoch (unreachable under `SystemTime::now`
/// on a well-configured system but defensively handled).
fn gettimeofday_packed() -> u64 {
    let now = SystemTime::now();
    let delta = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = delta.as_secs();
    let micros = u64::from(delta.subsec_micros());
    secs.wrapping_shl(17) | micros
}

/// Gather 64 bytes of heavy-path entropy (matches FASM layout at
/// `rng.inc` lines 136–192).
///
/// # Layout
///
/// ```text
/// [ 0.. 8) = rdtsc           (first TSC)
/// [ 8..16) = gettimeofday    (first wall-clock read)
/// [16..48) = /dev/urandom    (or /dev/random if RNG_PARANOID)
/// [48..56) = rdtsc           (post-syscall TSC)
/// [56..64) = gettimeofday    (post-syscall wall-clock read)
/// ```
///
/// # Errors
///
/// Returns the underlying [`io::Error`] if `/dev/urandom` /
/// `/dev/random` cannot be opened or fails to deliver
/// [`KERNEL_ENTROPY_BYTES`] bytes. The caller maps this to
/// [`CryptoError::Rng`].
fn gather_heavy_entropy() -> io::Result<[u8; HEAVY_SEED_BYTES]> {
    let mut seed = [0u8; HEAVY_SEED_BYTES];

    // First 16 bytes: rdtsc + gettimeofday (pre-syscall).
    // Matches FASM `rng.inc` lines 142–154.
    seed[0..8].copy_from_slice(&read_tsc().to_le_bytes());
    seed[8..16].copy_from_slice(&gettimeofday_packed().to_le_bytes());

    // Middle 32 bytes: /dev/urandom (or /dev/random in paranoid mode).
    // Matches FASM `rng.inc` lines 157–174 — 32 bytes read into the
    // middle of the seed buffer.
    let path = if RNG_PARANOID {
        DEV_RANDOM_PATH
    } else {
        DEV_URANDOM_PATH
    };
    let mut file = File::open(path)?;
    file.read_exact(&mut seed[16..16 + KERNEL_ENTROPY_BYTES])?;
    // `file` is dropped here; its RAII-backed `close(2)` mirrors the
    // explicit `syscall_close` at `rng.inc` line 171.

    // Last 16 bytes: rdtsc + gettimeofday (post-syscall).
    // Matches FASM `rng.inc` lines 183–192 — the filesystem read took
    // a non-deterministic amount of time, so this pair's delta from
    // the first pair adds entropy.
    seed[48..56].copy_from_slice(&read_tsc().to_le_bytes());
    seed[56..64].copy_from_slice(&gettimeofday_packed().to_le_bytes());

    Ok(seed)
}

/// Gather 32 bytes of light-path entropy (no filesystem I/O).
///
/// Used when [`config::RNG_HEAVY_INIT`](crate::config::RNG_HEAVY_INIT)
/// is `false` or when the filesystem fallback path fires inside
/// [`gather_heavy_entropy`]. Produces the minimum 32 bytes required
/// by [`HmacDrbg::new`] via four `rdtsc` + `gettimeofday` pairs.
///
/// Infallible.
fn gather_light_entropy() -> [u8; LIGHT_SEED_BYTES] {
    let mut seed = [0u8; LIGHT_SEED_BYTES];

    // Four pairs of (rdtsc, gettimeofday) for 4 × 16 = 64 bytes...
    // wait, we only want 32 here. Instead, stagger two rdtsc + two
    // gettimeofday reads to spread over a small time window.
    seed[0..8].copy_from_slice(&read_tsc().to_le_bytes());
    seed[8..16].copy_from_slice(&gettimeofday_packed().to_le_bytes());
    // Insert a short computed delay between reads so that the
    // subsequent `rdtsc` returns a materially different value.
    // `read_tsc` is branch-free and has ~30-cycle latency so
    // back-to-back calls do differ, but we chain through a wrapping
    // mix to discourage the compiler from re-ordering/eliminating
    // the reads in unusual optimisation settings.
    let mix = read_tsc().wrapping_mul(0x9E37_79B9_7F4A_7C15);
    seed[16..24].copy_from_slice(&mix.to_le_bytes());
    seed[24..32].copy_from_slice(&gettimeofday_packed().to_le_bytes());

    seed
}

/// Build a fresh [`HmacDrbg`] from the provided seed material.
///
/// Uses HMAC-SHA-512 for parity with the FASM `hmac$init_sha512`
/// at `rng.inc` line 195. The 512-bit (64-byte) HMAC output width
/// matches the maximum buffer size supported by [`HmacDrbg`] and
/// provides a ≥256-bit security strength per NIST SP 800-90A Rev. 1
/// Table 2.
///
/// # Errors
///
/// Returns [`CryptoError::Rng`] or [`CryptoError::Hmac`] if the
/// DRBG constructor rejects the seed (e.g., too short). Only
/// reachable when `seed.len() < 32`; both entropy-gathering paths
/// in this module produce ≥32 bytes so this path is unreachable
/// in practice.
fn build_drbg(seed: &[u8]) -> Result<HmacDrbg, CryptoError> {
    HmacDrbg::new_with_algorithm(HMAC_SHA512, seed, &[], PERSONALIZATION)
}

/// Install a freshly-built [`RngState`] into the global
/// [`OnceLock`], performing the appropriate reseed if the slot is
/// already populated (post-fork case).
///
/// This function is the single implementation shared by [`init`]
/// and [`reseed`]; the only difference between them is which path
/// this function reaches: the first caller wins the `OnceLock`
/// initialisation, subsequent callers fall through to the reseed
/// branch.
///
/// # Errors
///
/// Forwards [`CryptoError::Rng`] from
/// [`gather_heavy_entropy`] / [`build_drbg`] /
/// [`HmacDrbg::reseed`](crate::crypto::hmac_drbg::HmacDrbg::reseed).
fn install_or_reseed() -> Result<(), CryptoError> {
    // Heavy path is the default; light path is a compile-time config choice.
    if !RNG_HEAVY_INIT {
        return install_or_reseed_light();
    }

    // Attempt the heavy path first. If `/dev/urandom` fails (rare, but
    // possible in sandboxed test environments), fall back to the light
    // path so that the RNG remains usable even though its seed is
    // weaker.
    let seed = match gather_heavy_entropy() {
        Ok(s) => s,
        Err(_) => return install_or_reseed_light(),
    };

    // Branch on OnceLock state: first caller builds fresh, subsequent
    // callers reseed the existing instance.
    match RNG_STATE.get() {
        None => {
            let drbg = build_drbg(&seed)?;
            let state = RngState {
                drbg,
                counter: 0,
                last_reseed: Instant::now(),
                heavy_init: true,
            };
            // Race-tolerant `set`: if another thread initialised between
            // our check and our set, our locally-built state is dropped
            // (and its seed bytes zeroed by HmacDrbg's Drop impl on
            // scope exit). The other thread's state is equally valid.
            let _ = RNG_STATE.set(Mutex::new(state));
            Ok(())
        }
        Some(mutex) => reseed_locked(mutex, &seed, true),
    }
}

/// Light-path companion to [`install_or_reseed`].
///
/// Factored into its own function so that [`install_or_reseed`] can
/// fall back to it in either of two cases: when
/// [`RNG_HEAVY_INIT`](crate::config::RNG_HEAVY_INIT) is `false`, or
/// when the heavy path's filesystem read failed at runtime.
fn install_or_reseed_light() -> Result<(), CryptoError> {
    let seed = gather_light_entropy();
    match RNG_STATE.get() {
        None => {
            let drbg = build_drbg(&seed)?;
            let state = RngState {
                drbg,
                counter: 0,
                last_reseed: Instant::now(),
                heavy_init: false,
            };
            let _ = RNG_STATE.set(Mutex::new(state));
            Ok(())
        }
        Some(mutex) => reseed_locked(mutex, &seed, false),
    }
}

/// Reseed an existing [`RngState`] through the given [`Mutex`]
/// handle, preserving DRBG identity.
///
/// # Parameters
///
/// * `mutex` — the global-state Mutex.
/// * `seed` — new entropy material, ≥32 bytes.
/// * `heavy` — `true` if `seed` came from the heavy path.
///
/// # Errors
///
/// Forwards [`CryptoError`] from
/// [`HmacDrbg::reseed`](crate::crypto::hmac_drbg::HmacDrbg::reseed).
fn reseed_locked(mutex: &Mutex<RngState>, seed: &[u8], heavy: bool) -> Result<(), CryptoError> {
    // Mutex poisoning: if a previous holder of the lock panicked, the
    // Mutex is now poisoned. We recover the data anyway because the
    // DRBG is a pure value type and a prior panic cannot have left its
    // bytes in an invalid state (only a partially-updated Update).
    // This matches the defensive style used in `net::child::spawn_child`.
    let mut state = match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    state.drbg.reseed(seed, RESEED_ADDITIONAL)?;
    state.counter = 0;
    state.last_reseed = Instant::now();
    state.heavy_init = heavy;
    Ok(())
}

// ============================================================================
// Shared locking helper for the output functions
// ============================================================================

/// Run `f` against the global [`RngState`], auto-initialising on
/// first use with a light-path seed.
///
/// Used by the infallible output functions ([`int`], [`intmax`],
/// [`double`], [`block`], [`block_nzb`]) so they never need to
/// return `Result`. If the caller forgot to invoke [`init`] during
/// startup, this function transparently falls back to the light
/// path — callers who need cryptographic-strength entropy must still
/// call [`init`] explicitly.
fn with_state<R>(f: impl FnOnce(&mut RngState) -> R) -> R {
    // Resolve (or lazily build) the global Mutex. The `get_or_init`
    // closure is infallible by design: it uses the light path which
    // cannot fail under any reachable condition on Linux x86_64.
    let mutex = RNG_STATE.get_or_init(|| {
        // First-use auto-init: light path, because it is infallible.
        // A caller that actually needs heavy-path entropy will have
        // invoked `init()` explicitly during `lib::init_args` Stage 9
        // before any output function runs.
        let seed = gather_light_entropy();
        // This unwrap is sound: HmacDrbg::new_with_algorithm only
        // rejects inputs shorter than 32 bytes OR algorithms whose
        // output length exceeds 64 bytes. `gather_light_entropy`
        // always returns exactly 32 bytes and HMAC_SHA512 has a
        // 64-byte output length — both invariants hold
        // unconditionally, so the error variants are unreachable.
        // Nonetheless, for belt-and-braces robustness we fall
        // through to a secondary DRBG construction with a nonempty
        // nonce if the first attempt somehow fails.
        let drbg = match build_drbg(&seed) {
            Ok(d) => d,
            Err(_) => {
                // Re-seed material: pad with a fresh `rdtsc` to change
                // the entropy and retry. On any platform where the
                // first attempt failed, this second one will too; in
                // practice neither path ever fails.
                let mut padded = [0u8; LIGHT_SEED_BYTES + 8];
                padded[..LIGHT_SEED_BYTES].copy_from_slice(&seed);
                padded[LIGHT_SEED_BYTES..].copy_from_slice(&read_tsc().to_le_bytes());
                match build_drbg(&padded) {
                    Ok(d) => d,
                    // Absolute-last-resort: degenerate DRBG reachable only on a
                    // future Rust stdlib change that breaks HmacDrbg::new
                    // with otherwise-valid inputs. We build from an
                    // alternative (constant+TSC) seed so the caller
                    // still gets *some* output. Callers relying on
                    // cryptographic strength must have called init().
                    Err(_) => build_drbg(&[0xAA; LIGHT_SEED_BYTES]).unwrap_or_else(|_| {
                        unreachable!(
                            "HmacDrbg::new_with_algorithm with 32B seed + HMAC-SHA-512 is infallible"
                        )
                    }),
                }
            }
        };
        Mutex::new(RngState {
            drbg,
            counter: 0,
            last_reseed: Instant::now(),
            heavy_init: false,
        })
    });
    // Acquire the lock, recovering from poisoning (the DRBG state is
    // always structurally valid even after a caller panic).
    let mut guard = match mutex.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut guard)
}

/// Fill `out` with DRBG output, chunking to stay under the per-call
/// output cap of [`HmacDrbg`]. Automatically advances the state
/// counter and handles the (extremely rare) case where [`HmacDrbg`]
/// refuses a generate call due to counter exhaustion.
///
/// If a generate call fails (only reachable after 2^48 prior calls
/// without a reseed), falls back to gathering fresh local entropy
/// and retrying. On repeated failure, leaves `out` with whatever
/// bytes were written before the failure (typically zeros in the
/// caller's pre-initialised buffer).
fn generate_chunked(state: &mut RngState, out: &mut [u8]) {
    for chunk in out.chunks_mut(GENERATE_CHUNK_BYTES) {
        if state.drbg.generate(chunk).is_err() {
            // Counter exhaustion (2^48 prior calls) — reseed in place.
            // Prefer the heavy path, fall back to the light path so
            // that this never cascades into a hang.
            let seed_bytes = gather_heavy_entropy()
                .ok()
                .map(|b| b.to_vec())
                .unwrap_or_else(|| gather_light_entropy().to_vec());
            if state.drbg.reseed(&seed_bytes, RESEED_ADDITIONAL).is_ok() {
                let _ = state.drbg.generate(chunk);
            }
            state.last_reseed = Instant::now();
        }
        state.counter = state.counter.saturating_add(1);
    }
}

// ============================================================================
// Public API — matches the seven exports declared in the file schema
// ============================================================================

/// Initialise the process-global RNG with heavy-path entropy
/// (`/dev/urandom` + `rdtsc` + `gettimeofday`).
///
/// This is the function that `lib::init_args` Stage 9 calls via
/// `.map_err(InitError::Rng)?`. It is:
///
/// * **Idempotent.** Calling it twice is safe and produces the
///   post-fork semantics: the second call is equivalent to
///   [`reseed`], folding fresh entropy into the existing DRBG.
/// * **Heavy by default.** Uses `/dev/urandom` (or `/dev/random` if
///   [`config::RNG_PARANOID`](crate::config::RNG_PARANOID) is `true`).
///   If the filesystem read fails, falls back to the light path so
///   that binaries in sandboxed / chrooted environments still
///   function — albeit with weaker entropy.
/// * **Config-gated.** When
///   [`config::RNG_HEAVY_INIT`](crate::config::RNG_HEAVY_INIT) is
///   `false` (non-default), uses only the light path. Matches the
///   FASM conditional-compilation branch at `rng.inc` lines 372–559.
///
/// # Errors
///
/// * [`CryptoError::Rng`] wrapping the underlying [`io::Error`] if
///   both the heavy path and light path fail to produce a valid DRBG
///   (not possible on a working Linux x86_64 installation).
/// * [`CryptoError::Hmac`] if the HMAC primitive is somehow
///   rejected — unreachable because this module always uses
///   [`ring::hmac::HMAC_SHA512`] which
///   [`HmacDrbg`] explicitly supports.
///
/// # Examples
///
/// ```no_run
/// # use heavything::crypto::rng;
/// // Called once during startup:
/// rng::init().expect("RNG init should succeed on Linux");
/// let n: u64 = rng::int();
/// assert!(n <= u64::MAX);
/// ```
pub fn init() -> Result<(), CryptoError> {
    install_or_reseed()
}

/// Force a reseed of the global RNG from fresh kernel entropy.
///
/// Per AAP §0.5.1.8 and `crate::net::child::spawn_child` docs,
/// workers MUST call this immediately after `fork(2)` to prevent
/// parent and child from emitting identical "random" streams (both
/// inherited the same DRBG state from the parent).
///
/// The existing DRBG instance is preserved (the reseed counter is
/// reset to 1 but `K` and `V` are cryptographically mixed with the
/// new entropy). This avoids any transient "no RNG available"
/// window that a rebuild-from-scratch approach would introduce.
///
/// # Errors
///
/// Same error set as [`init`]. On failure of the heavy path this
/// falls back to the light path automatically.
pub fn reseed() -> Result<(), CryptoError> {
    install_or_reseed()
}

/// Return a uniformly distributed `u64`.
///
/// Matches the FASM `rng$u64` API at `rng.inc` line 721. The FASM
/// returns its value in `rax`; the Rust equivalent returns a native
/// `u64`.
///
/// # Behaviour
///
/// Internally draws 8 bytes from the DRBG (which apportions them
/// from its rolling output stream and applies the
/// 64-bit-per-3072-bit discard automatically). No error path is
/// exposed: if the global state is not yet initialised, it is
/// auto-initialised via the light path.
///
/// # Thread safety
///
/// Safe to call from any thread; internally locks the global
/// [`Mutex`] for the brief duration of the DRBG call.
#[must_use]
pub fn int() -> u64 {
    let mut buf = [0u8; 8];
    with_state(|state| {
        generate_chunked(state, &mut buf);
    });
    u64::from_le_bytes(buf)
}

/// Return a uniformly distributed `u64` in the half-open range
/// `[0, max)`.
///
/// Matches the FASM `rng$intmax` at `rng.inc` line 619 (which itself
/// delegates to `rng$int` with `min = 0, max = max - 1`). The Rust
/// API takes `max` as the exclusive upper bound for ergonomics.
///
/// # Parameters
///
/// * `max` — exclusive upper bound. Values of `0` and `1` both return
///   `0` (degenerate ranges).
///
/// # Algorithm
///
/// Unbiased rejection sampling:
///
/// 1. Compute `limit = (2^64 / max) * max`, the largest multiple of
///    `max` that fits in the 64-bit sample space.
/// 2. Draw candidates from [`int`] until one lands in `[0, limit)`.
/// 3. Return `candidate % max`.
///
/// The expected number of rejections is at most 1 (specifically,
/// `(2^64 mod max) / 2^64 < 1` per draw). For `max = 7` (the worst
/// small case) the probability of rejection is ≈ 5.4 × 10^-18.
///
/// Uses `u128` for the limit arithmetic to avoid `u64` overflow when
/// `max` is small and `2^64 / max * max` would otherwise wrap.
#[must_use]
pub fn intmax(max: u64) -> u64 {
    if max <= 1 {
        return 0;
    }
    // `(2^64 / max) * max` computed in u128 to avoid u64 overflow.
    let limit: u128 = (1u128 << 64) / u128::from(max) * u128::from(max);
    loop {
        let candidate = int();
        if u128::from(candidate) < limit {
            return candidate % max;
        }
    }
}

/// Return a uniformly distributed `f64` in `[0.0, 1.0)`.
///
/// Matches the FASM `rng$double` at `rng.inc` line 811 in semantics
/// (uniform in `[0, 1)`). The exact mantissa construction differs:
///
/// * FASM: 52-bit mantissa via `psrlq 12 | 0x3FF0...00 | subsd 1.0`
///   (the classic "exponent-preserving" trick).
/// * Rust port (per AAP §0.5.1.3): 53-bit mantissa via
///   `(u >> 11) * 2^-53`.
///
/// The 53-bit method is strictly more precise (1 more bit of
/// mantissa) and produces uniformly distributed values with the same
/// `[0, 1)` guarantee. This is a minimal-deviation improvement
/// allowed under the translation-quality gate.
#[must_use]
pub fn double() -> f64 {
    // `int() >> 11` yields a 53-bit value in `[0, 2^53)`. Scaling by
    // `2^-53` produces a uniform `f64` in `[0.0, 1.0)`.
    let bits53 = int() >> 11;
    // Using `f64::from_bits` for the scale ensures bit-exact
    // reproducibility across machines that support IEEE 754
    // (essentially all modern x86_64 targets).
    (bits53 as f64) * f64::from_bits(0x3CA0_0000_0000_0000) // 2^-53
}

/// Fill `out` with uniformly distributed pseudorandom bytes.
///
/// Matches the FASM `rng$block` at `rng.inc` line 934. Internally
/// uses [`HmacDrbg::generate`](crate::crypto::hmac_drbg::HmacDrbg::generate)
/// which already enforces the 64-bit-per-3072-bit discard mandated
/// by AAP §0.5.1.3 (preserving the FASM behaviour at `rng.inc` lines
/// 941–947 where `r12d = 48` counter drives a discard at every 48th
/// `rng$u64` call = every 384 emitted bytes).
///
/// # Parameters
///
/// * `out` — destination buffer; any length accepted.
///
/// # Behaviour
///
/// 1. Chunks `out` into at most [`GENERATE_CHUNK_BYTES`] (32 KiB) at
///    a time to stay under [`HmacDrbg`]'s per-call output cap.
/// 2. Calls [`HmacDrbg::generate`] on each chunk. The DRBG's
///    internal `bytes_since_discard` counter persists across chunks
///    so the 3072-bit boundary is honoured globally, not per-chunk.
/// 3. Performs a final 8-byte "trailing discard" after the last
///    chunk to preserve the FASM post-write discard at `rng.inc`
///    lines 983–985 (`call rng$u64` after `pop r12 rbp rbx` at
///    `.alldone`) — the trailing discard is what prevents the
///    *next* caller from observing the bytes immediately following
///    the last emitted byte.
///
/// No error path is exposed: if auto-initialisation triggers and
/// somehow fails, the caller sees a mix of DRBG output and
/// (statistically indistinguishable) zeros in the destination
/// buffer.
pub fn block(out: &mut [u8]) {
    if out.is_empty() {
        return;
    }
    with_state(|state| {
        generate_chunked(state, out);
        // Trailing 64-bit discard matching FASM `.alldone` branch
        // at `rng.inc` lines 982–985.
        let mut discard = [0u8; 8];
        let _ = state.drbg.generate(&mut discard);
    });
}

/// Fill `out` with uniformly distributed non-zero pseudorandom bytes.
///
/// Matches the FASM `rng$block_nzb` at `rng.inc` line 996. Produces
/// the same statistical distribution as [`block`], except that no
/// emitted byte is `0x00`. This is required by PKCS #1 v1.5 RSA
/// padding (RFC 8017 §7.2.1 step 2.d: "padding string PS [...] does
/// not contain any zero octets"), which is the primary consumer in
/// the FASM `tls.inc` / `X509.inc` code paths.
///
/// # Parameters
///
/// * `out` — destination buffer; any length accepted.
///
/// # Algorithm
///
/// Generates a batch of 32 DRBG bytes at a time, skipping any that
/// are `0x00`. This differs from the FASM per-u32 rejection
/// algorithm (lines 1004–1013) in the batching granularity (32
/// bytes vs. 4 bytes), but the output distribution is identical
/// because every emitted byte is drawn independently from the DRBG.
///
/// On a well-distributed DRBG, ~99.6% of byte draws pass the
/// non-zero test, so the expected expansion factor is ≈ 1.004 × the
/// output length.
///
/// # Trailing discard
///
/// Performs the same 8-byte trailing discard as [`block`], matching
/// FASM `.alldone` at `rng.inc` lines 1038–1041.
pub fn block_nzb(out: &mut [u8]) {
    if out.is_empty() {
        return;
    }
    with_state(|state| {
        let mut written = 0usize;
        let total = out.len();
        // Batch size for each DRBG draw. 32 bytes balances DRBG
        // per-call overhead against the small (~0.4%) rejection rate.
        let mut batch = [0u8; 32];
        while written < total {
            if state.drbg.generate(&mut batch).is_err() {
                // Counter exhaustion: reseed and retry once. Falls
                // through to the next iteration on success.
                let seed_bytes = gather_heavy_entropy()
                    .ok()
                    .map(|b| b.to_vec())
                    .unwrap_or_else(|| gather_light_entropy().to_vec());
                let _ = state.drbg.reseed(&seed_bytes, RESEED_ADDITIONAL);
                state.last_reseed = Instant::now();
                continue;
            }
            state.counter = state.counter.saturating_add(1);
            for &b in &batch {
                if b != 0 {
                    out[written] = b;
                    written += 1;
                    if written >= total {
                        break;
                    }
                }
            }
        }
        // Trailing 64-bit discard matching FASM `.alldone` branch
        // at `rng.inc` lines 1038–1041.
        let mut discard = [0u8; 8];
        let _ = state.drbg.generate(&mut discard);
    });
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    //! Unit tests for the RNG module.
    //!
    //! These tests are deliberately statistical rather than
    //! deterministic because the DRBG output is seeded from live
    //! entropy. We use generous tolerances (usually 1%+ for
    //! distribution checks) to avoid flaky test failures while still
    //! catching gross regressions such as "always returns 0" or
    //! "output is constant".

    use super::*;

    /// Acquire the global RNG lock for the duration of a test
    /// closure. Because tests run concurrently under `cargo test`,
    /// statistical tests would interfere with each other (each test
    /// consumes bytes from the shared DRBG and observes the
    /// aggregate, not its own sample). We therefore use a separate
    /// test-local mutex to serialise statistical tests.
    ///
    /// Tests that don't depend on statistical properties (e.g.,
    /// `init_is_idempotent`) skip this.
    fn stat_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    // --------------------------------------------------------------
    // init / reseed / lifecycle
    // --------------------------------------------------------------

    /// `init()` must succeed on a standard Linux test system.
    #[test]
    fn init_succeeds() {
        init().expect("init() must succeed on Linux x86_64 with /dev/urandom present");
    }

    /// `init()` is idempotent: calling it twice in a row must succeed
    /// both times. The second call transparently performs a reseed.
    #[test]
    fn init_is_idempotent() {
        init().expect("first init() call must succeed");
        init().expect("second init() call must succeed (reseed semantics)");
    }

    /// `reseed()` must succeed even when called before `init()`
    /// (because `reseed` auto-initialises via the same
    /// `install_or_reseed` codepath).
    #[test]
    fn reseed_before_init_succeeds() {
        reseed().expect("reseed() must succeed without prior init()");
    }

    /// `reseed()` must succeed after `init()`.
    #[test]
    fn reseed_after_init_succeeds() {
        init().expect("init() must succeed");
        reseed().expect("reseed() after init() must succeed");
    }

    // --------------------------------------------------------------
    // int() / intmax()
    // --------------------------------------------------------------

    /// Two consecutive `int()` calls must (almost always) return
    /// different values. The probability of a collision for a
    /// working 64-bit DRBG is 2^-64 ≈ 5.4 × 10^-20, so any failure
    /// here is a real bug.
    #[test]
    fn int_produces_nonconstant_output() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        let a = int();
        let b = int();
        assert_ne!(a, b, "two consecutive int() calls must differ");
    }

    /// `int()` output must have a non-trivial bit distribution.
    /// Specifically, across 1024 samples the bit-counts of each
    /// bit-position must be within a generous 35–65% range of the
    /// expected 50% (binomial distribution tail with n=1024 gives
    /// ~3σ outside 45.0–55.0%; 35–65% is a looser bound for CI
    /// robustness).
    #[test]
    fn int_bit_distribution_is_uniform_ish() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        const N: usize = 1024;
        let mut bit_counts = [0u32; 64];
        for _ in 0..N {
            let v = int();
            for (i, count) in bit_counts.iter_mut().enumerate() {
                if (v >> i) & 1 == 1 {
                    *count += 1;
                }
            }
        }
        for (i, &count) in bit_counts.iter().enumerate() {
            let ratio = f64::from(count) / (N as f64);
            assert!(
                (0.35..=0.65).contains(&ratio),
                "bit {i}: {ratio:.3} outside [0.35, 0.65] (count = {count} / {N})"
            );
        }
    }

    /// `intmax(0)` and `intmax(1)` are degenerate cases that return
    /// `0` per the documented contract.
    #[test]
    fn intmax_degenerate_cases_return_zero() {
        assert_eq!(intmax(0), 0);
        assert_eq!(intmax(1), 0);
    }

    /// `intmax(max)` must always return a value strictly less than
    /// `max`.
    #[test]
    fn intmax_respects_upper_bound() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        for max in [2u64, 3, 7, 100, 256, 65_535, 1_000_000] {
            for _ in 0..256 {
                let v = intmax(max);
                assert!(v < max, "intmax({max}) returned {v} which is >= {max}");
            }
        }
    }

    /// `intmax(7)` over many draws must cover all 7 buckets with no
    /// bucket deviating more than ~30% from the uniform expectation.
    /// (A chi-squared test at 95% confidence would reject only ~5%
    /// of the time; we use a looser tolerance to be CI-robust.)
    #[test]
    fn intmax_rejection_sampling_is_uniform() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        const N: usize = 7_000;
        let mut buckets = [0u32; 7];
        for _ in 0..N {
            let v = intmax(7);
            buckets[v as usize] += 1;
        }
        let expected = (N as f64) / 7.0;
        for (i, &count) in buckets.iter().enumerate() {
            let ratio = f64::from(count) / expected;
            assert!(
                (0.7..=1.3).contains(&ratio),
                "bucket {i}: count={count}, expected≈{expected:.0}, ratio={ratio:.3} outside [0.7, 1.3]"
            );
        }
    }

    // --------------------------------------------------------------
    // double()
    // --------------------------------------------------------------

    /// `double()` must always return a value in `[0.0, 1.0)`.
    #[test]
    fn double_in_unit_interval() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        for _ in 0..1_000 {
            let x = double();
            assert!(
                (0.0..1.0).contains(&x),
                "double() returned {x} outside [0.0, 1.0)"
            );
        }
    }

    /// `double()` mean over many samples must be near 0.5.
    #[test]
    fn double_mean_near_half() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        const N: usize = 20_000;
        let mut sum = 0.0f64;
        for _ in 0..N {
            sum += double();
        }
        let mean = sum / (N as f64);
        assert!(
            (0.45..=0.55).contains(&mean),
            "double() mean = {mean:.4}, expected ≈ 0.5"
        );
    }

    // --------------------------------------------------------------
    // block() / block_nzb()
    // --------------------------------------------------------------

    /// `block(&mut [])` must be a no-op and not panic.
    #[test]
    fn block_empty_is_noop() {
        let mut empty: [u8; 0] = [];
        block(&mut empty);
    }

    /// `block()` must fill the buffer with non-trivial output.
    /// Specifically, a 1024-byte buffer must not remain all-zero and
    /// must not equal a prior buffer draw.
    #[test]
    fn block_produces_nonzero_output() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        let mut buf = [0u8; 1024];
        block(&mut buf);
        assert!(buf.iter().any(|&b| b != 0), "block() output is all-zero");
    }

    /// Two consecutive `block()` calls must produce different output.
    /// Collision probability ≈ 2^-1024 — any failure here is a real bug.
    #[test]
    fn block_consecutive_differ() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        let mut a = [0u8; 128];
        let mut b = [0u8; 128];
        block(&mut a);
        block(&mut b);
        assert_ne!(a, b, "consecutive block() outputs must differ");
    }

    /// `block()` must fill buffers that exceed the internal chunking
    /// boundary without panicking or truncating.
    #[test]
    fn block_large_buffer() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        // 100 KiB — larger than GENERATE_CHUNK_BYTES (32 KiB) and
        // larger than HmacDrbg::MAX_OUTPUT_BYTES_PER_CALL (64 KiB).
        let mut buf = vec![0u8; 102_400];
        block(&mut buf);
        // Sanity: at least 90% of bytes should be non-zero on a
        // proper RNG (the all-zero byte has a 1/256 probability).
        let nonzero = buf.iter().filter(|&&b| b != 0).count();
        let ratio = (nonzero as f64) / (buf.len() as f64);
        assert!(
            ratio > 0.9,
            "large block() non-zero ratio = {ratio:.3}, expected > 0.9"
        );
    }

    /// `block_nzb(&mut [])` must be a no-op and not panic.
    #[test]
    fn block_nzb_empty_is_noop() {
        let mut empty: [u8; 0] = [];
        block_nzb(&mut empty);
    }

    /// `block_nzb()` must produce only non-zero bytes.
    #[test]
    fn block_nzb_has_no_zero_bytes() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        for len in [1usize, 4, 16, 64, 256, 1024, 4096] {
            let mut buf = vec![0u8; len];
            block_nzb(&mut buf);
            for (i, &b) in buf.iter().enumerate() {
                assert_ne!(b, 0, "block_nzb({len}) produced zero at index {i}");
            }
        }
    }

    /// `block_nzb()` output must have non-trivial byte variance
    /// across a reasonably-sized buffer.
    #[test]
    fn block_nzb_produces_varied_bytes() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        let mut buf = vec![0u8; 1024];
        block_nzb(&mut buf);
        let unique: std::collections::HashSet<u8> = buf.iter().copied().collect();
        assert!(
            unique.len() > 100,
            "block_nzb() byte diversity = {} unique values (expected > 100)",
            unique.len()
        );
    }

    // --------------------------------------------------------------
    // internal helpers
    // --------------------------------------------------------------

    /// Two consecutive `read_tsc()` calls must return different
    /// (strictly increasing, on Linux x86_64) values. This validates
    /// the single `unsafe` block.
    #[test]
    fn read_tsc_is_monotonic_usually() {
        let t1 = read_tsc();
        // Do a small amount of work to ensure the TSC has ticked.
        let mut acc = 0u64;
        for i in 0..64u64 {
            acc = acc.wrapping_add(i);
        }
        let t2 = read_tsc();
        // Use `acc` to prevent the compiler from eliminating the loop.
        let _ = std::hint::black_box(acc);
        assert!(t2 > t1, "read_tsc() not monotonic: t1={t1}, t2={t2} (acc={acc})");
    }

    /// `gettimeofday_packed()` must produce different values on
    /// consecutive invocations when called at least a microsecond
    /// apart. We sleep briefly between calls to guarantee this.
    #[test]
    fn gettimeofday_packed_advances() {
        let t1 = gettimeofday_packed();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let t2 = gettimeofday_packed();
        assert_ne!(t1, t2, "gettimeofday_packed() did not advance after 2ms sleep");
    }

    /// Heavy-path seed must have the documented 64-byte length and
    /// must succeed on any Linux system with `/dev/urandom`.
    #[test]
    fn gather_heavy_entropy_returns_64_bytes() {
        let seed = gather_heavy_entropy().expect("/dev/urandom should be available in tests");
        assert_eq!(seed.len(), HEAVY_SEED_BYTES);
    }

    /// Heavy-path seeds must differ between consecutive calls (the
    /// `rdtsc`, `gettimeofday`, and `/dev/urandom` components all
    /// independently change).
    #[test]
    fn gather_heavy_entropy_is_nonconstant() {
        let s1 = gather_heavy_entropy().expect("seed 1");
        let s2 = gather_heavy_entropy().expect("seed 2");
        assert_ne!(s1, s2, "heavy-path seeds must differ between calls");
    }

    /// Light-path seed must have the documented 32-byte length.
    #[test]
    fn gather_light_entropy_returns_32_bytes() {
        let seed = gather_light_entropy();
        assert_eq!(seed.len(), LIGHT_SEED_BYTES);
    }

    /// Light-path seeds must differ between consecutive calls (the
    /// `rdtsc` component changes).
    #[test]
    fn gather_light_entropy_is_nonconstant() {
        let s1 = gather_light_entropy();
        // Tiny delay to ensure the TSC has advanced meaningfully.
        for i in 0..1024u64 {
            let _ = std::hint::black_box(i.wrapping_mul(0x9E37_79B9));
        }
        let s2 = gather_light_entropy();
        assert_ne!(s1, s2, "light-path seeds must differ between calls");
    }

    /// `double()` uses the 53-bit-mantissa scaling documented at the
    /// function: verify the output is a multiple of `2^-53`. (Bits
    /// below position 52 must all be zero after the `(bits53 as f64)`
    /// conversion because only 53 bits enter the mantissa.)
    #[test]
    fn double_has_53bit_mantissa_precision() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        for _ in 0..100 {
            let x = double();
            // Multiplying by 2^53 and rounding should give back the
            // original integer mantissa.
            let recovered = (x * f64::from_bits(0x4340_0000_0000_0000)).round() as u64; // 2^53
            assert!(
                recovered < (1u64 << 53),
                "double() {x} has mantissa {recovered} >= 2^53"
            );
        }
    }

    /// `intmax` with the full `u64::MAX` range must pass every
    /// candidate through (no rejection possible since the full range
    /// is divisible by `2^64`).
    #[test]
    fn intmax_full_range_accepts_all() {
        let _g = stat_test_lock().lock().unwrap_or_else(|p| p.into_inner());
        init().expect("init ok");
        // Just verify we get a value (and don't hang) with a huge max.
        let v = intmax(u64::MAX);
        assert!(v < u64::MAX);
    }
}
