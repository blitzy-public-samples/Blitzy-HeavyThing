// ----------------------------------------------------------------------------
// heavything :: util :: sysinfo
// ----------------------------------------------------------------------------
// Port of `sysinfo.inc` from the HeavyThing x86_64 Linux assembly library.
//
// HeavyThing x86_64 Linux assembly language library and showcase programs
// Copyright © 2015 2 Ton Digital. Jeff Marrison jeff@2ton.com.au
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 3 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
// ----------------------------------------------------------------------------

//! System information helpers. Port of `sysinfo.inc`.
//!
//! Two free functions and one POD struct:
//!
//! * [`uname`] — thin wrapper over the Linux `uname(2)` syscall (via
//!   [`nix::sys::utsname::uname`]) returning a fully-owned [`Uname`] struct.
//!   Matches the behaviour implied by FASM `sysinfo$uname`.
//! * [`cpucount`] — count of online logical CPUs obtained by parsing
//!   `/proc/cpuinfo`. Falls back to [`std::thread::available_parallelism`]
//!   when `/proc/cpuinfo` is unreadable or empty (e.g., non-Linux dev hosts
//!   running the test suite, or an exotic kernel producing unexpected
//!   output). This mirrors FASM `sysinfo$cpucount`, which likewise parses
//!   `/proc/cpuinfo`. The FASM code counts `vendor_id` lines; the Rust
//!   port counts `processor\t` / `processor ` lines — both strings appear
//!   exactly once per logical CPU on x86_64 Linux, so the resulting count
//!   is equivalent while being more portable across architectures.
//!
//! # Containerised environments
//!
//! Parsing `/proc/cpuinfo` is deliberately preferred over
//! `sysconf(_SC_NPROCESSORS_ONLN)` because the latter reports the host CPU
//! count rather than the cgroup-limited mask visible to the current process.
//! Under Docker / LXC with a restricted CPU mask, `/proc/cpuinfo` reflects
//! the actually-available CPUs.

use std::fs;

use crate::error::UtilError;

// ----------------------------------------------------------------------------
// Uname
// ----------------------------------------------------------------------------

/// Owned copy of the five fields returned by the Linux `uname(2)` syscall.
///
/// The field layout mirrors the C `struct utsname` defined in
/// `<sys/utsname.h>`. Each field is a UTF-8 [`String`] obtained from the
/// underlying `&OsStr` via
/// [`to_string_lossy`](std::ffi::OsStr::to_string_lossy); on Linux the
/// kernel populates these with ASCII content so the conversion is lossless
/// in practice, but the use of `to_string_lossy` guarantees a valid
/// [`String`] even in pathological cases.
///
/// Derives [`Default`] so that [`crate::init_args`] can construct a
/// placeholder value before populating it during Stage 6 of initialisation.
#[derive(Debug, Clone, Default)]
pub struct Uname {
    /// Operating system name (e.g., `"Linux"`).
    pub sysname: String,

    /// Network node hostname (the nodename field of `utsname`).
    pub nodename: String,

    /// Operating system release (e.g., `"5.15.0-58-generic"`).
    pub release: String,

    /// Operating system version (free-form kernel-build string).
    pub version: String,

    /// Hardware identifier (e.g., `"x86_64"`).
    pub machine: String,
}

// ----------------------------------------------------------------------------
// uname — public API
// ----------------------------------------------------------------------------

/// Call `uname(2)` and return the kernel / machine information.
///
/// Matches FASM `sysinfo$uname`. On success returns a fully populated
/// [`Uname`] struct. On failure (which is extremely rare on Linux — the
/// `uname(2)` syscall only fails on `EFAULT`, which is unreachable from
/// safe Rust via [`nix::sys::utsname::uname`]) returns
/// [`UtilError::Io`] carrying an [`std::io::Error`] built from the
/// errno value.
///
/// # Errors
///
/// Returns [`UtilError::Io`] if the underlying syscall fails.
pub fn uname() -> Result<Uname, UtilError> {
    let info =
        nix::sys::utsname::uname().map_err(|e| UtilError::Io(std::io::Error::from_raw_os_error(e as i32)))?;
    Ok(Uname {
        sysname: info.sysname().to_string_lossy().into_owned(),
        nodename: info.nodename().to_string_lossy().into_owned(),
        release: info.release().to_string_lossy().into_owned(),
        version: info.version().to_string_lossy().into_owned(),
        machine: info.machine().to_string_lossy().into_owned(),
    })
}

// ----------------------------------------------------------------------------
// cpucount — public API
// ----------------------------------------------------------------------------

/// Count the number of online logical CPUs by parsing `/proc/cpuinfo`.
///
/// Matches FASM `sysinfo$cpucount`, which likewise parses `/proc/cpuinfo`.
/// The FASM implementation counts `vendor_id` lines; this port counts
/// lines beginning with `"processor\t"` or `"processor "` because these
/// appear on every logical CPU regardless of architecture (whereas
/// `vendor_id` is x86-specific).
///
/// On x86_64 Linux both strings appear exactly once per logical CPU, so
/// the resulting count is identical to the FASM behaviour.
///
/// # Fallback behaviour
///
/// If `/proc/cpuinfo` cannot be opened (e.g., unexpected procfs layout,
/// sandboxed test environment) or yields zero matching lines, the
/// function falls back to [`std::thread::available_parallelism`]. This
/// is only a secondary source because in containers
/// [`available_parallelism`](std::thread::available_parallelism) may
/// ignore cgroup CPU masks on some kernel versions, whereas
/// `/proc/cpuinfo` honours them.
///
/// # Errors
///
/// Returns [`UtilError::Io`] only if both the `/proc/cpuinfo` parse
/// yields zero processors **and** [`available_parallelism`](std::thread::available_parallelism)
/// also fails. On any successful Linux system this function always
/// succeeds with a count of at least 1.
pub fn cpucount() -> Result<usize, UtilError> {
    // Primary source: /proc/cpuinfo. Respects cgroup CPU masks.
    if let Ok(contents) = fs::read_to_string("/proc/cpuinfo") {
        let n = contents
            .lines()
            .filter(|line| line.starts_with("processor\t") || line.starts_with("processor "))
            .count();
        if n > 0 {
            return Ok(n);
        }
        // zero matches — procfs produced unexpected output; fall through.
    }

    // Fallback: std::thread::available_parallelism.
    std::thread::available_parallelism()
        .map(|n| n.get())
        .map_err(UtilError::Io)
}

// ----------------------------------------------------------------------------
// Unit tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uname_returns_nonempty() {
        let info = uname().expect("uname should succeed on a supported platform");
        assert!(!info.sysname.is_empty(), "sysname must be populated");
        assert!(!info.release.is_empty(), "release must be populated");
        assert!(!info.machine.is_empty(), "machine must be populated");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn uname_on_linux_reports_linux() {
        let info = uname().expect("uname should succeed on Linux");
        assert_eq!(info.sysname, "Linux");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn machine_is_x86_64() {
        let info = uname().expect("uname should succeed on x86_64");
        assert_eq!(info.machine, "x86_64");
    }

    #[test]
    fn uname_nodename_present() {
        let info = uname().expect("uname should succeed");
        // Every Linux host has a nodename even if it's just "localhost".
        // An empty nodename would indicate a bug in our `OsStr -> String`
        // conversion rather than a real system state.
        assert!(!info.nodename.is_empty(), "nodename must not be empty");
    }

    #[test]
    fn uname_default_is_all_empty() {
        let empty = Uname::default();
        assert!(empty.sysname.is_empty());
        assert!(empty.nodename.is_empty());
        assert!(empty.release.is_empty());
        assert!(empty.version.is_empty());
        assert!(empty.machine.is_empty());
    }

    #[test]
    fn uname_is_cloneable() {
        let info = uname().expect("uname should succeed");
        let clone = info.clone();
        assert_eq!(info.sysname, clone.sysname);
        assert_eq!(info.nodename, clone.nodename);
        assert_eq!(info.release, clone.release);
        assert_eq!(info.version, clone.version);
        assert_eq!(info.machine, clone.machine);
    }

    #[test]
    fn cpucount_at_least_one() {
        let n = cpucount().expect("cpucount should succeed");
        assert!(n >= 1, "expected at least 1 CPU, got {n}");
    }

    #[test]
    fn cpucount_reasonable_upper_bound() {
        let n = cpucount().expect("cpucount should succeed");
        // Sanity check — reject absurd values that would indicate we
        // parsed something other than `processor` lines.
        assert!(n < 4096, "expected < 4096 CPUs, got {n}");
    }

    #[test]
    fn cpucount_consistent_across_calls() {
        // The online CPU count may legitimately change at runtime
        // (hotplug), but on any reasonable CI host two back-to-back
        // calls should agree.
        let a = cpucount().expect("first call");
        let b = cpucount().expect("second call");
        assert_eq!(a, b);
    }
}
