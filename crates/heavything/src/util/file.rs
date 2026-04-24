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

//! File I/O helpers — port of `file.inc`.
//!
//! # Historical Context (FASM original)
//!
//! The FASM module `file.inc` provides stat / read / write helpers wrapping
//! the Linux syscalls `stat(2)`, `open(2)`, `read(2)`, `write(2)`, and
//! `close(2)`. Specifically:
//!
//! - `file$mtime_cstr` / `file$mtime` — call `stat(2)` with a 0x90-byte
//!   stat struct on the stack, then pull `st_mtime` out of offset `0x58`
//!   as an unsigned 64-bit second count.
//! - `file$size_cstr` / `file$size` — the same `stat(2)` path but extract
//!   `st_size` from offset `0x30`.
//! - `file$to_buffer_cstr` / `file$to_string_cstr` / `file$to_buffer` /
//!   `file$to_string` — single-shot reads that open-read-close a file into
//!   a `buffer` or `string32`.
//! - `file$proc_cstr` — a small helper used only by `sysinfo.inc` to slurp
//!   `/proc/*` pseudo-files whose size is reported as zero by `stat(2)`.
//!
//! These helpers feed three downstream subsystems: the `privmapped` module
//! (ETag derivation), the `webserver` module (`If-Modified-Since`
//! handling), and the `syslog` module (timestamp formatting on log
//! rotation).
//!
//! # Rust Strategy (per AAP §0.5.1.7)
//!
//! The Rust port delegates to `std::fs`, which itself issues the same
//! `stat(2)` / `openat(2)` / `read(2)` / `write(2)` / `close(2)` syscalls
//! the FASM version called directly. The two sets of helpers differ only
//! in surface ergonomics, not in the kernel traffic they generate.
//!
//! Several FASM-era distinctions collapse in the Rust port:
//!
//! - The `_cstr` / non-`_cstr` split (null-terminated C string vs. FASM
//!   length-prefixed `string32`) collapses to one generic function that
//!   accepts `AsRef<Path>`. Rust's `Path` handles both `&str` inputs and
//!   `CStr`-derived inputs, so there is no reason to maintain a second
//!   overload.
//! - The separate "read into buffer" vs. "read into string" split
//!   collapses to [`read`] (returns `Vec<u8>`) and [`read_to_string`]
//!   (returns `String`). These match the names in `std::fs` so consumers
//!   coming from idiomatic Rust find what they expect.
//! - `file$proc_cstr`'s special-case handling of `/proc/*` zero-sized
//!   files is unnecessary: `std::fs::read` and `std::fs::read_to_string`
//!   read to EOF rather than trusting `stat(2)`'s `st_size`.
//!
//! [`mtime`] returns seconds since the Unix epoch as a `u64` — the exact
//! FASM contract — rather than a `SystemTime`, so consumers can feed the
//! value straight into `If-Modified-Since` / ETag formatters without a
//! further conversion step.
//!
//! # Public Surface
//!
//! Twelve functions, grouped by intent:
//!
//! - **Metadata**: [`mtime`], [`size`], [`stat`] (combined `(size, mtime)`)
//! - **Predicates**: [`exists`], [`is_file`], [`is_dir`]
//! - **Reads**: [`read`], [`read_to_string`]
//! - **Writes**: [`write`] (truncates), [`append`] (creates-if-absent)
//! - **Namespace ops**: [`remove`], [`rename`]
//!
//! All fallible helpers return `Result<_, UtilError>`, carrying the
//! underlying `std::io::Error` via the `#[from]`-enabled
//! [`UtilError::Io`][crate::error::UtilError::Io] variant so callers can
//! propagate with `?`.
//!
//! # Non-Goals
//!
//! - No streaming iterator API. The FASM helpers are all single-shot
//!   slurp-the-whole-file operations; streaming readers belong to
//!   `std::io::BufReader` at the call site.
//! - No support for owned file descriptors. The FASM module exposes
//!   `file$opencb_cstr` (open-and-callback) which is an implementation
//!   detail of the slurp helpers rather than a distinct user API; Rust
//!   consumers who need an owned `File` should use `std::fs::File::open`
//!   directly.
//! - No atomic rename semantics beyond what `rename(2)` provides. The
//!   FASM module does not attempt to synthesise atomicity on non-POSIX
//!   filesystems, and neither does this port.
//!
//! # Safety
//!
//! This module contains no `unsafe` code. Every syscall the helpers issue
//! is mediated by `std::fs` or `std::io`, both of which encapsulate the
//! corresponding `unsafe extern` blocks behind safe APIs. The outer
//! `#![forbid(unsafe_code)]` attribute guarantees no future edit can
//! introduce `unsafe` without also disabling the lint.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;
use std::time::SystemTime;

use crate::error::UtilError;

/// Return the modification time of a file as seconds since the Unix epoch.
///
/// Matches the FASM `file$mtime` / `file$mtime_cstr` contract exactly: the
/// value read from `st_mtime` is widened to a `u64` in the same seconds
/// unit the kernel uses for its `stat(2)` reply.
///
/// # Errors
///
/// - [`UtilError::Io`] if the path cannot be stat'd (e.g., the file does
///   not exist, or the caller lacks permission on a parent directory).
/// - [`UtilError::Io`] wrapping an `io::ErrorKind::Other` if the system
///   clock reports `st_mtime` as a time before the Unix epoch — this is
///   not physically possible on a healthy Linux filesystem (where
///   `st_mtime` is stored as a non-negative seconds value), but the
///   defensive check protects against a hostile or broken filesystem
///   replying with an implausible time.
pub fn mtime<P: AsRef<Path>>(path: P) -> Result<u64, UtilError> {
    let meta = fs::metadata(path)?;
    let modified = meta.modified()?;
    let secs = modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| UtilError::Io(std::io::Error::other("mtime before UNIX epoch")))?
        .as_secs();
    Ok(secs)
}

/// Return the size of a file in bytes.
///
/// Matches the FASM `file$size` / `file$size_cstr` contract.
///
/// # Errors
///
/// Returns [`UtilError::Io`] if the path cannot be stat'd.
pub fn size<P: AsRef<Path>>(path: P) -> Result<u64, UtilError> {
    Ok(fs::metadata(path)?.len())
}

/// Return `true` if the path exists and is reachable by the current
/// effective user.
///
/// Any error (ENOENT, EACCES, symlink loop, ...) is reported as "does not
/// exist" — this matches how the FASM helpers use the information at
/// call sites (e.g., `webserver.inc` treats any stat failure as "file not
/// found" so it can emit a 404 without differentiating between "missing"
/// and "forbidden").
pub fn exists<P: AsRef<Path>>(path: P) -> bool {
    fs::metadata(path).is_ok()
}

/// Return `true` if the path refers to a regular file.
///
/// Any stat failure is collapsed to `false`, matching the FASM
/// short-circuit behaviour at its call sites.
pub fn is_file<P: AsRef<Path>>(path: P) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

/// Return `true` if the path refers to a directory.
///
/// Any stat failure is collapsed to `false`, matching the FASM
/// short-circuit behaviour at its call sites.
pub fn is_dir<P: AsRef<Path>>(path: P) -> bool {
    fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

/// Read the entire contents of a file into memory as a byte vector.
///
/// Matches FASM `file$to_buffer` / `file$to_buffer_cstr`.
///
/// # Errors
///
/// Returns [`UtilError::Io`] if the file cannot be opened or read.
pub fn read<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, UtilError> {
    Ok(fs::read(path)?)
}

/// Read the entire contents of a file into memory as a UTF-8 string.
///
/// Matches FASM `file$to_string` / `file$to_string_cstr`. Unlike the FASM
/// version — which uses the library's internal `string32` type holding
/// arbitrary bytes — this helper enforces UTF-8 validity; callers who
/// need byte-for-byte fidelity should use [`read`] instead.
///
/// # Errors
///
/// - [`UtilError::Io`] if the file cannot be opened or read.
/// - [`UtilError::Io`] wrapping `io::ErrorKind::InvalidData` if the file
///   contents are not valid UTF-8 (this is how `std::fs::read_to_string`
///   signals the error).
pub fn read_to_string<P: AsRef<Path>>(path: P) -> Result<String, UtilError> {
    Ok(fs::read_to_string(path)?)
}

/// Write bytes to a file, truncating any existing content.
///
/// The file is created if it does not exist. Matches the syscall sequence
/// `open(O_WRONLY|O_CREAT|O_TRUNC, 0o666) + write + close`, which is what
/// the FASM-era inverse of the slurp helpers would emit.
///
/// # Errors
///
/// Returns [`UtilError::Io`] if the file cannot be created, opened, or
/// written (e.g., disk full, permission denied, path is a directory).
pub fn write<P: AsRef<Path>>(path: P, bytes: &[u8]) -> Result<(), UtilError> {
    Ok(fs::write(path, bytes)?)
}

/// Append bytes to a file, creating the file if it does not yet exist.
///
/// Equivalent to `open(O_WRONLY|O_CREAT|O_APPEND, 0o666) + write + close`.
/// This function is used by `util::syslog` for rotating log appends.
///
/// # Errors
///
/// Returns [`UtilError::Io`] if the file cannot be created, opened, or
/// appended to.
pub fn append<P: AsRef<Path>>(path: P, bytes: &[u8]) -> Result<(), UtilError> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

/// Return the combined `(size, mtime)` pair via a single `stat(2)`.
///
/// This is a minor optimisation over calling [`size`] and [`mtime`]
/// separately: `std::fs::metadata` issues exactly one `stat(2)` syscall,
/// matching the FASM pattern of reusing the same stat struct for both
/// fields. The second element is Unix-epoch seconds, same as [`mtime`].
///
/// # Errors
///
/// - [`UtilError::Io`] if the path cannot be stat'd.
/// - [`UtilError::Io`] wrapping `io::ErrorKind::Other` if the reported
///   mtime is before the Unix epoch.
pub fn stat<P: AsRef<Path>>(path: P) -> Result<(u64, u64), UtilError> {
    let meta = fs::metadata(path)?;
    let size_bytes = meta.len();
    let mtime_secs = meta
        .modified()?
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| UtilError::Io(std::io::Error::other("mtime before UNIX epoch")))?
        .as_secs();
    Ok((size_bytes, mtime_secs))
}

/// Remove a file. Matches FASM `file$remove`.
///
/// The path must refer to a file, not a directory; use
/// `util::dir::remove` for directories.
///
/// # Errors
///
/// Returns [`UtilError::Io`] if the file cannot be unlinked (ENOENT,
/// EACCES, EISDIR, ...).
pub fn remove<P: AsRef<Path>>(path: P) -> Result<(), UtilError> {
    Ok(fs::remove_file(path)?)
}

/// Rename a file. Matches FASM `file$rename`.
///
/// This is a direct wrapper around `rename(2)`, which on Linux is atomic
/// when both paths reside on the same filesystem. Cross-filesystem
/// renames fall back to copy-and-unlink semantics internally, performed
/// by the kernel.
///
/// # Errors
///
/// Returns [`UtilError::Io`] if either path is invalid, the source does
/// not exist, or the destination is on a read-only filesystem.
pub fn rename<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<(), UtilError> {
    Ok(fs::rename(from, to)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Monotonic per-process counter so that concurrently-executed tests
    /// do not collide on the same tmp path (cargo test runs each
    /// `#[test]` in parallel by default).
    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// Compose a per-test temp path of the form
    /// `$TMPDIR/heavything_file_test_<name>_<pid>_<seq>`.
    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        p.push(format!("heavything_file_test_{name}_{pid}_{n}"));
        // Remove any leftover from a previous failed run so the test
        // starts from a known clean slate.
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn roundtrip_write_read() {
        let p = tmp("roundtrip");
        write(&p, b"hello").expect("write");
        let got = read(&p).expect("read");
        assert_eq!(&got, b"hello");
        remove(&p).expect("remove");
    }

    #[test]
    fn size_and_mtime() {
        let p = tmp("size_mtime");
        write(&p, b"hello world").expect("write");

        // Individual helpers.
        assert_eq!(size(&p).expect("size"), 11);
        let m = mtime(&p).expect("mtime");

        // Combined helper returns the same numbers.
        let (s2, m2) = stat(&p).expect("stat");
        assert_eq!(s2, 11);
        assert_eq!(m2, m);

        // mtime should be within the last 60 seconds of the test run.
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("now >= epoch")
            .as_secs();
        assert!(m <= now && now - m < 60, "mtime {m} not within 60s of now {now}");

        remove(&p).expect("remove");
    }

    #[test]
    fn exists_is_file_is_dir() {
        let p = tmp("exists");
        // Nothing there yet.
        assert!(!exists(&p));
        assert!(!is_file(&p));
        assert!(!is_dir(&p));

        write(&p, b"x").expect("write");

        // Now it is a regular file.
        assert!(exists(&p));
        assert!(is_file(&p));
        assert!(!is_dir(&p));

        remove(&p).expect("remove");
    }

    #[test]
    fn is_dir_true_for_directory() {
        // Exercise the is_dir predicate against a real directory so the
        // `m.is_dir()` branch is covered, not just the `false` fallback.
        // $TMPDIR is guaranteed to exist by POSIX.
        let d = std::env::temp_dir();
        assert!(exists(&d));
        assert!(is_dir(&d));
        assert!(!is_file(&d));
    }

    #[test]
    fn append_grows_file() {
        let p = tmp("append");
        write(&p, b"foo").expect("write");
        append(&p, b"bar").expect("append");
        let got = read(&p).expect("read");
        assert_eq!(&got, b"foobar");

        // Append to a non-existent path must create it.
        let p2 = tmp("append_create");
        assert!(!exists(&p2));
        append(&p2, b"created").expect("append-create");
        assert_eq!(read(&p2).expect("read"), b"created");

        remove(&p).expect("remove p");
        remove(&p2).expect("remove p2");
    }

    #[test]
    fn read_to_string_roundtrip() {
        let p = tmp("read_to_string");
        // Mix of ASCII + multi-byte UTF-8 (Latin-1 accent, Devanagari, CJK).
        let payload = "héllo, world!\nसंस्कृत 漢字";
        write(&p, payload.as_bytes()).expect("write");
        let got = read_to_string(&p).expect("read_to_string");
        assert_eq!(got, payload);
        remove(&p).expect("remove");
    }

    #[test]
    fn rename_moves_file() {
        let src = tmp("rename_src");
        let dst = tmp("rename_dst");
        write(&src, b"payload").expect("write src");
        assert!(exists(&src));
        assert!(!exists(&dst));

        rename(&src, &dst).expect("rename");
        assert!(!exists(&src));
        assert!(exists(&dst));
        assert_eq!(read(&dst).expect("read dst"), b"payload");

        remove(&dst).expect("remove dst");
    }

    #[test]
    fn write_truncates_existing_content() {
        // Ensure `write` really truncates — a subsequent read must see only
        // the new payload, not the leftover tail of the previous write.
        let p = tmp("truncate");
        write(&p, b"longer-initial-content").expect("write long");
        assert_eq!(size(&p).expect("size1"), 22);

        write(&p, b"short").expect("write short");
        assert_eq!(size(&p).expect("size2"), 5);
        assert_eq!(read(&p).expect("read"), b"short");

        remove(&p).expect("remove");
    }

    #[test]
    fn mtime_of_missing_path_is_io_error() {
        let p = tmp("missing_mtime");
        assert!(!exists(&p));
        let err = mtime(&p).expect_err("must error on missing file");
        // Exercise the #[from] std::io::Error conversion through the
        // `?` operator — this is the contract between this module and
        // `crate::error::UtilError`.
        assert!(
            matches!(err, UtilError::Io(_)),
            "expected UtilError::Io, got {err:?}"
        );
    }

    #[test]
    fn size_of_missing_path_is_io_error() {
        let p = tmp("missing_size");
        let err = size(&p).expect_err("must error on missing file");
        assert!(matches!(err, UtilError::Io(_)));
    }

    #[test]
    fn stat_of_missing_path_is_io_error() {
        let p = tmp("missing_stat");
        let err = stat(&p).expect_err("must error on missing file");
        assert!(matches!(err, UtilError::Io(_)));
    }

    #[test]
    fn remove_missing_is_io_error() {
        let p = tmp("missing_remove");
        let err = remove(&p).expect_err("must error on missing file");
        assert!(matches!(err, UtilError::Io(_)));
    }

    #[test]
    fn read_missing_is_io_error() {
        let p = tmp("missing_read");
        let err = read(&p).expect_err("must error on missing file");
        assert!(matches!(err, UtilError::Io(_)));
    }

    #[test]
    fn read_to_string_missing_is_io_error() {
        let p = tmp("missing_read_to_string");
        let err = read_to_string(&p).expect_err("must error on missing file");
        assert!(matches!(err, UtilError::Io(_)));
    }

    #[test]
    fn rename_missing_src_is_io_error() {
        let src = tmp("rename_missing_src");
        let dst = tmp("rename_missing_dst");
        let err = rename(&src, &dst).expect_err("must error on missing source");
        assert!(matches!(err, UtilError::Io(_)));
    }
}
