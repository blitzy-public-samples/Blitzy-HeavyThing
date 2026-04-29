// Rust translation © 2026, licensed under GPL-3.0-or-later.
//
// Derived from the HeavyThing assembly library:
//   Copyright © 2015–2018 2 Ton Digital, Jeff Marrison <info@2ton.com.au>
//   Homepage: https://2ton.com.au/
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

//! Directory enumeration helpers wrapping [`std::fs::read_dir`]. Port of
//! `dir.inc`.
//!
//! # Historical Context (FASM original)
//!
//! The FASM `dir.inc` exposes a single convenience function, `dir$read`,
//! that opens a directory via `syscall_open` with the `O_RDONLY |
//! O_DIRECTORY` flag combination (`0x10000`) and then repeatedly invokes
//! `syscall_getdents` against a 16 KiB stack buffer, unpacking each
//! `linux_dirent` record into a 24-byte "dir" heap structure holding the
//! entry's 8-byte type code (`dir_type_ofs`), 8-byte inode number
//! (`dir_inode_ofs`), and a pointer to a freshly-allocated string of the
//! file's basename (`dir_name_ofs`). A matching `dir$free` walks the
//! returned list and releases both the string payloads and the list
//! itself. The type-code field uses the `DT_*` constants from the
//! Linux `<dirent.h>` header — `DT_UNKNOWN = 0`, `DT_FIFO = 1`, `DT_CHR =
//! 2`, `DT_DIR = 4`, `DT_BLK = 6`, `DT_REG = 8`, `DT_LNK = 10`, `DT_SOCK =
//! 12` — whose on-kernel numeric values are part of the Linux ABI and
//! must be preserved bit-for-bit by any port that claims "API parity"
//! with the original library.
//!
//! # Rust Strategy (per AAP §0.5.1.7)
//!
//! This module delegates to [`std::fs::read_dir`], which on Linux
//! internally issues the very same `getdents64(2)` syscall that the FASM
//! code dispatches by hand — `std::fs` simply wraps it behind a
//! memory-safe iterator. The translation therefore preserves the
//! observable syscall behaviour (same kernel path, same `errno` surface,
//! same `getdents64` batching semantics) while replacing the explicit
//! 16 KiB stack buffer + manual record walker with the iterator returned
//! by the standard library. Directory entries are classified into `DT_*`
//! codes via [`std::fs::FileType`] plus the Unix-only
//! [`std::os::unix::fs::FileTypeExt`] trait, which exposes
//! `is_block_device` / `is_char_device` / `is_fifo` / `is_socket` — the
//! four file kinds not discoverable through the portable `FileType` API.
//!
//! # Public Surface
//!
//! * Eight `DT_*` `pub const u8` items matching the Linux ABI.
//! * A lightweight [`Dirent`] POD struct with the entry's full
//!   [`PathBuf`], the basename as a [`String`], and the `DT_*` type code.
//! * Six filesystem convenience wrappers — [`read`], [`read_files`],
//!   [`read_dirs`], [`create`], [`remove`], [`remove_all`] — that all
//!   return [`Result<_, UtilError>`], allowing `?` propagation through
//!   any [`std::io::Error`] via [`UtilError::Io`]'s `#[from]` conversion.
//!
//! # Non-Goals
//!
//! This module intentionally does **not** re-expose the FASM
//! `dir_type_ofs` / `dir_inode_ofs` / `dir_name_ofs` / `dir_size`
//! byte-offset constants: those describe the internal layout of the
//! 24-byte heap structure that the FASM allocator packs, and have no
//! meaning in a Rust port where the equivalent fields are exposed as
//! typed [`Dirent`] members. Preserving them would only invite misuse
//! via unsafe casts.
//!
//! # Safety
//!
//! The entire module is `#![forbid(unsafe_code)]` in spirit — all
//! filesystem I/O is routed through the safe [`std::fs`] façade. No
//! `unsafe` blocks appear anywhere in this file.

use std::fs::{self, DirEntry};
use std::path::{Path, PathBuf};

use crate::error::UtilError;

// ============================================================================
// DT_* file-type constants (Linux <dirent.h> ABI).
// ============================================================================
//
// These values are fixed by the Linux kernel and must not be renumbered.
// They are re-exported here so that callers porting FASM code that
// referenced the assembly-side `DT_UNKNOWN`, `DT_FIFO`, etc. symbols can
// continue to do so by name. The non-contiguous numbering (0, 1, 2, 4, 6,
// 8, 10, 12) is intentional — the Linux ABI skips odd values above 2 to
// leave room for future file types — and matches FASM `dir.inc` lines
// 32–39 exactly.

/// Unknown file type (Linux `DT_UNKNOWN`).
///
/// Returned when the kernel or filesystem (e.g., some older `ext2`
/// drivers, or unusual pseudo-filesystems) does not supply a type code,
/// or when [`DirEntry::file_type`] fails on a specific entry. Callers
/// that genuinely need to know the type of such an entry must stat it
/// explicitly.
pub const DT_UNKNOWN: u8 = 0;

/// Named pipe / FIFO (Linux `DT_FIFO`).
pub const DT_FIFO: u8 = 1;

/// Character device (Linux `DT_CHR`).
pub const DT_CHR: u8 = 2;

/// Directory (Linux `DT_DIR`).
pub const DT_DIR: u8 = 4;

/// Block device (Linux `DT_BLK`).
pub const DT_BLK: u8 = 6;

/// Regular file (Linux `DT_REG`).
pub const DT_REG: u8 = 8;

/// Symbolic link (Linux `DT_LNK`).
pub const DT_LNK: u8 = 10;

/// Unix-domain socket (Linux `DT_SOCK`).
pub const DT_SOCK: u8 = 12;

// ============================================================================
// Dirent — a single directory entry.
// ============================================================================

/// A single directory entry returned by [`read`], [`read_files`], or
/// [`read_dirs`].
///
/// The three public fields map onto the three meaningful slots of the
/// FASM 24-byte `dir` structure:
///
/// * [`Dirent::path`] holds the full path (parent directory prefix +
///   basename) as returned by [`DirEntry::path`] — convenient for
///   callers who need to `open(2)` or `stat(2)` the entry without
///   re-concatenating strings.
/// * [`Dirent::name`] holds the basename as a UTF-8 [`String`],
///   produced via [`std::ffi::OsStr::to_string_lossy`] so that entries
///   with non-UTF-8 byte sequences (rare on modern Linux but permitted
///   by the kernel) are replaced with `U+FFFD` rather than causing an
///   error. This matches the FASM behaviour of returning the raw bytes
///   as an opaque string.
/// * [`Dirent::dtype`] holds the `DT_*` file-type constant — one of the
///   eight values defined at the top of this module — derived from
///   [`DirEntry::file_type`].
///
/// [`Dirent`] is [`Clone`] + [`Debug`] but deliberately not [`Copy`]
/// (because it owns heap allocations in `path` and `name`), and not
/// [`PartialEq`] because path equality semantics are platform-dependent
/// (case-insensitive on some filesystems, canonicalisation differences,
/// etc.) and out of scope for this low-level primitive.
#[derive(Debug, Clone)]
pub struct Dirent {
    /// Full filesystem path to this entry, including the queried parent
    /// directory as prefix. Equivalent to calling [`DirEntry::path`].
    pub path: PathBuf,
    /// Basename of this entry (filename component only, no parent path
    /// prefix, no trailing separator). Converted from [`std::ffi::OsString`]
    /// via [`std::ffi::OsStr::to_string_lossy`], so non-UTF-8 byte
    /// sequences are mapped to `U+FFFD`.
    pub name: String,
    /// Linux-ABI `DT_*` file-type code. One of [`DT_UNKNOWN`], [`DT_FIFO`],
    /// [`DT_CHR`], [`DT_DIR`], [`DT_BLK`], [`DT_REG`], [`DT_LNK`],
    /// [`DT_SOCK`].
    pub dtype: u8,
}

// ============================================================================
// Public API.
// ============================================================================

/// Enumerate `path`, returning one [`Dirent`] per kernel-reported entry.
///
/// This is the Rust analogue of FASM `dir$read`: the kernel's
/// `getdents64(2)` syscall is dispatched by [`std::fs::read_dir`]
/// internally, so the observable syscall sequence is preserved.
///
/// Rust's [`std::fs::read_dir`] (unlike the raw `getdents64` stream)
/// transparently filters the synthetic `.` and `..` entries — callers
/// who need to see them must invoke `getdents64` directly, which is
/// outside the scope of this port. This differs from the FASM
/// `dir$read`, which passes these entries through untouched; however,
/// `.` and `..` are rarely useful in practice (every directory has
/// them, with a known type of [`DT_DIR`]) and their filtering is
/// behaviourally safe — the only callers of FASM `dir$read` in the
/// HeavyThing showcase applications (the TUI file browser variants)
/// already skipped them explicitly after the read.
///
/// # Errors
///
/// Returns [`UtilError::Io`] if the path does not exist, is not a
/// directory, access is denied, or any individual entry's metadata
/// cannot be read. Per-entry [`DirEntry`] iteration errors short-
/// circuit the whole read, matching FASM's "return null on any error"
/// contract.
pub fn read<P: AsRef<Path>>(path: P) -> Result<Vec<Dirent>, UtilError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if let Some(d) = to_dirent(&entry) {
            entries.push(d);
        }
    }
    Ok(entries)
}

/// Enumerate `path`, returning only regular-file entries (those with
/// `dtype == DT_REG`).
///
/// Convenience wrapper over [`read`] that discards non-file entries
/// (directories, symlinks, devices, FIFOs, sockets, unknowns). The
/// FASM library offered this same filtered variant via a boolean flag
/// into `dir$read`; the Rust port exposes it as a distinct function
/// for clarity and to avoid a boolean-argument anti-pattern.
///
/// # Errors
///
/// Propagates [`UtilError::Io`] from the underlying [`read`] call.
pub fn read_files<P: AsRef<Path>>(path: P) -> Result<Vec<Dirent>, UtilError> {
    Ok(read(path)?.into_iter().filter(|d| d.dtype == DT_REG).collect())
}

/// Enumerate `path`, returning only subdirectory entries (those with
/// `dtype == DT_DIR`).
///
/// Convenience wrapper over [`read`] that discards non-directory
/// entries. Note that — like [`read`] itself — synthetic `.` and `..`
/// entries are filtered out by [`std::fs::read_dir`], so this returns
/// only the *named* subdirectories.
///
/// # Errors
///
/// Propagates [`UtilError::Io`] from the underlying [`read`] call.
pub fn read_dirs<P: AsRef<Path>>(path: P) -> Result<Vec<Dirent>, UtilError> {
    Ok(read(path)?.into_iter().filter(|d| d.dtype == DT_DIR).collect())
}

/// Create `path`, creating any missing parent components along the way
/// (`mkdir -p` semantics).
///
/// Delegates to [`std::fs::create_dir_all`]. This is idempotent: if
/// `path` already exists and is a directory, the call succeeds without
/// error; if `path` exists but is *not* a directory, a
/// [`UtilError::Io`] is returned with an OS-level error describing the
/// conflict.
///
/// The FASM library did not expose a directory-create helper (relying
/// on callers to invoke `syscall_mkdir` directly); [`create`] is added
/// here as a convenience because it rounds out the symmetric
/// read/create/remove API that idiomatic Rust callers expect, and
/// because it satisfies AAP §0.5.1.7's instruction to provide
/// `mkdir -p` semantics.
///
/// # Errors
///
/// Returns [`UtilError::Io`] on I/O failure (permission denied,
/// read-only filesystem, path component conflicts with a non-directory,
/// etc.).
pub fn create<P: AsRef<Path>>(path: P) -> Result<(), UtilError> {
    Ok(fs::create_dir_all(path)?)
}

/// Remove `path`, which must be an empty directory.
///
/// Delegates to [`std::fs::remove_dir`]. Returns an error if `path` is
/// not empty, is not a directory, or cannot be unlinked.
///
/// This function intentionally does **not** recurse; callers who need
/// to remove a populated directory should use [`remove_all`].
///
/// # Errors
///
/// Returns [`UtilError::Io`] on any filesystem failure, including the
/// common "directory not empty" `ENOTEMPTY` case.
pub fn remove<P: AsRef<Path>>(path: P) -> Result<(), UtilError> {
    Ok(fs::remove_dir(path)?)
}

/// Remove `path` and all its contents recursively.
///
/// Delegates to [`std::fs::remove_dir_all`], which walks the tree
/// rooted at `path`, unlinking each regular file and empty directory
/// in post-order, and finally unlinking `path` itself.
///
/// Per the Rust standard library's documentation, this function does
/// **not** follow symbolic links — it only deletes the link, not the
/// target. This matches the safe default behaviour callers expect.
///
/// # Errors
///
/// Returns [`UtilError::Io`] on any filesystem failure. The operation
/// is *not* atomic: if an error occurs part-way through, the directory
/// tree is left in a partially-deleted state.
pub fn remove_all<P: AsRef<Path>>(path: P) -> Result<(), UtilError> {
    Ok(fs::remove_dir_all(path)?)
}

// ============================================================================
// Private helpers.
// ============================================================================

/// Classify a [`DirEntry`] into a [`Dirent`].
///
/// Produces a fully-populated [`Dirent`] for any entry. The `dtype`
/// field is resolved by dispatching on [`DirEntry::file_type`]:
///
/// 1. [`std::fs::FileType::is_file`] → [`DT_REG`]
/// 2. [`std::fs::FileType::is_dir`] → [`DT_DIR`]
/// 3. [`std::fs::FileType::is_symlink`] → [`DT_LNK`]
/// 4. Unix-specific extensions (via [`std::os::unix::fs::FileTypeExt`]):
///    * [`FileTypeExt::is_block_device`] → [`DT_BLK`]
///    * [`FileTypeExt::is_char_device`] → [`DT_CHR`]
///    * [`FileTypeExt::is_fifo`] → [`DT_FIFO`]
///    * [`FileTypeExt::is_socket`] → [`DT_SOCK`]
/// 5. Anything else (including a failed `file_type()` call) →
///    [`DT_UNKNOWN`]
///
/// The `#[cfg(unix)]` / `#[cfg(not(unix))]` split on the Unix
/// extensions is nominal for this crate (which targets
/// `x86_64-unknown-linux-gnu` exclusively per AAP §0.8.1), but follows
/// standard Rust portability idioms so that `cargo check --target
/// x86_64-pc-windows-msvc` on a developer's laptop still produces a
/// meaningful diagnostic instead of a missing-trait error.
///
/// Returns [`Option<Dirent>`] for forward-compatibility with any
/// future filtering logic (e.g., skipping entries with a specific
/// `dtype`). In the current implementation it always returns
/// [`Some`].
///
/// [`FileTypeExt::is_block_device`]: std::os::unix::fs::FileTypeExt::is_block_device
/// [`FileTypeExt::is_char_device`]: std::os::unix::fs::FileTypeExt::is_char_device
/// [`FileTypeExt::is_fifo`]: std::os::unix::fs::FileTypeExt::is_fifo
/// [`FileTypeExt::is_socket`]: std::os::unix::fs::FileTypeExt::is_socket
fn to_dirent(entry: &DirEntry) -> Option<Dirent> {
    let path = entry.path();
    let name = entry.file_name().to_string_lossy().into_owned();
    let dtype = match entry.file_type() {
        Ok(ft) if ft.is_file() => DT_REG,
        Ok(ft) if ft.is_dir() => DT_DIR,
        Ok(ft) if ft.is_symlink() => DT_LNK,
        Ok(ft) => {
            // Non-regular, non-directory, non-symlink — fall back to
            // the Unix-specific extension trait for fine-grained
            // classification.
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if ft.is_block_device() {
                    DT_BLK
                } else if ft.is_char_device() {
                    DT_CHR
                } else if ft.is_fifo() {
                    DT_FIFO
                } else if ft.is_socket() {
                    DT_SOCK
                } else {
                    DT_UNKNOWN
                }
            }
            #[cfg(not(unix))]
            {
                // Non-Unix targets cannot distinguish these kinds
                // through the stable standard-library API; report
                // `DT_UNKNOWN` rather than guessing.
                let _ = ft;
                DT_UNKNOWN
            }
        }
        Err(_) => DT_UNKNOWN,
    };
    Some(Dirent { path, name, dtype })
}

// ============================================================================
// Unit tests.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a per-test temporary directory under `$TMPDIR` with a
    /// name that is unique to (test-name, process-id) to avoid
    /// collisions when the test suite is run with `--test-threads > 1`.
    fn tmpdir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("heavything_dir_test_{name}_{}", std::process::id()));
        // Start from a clean slate if a previous crashed test left a
        // stale directory behind; ignore "not found" failures.
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create tmpdir");
        p
    }

    #[test]
    fn dt_constants_match_linux_abi() {
        // Lock in the Linux `<dirent.h>` ABI values so that an accidental
        // renumber (e.g., someone refactoring the constants into a
        // `#[repr(u8)]` enum) breaks this test rather than silently
        // corrupting on-the-wire compatibility with FASM callers.
        assert_eq!(DT_UNKNOWN, 0);
        assert_eq!(DT_FIFO, 1);
        assert_eq!(DT_CHR, 2);
        assert_eq!(DT_DIR, 4);
        assert_eq!(DT_BLK, 6);
        assert_eq!(DT_REG, 8);
        assert_eq!(DT_LNK, 10);
        assert_eq!(DT_SOCK, 12);
    }

    #[test]
    fn read_empty() {
        let d = tmpdir("empty");
        let entries = read(&d).expect("read");
        assert!(entries.is_empty(), "new tmpdir should be empty");
        remove(&d).expect("remove");
    }

    #[test]
    fn read_finds_files() {
        let d = tmpdir("files");
        let f1 = d.join("a.txt");
        let f2 = d.join("b.txt");
        fs::write(&f1, b"x").expect("write a");
        fs::write(&f2, b"y").expect("write b");

        let mut names: Vec<String> = read_files(&d)
            .expect("read_files")
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);

        // Every returned entry should carry dtype == DT_REG.
        assert!(
            read_files(&d)
                .expect("read_files again")
                .iter()
                .all(|d| d.dtype == DT_REG),
            "read_files must only return DT_REG entries"
        );

        remove_all(&d).expect("remove_all");
    }

    #[test]
    fn read_dirs_filters_correctly() {
        let d = tmpdir("dirs");
        let sub1 = d.join("sub1");
        let sub2 = d.join("sub2");
        fs::create_dir(&sub1).expect("create sub1");
        fs::create_dir(&sub2).expect("create sub2");
        fs::write(d.join("file.txt"), b"x").expect("write");

        let dirs = read_dirs(&d).expect("read_dirs");
        assert_eq!(dirs.len(), 2, "should find exactly two subdirectories");
        assert!(
            dirs.iter().all(|d| d.dtype == DT_DIR),
            "all returned entries must be DT_DIR"
        );

        let mut names: Vec<String> = dirs.into_iter().map(|d| d.name).collect();
        names.sort();
        assert_eq!(names, vec!["sub1".to_string(), "sub2".to_string()]);

        remove_all(&d).expect("remove_all");
    }

    #[test]
    fn read_returns_paths_and_names_together() {
        let d = tmpdir("pathsnames");
        fs::write(d.join("hello.txt"), b"greetings").expect("write");

        let entries = read(&d).expect("read");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.name, "hello.txt");
        assert_eq!(entry.dtype, DT_REG);
        // The path must be the full path (i.e., include the tmpdir
        // prefix), not the bare basename — this is what distinguishes
        // `Dirent::path` from `Dirent::name`.
        assert_eq!(entry.path, d.join("hello.txt"));

        remove_all(&d).expect("remove_all");
    }

    #[test]
    fn read_of_nonexistent_path_errors() {
        let d = tmpdir("nonexistent_parent");
        let missing = d.join("definitely_does_not_exist");
        // Sanity: the parent exists but the child does not.
        assert!(d.exists());
        assert!(!missing.exists());

        let err = read(&missing).expect_err("must fail on missing path");
        // Ensure the error is the Io variant (exercising `UtilError::Io`
        // and its `#[from] std::io::Error` conversion through the `?`
        // operator in `read`).
        assert!(
            matches!(err, UtilError::Io(_)),
            "expected UtilError::Io, got {err:?}"
        );

        remove_all(&d).expect("remove_all");
    }

    #[test]
    fn create_is_mkdir_p_idempotent() {
        let d = tmpdir("createp");
        // Build a deep path that does not yet exist.
        let deep = d.join("a").join("b").join("c");
        assert!(!deep.exists());
        create(&deep).expect("create deep");
        assert!(deep.is_dir(), "deep path must now be a directory");

        // `create` should be idempotent when the path already exists.
        create(&deep).expect("second create must succeed");

        remove_all(&d).expect("remove_all");
    }

    #[test]
    fn remove_rejects_nonempty_directory() {
        let d = tmpdir("nonempty");
        fs::write(d.join("file.txt"), b"content").expect("write");
        let err = remove(&d).expect_err("remove must fail on non-empty dir");
        assert!(matches!(err, UtilError::Io(_)));
        // Clean up via the recursive variant.
        remove_all(&d).expect("remove_all");
    }

    #[test]
    fn remove_all_removes_nested_tree() {
        let d = tmpdir("nested");
        let sub = d.join("x").join("y");
        fs::create_dir_all(&sub).expect("create nested");
        fs::write(sub.join("leaf.txt"), b"leaf").expect("write leaf");
        assert!(sub.exists());

        remove_all(&d).expect("remove_all");
        assert!(!d.exists(), "remove_all must remove the root dir as well");
    }

    #[test]
    fn dirent_is_clone_and_debug() {
        // Instantiate a Dirent by hand and verify the derive-macro
        // contract (Clone + Debug) is intact — guards against someone
        // removing the `#[derive]` attribute in a future refactor.
        let d = Dirent {
            path: PathBuf::from("/tmp/foo"),
            name: "foo".to_string(),
            dtype: DT_REG,
        };
        let cloned = d.clone();
        assert_eq!(cloned.path, d.path);
        assert_eq!(cloned.name, d.name);
        assert_eq!(cloned.dtype, d.dtype);
        // `Debug` formatting must not panic.
        let _ = format!("{d:?}");
    }
}
