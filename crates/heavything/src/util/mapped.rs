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

//! mmap-backed file access via [`memmap2::Mmap`]. Port of `mapped.inc`.
//!
//! # Historical Context (FASM original)
//!
//! The FASM `mapped.inc` exposes a 24-byte `mapped` "object" with three
//! fields (`mapped_base_ofs` at +0, `mapped_size_ofs` at +8,
//! `mapped_fd_ofs` at +16) and two constructors — `mapped$new_anon` for an
//! anonymous RAM-only region (using `mmap(MAP_ANONYMOUS | MAP_PRIVATE)`)
//! and `mapped$new_cstr` for a file-backed region (using
//! `mmap(MAP_SHARED)` on the file descriptor returned from `open(2)`).
//! The assembly consumer — the `webserver.inc` file hotlist cache —
//! treats the returned buffer as a zero-copy view of on-disk bytes, with
//! `MAP_SHARED` chosen so that multiple workers see a single page cache
//! across forked processes. See AAP §0.5.1.7.
//!
//! # Rust Strategy (per AAP §0.5.1.7 and §0.7.4.1)
//!
//! This module delegates to the [`memmap2`] crate, which wraps
//! `mmap(2)` / `munmap(2)` behind safe-by-construction lifetime types
//! (`MmapMut`, `Mmap`) with automatic `Drop` cleanup. Two variants are
//! preserved from the FASM API:
//!
//! * [`Mapped::new_anon`] — calls [`MmapMut::map_anon`], which is a
//!   **safe** function (no `unsafe` block required): memmap2 guarantees
//!   the resulting region is RAM-only and cannot be corrupted by
//!   external processes.
//! * [`Mapped::new_file`] — calls [`MmapOptions::map`] with
//!   `.populate()` (→ `MAP_POPULATE`, matching FASM's eager page-load
//!   intent) and without `map_copy` (→ default `MAP_SHARED`, exactly
//!   matching FASM `mapped$new_cstr`). This call is the module's sole
//!   `unsafe` site (AAP §0.7.4.1); its safety invariant is documented
//!   at the call site per `#![warn(clippy::undocumented_unsafe_blocks)]`.
//!
//! Divergences from the FASM behaviour:
//!
//! * File-backed mappings are opened **read-only** here
//!   ([`std::fs::File::open`]) where FASM opens the file with
//!   `O_RDWR | O_CREAT`. This is a deliberate tightening: the
//!   documented consumer (the `webserver` file cache) only ever reads
//!   served content, and read-only + `MAP_SHARED` is the narrowest
//!   privilege set that still matches FASM's observable semantics.
//!   The [`Mapped::as_bytes_mut`] accessor returns `None` for
//!   file-backed mappings to make this invariant unforgeable at the
//!   type level.
//! * The 24-byte FASM struct's `fd_ofs` slot is encapsulated inside
//!   [`Mmap`] (memmap2 tracks the descriptor internally and closes it
//!   in `Drop`); callers have no reason to reach in.
//!
//! # Sibling module
//!
//! For `MAP_PRIVATE` copy-on-write semantics, see
//! `crate::util::privmapped`.

use std::fs::File;
use std::path::Path;

use memmap2::{Mmap, MmapMut, MmapOptions};

use crate::error::UtilError;

/// Read-only mmap-backed file region. Direct translation of the FASM
/// `mapped` struct from `mapped.inc`.
///
/// A `Mapped` value represents one of two backings: an **anonymous**
/// RAM-only region (via [`Mapped::new_anon`]) that acts like a
/// page-aligned `Vec<u8>` but with mmap-derived allocation, or a
/// **file-backed** read-only region (via [`Mapped::new_file`]) that
/// provides zero-copy access to on-disk bytes through the kernel page
/// cache. Which variant is active can be queried with
/// [`Mapped::is_file_backed`].
///
/// The underlying mapping is released automatically when `Mapped` is
/// dropped (memmap2 invokes `munmap(2)` in its `Drop` impl and, for
/// file-backed variants, closes the internally-held file descriptor).
///
/// # Threading
///
/// The type is [`Send`] and [`Sync`] because its payload
/// ([`MmapMut`] / [`Mmap`]) is. Concurrent readers through
/// [`Mapped::as_bytes`] on different threads are sound; mutation via
/// [`Mapped::as_bytes_mut`] still requires `&mut self` and is
/// therefore statically serialised by the borrow checker.
pub struct Mapped {
    /// Which backing variant holds the mapped region.
    mmap: MappedInner,
    /// Cached length of the mapping in bytes. Matches FASM
    /// `mapped_size_ofs`.
    size: usize,
}

/// Internal discriminated union for the two FASM-compatible backings.
///
/// Kept private so the public [`Mapped`] surface is a single type with
/// matched accessor semantics instead of an API-breaking enum.
enum MappedInner {
    /// `MAP_ANONYMOUS | MAP_PRIVATE` (FASM `mapped$new_anon`). Mutable
    /// through [`Mapped::as_bytes_mut`].
    Anon(MmapMut),
    /// `MAP_SHARED | MAP_POPULATE` over a read-only file descriptor
    /// (FASM `mapped$new_cstr` with a narrower `O_RDONLY` open).
    /// Read-only: [`Mapped::as_bytes_mut`] returns `None`.
    File(Mmap),
}

impl Mapped {
    /// Create an anonymous (RAM-only) mmap region of `size` bytes.
    /// Direct port of FASM `mapped$new_anon`.
    ///
    /// The returned region is zero-initialised by the kernel (the
    /// standard `MAP_ANONYMOUS` guarantee) and is mutable in-place via
    /// [`Mapped::as_bytes_mut`]. No file descriptor is consumed; the
    /// allocation is backed purely by anonymous virtual memory.
    ///
    /// # Errors
    ///
    /// Returns [`UtilError::Mmap`] if the underlying
    /// `mmap(..., MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)` syscall fails —
    /// typically when `size` exceeds available address space or when
    /// `RLIMIT_AS` / `RLIMIT_DATA` limits are reached.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use heavything::util::mapped::Mapped;
    /// let mut m = Mapped::new_anon(4096)?;
    /// if let Some(buf) = m.as_bytes_mut() {
    ///     buf[..5].copy_from_slice(b"hello");
    /// }
    /// # Ok::<(), heavything::error::UtilError>(())
    /// ```
    pub fn new_anon(size: usize) -> Result<Self, UtilError> {
        let mmap = MmapMut::map_anon(size).map_err(|e| UtilError::Mmap(e.to_string()))?;
        Ok(Self {
            mmap: MappedInner::Anon(mmap),
            size,
        })
    }

    /// Create a file-backed mmap region over the entire length of the
    /// file at `path`. Direct port of FASM `mapped$new_cstr`.
    ///
    /// The file is opened **read-only** ([`File::open`]) and its full
    /// length (queried via [`File::metadata`]) is mapped with the
    /// following flags, matching FASM:
    ///
    /// * `MAP_SHARED` — multiple mappings of the same file see the
    ///   same page cache; required for the `webserver` file cache to
    ///   share pages between forked workers.
    /// * `MAP_POPULATE` (via [`MmapOptions::populate`]) — eagerly
    ///   faults in all pages at map time rather than lazily on first
    ///   access, matching FASM's intent that mapped pages be "hot"
    ///   before the worker loop begins serving.
    ///
    /// # Errors
    ///
    /// * [`UtilError::Io`] if [`File::open`] or [`File::metadata`]
    ///   fails (missing file, permission denied, etc.).
    /// * [`UtilError::Mmap`] if the underlying `mmap(2)` syscall
    ///   fails — e.g. address-space exhaustion, unsupported file type
    ///   (pipe/socket), or `size == 0` on kernels that reject
    ///   zero-length mappings.
    ///
    /// # Concurrency caveat
    ///
    /// As with every file-backed mapping, the kernel may invalidate
    /// pages if the file is truncated or modified by another process
    /// while the mapping is live; the FASM original carries the same
    /// caveat. Callers who need to guard against this should hold an
    /// exclusive `flock(2)` or coordinate at the application layer.
    pub fn new_file<P: AsRef<Path>>(path: P) -> Result<Self, UtilError> {
        let file = File::open(path)?;
        let file_len = file.metadata()?.len() as usize;
        // SAFETY: Creating a file-backed mmap is unsafe because the kernel
        // may invalidate the mapping (e.g. on file truncation or when the
        // backing store disappears), causing SIGBUS on subsequent access.
        // We uphold the standard memmap2 safety contract as follows:
        //
        //  * `file` is owned locally for the duration of this `unsafe`
        //    block; memmap2's `map()` internally duplicates the descriptor
        //    it needs, so dropping `file` at end-of-function is sound and
        //    does not prematurely unmap.
        //  * The file is opened `O_RDONLY` via `File::open`, so no
        //    aliasing `&mut [u8]` can be produced (`as_bytes_mut` returns
        //    `None` for the `File` variant); this eliminates data-race
        //    concerns between the mmap view and any potential writer in
        //    the same process.
        //  * Cross-process modification is an accepted platform caveat
        //    inherited from the FASM baseline (see module-level docs);
        //    callers needing ironclad guarantees must coordinate
        //    externally.
        let mmap = unsafe {
            MmapOptions::new()
                .len(file_len)
                .populate()
                .map(&file)
                .map_err(|e| UtilError::Mmap(e.to_string()))?
        };
        Ok(Self {
            mmap: MappedInner::File(mmap),
            size: file_len,
        })
    }

    /// Return an immutable byte-slice view over the mapped region.
    ///
    /// The returned slice is exactly [`Mapped::size`] bytes long. For
    /// anonymous mappings the bytes start zero-initialised; for
    /// file-backed mappings they are the raw on-disk contents as seen
    /// by the kernel page cache.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.mmap {
            MappedInner::Anon(m) => &m[..],
            MappedInner::File(m) => &m[..],
        }
    }

    /// Return a mutable byte-slice view **only** for anonymous
    /// mappings.
    ///
    /// Returns `None` for file-backed mappings, which are opened
    /// read-only by [`Mapped::new_file`] and therefore statically
    /// immutable. This encodes the FASM source's implicit contract
    /// (where the `webserver` file cache never writes through the
    /// mapping) directly into the Rust type system.
    pub fn as_bytes_mut(&mut self) -> Option<&mut [u8]> {
        match &mut self.mmap {
            MappedInner::Anon(m) => Some(&mut m[..]),
            MappedInner::File(_) => None,
        }
    }

    /// Return the size of the mapping in bytes. Matches FASM
    /// `mapped_size_ofs`.
    ///
    /// For anonymous mappings this is the value passed to
    /// [`Mapped::new_anon`]; for file-backed mappings it is the file
    /// length observed at [`Mapped::new_file`] time (subsequent file
    /// truncation does not change this cached value).
    pub fn size(&self) -> usize {
        self.size
    }

    /// Return `true` iff this mapping is file-backed (i.e. created
    /// via [`Mapped::new_file`]).
    ///
    /// Useful for distinguishing when [`Mapped::as_bytes_mut`] will
    /// return `None` without having to call it and match on the
    /// result.
    pub fn is_file_backed(&self) -> bool {
        matches!(self.mmap, MappedInner::File(_))
    }

    /// Flush pending writes in an anonymous mapping to the underlying
    /// memory region.
    ///
    /// For anonymous mappings this invokes
    /// [`memmap2::MmapMut::flush`] (which is itself a no-op on
    /// anonymous regions in current memmap2, but is provided for API
    /// parity and forward compatibility). For file-backed mappings
    /// this returns `Ok(())` immediately because the FASM
    /// `MAP_SHARED` backing auto-syncs through the kernel page cache
    /// without an explicit `msync(2)`; an explicit flush at the
    /// `Mapped` layer would be redundant here.
    ///
    /// # Errors
    ///
    /// Returns [`UtilError::Mmap`] if an underlying `msync(2)` fails.
    pub fn flush(&self) -> Result<(), UtilError> {
        match &self.mmap {
            MappedInner::Anon(m) => m.flush().map_err(|e| UtilError::Mmap(e.to_string())),
            MappedInner::File(_) => Ok(()),
        }
    }
}

// Manual `Debug` because neither `MmapMut` nor `Mmap` derive `Debug`,
// and even if they did, printing the entire mapped region for
// multi-megabyte file caches would be catastrophic. We project only
// the two externally meaningful fields.
impl std::fmt::Debug for Mapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mapped")
            .field("size", &self.size)
            .field("file_backed", &self.is_file_backed())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! Ad-hoc tests for the `Mapped` type.
    //!
    //! These cover the happy path for both backings plus the
    //! read-only invariant for file-backed mappings. A separate
    //! `tests/ffi_boundary.rs` integration test
    //! (`test_mmap_file_cache`, AAP §0.7.4.4) exercises the unsafe
    //! site under the full crate build configuration.

    use super::*;

    /// Unique temp-file path containing the current process ID and a
    /// nonce tag so tests running in parallel within the same process
    /// never collide on a shared path.
    fn tmp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("heavything_mapped_test_{}_{}", std::process::id(), tag));
        p
    }

    #[test]
    fn anon_roundtrip() {
        let mut m = Mapped::new_anon(4096).expect("anon mmap");
        assert_eq!(m.size(), 4096);
        assert!(!m.is_file_backed());
        let slice = m.as_bytes_mut().expect("mutable slice");
        slice[..5].copy_from_slice(b"hello");
        assert_eq!(&m.as_bytes()[..5], b"hello");
        // Flush is callable on anonymous mappings without error.
        m.flush().expect("anon flush");
    }

    #[test]
    fn file_backed_readonly() {
        let p = tmp_path("readonly");
        std::fs::write(&p, b"mapped_file_content").expect("write");
        let m = Mapped::new_file(&p).expect("file mmap");
        assert_eq!(m.as_bytes(), b"mapped_file_content");
        assert_eq!(m.size(), 19);
        assert!(m.is_file_backed());
        // Flush is a no-op for file-backed mappings but still callable.
        m.flush().expect("file flush");
        std::fs::remove_file(&p).expect("remove");
    }

    #[test]
    fn file_backed_no_mut() {
        let p = tmp_path("nomut");
        std::fs::write(&p, b"readonly").expect("write");
        let mut m = Mapped::new_file(&p).expect("file mmap");
        assert!(m.as_bytes_mut().is_none());
        std::fs::remove_file(&p).expect("remove");
    }

    #[test]
    fn debug_impl_does_not_print_contents() {
        let m = Mapped::new_anon(1024).expect("anon mmap");
        let s = format!("{m:?}");
        assert!(s.contains("Mapped"));
        assert!(s.contains("size"));
        assert!(s.contains("1024"));
        assert!(s.contains("file_backed"));
        assert!(s.contains("false"));
    }

    #[test]
    fn new_file_missing_returns_io_error() {
        let p = tmp_path("does_not_exist_never_written");
        // Ensure the path does not exist.
        let _ = std::fs::remove_file(&p);
        let err = Mapped::new_file(&p).expect_err("expected open error");
        assert!(matches!(err, UtilError::Io(_)), "expected Io, got {err:?}");
    }
}
