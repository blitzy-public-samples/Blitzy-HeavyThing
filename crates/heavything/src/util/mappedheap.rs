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

//! Heap-over-mmap allocator used by the TLS session cache. Port of
//! `mappedheap.inc`.
//!
//! # Historical Context (FASM original)
//!
//! The FASM `mappedheap.inc` module implements a freeblock-coalescing
//! heap backed by a [`mapped`](super::mapped) region that may be
//! anonymous (RAM-only) or file-backed. It is a dual-strategy
//! allocator — small allocations land in fixed-size bins, large
//! allocations land in a tree-ordered linked list of "unused pages"
//! that is flushed to dedicated 4 KiB metadata pages within the
//! mapping itself. The 32-byte header layout (`mappedheap_base_ofs`,
//! `mappedheap_size_ofs`, `mappedheap_fd_ofs`,
//! `mappedheap_largefree_ofs`) and the rationale "file based mapped
//! goods do MAP_SHARED" / "our base pointer itself can and will move!
//! (hence pointers are bad, haha)" are captured in `mappedheap.inc`
//! lines 45–80.
//!
//! The only in-tree consumer is the TLS session cache (see AAP
//! §0.5.1.7 and §0.7.2.4), which needs a large, persistent,
//! optionally-AES-256-encrypted memory region shared across forked
//! workers via `MAP_SHARED`.
//!
//! # Rust Strategy (per AAP §0.5.1.7, §0.7.2.4, §0.8.9)
//!
//! The FASM bin/tree allocator internals are **not** reproduced
//! faithfully — the TLS session cache treats the backing as a general
//! `alloc(size)` / `free(offset)` interface, which is behaviourally
//! sufficient with a simpler in-memory free-list. The port therefore
//! provides:
//!
//! * a thin [`MappedHeap`] type wrapping a single
//!   [`memmap2::MmapMut`] region (anonymous or file-backed), and
//! * an in-memory [`std::collections::BTreeMap`]`<u64, u64>`
//!   free-list (offset → size) implementing **first-fit** allocation
//!   with adjacent-block coalescing on free.
//!
//! AAP §0.8.9 explicitly requires std collections where semantically
//! equivalent; `BTreeMap` over `(offset, size)` is the minimal data
//! structure that supports both first-fit iteration and
//! predecessor/successor lookup for coalescing. The FASM heap's
//! allocator invariant (that free-list metadata lives inside the
//! mmap's first 4 KiB) is deliberately **not** preserved: the TLS
//! session cache is volatile across restarts, so rebuilding the
//! free-list in-memory each session is simpler and correct.
//!
//! # Pointer-stability divergence
//!
//! The FASM note "our base pointer itself can and will move!" refers
//! to `mremap(2)` growing the mapping. This port does not grow
//! mappings; `MappedHeap` is fixed-size after construction. Callers
//! reference allocations via the opaque [`MappedOffset`] handle,
//! which is stable for the heap's lifetime regardless of internal
//! state.
//!
//! # Concurrency
//!
//! All public methods serialise through an internal [`Mutex`]; the
//! type is therefore [`Send`] + [`Sync`] and safe to share across
//! tokio tasks via [`Arc`](std::sync::Arc).
//!
//! # Persistence
//!
//! * [`MappedHeap::new_anon`] creates a volatile RAM-only mapping
//!   (`MAP_ANONYMOUS | MAP_PRIVATE`), suitable for single-process
//!   session caches.
//! * [`MappedHeap::new_file`] creates a `MAP_SHARED` mapping over a
//!   truncated backing file, matching FASM's invariant so multiple
//!   forked workers see a single page-cache view. Writes are flushed
//!   to disk by the kernel.
//!
//! # Unsafe audit
//!
//! The sole `unsafe` block in this module is inside
//! [`MappedHeap::new_file`] at the [`memmap2::MmapOptions::map_mut`]
//! call. Its safety invariant — file ownership for the lifetime of
//! the mapping, and no external truncation — is documented inline
//! per `#![warn(clippy::undocumented_unsafe_blocks)]` and catalogued
//! in `UNSAFE_AUDIT.md` per AAP §0.7.4.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::Mutex;

use memmap2::{MmapMut, MmapOptions};

use crate::error::UtilError;

// ---------------------------------------------------------------------------
// Public types.
// ---------------------------------------------------------------------------

/// Opaque handle to a region previously allocated from a
/// [`MappedHeap`]. Wraps a byte offset into the mapping.
///
/// `MappedOffset` values are **stable** for the lifetime of the heap
/// that produced them — unlike the FASM baseline, where the base
/// pointer could move after `mremap(2)`, this port uses a fixed-size
/// mapping and therefore needs no relocation of handles. The wrapped
/// `u64` is public for ergonomic zero-cost conversion to `usize` when
/// callers need direct indexing (e.g., in integration tests).
///
/// Passing a `MappedOffset` from one `MappedHeap` to a different
/// `MappedHeap` is not detected and will result in silent corruption
/// or an out-of-bounds error; the semantics are identical to FASM's
/// raw pointer return from `mappedheap$alloc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MappedOffset(pub u64);

/// A heap allocator backed by a single `mmap(2)` region (anonymous
/// or file-backed).
///
/// Direct Rust port of the FASM `mappedheap` object. The sole
/// in-tree consumer is `heavything::net::tls`'s session cache (AAP
/// §0.5.1.7 / §0.7.2.4); external callers are welcome but should
/// understand the non-persistent free-list semantics documented
/// above.
///
/// # Allocation strategy
///
/// First-fit: [`MappedHeap::alloc`] walks the ordered free-list
/// (a [`BTreeMap`]) and returns the first block with sufficient
/// size, splitting the remainder back into the free-list if any.
/// [`MappedHeap::free`] inserts the released block into the
/// free-list and coalesces with the immediate predecessor and
/// successor when they are adjacent. The strategy is deliberately
/// simple — it is correct, not fast — and matches the behavioural
/// envelope expected by the TLS session cache.
///
/// # Errors
///
/// Every public method returns [`UtilError::Mmap`] for internal
/// failures (mutex poisoning, out-of-memory, out-of-bounds access)
/// and [`UtilError::Io`] for file-open / truncate failures in
/// [`MappedHeap::new_file`] (auto-converted via `#[from]`).
///
/// # Examples
///
/// ```ignore
/// use heavything::util::mappedheap::MappedHeap;
/// let heap = MappedHeap::new_anon(4096)?;
/// let off = heap.alloc(128)?;
/// heap.write(off, b"hello")?;
/// let bytes = heap.slice_mut(off, 5)?;
/// assert_eq!(&bytes, b"hello");
/// heap.free(off, 128)?;
/// # Ok::<(), heavything::error::UtilError>(())
/// ```
pub struct MappedHeap {
    /// Interior-mutable state gated by a [`Mutex`] so public methods
    /// can take `&self` and be invoked from concurrent tokio tasks
    /// that share the heap through [`Arc`](std::sync::Arc).
    inner: Mutex<MappedHeapInner>,
}

/// Internal state behind the [`MappedHeap`] mutex.
///
/// Grouped into a single struct so the [`Mutex::lock`] call
/// produces a single guard that proves exclusive access to both the
/// mapping bytes and the free-list simultaneously — this is the
/// invariant that prevents the classic "TOCTOU on allocator
/// metadata" race.
struct MappedHeapInner {
    /// The mmap-backed region itself. `MmapMut` covers both
    /// anonymous (`MAP_ANONYMOUS | MAP_PRIVATE`) and file-backed
    /// (`MAP_SHARED`) variants — the distinction is irrelevant at
    /// the allocator layer.
    mmap: MmapMut,
    /// Cached length of `mmap` in bytes, matching FASM
    /// `mappedheap_size_ofs`. Retained as `usize` because slice
    /// indexing operates in `usize`.
    size: usize,
    /// Free-list mapping block-start offset (`u64`) to block size
    /// (`u64`). Keyed by offset so adjacent-block coalescing can use
    /// [`BTreeMap::range`] to find the predecessor (strictly less
    /// than the freed offset) and successor (greater than or equal
    /// to the freed offset). `u64` is used throughout for
    /// architecture-independent math even though `usize` would
    /// suffice on `x86_64`; this eliminates a whole class of
    /// conversion errors on the free path.
    free_list: BTreeMap<u64, u64>,
}

// ---------------------------------------------------------------------------
// Constructors.
// ---------------------------------------------------------------------------

impl MappedHeap {
    /// Create a new anonymous (RAM-only) heap of `size` bytes.
    ///
    /// Direct port of the `new_anon = 1` branch of FASM
    /// `mappedheap$new`. The underlying mapping is backed by
    /// `MAP_ANONYMOUS | MAP_PRIVATE` (see
    /// [`memmap2::MmapMut::map_anon`]), which is internally safe
    /// because the kernel guarantees exclusive, zero-initialised
    /// pages.
    ///
    /// The entire range `[0, size)` is initially a single free
    /// block.
    ///
    /// # Errors
    ///
    /// Returns [`UtilError::Mmap`] if `mmap(2)` fails — typically
    /// when `size` exceeds the address-space limit or `RLIMIT_AS`.
    pub fn new_anon(size: usize) -> Result<Self, UtilError> {
        let mmap = MmapMut::map_anon(size).map_err(|e| UtilError::Mmap(e.to_string()))?;
        let mut free_list = BTreeMap::new();
        // The whole arena is initially one free block spanning
        // `[0, size)`. `size` is bounded by `usize::MAX` per
        // `map_anon`'s contract, so the `as u64` cast cannot
        // truncate on `x86_64` (`usize == u64`).
        free_list.insert(0u64, size as u64);
        Ok(Self {
            inner: Mutex::new(MappedHeapInner {
                mmap,
                size,
                free_list,
            }),
        })
    }

    /// Create a new file-backed heap of `size` bytes at `path`.
    ///
    /// Direct port of the `new_cstr` branch of FASM
    /// `mappedheap$new`. The file is opened `O_RDWR | O_CREAT`
    /// (without `O_TRUNC`, so existing content is preserved and
    /// overlaid after [`File::set_len`](std::fs::File::set_len)),
    /// then truncated / extended to exactly `size` bytes and mapped
    /// with `MAP_SHARED` — the FASM invariant "file based mapped
    /// goods do MAP_SHARED" (`mappedheap.inc` line 45) ensures
    /// forked workers share a single kernel page-cache view.
    ///
    /// `P` is generic over anything [`AsRef<Path>`] so callers may
    /// pass `&str`, `&Path`, `PathBuf`, etc.
    ///
    /// # Errors
    ///
    /// * [`UtilError::Io`] (auto-converted from
    ///   [`std::io::Error`]) if the `open(2)` or `ftruncate(2)`
    ///   syscall fails — typically when the path is invalid,
    ///   permissions are insufficient, or the filesystem is full.
    /// * [`UtilError::Mmap`] if the [`mmap(2)`](memmap2::MmapOptions::map_mut)
    ///   syscall fails — typically address-space exhaustion or
    ///   attempts to map a non-regular file.
    pub fn new_file<P: AsRef<Path>>(path: P, size: u64) -> Result<Self, UtilError> {
        // `create(true) + truncate(false)` preserves existing
        // contents; the explicit `set_len` below then grows (or
        // shrinks) the file to the requested heap size exactly.
        // These two steps together replace FASM's `syscall_open` +
        // `syscall_ftruncate` pair from `mappedheap.inc` lines
        // 87–90. The `?` operator auto-converts `std::io::Error`
        // into `UtilError::Io` via the `#[from]` conversion in
        // `error.rs`.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        file.set_len(size)?;

        // SAFETY: `memmap2::MmapOptions::map_mut` is marked
        // `unsafe` because a file-backed mapping's contents can be
        // invalidated by external mutation (truncation, file
        // deletion on some filesystems, or writes by another
        // process through the same backing), which could cause
        // SIGBUS on subsequent access or admit cross-process
        // data-race semantics for `&mut [u8]` access. We uphold
        // the memmap2 safety contract as follows:
        //
        //  * `file` is a locally-owned `std::fs::File` created on
        //    the preceding lines; memmap2's `map_mut()` dupes the
        //    file descriptor it needs internally, so dropping
        //    `file` at end-of-function is sound.
        //  * The file was just resized via `set_len(size)` and is
        //    not shared through any other path at this point in
        //    execution, so the length requested here matches the
        //    kernel's view.
        //  * The FASM baseline `mappedheap.inc` carries the
        //    identical caveat (external processes truncating the
        //    backing file would break it too); per AAP §0.7.4 this
        //    is the documented residual risk of the FFI boundary
        //    and is listed in `UNSAFE_AUDIT.md`. The integration
        //    test is `ffi_boundary::test_mmap_file_cache`
        //    (AAP §0.7.4.4).
        let mmap = unsafe {
            MmapOptions::new()
                .len(size as usize)
                .map_mut(&file)
                .map_err(|e| UtilError::Mmap(e.to_string()))?
        };

        let mut free_list = BTreeMap::new();
        free_list.insert(0u64, size);
        Ok(Self {
            inner: Mutex::new(MappedHeapInner {
                mmap,
                size: size as usize,
                free_list,
            }),
        })
    }
}

// ---------------------------------------------------------------------------
// Allocator surface.
// ---------------------------------------------------------------------------

impl MappedHeap {
    /// Allocate a contiguous region of `size` bytes from the heap.
    ///
    /// Uses a **first-fit** strategy — the free-list is walked in
    /// offset order and the first block with
    /// `free_size >= requested_size` is chosen. If the chosen block
    /// is larger than the request, the remainder is inserted back
    /// into the free-list at the appropriate offset.
    ///
    /// Returns an opaque [`MappedOffset`] handle that subsequent
    /// [`MappedHeap::write`], [`MappedHeap::slice_mut`], and
    /// [`MappedHeap::free`] calls use to address the region.
    ///
    /// # Errors
    ///
    /// * [`UtilError::Mmap`] with message
    ///   `"mappedheap: out of memory"` if no free block can satisfy
    ///   the request. The free-list is unchanged on error.
    /// * [`UtilError::Mmap`] with message
    ///   `"MappedHeap mutex poisoned"` if a prior panic left the
    ///   internal mutex in a poisoned state; the heap is logically
    ///   unusable thereafter.
    pub fn alloc(&self, size: usize) -> Result<MappedOffset, UtilError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| UtilError::Mmap("MappedHeap mutex poisoned".into()))?;
        let size64 = size as u64;

        // First-fit scan in offset order. `BTreeMap::iter` already
        // yields `(offset, size)` pairs sorted ascending by offset,
        // matching the FASM allocator's "scan from the start"
        // convention. Collecting a key lets us mutate the map
        // immediately below without fighting the borrow checker.
        let found = inner
            .free_list
            .iter()
            .find(|&(_, &free_sz)| free_sz >= size64)
            .map(|(&off, &free_sz)| (off, free_sz));

        let (off, free_sz) = match found {
            Some(pair) => pair,
            None => return Err(UtilError::Mmap("mappedheap: out of memory".into())),
        };

        // Remove the full free block, then re-insert the
        // post-allocation remainder if any. This two-step update
        // preserves the free-list invariant "every entry has
        // nonzero size" — we skip the re-insert when the block
        // exactly matches the request.
        inner.free_list.remove(&off);
        if free_sz > size64 {
            inner.free_list.insert(off + size64, free_sz - size64);
        }

        Ok(MappedOffset(off))
    }

    /// Release a previously-allocated region back to the free-list,
    /// coalescing with adjacent free blocks where possible.
    ///
    /// `size` must match the `size` originally passed to
    /// [`MappedHeap::alloc`] — the heap does **not** record
    /// allocation sizes on the allocation path (matching FASM's
    /// `mappedheap$free` signature, which takes an explicit size
    /// argument). Passing a mismatched size fragments the heap
    /// silently rather than panicking, to preserve FASM behaviour.
    ///
    /// Coalescing examines the immediate predecessor free block
    /// (via [`BTreeMap::range`] reverse walk) and the immediate
    /// successor (via forward walk); if either abuts the freed
    /// region they are merged into a single free block.
    ///
    /// # Errors
    ///
    /// Returns [`UtilError::Mmap`] with message
    /// `"MappedHeap mutex poisoned"` on mutex poisoning. The
    /// free-list is unchanged on error.
    pub fn free(&self, offset: MappedOffset, size: usize) -> Result<(), UtilError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| UtilError::Mmap("MappedHeap mutex poisoned".into()))?;

        // Canonical (offset, size) of the freed region; both may
        // grow via coalescing before final insertion.
        let mut off = offset.0;
        let mut sz = size as u64;

        // Coalesce with the immediate predecessor if adjacent.
        // `range(..off)` yields entries with key strictly less than
        // `off`; `.next_back()` picks the largest such key — the
        // nearest predecessor. We detach the pair into locals
        // before mutating the map to sidestep the borrow checker.
        let prev = inner
            .free_list
            .range(..off)
            .next_back()
            .map(|(&prev_off, &prev_sz)| (prev_off, prev_sz));
        if let Some((prev_off, prev_sz)) = prev {
            if prev_off + prev_sz == off {
                inner.free_list.remove(&prev_off);
                off = prev_off;
                sz += prev_sz;
            }
        }

        // Coalesce with the immediate successor if adjacent.
        // `range(off..)` yields entries with key `>= off`; the
        // first such entry is the nearest successor. Adjacency is
        // `off + sz == next_off` (the freed region's right edge
        // touching the successor's left edge).
        let next = inner
            .free_list
            .range(off..)
            .next()
            .map(|(&next_off, &next_sz)| (next_off, next_sz));
        if let Some((next_off, next_sz)) = next {
            if off + sz == next_off {
                inner.free_list.remove(&next_off);
                sz += next_sz;
            }
        }

        // Insert the (possibly-coalesced) free block.
        inner.free_list.insert(off, sz);
        Ok(())
    }

    /// Read a contiguous region from the heap as an owned
    /// `Vec<u8>`.
    ///
    /// Returning an owned copy (rather than a borrowed slice) means
    /// the mutex is released before the caller accesses the data,
    /// which matches the FASM `mappedheap$read` semantics where the
    /// allocator yielded caller-owned scratch buffers. A zero-copy
    /// variant (taking `&mut self` and returning a `&mut [u8]`
    /// pinned to the guard's lifetime) is intentionally **not**
    /// exposed: the sole in-tree consumer (TLS session cache)
    /// serialises entries and so always wants owned bytes anyway,
    /// and the public API surface is kept narrower until proven
    /// insufficient.
    ///
    /// # Errors
    ///
    /// * [`UtilError::Mmap`] with message
    ///   `"mappedheap: slice out of bounds"` if
    ///   `offset + size > heap_size` (using [`usize::checked_add`]
    ///   to guard against overflow).
    /// * [`UtilError::Mmap`] with message
    ///   `"MappedHeap mutex poisoned"` on mutex poisoning.
    pub fn slice_mut(&self, offset: MappedOffset, size: usize) -> Result<Vec<u8>, UtilError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| UtilError::Mmap("MappedHeap mutex poisoned".into()))?;
        let start = offset.0 as usize;
        // Use `checked_add` so pathologically large `size` values
        // do not wrap to a small end index and bypass the bounds
        // check — a CVE-class bug in C code that Rust avoids here.
        let end = start
            .checked_add(size)
            .ok_or_else(|| UtilError::Mmap("mappedheap: slice end overflow".into()))?;
        if end > inner.size {
            return Err(UtilError::Mmap("mappedheap: slice out of bounds".into()));
        }
        Ok(inner.mmap[start..end].to_vec())
    }

    /// Write `bytes` into the heap starting at `offset`.
    ///
    /// Direct port of FASM `mappedheap$write` at the semantic
    /// level. For file-backed heaps, changes become visible to
    /// concurrent readers of the same file because the mapping uses
    /// `MAP_SHARED` — the kernel flushes modified pages in the
    /// background. Explicit `msync(2)` is not invoked here; the
    /// FASM original didn't either, leaving flushing to the kernel.
    ///
    /// # Errors
    ///
    /// * [`UtilError::Mmap`] with message
    ///   `"mappedheap: write end overflow"` if
    ///   `offset + bytes.len()` overflows `usize`.
    /// * [`UtilError::Mmap`] with message
    ///   `"mappedheap: write out of bounds"` if
    ///   `offset + bytes.len() > heap_size`.
    /// * [`UtilError::Mmap`] with message
    ///   `"MappedHeap mutex poisoned"` on mutex poisoning.
    pub fn write(&self, offset: MappedOffset, bytes: &[u8]) -> Result<(), UtilError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| UtilError::Mmap("MappedHeap mutex poisoned".into()))?;
        let start = offset.0 as usize;
        let end = start
            .checked_add(bytes.len())
            .ok_or_else(|| UtilError::Mmap("mappedheap: write end overflow".into()))?;
        if end > inner.size {
            return Err(UtilError::Mmap("mappedheap: write out of bounds".into()));
        }
        inner.mmap[start..end].copy_from_slice(bytes);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unit tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: allocate, write, read back, free — the basic
    /// lifecycle the TLS session cache exercises on every session
    /// add / evict.
    #[test]
    fn anon_alloc_free_roundtrip() {
        let h = MappedHeap::new_anon(4096).expect("alloc heap");
        let off = h.alloc(128).expect("alloc 128");
        h.write(off, b"hello").expect("write");
        let v = h.slice_mut(off, 5).expect("read");
        assert_eq!(&v, b"hello");
        h.free(off, 128).expect("free");
    }

    /// Out-of-memory path: requesting a block larger than the total
    /// heap size must return `UtilError::Mmap` — the TLS session
    /// cache relies on this signal to prune its LRU before
    /// retrying.
    #[test]
    fn out_of_memory() {
        let h = MappedHeap::new_anon(256).expect("alloc heap");
        assert!(h.alloc(512).is_err());
    }

    /// Adjacent-block coalescing: two sequential allocations, when
    /// freed in order, must merge back into a single whole-heap
    /// free block. Verified by successfully re-allocating the
    /// entire 4096-byte region.
    #[test]
    fn coalesce_adjacent_free() {
        let h = MappedHeap::new_anon(4096).expect("alloc heap");
        let a = h.alloc(128).expect("a");
        let b = h.alloc(128).expect("b");
        h.free(a, 128).expect("free a");
        h.free(b, 128).expect("free b");
        // After coalescing, a single 4096-byte block should be
        // available starting at offset 0. This assertion fails if
        // coalescing is broken, if the initial free block is
        // misplaced, or if the free on `b` is inserted before the
        // free on `a` but coalescing with the predecessor is
        // missing.
        let c = h.alloc(4096).expect("single 4096 alloc");
        assert_eq!(c, MappedOffset(0));
    }

    /// Boundary-case: allocating exactly the whole heap should
    /// succeed, return offset 0, and fully drain the free-list.
    #[test]
    fn exact_size_alloc_drains_freelist() {
        let h = MappedHeap::new_anon(1024).expect("alloc heap");
        let off = h.alloc(1024).expect("alloc whole");
        assert_eq!(off, MappedOffset(0));
        // A subsequent one-byte alloc must fail (free-list empty).
        assert!(h.alloc(1).is_err());
        h.free(off, 1024).expect("free whole");
        // After the free, the whole heap is available again.
        let off2 = h.alloc(1024).expect("re-alloc");
        assert_eq!(off2, MappedOffset(0));
    }

    /// Reverse-order coalescing: free `b` first, then `a`. The
    /// `free(b)` call has only the whole tail as a successor
    /// (not adjacent), so no coalescing; the `free(a)` call then
    /// has `b`'s block as an adjacent successor and must coalesce
    /// forward.
    #[test]
    fn coalesce_successor_then_predecessor() {
        let h = MappedHeap::new_anon(4096).expect("alloc heap");
        let a = h.alloc(128).expect("a");
        let b = h.alloc(128).expect("b");
        // Free the second allocation first; it should coalesce
        // with the remaining tail free block.
        h.free(b, 128).expect("free b");
        // Then free the first; it must coalesce with the now-large
        // successor block.
        h.free(a, 128).expect("free a");
        let c = h.alloc(4096).expect("single 4096 alloc");
        assert_eq!(c, MappedOffset(0));
    }

    /// Bounds-check: slice_mut beyond heap size must error, not
    /// return a clipped or wraparound view.
    #[test]
    fn slice_mut_out_of_bounds_errors() {
        let h = MappedHeap::new_anon(256).expect("alloc heap");
        assert!(h.slice_mut(MappedOffset(200), 100).is_err());
    }

    /// Bounds-check: write beyond heap size must error before
    /// touching memory.
    #[test]
    fn write_out_of_bounds_errors() {
        let h = MappedHeap::new_anon(256).expect("alloc heap");
        let payload = [0u8; 100];
        assert!(h.write(MappedOffset(200), &payload).is_err());
    }

    /// Overflow guard: slice_mut with a `size` that would overflow
    /// `start + size` must error, proving `checked_add` guards
    /// against the classic wraparound-bypass bug class.
    #[test]
    fn slice_mut_overflow_guard() {
        let h = MappedHeap::new_anon(256).expect("alloc heap");
        assert!(h.slice_mut(MappedOffset(1), usize::MAX).is_err());
    }

    /// MappedOffset equality works as expected for handle
    /// comparison (used by the adjacent-free coalescing test and
    /// by downstream TLS session-cache bookkeeping).
    #[test]
    fn mapped_offset_is_comparable() {
        assert_eq!(MappedOffset(42), MappedOffset(42));
        assert_ne!(MappedOffset(42), MappedOffset(43));
    }

    /// File-backed heaps flush writes back through the `MAP_SHARED`
    /// mapping so re-opening the file observes the same bytes.
    /// This test double-checks the FASM invariant "file based
    /// mapped goods do MAP_SHARED" (`mappedheap.inc` line 45).
    #[test]
    fn file_backed_roundtrip_persists_through_drop() {
        use std::io::Read;
        let tmp =
            std::env::temp_dir().join(format!("blitzy_adhoc_test_mappedheap_{}.bin", std::process::id()));
        // Scope the heap so Drop tears down the mmap before the
        // read-back; without Drop, the MAP_SHARED flush might be
        // deferred.
        {
            let h = MappedHeap::new_file(&tmp, 4096).expect("new_file");
            let off = h.alloc(5).expect("alloc");
            h.write(off, b"world").expect("write");
        }
        let mut buf = Vec::new();
        std::fs::File::open(&tmp)
            .expect("reopen")
            .read_to_end(&mut buf)
            .expect("read");
        assert_eq!(&buf[..5], b"world");
        // Cleanup: remove the temp file so successive test runs
        // start clean.
        let _ = std::fs::remove_file(&tmp);
    }
}
