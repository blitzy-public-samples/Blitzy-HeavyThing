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

//! Private (`MAP_PRIVATE`) mmap variant with filename, mtime, and ETag.
//! Port of `privmapped.inc` (332 FASM lines).
//!
//! # Historical Context (FASM original)
//!
//! `privmapped.inc` implements an 80- or 88-byte "object" (the 88-byte
//! layout activates under `webservercfg` conditional compilation,
//! adding an `mtimestr_ofs` field at offset 72) that represents a
//! file-backed memory map with copy-on-write semantics:
//!
//! ```text
//! offset 0   (8) privmapped_base_ofs     — mmap base pointer
//! offset 8   (8) privmapped_size_ofs     — total size
//! offset 16  (8) privmapped_fd_ofs       — file descriptor
//! offset 24  (8) privmapped_mtime_ofs    — mtime seconds (from stat)
//! offset 32  (8) privmapped_filename_ofs — original filename string
//! offset 40  (8) privmapped_fname_ofs    — null-terminated cstring copy
//! offset 48  (8) privmapped_etag_ofs     — base64(SHA224(name+mtime)[0..26])
//! offset 56  (8) privmapped_pincount_ofs — reference pin count
//! offset 64  (8) privmapped_zbuf_ofs     — optional pre-gzipped buffer
//! offset 72  (8) privmapped_mtimestr_ofs — RFC 1123 mtime (webservercfg)
//! ```
//!
//! The FASM constructor (`privmapped$new`, lines 63–213) performs,
//! in order:
//!
//! 1. `open(2)` with `O_RDONLY` (and optional `O_NOATIME` if the
//!    `privmapped_noatime` compile-time flag is set — see the
//!    module-level FASM commentary at lines 30–33 which documents why
//!    the flag is disabled by default: `NOBODY` + `O_NOATIME` returns
//!    `EPERM`).
//! 2. `stat(2)` to recover the file size and modification timestamp;
//!    directories (`S_IFDIR`) and zero-byte files are rejected here.
//! 3. `mmap(2)` with `PROT_READ | MAP_PRIVATE` (**no** `MAP_POPULATE`,
//!    unlike the sibling `mapped.inc` — the FASM comment at line 28
//!    justifies this: most consumers do not want to block while the
//!    whole file faults in, especially when the file may be large).
//! 4. Optional ETag generation when the constructor's `bool` flag is
//!    set: `SHA224(filename ++ mtime_bytes)`, truncate to 27 bytes,
//!    base64-encode, strip any CRLF line breaks, wrap in double quotes.
//!
//! # Rust Strategy (per AAP §0.5.1.7 and §0.7.4.1)
//!
//! This module delegates the unsafe `mmap(2)` primitive to
//! [`memmap2::MmapOptions::map_copy_read_only`], which corresponds
//! **exactly** to `mmap(PROT_READ, MAP_PRIVATE)` — no `MAP_POPULATE`,
//! copy-on-write semantics, and no aliasing with the underlying file
//! (modifications via the mapping are invisible to other viewers and
//! not persisted). The FASM behaviour is preserved byte-for-byte at
//! the syscall level.
//!
//! Pin counting is translated to [`AtomicUsize`] so the downstream
//! `webserver` file-cache consumer can increment the reference count
//! from a per-request handler without holding the cache's outer lock.
//! The mtime is extracted via [`std::fs::Metadata::modified`] (which
//! reads `st_mtime` on Linux) and formatted to an RFC 1123 HTTP
//! `Date:` header value via [`crate::util::date::rfc1123`], matching
//! the FASM `ctime$to_jd` + `formatter$doit` sequence at lines 120–125.
//!
//! ETag computation (deferred until [`PrivMapped::compute_etag`] is
//! called, matching the FASM "generate a static etag if requested"
//! opt-in) uses SHA-256 (from [`crate::crypto::sha2`]) under the
//! default `crypto` Cargo feature. Per AAP §0.7.2 the Rust port is
//! free to use SHA-256 here because the FASM ETag is a *weak*
//! validator — it exists to let clients skip unchanged responses,
//! not for cryptographic integrity. A CRC-32 fallback via
//! [`crc32fast::Hasher`] is used when the `crypto` feature is
//! disabled so downstream crates can drop the `ring` dependency.
//!
//! # Sibling module
//!
//! For `MAP_SHARED` semantics (writes visible to other viewers of the
//! same file), see [`crate::util::mapped`]. That module implements
//! both an anonymous `MAP_PRIVATE` variant and a read-only
//! `MAP_SHARED | MAP_POPULATE` variant; this module is specifically
//! for the copy-on-write + filename+mtime case used by the
//! `webserver` file cache.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use memmap2::{Mmap, MmapOptions};

use crate::config::PRIVMAPPED_NOATIME;
use crate::error::UtilError;

/// Private-mapped file with metadata. Direct port of the FASM
/// `privmapped` struct from `privmapped.inc` (80- or 88-byte layout
/// depending on `webservercfg` conditional compilation).
///
/// A `PrivMapped` value represents a file that has been memory-mapped
/// with `PROT_READ | MAP_PRIVATE` semantics — the mapping is
/// read-only from outside, copy-on-write if (hypothetically) written
/// through a mutable view, and **not** shared with other viewers of
/// the same inode. Alongside the raw bytes it retains the metadata
/// needed to serve the file over HTTP: the original filename, the
/// `st_mtime` timestamp (both as raw Unix seconds and as an RFC 1123
/// `Date:` header string), an optional weak-validator ETag, a pin
/// count for cache-reference tracking, and an optional pre-gzipped
/// companion buffer.
///
/// # Semantics
///
/// - The mapping is **copy-on-write**: any (hypothetical) mutation via
///   the mapping is private to this process and does **not** propagate
///   to the file on disk. Since [`PrivMapped::as_bytes`] returns only
///   an immutable slice, mutation is in practice impossible through
///   the public API.
/// - `MAP_POPULATE` is **not** used; pages fault in lazily. This
///   matches FASM behaviour (see `privmapped.inc` line 28's
///   justification).
/// - External truncation or modification of the underlying file may
///   invalidate portions of the mapping and cause `SIGBUS` on
///   subsequent access. This caveat is inherited from the FASM
///   baseline and must be coordinated by the caller (for example, the
///   `webserver` file cache invalidates entries when `st_mtime`
///   changes, before allowing new mappings).
///
/// # Threading
///
/// The type is [`Send`] and [`Sync`]. Pin-count mutation through
/// [`PrivMapped::pin`] and [`PrivMapped::unpin`] is lock-free via
/// [`AtomicUsize`] so concurrent request handlers can share a single
/// `PrivMapped` entry in the webserver's file cache without holding
/// any outer mutex.
pub struct PrivMapped {
    /// The `MAP_PRIVATE` read-only memory mapping. Encapsulates the
    /// FASM `privmapped_base_ofs` (+0) pointer and `privmapped_fd_ofs`
    /// (+16) descriptor — memmap2 owns the dup'd file descriptor
    /// internally and releases both via `munmap(2)` + `close(2)` in
    /// its `Drop` impl.
    mmap: Mmap,

    /// The original filename as supplied to [`PrivMapped::open`].
    /// Replaces the FASM `privmapped_filename_ofs` (+32) slot; we use
    /// [`PathBuf`] (rather than two separate slots for a high-level
    /// string and a null-terminated cstring, as the FASM original
    /// does for FASM string vs. C-string interop) because Rust
    /// syscall wrappers consume [`Path`] directly.
    filename: PathBuf,

    /// Modification time as seconds since the Unix epoch. Matches
    /// FASM `privmapped_mtime_ofs` (+24), which is populated from
    /// `struct stat::st_mtime` at line 115.
    mtime: u64,

    /// Modification time formatted as an RFC 1123 HTTP `Date:` header
    /// value (for example `"Sun, 06 Nov 1994 08:49:37 GMT"`). Matches
    /// FASM `privmapped_mtimestr_ofs` (+72) — populated by the
    /// `ctime$to_jd` + `formatter$doit` sequence at lines 120–125
    /// under `webservercfg` conditional compilation. Populated
    /// unconditionally in the Rust port so the field is always
    /// available for HTTP response building.
    mtime_str: String,

    /// Base64-encoded ETag value (weak validator syntax `W/"..."`)
    /// or empty if not yet computed. Matches FASM
    /// `privmapped_etag_ofs` (+48). Populated on the first call to
    /// [`PrivMapped::compute_etag`] and cached thereafter, matching
    /// the FASM deferred-computation semantics where
    /// `privmapped$new`'s second argument toggles ETag generation at
    /// construction time.
    etag: String,

    /// Reference pin count for cache management. Matches FASM
    /// `privmapped_pincount_ofs` (+56). Initialised to zero; the
    /// FASM original notes at line 45 that the field is "not used in
    /// here but initialised to 0" — the downstream `webserver.inc`
    /// file-cache consumer drives it. Atomic so concurrent request
    /// handlers can pin/unpin without blocking.
    pin_count: AtomicUsize,

    /// Cached file length in bytes. Duplicates information also
    /// present in `self.mmap.len()` so [`PrivMapped::size`] stays
    /// [`u64`]-sized and matches the FASM `privmapped_size_ofs` (+8)
    /// slot exactly.
    size: usize,

    /// Optional pre-gzipped (`Content-Encoding: gzip`) companion
    /// buffer. Matches FASM `privmapped_zbuf_ofs` (+64), which is
    /// populated by the separate `privmapped$deflate` entry point at
    /// lines 299–331. The Rust port exposes this via
    /// [`PrivMapped::set_zbuf`] so the `webserver` can populate it
    /// after construction (matching FASM's two-step API) without
    /// forcing synchronous compression inside the constructor.
    zbuf: Option<Vec<u8>>,
}

impl PrivMapped {
    /// Open a file and create a private (copy-on-write) read-only
    /// mmap over it, populating the filename and mtime metadata.
    /// Direct port of FASM `privmapped$new` (`privmapped.inc` lines
    /// 63–213), with the ETag-generation flag deferred to an explicit
    /// [`PrivMapped::compute_etag`] call.
    ///
    /// The file is opened read-only; the `O_NOATIME` flag is set when
    /// the compile-time [`PRIVMAPPED_NOATIME`] constant is `true`.
    /// Note that `O_NOATIME` requires Linux kernel 2.6.8 or newer and
    /// returns `EPERM` when the current process does not own the file
    /// (hence the default of `false`). The size and `mtime` are read
    /// from the file's metadata, matching the FASM `stat(2)` call at
    /// lines 102–117. The mtime is formatted into an RFC 1123 HTTP
    /// `Date:` header value so [`PrivMapped::mtime_str`] can be
    /// returned cheaply later.
    ///
    /// # Errors
    ///
    /// - [`UtilError::Io`] if the file cannot be opened, if
    ///   [`File::metadata`] fails, if [`SystemTime::duration_since`]
    ///   reports an mtime earlier than the Unix epoch, or if
    ///   [`std::fs::Metadata::modified`] is not supported on the
    ///   underlying filesystem.
    /// - [`UtilError::Mmap`] if the underlying
    ///   `mmap(PROT_READ, MAP_PRIVATE)` syscall fails — for example
    ///   when `size == 0` (some kernels reject zero-length mappings)
    ///   or when `RLIMIT_AS` is exhausted. The FASM baseline rejects
    ///   zero-byte files earlier in the `stat(2)` check (line 112);
    ///   the Rust port surfaces the same class of condition through
    ///   the memmap2 error path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, UtilError> {
        let path: PathBuf = path.as_ref().to_owned();

        // Open the file read-only, optionally requesting `O_NOATIME`
        // when the compile-time knob is enabled. `O_NOATIME` is a
        // Linux-specific flag (see `open(2)` man page) so the
        // `custom_flags` invocation is guarded behind a cfg gate.
        // FASM source lines 89–95.
        let file = {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::OpenOptionsExt;

                // `O_NOATIME = 0o1_000_000` on Linux per `<bits/fcntl-linux.h>`
                // (FASM `0x40000` at line 92 — octal 01_000_000 == hex 0x40000).
                const O_NOATIME: i32 = 0o1_000_000;

                let mut options = File::options();
                options.read(true);
                if PRIVMAPPED_NOATIME {
                    options.custom_flags(O_NOATIME);
                }
                options.open(&path)?
            }
            #[cfg(not(target_os = "linux"))]
            {
                // On non-Linux targets `O_NOATIME` is unavailable;
                // the flag is silently ignored. This branch exists
                // purely for portability — the production project
                // targets only `x86_64-unknown-linux-gnu` per AAP
                // §0.1.1 "Linux-only" directive.
                File::open(&path)?
            }
        };

        // Recover size and mtime from the file metadata. The FASM
        // original performs `stat(2)` on the path; we let the kernel
        // service the stat through `fstat(2)` on the already-open
        // descriptor, which is equivalent for our purposes (same
        // inode, same mtime, no TOCTOU concerns the FASM original
        // does not also have).
        let meta = file.metadata()?;
        let size = meta.len() as usize;

        let mtime_system = meta.modified()?;
        let mtime = mtime_system
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| UtilError::Io(std::io::Error::other("mtime before UNIX epoch")))?
            .as_secs();

        // SAFETY: `memmap2::MmapOptions::map_copy_read_only` is
        // unsafe because the kernel may invalidate the mapping at any
        // time (for example, when the underlying file is truncated by
        // another process), and a subsequent access through the
        // returned `Mmap` will raise `SIGBUS`. The Rust port accepts
        // the same platform caveat the FASM baseline carries (see
        // module-level docs).
        //
        // Concretely, this call corresponds to
        // `mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0)` —
        // byte-identical with FASM `privmapped.inc` lines 130–137.
        // The fields we rely on for soundness:
        //
        //  * `file` is owned locally up to and including this
        //    `unsafe` block; memmap2 internally `dup(2)`s the
        //    descriptor it needs, so dropping `file` at end of
        //    function is sound and does not prematurely unmap.
        //  * The resulting `Mmap` is read-only (`MAP_PRIVATE +
        //    PROT_READ`), so no mutable-alias UB is possible
        //    through the public API ([`PrivMapped::as_bytes`]
        //    returns only `&[u8]`).
        //  * Cross-process modification (truncation, hole-punching)
        //    is an accepted platform caveat inherited from FASM;
        //    callers needing stronger guarantees must coordinate
        //    externally (for example via `flock(2)`).
        //
        // Integration test: `ffi_boundary::test_mmap_file_cache`
        // (AAP §0.7.4.4) exercises this code path under the full
        // crate build configuration.
        let mmap = unsafe {
            MmapOptions::new()
                .len(size)
                .map_copy_read_only(&file)
                .map_err(|e| UtilError::Mmap(e.to_string()))?
        };

        // Format mtime as an RFC 1123 HTTP `Date:` header value for
        // ready use by the webserver response builder. Matches the
        // FASM `ctime$to_jd` + `formatter$doit` sequence at lines
        // 120–125 (under `webservercfg` conditional compilation).
        //
        // `mtime` cannot exceed `i64::MAX` in practice — filesystems
        // store `st_mtime` as a 64-bit signed integer; the cast only
        // truncates values beyond year 292 277 026 596 which cannot
        // occur for any reasonable filesystem entry.
        let mtime_str = crate::util::date::rfc1123(crate::util::date::unix_secs_to_parts(mtime as i64));

        Ok(Self {
            mmap,
            filename: path,
            mtime,
            mtime_str,
            etag: String::new(),
            pin_count: AtomicUsize::new(0),
            size,
            zbuf: None,
        })
    }

    // -----------------------------------------------------------------
    // Accessors — byte-level view, filename, mtime, mtime string.
    // -----------------------------------------------------------------

    /// Return an immutable byte-slice view over the mapped region.
    ///
    /// The returned slice is exactly [`PrivMapped::size`] bytes long
    /// and is a zero-copy view over the kernel page cache (modulo
    /// copy-on-write fault semantics). For file-backed mappings the
    /// contents are the raw on-disk bytes at the time of last page
    /// fault — concurrent modification by other processes may
    /// invalidate portions of the mapping.
    pub fn as_bytes(&self) -> &[u8] {
        &self.mmap[..]
    }

    /// Return the size of the mapping in bytes. Matches FASM
    /// `privmapped_size_ofs` (+8), which is populated from
    /// `struct stat::st_size` at `privmapped.inc` line 114.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Return the source filename as a [`Path`]. Matches FASM
    /// `privmapped_filename_ofs` (+32) / `privmapped_fname_ofs` (+40)
    /// (those two slots differ only in whether the string is
    /// null-terminated for C interop; the Rust port uses [`PathBuf`]
    /// storage, from which either representation is recoverable).
    pub fn filename(&self) -> &Path {
        &self.filename
    }

    /// Return the modification time as seconds since the Unix epoch.
    /// Matches FASM `privmapped_mtime_ofs` (+24).
    pub fn mtime(&self) -> u64 {
        self.mtime
    }

    /// Return the modification time formatted as an RFC 1123 HTTP
    /// `Date:` header value. Matches FASM `privmapped_mtimestr_ofs`
    /// (+72) under `webservercfg` conditional compilation; always
    /// available in the Rust port.
    ///
    /// Output shape: `"Sun, 06 Nov 1994 08:49:37 GMT"`.
    pub fn mtime_str(&self) -> &str {
        &self.mtime_str
    }

    // -----------------------------------------------------------------
    // ETag computation — opt-in, cached.
    // -----------------------------------------------------------------

    /// Compute and cache a **weak** ETag for this file.
    ///
    /// The ETag derives from the filename plus the mtime, matching
    /// FASM `privmapped$new`'s ETag branch at lines 141–201. The
    /// FASM original uses SHA-224 truncated to 27 bytes then
    /// base64-encoded; the Rust port uses SHA-256 truncated to 26
    /// bytes (the first 26 bytes of a 32-byte digest) then
    /// base64-encoded. This is a deliberate AAP §0.7.2-endorsed
    /// divergence: the ETag is a *weak* validator (the `W/` prefix
    /// announces this in the HTTP header), so byte-identical parity
    /// with the FASM baseline is not part of the externally
    /// observable contract. The semantic guarantee — *"if the file's
    /// name or mtime change, the ETag changes"* — is preserved.
    ///
    /// The ETag is cached after the first computation; subsequent
    /// calls return the previously computed value without re-hashing.
    ///
    /// Format: `W/"<base64-of-26-byte-sha256>"` when the `crypto`
    /// Cargo feature is enabled (the default);
    /// `W/"<hex-crc32>"` when `crypto` is disabled. Either form is
    /// valid [RFC 7232 §2.3] weak-validator syntax.
    ///
    /// # Errors
    ///
    /// This function is infallible in practice but returns
    /// [`Result`] for API stability: future implementations may
    /// surface cryptographic-primitive errors here without a
    /// breaking change.
    pub fn compute_etag(&mut self) -> Result<&str, UtilError> {
        if self.etag.is_empty() {
            // Concatenate filename and mtime — the FASM original
            // feeds these as two separate `sha224$update` calls
            // (lines 147–162). Rust uses a single formatted buffer
            // here because the resulting hash is a weak validator
            // only; the format makes the input unambiguous (the
            // colon separator prevents `foo` + `1bar` colliding with
            // `foo1` + `bar`).
            let input = format!("{}:{}", self.filename.display(), self.mtime);

            #[cfg(feature = "crypto")]
            {
                // Use the project's SHA-256 wrapper over `ring`.
                // Truncate to 26 bytes before base64-encoding,
                // matching the spec in AAP §0.5.1.4 and the FASM
                // pattern of `[0..27]` with SHA-224 (we lose 1 byte
                // vs. FASM because the Rust port substitutes
                // SHA-256 for SHA-224 — the weak-validator
                // semantics are preserved).
                let digest = crate::crypto::sha2::sha256(input.as_bytes());
                let encoded = crate::util::base64::encode(&digest[..26]);
                self.etag = format!("W/\"{encoded}\"");
            }
            #[cfg(not(feature = "crypto"))]
            {
                // Fallback when the `crypto` feature is disabled —
                // use CRC-32 as a cheap non-cryptographic hash. Weak
                // validators need only change when the input
                // changes; CRC-32 over filename+mtime satisfies
                // that.
                use crc32fast::Hasher;
                let mut h = Hasher::new();
                h.update(input.as_bytes());
                self.etag = format!("W/\"{:x}\"", h.finalize());
            }
        }
        Ok(&self.etag)
    }

    /// Return the cached ETag without computing it.
    ///
    /// Returns the empty string when [`PrivMapped::compute_etag`]
    /// has not yet been called. Matches FASM `privmapped_etag_ofs`
    /// (+48) retrieval.
    pub fn etag(&self) -> &str {
        &self.etag
    }

    // -----------------------------------------------------------------
    // Pin counting — lock-free reference tracking.
    // -----------------------------------------------------------------

    /// Increment the pin count and return the new value.
    ///
    /// Used by the `webserver` file cache to prevent eviction of a
    /// `PrivMapped` entry while one or more request handlers still
    /// hold references to it. Matches FASM `privmapped_pincount_ofs`
    /// (+56), which is `u64`-sized and manipulated by the downstream
    /// `webserver.inc` consumer.
    ///
    /// The operation is lock-free via [`AtomicUsize::fetch_add`] with
    /// [`Ordering::AcqRel`] — strong enough to synchronise cache
    /// entry visibility across worker threads without requiring an
    /// outer mutex.
    ///
    /// # Caller contract
    ///
    /// Callers MUST call [`PrivMapped::unpin`] exactly once per
    /// successful [`PrivMapped::pin`]. Unbalanced pins will prevent
    /// cache eviction (memory leak); unbalanced unpins will
    /// wrapping-underflow the counter (to `usize::MAX`).
    pub fn pin(&self) -> usize {
        // `fetch_add` returns the previous value; the new value is
        // that plus one.
        self.pin_count.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Decrement the pin count and return the new value (saturating
    /// at zero for the return value only).
    ///
    /// See [`PrivMapped::pin`] for the caller contract. The return
    /// value is [`usize::saturating_sub`]-floored at zero for display
    /// purposes; note that a genuine underflow of the *stored*
    /// counter is still possible if pins and unpins are unbalanced
    /// by the caller — this matches the FASM pattern where the
    /// pincount slot is a raw `u64` with no underflow protection.
    pub fn unpin(&self) -> usize {
        // `fetch_sub` returns the previous value; the new value is
        // `previous - 1` if `previous >= 1`, else it wraps. We
        // report the saturating-subtracted result to callers but do
        // not unwind the wrap in the store — matches FASM raw-slot
        // semantics.
        self.pin_count.fetch_sub(1, Ordering::AcqRel).saturating_sub(1)
    }

    /// Return the current pin count with an acquire-ordered load.
    /// Matches FASM `privmapped_pincount_ofs` (+56) read.
    pub fn pin_count(&self) -> usize {
        self.pin_count.load(Ordering::Acquire)
    }

    // -----------------------------------------------------------------
    // Pre-gzipped companion buffer (webserver Content-Encoding: gzip).
    // -----------------------------------------------------------------

    /// Attach a pre-gzipped companion buffer to this mapping.
    ///
    /// The `webserver` file-cache path populates this when serving
    /// compressible content over a TLS connection (see AAP §0.7.2's
    /// BREACH-mitigation discussion), so that the same response body
    /// can be served repeatedly without re-compressing. Matches FASM
    /// `privmapped$deflate` at lines 299–331, which populates
    /// `privmapped_zbuf_ofs` (+64) with a `buffer$new` object.
    ///
    /// # Semantics
    ///
    /// * Replaces any previously attached buffer; the old buffer is
    ///   dropped.
    /// * Takes ownership of `buf`; no in-place compression is
    ///   performed here. Compression itself lives in
    ///   [`crate::util::zlib`].
    pub fn set_zbuf(&mut self, buf: Vec<u8>) {
        self.zbuf = Some(buf);
    }

    /// Return the attached pre-gzipped companion buffer, if any.
    ///
    /// Returns `None` when [`PrivMapped::set_zbuf`] has not been
    /// called. The returned slice borrows from `self`; the buffer is
    /// released when the `PrivMapped` is dropped or when a fresh
    /// buffer is attached via [`PrivMapped::set_zbuf`].
    pub fn zbuf(&self) -> Option<&[u8]> {
        self.zbuf.as_deref()
    }
}

// Manual `Debug` impl that deliberately **omits** the mapped bytes.
// Printing the entire mapping of a multi-megabyte web asset would be
// catastrophic in a test-failure context, and memmap2's `Mmap` does
// not implement `Debug` in a way that would help anyway. We project
// only the externally meaningful metadata.
impl std::fmt::Debug for PrivMapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivMapped")
            .field("filename", &self.filename)
            .field("size", &self.size)
            .field("mtime", &self.mtime)
            .field("mtime_str", &self.mtime_str)
            .field("etag", &self.etag)
            .field("pin_count", &self.pin_count())
            .field("has_zbuf", &self.zbuf.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Unit tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! Ad-hoc tests for [`PrivMapped`].
    //!
    //! Tests exercise the happy-path constructor, size and mtime
    //! extraction, pin/unpin atomic counter correctness, ETag
    //! computation idempotence, zbuf attach/detach, and the
    //! non-panic `Debug` projection. The FFI boundary (the `unsafe`
    //! `mmap(PROT_READ, MAP_PRIVATE)` call) is additionally covered
    //! by `tests/ffi_boundary.rs::test_mmap_file_cache` (AAP
    //! §0.7.4.4).

    use super::*;

    /// Unique temp-file path per test, based on the current process
    /// ID and a tag. Prevents collisions when tests within the same
    /// process run in parallel.
    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("heavything_privmapped_{}_{}", name, std::process::id()));
        p
    }

    #[test]
    fn open_reads_content() {
        let p = tmp("content");
        std::fs::write(&p, b"hello world").expect("write");
        let m = PrivMapped::open(&p).expect("open");
        assert_eq!(m.as_bytes(), b"hello world");
        assert_eq!(m.size(), 11);
        assert!(m.mtime() > 0);
        assert!(!m.mtime_str().is_empty());
        // RFC 1123 output ends with `" GMT"`.
        assert!(m.mtime_str().ends_with(" GMT"), "mtime_str={}", m.mtime_str());
        std::fs::remove_file(&p).expect("remove");
    }

    #[test]
    fn filename_is_preserved() {
        let p = tmp("filename");
        std::fs::write(&p, b"x").expect("write");
        let m = PrivMapped::open(&p).expect("open");
        assert_eq!(m.filename(), p.as_path());
        std::fs::remove_file(&p).expect("remove");
    }

    #[test]
    fn pin_counting() {
        let p = tmp("pins");
        std::fs::write(&p, b"x").expect("write");
        let m = PrivMapped::open(&p).expect("open");
        assert_eq!(m.pin_count(), 0);
        assert_eq!(m.pin(), 1);
        assert_eq!(m.pin(), 2);
        assert_eq!(m.pin_count(), 2);
        assert_eq!(m.unpin(), 1);
        assert_eq!(m.pin_count(), 1);
        assert_eq!(m.unpin(), 0);
        assert_eq!(m.pin_count(), 0);
        std::fs::remove_file(&p).expect("remove");
    }

    #[test]
    fn etag_is_deferred_and_cached() {
        let p = tmp("etag");
        std::fs::write(&p, b"x").expect("write");
        let mut m = PrivMapped::open(&p).expect("open");

        // Before computation: empty.
        assert!(m.etag().is_empty());

        // First compute populates; second call returns same value.
        let first = m.compute_etag().expect("etag compute").to_owned();
        assert!(!first.is_empty());
        assert!(first.starts_with("W/\""));
        assert!(first.ends_with('"'));

        let second = m.compute_etag().expect("etag cache").to_owned();
        assert_eq!(first, second);

        // Cached accessor returns the same value.
        assert_eq!(m.etag(), first);

        std::fs::remove_file(&p).expect("remove");
    }

    #[test]
    fn zbuf_attach() {
        let p = tmp("zbuf");
        std::fs::write(&p, b"content").expect("write");
        let mut m = PrivMapped::open(&p).expect("open");
        assert!(m.zbuf().is_none());
        m.set_zbuf(vec![0x1f, 0x8b, 0x08, 0x00]); // gzip magic
        let attached = m.zbuf().expect("zbuf attached");
        assert_eq!(&attached[..2], &[0x1f, 0x8b]);
        assert_eq!(attached.len(), 4);
        std::fs::remove_file(&p).expect("remove");
    }

    #[test]
    fn zbuf_replaces_on_reattach() {
        let p = tmp("zbuf_reattach");
        std::fs::write(&p, b"x").expect("write");
        let mut m = PrivMapped::open(&p).expect("open");
        m.set_zbuf(vec![1, 2, 3]);
        assert_eq!(m.zbuf().expect("first").len(), 3);
        m.set_zbuf(vec![9, 9]);
        assert_eq!(m.zbuf().expect("second").len(), 2);
        std::fs::remove_file(&p).expect("remove");
    }

    #[test]
    fn open_nonexistent_returns_io_error() {
        let p = tmp("does_not_exist_nonce");
        // Ensure the path does not exist.
        let _ = std::fs::remove_file(&p);
        let err = PrivMapped::open(&p).expect_err("expected open error");
        assert!(matches!(err, UtilError::Io(_)), "got {err:?}");
    }

    #[test]
    fn debug_does_not_include_bytes() {
        let p = tmp("debug");
        // Use content long enough to be recognisable in Debug output
        // if the Debug impl were leaking bytes.
        std::fs::write(&p, b"DEBUGCONTENT_should_not_appear_in_debug").expect("write");
        let m = PrivMapped::open(&p).expect("open");
        let s = format!("{m:?}");
        assert!(s.contains("PrivMapped"));
        assert!(s.contains("size"));
        assert!(s.contains("pin_count"));
        assert!(s.contains("has_zbuf"));
        // The byte content of the mapping MUST NOT leak into Debug.
        assert!(
            !s.contains("DEBUGCONTENT_should_not_appear_in_debug"),
            "Debug leaked mapped bytes: {s}"
        );
        std::fs::remove_file(&p).expect("remove");
    }

    #[test]
    fn size_matches_file_length() {
        let p = tmp("size");
        let payload: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        std::fs::write(&p, &payload).expect("write");
        let m = PrivMapped::open(&p).expect("open");
        assert_eq!(m.size(), 1024);
        assert_eq!(m.as_bytes().len(), 1024);
        assert_eq!(m.as_bytes(), payload.as_slice());
        std::fs::remove_file(&p).expect("remove");
    }
}
