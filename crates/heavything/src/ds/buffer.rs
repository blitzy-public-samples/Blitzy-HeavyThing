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

//! Growable byte buffer — port of `buffer.inc` (1,247 lines of FASM
//! assembly).
//!
//! This module defines [`Buffer`], a thin wrapper around
//! [`std::vec::Vec<u8>`] that preserves the public API of the FASM
//! `buffer$*` function set. The original FASM 56-byte buffer object
//! (`endptr`, `length`, `itself`, `size`) is collapsed into a single
//! `Vec<u8>` because `Vec` already tracks length, capacity, and the
//! backing pointer. Growth is amortised-doubling via [`Vec::reserve`],
//! matching the FASM `buffer$reserve` `shl r8, 1` loop
//! (`buffer.inc` lines 129–186).
//!
//! Per AAP §0.8.9 (*"MUST use std collections where semantically
//! equivalent"*) and the `ds`-folder std-only rule, this file pulls in
//! no third-party crates and contains **zero `unsafe` blocks**. The
//! folder's target is `0–1` unsafe sites; this file meets the `0`
//! preference.
//!
//! # Capacity semantics
//!
//! - [`Buffer::new`] allocates a [`DEFAULT_CAPACITY`]-byte backing,
//!   matching the FASM `buffer_default_size = 256` constant from
//!   `buffer.inc` line 34.
//! - [`Buffer::with_capacity`] takes an explicit initial capacity.
//! - [`Buffer::clear`] drops the length to `0` but keeps the backing
//!   (FASM `buffer$reset`).
//! - [`Buffer::clear_and_reserve_default`] drops the length and
//!   ensures the backing is at least [`DEFAULT_CAPACITY`] bytes
//!   (FASM `buffer$reset_reserve`).
//!
//! # Bounds-check error policy
//!
//! The four bounds-checked methods — [`Buffer::truncate`],
//! [`Buffer::consume`], [`Buffer::insert_slice`], and
//! [`Buffer::remove_range`] — return
//! [`DsError::BufferOverflow { requested, capacity }`](
//! crate::error::DsError::BufferOverflow) when the request exceeds the
//! buffer's current length. This is an intentional divergence from
//! the FASM behaviour (which silently reset the buffer to empty on
//! out-of-range input): the typed error gives callers actionable
//! diagnostics while preserving the no-panic discipline from
//! AAP §0.8.3.
//!
//! # Line-oriented helpers
//!
//! The FASM `buffer$has_more_lines` / `buffer$check_last_lf` /
//! `buffer$nextline` trio ports to [`Buffer::has_more_lines`],
//! [`Buffer::ends_with_lf`], and [`Buffer::next_line`]. Lines are
//! treated as opaque byte sequences delimited by `\n` (LF only); the
//! returned slice includes the trailing `\n`, and any `\r` in a CRLF
//! terminator is retained (callers may strip it explicitly).
//!
//! # File I/O helpers
//!
//! The FASM `buffer$file_write` / `buffer$file_append` helpers port to
//! [`Buffer::write_to_file`] / [`Buffer::append_to_file`], joined by a
//! new [`Buffer::read_from_file`] that appends the contents of a file
//! to the buffer. These return [`std::io::Result`] rather than
//! [`DsError`](crate::error::DsError) because the underlying failures
//! are OS-level (see AAP §0.8.3 / §0.8.4).
//!
//! # Functions deliberately not ported
//!
//! The following FASM helpers are intentionally omitted here per the
//! `ds`-folder scope rule; ports live in `crate::util`:
//!
//! - `buffer$append_string` — in `util::string`; Rust callers use
//!   `push_slice(s.as_bytes())`.
//! - `buffer$append_hexdecode` / `buffer$append_hexencode` — belong in
//!   `util::string` (or the `hex` dev-dep in test code).
//! - `buffer$append_base64decode` / `buffer$append_bintobase64_latin1`
//!   — belong in `util::base64`.
//! - `buffer$append_nocopy` — FASM-specific raw-pointer optimisation;
//!   Rust callers use `push_slice` or `reserve` + `extend_from_slice`.
//! - `buffer$cdebug` — callers use `println!("{:?}", buf.as_slice())`
//!   or structured logging in the showcase apps.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use crate::error::DsError;

// ============================================================================
// Public constants
// ============================================================================

/// Default initial capacity (in bytes) for a newly-constructed
/// [`Buffer`] via [`Buffer::new`] or [`Buffer::clear_and_reserve_default`].
///
/// Matches the FASM `buffer_default_size = 256` constant declared at
/// `buffer.inc` line 34. The value is tuned so that short line-oriented
/// payloads (log lines, HTTP header rows, SSH protocol messages) fit
/// without a reallocation while keeping the per-buffer footprint small.
pub const DEFAULT_CAPACITY: usize = 256;

// ============================================================================
// Buffer — primary type
// ============================================================================

/// A growable byte buffer wrapping [`Vec<u8>`] with a
/// capacity-preserving API.
///
/// `Buffer` is the Rust translation of the FASM `buffer` object from
/// `buffer.inc`. The original 56-byte FASM object stored `(endptr,
/// length, itself, size)`; `Vec<u8>` already stores equivalent state
/// (`len`, `capacity`, and a heap-backed data pointer) so no extra
/// bookkeeping is required.
///
/// # Growth strategy
///
/// Writes that exceed current capacity grow the backing via
/// [`Vec::reserve`], whose amortised-doubling strategy matches the
/// FASM `buffer$reserve` loop (lines 129–186 of `buffer.inc`).
///
/// # Alignment
///
/// `Buffer` is byte-aligned (the alignment of `u8` is `1`). Callers
/// that require aligned storage for SIMD / AES-NI intrinsics should
/// use aligned-allocation crates or the relevant RustCrypto API types
/// directly rather than `Buffer`. This matches AAP §0.5.1.6: `Buffer`
/// is the `ds`-level byte container; alignment-sensitive crypto
/// operations belong to `crate::crypto`.
///
/// # Thread safety
///
/// `Buffer` is `Send + Sync` by virtue of `Vec<u8>`'s auto traits.
#[derive(Debug, Clone, Default)]
pub struct Buffer {
    /// The backing byte storage. All public methods forward to, or
    /// query, this field; `Buffer` never exposes an owned `Vec<u8>`
    /// API surface beyond the narrow set enumerated in this module.
    inner: Vec<u8>,
}

// ----------------------------------------------------------------------------
// Construction
// ----------------------------------------------------------------------------

impl Buffer {
    /// Creates a new [`Buffer`] with [`DEFAULT_CAPACITY`] (256 bytes)
    /// pre-allocated. The returned buffer has length `0`.
    ///
    /// Equivalent to the no-argument form of FASM `buffer$new`
    /// (`buffer.inc` line 40).
    ///
    /// # Examples
    ///
    /// ```
    /// use heavything::ds::Buffer;
    /// let buf = Buffer::new();
    /// assert!(buf.is_empty());
    /// assert!(buf.capacity() >= 256);
    /// ```
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Vec::with_capacity(DEFAULT_CAPACITY),
        }
    }

    /// Creates a new [`Buffer`] with the exact requested initial
    /// capacity. The returned buffer has length `0`.
    ///
    /// Equivalent to FASM `buffer$new` invoked with the `rsi` register
    /// set to `capacity` (`buffer.inc` lines 40–60).
    ///
    /// # Examples
    ///
    /// ```
    /// use heavything::ds::Buffer;
    /// let buf = Buffer::with_capacity(1024);
    /// assert!(buf.is_empty());
    /// assert!(buf.capacity() >= 1024);
    /// ```
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }
}

// ----------------------------------------------------------------------------
// Basic accessors
// ----------------------------------------------------------------------------

impl Buffer {
    /// Returns the number of bytes currently stored in the buffer.
    ///
    /// Equivalent to reading the FASM `buffer_length_ofs` field.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` when the buffer holds zero bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the total capacity of the backing allocation in bytes.
    ///
    /// Equivalent to reading the FASM `buffer_size_ofs` field.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Returns an immutable byte slice over the buffer's contents.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Returns a mutable byte slice over the buffer's contents.
    ///
    /// The length of the returned slice equals [`Buffer::len`];
    /// callers cannot use this slice to grow the buffer (use
    /// [`Buffer::push`] / [`Buffer::push_slice`] instead).
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

// ----------------------------------------------------------------------------
// Reserve / clear
// ----------------------------------------------------------------------------

impl Buffer {
    /// Reserves space for at least `additional` more bytes. Internally
    /// delegates to [`Vec::reserve`], whose amortised-doubling growth
    /// strategy matches the FASM `buffer$reserve` `shl r8, 1` loop at
    /// `buffer.inc` lines 129–186.
    ///
    /// The buffer may reserve more than `additional` bytes to
    /// amortise allocation cost. Use [`Buffer::reserve_exact`] if a
    /// tighter footprint is required.
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);
    }

    /// Reserves space for exactly `additional` more bytes with no
    /// over-allocation. Useful when the final size is known precisely
    /// and memory footprint matters more than amortisation.
    #[inline]
    pub fn reserve_exact(&mut self, additional: usize) {
        self.inner.reserve_exact(additional);
    }

    /// Sets the buffer length to `0` without freeing the backing
    /// allocation — subsequent writes up to the current
    /// [`Buffer::capacity`] will not trigger a reallocation.
    ///
    /// Equivalent to FASM `buffer$reset` (`buffer.inc` line 189).
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Sets the buffer length to `0` and ensures the backing capacity
    /// is at least [`DEFAULT_CAPACITY`].
    ///
    /// After [`clear`][Self::clear] the length is `0`, so delegating to
    /// [`Vec::reserve`] with `DEFAULT_CAPACITY` as the `additional`
    /// argument guarantees `capacity() >= 0 + DEFAULT_CAPACITY`. When
    /// the backing already satisfies that bound, `Vec::reserve` is a
    /// no-op (per its documented "does nothing if capacity is already
    /// sufficient" contract), which preserves larger pre-allocated
    /// buffers — matching FASM `buffer$reset_reserve` which also never
    /// shrinks.
    ///
    /// Equivalent to FASM `buffer$reset_reserve` (`buffer.inc`
    /// line 115).
    pub fn clear_and_reserve_default(&mut self) {
        self.inner.clear();
        self.inner.reserve(DEFAULT_CAPACITY);
    }
}

// ----------------------------------------------------------------------------
// Truncate / consume (bounds-checked)
// ----------------------------------------------------------------------------

impl Buffer {
    /// Removes `n` bytes from the **end** of the buffer.
    ///
    /// Returns
    /// [`DsError::BufferOverflow { requested: n, capacity: len }`](
    /// DsError::BufferOverflow) when `n > self.len()`. The original
    /// FASM `buffer$truncate` (`buffer.inc` line 201) silently reset
    /// the buffer to empty on out-of-range input; this Rust port
    /// surfaces the overflow as a typed error so callers can react
    /// instead of losing data (AAP §0.8.3 no-panic / no-silent-loss).
    pub fn truncate(&mut self, n: usize) -> Result<(), DsError> {
        let len = self.inner.len();
        if n > len {
            return Err(DsError::BufferOverflow {
                requested: n,
                capacity: len,
            });
        }
        self.inner.truncate(len - n);
        Ok(())
    }

    /// Removes `n` bytes from the **head** of the buffer (the
    /// remaining bytes shift left to fill the gap).
    ///
    /// Returns
    /// [`DsError::BufferOverflow { requested: n, capacity: len }`](
    /// DsError::BufferOverflow) when `n > self.len()`. Equivalent to
    /// FASM `buffer$consume` (`buffer.inc` line 224), which used a
    /// `memmove` to slide the tail forward.
    pub fn consume(&mut self, n: usize) -> Result<(), DsError> {
        let len = self.inner.len();
        if n > len {
            return Err(DsError::BufferOverflow {
                requested: n,
                capacity: len,
            });
        }
        // `Vec::drain` handles the memmove + length adjustment.
        self.inner.drain(..n);
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Append / push (unbounded growth via Vec::reserve)
// ----------------------------------------------------------------------------

impl Buffer {
    /// Appends a single byte to the buffer.
    ///
    /// Equivalent to FASM `buffer$append_byte` (`buffer.inc` line 396).
    #[inline]
    pub fn push(&mut self, byte: u8) {
        self.inner.push(byte);
    }

    /// Appends a byte slice to the buffer, growing it by
    /// `slice.len()` bytes.
    ///
    /// Equivalent to FASM `buffer$append` (`buffer.inc` line 263),
    /// which performed `reserve` + `memcpy` in sequence.
    #[inline]
    pub fn push_slice(&mut self, slice: &[u8]) {
        self.inner.extend_from_slice(slice);
    }

    /// Appends a `u16` in little-endian byte order (2 bytes).
    ///
    /// Equivalent to FASM `buffer$append_word` (`buffer.inc`
    /// line 426). The FASM host was x86_64 (little-endian native), so
    /// a direct register-to-memory store produced LE bytes; this
    /// method preserves that behaviour.
    #[inline]
    pub fn push_u16_le(&mut self, value: u16) {
        self.inner.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a `u32` in little-endian byte order (4 bytes).
    ///
    /// Equivalent to FASM `buffer$append_dword` (`buffer.inc`
    /// line 442).
    #[inline]
    pub fn push_u32_le(&mut self, value: u32) {
        self.inner.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a `u64` in little-endian byte order (8 bytes).
    ///
    /// Equivalent to FASM `buffer$append_qword` (`buffer.inc`
    /// line 459).
    #[inline]
    pub fn push_u64_le(&mut self, value: u64) {
        self.inner.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends an `f64` in little-endian byte order (8 bytes of the
    /// IEEE 754 bit pattern).
    ///
    /// Equivalent to FASM `buffer$append_double` (`buffer.inc`
    /// line 476).
    #[inline]
    pub fn push_f64_le(&mut self, value: f64) {
        self.inner.extend_from_slice(&value.to_le_bytes());
    }
}

// ----------------------------------------------------------------------------
// Insert / remove range (bounds-checked)
// ----------------------------------------------------------------------------

impl Buffer {
    /// Inserts `slice` at byte offset `offset`, shifting existing
    /// bytes from `offset..` right by `slice.len()` positions.
    ///
    /// Returns
    /// [`DsError::BufferOverflow { requested: offset, capacity: len }`](
    /// DsError::BufferOverflow) when `offset > self.len()`.
    ///
    /// Equivalent to FASM `buffer$insert` (`buffer.inc` line 287).
    pub fn insert_slice(&mut self, offset: usize, slice: &[u8]) -> Result<(), DsError> {
        let len = self.inner.len();
        if offset > len {
            return Err(DsError::BufferOverflow {
                requested: offset,
                capacity: len,
            });
        }
        // `Vec::splice` with an empty removal range performs the
        // insert + memmove in a single pass.
        self.inner.splice(offset..offset, slice.iter().copied());
        Ok(())
    }

    /// Removes `count` bytes starting at `offset`, shifting the tail
    /// left by `count` positions.
    ///
    /// Returns
    /// [`DsError::BufferOverflow { requested, capacity: len }`](
    /// DsError::BufferOverflow) when `offset + count > self.len()` or
    /// when `offset + count` would overflow `usize`. The `requested`
    /// field carries the arithmetic-clamped end offset in the normal
    /// overflow case, or `usize::MAX` when the addition itself
    /// overflowed.
    ///
    /// Equivalent to FASM `buffer$remove` (`buffer.inc` line 341).
    pub fn remove_range(&mut self, offset: usize, count: usize) -> Result<(), DsError> {
        let len = self.inner.len();
        let end = offset.checked_add(count).ok_or(DsError::BufferOverflow {
            requested: usize::MAX,
            capacity: len,
        })?;
        if end > len {
            return Err(DsError::BufferOverflow {
                requested: end,
                capacity: len,
            });
        }
        self.inner.drain(offset..end);
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Line-oriented helpers
// ----------------------------------------------------------------------------

impl Buffer {
    /// Returns `true` when the buffer contains at least one `\n`
    /// (linefeed) byte.
    ///
    /// Equivalent to FASM `buffer$has_more_lines` (`buffer.inc`
    /// line 872). The FASM implementation also recognised bare `\r`
    /// as a delimiter; the Rust port uses LF only, matching the
    /// universally-deployed POSIX convention and the HTTP / SSH /
    /// SMTP line terminators the consumers actually emit.
    pub fn has_more_lines(&self) -> bool {
        self.inner.contains(&b'\n')
    }

    /// Returns `true` when the buffer's last byte is `\n`.
    ///
    /// Equivalent to a read-only variant of FASM `buffer$check_last_lf`
    /// (`buffer.inc` line 954). The FASM helper *auto-appended* a
    /// missing `\n`; the Rust port is a predicate only, so callers
    /// that need to normalise can follow the check with
    /// `buf.push(b'\n')`. This decoupling avoids hidden writes.
    pub fn ends_with_lf(&self) -> bool {
        matches!(self.inner.last(), Some(&b'\n'))
    }

    /// Consumes and returns the next line from the **head** of the
    /// buffer (every byte up to and including the first `\n`).
    ///
    /// Returns [`None`] when the buffer contains no `\n`; the buffer
    /// is left unchanged in that case.
    ///
    /// The returned [`Vec<u8>`] includes the trailing `\n`. If the
    /// terminator is `\r\n`, the `\r` is retained in the returned
    /// bytes as the second-to-last element — callers that want a
    /// stripped line must drop the trailing `\r\n` or `\n` explicitly.
    ///
    /// Equivalent to FASM `buffer$nextline` (`buffer.inc` line 977)
    /// which removed the consumed line from the head.
    pub fn next_line(&mut self) -> Option<Vec<u8>> {
        let pos = self.inner.iter().position(|&b| b == b'\n')?;
        let line: Vec<u8> = self.inner.drain(..=pos).collect();
        Some(line)
    }
}

// ----------------------------------------------------------------------------
// File I/O helpers (std::io::Result — OS-level errors belong to std::io)
// ----------------------------------------------------------------------------

impl Buffer {
    /// Writes the buffer's contents to `path`, creating or truncating
    /// the file. Calls [`File::sync_all`] before returning so the
    /// bytes are flushed to the underlying storage.
    ///
    /// Equivalent to FASM `buffer$file_write` / `buffer$file_write_cstr`
    /// (`buffer.inc` lines 1106 and 1139), which opened the file with
    /// `O_RDWR | O_CREAT | O_TRUNC` (`0x242`).
    ///
    /// # Errors
    ///
    /// Propagates any [`std::io::Error`] raised by
    /// [`File::create`], [`Write::write_all`], or
    /// [`File::sync_all`]. File-system errors are OS-level and
    /// therefore returned as [`io::Result`] rather than
    /// [`DsError`](crate::error::DsError) per AAP §0.8.4.
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(&self.inner)?;
        file.sync_all()
    }

    /// Appends the buffer's contents to `path`, creating the file if
    /// it does not exist.
    ///
    /// Equivalent to FASM `buffer$file_append` / `buffer$file_append_cstr`
    /// (`buffer.inc` lines 1181 and 1213), which opened the file with
    /// `O_RDWR | O_CREAT | O_APPEND` (`0x442`).
    ///
    /// # Errors
    ///
    /// Propagates any [`std::io::Error`] raised by
    /// [`OpenOptions::open`] or [`Write::write_all`].
    pub fn append_to_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(&self.inner)
    }

    /// Reads all bytes from `path` and appends them to the buffer.
    ///
    /// This helper has no FASM analogue — `buffer.inc` defined only
    /// the two write helpers — but is required to round-trip the
    /// output of [`Buffer::write_to_file`] back into a [`Buffer`] for
    /// integration tests and for consumers that want to reload
    /// serialised buffer state (for example, the `tls` session-cache
    /// layer).
    ///
    /// The method **appends** to the buffer (preserving any existing
    /// bytes at the head); callers that want a fresh read should
    /// [`clear`](Self::clear) the buffer first.
    ///
    /// # Errors
    ///
    /// Propagates any [`std::io::Error`] raised by [`File::open`] or
    /// [`Read::read_to_end`].
    pub fn read_from_file(&mut self, path: impl AsRef<Path>) -> io::Result<()> {
        let mut file = File::open(path)?;
        file.read_to_end(&mut self.inner)?;
        Ok(())
    }
}

// ============================================================================
// Trait implementations (excluding Deref / DerefMut per AAP §0.8.2)
// ============================================================================

impl AsRef<[u8]> for Buffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl AsMut<[u8]> for Buffer {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl From<Vec<u8>> for Buffer {
    #[inline]
    fn from(inner: Vec<u8>) -> Self {
        Self { inner }
    }
}

impl From<Buffer> for Vec<u8> {
    #[inline]
    fn from(buf: Buffer) -> Self {
        buf.inner
    }
}

impl<'a> From<&'a [u8]> for Buffer {
    #[inline]
    fn from(slice: &'a [u8]) -> Self {
        Self {
            inner: slice.to_vec(),
        }
    }
}

// ============================================================================
// Unit tests (AAP §0.8.4 requires ≥1 integration/unit test per subsystem
// surface; buffer.rs provides ≥20 targeted cases covering construction,
// accessors, growth, bounds checks, line helpers, file I/O, and trait impls)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // -- construction ---------------------------------------------------------

    #[test]
    fn test_new_has_default_capacity() {
        let buf = Buffer::new();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert!(buf.capacity() >= DEFAULT_CAPACITY);
    }

    #[test]
    fn test_with_capacity() {
        let buf = Buffer::with_capacity(1024);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert!(buf.capacity() >= 1024);
    }

    #[test]
    fn test_default_is_empty() {
        let buf = Buffer::default();
        assert!(buf.is_empty());
        // Default() uses Vec::default() which is zero-capacity; the
        // 256-byte pre-allocation is exclusive to Buffer::new().
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_default_capacity_constant() {
        assert_eq!(DEFAULT_CAPACITY, 256);
    }

    // -- basic append ---------------------------------------------------------

    #[test]
    fn test_push_and_push_slice() {
        let mut buf = Buffer::new();
        buf.push(0xAB);
        buf.push_slice(&[1, 2, 3]);
        assert_eq!(buf.as_slice(), &[0xAB, 1, 2, 3]);
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn test_push_u16_le() {
        let mut buf = Buffer::new();
        buf.push_u16_le(0x1234);
        assert_eq!(buf.as_slice(), &[0x34, 0x12]);
    }

    #[test]
    fn test_push_u32_le() {
        let mut buf = Buffer::new();
        buf.push_u32_le(0xDEAD_BEEF);
        assert_eq!(buf.as_slice(), &[0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn test_push_u64_le() {
        let mut buf = Buffer::new();
        buf.push_u64_le(0x0123_4567_89AB_CDEF);
        assert_eq!(buf.as_slice(), &[0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]);
    }

    #[test]
    fn test_push_f64_le() {
        let mut buf = Buffer::new();
        let value = 1.0_f64;
        buf.push_f64_le(value);
        // IEEE 754 1.0 -> 0x3FF0_0000_0000_0000, LE = 00 00 00 00 00 00 F0 3F.
        assert_eq!(buf.as_slice(), &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F]);
    }

    // -- reserve / clear ------------------------------------------------------

    #[test]
    fn test_reserve_grows() {
        let mut buf = Buffer::new();
        let before = buf.capacity();
        buf.reserve(4096);
        assert!(buf.capacity() >= before + 4096 - DEFAULT_CAPACITY);
        assert!(buf.capacity() >= 4096);
    }

    #[test]
    fn test_reserve_exact_grows_tightly() {
        let mut buf = Buffer::with_capacity(16);
        buf.reserve_exact(48);
        // reserve_exact does not over-allocate, though the allocator
        // is free to round up; we can only assert the lower bound.
        assert!(buf.capacity() >= 48);
    }

    #[test]
    fn test_clear_preserves_capacity() {
        let mut buf = Buffer::new();
        buf.push_slice(&[0; 200]);
        let cap_before = buf.capacity();
        buf.clear();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.capacity(), cap_before);
    }

    #[test]
    fn test_clear_and_reserve_default() {
        // Start with a buffer smaller than DEFAULT_CAPACITY and grow
        // it back up.
        let mut buf = Buffer::with_capacity(16);
        buf.push_slice(&[0xFF; 8]);
        buf.clear_and_reserve_default();
        assert_eq!(buf.len(), 0);
        assert!(buf.capacity() >= DEFAULT_CAPACITY);

        // Starting from a larger buffer, the capacity must not shrink.
        let mut buf = Buffer::with_capacity(4096);
        buf.clear_and_reserve_default();
        assert!(buf.capacity() >= 4096);
    }

    // -- truncate / consume ---------------------------------------------------

    #[test]
    fn test_truncate_ok() {
        let mut buf = Buffer::new();
        buf.push_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert!(buf.truncate(4).is_ok());
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_truncate_zero_is_noop() {
        let mut buf = Buffer::new();
        buf.push_slice(&[7, 7, 7]);
        assert!(buf.truncate(0).is_ok());
        assert_eq!(buf.as_slice(), &[7, 7, 7]);
    }

    #[test]
    fn test_truncate_overflow_returns_error() {
        let mut buf = Buffer::new();
        buf.push_slice(&[1, 2, 3, 4, 5]);
        match buf.truncate(10) {
            Err(DsError::BufferOverflow { requested, capacity }) => {
                assert_eq!(requested, 10);
                assert_eq!(capacity, 5);
            }
            other => panic!("expected BufferOverflow, got {:?}", other),
        }
        // Buffer must remain unchanged on error.
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_consume_ok() {
        let mut buf = Buffer::new();
        buf.push_slice(&[1, 2, 3, 4, 5]);
        assert!(buf.consume(2).is_ok());
        assert_eq!(buf.as_slice(), &[3, 4, 5]);
    }

    #[test]
    fn test_consume_overflow_returns_error() {
        let mut buf = Buffer::new();
        buf.push_slice(&[1, 2, 3, 4, 5]);
        match buf.consume(10) {
            Err(DsError::BufferOverflow { requested, capacity }) => {
                assert_eq!(requested, 10);
                assert_eq!(capacity, 5);
            }
            other => panic!("expected BufferOverflow, got {:?}", other),
        }
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5]);
    }

    // -- insert / remove range ------------------------------------------------

    #[test]
    fn test_insert_slice_ok() {
        let mut buf = Buffer::new();
        buf.push_slice(&[1, 2, 5]);
        assert!(buf.insert_slice(2, &[3, 4]).is_ok());
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_insert_slice_at_head_and_tail() {
        let mut buf = Buffer::new();
        buf.push_slice(&[2, 3]);
        assert!(buf.insert_slice(0, &[1]).is_ok());
        assert!(buf.insert_slice(buf.len(), &[4]).is_ok());
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_insert_slice_overflow_returns_error() {
        let mut buf = Buffer::new();
        buf.push_slice(&[1, 2, 3]);
        match buf.insert_slice(100, &[9]) {
            Err(DsError::BufferOverflow { requested, capacity }) => {
                assert_eq!(requested, 100);
                assert_eq!(capacity, 3);
            }
            other => panic!("expected BufferOverflow, got {:?}", other),
        }
        assert_eq!(buf.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_remove_range_ok() {
        let mut buf = Buffer::new();
        buf.push_slice(&[1, 2, 3, 4, 5]);
        assert!(buf.remove_range(1, 2).is_ok());
        assert_eq!(buf.as_slice(), &[1, 4, 5]);
    }

    #[test]
    fn test_remove_range_zero_is_noop() {
        let mut buf = Buffer::new();
        buf.push_slice(&[1, 2, 3]);
        assert!(buf.remove_range(1, 0).is_ok());
        assert_eq!(buf.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_remove_range_overflow_returns_error() {
        let mut buf = Buffer::new();
        buf.push_slice(&[1, 2, 3]);
        match buf.remove_range(0, 100) {
            Err(DsError::BufferOverflow { requested, capacity }) => {
                assert_eq!(requested, 100);
                assert_eq!(capacity, 3);
            }
            other => panic!("expected BufferOverflow, got {:?}", other),
        }
        assert_eq!(buf.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_remove_range_checked_add_overflow() {
        let mut buf = Buffer::new();
        buf.push_slice(&[1, 2, 3]);
        // offset + count overflows usize -> the `checked_add` branch
        // reports `usize::MAX` in the `requested` field.
        match buf.remove_range(usize::MAX, 2) {
            Err(DsError::BufferOverflow { requested, capacity }) => {
                assert_eq!(requested, usize::MAX);
                assert_eq!(capacity, 3);
            }
            other => panic!("expected BufferOverflow, got {:?}", other),
        }
        assert_eq!(buf.as_slice(), &[1, 2, 3]);
    }

    // -- line helpers ---------------------------------------------------------

    #[test]
    fn test_has_more_lines_true_and_false() {
        let mut buf = Buffer::new();
        assert!(!buf.has_more_lines());
        buf.push_slice(b"no newline here");
        assert!(!buf.has_more_lines());
        buf.push(b'\n');
        assert!(buf.has_more_lines());
    }

    #[test]
    fn test_ends_with_lf() {
        let mut buf = Buffer::new();
        assert!(!buf.ends_with_lf());
        buf.push_slice(b"abc");
        assert!(!buf.ends_with_lf());
        buf.push(b'\n');
        assert!(buf.ends_with_lf());
    }

    #[test]
    fn test_next_line_basic() {
        let mut buf = Buffer::new();
        buf.push_slice(b"line1\nline2\nline3");
        assert_eq!(buf.next_line().as_deref(), Some(b"line1\n".as_ref()));
        assert_eq!(buf.next_line().as_deref(), Some(b"line2\n".as_ref()));
        // Tail has no terminator -> None, buffer unchanged.
        assert_eq!(buf.next_line(), None);
        assert_eq!(buf.as_slice(), b"line3");
    }

    #[test]
    fn test_next_line_preserves_cr() {
        let mut buf = Buffer::new();
        buf.push_slice(b"crlf-line\r\nafter");
        assert_eq!(buf.next_line().as_deref(), Some(b"crlf-line\r\n".as_ref()));
        assert_eq!(buf.as_slice(), b"after");
    }

    #[test]
    fn test_next_line_without_newline_is_none() {
        let mut buf = Buffer::new();
        buf.push_slice(b"no newline");
        assert_eq!(buf.next_line(), None);
        assert_eq!(buf.as_slice(), b"no newline");
    }

    #[test]
    fn test_next_line_empty_buffer() {
        let mut buf = Buffer::new();
        assert_eq!(buf.next_line(), None);
    }

    // -- file I/O -------------------------------------------------------------

    #[test]
    fn test_write_and_read_roundtrip() {
        // Create a populated buffer, persist it, then reload into a
        // fresh buffer and verify byte-for-byte equality.
        let mut src = Buffer::new();
        src.push_slice(b"HeavyThing buffer round-trip payload\x00\x01\x02\xFF");

        let tmp = NamedTempFile::new().expect("create tempfile");
        src.write_to_file(tmp.path()).expect("write_to_file");

        let mut dst = Buffer::new();
        dst.read_from_file(tmp.path()).expect("read_from_file");

        assert_eq!(dst.as_slice(), src.as_slice());
    }

    #[test]
    fn test_append_to_file_accumulates() {
        let first = Buffer::from(&b"first-chunk\n"[..]);
        let second = Buffer::from(&b"second-chunk\n"[..]);

        let tmp = NamedTempFile::new().expect("create tempfile");
        // `write_to_file` creates / truncates; `append_to_file`
        // subsequently extends.
        first.write_to_file(tmp.path()).expect("write_to_file");
        second.append_to_file(tmp.path()).expect("append_to_file");

        let mut reloaded = Buffer::new();
        reloaded.read_from_file(tmp.path()).expect("read_from_file");
        assert_eq!(reloaded.as_slice(), b"first-chunk\nsecond-chunk\n");
    }

    #[test]
    fn test_read_from_file_appends_to_existing_content() {
        let tmp = NamedTempFile::new().expect("create tempfile");
        Buffer::from(&b"file-bytes"[..])
            .write_to_file(tmp.path())
            .expect("write_to_file");

        let mut buf = Buffer::new();
        buf.push_slice(b"prefix:");
        buf.read_from_file(tmp.path()).expect("read_from_file");
        assert_eq!(buf.as_slice(), b"prefix:file-bytes");
    }

    #[test]
    fn test_read_from_file_missing_returns_error() {
        let mut buf = Buffer::new();
        let err = buf
            .read_from_file("/this/path/definitely/does/not/exist.dat")
            .expect_err("missing path must raise io error");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    // -- trait implementations ------------------------------------------------

    #[test]
    fn test_as_ref_and_as_mut_slice() {
        let mut buf = Buffer::from(&[10, 20, 30][..]);
        assert_eq!(AsRef::<[u8]>::as_ref(&buf), &[10, 20, 30]);
        AsMut::<[u8]>::as_mut(&mut buf)[0] = 0xFF;
        assert_eq!(buf.as_slice(), &[0xFF, 20, 30]);
    }

    #[test]
    fn test_from_vec_and_back() {
        let v = vec![1u8, 2, 3];
        let buf: Buffer = v.clone().into();
        assert_eq!(buf.as_slice(), v.as_slice());
        let round: Vec<u8> = buf.into();
        assert_eq!(round, v);
    }

    #[test]
    fn test_from_slice() {
        let buf: Buffer = (&[4u8, 5, 6][..]).into();
        assert_eq!(buf.as_slice(), &[4, 5, 6]);
    }

    #[test]
    fn test_clone_is_independent() {
        let mut original = Buffer::from(&[1u8, 2, 3][..]);
        let clone = original.clone();
        original.push(4);
        assert_eq!(original.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(clone.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_debug_is_derivable() {
        // The Debug derive must exist for diagnostic logging.
        let buf = Buffer::from(&[1u8, 2, 3][..]);
        let printed = format!("{:?}", buf);
        assert!(printed.contains('1'));
    }
}
