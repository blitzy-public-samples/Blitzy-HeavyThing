// ------------------------------------------------------------------------
// HeavyThing x86_64 assembly language library and showcase programs
// Copyright © 2015 2 Ton Digital
// Homepage: https://2ton.com.au/
// Author: Jeff Marrison <jeff@2ton.com.au>
//
// This file is part of the HeavyThing library.
//
// HeavyThing is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License, or
// (at your option) any later version.
//
// HeavyThing is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with the HeavyThing library. If not, see <http://www.gnu.org/licenses/>.
// ------------------------------------------------------------------------
//
// ssh/compression.rs: zlib compression/decompression for SSH transport layer.
// Rust port of the zlib-related fragments of ssh.inc.
// ------------------------------------------------------------------------

//! SSH zlib compression/decompression for the transport layer.
//!
//! This module is the Rust translation of the compression-related fragments
//! of `ssh.inc` — specifically:
//!
//! * `ssh$encrypt` compression block (FASM lines 683–854): outbound path,
//!   msg_type + payload → deflate → encrypt.
//! * `ssh$receive` inflate block (FASM lines 1230–1279): inbound path,
//!   decrypt → verify HMAC → inflate.
//! * `ssh$got_kexinit` compression negotiation (FASM lines 4894–4999): the
//!   peer-KEXINIT byte-scan that decides whether to enable compression and
//!   whether the activation is immediate (`zlib`) or delayed-until-userauth
//!   (`zlib@openssh.com`).
//! * NEWKEYS handler `zlib$deflateInit` / `zlib$inflateInit` (FASM lines
//!   3886–4100 and 3095–3135): both contexts are initialised with
//!   compression level **1** (speed over ratio — SSH traffic is already
//!   encrypted so maximum compression ratio is low-value).
//! * USERAUTH_SUCCESS state promotion (FASM lines 2740–2840): the
//!   `1 → 2` transition that flips delayed compression into active state.
//! * NEWKEYS state promotion (FASM lines 3095–3135): the `3 → 2` transition
//!   that flips immediate-zlib's transient value into the canonical active
//!   state.
//!
//! # State machine (`ssh_compstate_ofs`)
//!
//! FASM's `ssh_compstate_ofs` is a `u32` with four distinct values:
//!
//! | FASM `u32` | [`CompressionState`]   | Meaning                                   |
//! |------------|------------------------|-------------------------------------------|
//! | `0`        | [`CompressionState::None`]            | No compression negotiated.                |
//! | `1`        | [`CompressionState::Delayed`]         | `zlib@openssh.com` negotiated; waits for SSH_MSG_USERAUTH_SUCCESS. |
//! | `2`        | [`CompressionState::Active`]          | Compression in use — deflate/inflate run on every packet. |
//! | `3`        | [`CompressionState::ActiveImmediate`] | Plain `zlib` negotiated — active from NEWKEYS (promoted to 2 at the NEWKEYS handler). |
//!
//! Two callers trigger transitions:
//!
//! * After USERAUTH_SUCCESS the SSH server walks `1 → 2`
//!   ([`CompressionState::promote_after_userauth`]), triggered from FASM
//!   lines 2752–2755, 2801–2804, and 2828–2831.
//! * At NEWKEYS the server walks `3 → 2` inline (FASM lines 3119–3123).
//!   The Rust port treats `ActiveImmediate` as already "active" — callers
//!   can simply read [`CompressionState::is_active`].
//!
//! # Flush mode
//!
//! FASM uses `zlib_partial_flush` (Z_PARTIAL_FLUSH, value `1`) at both
//! `ssh$encrypt` (line 717) and `ssh$receive` (line 1281). The Rust port
//! uses [`FlushCompress::Sync`] / [`FlushDecompress::Sync`]
//! (Z_SYNC_FLUSH, value `2`) per the schema's deliberate port decision —
//! Z_SYNC_FLUSH is more RFC-aligned for packet-boundary alignment and
//! both modes flush pending output to byte-aligned boundaries without
//! resetting the compressor state across packets.
//!
//! # AAP cross-references
//!
//! * AAP §0.5.1.4 — "zlib compression via `flate2`; forced when
//!   `ssh_force_compression = 1`".
//! * AAP §0.6.1 — `flate2 = "1"` declared in workspace dependencies.
//! * AAP §0.8.1 — behavioural preservation of SSH wire protocol.

use crate::error::{NetError, SshError};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

// ---------------------------------------------------------------------------
// CompressionState
// ---------------------------------------------------------------------------

/// SSH compression negotiation / activation state (maps to FASM
/// `ssh_compstate_ofs`, a 4-valued `u32`).
///
/// See the [module-level state-machine table](self#state-machine-ssh_compstate_ofs)
/// for the `u32 ↔ variant` mapping and transition rules.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CompressionState {
    /// No compression negotiated (FASM value `0`). Deflate/inflate are
    /// never invoked for this session.
    None,
    /// `zlib@openssh.com` negotiated (FASM value `1`). Deflate/inflate
    /// are **NOT** yet invoked; the state promotes to [`Active`] after
    /// SSH_MSG_USERAUTH_SUCCESS (see [`Self::promote_after_userauth`]).
    ///
    /// [`Active`]: Self::Active
    Delayed,
    /// Compression active (FASM value `2`). Deflate/inflate run on
    /// every packet. This variant is reached either by promotion from
    /// [`Delayed`] at USERAUTH_SUCCESS, or by direct transition from
    /// [`ActiveImmediate`] at NEWKEYS.
    ///
    /// [`Delayed`]: Self::Delayed
    /// [`ActiveImmediate`]: Self::ActiveImmediate
    Active,
    /// Plain `zlib` negotiated (FASM value `3`). Deflate/inflate are
    /// invoked immediately from NEWKEYS. The FASM port promotes this to
    /// [`Active`] inside the NEWKEYS handler (lines 3119–3123); the
    /// Rust port treats both [`Active`] and [`ActiveImmediate`] as
    /// equivalent for the purposes of [`Self::is_active`].
    ///
    /// [`Active`]: Self::Active
    ActiveImmediate,
}

impl CompressionState {
    /// Return `true` when deflate/inflate should actually be invoked on
    /// outbound/inbound packets.
    ///
    /// This matches the FASM check `cmp dword [rbx+ssh_compstate_ofs], 2`
    /// used at both `ssh$encrypt` (line 699) and `ssh$receive` (line 1244)
    /// — extended to also cover [`ActiveImmediate`] which FASM promotes
    /// to `2` inside the NEWKEYS handler before any encrypt/receive call.
    ///
    /// [`ActiveImmediate`]: Self::ActiveImmediate
    pub fn is_active(self) -> bool {
        matches!(self, CompressionState::Active | CompressionState::ActiveImmediate)
    }

    /// Promote a [`Delayed`](Self::Delayed) state to
    /// [`Active`](Self::Active) after SSH_MSG_USERAUTH_SUCCESS.
    ///
    /// This is the Rust-idiomatic equivalent of the FASM `cmove` triple
    /// at lines 2752–2755 (and 2801–2804, 2828–2831):
    ///
    /// ```text
    ///     mov     edx, 2
    ///     mov     ecx, [rbx+ssh_compstate_ofs]
    ///     cmp     ecx, 1
    ///     cmove   ecx, edx                ; if state == 1, promote to 2
    ///     mov     [rbx+ssh_compstate_ofs], ecx
    /// ```
    ///
    /// All other states are left untouched.
    pub fn promote_after_userauth(&mut self) {
        if matches!(*self, CompressionState::Delayed) {
            *self = CompressionState::Active;
        }
    }

    /// Map a raw FASM `ssh_compstate_ofs` `u32` value to this enum.
    ///
    /// Unknown / out-of-range values fall through to
    /// [`CompressionState::None`] as a defensive default — the FASM
    /// layout never stores anything else, but a defensive mapping keeps
    /// the port robust if the `u32` is fed from untrusted input (e.g.
    /// FFI bridge, serialized session state, debug dumps).
    pub fn from_fasm_u32(v: u32) -> Self {
        match v {
            0 => CompressionState::None,
            1 => CompressionState::Delayed,
            2 => CompressionState::Active,
            3 => CompressionState::ActiveImmediate,
            _ => CompressionState::None,
        }
    }
}

// ---------------------------------------------------------------------------
// negotiate_compression
// ---------------------------------------------------------------------------

/// Scan a peer's raw KEXINIT packet payload for a zlib compression offer
/// and return the resulting [`CompressionState`].
///
/// This is a direct Rust translation of the FASM byte-scan at
/// `ssh$got_kexinit` lines 4893–4930. The scan is **intentionally
/// primitive**: it searches the packet bytes for the ASCII substring
/// `"zlib"` with an optional follow-up `"@ope"` probe — it does **NOT**
/// RFC-parse the algorithm-name list. This mirrors the FASM comment:
/// *"subsequent packets will fail miserably anyway if peer plays silly
/// buggers"*.
///
/// # Algorithm
///
/// 1. **Sanity check**: packets below `32` bytes return
///    [`CompressionState::None`] immediately (matches FASM
///    `cmp rcx, 32; jb .got_kexinit_nocomp`).
///
/// 2. **Non-forced prelude**: when `force_compression == false`, if the
///    4-byte sequence `"ne,z"` appears **anywhere** in the buffer, return
///    [`CompressionState::None`]. This is the FASM heuristic for
///    *"peer advertised `none,zlib...` in their compression-preference
///    list so their first choice is no-compression"* — `"ne,z"` is the
///    literal prefix of *"none,zlib..."* that appears in the peer's
///    `name_list`.
///
/// 3. **Scan for `"zlib"`**: if any 4-byte window matches `"zlib"`, take
///    the first such occurrence. If no match, return
///    [`CompressionState::None`].
///
/// 4. **Variant discrimination**: at the matched position, look **4
///    bytes further** for `"@ope"` (the prefix of `"@openssh.com"`). If
///    found → [`CompressionState::Delayed`]. Otherwise →
///    [`CompressionState::ActiveImmediate`].
///
/// # FASM equivalence check
///
/// The FASM `cmp dword [rsi], 'zlib'` compares the 4 bytes at `rsi` (in
/// memory / little-endian order) against the literal. Because FASM's
/// string literal `'zlib'` assembles as `z, l, i, b` in memory-order,
/// this is byte-for-byte identical to Rust's `w == b"zlib"` comparison.
/// The same identity holds for `'ne,z'`/`b"ne,z"` and
/// `'@ope'`/`b"@ope"`.
///
/// # Cross-references
///
/// * FASM lines 4893–4930 (`ssh$got_kexinit` compression negotiation).
/// * `ht_defaults.inc` line 411: `ssh_force_compression = 1`.
/// * `ht_defaults.inc` line 405: `ssh_do_compression = 1` (gates whether
///   this function is called at all; callers are expected to already
///   honour that flag).
pub fn negotiate_compression(peer_kexinit: &[u8], force_compression: bool) -> CompressionState {
    // Step 1: sanity-check buffer length. FASM requires ≥ 32 bytes
    // before it will even enter the compression-search loop
    // (cmp rcx, 32; jb .got_kexinit_nocomp).
    if peer_kexinit.len() < 32 {
        return CompressionState::None;
    }

    // Step 2: non-forced mode must first rule out the "peer prefers
    // none" case. In FASM (lines 4921–4923) this is a per-byte check
    // at the current scan position, but the check is commutative w.r.t.
    // position (if "ne,z" appears *anywhere*, compression is disabled),
    // so a single windowed scan suffices.
    if !force_compression && peer_kexinit.windows(4).any(|w| w == b"ne,z") {
        return CompressionState::None;
    }

    // Step 3: search for the first occurrence of "zlib".
    let pos = match peer_kexinit.windows(4).position(|w| w == b"zlib") {
        Some(p) => p,
        None => return CompressionState::None,
    };

    // Step 4: probe 4 bytes past the "zlib" match for the
    // "@ope" (= "@openssh.com" prefix) qualifier. Guard against
    // running off the end of the buffer — if there aren't 4 bytes
    // remaining after the match, treat the offer as the plain `zlib`
    // variant.
    let check_pos = pos + 4;
    if check_pos + 4 <= peer_kexinit.len() && &peer_kexinit[check_pos..check_pos + 4] == b"@ope" {
        CompressionState::Delayed
    } else {
        CompressionState::ActiveImmediate
    }
}

// ---------------------------------------------------------------------------
// DeflateStream — outbound compression context
// ---------------------------------------------------------------------------

/// Per-session, per-direction **outbound** zlib deflate context for the
/// SSH transport layer.
///
/// Owns a [`flate2::Compress`] engine plus two reusable buffers that are
/// reset on every packet. This mirrors the FASM object layout anchored
/// at `ssh_deflate_ofs`, which contains the zlib state plus its own
/// inbuf/outbuf (see `zlib_inbuf_ofs`/`zlib_outbuf_ofs` in
/// `zlib_deflate.inc`).
///
/// The compressor is initialised with **level 1** (speed-over-ratio) to
/// match the FASM `zlib$deflateInit level=1` call at `ssh.inc` line 4038
/// — SSH transport traffic is already encrypted downstream, so the high
/// latency cost of higher compression ratios is rarely worth the small
/// bandwidth savings.
///
/// The `zlib_header = true` argument to [`Compress::new`] requests the
/// standard zlib wrapper (RFC 1950) rather than raw DEFLATE (RFC 1951)
/// — SSH RFC 4253 §6.2 mandates `zlib` compression *"as described in
/// [RFC1950] and in [RFC1951]"*, i.e. with the zlib wrapper.
///
/// # Thread-safety
///
/// [`DeflateStream`] is `Send` but **is not** `Sync` across mutating
/// calls — the flate2 `Compress` engine maintains internal state that
/// is mutated on every `compress_vec` call. Callers wrap the stream in
/// `tokio::sync::Mutex` or similar when sharing it across tasks.
pub struct DeflateStream {
    /// The zlib deflate engine. Internal state persists across packets
    /// within a single SSH session (never reset mid-session; only reset
    /// at NEWKEYS via a fresh [`DeflateStream::new`] call).
    compressor: Compress,
    /// Staging buffer: `msg_type` byte prepended to the plaintext
    /// payload before each compress call. Cleared per packet.
    inbuf: Vec<u8>,
    /// Accumulator for compressed output. Cleared per packet.
    outbuf: Vec<u8>,
}

impl DeflateStream {
    /// Initial staging-buffer capacity (matches FASM `zlib_inbuf_ofs`
    /// initial size of 32 KiB).
    const INITIAL_CAPACITY: usize = 32 * 1024;

    /// Initialise a fresh deflate context with **level 1** and the
    /// zlib wrapper.
    ///
    /// Equivalent to the FASM NEWKEYS-handler call sequence at
    /// `ssh.inc` lines 4031–4039:
    ///
    /// ```text
    ///     lea     rdi, [rbx+ssh_deflate_ofs]
    ///     mov     esi, 1                       ; level=1
    ///     call    zlib$deflateInit
    /// ```
    pub fn new() -> Self {
        Self {
            compressor: Compress::new(Compression::new(1), true),
            inbuf: Vec::with_capacity(Self::INITIAL_CAPACITY),
            outbuf: Vec::with_capacity(Self::INITIAL_CAPACITY),
        }
    }

    /// Compress one plaintext SSH packet (`msg_type` byte + `payload`)
    /// and return a reference to the compressed bytes.
    ///
    /// This mirrors the FASM `ssh$encrypt` compression path at lines
    /// 683–854:
    ///
    /// 1. Reset the session's zlib inbuf and outbuf
    ///    (`buffer$reset`).
    /// 2. Append the `msg_type` byte and the payload bytes to the
    ///    zlib inbuf (`buffer$append`).
    /// 3. Call `zlib$deflate` with flush mode
    ///    [`FlushCompress::Sync`].
    /// 4. The resulting compressed bytes in `outbuf` become the packet
    ///    payload fed to the AES/HMAC path.
    ///
    /// # Errors
    ///
    /// Returns `NetError::Ssh(SshError::Compression(_))` if
    /// [`flate2::Compress::compress_vec`] reports an error or the
    /// buffer-error status. Compression errors in SSH are fatal —
    /// callers are expected to tear down the session.
    ///
    /// # Lifetime
    ///
    /// The returned slice is borrowed from `self.outbuf` and remains
    /// valid until the next call to [`DeflateStream::compress_packet`]
    /// or [`DeflateStream::reset`].
    pub fn compress_packet(&mut self, msg_type: u8, payload: &[u8]) -> Result<&[u8], NetError> {
        // Reset per-packet staging buffers (matches FASM `buffer$reset`
        // at the top of the compression branch). We do NOT reset the
        // compressor engine itself — cross-packet state (window history,
        // Huffman tables) persists across packets within a session,
        // which is the whole point of stream compression.
        self.inbuf.clear();
        self.outbuf.clear();

        // Build the to-be-compressed payload: msg_type byte followed
        // by the packet payload (matches FASM lines 688–699 which
        // writes `type` then appends the rest of the packet into the
        // zlib inbuf).
        self.inbuf.push(msg_type);
        self.inbuf.extend_from_slice(payload);

        // Invoke the deflate engine with Sync flush (schema-mandated,
        // see module-level "Flush mode" section). compress_vec handles
        // all the output-buffer growth internally.
        let status = self
            .compressor
            .compress_vec(&self.inbuf, &mut self.outbuf, FlushCompress::Sync)
            .map_err(|e| NetError::Ssh(SshError::Compression(format!("deflate error: {:?}", e))))?;

        match status {
            Status::Ok | Status::StreamEnd => Ok(&self.outbuf),
            Status::BufError => Err(NetError::Ssh(SshError::Compression(
                "deflate buffer error".to_string(),
            ))),
        }
    }

    /// Clear the per-packet staging buffers **without** resetting the
    /// compressor's internal state.
    ///
    /// Called by the session destroy path (FASM `ssh$destroy`
    /// compression cleanup). The compressor engine itself is dropped
    /// when this struct is dropped — `Compress` implements `Drop` which
    /// calls zlib's `deflateEnd` internally.
    pub fn reset(&mut self) {
        self.inbuf.clear();
        self.outbuf.clear();
    }
}

impl Default for DeflateStream {
    /// Delegates to [`DeflateStream::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// Debug representation intentionally redacts the compressor engine's
/// internal state and the buffer contents — SSH payloads routinely
/// contain credentials and session data that must never appear in logs.
impl std::fmt::Debug for DeflateStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeflateStream")
            .field("inbuf_len", &self.inbuf.len())
            .field("outbuf_len", &self.outbuf.len())
            .field("inbuf_capacity", &self.inbuf.capacity())
            .field("outbuf_capacity", &self.outbuf.capacity())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// InflateStream — inbound decompression context
// ---------------------------------------------------------------------------

/// Per-session, per-direction **inbound** zlib inflate context for the
/// SSH transport layer.
///
/// Owns a [`flate2::Decompress`] engine plus two reusable buffers. This
/// mirrors the FASM object layout anchored at `ssh_inflate_ofs`.
///
/// The `zlib_header = true` argument to [`Decompress::new`] matches the
/// corresponding [`DeflateStream`] configuration so inbound packets can
/// be decompressed by the zlib-wrapped stream the peer sent.
///
/// # Thread-safety
///
/// Same guarantees as [`DeflateStream`]: `Send` but not `Sync` across
/// mutating calls.
pub struct InflateStream {
    /// The zlib inflate engine. Internal state persists across packets
    /// within a single SSH session.
    decompressor: Decompress,
    /// Staging buffer: holds the raw compressed bytes for the current
    /// packet. Cleared per packet.
    inbuf: Vec<u8>,
    /// Accumulator for decompressed output. Cleared per packet.
    outbuf: Vec<u8>,
}

impl InflateStream {
    /// Initial staging-buffer capacity (matches FASM `zlib_inbuf_ofs`
    /// initial size of 32 KiB).
    const INITIAL_CAPACITY: usize = 32 * 1024;

    /// Initialise a fresh inflate context with the zlib wrapper.
    ///
    /// Equivalent to the FASM NEWKEYS-handler call sequence at
    /// `ssh.inc` lines ~3100–3135 (inflateInit call with level=1,
    /// though the level parameter is ignored for inflate).
    pub fn new() -> Self {
        Self {
            decompressor: Decompress::new(true),
            inbuf: Vec::with_capacity(Self::INITIAL_CAPACITY),
            outbuf: Vec::with_capacity(Self::INITIAL_CAPACITY),
        }
    }

    /// Decompress one SSH packet's payload (after AES decrypt and HMAC
    /// verification have succeeded) and return a reference to the
    /// decompressed bytes.
    ///
    /// This mirrors the FASM `ssh$receive` inflate path at lines
    /// 1230–1279:
    ///
    /// 1. Reset the session's zlib inbuf.
    /// 2. Slice off the 4-byte packet-length prefix and the 1-byte
    ///    padding-length field, then append the remaining
    ///    `(packet_length − padding_length − 1)` bytes to the inbuf.
    ///    Callers are expected to have already performed that slicing
    ///    before passing the `compressed` slice in.
    /// 3. Call `zlib$inflate` with flush mode
    ///    [`FlushDecompress::Sync`].
    /// 4. The decompressed bytes are the packet content (first byte
    ///    = `msg_type`).
    ///
    /// # Errors
    ///
    /// Returns `NetError::Ssh(SshError::Compression(_))` if
    /// [`flate2::Decompress::decompress_vec`] reports an error or the
    /// buffer-error status.
    ///
    /// # Lifetime
    ///
    /// The returned slice is borrowed from `self.outbuf` and remains
    /// valid until the next call to
    /// [`InflateStream::decompress_packet`] or
    /// [`InflateStream::reset`].
    pub fn decompress_packet(&mut self, compressed: &[u8]) -> Result<&[u8], NetError> {
        self.inbuf.clear();
        self.outbuf.clear();
        self.inbuf.extend_from_slice(compressed);

        let status = self
            .decompressor
            .decompress_vec(&self.inbuf, &mut self.outbuf, FlushDecompress::Sync)
            .map_err(|e| NetError::Ssh(SshError::Compression(format!("inflate error: {:?}", e))))?;

        match status {
            Status::Ok | Status::StreamEnd => Ok(&self.outbuf),
            Status::BufError => Err(NetError::Ssh(SshError::Compression(
                "inflate buffer error".to_string(),
            ))),
        }
    }

    /// Clear the per-packet staging buffers **without** resetting the
    /// decompressor's internal state.
    pub fn reset(&mut self) {
        self.inbuf.clear();
        self.outbuf.clear();
    }
}

impl Default for InflateStream {
    /// Delegates to [`InflateStream::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// Debug representation intentionally redacts the decompressor engine's
/// internal state and the buffer contents — see the [`DeflateStream`]
/// rationale.
impl std::fmt::Debug for InflateStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InflateStream")
            .field("inbuf_len", &self.inbuf.len())
            .field("outbuf_len", &self.outbuf.len())
            .field("inbuf_capacity", &self.inbuf.capacity())
            .field("outbuf_capacity", &self.outbuf.capacity())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Send + Sync assertions
// ---------------------------------------------------------------------------
//
// All public types must be `Send + Sync` so they can be moved across the
// tokio runtime's tasks (and, for Send, held across `.await` points).
// `flate2::Compress` and `flate2::Decompress` are `Send + Sync`, and
// `Vec<u8>` is trivially `Send + Sync`, so these derivations come for
// free — but we statically assert them here so a future flate2 upgrade
// that regresses on `Send`/`Sync` would fail the build immediately.

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CompressionState>();
    assert_send_sync::<DeflateStream>();
    assert_send_sync::<InflateStream>();
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CompressionState tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compression_state_promotion() {
        // Delayed → Active on USERAUTH_SUCCESS.
        let mut s = CompressionState::Delayed;
        s.promote_after_userauth();
        assert_eq!(s, CompressionState::Active);

        // None, Active, ActiveImmediate must all be left untouched.
        let mut s = CompressionState::None;
        s.promote_after_userauth();
        assert_eq!(s, CompressionState::None);

        let mut s = CompressionState::Active;
        s.promote_after_userauth();
        assert_eq!(s, CompressionState::Active);

        let mut s = CompressionState::ActiveImmediate;
        s.promote_after_userauth();
        assert_eq!(s, CompressionState::ActiveImmediate);
    }

    #[test]
    fn test_compression_state_is_active() {
        // is_active matches the FASM `cmp dword [...ssh_compstate_ofs], 2`
        // check, extended to include state 3 (ActiveImmediate) which
        // FASM promotes to 2 at NEWKEYS before any encrypt/receive call.
        assert!(!CompressionState::None.is_active());
        assert!(!CompressionState::Delayed.is_active());
        assert!(CompressionState::Active.is_active());
        assert!(CompressionState::ActiveImmediate.is_active());
    }

    #[test]
    fn test_compression_state_from_fasm_u32() {
        assert_eq!(CompressionState::from_fasm_u32(0), CompressionState::None);
        assert_eq!(CompressionState::from_fasm_u32(1), CompressionState::Delayed);
        assert_eq!(CompressionState::from_fasm_u32(2), CompressionState::Active);
        assert_eq!(
            CompressionState::from_fasm_u32(3),
            CompressionState::ActiveImmediate
        );
        // Defensive: unknown → None.
        assert_eq!(CompressionState::from_fasm_u32(4), CompressionState::None);
        assert_eq!(CompressionState::from_fasm_u32(u32::MAX), CompressionState::None);
    }

    // -----------------------------------------------------------------------
    // negotiate_compression tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_negotiate_none_when_too_short() {
        // FASM sanity check: cmp rcx, 32; jb .got_kexinit_nocomp.
        // Any buffer < 32 bytes immediately yields None.
        let short_buf = b"zlib@openssh.com";
        assert!(short_buf.len() < 32);
        assert_eq!(negotiate_compression(short_buf, false), CompressionState::None);
        assert_eq!(negotiate_compression(short_buf, true), CompressionState::None);

        // Exactly 31 bytes — still below threshold.
        let buf31 = vec![b'A'; 31];
        assert_eq!(negotiate_compression(&buf31, false), CompressionState::None);
        assert_eq!(negotiate_compression(&buf31, true), CompressionState::None);

        // Empty buffer.
        assert_eq!(negotiate_compression(&[], false), CompressionState::None);
        assert_eq!(negotiate_compression(&[], true), CompressionState::None);
    }

    #[test]
    fn test_negotiate_zlib_only() {
        // A buffer containing the bare "zlib" ASCII string (with
        // enough padding to exceed the 32-byte sanity threshold)
        // should return ActiveImmediate — plain `zlib`, activate
        // from NEWKEYS.
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&[0u8; 40]);
        buf.extend_from_slice(b"zlib");
        // Pad with non-"@ope" bytes so the @openssh.com probe fails.
        buf.extend_from_slice(b",none");
        buf.extend_from_slice(&[0u8; 16]);
        assert!(buf.len() >= 32);
        assert_eq!(
            negotiate_compression(&buf, false),
            CompressionState::ActiveImmediate
        );
        assert_eq!(
            negotiate_compression(&buf, true),
            CompressionState::ActiveImmediate
        );
    }

    #[test]
    fn test_negotiate_zlib_openssh() {
        // A buffer containing "zlib@openssh.com" should return Delayed
        // — the @openssh.com variant activates only after userauth.
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&[0u8; 40]);
        buf.extend_from_slice(b"zlib@openssh.com");
        buf.extend_from_slice(&[0u8; 16]);
        assert!(buf.len() >= 32);
        assert_eq!(negotiate_compression(&buf, false), CompressionState::Delayed);
        assert_eq!(negotiate_compression(&buf, true), CompressionState::Delayed);
    }

    #[test]
    fn test_negotiate_none_preferred() {
        // Peer's compression-preference list starts with "none", then
        // offers "zlib@openssh.com" as a fallback:
        //   "none,zlib@openssh.com,zlib"
        // The literal substring "ne,z" appears at position 2 (inside
        // "none,zlib..."), so in non-forced mode the FASM heuristic
        // returns None regardless of the later zlib offers.
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(b"none,zlib@openssh.com,zlib");
        buf.extend_from_slice(&[0u8; 8]);
        assert!(buf.len() >= 32);
        assert_eq!(negotiate_compression(&buf, false), CompressionState::None);
    }

    #[test]
    fn test_negotiate_none_preferred_forced_finds_zlib() {
        // When force_compression = true, the "none-first" heuristic is
        // bypassed entirely (matches FASM's `if ssh_force_compression`
        // branch at lines 4910–4919). The FIRST "zlib" in the buffer
        // is "zlib@openssh.com" (inside the preference list), so the
        // forced path returns Delayed.
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(b"none,zlib@openssh.com,zlib");
        buf.extend_from_slice(&[0u8; 8]);
        assert!(buf.len() >= 32);
        assert_eq!(negotiate_compression(&buf, true), CompressionState::Delayed);

        // Second scenario — forced + peer only offers plain `zlib`
        // with "none" first. Forced mode should still return
        // ActiveImmediate.
        let mut buf2 = Vec::with_capacity(64);
        buf2.extend_from_slice(&[0u8; 32]);
        buf2.extend_from_slice(b"none,zlib,more");
        buf2.extend_from_slice(&[0u8; 16]);
        assert!(buf2.len() >= 32);
        assert_eq!(
            negotiate_compression(&buf2, true),
            CompressionState::ActiveImmediate
        );
    }

    #[test]
    fn test_negotiate_no_match_returns_none() {
        // Buffer meeting the length requirement but containing no
        // "zlib" substring returns None in both modes.
        let buf = vec![b'X'; 128];
        assert_eq!(negotiate_compression(&buf, false), CompressionState::None);
        assert_eq!(negotiate_compression(&buf, true), CompressionState::None);
    }

    #[test]
    fn test_negotiate_zlib_at_buffer_tail() {
        // Edge case: "zlib" appears too close to the end of the
        // buffer to permit a @ope probe — the guard condition
        // `check_pos + 4 <= peer_kexinit.len()` must short-circuit
        // cleanly to ActiveImmediate, never panic.
        let mut buf = vec![0u8; 60];
        // Place "zlib" at position buf.len() - 4 (very last position).
        let len = buf.len();
        buf[len - 4..].copy_from_slice(b"zlib");
        assert_eq!(
            negotiate_compression(&buf, true),
            CompressionState::ActiveImmediate
        );

        // Place "zlib" at position buf.len() - 7 (probe would be
        // at buf.len()-3..buf.len()+1, still out of range).
        let mut buf = vec![0u8; 60];
        let len = buf.len();
        buf[len - 7..len - 3].copy_from_slice(b"zlib");
        assert_eq!(
            negotiate_compression(&buf, true),
            CompressionState::ActiveImmediate
        );
    }

    // -----------------------------------------------------------------------
    // Deflate / Inflate round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_deflate_inflate_roundtrip() {
        // Single-packet round-trip: compress a 1 KiB payload through a
        // DeflateStream, then decompress through a fresh InflateStream,
        // and verify the recovered bytes match exactly.
        let mut deflate = DeflateStream::new();
        let mut inflate = InflateStream::new();

        // Use a non-uniform 1 KiB payload so zlib actually does work
        // (a flat-zero payload would compress extremely well but
        // wouldn't stress the sliding-window / Huffman paths).
        let payload: Vec<u8> = (0u32..1024u32).map(|i| (i % 251) as u8).collect();
        let msg_type: u8 = 94; // SSH_MSG_CHANNEL_DATA (arbitrary, non-zero)

        // Compress.
        let compressed_bytes = {
            let compressed = deflate
                .compress_packet(msg_type, &payload)
                .expect("deflate must succeed");
            compressed.to_vec()
        };
        assert!(
            !compressed_bytes.is_empty(),
            "compressed output must not be empty"
        );

        // Decompress.
        let decompressed = inflate
            .decompress_packet(&compressed_bytes)
            .expect("inflate must succeed");

        // Decompressed form is msg_type || payload.
        assert_eq!(decompressed.len(), 1 + payload.len());
        assert_eq!(decompressed[0], msg_type);
        assert_eq!(&decompressed[1..], &payload[..]);
    }

    #[test]
    fn test_deflate_inflate_roundtrip_multi_packet() {
        // Multi-packet round-trip: compress three DIFFERENT packets
        // through the SAME DeflateStream (cross-packet state must
        // persist), then decompress through the SAME InflateStream
        // in the same order. Verify all three recover exactly.
        //
        // This is the critical test for SSH compression correctness:
        // SSH transport compression accumulates state across packets
        // within a session, so resetting the engine between packets
        // would corrupt the inflation side.
        let mut deflate = DeflateStream::new();
        let mut inflate = InflateStream::new();

        let packets: [(u8, Vec<u8>); 3] = [
            (20, b"hello world".to_vec()),
            (21, (0u8..=200u8).collect()),
            (
                50,
                b"SSH packet number three with distinct bytes 0123456789".to_vec(),
            ),
        ];

        // Compress all three in order, collecting the compressed
        // output bytes for each.
        let mut compressed_frames: Vec<Vec<u8>> = Vec::with_capacity(3);
        for (msg_type, payload) in &packets {
            let compressed = deflate
                .compress_packet(*msg_type, payload)
                .expect("deflate must succeed");
            compressed_frames.push(compressed.to_vec());
        }

        // Decompress all three in the same order and verify.
        for ((msg_type, payload), compressed) in packets.iter().zip(compressed_frames.iter()) {
            let decompressed = inflate
                .decompress_packet(compressed)
                .expect("inflate must succeed");
            assert_eq!(
                decompressed.len(),
                1 + payload.len(),
                "msg_type={}: decompressed length mismatch",
                msg_type
            );
            assert_eq!(
                decompressed[0], *msg_type,
                "msg_type={}: first byte mismatch",
                msg_type
            );
            assert_eq!(
                &decompressed[1..],
                &payload[..],
                "msg_type={}: payload mismatch",
                msg_type
            );
        }
    }

    #[test]
    fn test_deflate_reset_clears_buffers() {
        // After one compression call + reset, the per-packet staging
        // buffers must be empty. The compressor state itself is
        // NOT reset (that's by design — inflate cannot keep up if
        // deflate reset its state).
        let mut deflate = DeflateStream::new();
        let payload = vec![0x5Au8; 512];
        let _ = deflate
            .compress_packet(1, &payload)
            .expect("deflate must succeed");

        // Some bytes must have been written to outbuf.
        assert!(!deflate.outbuf.is_empty());

        deflate.reset();
        assert!(deflate.inbuf.is_empty(), "inbuf must be empty after reset");
        assert!(deflate.outbuf.is_empty(), "outbuf must be empty after reset");
    }

    #[test]
    fn test_inflate_reset_clears_buffers() {
        // Symmetric test for InflateStream::reset.
        let mut deflate = DeflateStream::new();
        let mut inflate = InflateStream::new();
        let payload = vec![0xA5u8; 512];

        let compressed = deflate
            .compress_packet(2, &payload)
            .expect("deflate must succeed")
            .to_vec();

        let _ = inflate
            .decompress_packet(&compressed)
            .expect("inflate must succeed");

        assert!(!inflate.outbuf.is_empty());
        inflate.reset();
        assert!(inflate.inbuf.is_empty(), "inbuf must be empty after reset");
        assert!(inflate.outbuf.is_empty(), "outbuf must be empty after reset");
    }

    #[test]
    fn test_default_constructors() {
        // Default derivations must match new() for both stream types
        // (needed for convenient test/builder integration and for
        // tokio/Arc construction patterns).
        let d = DeflateStream::default();
        assert!(d.inbuf.is_empty());
        assert!(d.outbuf.is_empty());

        let i = InflateStream::default();
        assert!(i.inbuf.is_empty());
        assert!(i.outbuf.is_empty());
    }

    #[test]
    fn test_debug_impls_redact_buffers() {
        // Debug output must NOT leak buffer contents (security
        // requirement — SSH payloads contain credentials).
        let mut deflate = DeflateStream::new();
        let _ = deflate.compress_packet(1, b"SECRET_TOKEN_NOT_IN_DEBUG");
        let dbg = format!("{:?}", deflate);
        assert!(!dbg.contains("SECRET_TOKEN"));
        assert!(dbg.contains("DeflateStream"));

        let inflate = InflateStream::new();
        let dbg = format!("{:?}", inflate);
        assert!(dbg.contains("InflateStream"));
    }
}
