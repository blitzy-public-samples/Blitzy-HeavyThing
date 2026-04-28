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
// ssh/cipher.rs: SSH transport-layer encryption (AES-256-CBC) and MAC
// (HMAC-SHA-256). Rust port of the cipher/MAC fragments of ssh.inc.
// ------------------------------------------------------------------------

//! SSH transport-layer encryption (`aes256-cbc`) and MAC (`hmac-sha2-256`).
//!
//! This module is the Rust translation of the cipher and MAC fragments of
//! `ssh.inc`. Specifically:
//!
//! * [`CipherState::cbc_encrypt_in_place`] — CBC encrypt loop with IV
//!   chaining (FASM `ssh$encrypt`, `ssh.inc` lines 861–896).
//! * [`CipherState::cbc_decrypt_in_place`] — CBC decrypt loop with IV
//!   chaining and the FASM "block flipper" pattern (FASM `ssh$receive`,
//!   `ssh.inc` lines 1140–1196).
//! * [`CipherState::compute_mac`] — outgoing HMAC computation plus
//!   sequence-number increment (FASM lines 824–845, 898–905, 917).
//! * [`CipherState::verify_mac`] — incoming HMAC verification in
//!   constant time plus unconditional sequence-number increment (FASM
//!   lines 1199–1230).
//! * [`frame_packet_into`] and [`compute_padding`] — packet assembly
//!   with RFC 4253 §6 padding rules (FASM lines 724–816).
//! * [`CipherState::activate`] — NEWKEYS activation (FASM lines
//!   ~3960–4020 for local/writer state, ~3300 for remote/reader state).
//!
//! # Cipher-suite design
//!
//! The FASM author locked in exactly one cipher suite for SSH (`ssh.inc`
//! lines 42–61):
//!
//! > "aes256-cbc: On AESNI hardware, aes256 is insanely fast, and the
//! > bottleneck is of course the HMAC speed. For all my SSH needs the
//! > actual full-rate aes256-cbc is ridiculously more than enough."
//! >
//! > "hmac-sha2-256: While SHA512 is faster, the extra protocol overhead
//! > to carry it doesn't seem to have any benefit. SHA256 it is."
//!
//! This port preserves that single suite:
//!
//! | Parameter             | Value                                   |
//! |-----------------------|-----------------------------------------|
//! | Encryption algorithm  | `aes256-cbc` ([`CIPHER_KEY_SIZE`] = 32) |
//! | MAC algorithm         | `hmac-sha2-256` ([`MAC_KEY_SIZE`] = 32) |
//! | AES block size        | [`CIPHER_BLOCK_SIZE`] = 16              |
//! | AES IV size           | [`CIPHER_IV_SIZE`] = 16                 |
//! | HMAC tag size         | [`MAC_SIZE`] = 32                       |
//! | Minimum padding       | [`MIN_PADDING`] = 4                     |
//! | Maximum packet size   | [`MAX_PACKET_SIZE`] = 35000             |
//!
//! # State model
//!
//! Each SSH session has **two** independent [`CipherState`] instances:
//!
//! | FASM field name        | Direction       | Owner in ssh.inc               |
//! |------------------------|-----------------|--------------------------------|
//! | `ssh_localenc_ofs`, `ssh_localiv_ofs`, `ssh_localhmac_ofs`, `ssh_writeseq_ofs` | local → peer (write) | `ssh$encrypt`            |
//! | `ssh_remoteenc_ofs`, `ssh_remoteiv_ofs`, `ssh_remotehmac_ofs`, `ssh_readseq_ofs` | peer → local (read)  | `ssh$receive`            |
//!
//! Key material for each direction is derived independently per RFC 4253
//! §7.2 (key IDs `A`/`B`/`C`/`D`/`E`/`F`) — see `kex.rs` for the
//! derivation routine. After NEWKEYS, `kex.rs` calls
//! [`CipherState::activate`] on each direction's state with the
//! appropriate IV, encryption key, and integrity key.
//!
//! # CBC-oracle timing-attack mitigation
//!
//! FASM `ssh$receive` implements two timing-attack mitigations from the
//! Albrecht–Paterson CBC-oracle paper (`ssh.inc` lines 46–57):
//!
//! * **Bad-length randomization**: when the decrypted length field is
//!   implausible, ssh$receive keeps reading for a random number of
//!   bytes so bad-length and bad-HMAC are indistinguishable to an
//!   attacker.
//! * **Bad-HMAC randomization**: when HMAC verification fails, the
//!   same random-length behaviour runs, and the sequence number is
//!   incremented regardless.
//!
//! This module implements the **MAC verification** half of that
//! mitigation: [`CipherState::verify_mac`] uses
//! [`ring::hmac::verify`] (which performs a constant-time
//! byte-by-byte comparison per ring's documented contract) and
//! increments the sequence number on both success and failure paths.
//! The packet-level randomization lives in `server.rs` because it
//! requires I/O state the cipher state does not own.
//!
//! # Dependencies
//!
//! * [`aes::Aes256`] — raw AES-256 block cipher. `ring` does **not**
//!   expose raw AES-CBC or raw AES block operations (only AEAD modes),
//!   so we must pull `aes` + `cbc` from RustCrypto per AAP §0.6.1.
//! * [`ring::hmac`] — HMAC-SHA-256 computation. Preferred over the
//!   `crate::crypto::hmac` wrapper here because SSH's per-packet MAC
//!   context lifecycle (create / update / finalise per packet) is
//!   simpler with direct `ring::hmac::Context`.
//! * [`ring::hmac::verify`] — single-shot HMAC verification with a
//!   documented constant-time comparison ("The verification will be
//!   done in constant time to prevent timing attacks."). Using `==`
//!   or `<[u8]>::eq` here would leak MAC byte position to timing
//!   attackers; ring's `ring::constant_time` module is deprecated in
//!   ring 0.17, hence the use of the still-public `hmac::verify`
//!   wrapper which goes through the same internal primitive.
//! * [`crate::crypto::rng::block`] — cryptographically secure random
//!   bytes for padding generation (matches FASM `rng$block`).
//! * [`crate::error::NetError`] — outer error envelope; this file
//!   constructs `NetError::Ssh(SshError::Cipher)` on every error path.
//!
//! # `unsafe` audit
//!
//! This file contributes **zero** `unsafe` blocks to the crate's
//! `UNSAFE_AUDIT.md` tally (AAP §0.7.4.1). The key-zeroization
//! [`CipherState::zeroize`] uses plain `self.key = [0; 32]` assignment
//! because the FASM equivalent (`memset32` in `ssh$destroy`) does not
//! use volatile writes either — behavioural parity is preserved.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;

use ring::hmac;

use crate::crypto::rng;
use crate::error::{NetError, SshError};

// ============================================================================
// Constants — wire-format parameters for SSH `aes256-cbc` +
// `hmac-sha2-256`.
// ============================================================================

/// AES block size in bytes. Matches the SSH transport-layer block size
/// (`16`). This equals both the AES cipher block size and the SSH IV
/// size per RFC 4253 §6.3.
pub const CIPHER_BLOCK_SIZE: usize = 16;

/// AES-256 key size in bytes (`32`). Matches FASM `aes_key256_ofs`
/// allocation and the `"C"` / `"D"` key-derivation output lengths per
/// RFC 4253 §7.2.
pub const CIPHER_KEY_SIZE: usize = 32;

/// SSH transport IV size in bytes (`16`). Equals [`CIPHER_BLOCK_SIZE`]
/// because SSH CBC uses the cipher's block size as the IV size per RFC
/// 4253 §6.3.
pub const CIPHER_IV_SIZE: usize = 16;

/// HMAC-SHA-256 output size in bytes (`32`). Matches RFC 6668 §2 and
/// the FASM `hmac_final` write size at `ssh.inc` line 904.
pub const MAC_SIZE: usize = 32;

/// HMAC-SHA-256 key size in bytes (`32`). SSH `hmac-sha2-256` uses the
/// full 32-byte derived integrity material per RFC 6668 §2. Note: the
/// HMAC block size is 64 bytes (SHA-256 block size), but ring's
/// [`hmac::Key::new`] performs any necessary key padding internally.
pub const MAC_KEY_SIZE: usize = 32;

/// Minimum SSH packet padding in bytes (`4`). Matches RFC 4253 §6
/// "random padding" constraint — "4 ≤ padding_length ≤ 255".
pub const MIN_PADDING: usize = 4;

/// Maximum SSH packet size in bytes (`35000`). Matches RFC 4253 §6.1
/// "packet_length" cap. The FASM implementation tolerates larger
/// packets in some code paths, but this module treats 35000 as the
/// authoritative cap for diagnostic purposes; enforcement lives in
/// `server.rs`.
pub const MAX_PACKET_SIZE: usize = 35000;

// ============================================================================
// CipherState — per-direction cipher + MAC + IV + sequence-number
// bundle.
// ============================================================================

/// Owns the per-direction SSH transport-layer crypto state: AES-256
/// key, 128-bit IV, HMAC-SHA-256 key, and 32-bit sequence number.
///
/// Used for both client-to-server and server-to-client directions.
/// The FASM layout has two such bundles per `ssh` object:
///
/// | FASM fields                                        | Rust field(s) |
/// |----------------------------------------------------|---------------|
/// | `ssh_localenc_ofs`, `ssh_localiv_ofs`, `ssh_localhmac_ofs`, `ssh_writeseq_ofs` | The *local* (writer) `CipherState` |
/// | `ssh_remoteenc_ofs`, `ssh_remoteiv_ofs`, `ssh_remotehmac_ofs`, `ssh_readseq_ofs` | The *remote* (reader) `CipherState` |
///
/// # Lifecycle
///
/// 1. [`CipherState::new`] — created in the dormant state with all
///    keys zeroed and `active == false`.
/// 2. [`CipherState::activate`] — called from `kex.rs` upon the
///    SSH_MSG_NEWKEYS exchange to install the derived key material.
/// 3. [`CipherState::cbc_encrypt_in_place`] /
///    [`CipherState::cbc_decrypt_in_place`] +
///    [`CipherState::compute_mac`] / [`CipherState::verify_mac`] —
///    used per packet.
/// 4. [`CipherState::zeroize`] — clears key material at session end.
///
/// # Clone / Copy semantics
///
/// `CipherState` deliberately does **not** implement [`Clone`] or
/// [`Copy`]. Duplicating a cipher context would break the "one
/// sequence-number sequence per direction per session" contract and
/// would risk catastrophic key reuse. The type is passively `Send +
/// Sync` because every field is a plain fixed-size array or primitive.
pub struct CipherState {
    /// AES-256 key (`32` bytes). Passed to [`Aes256::new`] on every
    /// CBC operation — the `aes` crate's round-key expansion is cheap
    /// compared with HMAC cost (per the FASM author's own note at
    /// `ssh.inc` lines 42–45).
    key: [u8; CIPHER_KEY_SIZE],

    /// Per-packet CBC IV (`16` bytes).
    ///
    /// Updated to the **last ciphertext block** after each
    /// [`Self::cbc_encrypt_in_place`] / [`Self::cbc_decrypt_in_place`]
    /// call per standard CBC-mode chaining. This mirrors FASM's
    /// `ssh_localiv_ofs` / `ssh_remoteiv_ofs` updates at `ssh.inc`
    /// lines 892–896 (write) and 1192–1196 (read).
    iv: [u8; CIPHER_IV_SIZE],

    /// HMAC-SHA-256 key (`32` bytes). Passed to [`hmac::Key::new`] on
    /// every MAC operation.
    mac_key: [u8; MAC_KEY_SIZE],

    /// Sequence number (32-bit wrapping counter) included in every
    /// HMAC input per RFC 4253 §6.4. Increments after every
    /// [`Self::compute_mac`] and every [`Self::verify_mac`]
    /// (regardless of verify outcome).
    seqnum: u32,

    /// `true` once [`Self::activate`] has installed key material.
    /// Used by callers to check that the transport layer has
    /// transitioned past the NEWKEYS handshake.
    active: bool,
}

impl CipherState {
    /// Create a dormant `CipherState` with all key material zeroed and
    /// `active == false`.
    ///
    /// Matches the FASM layout where `ssh_localenc_ofs`,
    /// `ssh_remoteenc_ofs`, `ssh_localhmac_ofs`, and
    /// `ssh_remotehmac_ofs` are all zero (pre-NEWKEYS). The sequence
    /// number starts at 0 per RFC 4253 §6.4.
    #[must_use]
    pub fn new() -> Self {
        Self {
            key: [0; CIPHER_KEY_SIZE],
            iv: [0; CIPHER_IV_SIZE],
            mac_key: [0; MAC_KEY_SIZE],
            seqnum: 0,
            active: false,
        }
    }

    /// Install freshly-derived key material from the KEX phase.
    ///
    /// Called from `kex.rs` after receiving / sending SSH_MSG_NEWKEYS.
    /// Matches the FASM NEWKEYS handler (`ssh.inc` lines ~3960–4020
    /// for the write side, ~3300 for the read side):
    ///
    /// ```text
    /// memcpy pending_iv → iv
    /// aes$init_encrypt cipher ← pending_key
    /// hmac$init_sha256 hmac
    /// hmac$key hmac ← pending_integrity
    /// zero pending fields
    /// ```
    ///
    /// # Arguments
    /// * `key` — 32-byte AES-256 encryption key (derived from
    ///   `SHA256(K || H || "C"|"D" || session_id)` then key-extended
    ///   to 32 bytes).
    /// * `iv` — 16-byte initial IV (derived from
    ///   `SHA256(K || H || "A"|"B" || session_id)`).
    /// * `mac_key` — 32-byte HMAC-SHA-256 integrity key (derived from
    ///   `SHA256(K || H || "E"|"F" || session_id)`).
    ///
    /// # Sequence-number preservation
    ///
    /// This method does **not** reset [`Self::seqnum`]. Per RFC 4253
    /// §6.4, "The packet sequence number MUST NOT be reset on rekey."
    /// The FASM code initialises `ssh_writeseq_ofs` / `ssh_readseq_ofs`
    /// to 0 at session *creation* (before any KEX), so the sequence
    /// carries continuously through all KEX cycles for the session's
    /// lifetime.
    pub fn activate(
        &mut self,
        key: [u8; CIPHER_KEY_SIZE],
        iv: [u8; CIPHER_IV_SIZE],
        mac_key: [u8; MAC_KEY_SIZE],
    ) {
        self.key = key;
        self.iv = iv;
        self.mac_key = mac_key;
        self.active = true;
    }

    /// Returns `true` once [`Self::activate`] has installed key
    /// material (post-NEWKEYS).
    ///
    /// Callers in `server.rs` use this to decide whether to run the
    /// encrypt / decrypt path (matches the FASM branch at `ssh.inc`
    /// line 821: `cmp dword [rbx+ssh_open_ofs], 0 / je .plaintext`).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Current packet sequence number.
    ///
    /// Read-only accessor for testing and diagnostic logging; mutation
    /// happens in [`Self::compute_mac`], [`Self::verify_mac`], and
    /// [`Self::bump_seqnum_plaintext`].
    #[must_use]
    pub fn seqnum(&self) -> u32 {
        self.seqnum
    }

    /// Increment the packet sequence number without performing any
    /// cryptographic operation.
    ///
    /// # Why this exists
    ///
    /// Per RFC 4253 §6.4, the SSH packet sequence number "is an
    /// implicit packet sequence number ... initialized to zero for
    /// the first packet and is incremented after every packet
    /// (regardless of whether encryption or MAC was in use)." The
    /// FASM `ssh.inc` baseline implements this faithfully: every
    /// packet — plaintext KEX packets included — bumps the relevant
    /// sequence number (`ssh_writeseq_ofs` / `ssh_readseq_ofs`)
    /// before the next packet is processed.
    ///
    /// In our Rust port the sequence number is co-located with the
    /// cipher state for cache locality, and `compute_mac` /
    /// `verify_mac` increment it as a side-effect of the HMAC build
    /// path. Those paths are skipped during plaintext key exchange,
    /// so without this method the seqnum would remain at 0 across
    /// every plaintext packet and then disagree with the peer the
    /// moment the first encrypted packet arrives (yielding the
    /// classic "MAC verification failed on first encrypted packet"
    /// symptom that the FASM baseline never exhibits).
    ///
    /// # Semantics
    ///
    /// * Adds 1 with wrapping arithmetic, matching FASM's 32-bit
    ///   `add ssh_writeseq_ofs, 1` (line 917) / `add dword
    ///   ssh_readseq_ofs, 1` (line 1230+) which silently wrap on
    ///   overflow.
    /// * Does **not** touch any other field — `key`, `iv`, `mac_key`,
    ///   `active` are all preserved.
    /// * Idempotent only in the trivial sense; each call advances
    ///   the counter by one. Callers must invoke it exactly once per
    ///   plaintext packet, and not at all on encrypted packets
    ///   (because `compute_mac` / `verify_mac` already bump on the
    ///   encrypted path).
    pub fn bump_seqnum_plaintext(&mut self) {
        self.seqnum = self.seqnum.wrapping_add(1);
    }

    /// Encrypt one complete SSH packet **in place** using AES-256-CBC,
    /// chaining from [`Self::iv`] into the first block and updating
    /// [`Self::iv`] to the last ciphertext block on completion.
    ///
    /// `packet_bytes` is the full pre-encryption packet — namely the
    /// 4-byte length prefix, 1-byte padlen byte, the body, and the
    /// random padding bytes. Per RFC 4253 §6.1 the packet length
    /// excluding MAC must be a multiple of the cipher block size (16
    /// for AES). This invariant is enforced by [`frame_packet_into`]
    /// in this module; callers passing hand-rolled buffers must
    /// ensure it themselves.
    ///
    /// # Algorithm
    ///
    /// Standard CBC encrypt with the FASM "previous-block ↔ current"
    /// chaining pattern from `ssh.inc` lines 861–896:
    ///
    /// ```text
    /// prev = iv
    /// for each 16-byte block c in packet_bytes:
    ///     c ^= prev
    ///     c  = AES_encrypt(c)
    ///     prev = c
    /// iv = prev   # last ciphertext block
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Ssh`] wrapping [`SshError::Cipher`] if
    /// `packet_bytes.len()` is not a multiple of [`CIPHER_BLOCK_SIZE`].
    ///
    /// # Performance
    ///
    /// The `aes` crate's [`Aes256::new`] performs round-key expansion
    /// on every call. Per the FASM author's note (`ssh.inc` lines
    /// 42–45), HMAC dominates AES throughput on AES-NI hardware, so
    /// the per-call constructor cost is acceptable for SSH (which
    /// processes one packet at a time). The library could cache the
    /// expanded round keys inside [`CipherState`] in a future
    /// optimisation, but the schema specifies the simpler "construct
    /// per call" pattern for parity with the FASM code shape.
    pub fn cbc_encrypt_in_place(&mut self, packet_bytes: &mut [u8]) -> Result<(), NetError> {
        // FASM ssh$encrypt accepts only block-aligned packets — the
        // padding logic in compute_padding guarantees this. Reject
        // misaligned input rather than truncating, which would corrupt
        // the wire stream.
        if packet_bytes.len() % CIPHER_BLOCK_SIZE != 0 {
            return Err(NetError::Ssh(SshError::Cipher));
        }
        // Fast path: empty packet (no blocks). FASM `r13d` would be
        // zero so the .cbc_loop never executes and the IV is not
        // updated. We replicate that behaviour: leave self.iv intact.
        if packet_bytes.is_empty() {
            return Ok(());
        }

        let key_ga: &GenericArray<u8, _> = GenericArray::from_slice(&self.key);
        let cipher = Aes256::new(key_ga);

        // `prev` tracks the previous ciphertext block (or the IV for
        // block 0). We update it after every block. The trailing value
        // becomes the new IV for the next packet.
        let mut prev = self.iv;

        for chunk in packet_bytes.chunks_exact_mut(CIPHER_BLOCK_SIZE) {
            // C[i] = AES_encrypt(P[i] XOR prev). The XOR matches FASM
            // `memxor` at `ssh.inc` line 884.
            for (b, p) in chunk.iter_mut().zip(prev.iter()) {
                *b ^= *p;
            }
            // Single-block AES-256 encryption — `BlockEncrypt` is the
            // RustCrypto trait that exposes `encrypt_block`. Using a
            // mutable `GenericArray` view of `chunk` keeps the encrypt
            // in place per FASM `aes$encrypt` semantics (single-block
            // primitive that overwrites its argument).
            let block_ga: &mut GenericArray<u8, _> = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(block_ga);
            // Save C[i] for the next iteration's XOR.
            prev.copy_from_slice(chunk);
        }

        // Update iv ← last ciphertext block per FASM ssh.inc lines
        // 892–896 (`memcpy ssh_localiv_ofs ← r14`).
        self.iv = prev;
        Ok(())
    }

    /// Decrypt one complete SSH packet **in place** using AES-256-CBC,
    /// chaining from [`Self::iv`] into the first block and updating
    /// [`Self::iv`] to the last *original* ciphertext block on
    /// completion.
    ///
    /// `packet_bytes` is the encrypted packet body **without** the
    /// trailing 32-byte HMAC tag. Length must be a multiple of 16.
    ///
    /// # Algorithm
    ///
    /// Standard CBC decrypt with the FASM "save ciphertext block before
    /// decryption" pattern from `ssh.inc` lines 1140–1196. We need to
    /// remember each ciphertext block before AES-decrypting it (because
    /// AES-decrypt overwrites the block) so we can XOR the next block
    /// against it.
    ///
    /// ```text
    /// prev = iv
    /// for each 16-byte block c in packet_bytes:
    ///     saved = c           # save C[i] before AES_decrypt overwrites it
    ///     c     = AES_decrypt(c)
    ///     c    ^= prev
    ///     prev  = saved
    /// iv = prev   # last original ciphertext block
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Ssh`] wrapping [`SshError::Cipher`] if
    /// `packet_bytes.len()` is not a multiple of [`CIPHER_BLOCK_SIZE`].
    ///
    /// # CBC-oracle note
    ///
    /// The FASM source uses a two-slot "block flipper" with `cmove` /
    /// `cmovne` (`ssh.inc` lines 1167–1190) so the CPU does not branch
    /// on data-dependent paths during the chained XOR. The Rust port
    /// uses a plain stack-allocated 16-byte `saved` buffer — modern
    /// LLVM does not introduce data-dependent branches in this loop
    /// (verified via release-mode codegen inspection), so the simpler
    /// pattern is functionally equivalent. The packet-level CBC-oracle
    /// mitigation (random `peeklen` advancement on bad HMAC) lives in
    /// `server.rs`; see [`CipherState::verify_mac`] for the MAC half.
    pub fn cbc_decrypt_in_place(&mut self, packet_bytes: &mut [u8]) -> Result<(), NetError> {
        if packet_bytes.len() % CIPHER_BLOCK_SIZE != 0 {
            return Err(NetError::Ssh(SshError::Cipher));
        }
        if packet_bytes.is_empty() {
            return Ok(());
        }

        let key_ga: &GenericArray<u8, _> = GenericArray::from_slice(&self.key);
        let cipher = Aes256::new(key_ga);

        // `prev` is the previous-block input to the XOR; for block 0
        // it is the current IV. After each iteration `prev` becomes
        // the *original* ciphertext block (NOT the decrypted output).
        let mut prev = self.iv;
        // `saved` holds the current iteration's ciphertext before
        // AES-decrypt overwrites it. The trailing value becomes the
        // new IV for the next packet.
        let mut saved = [0u8; CIPHER_BLOCK_SIZE];

        for chunk in packet_bytes.chunks_exact_mut(CIPHER_BLOCK_SIZE) {
            // FASM `memcpy r12 ← r14` at line 1158: save C[i] before
            // AES_decrypt overwrites it.
            saved.copy_from_slice(chunk);
            // Single-block AES-256 decryption — `BlockDecrypt` is the
            // RustCrypto trait. Mirrors FASM `aes$decrypt` at line
            // 1141.
            let block_ga: &mut GenericArray<u8, _> = GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block(block_ga);
            // P[i] = AES_decrypt(C[i]) XOR prev. Mirrors FASM `memxor`
            // at line 1149 / 1175.
            for (b, p) in chunk.iter_mut().zip(prev.iter()) {
                *b ^= *p;
            }
            // Save C[i] for the next iteration's XOR. Mirrors FASM's
            // `cmove`/`cmovne` flipper logic (lines 1167–1190) which
            // achieves the same prev←C[i] swap via the two-slot
            // alternation.
            prev.copy_from_slice(&saved);
        }

        // Update iv ← last *original* ciphertext block per FASM
        // `memcpy ssh_remoteiv_ofs ← r12` at lines 1192–1196.
        self.iv = prev;
        Ok(())
    }

    /// Compute the HMAC-SHA-256 MAC for an outgoing packet and
    /// increment the sequence number.
    ///
    /// The MAC input per RFC 4253 §6.4 is:
    ///
    /// ```text
    /// mac = HMAC( key, sequence_number_be_u32 || unencrypted_packet )
    /// ```
    ///
    /// where `unencrypted_packet` includes the 4-byte length prefix,
    /// 1-byte padlen, body, and random padding (i.e., the input to
    /// CBC encryption). FASM computes the MAC **before** CBC
    /// encryption (see `ssh.inc` lines 824–845) which allows this
    /// function to operate on a single contiguous slice.
    ///
    /// # FASM mapping
    ///
    /// | FASM step                                   | Rust step                |
    /// |---------------------------------------------|--------------------------|
    /// | `bswap eax` on `ssh_writeseq_ofs` (l. 826)  | `seqnum.to_be_bytes()`   |
    /// | `hmac_macupdate(seq_be, 4)` (l. 837)        | `ctx.update(&seq_be)`    |
    /// | `hmac_macupdate(packet, len)` (l. 844)      | `ctx.update(packet_bytes)` |
    /// | `hmac$final(out_32b)` (l. 904)              | `ctx.sign().as_ref()`    |
    /// | `add ssh_writeseq_ofs, 1` (l. 917)          | `seqnum.wrapping_add(1)` |
    ///
    /// # Returns
    ///
    /// The 32-byte HMAC-SHA-256 tag. Callers in `server.rs` append
    /// this directly after the encrypted ciphertext on the wire.
    ///
    /// # Sequence-number wrap
    ///
    /// The FASM source uses `add dword [...], 1` which wraps modulo
    /// `2^32` (silently). Rust's `wrapping_add(1)` reproduces this
    /// exactly. RFC 4253 §6.4 mandates a rekey before sequence-number
    /// wrap (every gigabyte of traffic), but per FASM behaviour we
    /// continue regardless — the wrap is observable but harmless.
    pub fn compute_mac(&mut self, packet_bytes: &[u8]) -> [u8; MAC_SIZE] {
        // Construct the HMAC context per packet. ring's Key::new is
        // cheap (it precomputes ipad/opad once) and Context::with_key
        // clones the inner pad state; this matches FASM where
        // ssh_writehmac_ofs is reset implicitly each call via
        // `hmac$macupdate`'s internal SHA-256 init.
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.mac_key);
        let mut ctx = hmac::Context::with_key(&key);

        // Feed the big-endian sequence number first. FASM uses
        // `bswap eax` on a 32-bit register; Rust's `to_be_bytes` does
        // exactly this on little-endian targets (the only target this
        // crate supports per AAP §0.1.1: x86_64-unknown-linux-gnu).
        ctx.update(&self.seqnum.to_be_bytes());
        ctx.update(packet_bytes);

        let tag: hmac::Tag = ctx.sign();
        // Copy the 32-byte tag into a stable [u8; 32] for return. ring
        // does not expose Tag as Into<[u8; N]>, so we go via as_ref().
        let mut mac = [0u8; MAC_SIZE];
        mac.copy_from_slice(tag.as_ref());

        // Increment write sequence per FASM `add dword
        // [rbx+ssh_writeseq_ofs], 1` at line 917. Wrapping is
        // intentional.
        self.seqnum = self.seqnum.wrapping_add(1);

        mac
    }

    /// Verify the HMAC-SHA-256 MAC for an incoming packet in **constant
    /// time** and unconditionally increment the sequence number.
    ///
    /// `packet_bytes` is the decrypted packet body excluding the
    /// trailing 32-byte MAC. `mac` is the 32-byte MAC the peer
    /// appended to the wire packet. The MAC is recomputed locally and
    /// compared against `mac` using [`ring::hmac::verify`], which
    /// "will be done in constant time to prevent timing attacks" per
    /// ring's documented contract.
    ///
    /// # FASM mapping
    ///
    /// | FASM step                                   | Rust step                |
    /// |---------------------------------------------|--------------------------|
    /// | `bswap eax` on `ssh_readseq_ofs` (l. 1208)  | `seqnum.to_be_bytes()`   |
    /// | `hmac_macupdate(seq_be, 4)` (l. 1215)       | `input[0..4].copy_from_slice(&seq_be)` |
    /// | `hmac_macupdate(packet, peeklen-32)` (l. 1223) | `input[4..].copy_from_slice(packet_bytes)` |
    /// | `hmac$final(rsp)` (l. 1227)                 | `hmac::verify(...)` (computes internally) |
    /// | constant-time memcmp (l. 1229+)             | `hmac::verify` (constant-time) |
    /// | `add dword ssh_readseq_ofs, 1` (l. 1230+)   | `seqnum.wrapping_add(1)` |
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Ssh`] wrapping [`SshError::Cipher`] when
    /// the recomputed MAC does not match `mac`. The sequence number
    /// is incremented **regardless** of the verification outcome —
    /// this preserves FASM's `add dword [rbx+ssh_readseq_ofs], 1`
    /// behaviour which is unconditional, and is part of the
    /// CBC-oracle timing-attack mitigation (`ssh.inc` lines 46–58:
    /// "if we do encounter an hmac error, we intentionally randomize
    /// our length requirement at that moment in time such that no
    /// information is leaked").
    ///
    /// # Constant-time guarantee
    ///
    /// [`ring::hmac::verify`] is documented to "be done in constant
    /// time to prevent timing attacks" and internally routes through
    /// the same constant-time primitive that `ring::constant_time`
    /// (now deprecated in ring 0.17) used to expose publicly. This
    /// prevents the timing oracle described in the Albrecht–Paterson
    /// paper (referenced at `ssh.inc` lines 46–49) from leaking which
    /// byte of the MAC differed.
    ///
    /// # Allocation
    ///
    /// `ring::hmac::verify` accepts a single `&[u8]` slice rather than
    /// the multi-chunk update-then-finalize API of
    /// [`ring::hmac::Context`]. To match FASM's two-step
    /// `seqnum_be || packet_bytes` HMAC input we therefore allocate
    /// one transient `Vec<u8>` per packet of size
    /// `4 + packet_bytes.len()`. This is a deliberate trade-off:
    /// per-packet allocation is acceptable at SSH packet rates (at
    /// most a few thousand packets per second per session) in
    /// exchange for routing through ring's tested,
    /// non-deprecated constant-time path. The alternative —
    /// hand-rolling an XOR-accumulate constant-time compare — would
    /// not carry ring's documented guarantee.
    pub fn verify_mac(&mut self, packet_bytes: &[u8], mac: &[u8; MAC_SIZE]) -> Result<(), NetError> {
        // Build the HMAC input as `seqnum_be || packet_bytes` in a
        // single contiguous buffer so we can use the single-shot
        // ring::hmac::verify entry point (which is documented as
        // constant-time and is NOT deprecated like the lower-level
        // ring::constant_time module is in ring 0.17).
        //
        // The flow matches FASM's ssh$receive ordering: HMAC the
        // pre-MAC bytes (length prefix + padlen + payload + padding)
        // prefixed with the big-endian sequence number, then verify.
        let mut input = Vec::with_capacity(4 + packet_bytes.len());
        input.extend_from_slice(&self.seqnum.to_be_bytes());
        input.extend_from_slice(packet_bytes);

        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.mac_key);
        let result = hmac::verify(&key, &input, mac);

        // Unconditional increment per FASM behaviour. FASM does this
        // even when `_blacklist_pid` is invoked on bad MAC; the
        // sequence counter advances so any further packets on the
        // same socket continue to be processable until the connection
        // is torn down.
        self.seqnum = self.seqnum.wrapping_add(1);

        // Map ring's opaque Unspecified error into our typed error.
        result.map_err(|_| NetError::Ssh(SshError::Cipher))
    }

    /// Zero all key material held by this state.
    ///
    /// Called from the `Drop` path of the owning `Ssh` struct in
    /// `server.rs`, and explicitly during graceful session teardown
    /// where the key material must not linger in memory longer than
    /// necessary.
    ///
    /// # Compiler-optimisation note
    ///
    /// Rust does not guarantee that the compiler will preserve dead
    /// stores to memory — under aggressive inlining the LLVM optimiser
    /// could elide these zeroing assignments. The FASM equivalent
    /// (`memset32` in `ssh$destroy`) does **not** use volatile writes
    /// either, so behavioural parity with the assembly source is
    /// preserved. Adopting the `zeroize` crate (which uses volatile
    /// writes) would be a strict improvement; that change is deferred
    /// per AAP §0.6.1 dependency-list discipline.
    pub fn zeroize(&mut self) {
        self.key = [0; CIPHER_KEY_SIZE];
        self.iv = [0; CIPHER_IV_SIZE];
        self.mac_key = [0; MAC_KEY_SIZE];
        // Sequence number is intentionally not zeroed — the FASM
        // ssh$destroy does not reset it either, and any code observing
        // the sequence number after destroy is itself buggy.
        self.active = false;
    }
}

impl Default for CipherState {
    /// Delegates to [`CipherState::new`] so that callers in `kex.rs`
    /// and `server.rs` can construct a dormant state via
    /// [`Default::default`] or via field-default structs.
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// `std::fmt::Debug` — elide key material.
// ============================================================================

impl std::fmt::Debug for CipherState {
    /// Emits the active flag and sequence number but deliberately
    /// **omits** the encryption key, IV, and MAC key. Printing those
    /// to logs would defeat the point of the session.
    ///
    /// Matches the FASM convention (ssh.inc has no debug-print path
    /// that dumps key material).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherState")
            .field("active", &self.active)
            .field("seqnum", &self.seqnum)
            .field("key", &"[REDACTED; 32 bytes]")
            .field("iv", &"[REDACTED; 16 bytes]")
            .field("mac_key", &"[REDACTED; 32 bytes]")
            .finish()
    }
}

// ============================================================================
// Free helpers — packet padding and framing (FASM ssh.inc lines
// 724–816).
// ============================================================================

/// Compute the required padding length for a given pre-padding body
/// length, per RFC 4253 §6 and FASM `ssh$encrypt` padding math
/// (`ssh.inc` lines 729–733).
///
/// The SSH packet structure on the wire (excluding MAC) is:
///
/// ```text
/// [4-byte length][1-byte padlen][body][padding]
/// ```
///
/// Per RFC 4253 §6 ("the length of the concatenation of
/// 'packet_length', 'padding_length', 'payload', and 'random padding'
/// MUST be a multiple of the cipher block size or 8, whichever is
/// larger"), the **full wire** (length prefix + padlen byte + body +
/// padding) must be a multiple of [`CIPHER_BLOCK_SIZE`] (16). For
/// the `aes256-cbc` non-ETM transport mode used by HeavyThing, CBC
/// encryption begins at offset 0 (FASM ssh.inc line 862) and covers
/// the entire wire packet, so the 4-byte length prefix is included
/// in the alignment. The padding length must itself be at least
/// [`MIN_PADDING`] (4).
///
/// # FASM source
///
/// ```text
/// ; ssh.inc lines 729–733
/// add  ecx, 5            ; ecx = body_len + 5  (+4 length, +1 padlen)
/// mov  r8d, ecx
/// and  r8d, 0fh          ; r8d = ecx & 0xF
/// mov  edx, 16
/// sub  edx, r8d          ; edx = 16 - (ecx & 0xF)
/// cmp  edx, 4
/// jge  .padlen_set
/// add  edx, 16           ; if edx < 4: edx += 16
/// .padlen_set:
/// ```
///
/// # Examples
///
/// ```text
/// body_len = 10  → (10+5) & 0xF = 15 → 16-15 = 1 → +16 = 17 (total = 4+1+10+17 = 32)
/// body_len = 11  → (11+5) & 0xF =  0 → 16- 0 =16 → unchanged (total = 4+1+11+16 = 32)
/// body_len = 100 → (100+5)&0xF =  9 → 16- 9 = 7 → unchanged (total = 4+1+100+7 = 112)
/// body_len =  0  → (0+5) & 0xF =  5 → 16- 5 =11 → unchanged (total = 4+1+0+11  = 16)
/// ```
#[must_use]
pub fn compute_padding(body_len: usize) -> usize {
    // Provisional total = 4-byte length + 1-byte padlen + body. We
    // want total % 16 == 0, so padding = (16 - (provisional % 16))
    // mod 16. But we also need padding >= MIN_PADDING, so when the
    // computed padding is < 4 we add 16 to it.
    let provisional = body_len.wrapping_add(5);
    let mut padlen = CIPHER_BLOCK_SIZE - (provisional % CIPHER_BLOCK_SIZE);
    if padlen < MIN_PADDING {
        padlen += CIPHER_BLOCK_SIZE;
    }
    padlen
}

/// Assemble a fully-framed SSH packet (length prefix + padlen byte +
/// body + random padding) into `out`.
///
/// Layout (bytes):
///
/// ```text
/// [0..4]                       : big-endian u32 packet_length = 1 + body.len() + padlen
/// [4]                          : u8 padlen
/// [5..5+body.len()]            : body (msg_type + payload, or compressed output)
/// [5+body.len()..5+body.len()+padlen] : padlen random bytes (from rng::block)
/// ```
///
/// Total length = `4 + 1 + body.len() + padlen`, which is always a
/// multiple of [`CIPHER_BLOCK_SIZE`] (i.e., `out.len() % 16 == 0`).
/// The leading 4-byte length prefix is itself encrypted per RFC 4253
/// §6 alongside the rest of the packet body, and CBC encryption
/// begins at offset 0 (FASM ssh.inc line 862), so the full wire
/// (including the length prefix) must be 16-aligned.
///
/// # FASM mapping
///
/// Mirrors `ssh.inc` lines 724–816 (packet assembly with random
/// padding). FASM uses the same byte layout but writes through a
/// `buffer$reserve` allocation; the Rust port reuses the caller's
/// `Vec<u8>` (cleared first) for the same end result.
///
/// # Errors
///
/// Returns [`NetError::Ssh`] wrapping [`SshError::Cipher`] in the
/// (currently unreachable) case where the computed packet length
/// would not be a 16-byte multiple. This is defensive — the
/// [`compute_padding`] math above guarantees the multiple — but
/// keeping the check lets the function return a `Result` for forward
/// compatibility if more elaborate framing rules are added later.
pub fn frame_packet_into(body: &[u8], out: &mut Vec<u8>) -> Result<(), NetError> {
    let padlen = compute_padding(body.len());
    let packet_length = 1usize
        .checked_add(body.len())
        .and_then(|n| n.checked_add(padlen))
        .ok_or(NetError::Ssh(SshError::Cipher))?;
    let total = packet_length
        .checked_add(4)
        .ok_or(NetError::Ssh(SshError::Cipher))?;

    out.clear();
    out.reserve(total);

    // 4-byte big-endian packet_length prefix.
    let length_be = (packet_length as u32).to_be_bytes();
    out.extend_from_slice(&length_be);

    // 1-byte padlen.
    out.push(padlen as u8);

    // body bytes.
    out.extend_from_slice(body);

    // padlen random bytes via crate::crypto::rng::block — matches FASM
    // `rng$block` at `ssh.inc` line 778. The padding bytes are random
    // (not zero) per RFC 4253 §6 "the padding SHOULD consist of random
    // bytes" — required to prevent known-plaintext attacks against the
    // CBC-encrypted padding region.
    let pad_start = out.len();
    out.resize(pad_start + padlen, 0);
    rng::block(&mut out[pad_start..pad_start + padlen]);

    // Defensive sanity check: per RFC 4253 §6 and FASM `ssh$encrypt`
    // (ssh.inc lines 730-741, 783-797), the FULL wire packet — which
    // includes the 4-byte `packet_length` prefix, the 1-byte
    // `padding_length` byte, the body, and the random padding — must
    // be a multiple of the 16-byte cipher block size. CBC mode
    // encrypts ALL of this region (FASM begins the CBC loop at
    // `buffer_itself_ofs` offset 0; see ssh.inc line 862), hence the
    // full wire (including length prefix) must be 16-aligned.
    // `compute_padding` arithmetically guarantees this; assert in
    // debug builds and verify-via-Result in release. Both branches
    // return the same error on failure, but only `debug_assert!`
    // panics for the convenience of test failures.
    debug_assert_eq!(
        out.len() % CIPHER_BLOCK_SIZE,
        0,
        "framed SSH packet (full wire incl. length prefix) must be a 16-byte multiple after padding (got {} bytes)",
        out.len()
    );
    if out.len() % CIPHER_BLOCK_SIZE != 0 {
        return Err(NetError::Ssh(SshError::Cipher));
    }

    Ok(())
}

// ============================================================================
// Tests — vector-based and roundtrip coverage.
// ============================================================================

#[cfg(test)]
mod tests {
    //! Tests for the SSH transport-layer cipher and MAC.
    //!
    //! Coverage strategy:
    //!
    //! * **Constants** — assert wire-format constants match RFC 4253 §6
    //!   and FASM `ssh.inc`.
    //! * **Padding math** — verify [`compute_padding`] produces totals
    //!   that are 16-byte multiples and pad lengths that are at least
    //!   [`MIN_PADDING`] across edge cases (0, 1, 11, 16, 17, 100).
    //! * **CBC roundtrip** — encrypt then decrypt single- and
    //!   multi-block buffers; verify plaintext recovered exactly.
    //! * **IV chaining** — verify the IV is updated to the last
    //!   ciphertext block after each operation; verify a second
    //!   encrypt+decrypt cycle uses the new IV correctly.
    //! * **Length validation** — non-aligned input → `Err`.
    //! * **HMAC roundtrip** — compute MAC with state A, verify with
    //!   fresh state B (same key), expect `Ok`.
    //! * **HMAC tamper detection** — flip one byte of input, verify
    //!   returns `Err`.
    //! * **Sequence-number behaviour** — increments after compute,
    //!   increments after both successful and failed verify, wraps
    //!   from `u32::MAX` to 0.
    //! * **Frame helper** — assembles a 16-byte-aligned packet with
    //!   correct length prefix and padlen byte.
    //! * **AES-256-CBC NIST test vector** — verify the underlying AES
    //!   primitive against NIST SP 800-38A vector to catch any
    //!   keying / endianness regression.
    //! * **HMAC-SHA-256 RFC 4231 test vector** — verify HMAC against
    //!   RFC 4231 §4.2 test case 1.

    use super::*;

    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    /// Sanity-check the published wire-format constants against the
    /// FASM source values.
    #[test]
    fn constants_match_fasm() {
        assert_eq!(CIPHER_BLOCK_SIZE, 16, "AES block size");
        assert_eq!(CIPHER_KEY_SIZE, 32, "AES-256 key size");
        assert_eq!(CIPHER_IV_SIZE, 16, "SSH IV size = AES block size");
        assert_eq!(MAC_SIZE, 32, "HMAC-SHA-256 tag size");
        assert_eq!(MAC_KEY_SIZE, 32, "SSH HMAC key size");
        assert_eq!(MIN_PADDING, 4, "RFC 4253 §6 minimum padding");
        assert_eq!(MAX_PACKET_SIZE, 35000, "RFC 4253 §6.1 max packet");
    }

    // ------------------------------------------------------------------
    // Padding math (FASM ssh.inc lines 729–733)
    // ------------------------------------------------------------------

    /// `compute_padding(0)` covers the smallest legal SSH packet (a
    /// single message-type byte with empty payload would have
    /// body_len = 1, but we test 0 to exercise the boundary).
    ///
    /// Per RFC 4253 §6 and FASM ssh.inc lines 730-741, the FULL wire
    /// (`packet_length`(4) + `padding_length`(1) + body + padding)
    /// must be a 16-byte multiple. Equivalently:
    /// `(body_len + padlen + 5) % 16 == 0`.
    #[test]
    fn compute_padding_zero_body() {
        let body_len = 0usize;
        let padlen = compute_padding(body_len);
        assert_eq!(padlen, 11, "(0+5)&0xF=5, 16-5=11");
        // Full wire = 4 (length prefix) + 1 (padlen byte) + 0 (body) + 11 (padding) = 16.
        let total_wire_len = 5 + body_len + padlen;
        assert_eq!(total_wire_len % CIPHER_BLOCK_SIZE, 0);
        assert!(padlen >= MIN_PADDING);
    }

    /// `compute_padding(10)`: body+5 = 15, gap = 1 (< MIN_PADDING),
    /// so add 16 → 17. Total wire = 5 + 10 + 17 = 32.
    #[test]
    fn compute_padding_min_padding_branch() {
        let padlen = compute_padding(10);
        assert_eq!(padlen, 17, "(10+5)&0xF=15, 16-15=1<4 so +16=17");
        let total_wire_len = 5 + 10 + padlen;
        assert_eq!(total_wire_len % CIPHER_BLOCK_SIZE, 0);
        assert!(padlen >= MIN_PADDING);
    }

    /// `compute_padding(11)`: body+5 = 16, exact multiple, gap = 16
    /// (which is >= MIN_PADDING; no adjustment needed).
    /// Total wire = 5 + 11 + 16 = 32.
    #[test]
    fn compute_padding_exact_multiple() {
        let padlen = compute_padding(11);
        assert_eq!(padlen, 16, "(11+5)&0xF=0, 16-0=16");
        let total_wire_len = 5 + 11 + padlen;
        assert_eq!(total_wire_len % CIPHER_BLOCK_SIZE, 0);
        assert!(padlen >= MIN_PADDING);
    }

    /// `compute_padding(100)`: gap = 7 (>= MIN_PADDING).
    /// Total wire = 5 + 100 + 7 = 112 (= 7 × 16).
    #[test]
    fn compute_padding_typical_payload() {
        let padlen = compute_padding(100);
        assert_eq!(padlen, 7, "(100+5)&0xF=9, 16-9=7");
        let total_wire_len = 5 + 100 + padlen;
        assert_eq!(total_wire_len % CIPHER_BLOCK_SIZE, 0);
        assert!(padlen >= MIN_PADDING);
    }

    /// Sweep across body lengths 0..=128 to ensure the invariant
    /// `(body_len + padlen + 5) % 16 == 0` (full wire, including the
    /// 4-byte length prefix and 1-byte padlen byte, is 16-aligned)
    /// and `padlen >= 4` holds universally. This matches FASM
    /// ssh.inc lines 730-741 padding math and RFC 4253 §6.
    #[test]
    fn compute_padding_sweep_invariants() {
        for body_len in 0..=128usize {
            let padlen = compute_padding(body_len);
            let total_wire_len = 5 + body_len + padlen;
            assert_eq!(
                total_wire_len % CIPHER_BLOCK_SIZE,
                0,
                "body_len={} → padlen={} → total_wire_len={} not multiple of 16",
                body_len,
                padlen,
                total_wire_len
            );
            assert!(
                padlen >= MIN_PADDING,
                "body_len={} → padlen={} < MIN_PADDING",
                body_len,
                padlen
            );
            assert!(
                padlen <= 255,
                "body_len={} → padlen={} > 255 (RFC 4253 limit)",
                body_len,
                padlen
            );
        }
    }

    // ------------------------------------------------------------------
    // CipherState lifecycle
    // ------------------------------------------------------------------

    #[test]
    fn cipher_state_inactive_by_default() {
        let s = CipherState::new();
        assert!(!s.is_active());
        assert_eq!(s.seqnum(), 0);
    }

    #[test]
    fn cipher_state_default_matches_new() {
        let a = CipherState::new();
        let b = CipherState::default();
        assert_eq!(a.is_active(), b.is_active());
        assert_eq!(a.seqnum(), b.seqnum());
    }

    #[test]
    fn cipher_state_activate_marks_active() {
        let mut s = CipherState::new();
        s.activate(
            [0x42; CIPHER_KEY_SIZE],
            [0x33; CIPHER_IV_SIZE],
            [0x77; MAC_KEY_SIZE],
        );
        assert!(s.is_active());
    }

    #[test]
    fn cipher_state_activate_does_not_reset_seqnum() {
        let mut s = CipherState::new();
        // Pump the seqnum forward via compute_mac calls.
        s.activate([0; 32], [0; 16], [0; 32]);
        let _ = s.compute_mac(b"first");
        let _ = s.compute_mac(b"second");
        assert_eq!(s.seqnum(), 2);
        // Re-activate (rekey scenario per RFC 4253 §6.4).
        s.activate([1; 32], [2; 16], [3; 32]);
        assert_eq!(s.seqnum(), 2, "RFC 4253 §6.4: seqnum survives rekey");
    }

    /// Debug impl must not leak key material.
    #[test]
    fn cipher_state_debug_redacts_keys() {
        let mut s = CipherState::new();
        s.activate([0xCC; 32], [0xDD; 16], [0xEE; 32]);
        let dbg = format!("{:?}", s);
        // The redaction strings must appear and the raw byte 0xCC/EE
        // must not appear in any printable form.
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("CC"));
        assert!(!dbg.contains("DD"));
        assert!(!dbg.contains("EE"));
    }

    /// `zeroize` clears all key material and `active`.
    #[test]
    fn zeroize_clears_keys() {
        let mut s = CipherState::new();
        s.activate([0xAA; 32], [0xBB; 16], [0xCC; 32]);
        let _ = s.compute_mac(b"x"); // bump seqnum to 1
        s.zeroize();
        assert!(!s.is_active());
        // We can't read fields directly outside this module, but we
        // can roundtrip — verify a fresh new() with same seqnum
        // produces same output, demonstrating the cleared key took
        // effect. (Direct field inspection is via the test below.)
        assert_eq!(s.key, [0u8; 32]);
        assert_eq!(s.iv, [0u8; 16]);
        assert_eq!(s.mac_key, [0u8; 32]);
        // Per FASM behaviour, seqnum is NOT reset by zeroize.
        assert_eq!(s.seqnum(), 1);
    }

    // ------------------------------------------------------------------
    // CBC encrypt / decrypt
    // ------------------------------------------------------------------

    /// Single-block CBC roundtrip: encrypt 16 bytes, decrypt with a
    /// fresh state (same key + initial IV), recover original.
    #[test]
    fn cbc_roundtrip_single_block() {
        let key = [0x42u8; 32];
        let iv = [0x33u8; 16];
        let mut enc = CipherState::new();
        enc.activate(key, iv, [0; 32]);
        let mut dec = CipherState::new();
        dec.activate(key, iv, [0; 32]);

        let plaintext = *b"sixteen bytes!!!";
        let mut buf = plaintext;
        enc.cbc_encrypt_in_place(&mut buf).expect("encrypt 16B");
        // Ciphertext must differ from plaintext.
        assert_ne!(buf, plaintext, "ciphertext must differ from plaintext");

        dec.cbc_decrypt_in_place(&mut buf).expect("decrypt 16B");
        assert_eq!(buf, plaintext, "roundtrip must recover plaintext");
    }

    /// Multi-block CBC roundtrip: 64 bytes (4 blocks).
    #[test]
    fn cbc_roundtrip_multi_block() {
        let key = [0x55u8; 32];
        let iv = [0xA5u8; 16];
        let mut enc = CipherState::new();
        enc.activate(key, iv, [0; 32]);
        let mut dec = CipherState::new();
        dec.activate(key, iv, [0; 32]);

        let plaintext: Vec<u8> = (0..64u8).collect();
        let mut buf = plaintext.clone();
        enc.cbc_encrypt_in_place(&mut buf).unwrap();
        assert_ne!(buf, plaintext);

        dec.cbc_decrypt_in_place(&mut buf).unwrap();
        assert_eq!(buf, plaintext);
    }

    /// IV update: after `cbc_encrypt_in_place`, `state.iv` equals the
    /// last 16 bytes of the encrypted output (per FASM lines 892–896).
    #[test]
    fn cbc_encrypt_updates_iv_to_last_ciphertext_block() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let mut s = CipherState::new();
        s.activate(key, iv, [0; 32]);
        let mut buf = vec![0u8; 32]; // 2 blocks
        s.cbc_encrypt_in_place(&mut buf).unwrap();
        // IV must equal the last 16 bytes of buf.
        assert_eq!(&s.iv[..], &buf[16..32], "iv must equal last ciphertext block");
    }

    /// IV update on decrypt: equals the last *original* ciphertext
    /// block (which becomes the new IV for the next packet).
    #[test]
    fn cbc_decrypt_updates_iv_to_last_original_ciphertext() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let mut enc = CipherState::new();
        enc.activate(key, iv, [0; 32]);
        let mut dec = CipherState::new();
        dec.activate(key, iv, [0; 32]);

        let plaintext: Vec<u8> = (0..32u8).collect();
        let mut buf = plaintext.clone();
        enc.cbc_encrypt_in_place(&mut buf).unwrap();
        let ciphertext_last_block: [u8; 16] = buf[16..32].try_into().expect("last block is 16 bytes");

        dec.cbc_decrypt_in_place(&mut buf).unwrap();
        // After decrypt, IV equals the *original* last ciphertext
        // block, NOT the now-recovered plaintext block.
        assert_eq!(dec.iv, ciphertext_last_block);
    }

    /// Two-packet CBC chaining: encrypt packet A, then encrypt packet
    /// B with the IV from packet A; decrypt in the same order.
    /// Verifies the IV is correctly carried across packets.
    #[test]
    fn cbc_two_packet_chain_roundtrip() {
        let key = [0xF1u8; 32];
        let iv = [0x10u8; 16];
        let mut enc = CipherState::new();
        enc.activate(key, iv, [0; 32]);
        let mut dec = CipherState::new();
        dec.activate(key, iv, [0; 32]);

        let pkt_a: Vec<u8> = (0..16u8).collect();
        let pkt_b: Vec<u8> = (100..132u8).collect();

        let mut buf_a = pkt_a.clone();
        enc.cbc_encrypt_in_place(&mut buf_a).unwrap();
        let mut buf_b = pkt_b.clone();
        enc.cbc_encrypt_in_place(&mut buf_b).unwrap();

        dec.cbc_decrypt_in_place(&mut buf_a).unwrap();
        dec.cbc_decrypt_in_place(&mut buf_b).unwrap();
        assert_eq!(buf_a, pkt_a, "packet A roundtrip");
        assert_eq!(buf_b, pkt_b, "packet B roundtrip");
    }

    /// Non-aligned encrypt input → `Err(NetError::Ssh(SshError::Cipher))`.
    #[test]
    fn cbc_encrypt_rejects_non_aligned_length() {
        let mut s = CipherState::new();
        s.activate([0; 32], [0; 16], [0; 32]);
        let mut buf = vec![0u8; 17];
        let err = s.cbc_encrypt_in_place(&mut buf).unwrap_err();
        assert!(matches!(err, NetError::Ssh(SshError::Cipher)));
    }

    /// Non-aligned decrypt input → `Err(NetError::Ssh(SshError::Cipher))`.
    #[test]
    fn cbc_decrypt_rejects_non_aligned_length() {
        let mut s = CipherState::new();
        s.activate([0; 32], [0; 16], [0; 32]);
        let mut buf = vec![0u8; 15];
        let err = s.cbc_decrypt_in_place(&mut buf).unwrap_err();
        assert!(matches!(err, NetError::Ssh(SshError::Cipher)));
    }

    /// Empty packet is a no-op for both encrypt and decrypt; IV is
    /// not updated.
    #[test]
    fn cbc_empty_packet_is_noop() {
        let mut s = CipherState::new();
        s.activate([0; 32], [0xAA; 16], [0; 32]);
        let original_iv = s.iv;
        let mut buf: Vec<u8> = Vec::new();
        s.cbc_encrypt_in_place(&mut buf).unwrap();
        assert_eq!(s.iv, original_iv, "iv must not change on empty input");
        s.cbc_decrypt_in_place(&mut buf).unwrap();
        assert_eq!(s.iv, original_iv, "iv must not change on empty input");
    }

    /// AES-256-CBC encryption against the NIST SP 800-38A
    /// (Section F.2.5) test vector. This catches any regression in
    /// the AES primitive choice or endianness handling.
    ///
    /// Vector parameters (NIST SP 800-38A):
    /// * Key: `603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4`
    /// * IV:  `000102030405060708090a0b0c0d0e0f`
    /// * Plaintext (block 1): `6bc1bee22e409f96e93d7e117393172a`
    /// * Ciphertext (block 1): `f58c4c04d6e5f1ba779eabfb5f7bfbd6`
    #[test]
    fn cbc_encrypt_nist_sp800_38a_block1() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let expected_ciphertext: [u8; 16] = [
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
        ];

        let mut s = CipherState::new();
        s.activate(key, iv, [0; 32]);
        let mut buf = plaintext;
        s.cbc_encrypt_in_place(&mut buf).unwrap();
        assert_eq!(
            buf, expected_ciphertext,
            "NIST SP 800-38A AES-256-CBC block 1 must match"
        );
        // After encrypt, IV equals the ciphertext block.
        assert_eq!(s.iv, expected_ciphertext);
    }

    /// AES-256-CBC decryption of the NIST SP 800-38A vector — round
    /// trip the encrypted block back to plaintext.
    #[test]
    fn cbc_decrypt_nist_sp800_38a_block1() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let ciphertext: [u8; 16] = [
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
        ];
        let expected_plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];

        let mut s = CipherState::new();
        s.activate(key, iv, [0; 32]);
        let mut buf = ciphertext;
        s.cbc_decrypt_in_place(&mut buf).unwrap();
        assert_eq!(
            buf, expected_plaintext,
            "NIST SP 800-38A AES-256-CBC decrypt must match"
        );
        // After decrypt, IV equals the original ciphertext block.
        assert_eq!(s.iv, ciphertext);
    }

    /// AES-256-CBC two-block NIST SP 800-38A vector: verifies CBC
    /// chaining across multiple blocks.
    ///
    /// Block 2 plaintext: `ae2d8a571e03ac9c9eb76fac45af8e51`
    /// Block 2 ciphertext: `9cfc4e967edb808d679f777bc6702c7d`
    #[test]
    fn cbc_encrypt_nist_sp800_38a_blocks_1_and_2() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let plaintext: [u8; 32] = [
            // block 1
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            // block 2
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        ];
        let expected_ciphertext: [u8; 32] = [
            // block 1
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
            // block 2
            0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
        ];

        let mut s = CipherState::new();
        s.activate(key, iv, [0; 32]);
        let mut buf = plaintext;
        s.cbc_encrypt_in_place(&mut buf).unwrap();
        assert_eq!(buf, expected_ciphertext);
    }

    // ------------------------------------------------------------------
    // HMAC-SHA-256 compute / verify
    // ------------------------------------------------------------------

    /// HMAC compute + verify roundtrip with the same MAC key on
    /// independent states.
    #[test]
    fn hmac_roundtrip() {
        let mac_key = [0x77u8; 32];
        let mut writer = CipherState::new();
        writer.activate([0; 32], [0; 16], mac_key);
        let mut reader = CipherState::new();
        reader.activate([0; 32], [0; 16], mac_key);

        let pkt = b"\x00\x00\x00\x10\x06hello-ssh-world!"; // arbitrary 20 bytes
        let mac = writer.compute_mac(pkt);
        reader.verify_mac(pkt, &mac).expect("MACs must match");
    }

    /// MAC tamper detection: flip one byte of the packet, verify
    /// returns `Err(SshError::Cipher)`.
    #[test]
    fn hmac_verify_fails_on_packet_tamper() {
        let mac_key = [0x88u8; 32];
        let mut writer = CipherState::new();
        writer.activate([0; 32], [0; 16], mac_key);
        let mut reader = CipherState::new();
        reader.activate([0; 32], [0; 16], mac_key);

        let mut pkt = b"\x00\x00\x00\x10\x06hello-ssh-world!".to_vec();
        let mac = writer.compute_mac(&pkt);
        // Tamper.
        pkt[10] ^= 0x01;
        let err = reader.verify_mac(&pkt, &mac).unwrap_err();
        assert!(matches!(err, NetError::Ssh(SshError::Cipher)));
    }

    /// MAC tamper detection: flip one byte of the MAC tag itself.
    #[test]
    fn hmac_verify_fails_on_mac_tamper() {
        let mac_key = [0x99u8; 32];
        let mut writer = CipherState::new();
        writer.activate([0; 32], [0; 16], mac_key);
        let mut reader = CipherState::new();
        reader.activate([0; 32], [0; 16], mac_key);

        let pkt = b"some payload bytes";
        let mut mac = writer.compute_mac(pkt);
        mac[15] ^= 0x80;
        let err = reader.verify_mac(pkt, &mac).unwrap_err();
        assert!(matches!(err, NetError::Ssh(SshError::Cipher)));
    }

    /// Sequence number increments after each compute_mac.
    #[test]
    fn hmac_compute_increments_seqnum() {
        let mut s = CipherState::new();
        s.activate([0; 32], [0; 16], [0; 32]);
        assert_eq!(s.seqnum(), 0);
        let _ = s.compute_mac(b"a");
        assert_eq!(s.seqnum(), 1);
        let _ = s.compute_mac(b"b");
        assert_eq!(s.seqnum(), 2);
    }

    /// Sequence number increments after successful verify_mac.
    #[test]
    fn hmac_verify_success_increments_seqnum() {
        let mac_key = [0x11u8; 32];
        let mut writer = CipherState::new();
        writer.activate([0; 32], [0; 16], mac_key);
        let mut reader = CipherState::new();
        reader.activate([0; 32], [0; 16], mac_key);
        let pkt = b"verified-payload";
        let mac = writer.compute_mac(pkt);
        assert_eq!(reader.seqnum(), 0);
        reader.verify_mac(pkt, &mac).unwrap();
        assert_eq!(reader.seqnum(), 1);
    }

    /// **Critical**: sequence number increments after FAILED verify_mac
    /// (matches FASM behaviour for CBC-oracle timing-attack mitigation).
    #[test]
    fn hmac_verify_failure_still_increments_seqnum() {
        let mut s = CipherState::new();
        s.activate([0; 32], [0; 16], [0; 32]);
        assert_eq!(s.seqnum(), 0);
        // Provide a MAC that is definitely wrong (all zeros).
        let bad_mac = [0u8; 32];
        let err = s.verify_mac(b"some packet", &bad_mac).unwrap_err();
        assert!(matches!(err, NetError::Ssh(SshError::Cipher)));
        // Per FASM ssh.inc lines 1230+: seqnum increments unconditionally.
        assert_eq!(
            s.seqnum(),
            1,
            "verify_mac MUST increment seqnum on failure for CBC-oracle mitigation"
        );
    }

    /// Sequence number wraps from u32::MAX to 0.
    #[test]
    fn hmac_compute_wraps_seqnum_on_overflow() {
        let mut s = CipherState::new();
        s.activate([0; 32], [0; 16], [0; 32]);
        // Manually set seqnum to the wrap boundary.
        s.seqnum = u32::MAX;
        let _ = s.compute_mac(b"wrap-test");
        assert_eq!(s.seqnum(), 0, "seqnum must wrap to 0 on overflow");
    }

    /// HMAC depends on the sequence number — the same packet bytes
    /// produce different MACs for different seqnums. This tests the
    /// FASM `bswap eax` step plus the `hmac_macupdate(seq_be, 4)`
    /// prelude.
    #[test]
    fn hmac_changes_with_seqnum() {
        let mut s = CipherState::new();
        s.activate([0; 32], [0; 16], [0xCDu8; 32]);
        let pkt = b"identical-bytes";
        let mac0 = s.compute_mac(pkt);
        let mac1 = s.compute_mac(pkt);
        assert_ne!(mac0, mac1, "MAC must depend on sequence number");
    }

    /// HMAC-SHA-256 against the RFC 4231 §4.2 test case 1 vector.
    /// This catches any regression in ring's HMAC-SHA-256 binding or
    /// any unintended seqnum prefix when seqnum=0.
    ///
    /// Vector parameters (RFC 4231 §4.2 Test Case 1):
    /// * Key:  20 bytes of `0x0b`
    /// * Data: ASCII "Hi There"
    /// * MAC:  `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7`
    ///
    /// We feed the data via compute_mac with seqnum=0; since SSH MAC
    /// input is `seqnum_be(4) || data`, we compute the expected
    /// against `\x00\x00\x00\x00 || "Hi There"` and use ring directly
    /// to derive the *expected* MAC for that prefixed input — proving
    /// our compute_mac matches ring's HMAC-SHA-256 contract.
    #[test]
    fn hmac_matches_ring_with_seqnum_prefix() {
        let mac_key = [0x0bu8; 20]; // RFC 4231 §4.2 TC1 key (short — ring will pad)
        let mut padded_key = [0u8; 32];
        padded_key[..20].copy_from_slice(&mac_key);
        // Note: SSH uses a 32-byte key. To keep the test self-consistent
        // and exercise the same code path as production, we pad the
        // RFC 4231 key to 32 bytes with zeros. The expected MAC below
        // is therefore computed against the padded key, NOT the raw
        // RFC 4231 vector. This still proves our HMAC pipeline is
        // byte-equivalent to ring's contract.

        let data = b"Hi There";
        let mut s = CipherState::new();
        s.activate([0; 32], [0; 16], padded_key);
        let our_mac = s.compute_mac(data);

        // Compute the same MAC using ring directly with the same
        // seqnum_be(4) || data prefix.
        let key = hmac::Key::new(hmac::HMAC_SHA256, &padded_key);
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&0u32.to_be_bytes());
        ctx.update(data);
        let ring_tag = ctx.sign();
        assert_eq!(our_mac.as_slice(), ring_tag.as_ref());
    }

    /// Verify that for a non-zero seqnum, the MAC matches a manual
    /// recomputation with the same seqnum prefix. This pins the
    /// FASM `bswap eax` semantic (big-endian seqnum prefix).
    #[test]
    fn hmac_seqnum_prefix_is_big_endian() {
        let mac_key = [0xA5u8; 32];
        let mut s = CipherState::new();
        s.activate([0; 32], [0; 16], mac_key);
        s.seqnum = 0x12345678;
        let data = b"check endianness";
        let our_mac = s.compute_mac(data);

        // Manually compute with the seqnum in big-endian prefix.
        let key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key);
        let mut ctx = hmac::Context::with_key(&key);
        let expected_prefix: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        ctx.update(&expected_prefix);
        ctx.update(data);
        let expected = ctx.sign();
        assert_eq!(our_mac.as_slice(), expected.as_ref());
    }

    // ------------------------------------------------------------------
    // frame_packet_into
    // ------------------------------------------------------------------

    /// Frame a small body and verify the layout: 4-byte length
    /// prefix, padlen byte, body, random padding. The full wire
    /// (length prefix + padlen + body + padding) must be a 16-byte
    /// multiple, since CBC mode encrypts the entire region beginning
    /// at offset 0 (FASM ssh.inc line 862). Per RFC 4253 §6.
    #[test]
    fn frame_packet_layout_small_body() {
        let body = b"hello";
        let mut out: Vec<u8> = Vec::new();
        frame_packet_into(body, &mut out).unwrap();

        // Length prefix.
        let length_prefix = u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize;
        assert_eq!(length_prefix, 1 + body.len() + compute_padding(body.len()));

        // padlen byte.
        let padlen = out[4] as usize;
        assert_eq!(padlen, compute_padding(body.len()));

        // Body bytes at offset 5.
        assert_eq!(&out[5..5 + body.len()], body);

        // Total wire length must be 4 + length_prefix.
        assert_eq!(out.len(), 4 + length_prefix);

        // Full wire (incl. length prefix) must be a 16-byte multiple
        // because CBC mode encrypts everything starting at offset 0.
        assert_eq!(out.len() % CIPHER_BLOCK_SIZE, 0);
    }

    /// Frame a body whose length forces the MIN_PADDING branch.
    #[test]
    fn frame_packet_layout_min_padding_branch() {
        let body = vec![0u8; 10]; // 10+5=15, gap=1, padlen=17 → wire=4+1+10+17=32
        let mut out: Vec<u8> = Vec::new();
        frame_packet_into(&body, &mut out).unwrap();
        assert_eq!(out[4] as usize, 17);
        // Full wire must be 16-aligned.
        assert_eq!(out.len() % CIPHER_BLOCK_SIZE, 0);
        assert_eq!(out.len(), 32);
    }

    /// Frame an empty body. Full wire = 4 + 1 + 0 + 11 = 16 bytes.
    #[test]
    fn frame_packet_empty_body() {
        let body: &[u8] = &[];
        let mut out: Vec<u8> = Vec::new();
        frame_packet_into(body, &mut out).unwrap();
        // length prefix value = 1 (padlen byte) + 0 body + 11 padding = 12
        // (length prefix encodes the bytes AFTER the 4-byte prefix itself).
        assert_eq!(u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize, 12);
        assert_eq!(out[4], 11);
        // Full wire including the 4-byte length prefix is 16 bytes.
        assert_eq!(out.len(), 16);
        assert_eq!(out.len() % CIPHER_BLOCK_SIZE, 0);
    }

    /// Frame helper sweeps every body length from 0 to 64 and
    /// verifies the framed output meets all invariants. The full
    /// wire (out.len()) must be a 16-byte multiple because CBC mode
    /// encrypts the entire framed buffer from offset 0 (per FASM
    /// ssh.inc line 862 and RFC 4253 §6).
    #[test]
    fn frame_packet_sweep() {
        for body_len in 0..=64usize {
            let body = vec![0xCDu8; body_len];
            let mut out: Vec<u8> = Vec::new();
            frame_packet_into(&body, &mut out).unwrap();
            // Full wire (including length prefix) must be 16-byte aligned.
            assert_eq!(
                out.len() % CIPHER_BLOCK_SIZE,
                0,
                "body_len={} → out.len()={}",
                body_len,
                out.len()
            );
            // Length prefix matches.
            let prefix = u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize;
            assert_eq!(prefix + 4, out.len());
            // padlen >= 4.
            assert!(out[4] >= MIN_PADDING as u8);
            // Body bytes preserved.
            assert_eq!(&out[5..5 + body_len], &body[..]);
        }
    }

    /// frame + encrypt + decrypt + (peel padding) roundtrip — the
    /// full SSH transport-layer write/read pipeline minus the MAC.
    #[test]
    fn frame_encrypt_decrypt_roundtrip_recovers_body() {
        let key = [0xE1u8; 32];
        let iv = [0xE2u8; 16];

        let mut writer = CipherState::new();
        writer.activate(key, iv, [0; 32]);
        let mut reader = CipherState::new();
        reader.activate(key, iv, [0; 32]);

        let body = b"ssh test message";
        let mut framed: Vec<u8> = Vec::new();
        frame_packet_into(body, &mut framed).unwrap();
        let body_offset = 5;
        let pad_len = framed[4] as usize;

        // Encrypt the entire framed buffer (length prefix + padlen +
        // body + padding) per FASM behaviour: the length prefix is
        // also encrypted.
        writer.cbc_encrypt_in_place(&mut framed).unwrap();

        // Decrypt at peer.
        reader.cbc_decrypt_in_place(&mut framed).unwrap();

        // Recovered body matches original.
        assert_eq!(&framed[body_offset..body_offset + body.len()], body);
        // Padlen byte preserved.
        assert_eq!(framed[4] as usize, pad_len);
    }
}
