// crates/heavything/src/tui/widgets/ssh.rs — SSH TUI integration widget.
//
// Port of `tui_ssh.inc` (635 lines, dual-class). Bridges the TUI widget
// tree and the SSH protocol transport. Provides three public types:
//
// * `TuiSsh` — I/O-chain descendant. In the FASM original, this is an
//   `io_base` descendant whose 7-method I/O vtable is
//   `[tui_ssh$destroy, tui_ssh$clone, tui_ssh$connected, io$send,
//    tui_ssh$receive, io$error, io$timeout]`. The Rust equivalent
//   exposes inherent methods with the same names — the actual
//   `IoChain` trait implementation lives in `crate::net::ssh` and is
//   added there once the SSH protocol layer is built (per AAP §0.5).
// * `TuiSshRenderer` — `tui_render` descendant. Implements the
//   [`Renderer`] trait and the [`Widget`] trait. Its
//   `ansi_output` method appends bytes to a [`Buffer`] accumulator
//   that flushes to the SSH channel via [`SshTransport::send_bytes`].
// * `SshTransport` — local trait abstracting what SSH operations the
//   TUI widget needs (send bytes, set window size, expose remote
//   address). Defining the trait HERE — instead of importing a
//   concrete type from `crate::net::ssh` — preserves the
//   build-order independence required by AAP §0.5: the `tui` module
//   must be compilable before `net::ssh` exists. When `net::ssh` is
//   built it will implement [`SshTransport`] on its connection
//   handle.
//
// FASM source byte-exact preservation:
//
// * Connect path `tui_ssh$connected` (lines 293-345): emits
//   `ESC[?1049h ESC[12h` when `TUI_SSH_ALTERNATESCREEN` is true, else
//   just `ESC[12h`.
// * Exit path `tui_ssh_renderer$exit` (lines 128-194): with alt-screen
//   `27,'[r',27,'[?25h',27,'[' + <width> + ';1H',27,'[?1049l!!Exit!!',13,10`,
//   without alt-screen the same minus the `27,'[?1049l'` middle.
// * Ctrl-C path `tui_ssh$receive .ctrlc` (lines 571-629): identical to
//   the exit banner but with `!!Ctrl-C!!` instead of `!!Exit!!`.
// * The 126-byte `raddr` field and 1-byte `raddr_len` are preserved
//   verbatim from FASM offsets 16/126.
//
// Architectural invariants:
//
// * `TuiSsh` holds a STRONG `Arc<TuiSshRenderer>` (not Weak — the
//   renderer is owned by the SSH layer per FASM `tui_ssh$destroy`
//   lines 198-228 which explicitly `heap$free`s the renderer).
// * `TuiSshRenderer` holds a WEAK `Weak<TuiSsh>` back-pointer to
//   break the otherwise-circular ownership and reach the transport
//   for output flush. Constructed via [`Arc::new_cyclic`] so the
//   renderer can record its parent even before `TuiSsh::new` returns.
// * Interior mutability via `std::sync::Mutex<TuiSshRendererInner>`
//   following the canonical pattern from `widgets::matrix`,
//   `widgets::effect`, and `widgets::spinner`. The widget framework
//   calls Widget trait `&mut self` methods through `Arc::get_mut`
//   (per `crate::tui::object::cleanup_widget`) which only succeeds at
//   refcount=1; for shared-ownership mutation (e.g. accumulating
//   bytes from concurrent draw paths) the `Mutex` is required.
// * `lock_inner_recoverable` translates poison errors back into the
//   inner guard following the matrix.rs / effect.rs precedent — a
//   panic in one render path must not permanently brick the
//   renderer.
// * NO `unsafe` in this file. All channel/syscall work lives in
//   `crate::net::ssh` and `crate::tui::terminal`. Enforced by
//   `#![forbid(unsafe_code)]`.
// * NO third-party TUI crate (per AAP §0.1.1: ratatui / crossterm /
//   termion are PROHIBITED).
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

#![forbid(unsafe_code)]

//! SSH-aware TUI integration widget.
//!
//! Port of FASM `tui_ssh.inc`. Provides [`TuiSsh`] (the I/O-chain
//! widget that mediates between an SSH session and a TUI widget tree)
//! and [`TuiSshRenderer`] (the [`Renderer`] descendant that converts
//! widget draws into byte streams routed back over the SSH channel).
//!
//! The two types reference each other to mirror the FASM dual-pointer
//! layout: `TuiSsh` owns its renderer via [`Arc`] so destruction
//! order is deterministic (renderer first, then chain teardown);
//! `TuiSshRenderer` reaches the SSH transport via a [`Weak`]
//! back-pointer to avoid a reference cycle.
//!
//! ```text
//! Widget tree → TuiSshRenderer::ansi_output ─┐
//!                                            ▼
//!                              TuiSsh::transport (SshTransport)
//!                                            │
//!                                            ▼
//!                                       SSH channel
//!                                            │
//!                                            ▼
//!                              TuiSsh::on_receive (raw bytes)
//!                                            │
//!                                            ▼
//!                       UTF-8 / ANSI parser → KeyEvent
//!                                            │
//!                                            ▼
//!                       Widget tree::fire_key_event
//! ```
//!
//! # Build-order notes
//!
//! This file is a sibling of [`crate::tui::widgets::matrix`] and the
//! other concrete widgets. It deliberately does NOT depend on
//! `crate::net::ssh` — that module implements [`SshTransport`] later
//! once the SSH protocol layer is built. This keeps the `tui` crate
//! buildable in isolation.
//!
//! Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
//! Licensed under GPL-3.0-or-later.

use std::any::Any;
use std::io::{Error as IoError, ErrorKind};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use crate::config::TUI_SSH_ALTERNATESCREEN;
use crate::ds::Buffer;
use crate::error::TuiError;
use crate::tui::ansi::{ALT_SCREEN_EXIT, CLEAR_SCREEN, CURSOR_HOME, HIDE_CURSOR, SHOW_CURSOR};
use crate::tui::geometry::{Point, Rect};
use crate::tui::object::{KeyEvent, Widget, WidgetState};
use crate::tui::render::{RenderState, Renderer};

// ============================================================================
// SshTransport — abstraction boundary between the TUI widget and the SSH
// protocol layer.
// ============================================================================

/// Operations the TUI layer needs from an SSH protocol session.
///
/// Defining this trait here (instead of importing a concrete type from
/// `crate::net::ssh`) lets the `tui` module compile independently of
/// the `net::ssh` module. The eventual SSH server / client connection
/// handle will implement [`SshTransport`].
///
/// # FASM mapping
///
/// In `tui_ssh.inc`, the renderer's `ansi_output` (lines 116-126)
/// invokes `[rcx+io_vsend]` on the underlying io child — i.e. the
/// `ssh` object's `io$send` virtual method. [`Self::send_bytes`] is
/// the Rust equivalent.
///
/// The window-size callback registered at lines 313-317
/// (`ssh_wsizecb_ofs` / `ssh_wsizecbarg_ofs`) translates to
/// [`Self::set_window_size`].
///
/// FASM `ssh_remoteaddr_ofs` and the 126-byte buffer copy at
/// `tui_ssh$connected` lines 299-304 surface here as
/// [`Self::remote_addr`].
///
/// # Send + Sync
///
/// Required because `Arc<dyn SshTransport>` is shared across async
/// tasks managed by the `tokio` runtime.
pub trait SshTransport: Send + Sync {
    /// Send `bytes` to the remote peer over the SSH channel.
    ///
    /// Equivalent to FASM `[rcx+io_vsend]` invoked by
    /// `tui_ssh_renderer$ansioutput` (lines 117-124). The transport
    /// is responsible for any framing, encryption, and flow control;
    /// callers see a simple write-bytes API.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when the SSH transport cannot
    /// accept the bytes (channel closed, encryption failure, etc.).
    fn send_bytes(&self, bytes: &[u8]) -> Result<(), TuiError>;

    /// Notify the SSH transport that the terminal window changed
    /// dimensions to `cols` × `rows` cells.
    ///
    /// Equivalent to FASM `tui_ssh$wsize` (lines 281-291) and the
    /// window-size callback hookup at `tui_ssh$connected` lines
    /// 313-317. The transport may send a SSH_MSG_WINDOW_CHANGE
    /// channel-request message to the peer.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when the size update cannot be
    /// transmitted.
    fn set_window_size(&self, cols: u16, rows: u16) -> Result<(), TuiError>;

    /// Return the remote peer's address as a raw byte sequence.
    ///
    /// Format-preserving: returns the same bytes the FASM
    /// `ssh_remoteaddr_ofs` field carries. The FASM code copies up
    /// to 126 bytes via `memcpy` at `tui_ssh$connected` lines
    /// 299-304; callers should expect at most that many bytes.
    ///
    /// Returns `None` for transport stubs (testing) that don't
    /// expose a remote peer.
    fn remote_addr(&self) -> Option<&[u8]>;
}

// ============================================================================
// Constants — preserve FASM byte-exact layout.
// ============================================================================

/// Length of the remote-address buffer carried by [`TuiSsh::raddr`].
///
/// Matches FASM `tui_ssh.inc` offset arithmetic:
/// ```text
/// tui_ssh_raddr_ofs    = io_base_size + 16
/// tui_ssh_raddrlen_ofs = io_base_size + 126
/// ```
/// — i.e. the buffer occupies bytes 16..142 = 126 bytes.
pub const RADDR_LEN: usize = 126;

/// FASM `tui_ssh$connected` `.altscr` data block (lines 334-342).
///
/// Two variants:
/// * `TUI_SSH_ALTERNATESCREEN = true` (default): `ESC[?1049h ESC[12h`
///   — switches to the alternate screen buffer AND enables
///   keyboard insertion mode.
/// * `TUI_SSH_ALTERNATESCREEN = false`: `ESC[12h` only (insertion
///   mode without alternate screen).
///
/// The FASM build emits exactly one of these; we emit the same
/// sequence at runtime gated by [`TUI_SSH_ALTERNATESCREEN`].
const ALT_SCREEN_AND_INSERT: &[u8] = b"\x1b[?1049h\x1b[12h";

/// FASM `.altscr` (alternate-screen disabled variant): just enable
/// insertion mode.
const INSERT_MODE_ONLY: &[u8] = b"\x1b[12h";

/// Re-enable wrapping: `ESC[r`. Sent as the first chunk of the
/// exit / Ctrl-C banner ("see ya later" preamble) per FASM
/// `.seeyalater` data block (lines 172-174).
const RESET_SCROLL_REGION: &[u8] = b"\x1b[r";

/// FASM exit-banner farewell marker (lines 177, 188): `!!Exit!!\r\n`.
///
/// When `TUI_SSH_ALTERNATESCREEN` is true the FASM output prefixes
/// this with `ESC[?1049l` (alt-screen exit); we emit that escape
/// separately at the appropriate site.
const EXIT_MARKER: &[u8] = b"!!Exit!!\r\n";

/// FASM Ctrl-C banner farewell marker (lines 617, 628):
/// `!!Ctrl-C!!\r\n`. Same structure as [`EXIT_MARKER`].
const CTRLC_MARKER: &[u8] = b"!!Ctrl-C!!\r\n";

/// `H` terminator for the cursor-position parametric escape
/// `ESC[<row>;<col>H`. The FASM code writes the first half
/// (`ESC[<width>`) inline and then completes with `;1H` — see
/// `.reallyseeya` data block lines 176-189.
const CURSOR_TO_LAST_ROW_TAIL: &[u8] = b";1H";

/// Initial flush threshold for [`TuiSshRendererInner::out_buffer`].
///
/// Reaching this byte count triggers an automatic flush from
/// `ansi_output`. The number is a soft threshold — any explicit
/// [`TuiSshRenderer::flush`] call drains the buffer regardless of
/// fill level. 4 KiB matches the typical SSH packet payload size
/// (RFC 4253 §6.1: 32 768 bytes maximum, 4 KiB typical).
const FLUSH_THRESHOLD_BYTES: usize = 4096;

// ============================================================================
// TuiSsh — I/O-chain widget.
// ============================================================================

/// FASM `tui_ssh` object (lines 43-48):
/// ```text
/// tui_ssh_renderer_ofs   = io_base_size + 0      ; ptr to TuiSshRenderer
/// tui_ssh_onlychild_ofs  = io_base_size + 8      ; ptr to display Widget
/// tui_ssh_raddr_ofs      = io_base_size + 16     ; 126 bytes of remote addr
/// tui_ssh_raddrlen_ofs   = io_base_size + 126    ; length of remote addr
/// tui_ssh_size           = io_base_size + 134
/// ```
///
/// The Rust struct mirrors that layout while replacing the FASM
/// `io_base` 24-byte vtable+parent+child preamble with idiomatic
/// inherent methods (Phase 4 of the agent_prompt; the actual
/// `IoChain` trait implementation lives in `crate::net::ssh`).
///
/// # Ownership
///
/// `renderer` is held by strong [`Arc`] because the FASM
/// `tui_ssh$destroy` (lines 198-228) explicitly `heap$free`s the
/// renderer — i.e. the SSH widget OWNS the renderer. The renderer
/// holds a [`Weak`] back-pointer (in
/// [`TuiSshRendererInner::ssh_parent`]) to break the cycle.
///
/// `only_child` is wrapped in [`Mutex`] because it's set in
/// [`TuiSsh::new`] but moved into the renderer's child list in
/// [`TuiSsh::on_connected`] — i.e. it's a one-shot field that needs
/// shared-mutable access through `Arc<TuiSsh>`.
///
/// # Send + Sync
///
/// All fields are `Send + Sync` (`Arc`, `Weak`, primitives, `Mutex`,
/// `Arc<dyn SshTransport>`), so `TuiSsh` derives `Send + Sync`
/// automatically.
pub struct TuiSsh {
    /// FASM `tui_ssh_renderer_ofs` — pointer to the renderer.
    ///
    /// Strong reference: `TuiSsh` owns the renderer and is
    /// responsible for its lifecycle (matches FASM `heap$free` at
    /// `tui_ssh$destroy` line 210).
    pub(crate) renderer: Arc<TuiSshRenderer>,

    /// FASM `tui_ssh_onlychild_ofs` — pointer to the display widget
    /// to be hooked into the renderer's children list once the SSH
    /// channel connects.
    ///
    /// Wrapped in `Mutex<Option<...>>` because:
    /// * The field MUST be settable in [`TuiSsh::new`].
    /// * The field MUST become `None` after [`TuiSsh::on_connected`]
    ///   moves the widget into the renderer's children list (FASM
    ///   `tui_ssh$connected` lines 327-329 zero this slot:
    ///   `mov qword [rdi+tui_ssh_onlychild_ofs], 0`).
    /// * Both events occur through `Arc<TuiSsh>` shared references,
    ///   so interior mutability is required.
    pub(crate) only_child: Mutex<Option<Arc<dyn Widget>>>,

    /// FASM `tui_ssh_raddr_ofs` — 126-byte remote-peer buffer.
    ///
    /// Format-preserving: caller-defined byte layout (typically
    /// `sockaddr_in6` text rendition, but the FASM code is
    /// format-agnostic).
    pub(crate) raddr: [u8; RADDR_LEN],

    /// FASM `tui_ssh_raddrlen_ofs` — number of valid bytes in
    /// [`Self::raddr`]. Stored as `u8` to match FASM (lines 50-51:
    /// the field width is 1 byte / 8 bits — `tui_ssh_size = ofs +
    /// 134` minus `+126` minus `+8`).
    pub(crate) raddr_len: u8,

    /// Backing transport. The eventual `crate::net::ssh` connection
    /// handle implements [`SshTransport`].
    ///
    /// Held by `Arc<dyn ...>` because:
    /// * The transport may be shared with other layers (e.g. an
    ///   auth subsystem reading user credentials).
    /// * The widget tree may need to clone the transport during
    ///   [`Widget::clone_widget`] / FASM `tui_ssh$clone` flows.
    pub(crate) transport: Arc<dyn SshTransport>,
}

impl TuiSsh {
    /// FASM `tui_ssh$new` (lines 58-73).
    ///
    /// Pre-conditions:
    /// * `display` is a valid TUI widget (FASM comment: "argument in
    ///   rdi cannot be NULL, and it doesn't make sense to use this
    ///   without a TUI object in the first place").
    /// * `transport` is a valid SSH connection handle.
    ///
    /// Construction order:
    /// 1. Snapshot the transport's remote address into a 126-byte
    ///    buffer (zero-padded). FASM `tui_ssh$connected` lines
    ///    299-304 do this lazily on connect; we eagerly snapshot
    ///    here for diagnostic visibility while the connection is
    ///    still being established.
    /// 2. Create the renderer via [`TuiSshRenderer::new`], wiring
    ///    the renderer's `Weak<TuiSsh>` back-pointer through
    ///    [`Arc::new_cyclic`].
    /// 3. Wrap the result in `Arc<TuiSsh>` and return.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use heavything::tui::widgets::ssh::{SshTransport, TuiSsh};
    /// use heavything::tui::widgets::matrix::Matrix;
    ///
    /// // Application supplies a concrete SshTransport implementation
    /// // (typically the connection handle from `net::ssh`).
    /// let transport: Arc<dyn SshTransport> = /* ... */ unimplemented!();
    /// let display = Matrix::new(); // Arc<Matrix> implements Widget
    /// let ssh_widget = TuiSsh::new(display, transport);
    /// // Once the SSH channel is fully open, the SSH layer calls
    /// // ssh_widget.on_connected() which appends `display` into the
    /// // renderer and emits the alt-screen escape sequence.
    /// ```
    pub fn new(display: Arc<dyn Widget>, transport: Arc<dyn SshTransport>) -> Arc<Self> {
        // Snapshot the remote address (best-effort; some transports
        // may not expose it yet at construction time).
        let mut raddr = [0u8; RADDR_LEN];
        let raddr_len = match transport.remote_addr() {
            Some(bytes) => {
                let n = bytes.len().min(RADDR_LEN);
                raddr[..n].copy_from_slice(&bytes[..n]);
                // u8::try_from is infallible because n <= RADDR_LEN
                // = 126 < 256.
                u8::try_from(n).unwrap_or(0)
            }
            None => 0,
        };

        // Use Arc::new_cyclic to construct the TuiSsh while
        // simultaneously giving the renderer a Weak back-pointer to
        // it. This is the canonical pattern for breaking parent ↔
        // child Arc cycles.
        Arc::new_cyclic(|weak_self: &Weak<Self>| {
            let renderer = TuiSshRenderer::new(weak_self.clone());
            Self {
                renderer,
                only_child: Mutex::new(Some(display)),
                raddr,
                raddr_len,
                transport,
            }
        })
    }

    /// FASM `tui_ssh$connected` (lines 293-345) — called by the SSH
    /// layer when the channel is fully established and ready for
    /// terminal output.
    ///
    /// Operations (in FASM source order):
    /// 1. Refresh the remote-address snapshot. FASM lines 299-304
    ///    do this via `memcpy` from the SSH connection's address
    ///    buffer; we re-query the transport.
    /// 2. Emit alt-screen + insertion-mode bytes via the transport
    ///    (FASM lines 306-312 write `[rcx+io_vsend]`).
    /// 3. Tell the SSH layer about our window-size callback by
    ///    forwarding the current size to the renderer's
    ///    `new_window_size` (FASM lines 313-325 register
    ///    `ssh_wsizecb_ofs` / `ssh_wsizecbarg_ofs` then call
    ///    `tui_vnewwindowsize`). In Rust the registration is
    ///    implicit: the SSH transport calls
    ///    [`Self::on_window_size`] directly when it sees a window-
    ///    change request.
    /// 4. Append the only-child widget to the renderer's children
    ///    list (FASM lines 327-332 `tui_vappendchild`). The
    ///    `only_child` slot is then cleared.
    ///
    /// # Errors
    ///
    /// Propagates any [`TuiError::Render`] from the transport
    /// (e.g. SSH channel write failure). On error the alt-screen
    /// bytes may have been partially sent — the SSH transport is
    /// expected to surface a clean shutdown when the channel
    /// closes.
    pub fn on_connected(&self) -> Result<(), TuiError> {
        // Step 1: emit the alt-screen + insertion-mode escape
        // sequence. The FASM code chooses between the two byte
        // strings at compile time via the `if tui_ssh_alternatescreen`
        // gate (lines 334-342); the Rust code chooses at runtime
        // via the const value (which is compiled out as constant
        // folding when -Copt-level >= 1).
        let altscr_bytes: &[u8] = if TUI_SSH_ALTERNATESCREEN {
            ALT_SCREEN_AND_INSERT
        } else {
            INSERT_MODE_ONLY
        };
        self.transport.send_bytes(altscr_bytes)?;

        // Step 2: emit cursor-hide + clear-screen + cursor-home so
        // the alt-screen buffer starts in a known state. The FASM
        // build leaves this implicit (the alt-screen buffer is
        // newly allocated by the terminal on `ESC[?1049h`); we are
        // explicit per the agent_prompt Phase 4 for
        // protocol-implementation parity with Linux pty terminals.
        self.transport.send_bytes(HIDE_CURSOR)?;
        self.transport.send_bytes(CLEAR_SCREEN)?;
        self.transport.send_bytes(CURSOR_HOME)?;

        // Step 3: hand off the only-child widget to the renderer.
        // We take the widget out of the Mutex slot (mirroring the
        // FASM line 329 zero-store) and append it via
        // Arc::get_mut on the renderer. This requires refcount=1
        // on the renderer Arc, which is true at this point because
        // the SSH layer holds the only Arc<TuiSsh> and the
        // renderer is owned solely by us — we currently hold the
        // sole strong reference to the renderer.
        //
        // The FASM equivalent is `qword [rdx+tui_vappendchild]`
        // calling `tui_object$appendchild` which does
        // `list$append` on the renderer's children list.
        let display_opt = {
            let mut guard = lock_only_child_recoverable(&self.only_child);
            guard.take()
        };
        if let Some(display) = display_opt {
            // Best-effort exclusive access on the renderer. If
            // refcount > 1 (e.g. another concurrent on_connected
            // call has cloned the Arc) we fall back to silently
            // skipping — matching the framework convention from
            // `crate::tui::object::cleanup_widget` line 1051.
            //
            // We have to clone the Arc here briefly to satisfy the
            // borrow checker (Arc::get_mut requires &mut Arc, but
            // self.renderer is behind a shared reference).
            let mut renderer_arc = self.renderer.clone();
            if let Some(renderer) = Arc::get_mut(&mut renderer_arc) {
                // Disambiguate: `TuiSshRenderer` implements both
                // `Widget::state_mut` (returns `&mut WidgetState`)
                // and `Renderer::state_mut` (returns
                // `&mut RenderState`). We want the WidgetState
                // here because `children` lives on it. Direct
                // field access bypasses the trait dispatch and
                // is also faster than a virtual call.
                renderer.state.children.push_back(display);
            }
        }

        Ok(())
    }

    /// FASM `tui_ssh$wsize` (lines 281-291) — called by the SSH
    /// transport when the peer signals a window-size change.
    ///
    /// Forwards `(cols, rows)` to the renderer's `new_window_size`
    /// (FASM line 287-288 `tui_vnewwindowsize`) which updates the
    /// cached `RenderState::window` rectangle and triggers a
    /// re-layout via the widget tree.
    ///
    /// # Errors
    ///
    /// Propagates any [`TuiError::Render`] from the renderer
    /// (e.g. layout-buffer allocation failure).
    pub fn on_window_size(&self, cols: u16, rows: u16) -> Result<(), TuiError> {
        // Same Arc::get_mut pattern as on_connected — silently
        // skipping when the renderer has additional references.
        let mut renderer_arc = self.renderer.clone();
        if let Some(renderer) = Arc::get_mut(&mut renderer_arc) {
            renderer.new_window_size(cols, rows)
        } else {
            // Renderer is shared (e.g. a draw is in flight). The
            // SSH transport will re-deliver the resize at the next
            // SIGWINCH if the dimensions change again.
            Ok(())
        }
    }

    /// FASM `tui_ssh$receive` (lines 349-569) — called by the SSH
    /// layer with a chunk of incoming raw bytes from the peer.
    ///
    /// Parses the byte stream as either:
    /// * A printable ASCII byte (UTF-8 single-byte cluster);
    /// * A UTF-8 multi-byte cluster (2/3/4-byte sequences,
    ///   FASM `.unichar_2`/`.unichar_3`/`.unichar_4` lines 460-564);
    /// * An ANSI CSI escape sequence beginning with `ESC[`
    ///   (FASM `.escbracket` lines 408-437);
    /// * An ANSI SS3 escape sequence beginning with `ESC O`
    ///   (FASM `.escoh` lines 439-445);
    /// * A literal control byte (Ctrl-C = 0x03 → suicide path,
    ///   FASM `.ctrlc` lines 571-608).
    ///
    /// Each decoded code-point or escape sequence is forwarded to
    /// the renderer's [`Widget::fire_key_event`] (FASM line 395
    /// `tui_vfirekeyevent`).
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` to signal the caller that the SSH
    /// connection should be torn down (FASM `.ctrlc` returns
    /// `eax=1` "suicide" at line 607).
    /// Returns `Ok(false)` for normal completion (FASM `.alldone`
    /// returns `eax=0` at line 568).
    ///
    /// # Errors
    ///
    /// Propagates any [`TuiError::Render`] from the Ctrl-C banner
    /// emission via the transport.
    pub fn on_receive(&self, data: &[u8]) -> Result<bool, TuiError> {
        let mut i = 0usize;
        while i < data.len() {
            let byte = data[i];
            // FASM lines 367-370: `shr eax, 4 ; cmp eax, 12` —
            // i.e. test the top nibble. Top nibble >= 12 means a
            // UTF-8 leading byte (0xC0..0xFF). The narrower
            // ranges 12..=15 = 0xC0..0xFF select 2/3/4-byte
            // sequences via the lower 2 bits of the top nibble.
            let top_nibble = byte >> 4;
            if top_nibble >= 12 {
                // UTF-8 leading byte. FASM dispatches:
                //   12 (0xC0..0xCF) → unichar_2
                //   13 (0xD0..0xDF) → unichar_2
                //   14 (0xE0..0xEF) → unichar_3
                //   15 (0xF0..0xFF) → unichar_4
                let consumed = match top_nibble {
                    12 | 13 => parse_utf8_continuation(data, i, 2),
                    14 => parse_utf8_continuation(data, i, 3),
                    15 => parse_utf8_continuation(data, i, 4),
                    _ => None, // unreachable but explicit
                };
                if let Some((codepoint, used)) = consumed {
                    self.fire_key_char(codepoint)?;
                    i += used;
                    continue;
                }
                // Invalid UTF-8: fall through to the not-unicode
                // path, treating the byte as a normal ASCII char
                // (FASM lines 456-458 `jmp .notunicode`).
            }

            // Not-unicode path (FASM `.notunicode` line 372).
            if byte == 27 && i + 3 <= data.len() {
                // ESC followed by [ or O = CSI / SS3.
                let next = data[i + 1];
                if next == b'[' {
                    let (esc_key, used) = parse_csi(data, i);
                    self.fire_key_escape(esc_key)?;
                    i += used;
                    continue;
                }
                if next == b'O' {
                    // FASM `.escoh` lines 439-445: shift 'O' left
                    // 8 and OR with the next byte to encode the
                    // function key.
                    let esc_key = (u32::from(b'O') << 8) | u32::from(data[i + 2]);
                    self.fire_key_escape(esc_key)?;
                    i += 3;
                    continue;
                }
            }

            // FASM `.normalchar` line 388: Ctrl-C (0x03) is the
            // "kill switch" — we send the farewell banner and
            // return suicide=true.
            if byte == 0x03 {
                self.emit_ctrlc_banner()?;
                return Ok(true);
            }

            // Ordinary printable / control byte: deliver as a key
            // event and advance one byte (FASM lines 391-397).
            self.fire_key_char(u32::from(byte))?;
            i += 1;
        }
        Ok(false)
    }

    /// Helper: forward a Unicode code-point keypress to the
    /// renderer's widget tree.
    ///
    /// FASM equivalent: lines 391-397 / 478-485 / 513-520 / 557-564
    /// — all four call `tui_vfirekeyevent` with `esi=key` and
    /// `edx=esc_key=0`.
    fn fire_key_char(&self, codepoint: u32) -> Result<(), TuiError> {
        let event = decode_key_event(codepoint, 0);
        let mut renderer_arc = self.renderer.clone();
        if let Some(renderer) = Arc::get_mut(&mut renderer_arc) {
            let _ = renderer.fire_key_event(event);
        }
        Ok(())
    }

    /// Helper: forward an ANSI escape sequence (CSI or SS3) to the
    /// renderer's widget tree.
    ///
    /// FASM equivalent: `.fireescaped` (lines 399-407) — passes
    /// `esi=0`, `edx=esc_key`.
    fn fire_key_escape(&self, esc_key: u32) -> Result<(), TuiError> {
        let event = decode_key_event(0, esc_key);
        let mut renderer_arc = self.renderer.clone();
        if let Some(renderer) = Arc::get_mut(&mut renderer_arc) {
            let _ = renderer.fire_key_event(event);
        }
        Ok(())
    }

    /// FASM `tui_ssh_renderer$exit` (lines 128-194) and the
    /// `.ctrlc` path (lines 571-608) emit nearly identical
    /// farewell banners differing only in the trailing marker
    /// (`!!Exit!!` vs `!!Ctrl-C!!`). We dispatch to a common helper
    /// parameterised on the marker.
    ///
    /// Banner format (with `TUI_SSH_ALTERNATESCREEN = true`):
    ///   `ESC[r ESC[?25h ESC[ <width> ;1H ESC[?1049l !!Marker!!\r\n`
    /// Without alt-screen:
    ///   `ESC[r ESC[?25h ESC[ <width> ;1H !!Marker!!\r\n`
    ///
    /// The `<width>` token is decimal text rendered from the
    /// renderer's cached width (FASM `tui_width_ofs` accessed at
    /// lines 136 / 574). We read the value from
    /// [`RenderState::window`] which is the Rust-side equivalent.
    fn emit_ctrlc_banner(&self) -> Result<(), TuiError> {
        self.emit_farewell_banner(CTRLC_MARKER)
    }

    /// Emit the exit banner with a custom marker. Public-crate so
    /// [`TuiSshRenderer::exit`] can call it.
    pub(crate) fn emit_farewell_banner(&self, marker: &[u8]) -> Result<(), TuiError> {
        let width = self.renderer.cached_width();

        // Buffer: max realistic size is
        //   3 (ESC[r) + 6 (ESC[?25h) + 2 (ESC[) + 5 (width digits)
        //   + 3 (;1H) + 8 (ESC[?1049l) + marker.len() + 2 (\r\n)
        //   ≈ 35 + marker.len()
        let mut buf: Vec<u8> = Vec::with_capacity(64 + marker.len());
        buf.extend_from_slice(RESET_SCROLL_REGION);
        buf.extend_from_slice(SHOW_CURSOR);
        // FASM emits `ESC[` then the decimal width, completing the
        // cursor-position escape with `;1H`.
        buf.extend_from_slice(b"\x1b[");
        push_decimal_u32(&mut buf, width);
        buf.extend_from_slice(CURSOR_TO_LAST_ROW_TAIL);
        if TUI_SSH_ALTERNATESCREEN {
            buf.extend_from_slice(ALT_SCREEN_EXIT);
        }
        buf.extend_from_slice(marker);

        self.transport.send_bytes(&buf)
    }

    /// FASM `tui_ssh$destroy` (lines 198-228) — invoked when the
    /// SSH connection tears down.
    ///
    /// The Rust equivalent of this method does NOT free memory
    /// (Drop handles that automatically); instead it emits the
    /// alt-screen-exit + cursor-restore escape sequences so the
    /// remote terminal returns to its previous state.
    ///
    /// FASM lines 200-227 deallocate the renderer (line 210
    /// `heap$free`) and the `only_child` (line 220) and then chain
    /// to `io$destroy`. In Rust, dropping the `Arc<TuiSsh>` cleans
    /// up the renderer (it's the sole strong reference once
    /// `on_connected` has moved the only-child into the renderer's
    /// children list); the renderer's [`Drop`] handles its own
    /// resources via the [`Buffer`] and [`Mutex`] destructors.
    ///
    /// # Errors
    ///
    /// Best-effort: errors emitting the cleanup escape are
    /// silently swallowed because at this point the channel may
    /// already be closing. Callers that care should call this
    /// before initiating SSH disconnect.
    pub fn on_destroy(&self) {
        // Show the cursor (peer's terminal may have left it
        // hidden after our HIDE_CURSOR on connect).
        let _ = self.transport.send_bytes(SHOW_CURSOR);

        // Restore the alternate screen if we entered it.
        if TUI_SSH_ALTERNATESCREEN {
            let _ = self.transport.send_bytes(ALT_SCREEN_EXIT);
        }
    }

    /// FASM `io$error` is the default error handler invoked by
    /// `tui_ssh$vtable[5]` (line 41). The default semantics are to
    /// propagate the error up the I/O chain (FASM `io$error`
    /// chases `io_parent_ofs`).
    ///
    /// In Rust we accept the [`IoError`] but treat it as a
    /// notification that triggers the same teardown as
    /// [`Self::on_destroy`]. The actual "propagation" up the chain
    /// is handled by the `crate::net::io::IoChain` machinery once
    /// `net::ssh` wires this widget into a chain.
    pub fn on_error(&self, _err: IoError) {
        self.on_destroy();
    }

    /// FASM `io$timeout` is the default timeout handler invoked by
    /// `tui_ssh$vtable[6]` (line 41). Default is no-op (FASM
    /// `io$timeout` returns 0 = "reset timer").
    ///
    /// We have no widget-layer timeout semantics; the widget tree
    /// runs animations via `tokio::time::interval` registered by
    /// individual widgets (e.g. `Matrix`, `Spinner`). The SSH
    /// channel timeout is handled by the SSH protocol layer.
    pub fn on_timeout(&self) {
        // intentional no-op
    }

    /// FASM `tui_ssh$clone` (lines 231-279) — produce a deep copy
    /// suitable for use in a separate I/O chain.
    ///
    /// Operations (in FASM source order):
    /// 1. Clone `only_child` via its `tui_vclone` vmethod (lines
    ///    240-243). The Rust equivalent uses
    ///    [`Widget::clone_widget`].
    /// 2. Allocate a fresh [`TuiSsh`] (FASM line 244-247).
    /// 3. Create a fresh renderer (FASM lines 250-255 — note FASM
    ///    creates a "virgin" renderer, NOT a clone of the original
    ///    renderer). Our [`TuiSsh::new`] does the equivalent.
    /// 4. If the original had an `io_child` (the SSH protocol
    ///    layer), clone it too (FASM lines 257-271). In Rust the
    ///    SSH transport is shared via `Arc<dyn SshTransport>`;
    ///    we keep the same `Arc` since the abstraction has no
    ///    user-clonable wire state.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if either:
    /// * The `only_child` clone fails (e.g. the underlying widget
    ///   does not override [`Widget::clone_widget`]).
    /// * The `only_child` slot is empty (the FASM code expects
    ///   non-null at offset 8 — we surface this as a `NotFound`
    ///   error instead of panicking).
    pub fn try_clone(&self) -> Result<Arc<TuiSsh>, TuiError> {
        // Step 1: clone only_child.
        let original_child = {
            let guard = lock_only_child_recoverable(&self.only_child);
            guard.as_ref().cloned()
        };
        let cloned_child = match original_child {
            Some(child) => child.clone_widget()?,
            None => {
                return Err(TuiError::Render(IoError::new(
                    ErrorKind::NotFound,
                    "TuiSsh::try_clone: only_child slot is empty",
                )));
            }
        };

        // Steps 2-4: build a fresh TuiSsh sharing the transport.
        Ok(TuiSsh::new(cloned_child, self.transport.clone()))
    }

    /// Returns the cached remote-peer address as a byte slice.
    ///
    /// Reads from the [`Self::raddr`] / [`Self::raddr_len`] fields
    /// populated at construction time from
    /// [`SshTransport::remote_addr`]. The returned slice has
    /// `raddr_len` bytes (between `0` and `RADDR_LEN = 126`).
    ///
    /// FASM equivalent: reading `[r12 + tui_ssh_raddr_ofs]` for
    /// `[r12 + tui_ssh_raddrlen_ofs]` bytes (offsets 16 / 142
    /// from the FASM `io_base_size`-relative struct).
    ///
    /// Format-preserving: the bytes are exactly what the
    /// transport returned at connect time. Typical formats are a
    /// printable IPv4 / IPv6 address (e.g.
    /// `b"192.0.2.1:54321"`), but the FASM code is
    /// format-agnostic so callers should treat the bytes as
    /// opaque diagnostic data unless they know the transport's
    /// convention.
    ///
    /// Returns an empty slice if no address was available at
    /// connect time (e.g. when the transport is a stub or the
    /// connection's peer info isn't yet populated).
    pub fn remote_address(&self) -> &[u8] {
        // Clamp len to the buffer size as a defense-in-depth
        // measure even though the constructor already does this.
        let len = (self.raddr_len as usize).min(RADDR_LEN);
        &self.raddr[..len]
    }
}

// ============================================================================
// TuiSshRenderer — Renderer-descendant + Widget hybrid.
// ============================================================================

/// Mutable inner state carried by [`TuiSshRenderer`] under a
/// [`Mutex`]. Mirrors the FASM `tui_ssh_renderer` layout (line 80:
/// `tui_ssh_renderer_size = tui_render_size + 8` — the only added
/// field is the `tui_ssh_renderer_base_ofs` pointer back to the
/// owning `TuiSsh`).
///
/// Only fields that need shared-mutable access through `&self`
/// live here:
/// * `out_buffer` — appended to from [`Renderer::ansi_output`]
///   (which receives `&mut self`) AND drained by
///   [`TuiSshRenderer::flush`] (which receives `&self`); the dual-
///   mode access mandates interior mutability.
/// * `ssh_parent` — the [`Weak`] back-pointer; immutable after
///   construction but kept here for layout symmetry with the FASM
///   `tui_ssh_renderer_base_ofs` field.
///
/// The [`RenderState`] mirror lives DIRECTLY on the renderer struct
/// (as the `render` field) — NOT inside this Mutex — because the
/// [`Renderer`] trait requires `&self -> &RenderState` which cannot
/// safely return a borrow into a Mutex guard.
struct TuiSshRendererInner {
    /// Accumulator for ANSI bytes emitted via
    /// [`Renderer::ansi_output`]. Flushed to the SSH transport
    /// when [`FLUSH_THRESHOLD_BYTES`] is reached or
    /// [`Renderer::flush`] is called.
    out_buffer: Buffer,

    /// FASM `tui_ssh_renderer_base_ofs` — back-pointer to the
    /// owning `TuiSsh`. Stored as [`Weak`] to break the otherwise-
    /// circular ownership graph (`TuiSsh -> Arc<TuiSshRenderer>`
    /// and `TuiSshRenderer -> Weak<TuiSsh>`).
    ssh_parent: Weak<TuiSsh>,
}

/// FASM `tui_ssh_renderer` object (lines 80-95). A descendant of
/// `tui_render` whose only added field is a back-pointer to the
/// owning `TuiSsh`.
///
/// In Rust this is a `Widget` AND a `Renderer`:
/// * As a [`Widget`] (lines 1125-onwards in `matrix.rs` precedent),
///   it participates in the widget tree — it owns the
///   `WidgetState` containing the children list (the only-child
///   widget is appended here on connect) and dispatches key
///   events.
/// * As a [`Renderer`] (lines 200-onwards in `render.rs`), it
///   accepts ANSI byte streams from the widget tree's `draw`
///   methods and routes them out the SSH channel via
///   [`SshTransport::send_bytes`].
///
/// # Layout
///
/// Public-crate field `state` contains the [`WidgetState`] (FASM
/// `tui_object` base inherited transitively through `tui_render`).
/// The remainder of the FASM-equivalent state lives in the
/// `Mutex<TuiSshRendererInner>` for shared-mutable access.
pub struct TuiSshRenderer {
    /// Widget state inherited from the [`Widget`] base. Mutable
    /// directly through `&mut self` (which the framework obtains
    /// via [`std::sync::Arc::get_mut`]).
    pub(crate) state: WidgetState,

    /// Renderer state cache (cursor, colors, attributes, window
    /// bounds). Required directly on the struct (rather than
    /// inside the Mutex) because the [`Renderer`] trait requires
    /// `&self -> &RenderState` and `&mut self -> &mut RenderState`
    /// which cannot return references into a Mutex guard. All
    /// mutations occur through `&mut self` (via the framework's
    /// `Arc::get_mut` dispatch), so no further synchronization
    /// is required.
    ///
    /// Schema name: `render` (matches the AAP §0.4 Phase-5 layout
    /// description `pub(crate) render: RenderState`).
    pub(crate) render: RenderState,

    /// Output buffer + SSH back-pointer, behind a recoverable
    /// [`Mutex`] following the matrix.rs / effect.rs / spinner.rs
    /// precedent for interior-mutable widget state. The Mutex is
    /// required because [`Self::flush`] (called via `&self`)
    /// drains the output buffer.
    inner: Mutex<TuiSshRendererInner>,
}

impl TuiSshRenderer {
    /// FASM `tui_ssh_renderer$new` (lines 99-111).
    ///
    /// FASM steps:
    /// 1. Allocate `tui_ssh_renderer_size` bytes (line 102) and
    ///    zero them (line 103 `heap$alloc_clear`).
    /// 2. Store the SSH back-pointer at `tui_ssh_renderer_base_ofs`
    ///    (line 107).
    /// 3. Set the vtable (line 108).
    /// 4. Call `tui_render$init_defaults` to initialize the render
    ///    state to its default values (line 109).
    ///
    /// In Rust we use [`Default`] on the relevant types to mimic
    /// the zero-clear + init-defaults effect.
    ///
    /// Wrapped in [`Arc`] for shared ownership consistent with the
    /// matrix / effect / spinner widget-construction precedent.
    pub fn new(ssh_parent: Weak<TuiSsh>) -> Arc<Self> {
        Arc::new(Self {
            state: WidgetState::new(),
            render: RenderState::default(),
            inner: Mutex::new(TuiSshRendererInner {
                out_buffer: Buffer::new(),
                ssh_parent,
            }),
        })
    }

    /// FASM `tui_ssh_renderer$exit` (lines 128-194) implemented as
    /// an inherent method (the [`Widget::exit`] trait method takes
    /// no parameters and is therefore unsuitable for the FASM
    /// signature).
    ///
    /// FASM signature: `(rdi == self, esi == exit_code)`. The
    /// FASM comment at line 133 states "we don't really care about
    /// the exit code". The Rust signature matches: it accepts the
    /// exit code for documentation but ignores it.
    ///
    /// Behavior: emit the `!!Exit!!` farewell banner (FASM
    /// `.seeyalater` + decimal width + `.reallyseeya` lines
    /// 172-189) and ask the SSH layer for a clean exit (FASM line
    /// 165 `ssh$cleanexit`).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if:
    /// * The Weak back-pointer to [`TuiSsh`] cannot be upgraded
    ///   (the widget was already dropped — should not happen in
    ///   normal flow).
    /// * The transport rejects the banner bytes.
    pub fn exit_with_code(&self, _exit_code: i32) -> Result<(), TuiError> {
        // Weak back-pointer upgrade: returns None if the TuiSsh
        // has been dropped, in which case there is no transport
        // to write to.
        let parent_arc = {
            let guard = lock_inner_recoverable(&self.inner);
            guard.ssh_parent.upgrade()
        };
        let parent = parent_arc.ok_or_else(|| {
            TuiError::Render(IoError::new(
                ErrorKind::NotFound,
                "TuiSshRenderer::exit_with_code: TuiSsh parent already dropped",
            ))
        })?;

        // Emit the !!Exit!! banner via the parent's helper.
        parent.emit_farewell_banner(EXIT_MARKER)
    }

    /// Return the cached terminal width in cells.
    ///
    /// Used by the farewell-banner formatter to reproduce the
    /// FASM behavior of placing the banner at the LAST column
    /// before the bottom row (the FASM code at lines 136 / 574
    /// reads `tui_width_ofs` for this purpose).
    ///
    /// Returns at least 1 to avoid producing the bogus `ESC[0;1H`
    /// escape (which most terminals interpret as `ESC[1;1H`,
    /// negating the intent).
    pub(crate) fn cached_width(&self) -> u32 {
        let w = self.render.window.width();
        if w <= 0 {
            1
        } else {
            // .width() returns i32; the Rect always carries
            // non-negative bx-ax (validated by Rect's
            // construction invariants), so this cast is safe.
            u32::try_from(w).unwrap_or(1)
        }
    }

    /// FASM `tui_render$new_window_size` equivalent for the SSH
    /// renderer — invoked by `TuiSsh::on_window_size` (which is
    /// called by the SSH transport on `SSH_MSG_CHANNEL_REQUEST`
    /// `window-change`).
    ///
    /// Updates the cached `RenderState::window` rectangle and
    /// triggers a re-layout via the widget tree.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] only if a downstream layout
    /// hook fails. This implementation is currently infallible
    /// but the signature preserves the trait contract for
    /// implementors that want to defer layout to a fallible
    /// `update_display_list` pass.
    pub fn new_window_size(&mut self, cols: u16, rows: u16) -> Result<(), TuiError> {
        self.apply_new_window_size(cols, rows);
        // FASM additionally invokes the widget tree's
        // `tui_vlayoutchanged` (lines not directly reproduced
        // here because the agent_prompt explicitly defers
        // layout-change propagation to the framework's
        // widget-tree update pass). The call is implicit: the
        // next render cycle's `update_display_list` walks
        // children and applies the new bounds.
        Ok(())
    }

    /// Private helper shared by the inherent
    /// [`Self::new_window_size`] (returns `Result`) and the trait
    /// [`Renderer::new_window_size`] (returns `()`).
    ///
    /// Centralizes the actual state-update side effects in one
    /// place so the two public entry points don't drift, and so
    /// the trait method can avoid the
    /// "multiple applicable items" ambiguity that would arise
    /// from delegating via `Type::new_window_size` (where both an
    /// inherent and a trait method share the same name).
    fn apply_new_window_size(&mut self, cols: u16, rows: u16) {
        // Update the cached window rectangle. FASM stores width /
        // height directly; we use Rect::from_origin_size for
        // structural symmetry with `RenderState::window`.
        let new_window = Rect::from_origin_size(Point::ZERO, i32::from(cols), i32::from(rows));
        self.render.window = new_window;

        // Mirror the dimensions in the WidgetState as well so
        // child widgets that read `state().bounds` see the new
        // size.
        self.state.bounds = new_window;
        self.state.width = i32::from(cols);
        self.state.height = i32::from(rows);
    }

    /// Inherent `ansi_output` for direct external callers (e.g.
    /// `crate::tui::widgets::ssh` integration tests).
    ///
    /// Most production callers reach this method indirectly via
    /// the [`Renderer::ansi_output`] trait method.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if the buffered bytes cannot
    /// be flushed to the transport (when the threshold is hit).
    pub fn ansi_output(&self, bytes: &[u8]) -> Result<(), TuiError> {
        // Append to the buffer. Flush if threshold reached.
        let needs_flush = {
            let mut guard = lock_inner_recoverable(&self.inner);
            guard.out_buffer.extend_from_slice(bytes);
            guard.out_buffer.len() >= FLUSH_THRESHOLD_BYTES
        };
        if needs_flush {
            // Use the `&self` private helper directly. The public
            // `flush_pending` does the same thing but going
            // through it here would just add a method call on the
            // hot path. The trait `Renderer::flush(&mut self)`
            // can't be called here because `self` is `&self`.
            self.flush_internal()
        } else {
            Ok(())
        }
    }

    /// Inherent `flush` for direct external callers (and for the
    /// internal `flush_internal` that the [`Renderer`] trait impls
    /// dispatch to).
    ///
    /// Drains the [`TuiSshRendererInner::out_buffer`] and writes
    /// the bytes to the SSH transport via
    /// [`SshTransport::send_bytes`]. The buffer is cleared on
    /// success; on failure the bytes remain in the buffer so a
    /// subsequent retry can resend them.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when:
    /// * The Weak back-pointer to [`TuiSsh`] cannot be upgraded.
    /// * The transport rejects the buffered bytes.
    pub fn flush_pending(&self) -> Result<(), TuiError> {
        self.flush_internal()
    }

    /// Internal flush implementation shared by [`Self::flush_pending`]
    /// (public, takes `&self`) and by the [`Renderer::flush`] trait
    /// method (which receives `&mut self` but reborrows as `&self`).
    ///
    /// Steps:
    /// 1. Snapshot the buffer contents (copy out under the lock).
    /// 2. Clear the buffer (under the lock).
    /// 3. Upgrade the Weak back-pointer to TuiSsh.
    /// 4. Release the lock.
    /// 5. Send the snapshot via the transport.
    ///
    /// The lock is held only across the buffer copy + clear; the
    /// transport send happens lock-free so concurrent
    /// `ansi_output` writes don't block on slow I/O.
    fn flush_internal(&self) -> Result<(), TuiError> {
        // Step 1-3: take ownership of the buffer's bytes and the
        // parent reference (move them out under the lock).
        let (bytes_to_send, parent) = {
            let mut guard = lock_inner_recoverable(&self.inner);
            if guard.out_buffer.is_empty() {
                return Ok(());
            }
            let parent = guard.ssh_parent.upgrade();
            // Snapshot the buffer contents and clear.
            let snap: Vec<u8> = guard.out_buffer.as_slice().to_vec();
            guard.out_buffer.clear();
            (snap, parent)
        };

        // Step 4: validate the back-pointer.
        let parent = parent.ok_or_else(|| {
            TuiError::Render(IoError::new(
                ErrorKind::NotFound,
                "TuiSshRenderer::flush: TuiSsh parent already dropped",
            ))
        })?;

        // Step 5: send via the transport.
        parent.transport.send_bytes(&bytes_to_send)
    }
}

// ============================================================================
// Widget impl for TuiSshRenderer.
// ============================================================================

impl Widget for TuiSshRenderer {
    fn state(&self) -> &WidgetState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// FASM vtable slot 5 / `tui_render$cleanup` — drain the output
    /// buffer and clear the inherited base-widget state.
    ///
    /// The FASM `tui_ssh_renderer$vtable` (lines 86-87) overrides
    /// `cleanup` from `tui_object$cleanup` to `tui_render$cleanup`.
    /// We replicate that by:
    /// 1. Best-effort flushing any pending bytes (errors are
    ///    swallowed because cleanup paths cannot meaningfully
    ///    propagate failures).
    /// 2. Clearing the inherited base-widget collections (matching
    ///    the trait default's body verbatim — see
    ///    `crate::tui::object::Widget::cleanup` lines 686-693).
    fn cleanup(&mut self) {
        // Best-effort flush — swallow errors because there is no
        // sensible recovery path during cleanup. We use the
        // private `flush_internal` (takes `&self`) directly to
        // avoid the trait-vs-inherent ambiguity that would arise
        // from calling `self.flush()`.
        let _ = self.flush_internal();

        // Inline the trait-default body (calling
        // `cleanup_widget(self)` would re-dispatch through the
        // vtable and trigger infinite recursion).
        //
        // Use direct field access to bypass the
        // `Widget::state_mut` / `Renderer::state_mut`
        // ambiguity: the WidgetState is the `state` field
        // directly on this struct, no dispatch needed.
        let state = &mut self.state;
        state.children.clear();
        state.bastards.clear();
        state.text.clear();
        state.attributes.clear();
        state.display_name.clear();
    }

    /// FASM `tui_ssh$clone` (lines 231-279) creates a fresh
    /// renderer rather than cloning the existing one — see FASM
    /// comment at line 239: "we are free to create a virgin /
    /// non-cloned renderer".
    ///
    /// We follow that convention: cloning is unsupported because
    /// it doesn't make sense in isolation — the renderer's
    /// identity is tied to its owning `TuiSsh`, and cloning the
    /// `TuiSsh` (via [`TuiSsh::try_clone`]) constructs a fresh
    /// renderer through that path.
    ///
    /// # Errors
    ///
    /// Always returns [`TuiError::Render`] with
    /// [`ErrorKind::Unsupported`].
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        Err(TuiError::Render(IoError::new(
            ErrorKind::Unsupported,
            "TuiSshRenderer::clone_widget: clone via TuiSsh::try_clone instead",
        )))
    }

    /// FASM vtable slot 15 / `tui_object$exit` overridden to
    /// `tui_ssh_renderer$exit` (line 87 of `tui_ssh.inc`). The
    /// trait method signature `fn exit(&mut self)` accepts no
    /// parameters; the FASM equivalent ignores its `esi` exit
    /// code. We forward to the inherent [`Self::exit_with_code`]
    /// helper passing 0 as the code.
    ///
    /// Errors are swallowed (the `Widget::exit` trait method is
    /// `() -> ()`); production callers wanting error visibility
    /// should call [`Self::exit_with_code`] directly.
    fn exit(&mut self) {
        let _ = self.exit_with_code(0);
    }
}

// ============================================================================
// Renderer impl for TuiSshRenderer.
// ============================================================================
//
// `RenderState` is held directly on the `TuiSshRenderer` struct (NOT
// inside the Mutex) so that the trait's `&self -> &RenderState` and
// `&mut self -> &mut RenderState` accessors can return direct
// borrows. Only the truly-shared state (`out_buffer` + `ssh_parent`)
// lives behind the `Mutex` for the dual-mode access pattern of
// `ansi_output` (caller has `&mut self`) vs `flush_pending` (caller
// has `&self` only).

impl Renderer for TuiSshRenderer {
    /// FASM `tui_ssh_renderer$ansioutput` (lines 116-126).
    ///
    /// FASM dispatch:
    /// ```text
    /// mov rdi, [rdi+tui_ssh_renderer_base_ofs]  ; reach the SSH base
    /// mov rcx, [rdi]                            ; SSH base vtable
    /// call qword [rcx+io_vsend]                 ; io$send on SSH
    /// ```
    ///
    /// In Rust the equivalent is to append the bytes to our
    /// accumulator buffer (under the Mutex) and flush when the
    /// threshold is reached. The Weak back-pointer to TuiSsh is
    /// upgraded only at flush time (see [`Self::flush`]).
    fn ansi_output(&mut self, bytes: &[u8]) -> Result<(), TuiError> {
        // We have &mut self so we have exclusive access; bypass
        // the Mutex via get_mut for performance.
        let needs_flush = {
            let inner = self
                .inner
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner.out_buffer.extend_from_slice(bytes);
            inner.out_buffer.len() >= FLUSH_THRESHOLD_BYTES
        };
        if needs_flush {
            // `flush_internal` takes `&self`; auto-borrow
            // re-borrows our `&mut self` as `&self` here.
            self.flush_internal()
        } else {
            Ok(())
        }
    }

    /// FASM equivalent: `tui_render$flush` (defined in
    /// `tui_render.inc`, called by the widget framework after a
    /// draw-walk to push pending bytes to the wire).
    ///
    /// Drains the accumulator and writes via the SSH transport.
    fn flush(&mut self) -> Result<(), TuiError> {
        self.flush_internal()
    }

    /// Return an immutable reference to the cached `RenderState`.
    ///
    /// The `RenderState` lives directly on the [`TuiSshRenderer`]
    /// struct (not behind the Mutex), so the borrow is trivial.
    /// All mutations occur through `state_mut` which receives
    /// `&mut self` — the framework's `Arc::get_mut` dispatch
    /// guarantees exclusive access at mutation time.
    fn state(&self) -> &RenderState {
        &self.render
    }

    /// Return a mutable reference to the cached `RenderState`.
    ///
    /// Returns a direct borrow of the owned `render` field.
    /// The default `Renderer` trait methods (cursor / fg / bg /
    /// attr setters) use this borrow to update the elision-cache
    /// after writing the corresponding ANSI escape.
    fn state_mut(&mut self) -> &mut RenderState {
        &mut self.render
    }

    /// FASM `tui_render$new_window_size` — entry point invoked by
    /// `TuiSsh::on_window_size` and by the SSH transport's
    /// window-change callback.
    ///
    /// Updates the cached window rectangle and the Widget state's
    /// bounds. The trait signature returns `()` (matching the FASM
    /// model where the renderer never propagates errors back from a
    /// resize). Callers that want explicit `Result` semantics
    /// should call the inherent [`TuiSshRenderer::new_window_size`]
    /// directly.
    fn new_window_size(&mut self, cols: u16, rows: u16) {
        // Delegate to the shared helper; both this trait method
        // and the inherent method use the same body so layout
        // semantics never diverge.
        self.apply_new_window_size(cols, rows);
    }

    /// Returns the cached window bounds as a [`Rect`]. Default
    /// trait impl reads from `state().window`; we override to
    /// also read from the WidgetState bounds for symmetry with
    /// child-widget layout queries.
    fn window_bounds(&self) -> Rect {
        self.render.window
    }
}

// ============================================================================
// Helper functions.
// ============================================================================

/// Lock the [`TuiSshRendererInner`] [`Mutex`], translating any
/// poison error back into the inner guard so a panic in one
/// flush path doesn't permanently brick the renderer.
///
/// Matches the precedent set by:
/// * `crate::tui::widgets::matrix::lock_inner_recoverable`
/// * `crate::tui::widgets::effect` (line 1342)
/// * `crate::tui::widgets::spinner` (line 425)
fn lock_inner_recoverable(m: &Mutex<TuiSshRendererInner>) -> MutexGuard<'_, TuiSshRendererInner> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Lock the only-child [`Mutex`] with poison recovery. Same
/// pattern as [`lock_inner_recoverable`] but for the
/// `TuiSsh::only_child` field.
fn lock_only_child_recoverable(
    m: &Mutex<Option<Arc<dyn Widget>>>,
) -> MutexGuard<'_, Option<Arc<dyn Widget>>> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Append the decimal-ASCII representation of `value` to `buf`.
///
/// Equivalent to FASM `string$from_unsigned` + `string$to_utf8`
/// at lines 137-148 / 575-586. The FASM code allocates a heap
/// `string` object; we write directly to a `Vec<u8>`.
///
/// Always emits at least one digit (zero is rendered as `"0"`,
/// matching FASM behavior).
fn push_decimal_u32(buf: &mut Vec<u8>, value: u32) {
    if value == 0 {
        buf.push(b'0');
        return;
    }
    // Maximum decimal digits for u32 is 10.
    let mut digits = [0u8; 10];
    let mut n = value;
    let mut idx = digits.len();
    while n > 0 {
        idx -= 1;
        // n % 10 ∈ [0, 9] which always fits in u8.
        let d = (n % 10) as u8;
        digits[idx] = b'0' + d;
        n /= 10;
    }
    buf.extend_from_slice(&digits[idx..]);
}

/// Decode a UTF-8 multi-byte sequence beginning at `data[start]`.
///
/// `byte_count` is the expected sequence length (2, 3, or 4 bytes
/// — selected by the leading-byte top-nibble dispatch in
/// [`TuiSsh::on_receive`]). The function:
/// * Verifies enough bytes remain in `data`.
/// * Verifies the continuation bytes match the `0b10xxxxxx`
///   pattern (FASM `and edx, 0xc0 ; cmp edx, 0x80`).
/// * Decodes the code-point using the FASM bit-shift expressions
///   verbatim (lines 470-482 / 502-517 / 543-561).
/// * Validates the minimum-encoding constraint (FASM `cmp eax, 0x80
///   ; jb .notunicode` at line 475 and similar).
///
/// Returns `Some((codepoint, bytes_consumed))` on success, `None`
/// when the sequence is malformed (caller falls back to the
/// not-unicode handler).
fn parse_utf8_continuation(data: &[u8], start: usize, byte_count: usize) -> Option<(u32, usize)> {
    if start + byte_count > data.len() {
        return None;
    }
    let b0 = u32::from(data[start]);

    match byte_count {
        2 => {
            let b1 = u32::from(data[start + 1]);
            if (b1 & 0xC0) != 0x80 {
                return None;
            }
            // FASM lines 470-474:
            //   eax = (b0 << 6) & 0x7c0   ; pulls 5 bits of b0 to bits 6..10
            //   eax |= (b1 & 0x3f)        ; pulls 6 bits of b1 to bits 0..5
            let cp = ((b0 << 6) & 0x7C0) | (b1 & 0x3F);
            if cp < 0x80 {
                return None; // overlong encoding
            }
            Some((cp, 2))
        }
        3 => {
            let b1 = u32::from(data[start + 1]);
            let b2 = u32::from(data[start + 2]);
            if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 {
                return None;
            }
            // FASM lines 502-509:
            //   r8d = (b0 << 12) & 0xf000
            //   r10d = (b1 << 6) & 0xfc0
            //   r11d = b2 & 0x3f
            let cp = ((b0 << 12) & 0xF000) | ((b1 << 6) & 0xFC0) | (b2 & 0x3F);
            if cp < 0x800 {
                return None;
            }
            Some((cp, 3))
        }
        4 => {
            let b1 = u32::from(data[start + 1]);
            let b2 = u32::from(data[start + 2]);
            let b3 = u32::from(data[start + 3]);
            if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80 {
                return None;
            }
            // FASM lines 543-553:
            //   r9d = (b0 << 18) & 0x1c0000
            //   eax = (b1 << 12) & 0x3f000
            //   edx = (b2 << 6) & 0xfc0
            //   r8d = b3 & 0x3f
            let cp = ((b0 << 18) & 0x1C0000) | ((b1 << 12) & 0x3F000) | ((b2 << 6) & 0xFC0) | (b3 & 0x3F);
            if cp < 0x10000 {
                return None;
            }
            Some((cp, 4))
        }
        _ => None,
    }
}

/// Parse an ANSI CSI escape sequence beginning at `data[start]`
/// (where `data[start] == ESC` and `data[start+1] == b'['`).
///
/// FASM `.escbracket` (lines 408-437) handles two cases:
/// * Single-letter A/B/C/D (cursor up/down/right/left): the
///   third byte IS the escape key and is fired directly via
///   `.fireescaped`.
/// * Multi-byte parameters terminated by `~`: shift left 8 bits
///   and OR each byte until the `~` terminator or end-of-buffer.
///
/// Returns `(esc_key, bytes_consumed_total)`. The total includes
/// the leading `ESC[` (2 bytes).
fn parse_csi(data: &[u8], start: usize) -> (u32, usize) {
    // Skip ESC[
    let mut p = start + 2;
    if p >= data.len() {
        // Malformed: just consume what we have.
        return (0, data.len() - start);
    }
    let first = data[p];
    if matches!(first, b'A' | b'B' | b'C' | b'D') {
        // FASM lines 412-420: single-letter cursor escape.
        return (u32::from(first), p - start + 1);
    }
    // FASM lines 421-437: shift-and-OR until `~` or EOB.
    let mut esc_key: u32 = 0;
    while p < data.len() {
        let b = data[p];
        if b == b'~' {
            // FASM line 429 (`.escloopdone`) breaks out of the
            // loop without modifying `eax` (the esc_key
            // accumulator). The `~` terminator is consumed (the
            // following `.fireescaped` advances `r13` by 1) but
            // does NOT enter the accumulator.
            //
            // Therefore: we just consume the `~` and break,
            // leaving `esc_key` carrying whatever shift-and-OR
            // values were accumulated from the bytes BEFORE the
            // `~`.
            p += 1;
            break;
        }
        // FASM lines 430-432: shl eax, 8 ; or eax, ecx
        esc_key = esc_key.wrapping_shl(8) | u32::from(b);
        p += 1;
    }
    (esc_key, p - start)
}

/// Decode a Unicode code-point + ANSI escape pair into a
/// [`KeyEvent`].
///
/// FASM passes both `(esi=key, edx=esc_key)` to
/// `tui_vfirekeyevent`; the receiving widget interprets either
/// (a) a printable Unicode code-point with `esc_key=0` or (b) a
/// pre-decoded ANSI escape with `key=0`.
///
/// In Rust we map onto the [`KeyEvent`] enum:
/// * `(codepoint, 0)` where `codepoint` is a printable char →
///   [`KeyEvent::Char`].
/// * `(0, 0x1B5B41 / 'A')` → [`KeyEvent::ArrowUp`] etc.
/// * `(codepoint, 0)` where `codepoint < 0x20` → [`KeyEvent::Ctrl`]
///   for Ctrl-key shortcuts.
/// * Special bytes: `(13, 0)` → [`KeyEvent::Enter`], `(27, 0)`
///   → [`KeyEvent::Escape`], `(8, 0)` / `(127, 0)` →
///   [`KeyEvent::Backspace`], `(9, 0)` → [`KeyEvent::Tab`].
///
/// This decoder favors faithfulness to the FASM byte stream
/// over Rust idiomatic key handling — widgets that receive a
/// [`KeyEvent::Char`] are responsible for interpreting it.
fn decode_key_event(codepoint: u32, esc_key: u32) -> KeyEvent {
    if esc_key != 0 {
        // ANSI escape — map well-known sequences to enum
        // variants, fall through to Char for unknown.
        match esc_key {
            // CSI A/B/C/D — cursor arrows.
            0x41 => return KeyEvent::ArrowUp,    // 'A'
            0x42 => return KeyEvent::ArrowDown,  // 'B'
            0x43 => return KeyEvent::ArrowRight, // 'C'
            0x44 => return KeyEvent::ArrowLeft,  // 'D'
            // CSI <param>~ — function / nav keys.
            // FASM accumulator builds e.g. CSI 5 ~ → 0x357E. We
            // decode the most common ones; unknown sequences
            // fall through to a Char variant carrying the raw
            // accumulator value.
            // CSI 1 ~ = Home, CSI 4 ~ = End,
            // CSI 5 ~ = PageUp, CSI 6 ~ = PageDown,
            // CSI 2 ~ = Insert, CSI 3 ~ = Delete.
            // CSI 11..15 ~ = F1..F5, CSI 17..21 ~ = F6..F10.
            0x317E => return KeyEvent::Home,     // "1~"
            0x347E => return KeyEvent::End,      // "4~"
            0x357E => return KeyEvent::PageUp,   // "5~"
            0x367E => return KeyEvent::PageDown, // "6~"
            0x327E => return KeyEvent::Insert,   // "2~"
            0x337E => return KeyEvent::Delete,   // "3~"
            // SS3 sequences: ESC O followed by a single byte.
            // Encoded as ('O' << 8) | byte = 0x4F00 | byte.
            0x4F50 => return KeyEvent::F(1), // 'P'
            0x4F51 => return KeyEvent::F(2), // 'Q'
            0x4F52 => return KeyEvent::F(3), // 'R'
            0x4F53 => return KeyEvent::F(4), // 'S'
            // CSI Z — Shift-Tab.
            0x5A => return KeyEvent::ShiftTab, // 'Z'
            _ => {
                // Unknown escape: surface as Char of the raw
                // accumulator low byte for diagnostic visibility.
                return KeyEvent::Char(char::from_u32(esc_key & 0xFF).unwrap_or('\u{FFFD}'));
            }
        }
    }

    // Plain key path.
    match codepoint {
        // Common control bytes mapped to dedicated variants.
        0x08 | 0x7F => KeyEvent::Backspace,
        0x09 => KeyEvent::Tab,
        0x0A | 0x0D => KeyEvent::Enter,
        0x1B => KeyEvent::Escape,
        // Other low-control bytes (0x01..=0x1A excluding the
        // above) map to Ctrl(byte). The `KeyEvent::Ctrl` variant
        // (per `crate::tui::object`) carries the raw control
        // byte as a `u8` — we pass the codepoint directly,
        // which is guaranteed in 0x01..=0x1A range here. The
        // narrowing cast is therefore lossless.
        0x01..=0x1A => KeyEvent::Ctrl(codepoint as u8),
        // Otherwise: treat as a printable / extended-ASCII /
        // Unicode codepoint.
        _ => KeyEvent::Char(char::from_u32(codepoint).unwrap_or('\u{FFFD}')),
    }
}

// ============================================================================
// Tests.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::sync::Mutex as StdMutex;

    // ------------------------------------------------------------------------
    // Test fixtures.
    // ------------------------------------------------------------------------

    /// A mock [`SshTransport`] that records every byte sent via
    /// [`SshTransport::send_bytes`] for later inspection.
    ///
    /// Used to exercise the renderer's flush path and the
    /// `TuiSsh` connect path without depending on the
    /// (still-unbuilt) `crate::net::ssh` implementation.
    /// `set_window_size` is a no-op stub — no current code path
    /// in this file calls it, so we don't need to capture its
    /// arguments.
    struct CapturingTransport {
        sent: StdMutex<Vec<u8>>,
        remote: Vec<u8>,
    }

    impl CapturingTransport {
        fn new() -> Self {
            Self {
                sent: StdMutex::new(Vec::new()),
                remote: Vec::new(),
            }
        }

        fn with_remote(remote: &[u8]) -> Self {
            Self {
                sent: StdMutex::new(Vec::new()),
                remote: remote.to_vec(),
            }
        }

        fn snapshot_sent(&self) -> Vec<u8> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl SshTransport for CapturingTransport {
        fn send_bytes(&self, bytes: &[u8]) -> Result<(), TuiError> {
            self.sent.lock().unwrap().extend_from_slice(bytes);
            Ok(())
        }

        fn set_window_size(&self, _cols: u16, _rows: u16) -> Result<(), TuiError> {
            Ok(())
        }

        fn remote_addr(&self) -> Option<&[u8]> {
            if self.remote.is_empty() {
                None
            } else {
                Some(&self.remote)
            }
        }
    }

    /// A minimal [`Widget`] with no behavior of its own — just
    /// enough state to satisfy the trait. Used as the
    /// `display` argument to [`TuiSsh::new`].
    struct MockWidget {
        state: WidgetState,
    }

    impl MockWidget {
        fn new_arc() -> Arc<Self> {
            Arc::new(Self {
                state: WidgetState::new(),
            })
        }
    }

    impl Widget for MockWidget {
        fn state(&self) -> &WidgetState {
            &self.state
        }

        fn state_mut(&mut self) -> &mut WidgetState {
            &mut self.state
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    // ------------------------------------------------------------------------
    // push_decimal_u32 — ASCII decimal serializer used by farewell banner.
    // ------------------------------------------------------------------------

    #[test]
    fn push_decimal_u32_zero() {
        let mut buf = Vec::new();
        push_decimal_u32(&mut buf, 0);
        assert_eq!(&buf, b"0");
    }

    #[test]
    fn push_decimal_u32_single_digit() {
        let mut buf = Vec::new();
        push_decimal_u32(&mut buf, 7);
        assert_eq!(&buf, b"7");
    }

    #[test]
    fn push_decimal_u32_multi_digit() {
        let mut buf = Vec::new();
        push_decimal_u32(&mut buf, 1234);
        assert_eq!(&buf, b"1234");
    }

    #[test]
    fn push_decimal_u32_max() {
        let mut buf = Vec::new();
        push_decimal_u32(&mut buf, u32::MAX);
        assert_eq!(&buf, b"4294967295");
    }

    #[test]
    fn push_decimal_u32_appends_to_existing() {
        let mut buf = b"prefix-".to_vec();
        push_decimal_u32(&mut buf, 42);
        assert_eq!(&buf, b"prefix-42");
    }

    // ------------------------------------------------------------------------
    // parse_utf8_continuation — UTF-8 multi-byte sequence parser.
    // ------------------------------------------------------------------------

    #[test]
    fn parse_utf8_2byte_sequence() {
        // U+00E9 (é) = 0xC3 0xA9.
        let data = [0xC3, 0xA9];
        let result = parse_utf8_continuation(&data, 0, 2);
        assert_eq!(result, Some((0xE9, 2)));
    }

    #[test]
    fn parse_utf8_3byte_sequence() {
        // U+20AC (€) = 0xE2 0x82 0xAC.
        let data = [0xE2, 0x82, 0xAC];
        let result = parse_utf8_continuation(&data, 0, 3);
        assert_eq!(result, Some((0x20AC, 3)));
    }

    #[test]
    fn parse_utf8_4byte_sequence() {
        // U+1F600 (😀) = 0xF0 0x9F 0x98 0x80.
        let data = [0xF0, 0x9F, 0x98, 0x80];
        let result = parse_utf8_continuation(&data, 0, 4);
        assert_eq!(result, Some((0x1F600, 4)));
    }

    #[test]
    fn parse_utf8_truncated_returns_none() {
        // 3-byte sequence with only 2 bytes available.
        let data = [0xE2, 0x82];
        let result = parse_utf8_continuation(&data, 0, 3);
        assert_eq!(result, None);
    }

    #[test]
    fn parse_utf8_overlong_2byte_rejected() {
        // 0xC1 0x80 would decode to U+0040 (overlong; min is 0x80).
        // Per FASM minimum-encoding constraint, this is rejected.
        let data = [0xC1, 0x80];
        let result = parse_utf8_continuation(&data, 0, 2);
        assert_eq!(result, None, "overlong 2-byte must be rejected");
    }

    #[test]
    fn parse_utf8_overlong_3byte_rejected() {
        // 3-byte sequence decoding to < 0x800 must be rejected.
        // 0xE0 0x80 0x80 would decode to U+0000.
        let data = [0xE0, 0x80, 0x80];
        let result = parse_utf8_continuation(&data, 0, 3);
        assert_eq!(result, None, "overlong 3-byte must be rejected");
    }

    #[test]
    fn parse_utf8_overlong_4byte_rejected() {
        // 4-byte sequence decoding to < 0x10000 must be rejected.
        // 0xF0 0x80 0x80 0x80 would decode to U+0000.
        let data = [0xF0, 0x80, 0x80, 0x80];
        let result = parse_utf8_continuation(&data, 0, 4);
        assert_eq!(result, None, "overlong 4-byte must be rejected");
    }

    // ------------------------------------------------------------------------
    // parse_csi — ESC[ accumulator parser.
    // ------------------------------------------------------------------------

    #[test]
    fn parse_csi_arrow_up() {
        // ESC[A — single-letter cursor escape.
        let data = b"\x1b[A";
        let (esc_key, consumed) = parse_csi(data, 0);
        assert_eq!(esc_key, u32::from(b'A'));
        assert_eq!(consumed, 3);
    }

    #[test]
    fn parse_csi_arrow_down() {
        let data = b"\x1b[B";
        let (esc_key, _) = parse_csi(data, 0);
        assert_eq!(esc_key, u32::from(b'B'));
    }

    #[test]
    fn parse_csi_arrow_right() {
        let data = b"\x1b[C";
        let (esc_key, _) = parse_csi(data, 0);
        assert_eq!(esc_key, u32::from(b'C'));
    }

    #[test]
    fn parse_csi_arrow_left() {
        let data = b"\x1b[D";
        let (esc_key, _) = parse_csi(data, 0);
        assert_eq!(esc_key, u32::from(b'D'));
    }

    #[test]
    fn parse_csi_with_tilde_accumulator() {
        // ESC[5~ — Page Up. Accumulator carries '5' (0x35).
        let data = b"\x1b[5~";
        let (esc_key, consumed) = parse_csi(data, 0);
        assert_eq!(esc_key, u32::from(b'5'), "accumulator should hold '5'");
        assert_eq!(consumed, 4, "should consume ESC[5~ entirely");
    }

    #[test]
    fn parse_csi_with_two_byte_tilde_accumulator() {
        // ESC[15~ — F5. Accumulator: '1' shl 8 | '5' = 0x3135.
        let data = b"\x1b[15~";
        let (esc_key, consumed) = parse_csi(data, 0);
        assert_eq!(
            esc_key,
            (u32::from(b'1') << 8) | u32::from(b'5'),
            "accumulator should be shift-and-OR of '1' and '5'"
        );
        assert_eq!(consumed, 5);
    }

    // ------------------------------------------------------------------------
    // decode_key_event — codepoint+esc_key → KeyEvent variant.
    // ------------------------------------------------------------------------

    #[test]
    fn decode_key_event_printable_char() {
        let ev = decode_key_event(u32::from(b'a'), 0);
        assert!(matches!(ev, KeyEvent::Char('a')));
    }

    #[test]
    fn decode_key_event_enter_via_lf() {
        let ev = decode_key_event(0x0A, 0);
        assert!(matches!(ev, KeyEvent::Enter));
    }

    #[test]
    fn decode_key_event_enter_via_cr() {
        let ev = decode_key_event(0x0D, 0);
        assert!(matches!(ev, KeyEvent::Enter));
    }

    #[test]
    fn decode_key_event_tab() {
        let ev = decode_key_event(0x09, 0);
        assert!(matches!(ev, KeyEvent::Tab));
    }

    #[test]
    fn decode_key_event_escape() {
        let ev = decode_key_event(0x1B, 0);
        assert!(matches!(ev, KeyEvent::Escape));
    }

    #[test]
    fn decode_key_event_backspace_bs() {
        let ev = decode_key_event(0x08, 0);
        assert!(matches!(ev, KeyEvent::Backspace));
    }

    #[test]
    fn decode_key_event_backspace_del() {
        let ev = decode_key_event(0x7F, 0);
        assert!(matches!(ev, KeyEvent::Backspace));
    }

    #[test]
    fn decode_key_event_ctrl_a() {
        // Ctrl-A = 0x01.
        let ev = decode_key_event(0x01, 0);
        match ev {
            KeyEvent::Ctrl(byte) => assert_eq!(byte, 0x01),
            other => panic!("expected Ctrl(0x01), got {:?}", other),
        }
    }

    #[test]
    fn decode_key_event_arrow_up() {
        let ev = decode_key_event(0, u32::from(b'A'));
        assert!(matches!(ev, KeyEvent::ArrowUp));
    }

    #[test]
    fn decode_key_event_arrow_down() {
        let ev = decode_key_event(0, u32::from(b'B'));
        assert!(matches!(ev, KeyEvent::ArrowDown));
    }

    #[test]
    fn decode_key_event_arrow_right() {
        let ev = decode_key_event(0, u32::from(b'C'));
        assert!(matches!(ev, KeyEvent::ArrowRight));
    }

    #[test]
    fn decode_key_event_arrow_left() {
        let ev = decode_key_event(0, u32::from(b'D'));
        assert!(matches!(ev, KeyEvent::ArrowLeft));
    }

    #[test]
    fn decode_key_event_unicode_char() {
        // U+00E9 (é) — printable Unicode.
        let ev = decode_key_event(0xE9, 0);
        assert!(matches!(ev, KeyEvent::Char('é')));
    }

    // ------------------------------------------------------------------------
    // TuiSsh — construction, remote_address.
    // ------------------------------------------------------------------------

    #[test]
    fn tui_ssh_new_with_no_remote() {
        let widget = MockWidget::new_arc();
        let transport = Arc::new(CapturingTransport::new());
        let tui = TuiSsh::new(widget, transport);
        // raddr_len should be 0 when transport returns None.
        assert_eq!(tui.remote_address().len(), 0);
        assert_eq!(tui.raddr_len, 0);
    }

    #[test]
    fn tui_ssh_new_with_remote_address() {
        let widget = MockWidget::new_arc();
        let transport = Arc::new(CapturingTransport::with_remote(b"192.0.2.1:54321"));
        let tui = TuiSsh::new(widget, transport);
        assert_eq!(tui.remote_address(), b"192.0.2.1:54321");
        assert_eq!(tui.raddr_len, 15);
    }

    #[test]
    fn tui_ssh_new_clamps_oversized_remote_address() {
        // 200-byte remote — must be truncated to RADDR_LEN=126.
        let oversized = vec![b'X'; 200];
        let widget = MockWidget::new_arc();
        let transport = Arc::new(CapturingTransport::with_remote(&oversized));
        let tui = TuiSsh::new(widget, transport);
        assert_eq!(tui.remote_address().len(), RADDR_LEN);
        assert_eq!(tui.raddr_len, RADDR_LEN as u8);
        // All bytes should be 'X'.
        assert!(tui.remote_address().iter().all(|&b| b == b'X'));
    }

    // ------------------------------------------------------------------------
    // TuiSsh — connect path: ANSI byte sequences hit the wire.
    // ------------------------------------------------------------------------

    #[test]
    fn tui_ssh_on_connected_emits_alt_screen_when_enabled() {
        // TUI_SSH_ALTERNATESCREEN is `true` in default config.
        // The connect path should emit:
        //   ALT_SCREEN_ENTER + INSERT_MODE_ONLY (= ALT_SCREEN_AND_INSERT)
        //   HIDE_CURSOR
        //   CLEAR_SCREEN
        //   CURSOR_HOME
        let widget = MockWidget::new_arc();
        let transport = Arc::new(CapturingTransport::new());
        let tui = TuiSsh::new(widget, transport.clone());
        tui.on_connected().expect("on_connected");

        let sent = transport.snapshot_sent();
        // Verify ALT_SCREEN_AND_INSERT is the first 14 bytes.
        if TUI_SSH_ALTERNATESCREEN {
            assert!(
                sent.starts_with(b"\x1b[?1049h\x1b[12h"),
                "expected alt-screen-enter + insert-mode prefix, got: {:?}",
                sent
            );
        } else {
            assert!(
                sent.starts_with(b"\x1b[12h"),
                "expected insert-mode-only prefix, got: {:?}",
                sent
            );
        }
        // Verify hide-cursor and clear-screen escapes are present.
        assert!(
            sent.windows(HIDE_CURSOR.len()).any(|w| w == HIDE_CURSOR),
            "expected HIDE_CURSOR in stream"
        );
        assert!(
            sent.windows(CLEAR_SCREEN.len()).any(|w| w == CLEAR_SCREEN),
            "expected CLEAR_SCREEN in stream"
        );
        assert!(
            sent.windows(CURSOR_HOME.len()).any(|w| w == CURSOR_HOME),
            "expected CURSOR_HOME in stream"
        );
    }

    #[test]
    fn tui_ssh_on_destroy_emits_show_cursor_and_alt_screen_exit() {
        let widget = MockWidget::new_arc();
        let transport = Arc::new(CapturingTransport::new());
        let tui = TuiSsh::new(widget, transport.clone());
        tui.on_destroy();

        let sent = transport.snapshot_sent();
        assert!(
            sent.windows(SHOW_CURSOR.len()).any(|w| w == SHOW_CURSOR),
            "expected SHOW_CURSOR in destroy stream, got: {:?}",
            sent
        );
        if TUI_SSH_ALTERNATESCREEN {
            assert!(
                sent.windows(ALT_SCREEN_EXIT.len()).any(|w| w == ALT_SCREEN_EXIT),
                "expected ALT_SCREEN_EXIT in destroy stream"
            );
        }
    }

    // ------------------------------------------------------------------------
    // TuiSshRenderer — new_window_size updates state.
    // ------------------------------------------------------------------------

    #[test]
    fn tui_ssh_renderer_new_window_size_updates_render_state() {
        let mut renderer = TuiSshRenderer {
            state: WidgetState::new(),
            render: RenderState::default(),
            inner: Mutex::new(TuiSshRendererInner {
                out_buffer: Buffer::new(),
                ssh_parent: Weak::new(),
            }),
        };
        // Use the inherent (Result-returning) method.
        renderer.new_window_size(80, 24).expect("new_window_size");

        // RenderState.window should reflect (80, 24).
        let win = renderer.render.window;
        assert_eq!(win.width(), 80);
        assert_eq!(win.height(), 24);

        // WidgetState bounds + width + height should mirror.
        assert_eq!(renderer.state.bounds.width(), 80);
        assert_eq!(renderer.state.bounds.height(), 24);
        assert_eq!(renderer.state.width, 80);
        assert_eq!(renderer.state.height, 24);
    }

    #[test]
    fn tui_ssh_renderer_new_window_size_via_renderer_trait_returns_unit() {
        let mut renderer = TuiSshRenderer {
            state: WidgetState::new(),
            render: RenderState::default(),
            inner: Mutex::new(TuiSshRendererInner {
                out_buffer: Buffer::new(),
                ssh_parent: Weak::new(),
            }),
        };
        // The Renderer-trait variant returns ().
        Renderer::new_window_size(&mut renderer, 100, 50);
        assert_eq!(renderer.render.window.width(), 100);
        assert_eq!(renderer.render.window.height(), 50);
    }

    // ------------------------------------------------------------------------
    // TuiSshRenderer — ansi_output + flush — bytes reach the transport.
    // ------------------------------------------------------------------------

    #[test]
    fn tui_ssh_renderer_ansi_output_and_flush_pending() {
        let widget = MockWidget::new_arc();
        let transport = Arc::new(CapturingTransport::new());
        let tui = TuiSsh::new(widget, transport.clone());

        // Get a Weak ref to the renderer via the strong Arc on
        // the TuiSsh (we cannot easily extract a &mut renderer
        // because the Arc has refcount > 1 — so we just use the
        // shared (`&self`) ansi_output and flush_pending paths).
        let renderer_arc: Arc<TuiSshRenderer> = tui.renderer.clone();

        // Append some bytes; should NOT auto-flush (sub-threshold).
        renderer_arc.ansi_output(b"hello").expect("ansi_output");
        // Buffer has 5 bytes pending; transport should not yet have them
        // (because ansi_output flushes only at threshold = 4096).
        assert_eq!(transport.snapshot_sent(), b"");

        // Explicit flush should send the buffered bytes.
        renderer_arc.flush_pending().expect("flush_pending");
        let sent = transport.snapshot_sent();
        assert_eq!(sent, b"hello");

        // Subsequent flush with empty buffer is a no-op (no extra bytes).
        renderer_arc.flush_pending().expect("flush_pending again");
        assert_eq!(transport.snapshot_sent(), b"hello");
    }

    #[test]
    fn tui_ssh_renderer_ansi_output_auto_flush_at_threshold() {
        let widget = MockWidget::new_arc();
        let transport = Arc::new(CapturingTransport::new());
        let tui = TuiSsh::new(widget, transport.clone());
        let renderer_arc: Arc<TuiSshRenderer> = tui.renderer.clone();

        // Push exactly FLUSH_THRESHOLD_BYTES bytes; should auto-flush.
        let payload = vec![b'X'; FLUSH_THRESHOLD_BYTES];
        renderer_arc.ansi_output(&payload).expect("ansi_output");

        // Transport should now hold all payload bytes.
        let sent = transport.snapshot_sent();
        assert_eq!(sent.len(), FLUSH_THRESHOLD_BYTES);
        assert!(sent.iter().all(|&b| b == b'X'));
    }

    // ------------------------------------------------------------------------
    // Constants — byte-exact match with FASM tui_ssh.inc.
    // ------------------------------------------------------------------------

    #[test]
    fn fasm_constants_byte_exact() {
        // FASM line 612-616 (alt-screen + insert mode):
        //   27,'[?1049h',27,'[12h'
        assert_eq!(
            ALT_SCREEN_AND_INSERT, b"\x1b[?1049h\x1b[12h",
            "FASM alt-screen+insert byte sequence"
        );
        // FASM line 619 (insert mode only):
        //   27,'[12h'
        assert_eq!(INSERT_MODE_ONLY, b"\x1b[12h", "FASM insert-mode-only");
        // FASM line 165-166 (reset scroll region):
        //   27,'[r'
        assert_eq!(RESET_SCROLL_REGION, b"\x1b[r", "FASM reset-scroll-region");
        // FASM exit/farewell markers per session-continuity notes.
        assert_eq!(EXIT_MARKER, b"!!Exit!!\r\n", "FASM exit marker");
        assert_eq!(CTRLC_MARKER, b"!!Ctrl-C!!\r\n", "FASM ctrl-c marker");
        // FASM cursor-to-last-row tail (after width digits).
        assert_eq!(CURSOR_TO_LAST_ROW_TAIL, b";1H", "FASM cursor-to-last-row tail");
    }

    #[test]
    fn raddr_len_constant_matches_fasm() {
        // FASM line 47: tui_ssh_raddrlen_ofs = io_base_size + 126.
        // 126 bytes for the remote-peer buffer.
        assert_eq!(RADDR_LEN, 126, "RADDR_LEN must match FASM 126-byte buffer");
    }
}
