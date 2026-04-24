// crates/heavything/src/tui/terminal.rs — HeavyThing terminal raw-mode singleton.
//
// Rust translation of tui_terminal.inc (1,024 lines of FASM assembly).
// Manages the process-wide raw-mode terminal state: enters raw mode on
// startup via libc::tcsetattr, queries window size via libc::ioctl
// TIOCGWINSZ, installs signal handlers for SIGWINCH/SIGTERM/SIGINT, and
// restores cooked mode on exit (including signal-driven paths).
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

//! Terminal raw-mode management through direct `libc::termios` syscalls.
//!
//! Per AAP §0.7.3, this module is the **only** place in `heavything` that
//! performs termios and ioctl operations on [`libc::STDIN_FILENO`]. All
//! `unsafe` blocks are encapsulated behind safe methods on [`RawTerminal`]
//! and accounted for in `UNSAFE_AUDIT.md`.
//!
//! # Invariants
//!
//! - The terminal is managed as a **process-wide singleton**. Calling
//!   [`RawTerminal::enter`] more than once returns
//!   [`crate::error::TuiError::Termios`] wrapping
//!   [`std::io::ErrorKind::AlreadyExists`].
//! - On [`RawTerminal`] drop, the original termios is restored, the
//!   alternate-screen buffer (when used) is disabled, and the cursor is
//!   re-shown.
//! - Signal handlers for `SIGINT`, `SIGTERM`, `SIGWINCH`, and crash
//!   signals (`SIGSEGV`, `SIGABRT`) are installed at enter time.
//!   Handlers are async-signal-safe: they perform only atomic stores,
//!   `libc::write`, and `libc::_exit` / `libc::raise`.
//!
//! # Correspondence with `tui_terminal.inc`
//!
//! FASM function | Rust equivalent
//! --- | ---
//! `tui_terminal$new` (singleton init + sigwinch/sigterm install) | [`RawTerminal::enter`]
//! `stdio_winch` (SIGWINCH handler) | [`sigwinch_handler`]
//! `stdio_term` (SIGTERM handler) | [`sigterm_handler`]
//! `tui_terminal$cleanup` (TCSETSF restore, alt-screen exit) | [`RawTerminal`] `Drop`
//! `tui_terminal$keyevent` Ctrl-C path | [`sigint_handler`] (signal-driven exit with 130)

use std::io::{self, Write};
use std::mem::{self, MaybeUninit};
use std::os::fd::RawFd;
use std::ptr::{self, addr_of, addr_of_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use libc::{
    c_int, c_void, cfmakeraw, ioctl, sigaction, sigemptyset, sighandler_t, siginfo_t, tcgetattr, tcsetattr,
    termios, winsize, SA_RESTART, SA_SIGINFO, SIGABRT, SIGINT, SIGSEGV, SIGTERM, SIGWINCH, SIG_DFL,
    STDIN_FILENO, STDOUT_FILENO, TCSANOW, TIOCGWINSZ,
};

use crate::config::TERMINAL_ALTERNATESCREEN;
use crate::error::TuiError;
use crate::tui::ansi;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Process-wide flag: `true` while raw mode is active. Set by
/// [`RawTerminal::enter`] on success, cleared by [`RawTerminal`] `Drop`
/// or by [`cleanup_terminal_from_signal`] when a signal terminates the
/// process.
///
/// Signal handlers read this flag (async-signal-safely via
/// [`AtomicBool::load`]) to skip cleanup if raw mode was never entered.
static RAW_MODE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Stored original termios for signal-handler restoration. Written
/// exactly once by [`RawTerminal::enter`] under [`INIT_GUARD`]
/// protection; read thereafter by [`cleanup_terminal_from_signal`].
///
/// # Safety invariant
///
/// Written once before any signal handler is installed (the
/// [`RawTerminal::enter`] call sequence runs the write, then installs
/// handlers, then returns). Because [`INIT_GUARD`] enforces a single
/// writer, there is no data race. All reads are via raw pointer to
/// avoid the `static_mut_refs` lint per Rust 2024 guidance.
static mut SAVED_TERMIOS: MaybeUninit<termios> = MaybeUninit::uninit();

/// One-shot initialization guard enforcing the singleton invariant:
/// [`OnceLock::set`] succeeds on the first call and fails on every
/// subsequent call. Together with [`SAVED_TERMIOS`], this gives us a
/// race-free single-writer semantics without any runtime lock cost.
static INIT_GUARD: OnceLock<()> = OnceLock::new();

/// SIGWINCH pending flag. Set by [`sigwinch_handler`] at signal-receipt
/// time; the event loop polls via [`RawTerminal::take_winch_pending`]
/// (which atomically swaps the flag to `false`) at a safe point and
/// re-queries [`RawTerminal::get_winsize`].
static WINCH_PENDING: AtomicBool = AtomicBool::new(false);

/// Graceful-exit-requested flag. Set by [`sigterm_handler`] or
/// [`sigint_handler`] before they trigger termios restore and
/// [`libc::_exit`]. The event loop may check this via
/// [`RawTerminal::exit_pending`] to break out of its poll loop
/// cooperatively, though the handlers also call `_exit` directly to
/// cover the case where the main thread is blocked.
static EXIT_PENDING: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// WindowSize
// ---------------------------------------------------------------------------

/// Terminal window dimensions reported by `ioctl(TIOCGWINSZ)`.
///
/// The FASM `stdio_winch` handler in `tui_terminal.inc` reads the same
/// `(ws_row, ws_col)` pair into `edx:esi` to fire the
/// `vnewwindowsize` virtual method (see lines 101–117 of the source).
/// This Rust port exposes the pair as a `Copy` struct so the value can
/// flow through widget sizing callbacks without borrowing gymnastics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowSize {
    /// Number of rows (`struct winsize::ws_row`).
    pub rows: u16,
    /// Number of columns (`struct winsize::ws_col`).
    pub cols: u16,
}

// ---------------------------------------------------------------------------
// RawTerminal
// ---------------------------------------------------------------------------

/// RAII handle to the process-wide raw-mode terminal.
///
/// Created by [`RawTerminal::enter`] (which performs all termios setup
/// and installs signal handlers) and restored automatically on drop
/// (which reverts termios, disables the alternate-screen buffer, and
/// re-shows the cursor). Because the terminal is a singleton, this
/// struct is `!Send` and `!Sync` in practice (its fields happen to be
/// `Send + Sync`, but the global [`INIT_GUARD`] prevents more than one
/// instance from existing at a time).
pub struct RawTerminal {
    /// File descriptor number for stdin (always [`libc::STDIN_FILENO`]
    /// today, but stored explicitly so the `Drop` impl does not depend
    /// on the constant being in scope).
    stdin_fd: RawFd,
    /// Original termios captured via `tcgetattr` in [`Self::enter`].
    /// Used by `Drop` to restore cooked mode. Held by-value (rather
    /// than reading from `SAVED_TERMIOS`) so the Drop path does not
    /// need any unsafe static access.
    original: termios,
    /// `true` when [`Self::enter`] emitted the `ESC[?1049h` alternate-
    /// screen enter sequence. If so, `Drop` emits `ESC[?1049l` to
    /// restore the user's prior screen contents.
    alternate_screen_entered: bool,
}

impl RawTerminal {
    /// Enters raw mode on stdin, emits the alternate-screen / clear /
    /// hide-cursor escape sequence, and installs signal handlers.
    ///
    /// Returns [`TuiError::Termios`] if any syscall fails. On failure
    /// after `tcgetattr` succeeded but `tcsetattr` failed, no termios
    /// change is visible to the user (the kernel atomically rejects
    /// the failed `tcsetattr`).
    ///
    /// This function may be called exactly **once per process**.
    /// Subsequent calls return [`TuiError::Termios`] wrapping
    /// [`io::ErrorKind::AlreadyExists`], preserving the FASM
    /// singleton contract (`_tui_terminal_singleton` non-zero check
    /// at line 197 of `tui_terminal.inc`).
    pub fn enter() -> Result<Self, TuiError> {
        if INIT_GUARD.set(()).is_err() {
            return Err(TuiError::Termios(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "RawTerminal already entered; terminal is a process-wide singleton",
            )));
        }

        let stdin_fd: RawFd = STDIN_FILENO;

        // SAFETY: Enter raw mode and publish the original termios for
        // signal-handler restoration, in four FFI / static-mut steps:
        //
        //  1. `tcgetattr(stdin_fd, &mut t)` fills a zero-initialized
        //     `termios` (POD; all-zeros is a valid starting state) with
        //     the current terminal attributes via its `&mut` argument.
        //     `stdin_fd` is valid for the life of the process.
        //  2. `cfmakeraw(&mut raw)` mutates a local copy in place; its
        //     Linux libc-0.2 binding returns void.
        //  3. `tcsetattr(stdin_fd, TCSANOW, &raw)` applies the new
        //     attributes atomically — on failure the kernel leaves the
        //     pre-existing cooked mode intact, so early return is safe.
        //  4. `addr_of_mut!(SAVED_TERMIOS).write(...)` publishes the
        //     saved termios to the static. `INIT_GUARD.set(())` above
        //     succeeded exactly once; we are the sole writer. No signal
        //     handlers are installed yet (that happens below), so no
        //     concurrent reader can observe partial state. Using
        //     `addr_of_mut!` avoids constructing a `&mut` reference to
        //     a `static mut`, silencing the `static_mut_refs` lint.
        //
        // `cfmakeraw` sets the same flag combination as the FASM source
        // (lines 308–316 of `tui_terminal.inc`): clears ECHO/ICANON/
        // IEXTEN/ISIG on `c_lflag`, BRKINT/ICRNL/ISTRIP on `c_iflag`,
        // CSIZE/PARENB on `c_cflag` then sets CS8, clears OPOST on
        // `c_oflag`, and sets `c_cc[VMIN]=0`, `c_cc[VTIME]=0`.
        let original: termios = unsafe {
            let mut t: termios = mem::zeroed();
            if tcgetattr(stdin_fd, &mut t) != 0 {
                return Err(TuiError::Termios(io::Error::last_os_error()));
            }
            let mut raw: termios = t;
            cfmakeraw(&mut raw);
            if tcsetattr(stdin_fd, TCSANOW, &raw) != 0 {
                return Err(TuiError::Termios(io::Error::last_os_error()));
            }
            addr_of_mut!(SAVED_TERMIOS).write(MaybeUninit::new(t));
            t
        };
        RAW_MODE_ACTIVE.store(true, Ordering::SeqCst);

        // Emit the setup sequence: [alternate-screen enter,] hide cursor,
        // clear screen, home cursor. Any write failure here is surfaced
        // as `TuiError::Render` — the raw mode is already applied but
        // the terminal is in a visibly broken state, so the caller
        // should treat this as fatal.
        let alternate_screen_entered = {
            let mut out = io::stdout().lock();
            let alt = TERMINAL_ALTERNATESCREEN;
            if alt {
                out.write_all(ansi::ALT_SCREEN_ENTER).map_err(TuiError::Render)?;
            }
            out.write_all(ansi::HIDE_CURSOR).map_err(TuiError::Render)?;
            out.write_all(ansi::CLEAR_SCREEN).map_err(TuiError::Render)?;
            out.write_all(ansi::CURSOR_HOME).map_err(TuiError::Render)?;
            out.flush().map_err(TuiError::Render)?;
            alt
        };

        // Install signal handlers last, so that `RAW_MODE_ACTIVE` and
        // `SAVED_TERMIOS` are both visible to handlers before they can
        // fire (per happens-before via the `SeqCst` store above).
        Self::install_signal_handlers()?;

        Ok(Self {
            stdin_fd,
            original,
            alternate_screen_entered,
        })
    }

    /// Queries the current terminal window size via `ioctl(TIOCGWINSZ)`.
    ///
    /// Returns [`TuiError::Winsize`] if the ioctl fails (typically
    /// `ENOTTY` when stdin is not a terminal — e.g., when the program
    /// is piped or run under a non-interactive harness).
    ///
    /// Mirrors the FASM winsize query path at lines 349–355 of
    /// `tui_terminal.inc` (`syscall_ioctl` with `TIOCGWINSZ=0x5413`).
    pub fn get_winsize(&self) -> Result<WindowSize, TuiError> {
        let mut ws: MaybeUninit<winsize> = MaybeUninit::uninit();

        // SAFETY: Two-step ioctl + field read:
        //  1. `ioctl(TIOCGWINSZ)` writes a full `struct winsize` into
        //     the storage backing `ws` when it returns 0. `self.stdin_fd`
        //     is valid for the life of the process; `ws.as_mut_ptr()`
        //     is correctly aligned for `struct winsize`.
        //  2. If the ioctl failed (non-zero rc) we return without
        //     touching `ws`. If it succeeded, `ws` is fully initialized
        //     and the dereference of `ws.as_ptr()` reads valid data.
        unsafe {
            let rc = ioctl(self.stdin_fd, TIOCGWINSZ, ws.as_mut_ptr());
            if rc != 0 {
                return Err(TuiError::Winsize(io::Error::last_os_error()));
            }
            let p: *const winsize = ws.as_ptr();
            Ok(WindowSize {
                rows: (*p).ws_row,
                cols: (*p).ws_col,
            })
        }
    }

    /// Returns `true` if a `SIGWINCH` has been received since the last
    /// check. Atomically clears the flag as a side effect, so the
    /// subsequent tick returns `false` unless another resize occurs.
    ///
    /// Intended for the event loop to call on a polling schedule —
    /// typical pattern: on each tick, if `take_winch_pending()` then
    /// call `get_winsize()` and propagate the new dimensions to the
    /// widget tree via its layout-changed callback (mirroring the FASM
    /// `tui_vnewwindowsize` virtual method).
    pub fn take_winch_pending(&self) -> bool {
        WINCH_PENDING.swap(false, Ordering::SeqCst)
    }

    /// Returns `true` if `SIGTERM` or `SIGINT` has been received.
    ///
    /// Note: the signal handlers also invoke [`libc::_exit`] after
    /// restoring the terminal, so in most cases the event loop never
    /// sees this flag transition — the process has already exited.
    /// This accessor is provided for cooperatively-cancelable loops
    /// that run off the main thread (e.g., tokio-driven timers) and
    /// want to detect the exit request before the kernel kills them.
    pub fn exit_pending() -> bool {
        EXIT_PENDING.load(Ordering::SeqCst)
    }

    /// Installs `sigaction` handlers for `SIGWINCH`, `SIGTERM`,
    /// `SIGINT`, `SIGSEGV`, and `SIGABRT`.
    ///
    /// The first three are critical: failure to install them is
    /// reported as [`TuiError::Termios`]. `SIGSEGV` / `SIGABRT`
    /// handlers are best-effort (terminal cleanup on crash) and
    /// installation failure is ignored.
    fn install_signal_handlers() -> Result<(), TuiError> {
        // SAFETY: `install_one` performs `sigaction` with a
        // well-defined async-signal-safe handler and a zeroed
        // `sa_mask`. Handlers do only atomic stores, direct `libc::
        // write`, and `_exit`/`raise`. The outer function runs on the
        // main thread before any tokio task is spawned.
        unsafe {
            install_one(SIGWINCH, sigwinch_handler).map_err(TuiError::Termios)?;
            install_one(SIGTERM, sigterm_handler).map_err(TuiError::Termios)?;
            install_one(SIGINT, sigint_handler).map_err(TuiError::Termios)?;
            // Crash-signal cleanup is best-effort.
            let _ = install_one(SIGSEGV, crash_handler);
            let _ = install_one(SIGABRT, crash_handler);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Signal handler installation helper
// ---------------------------------------------------------------------------

/// Installs a single `sigaction` for `sig`, directing it to `handler`.
///
/// Uses `SA_RESTART | SA_SIGINFO` so that (a) interrupted slow syscalls
/// restart transparently and (b) handlers receive the
/// `(sig, *mut siginfo_t, *mut c_void)` argument triple — the 3-arg
/// signature is required when `SA_SIGINFO` is set. Modern Linux
/// strongly prefers the `SA_SIGINFO` path (per `sigaction(2)`).
///
/// # Safety
///
/// - `handler` must be a valid `extern "C" fn(c_int, *mut siginfo_t,
///   *mut c_void)` pointer whose body is async-signal-safe.
/// - This function writes a zeroed `sigaction` struct, fills in the
///   required fields, and passes a `*const sigaction` to `libc::
///   sigaction`. The kernel copies the struct synchronously, so the
///   local `sa` may be dropped after the call.
unsafe fn install_one(
    sig: c_int,
    handler: extern "C" fn(c_int, *mut siginfo_t, *mut c_void),
) -> io::Result<()> {
    let mut sa: MaybeUninit<sigaction> = MaybeUninit::uninit();
    // SAFETY: zero-initialize the entire sigaction struct. `sigaction`
    // contains an `Option<extern "C" fn()>` in `sa_restorer` which
    // uses the null-pointer niche: all-zeros represents `None`, a
    // valid value. `sa_mask` (sigset_t) and `sa_flags` are POD.
    ptr::write_bytes(sa.as_mut_ptr().cast::<u8>(), 0, mem::size_of::<sigaction>());
    let p = sa.as_mut_ptr();
    (*p).sa_sigaction = handler as *const () as sighandler_t;
    (*p).sa_flags = SA_RESTART | SA_SIGINFO;
    sigemptyset(&mut (*p).sa_mask);

    // SAFETY: sigaction reads `sa.as_ptr()` synchronously. Passing
    // `null_mut()` for `oldact` means we are not retrieving the
    // previous handler (we do not need it). The return value is 0 on
    // success, -1 on failure with errno set.
    if sigaction(sig, sa.as_ptr(), ptr::null_mut()) != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Signal handler bodies (async-signal-safe)
// ---------------------------------------------------------------------------

// All handlers below use ONLY:
//   - atomic stores/loads on `AtomicBool`
//   - `libc::write` to STDOUT_FILENO
//   - `libc::_exit` (no `std::process::exit` — not async-signal-safe)
//   - `libc::raise` + `libc::sigaction(SIG_DFL, ...)` (for crash handler)
// No allocations, no mutex, no stdio, no println/eprintln.

/// `SIGWINCH` handler — terminal resized. Records the event for the
/// event loop to pick up on its next poll via
/// [`RawTerminal::take_winch_pending`].
extern "C" fn sigwinch_handler(_sig: c_int, _info: *mut siginfo_t, _ctx: *mut c_void) {
    // SAFETY for atomic store: async-signal-safe — `AtomicBool::store`
    // compiles to a single atomic instruction on x86_64.
    WINCH_PENDING.store(true, Ordering::SeqCst);
}

/// `SIGTERM` handler — graceful shutdown requested by an external
/// signal (e.g., `kill(pid, SIGTERM)` from a supervisor). Restores
/// termios and exits with status 0.
extern "C" fn sigterm_handler(_sig: c_int, _info: *mut siginfo_t, _ctx: *mut c_void) {
    EXIT_PENDING.store(true, Ordering::SeqCst);
    cleanup_terminal_from_signal();
    // SAFETY: `_exit` is async-signal-safe and terminates the process
    // without running destructors (which we explicitly want — we have
    // already restored the terminal via `cleanup_terminal_from_signal`,
    // and running other destructors from a signal context could
    // deadlock on mutexes held elsewhere in the program).
    unsafe { libc::_exit(0) };
}

/// `SIGINT` handler — user pressed Ctrl-C. Restores termios and exits
/// with POSIX status `128 + SIGINT = 130`. Mirrors the FASM
/// `tui_terminal$keyevent` Ctrl-C path (lines 387–420 of
/// `tui_terminal.inc`), which prints a banner and exits with a
/// different code; the Rust port uses the POSIX-conventional 130 so
/// shell `$?` matches user expectations.
extern "C" fn sigint_handler(_sig: c_int, _info: *mut siginfo_t, _ctx: *mut c_void) {
    EXIT_PENDING.store(true, Ordering::SeqCst);
    cleanup_terminal_from_signal();
    // SAFETY: `_exit` is async-signal-safe; see `sigterm_handler`.
    unsafe { libc::_exit(130) };
}

/// `SIGSEGV` / `SIGABRT` handler — best-effort terminal cleanup on
/// crash. After restoring termios, re-raises the signal through the
/// default handler so the kernel can produce a core dump.
extern "C" fn crash_handler(sig: c_int, _info: *mut siginfo_t, _ctx: *mut c_void) {
    cleanup_terminal_from_signal();
    // SAFETY: reset the signal handler to SIG_DFL then `raise` it.
    // `sigaction` and `raise` are both async-signal-safe. We use
    // `MaybeUninit::zeroed` via `write_bytes` to get an all-zeros
    // `sigaction` (valid because `sa_restorer`'s None representation
    // is all-zeros, and `SIG_DFL` is defined as `0 as sighandler_t`).
    // Once the default handler is installed, `raise(sig)` redelivers
    // the signal and the kernel dumps core / terminates the process.
    unsafe {
        let mut sa: MaybeUninit<sigaction> = MaybeUninit::uninit();
        ptr::write_bytes(sa.as_mut_ptr().cast::<u8>(), 0, mem::size_of::<sigaction>());
        (*sa.as_mut_ptr()).sa_sigaction = SIG_DFL;
        sigaction(sig, sa.as_ptr(), ptr::null_mut());
        libc::raise(sig);
    }
}

/// Best-effort terminal restore callable from a signal handler.
///
/// Uses only async-signal-safe primitives: [`AtomicBool`] ops,
/// [`libc::write`] (to STDOUT_FILENO) for the cursor/alternate-screen
/// restore sequence, and [`libc::tcsetattr`] for termios restore.
/// Reads [`SAVED_TERMIOS`] via raw pointer because:
///
/// 1. [`INIT_GUARD`] guarantees `SAVED_TERMIOS` was written exactly
///    once before any signal handler was installed.
/// 2. The write happens-before handler installation via `SeqCst`
///    `RAW_MODE_ACTIVE.store(true, ...)`.
/// 3. We only read if `RAW_MODE_ACTIVE.load() == true`, which
///    synchronizes with that store.
///
/// `MaybeUninit<termios>` is `#[repr(transparent)]` over `termios`,
/// so casting `*const MaybeUninit<termios>` to `*const termios` is
/// layout-sound.
fn cleanup_terminal_from_signal() {
    if !RAW_MODE_ACTIVE.load(Ordering::SeqCst) {
        return;
    }
    // Even if writes or the final tcsetattr partially fail, we keep
    // going: the whole path is best-effort from a crashing process.

    // SAFETY: `libc::write` and `libc::tcsetattr` are both
    // async-signal-safe (per POSIX `signal-safety(7)`). The byte
    // slices are `&'static [u8]` constants with valid pointers and
    // lengths. `STDOUT_FILENO` (1) and `STDIN_FILENO` (0) are valid
    // FDs for any process with an attached terminal. The cast from
    // `*const MaybeUninit<termios>` to `*const termios` is sound
    // because `MaybeUninit<T>` has the same layout as `T` and the
    // inner value is guaranteed initialized (see this fn's doc
    // comment for the happens-before argument).
    unsafe {
        let _ = libc::write(
            STDOUT_FILENO,
            ansi::SHOW_CURSOR.as_ptr() as *const c_void,
            ansi::SHOW_CURSOR.len(),
        );
        if TERMINAL_ALTERNATESCREEN {
            let _ = libc::write(
                STDOUT_FILENO,
                ansi::ALT_SCREEN_EXIT.as_ptr() as *const c_void,
                ansi::ALT_SCREEN_EXIT.len(),
            );
        }
        let saved: *const termios = addr_of!(SAVED_TERMIOS) as *const termios;
        let _ = tcsetattr(STDIN_FILENO, TCSANOW, saved);
    }
    RAW_MODE_ACTIVE.store(false, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Drop — graceful-exit cleanup path
// ---------------------------------------------------------------------------

impl Drop for RawTerminal {
    fn drop(&mut self) {
        // Emit exit sequence on stdout (via std::io, permitted here —
        // we are not in a signal handler). Errors are best-effort: if
        // stdout is broken we still want to restore termios.
        {
            let mut out = io::stdout().lock();
            let _ = out.write_all(ansi::SHOW_CURSOR);
            if self.alternate_screen_entered {
                let _ = out.write_all(ansi::ALT_SCREEN_EXIT);
            }
            let _ = out.flush();
        }

        // SAFETY: restore termios via `tcsetattr` using the `original`
        // termios captured by `tcgetattr` in `enter`. `self.stdin_fd`
        // is valid (owned by the process). `&self.original` is a
        // well-aligned pointer to initialized POD storage. We ignore
        // the return value because on `Drop` there is no caller to
        // propagate an error to.
        unsafe {
            let _ = tcsetattr(self.stdin_fd, TCSANOW, &self.original);
        }
        RAW_MODE_ACTIVE.store(false, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // The heavy RawTerminal lifecycle tests (enter -> get_winsize ->
    // drop roundtrip, SIGWINCH-driven WINCH_PENDING flip, singleton
    // rejection) live in crates/heavything/tests/ffi_boundary.rs
    // because they mutate process-wide termios and signal-handler
    // state, which is incompatible with cargo's default parallel test
    // execution. See AAP §0.7.4.4 for the FFI boundary test inventory.

    #[test]
    fn window_size_is_copy() {
        let a = WindowSize { rows: 24, cols: 80 };
        let b = a;
        assert_eq!(a.rows, 24);
        assert_eq!(a.cols, 80);
        assert_eq!(b, a);
    }

    #[test]
    fn window_size_equality() {
        let a = WindowSize { rows: 24, cols: 80 };
        let b = WindowSize { rows: 24, cols: 80 };
        let c = WindowSize { rows: 25, cols: 80 };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn exit_pending_starts_false() {
        // Before any signal delivery, the flag is quiescent.
        // (This test must NOT call RawTerminal::enter because that
        // installs global signal handlers.)
        assert!(!RawTerminal::exit_pending());
    }
}
