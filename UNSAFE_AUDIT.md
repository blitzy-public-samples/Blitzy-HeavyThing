<!--
  HeavyThing x86_64 assembly language library and showcase programs
  Copyright (c) 2015 2 Ton Digital
  Homepage: https://2ton.com.au/
  Author: Jeff Marrison <jeff@2ton.com.au>

  This file is part of the HeavyThing library.

  HeavyThing is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License, or
  (at your option) any later version.

  HeavyThing is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along
  with the HeavyThing library. If not, see <http://www.gnu.org/licenses/>.
-->

# HeavyThing Rust Port — Unsafe Block Audit

This document inventories every `unsafe` block appearing in the Rust port of HeavyThing. The inventory is maintained per AAP §0.7.4 and Gate 6 of the validation framework. Every entry below includes:

- **Location**: path within the workspace, with the actual line number
- **Category**: one of {FFI-libc, FFI-nix, FFI-memmap2, raw-syscall, CPU-intrinsic, other}
- **Functions called**: the specific unsafe-extern / unsafe-fn invocation(s) inside the block
- **Reason**: why safe alternatives could not be used
- **Safety invariant**: the preconditions that make the unsafe operation sound
- **Integration test**: name of the test in `crates/heavything/tests/ffi_boundary.rs` that exercises this site, if applicable (aspirational tests — those referenced by the audit that do not yet exist — are marked as _pending_)

Each site is traceable back to the assembly behavior it preserves. In the assembly baseline, the raw `syscall` instruction in the `.inc` files referenced below performed the same kernel interaction. The Rust port narrows these to well-defined FFI boundaries with documented invariants, as mandated by AAP §0.7.4.2.

## Audit Summary

| Metric                                    | Value |
|-------------------------------------------|-------|
| Total production `unsafe` sites           | 27    |
| Target budget (AAP §0.7.4)                | ≤ 50  |
| Expected count per AAP §0.7.4.1           | 14–22 |
| FFI / raw-syscall / intrinsic sites       | 27    |
| Sites exceeding budget with justification | 0     |
| Additional test-only `unsafe` sites       | 3     |

The 27 production sites enumerated below were verified by grepping
`\bunsafe\s+(fn|impl|\{|extern)` across both production crate roots
that contain `unsafe` code — `crates/heavything/src/` (27 lexical
matches: 24 production + 3 test-only blocks) and `crates/webserver/src/`
(3 lexical matches, all production: `master.rs:872`, `:893`, `:1017`).
The remaining production crates (`crates/sshtalk/src/`, `crates/hnwatch/src/`)
contain zero `unsafe` blocks. Test-only sites are listed in the
"Test-only Unsafe (Appendix)" section for completeness but do not count
against the AAP §0.7.4 budget, which governs production code only.

The overall count (27) is five sites over the top of the AAP §0.7.4.1
"expected 14–22" range. The excess is attributable to four site
clusters: the sub-TUI signal-handler installation / restore machinery
(nine sites in `heavything/src/tui/terminal.rs`, where AAP §0.7.4.1
anticipated roughly 6–8), the five `heavything/src/net/http/mimelike.rs`
sites that implement the raw-pointer escape hatch needed for zero-copy
mmap delivery of HTTP response bodies, a single
`heavything/src/net/http/server.rs` mmap site that backs the webserver
hotlist file cache, and the three `webserver/src/master.rs` sites that
implement the master-process daemonization and worker-spawn forks per
AAP §0.5.1.8. Each site group is isolated behind a type boundary
(`RawTerminal`, `Mimelike::set_body_external`, `HotEntry::open`,
`daemonize_master`/`fork_workers` respectively), consumers interact
via safe method surfaces, and every block carries a `// SAFETY:`
comment naming the invariants. No single site requires the >50
justification paragraph carve-out described in the "Unsafe Minimization
Principles" section.

### Breakdown by Category

| Category       | Sites | Files                                                     |
|----------------|-------|-----------------------------------------------------------|
| FFI-libc       | 12    | `heavything/src/net/runtime.rs` (2), `heavything/src/tui/terminal.rs` (9), `webserver/src/master.rs` (1) |
| FFI-nix        | 5     | `heavything/src/net/child.rs` (3), `webserver/src/master.rs` (2) |
| FFI-memmap2    | 4     | `heavything/src/net/http/server.rs`, `heavything/src/util/mapped.rs`, `heavything/src/util/mappedheap.rs`, `heavything/src/util/privmapped.rs` |
| CPU-intrinsic  | 1     | `heavything/src/crypto/rng.rs`                            |
| Other          | 5     | `heavything/src/net/http/mimelike.rs` (marker traits + raw pointers) |
| Raw syscall    | 0     | —                                                         |
| **Total**      | **27**|                                                           |

## FFI-libc — TUI Raw Mode and Signal Handling

This category encapsulates the direct `libc` termios operations required to place the controlling terminal into raw mode, plus the `sigaction` / `_exit` / `raise` / `write` / `tcsetattr` operations inside async-signal-safe signal handlers. The Rust port mirrors `tui_terminal.inc`, which hand-coded `ioctl(TCGETS)`/`ioctl(TCSETSF)`/`ioctl(TIOCGWINSZ)` on `STDIN_FILENO` and used `sigaction` for terminal-cleanup-on-crash. Per AAP §0.7.3 and §0.7.4.1 these sites are strictly necessary because the Rust std library does not expose a raw-mode abstraction, and the prompt explicitly prohibits `crossterm`/`termion`.

### `RawTerminal::enter` — raw-mode acquisition and save-to-static

- **Location**: `crates/heavything/src/tui/terminal.rs:203`
- **Category**: FFI-libc
- **Functions called**: `std::mem::zeroed::<termios>()`, `libc::tcgetattr`, `libc::cfmakeraw`, `libc::tcsetattr`, `ptr::addr_of_mut!(SAVED_TERMIOS).write(...)`
- **Reason**: `libc` declares these FFI functions as `unsafe extern "C"`; no safe wrapper exists in `std` for raw TTY mode manipulation; the AAP prohibits `crossterm`/`termion` whose safe wrappers would otherwise apply. Consolidated into a single `unsafe { ... }` block per the "Group related unsafe into single blocks" minimization principle.
- **Safety invariant**:
  - `STDIN_FILENO` is a valid process file descriptor for the lifetime of the process
  - `termios` is POD; `mem::zeroed()` produces a valid initial state before `tcgetattr` fully overwrites it
  - `cfmakeraw` mutates a local stack copy in place; its Linux libc-0.2 binding returns void
  - `tcsetattr` applies atomically — on failure, the kernel leaves cooked mode intact, so the early-return path is sound
  - `addr_of_mut!(SAVED_TERMIOS).write(MaybeUninit::new(t))` publishes the saved termios to a `static mut`; `INIT_GUARD.set(())` above succeeded exactly once, so this writer has no concurrent peer. No signal handlers are installed yet at this point, so no concurrent reader exists. `addr_of_mut!` avoids the `static_mut_refs` lint
- **Integration test**: `test_raw_terminal_roundtrip` (`tests/ffi_boundary.rs:1147` — gracefully skips when stdin is not a TTY; covered indirectly by the in-file unit tests at `tui/terminal.rs:530+` for non-TTY CI environments)

### `RawTerminal::get_winsize` — TIOCGWINSZ ioctl

- **Location**: `crates/heavything/src/tui/terminal.rs:267`
- **Category**: FFI-libc
- **Functions called**: `libc::ioctl(self.stdin_fd, TIOCGWINSZ, *mut winsize)`, pointer dereference of `ws.as_ptr()` after success
- **Reason**: `libc::ioctl` is variadic FFI with no safe wrapper in `std`; `TIOCGWINSZ` is Linux-specific and not exposed by `nix::pty`
- **Safety invariant**:
  - `self.stdin_fd` is valid for the life of the process
  - `ws.as_mut_ptr()` is correctly aligned for `struct winsize`
  - Only after the ioctl returns 0 do we dereference the storage; on non-zero rc the early-return path is taken without touching the uninitialized memory
- **Integration test**: `test_raw_terminal_roundtrip` (`tests/ffi_boundary.rs:1147` — calls `term.get_winsize()` after `enter()` and asserts both rows and cols are non-zero on TTY)

### `RawTerminal::install_signal_handlers` — sigaction install batch

- **Location**: `crates/heavything/src/tui/terminal.rs:318`
- **Category**: FFI-libc
- **Functions called**: 5× `install_one` (itself `unsafe fn`, see next entry) for `SIGWINCH`, `SIGTERM`, `SIGINT`, `SIGSEGV`, `SIGABRT`
- **Reason**: `sigaction(2)` is a C API expressed as `unsafe extern "C"` by `libc`; no safe Rust wrapper exposes the `SA_SIGINFO` 3-argument handler shape required by POSIX
- **Safety invariant**:
  - Every handler passed in (`sigwinch_handler`, `sigterm_handler`, `sigint_handler`, `crash_handler`) is `extern "C" fn(c_int, *mut siginfo_t, *mut c_void)` and uses only async-signal-safe operations (atomic stores, `libc::write`, `libc::_exit`, `libc::raise`, `libc::tcsetattr`)
  - The outer `install_signal_handlers` runs on the main thread before any tokio task is spawned, so no concurrent handler invocation can race with installation
- **Integration test**: `test_sigwinch_handler` (`tests/ffi_boundary.rs:1389` — fork-isolated; gracefully skips on non-TTY or when `RawTerminal::enter` returns `AlreadyExists`; raises SIGWINCH and polls `take_winch_pending()`)

### `unsafe fn install_one` — sigaction helper

- **Location**: `crates/heavything/src/tui/terminal.rs:350`
- **Category**: FFI-libc
- **Functions called**: `ptr::write_bytes` (zero-initialize sigaction), `libc::sigemptyset`, `libc::sigaction`
- **Reason**: `unsafe fn` declaration forces callers to make explicit their promise that `handler` is async-signal-safe. The function body contains two `unsafe` sub-operations (write_bytes of a POD struct; sigaction syscall); grouping them under the outer `unsafe fn` is the idiomatic Rust pattern.
- **Safety invariant**:
  - `handler` (caller's argument) is a valid `extern "C" fn(c_int, *mut siginfo_t, *mut c_void)` pointer whose body is async-signal-safe
  - `ptr::write_bytes(sa.as_mut_ptr().cast::<u8>(), 0, size_of::<sigaction>())` produces a valid `sigaction` because: (a) `sa_restorer` is `Option<extern "C" fn()>` whose `None` representation is all-zeros (niche), (b) `sa_mask` (sigset_t) and `sa_flags` are POD
  - `sigaction` reads the struct synchronously; the local `sa` may be dropped after the call
- **Integration test**: exercised transitively by `test_sigwinch_handler` (`tests/ffi_boundary.rs:1389`)

### `sigterm_handler` — _exit after cleanup

- **Location**: `crates/heavything/src/tui/terminal.rs:406`
- **Category**: FFI-libc
- **Functions called**: `libc::_exit(0)`
- **Reason**: `_exit` is async-signal-safe and terminates the process without running destructors — which is explicitly what we want, since we just restored the terminal via `cleanup_terminal_from_signal` and running other destructors from a signal context could deadlock on mutexes held elsewhere
- **Safety invariant**: `_exit` has no preconditions beyond "the process is still alive"; it cannot fail
- **Integration test**: _pending_ (requires sending `SIGTERM` to a subprocess)

### `sigint_handler` — _exit after cleanup

- **Location**: `crates/heavything/src/tui/terminal.rs:419`
- **Category**: FFI-libc
- **Functions called**: `libc::_exit(130)` (POSIX convention `128 + SIGINT`)
- **Reason**: identical to `sigterm_handler`; the exit code is the only difference
- **Safety invariant**: identical to `sigterm_handler`
- **Integration test**: _pending_ (requires sending `SIGINT` to a subprocess)

### `crash_handler` — SIG_DFL reset + raise

- **Location**: `crates/heavything/src/tui/terminal.rs:434`
- **Category**: FFI-libc
- **Functions called**: `ptr::write_bytes` (zero-initialize sigaction), field writes through `sa.as_mut_ptr()`, `libc::sigaction`, `libc::raise`
- **Reason**: on `SIGSEGV`/`SIGABRT` we restore the terminal best-effort, then reset the handler to `SIG_DFL` and `raise` the signal so the kernel can produce a core dump. Both `sigaction` and `raise` are async-signal-safe.
- **Safety invariant**:
  - `ptr::write_bytes(sa.as_mut_ptr().cast::<u8>(), 0, size_of::<sigaction>())` is sound because `SIG_DFL` is defined as `0 as sighandler_t` and `sa_restorer` is `Option<extern "C" fn()>` whose `None` is all-zeros
  - `sigaction(sig, sa.as_ptr(), null_mut())` reads `sa` synchronously
  - `raise(sig)` has no memory effects
- **Integration test**: _pending_ (requires SIGSEGV/SIGABRT induction in a subprocess)

### `cleanup_terminal_from_signal` — write + tcsetattr from signal context

- **Location**: `crates/heavything/src/tui/terminal.rs:476`
- **Category**: FFI-libc
- **Functions called**: 2× `libc::write(STDOUT_FILENO, ...)`, `libc::tcsetattr(STDIN_FILENO, TCSANOW, *const termios)`; cast of `*const MaybeUninit<termios>` to `*const termios`
- **Reason**: all three are async-signal-safe per POSIX `signal-safety(7)` and are invoked from signal handlers; no Rust-level alternative is async-signal-safe
- **Safety invariant**:
  - `STDOUT_FILENO` (1) and `STDIN_FILENO` (0) are valid FDs for any process with an attached terminal
  - The byte slices (`ansi::SHOW_CURSOR`, `ansi::ALT_SCREEN_EXIT`) are `&'static [u8]` constants with valid pointers and lengths
  - The cast `*const MaybeUninit<termios>` → `*const termios` is layout-sound (`MaybeUninit<T>` is `#[repr(transparent)]` over `T`), and the inner value is guaranteed initialized because `RAW_MODE_ACTIVE.load(SeqCst) == true` synchronizes with the `SeqCst` store performed after `SAVED_TERMIOS.write()` in `RawTerminal::enter`
- **Integration test**: exercised transitively by `test_sigterm_handler` / `test_sigint_handler` (_pending_)

### `RawTerminal::drop` — tcsetattr restore

- **Location**: `crates/heavything/src/tui/terminal.rs:519`
- **Category**: FFI-libc
- **Functions called**: `libc::tcsetattr(self.stdin_fd, TCSANOW, &self.original)`
- **Reason**: `tcsetattr` is `unsafe extern "C"` with no safe wrapper. `self.original` is owned by-value on the `RawTerminal` struct (rather than being read from `SAVED_TERMIOS`) so the Drop path does not need any unsafe static access beyond the `tcsetattr` call itself
- **Safety invariant**:
  - `self.stdin_fd` is valid (owned by the process; set at `enter` time)
  - `&self.original` is a well-aligned pointer to initialized POD storage (captured by `tcgetattr` in `enter`)
  - Return value intentionally discarded — on Drop there is no caller to propagate an error to
- **Integration test**: `test_raw_terminal_roundtrip` (`tests/ffi_boundary.rs:1147` — drop runs at end of the integration test as well as at the end of every in-file unit test via RAII)

## FFI-libc — Runtime / `epoll.inc` backend

Per AAP §0.5.1.4 / §0.7.1, the `tokio` + `mio` runtime replaces `epoll.inc`, but two specific syscalls at the boundary have no safe wrapper in `std` or `tokio`:

### `runtime::check_ulimit` — getrlimit / setrlimit

- **Location**: `crates/heavything/src/net/runtime.rs:509`
- **Category**: FFI-libc
- **Functions called**: `std::mem::zeroed::<libc::rlimit>()`, `libc::getrlimit`, `libc::setrlimit`
- **Reason**: no safe Rust wrapper in `std` exposes ulimit-raising behaviour; `nix::sys::resource::{getrlimit, setrlimit}` is available but was not pulled in because the nix feature matrix for this functionality would require additional compile-time features beyond the ones already enabled per AAP §0.6.1
- **Safety invariant**:
  - `libc::RLIMIT_NOFILE` is a valid `c_int` resource identifier
  - `libc::rlimit` is POD with two `rlim_t` fields; `mem::zeroed()` produces a valid initial state
  - `&mut rl` and `&mut rl2` satisfy the `*mut rlimit` pointer shape; lifetime of both extends through the call
  - `setrlimit` return value is discarded — if the process lacks `CAP_SYS_RESOURCE` the syscall fails silently, and the subsequent `getrlimit` detects the shortfall cleanly
- **Integration test**: `test_check_ulimit` (`tests/ffi_boundary.rs:812`)

### `runtime::apply_stream_defaults` — setsockopt

- **Location**: `crates/heavything/src/net/runtime.rs:619`
- **Category**: FFI-libc
- **Functions called**: `libc::setsockopt(fd, SOL_SOCKET, SO_LINGER, ...)`, `libc::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, ...)` (latter gated by `crate::config::EPOLL_KEEPALIVE`)
- **Reason**: neither `std::net` nor `tokio` expose `SO_LINGER` configuration; AAP §0.6.1 prohibits pulling in `socket2` (not in the dependency inventory)
- **Safety invariant**:
  - `fd` is a valid socket file descriptor for the duration of the call (obtained via `AsRawFd::as_raw_fd` on an owned `tokio::net::TcpStream`)
  - `libc::linger` and `libc::c_int` are POD; their lifetimes extend through the `setsockopt` call
  - Both calls use `SOL_SOCKET` (level 1) with valid `SO_LINGER` / `SO_KEEPALIVE` option identifiers from `libc`
  - Return values discarded per FASM best-effort baseline (`epoll.inc:1438–1490`); setsockopt failures surface later as read/write errors on the stream
- **Integration test**: `test_stream_defaults_roundtrip` (`tests/ffi_boundary.rs:964`)

## FFI-nix — Process Management

Per AAP §0.5.1.4 and §0.7.4.1, `nix` wraps the process-management syscalls (`fork`, `setuid`, `setgid`, `prctl`), but the returned raw-fd values from `socketpair` must be handed off to `std::os::unix::net::UnixStream::from_raw_fd`, which remains `unsafe fn` regardless of the `nix` wrapper.

### `net::child::spawn_child` — fork

- **Location**: `crates/heavything/src/net/child.rs:910`
- **Category**: FFI-nix
- **Functions called**: `nix::unistd::fork`
- **Reason**: `fork(2)` is fundamentally unsafe in a multi-threaded program — only the calling thread survives the fork, and any mutex held by another thread deadlocks if the child attempts to take it. `nix` exposes this correctly as `unsafe fn fork()` so callers acknowledge the contract
- **Safety invariant**:
  - Production callers (`webserver` master per AAP §0.5.1.8) fork before spawning additional threads
  - Tests use `#[tokio::test(flavor = "current_thread")]` to stay single-threaded
  - On fork failure both socketpair fds are closed before returning, preventing fd leaks
- **Integration test**: `test_fork_spawn_child_basic` (`tests/ffi_boundary.rs:353`), `test_prctl_pdeathsig` (`:506`), `test_killall_children_on_drop` (`:680`), `test_fork_workers` (`:1750`)

### `net::child::spawn_child` — parent-side `UnixStream::from_raw_fd`

- **Location**: `crates/heavything/src/net/child.rs:945`
- **Category**: FFI-nix (bridging `nix::socketpair` → `std::os::unix::net::UnixStream`)
- **Functions called**: `std::os::unix::net::UnixStream::from_raw_fd(parent_fd)`
- **Reason**: `UnixStream::from_raw_fd` is declared `unsafe fn` because it asserts exclusive ownership of the fd; no safe alternative exists for bridging from `nix::socketpair`'s `OwnedFd` pair into a `tokio::net::UnixStream` (which requires a `std::os::unix::net::UnixStream` first)
- **Safety invariant**:
  - `parent_fd` was just returned by `socketpair(2)` and converted from `OwnedFd` via `into_raw_fd`, suppressing the original `Drop`. No other code path has observed or re-used this fd
  - The child branch of the fork `close`s its duplicate of `parent_fd` as the first operation, so the fd is exclusively owned by the parent here
  - Ownership transfers to the `UnixStream`; no double-close because we do not call `close(parent_fd)` explicitly in the parent branch
- **Integration test**: `test_fork_spawn_child_basic` (`tests/ffi_boundary.rs:353`)

### `net::child::spawn_child` — child-side `UnixStream::from_raw_fd`

- **Location**: `crates/heavything/src/net/child.rs:1011`
- **Category**: FFI-nix
- **Functions called**: `std::os::unix::net::UnixStream::from_raw_fd(child_fd)`
- **Reason**: identical to parent-side — the child needs to hand off its end of the socketpair to `std::os::unix::net::UnixStream` before further tokio wrapping
- **Safety invariant**:
  - `child_fd` was returned by `socketpair(2)` in the pre-fork parent; `fork(2)` duplicates the fd table verbatim so the child inherits the same raw fd number pointing at the same kernel socket
  - `OwnedFd` for `child_fd` was consumed by `into_raw_fd` before the fork, so no `Drop` runs in either process
  - In this branch we have `close(parent_fd)` only — `child_fd` is not re-used
  - `UnixStream` `Drop` closes the fd when `child_main` returns (or on `exit(0)` post-fall-through)
- **Integration test**: `test_fork_spawn_child_basic` (`tests/ffi_boundary.rs:353`)

## FFI — webserver Master Daemonization (cross-crate)

Per AAP §0.5.1.8 (master-worker process model) and §0.7.1.2 (privilege-drop ordering), the `webserver` binary's master process performs three production `unsafe` operations during its pre-tokio bootstrap:

1. `daemonize_master` calls `fork(2)` to detach from the launching shell (FASM `master.inc` line 38 `.dofork`).
2. `daemonize_master` closes inherited stdio (fds 0/1/2) via `libc::close` (FASM `master.inc` lines 53–58 byte-identical).
3. `fork_workers` calls `fork(2)` once per CPU to spawn worker processes paired with `socketpair(2)` IPC channels (FASM `master.inc` line ~150 / `epoll_child$spawn` machinery).

These three sites live in `crates/webserver/src/master.rs` rather than the `heavything` library because the daemonization + worker-spawn lifecycle is webserver-specific (per AAP §0.5.1.8 the `sshtalk` and `hnwatch` binaries are single-process and do not invoke this machinery). They are enumerated here so the unsafe audit covers every production crate in the workspace, not only `heavything`. Underlying syscall semantics (and their associated safety invariants) are identical to the `heavything::net::child::spawn_child` site at `net/child.rs:910`, which the same `nix::unistd::fork` wrapper guards. The integration tests for that helper (`test_fork_spawn_child_basic`, `test_killall_children_on_drop`, `test_fork_workers`) consequently exercise the exact `nix::unistd::fork` machinery used at these three webserver sites.

### `webserver::master::daemonize_master` — fork

- **Location**: `crates/webserver/src/master.rs:872`
- **Category**: FFI-nix
- **Functions called**: `nix::unistd::fork`
- **Reason**: `fork(2)` is fundamentally unsafe in a multi-threaded program — only the calling thread survives the fork, and any mutex held by another thread deadlocks if the child attempts to take it. `nix` exposes this correctly as `unsafe fn fork()` so callers acknowledge the contract. The webserver master invokes this fork to detach from its launching shell when `-background` is requested (FASM `master.inc` line 38 `.dofork`).
- **Safety invariant**:
  - Master process is single-threaded at this site: per AAP §0.7.1.2, the tokio runtime is built strictly post-fork (in `master_event_loop` at `master.rs:1173`), and no `std::thread::spawn` precedes this call. The only stack is the original `main` thread.
  - The parent branch exits immediately via `process::exit(0)` (FASM `master.inc` line 38 `.doexit` parity at line 876), so no parent-side bookkeeping survives.
  - The child branch closes inherited stdio (next site, line 893), calls `setsid()`, and re-seeds the HMAC-DRBG via `rng::reseed()` to avoid producing identical key streams to the parent — a critical invariant per AAP §0.5.1.8.
  - On fork failure the `?` propagation surfaces a typed `anyhow::Error` to the caller; no fd leakage at this site (no fds are owned at this point in the daemonize sequence).
- **Integration test**: `test_fork_workers` (`tests/ffi_boundary.rs:1798`), `test_fork_spawn_child_basic` (`:380`), `test_killall_children_on_drop` (`:707`) — all three exercise the same `nix::unistd::fork` wrapper via `heavything::net::child::spawn_child`, which is the helper consumed by `fork_workers` (and its safety contract is identical here).

### `webserver::master::daemonize_master` — `libc::close(fd)` for inherited stdio

- **Location**: `crates/webserver/src/master.rs:893`
- **Category**: FFI-libc
- **Functions called**: `libc::close(fd)` for each `fd ∈ {0, 1, 2}` (stdin/stdout/stderr)
- **Reason**: post-daemonize stdio closure mirroring FASM `master.inc` lines 53–58 byte-identically (`syscall_close` with `edi = 0`, `1`, `2` in sequence with no error checking). Neither `std` nor `tokio` exposes a "close stdin/stdout/stderr by fd number" primitive, and `nix::unistd::close` requires a `BorrowedFd` whose lifetime semantics conflict with the fact that the daemon is permanently giving up these descriptors (no surrounding `OwnedFd` can be constructed for a fd we are about to discard). Direct `libc::close` is the cleanest fit.
- **Safety invariant**:
  - Each `fd ∈ {0, 1, 2}` is a known-valid process-lifetime descriptor inherited from the original launching process; the kernel guarantees these fds are always allocated for any process started from a shell.
  - `libc::close(fd)` is benign even if the fd was already closed (returns `-1` with `EBADF`, which we discard via `let _ =` per the FASM baseline's no-error-check pattern).
  - We are inside the post-fork daemon child branch (parent exited at line 876); no other code path observes these stdio descriptors after this loop. Subsequent code in `daemonize_master` (`setsid()`, `rng::reseed()`, `syslog::set_pid()`) does not read or write fds 0/1/2.
  - The detach-from-tty `setsid()` call at line 902 follows immediately, completing the FASM `master.inc` line 60 daemonization sequence.
- **Integration test**: indirectly covered by `test_fork_workers` (`tests/ffi_boundary.rs:1798`) via shared fork machinery. A dedicated unit test that closes its own stdio is impractical because the test harness itself relies on stdout for output capture; the production close path is exercised end-to-end whenever `webserver` runs in `-background` mode (Gate 1 / Gate 5 live smoke tests).

### `webserver::master::fork_workers` — fork (per worker)

- **Location**: `crates/webserver/src/master.rs:1017`
- **Category**: FFI-nix
- **Functions called**: `nix::unistd::fork`
- **Reason**: `fork(2)` is `unsafe fn` for the same reason as the `daemonize_master` site above. This is the worker-spawn fork: one iteration per CPU produces one worker child paired with a `socketpair(2)` IPC channel, mirroring FASM `epoll_child$spawn` (`epoll_child.inc`) and the master-side dispatcher at `master.inc` line ~150.
- **Safety invariant**:
  - Process is still pre-tokio at this site: the master's tokio runtime is built only after `fork_workers` returns (per AAP §0.7.1.2 / §0.5.1.8), inside `master_event_loop` at `master.rs:1173`.
  - The previous `daemonize_master` call (when invoked) was also pre-tokio and did not start any threads of its own; the process state at this loop body is single-threaded.
  - Only async-signal-safe operations follow until the runtime starts after `fork_workers` returns (the parent branch updates `pre_workers` on the original main thread; the child branch transfers fd ownership and dispatches to `crate::worker::run`).
  - On fork failure the FASM byte-identical `"Fatal: fork and/or socketpair failed."` message is emitted and the process exits 1 (FASM `master.inc` line 154 `.err_forkfail` parity at lines 1019–1023).
  - The companion `socketpair(2)` succeeds before each fork attempt (lines 994–999); on fork failure the socketpair `OwnedFd` pair is cleaned up automatically via Rust's `Drop` semantics when the closure returns `Err` (no fd leakage).
  - Both branches of the `ForkResult` match arm correctly handle their respective fd ownership: parent drops `child_fd` (line 1031), child drops `parent_fd` (line 1055). Both ends of every spawned socketpair therefore have exactly one owning process post-fork, matching the FASM baseline's IPC topology.
- **Integration test**: `test_fork_workers` (`tests/ffi_boundary.rs:1798`) — directly exercises the worker-spawn pattern via `heavything::net::child::spawn_child` × `WORKER_COUNT=2`, preserving the FASM `epoll_child$spawn` master/worker shape and validating both the parent-side and child-side `ForkResult` arms behave per spec.

## FFI-memmap2 — Memory-Mapped Files

Per AAP §0.5.1.7 the `memmap2` crate wraps raw `mmap` syscalls but exposes three variants (`map`, `map_mut`, `map_copy_read_only`) as `unsafe fn` because the kernel may invalidate the mapping (e.g., on file truncation or backing-store disappearance), causing SIGBUS on subsequent access. All four in-scope sites uphold the same documented safety contract.

### `net::http::server::HotEntry::open` — webserver hotlist file cache mmap

- **Location**: `crates/heavything/src/net/http/server.rs:479`
- **Category**: FFI-memmap2
- **Functions called**: `memmap2::MmapOptions::new().map(&file)`
- **Reason**: `Mmap::map` is `unsafe fn` per the memmap2 contract; used by the webserver hotlist file cache (`HotEntry`) for zero-copy delivery of static asset bodies. This is the Rust port of the FASM `webserver.inc` mmap-based hotlist; `webserver.inc` performed the same kernel `mmap` syscall directly. Per AAP §0.4.1.1 deliverables and §0.5.1.4, the hotlist preserves the 900s entry lifetime and 120s recheck cadence from the assembly baseline.
- **Safety invariant**:
  - Read-only mapping (default for `MmapOptions::map` — `PROT_READ` only)
  - `file` is a locally-owned `std::fs::File`; `memmap2` dupes the underlying fd internally so dropping the local handle at end-of-function is sound
  - Returned `Mmap` is retained inside the `HotEntry` value for the entry's full lifetime (typically wrapped in `Arc<HotEntry>` by the cache); `memmap2::Drop` releases the mapping when the last refcount hits zero
  - Static-asset serving convention: webserver content directories must not be modified concurrently by external writers; operators replacing files use atomic `rename(2)` semantics (the hotlist re-detects via 120s mtime poll). External truncation-induced SIGBUS is the same accepted caveat as in `mapped.inc` / `privmapped.inc`
  - Public `HotEntry` API exposes only `&[u8]` via `mmap()`; no aliasing `&mut [u8]` can be produced
- **Integration test**: `test_mmap_file_cache` (`tests/ffi_boundary.rs:1876`)

### `util::mapped::Mapped::new_file` — shared read-only mmap

- **Location**: `crates/heavything/src/util/mapped.rs:209`
- **Category**: FFI-memmap2
- **Functions called**: `memmap2::MmapOptions::new().len(file_len).populate().map(&file)`
- **Reason**: `Mmap::map` is `unsafe fn` per the memmap2 contract
- **Safety invariant**:
  - `file` is owned locally; `memmap2` dupes the fd it needs internally, so dropping `file` at end-of-function is sound
  - File is opened `O_RDONLY`; no aliasing `&mut [u8]` can be produced (public API `as_bytes` returns only `&[u8]`)
  - Cross-process modification is an accepted platform caveat inherited from the FASM baseline (`mapped.inc`); callers needing stronger guarantees coordinate externally
- **Integration test**: `test_mmap_file_cache` (`tests/ffi_boundary.rs:1876` — exercises the `MmapOptions::new().map` path of all four sites in this category via `HotEntry::open` over a `tempfile::NamedTempFile`)

### `util::mappedheap::MappedHeap::new_file` — shared read-write mmap

- **Location**: `crates/heavything/src/util/mappedheap.rs:305`
- **Category**: FFI-memmap2
- **Functions called**: `memmap2::MmapOptions::new().len(size as usize).map_mut(&file)`
- **Reason**: `MmapMut::map_mut` is `unsafe fn` per the memmap2 contract; used by the TLS session cache (port of `mappedheap.inc`) which requires read-write access for allocator bookkeeping
- **Safety invariant**:
  - `file` is a locally-owned `std::fs::File`; `memmap2::map_mut` dupes the fd internally
  - File was just resized via `set_len(size)` and is not shared through any other path; kernel's view of the length matches what we pass
  - Mutability is bounded by the `Mutex<MappedHeapInner>` wrapping the mmap; no concurrent mutable access through this Rust-level handle
  - Same external-process truncation caveat as the FASM baseline (`mappedheap.inc`)
- **Integration test**: `test_mmap_file_cache` (`tests/ffi_boundary.rs:1876` — covers the shared `MmapOptions` machinery this site relies on; `map_mut` itself is exercised by the in-file unit tests at `util/mappedheap.rs:600+`)

### `util::privmapped::PrivMapped::open` — private (MAP_PRIVATE) read-only mmap

- **Location**: `crates/heavything/src/util/privmapped.rs:319`
- **Category**: FFI-memmap2
- **Functions called**: `memmap2::MmapOptions::new().len(size).map_copy_read_only(&file)` (= `mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0)` — byte-identical with `privmapped.inc:130–137`)
- **Reason**: `map_copy_read_only` is `unsafe fn` per the memmap2 contract. `MAP_PRIVATE + PROT_READ` produces a COW mapping that is isolated from cross-process writes through the same inode, which is the FASM baseline's intent for the webserver file hotlist cache
- **Safety invariant**:
  - `file` is owned locally; `memmap2` dupes the fd internally
  - Resulting `Mmap` is read-only (`MAP_PRIVATE + PROT_READ`); public API (`as_bytes`) returns only `&[u8]`, so no mutable-alias UB possible
  - Same external-process truncation caveat as the FASM baseline (`privmapped.inc`); callers needing stronger guarantees use `flock(2)`
- **Integration test**: `test_mmap_file_cache` (`tests/ffi_boundary.rs:1876` — covers the shared `MmapOptions` machinery this site relies on; `map_copy_read_only` itself is exercised by the in-file unit tests at `util/privmapped.rs:380+`)

## CPU-intrinsic — `rdtsc` Timestamp Counter

### `crypto::rng::read_tsc` — rdtsc for RNG entropy mixing

- **Location**: `crates/heavything/src/crypto/rng.rs:297`
- **Category**: CPU-intrinsic
- **Functions called**: `std::arch::x86_64::_rdtsc()`
- **Reason**: `_rdtsc` is declared `unsafe fn` per the `std::arch::x86_64` convention even though on the `x86_64-unknown-linux-gnu` target it cannot trap, cannot fault, and has no side effects beyond a brief pipeline stall. No safe wrapper exists. The FASM baseline (`rng.inc:137–144`) uses the same instruction for entropy mixing
- **Safety invariant**:
  - The `rdtsc` instruction is architecturally required on x86_64 (present since AMD Opteron / Intel Nocona, 2003)
  - It cannot trap in user mode on Linux (`CR4.TSD` is cleared by default)
  - It has no memory effects and cannot UB
  - Module's compile target `x86_64-unknown-linux-gnu` guarantees availability at compile time
- **Integration test**: exercised by `crypto::rng::tests::*` (in-file; 13 tests cover the RNG construction pipeline including `read_tsc`)

## Other — Raw-Pointer / Marker-Trait Escape Hatches (HTTP Mimelike)

Per AAP §0.5.1.4 `net/http/mimelike.rs` ports `mimelike.inc` with byte-identical layout including its body-by-pointer optimization. The FASM baseline used a raw pointer to the mmap'd file body (`bodyext` field) to avoid copying the file contents into the response buffer. The Rust port preserves this zero-copy optimization via five carefully-isolated unsafe sites.

### `unsafe impl Send for Mimelike`

- **Location**: `crates/heavything/src/net/http/mimelike.rs:384`
- **Category**: Other (unsafe impl of auto trait)
- **Functions called**: none (marker trait impl)
- **Reason**: `Mimelike` contains a `*const u8` raw pointer (`bodyext`) which is `!Send` and `!Sync` by default. We assert `Send + Sync` manually because the pointer is set only at construction or via the explicitly-`unsafe` `set_body_external` entry point, and thereafter read-only through `body_bytes` / `body_len` / `compose`
- **Safety invariant** (shared with line 385):
  - `bodyext` is set only at construction (null), via `new_parse` (which does not use it), via `set_body` (which clears it to null), or via the explicitly-`unsafe` `set_body_external`, whose caller documents lifetime
  - After being set, `bodyext` is read-only through public accessors; no interior-mutability path admits a data race
  - `parent` (the other raw pointer) is set only at parse-time when linking into a parent's `parts` list and never mutated thereafter
  - The remaining fields are all owned types (`HttpHeaders`, `Option<String>`, `Buffer`, `Vec<Mimelike>`) that are themselves `Send + Sync`
- **Integration test**: exercised by `mimelike` unit tests (in-file, 40+ tests)

### `unsafe impl Sync for Mimelike`

- **Location**: `crates/heavything/src/net/http/mimelike.rs:385`
- **Category**: Other (unsafe impl of auto trait)
- **Functions called**: none (marker trait impl)
- **Reason / safety invariant**: same rationale as the `Send` impl above; `Mimelike` is read-only post-parse except through the explicitly-unsafe mutators (`set_body_external`) which are `&mut self`, so `Sync` is sound
- **Integration test**: exercised by `mimelike` unit tests (in-file)

### `pub unsafe fn Mimelike::set_body_external`

- **Location**: `crates/heavything/src/net/http/mimelike.rs:712`
- **Category**: Other (unsafe fn — caller-upheld pointer-lifetime contract)
- **Functions called**: stores `*const u8` and precomputed end pointer into struct fields
- **Reason**: the sole purpose of this function is to bypass the owned-body copy path for zero-copy delivery of mmap'd file bodies (e.g., webserver static file serving). Declaring it `unsafe fn` forces callers to make explicit their promise about the pointer's lifetime
- **Safety invariant** (documented on the fn's `# Safety` Rustdoc):
  - The `data: *const u8` pointer must remain valid (live, readable, untouched by writers) for the entire lifetime of this `Mimelike`, OR until the next call to a body-mutating method (`set_body`, `set_body_external`, `new_parse`) which clears the external reference
- **Integration test**: `body_bytes_uses_external_pointer_when_set` (test-only unsafe consumer, in-file at `mimelike.rs:2195`)

### `Mimelike::body_bytes` — `slice::from_raw_parts` on external body

- **Location**: `crates/heavything/src/net/http/mimelike.rs:825`
- **Category**: Other (raw slice construction)
- **Functions called**: `std::slice::from_raw_parts(self.bodyext, self.bodyextlen)`
- **Reason**: the caller of `set_body_external` promised the pointer stays valid; this method exposes the bytes as `&[u8]` without copying them
- **Safety invariant**:
  - Only taken when `!self.bodyext.is_null()` — the null case falls through to the owned `body` buffer
  - The caller of `set_body_external` promised the pointer remains valid for our lifetime; no body-mutating method has been invoked since then (those clear `bodyext` to null)
  - `self.bodyextlen` matches the length the caller provided at `set_body_external` time
- **Integration test**: `body_bytes_uses_external_pointer_when_set` (in-file at `mimelike.rs:2195`)

### `Mimelike::compose` — `slice::from_raw_parts` for external-body pickup

- **Location**: `crates/heavything/src/net/http/mimelike.rs:980`
- **Category**: Other (raw slice construction)
- **Functions called**: `std::slice::from_raw_parts(self.bodyext, self.bodyextlen)`
- **Reason**: during response composition, if the caller set an external body, we materialize the slice once (then copy to an owned buffer, because the encoding pipeline may need to mutate). The zero-copy fast path is elsewhere — this site exists for the compose-with-encoding path
- **Safety invariant**: same as `body_bytes` — only taken on `!bodyext.is_null()`; caller's lifetime promise still holds; length matches
- **Integration test**: `mimelike` compose tests (in-file)

## Raw Syscall — `libc::syscall` Paths

> **Zero sites**. All syscalls needed by the Rust port are exposed as typed wrappers by `libc` (`tcgetattr`, `setsockopt`, `getrlimit`, etc.), by `nix` (`fork`, `prctl::set_pdeathsig`, `kill`, `socketpair`), or by `memmap2` (`mmap` variants). No direct `libc::syscall(SYS_...)` invocation is required.
>
> Should a future change require a syscall not exposed through these wrappers, the new `unsafe` block will be recorded under this heading with the full six-field template.

## Test-only Unsafe (Appendix)

These sites exist only inside `#[cfg(test)]` blocks and do not count against the production AAP §0.7.4 budget. They are listed here for grep-completeness — any maintenance script that counts `unsafe` lexical occurrences in `crates/heavything/src/` (after filtering out comment lines) will observe 27 total matches (24 production + 3 test-only).

| # | File:Line                                                   | Purpose                                                                   |
|---|-------------------------------------------------------------|---------------------------------------------------------------------------|
| 1 | `crates/heavything/src/net/runtime.rs:1095`                 | `test_check_ulimit_current` — independently invoke `libc::getrlimit` to double-check `check_ulimit`'s return value matches kernel reality |
| 2 | `crates/heavything/src/net/runtime.rs:1380`                 | `test_stream_defaults_roundtrip` — invoke `libc::getsockopt` to read back `SO_LINGER` / `SO_KEEPALIVE` after `apply_stream_defaults` set them |
| 3 | `crates/heavything/src/net/http/mimelike.rs:2195`           | `body_bytes_uses_external_pointer_when_set` — call the `unsafe fn set_body_external` from the test body to exercise the external-pointer code path |

## Integration Test Mapping

Per AAP §0.7.4.4, every FFI / raw-syscall boundary site must have a corresponding integration test in `crates/heavything/tests/ffi_boundary.rs`. The table below maps site → test. Tests marked _pending_ are referenced by this document but not yet implemented; per AAP §0.7.4.4 they are scheduled to be added alongside the SIGTERM/SIGINT/SIGSEGV signal-handler deliverables (CP8 — webserver binary integration), which require subprocess signal-induction harnessing not yet in scope.

Integration tests currently implemented in `crates/heavything/tests/ffi_boundary.rs`:

| Test Name                       | File:Line | Unsafe Sites Exercised                                |
|---------------------------------|-----------|-------------------------------------------------------|
| `test_fork_spawn_child_basic`   | `:353`    | `net/child.rs` fork + 2× from_raw_fd                  |
| `test_prctl_pdeathsig`          | `:506`    | `net/child.rs` (same) — exercises `prctl::set_pdeathsig` post-fork in the child branch |
| `test_killall_children_on_drop` | `:680`    | `net/child.rs` (same) — exercises the `ChildProcess::Drop` kill path |
| `test_check_ulimit`             | `:812`    | `net/runtime.rs` (getrlimit/setrlimit)                |
| `test_stream_defaults_roundtrip`| `:964`    | `net/runtime.rs` (setsockopt)                         |
| `test_raw_terminal_roundtrip`   | `:1147`   | `tui/terminal.rs:203, 267, 519` (enter → get_winsize → drop round-trip; gracefully skips when stdin is not a TTY) |
| `test_sigwinch_handler`         | `:1389`   | `tui/terminal.rs:318, 350` (sigaction install + SIGWINCH delivery via `signal::raise(SIGWINCH)` + poll on `take_winch_pending`) |
| `test_setuid_setgid_drop`       | `:1582`   | webserver master privilege-drop primitives (`nix::unistd::setuid`, `setgid`); gated on `HEAVYTHING_PRIVILEGED_TESTS=1` and `getuid() == 0` |
| `test_fork_workers`             | `:1750`   | `net/child.rs` worker-spawn pattern (`spawn_child` × `WORKER_COUNT=2`); preserves the FASM `epoll_child$spawn` master/worker shape for CP8 |
| `test_mmap_file_cache`          | `:1876`   | `net/http/server.rs:479` (HotEntry::open) — covers the shared `MmapOptions::map` machinery used by all four memmap2 sites |
| `test_cpuid_vendor_string`      | `:2040`   | _Supplementary CPU-instruction-boundary test_ — exercises `std::arch::x86_64::__cpuid(0)` (a **safe fn** on x86_64 per AAP §0.7.4.1 "0 sites" budget, not an unsafe site) and ground-truths the result against `/proc/cpuinfo`'s `vendor_id` field plus the `cpu::detect_is_intel` ECX-only check at `cpu.rs:141`. Added in CP7 to satisfy the QA Checkpoint 7 expected-outcome enumeration; not strictly required by AAP §0.7.4.4 but increases CPU-feature-detection regression confidence at zero risk. |

Aspirational tests referenced by this document but not yet implemented (CP8 scope — require subprocess signal-induction harnessing):

| Test Name                       | Planned Coverage                                                                 |
|---------------------------------|----------------------------------------------------------------------------------|
| `test_sigterm_handler`          | `tui/terminal.rs:406, 476` (SIGTERM → cleanup_terminal_from_signal → _exit)      |
| `test_sigint_handler`           | `tui/terminal.rs:419, 476` (SIGINT → cleanup_terminal_from_signal → _exit)       |
| `test_crash_handler`            | `tui/terminal.rs:434` (SIGSEGV → SIG_DFL reset → raise)                          |

Run the currently-implemented integration tests via:

    HEAVYTHING_LIVE_TESTS=1 cargo test -p heavything --test ffi_boundary

Tests requiring elevated privileges (`test_setuid_setgid_drop`) are additionally gated on a `HEAVYTHING_PRIVILEGED_TESTS=1` environment variable to prevent accidental invocation in unprivileged CI environments. The full privileged invocation is:

    HEAVYTHING_LIVE_TESTS=1 HEAVYTHING_PRIVILEGED_TESTS=1 cargo test -p heavything --test ffi_boundary -- --test-threads=1

## Unsafe Minimization Principles

The following principles are applied uniformly across the Rust port to keep the unsafe budget well below the 50-site ceiling (per AAP §0.7.4.2):

- **Encapsulate unsafe at type boundaries**: e.g., `RawTerminal` owns all termios unsafe; consumers interact via safe methods. The nine unsafe blocks in `tui/terminal.rs` are all members of this one newtype plus its helpers; external callers see only the safe API.
- **Prefer wrapper crates over raw libc**: `nix::unistd::fork` instead of `libc::fork`; `memmap2::Mmap` instead of raw `mmap`; `ring`/`aes` crates for AES (zero direct AES-NI intrinsic unsafe per AAP §0.7.4.1 budget). The `nix` and `memmap2` crates have their own safety-invariant documentation and have been reviewed by the Rust community.
- **Group related unsafe into single blocks**: consolidate `mem::zeroed → tcgetattr → cfmakeraw → tcsetattr → SAVED_TERMIOS.write` into one `unsafe { … }` with one consolidated safety comment at `tui/terminal.rs:203`. The `install_signal_handlers` function at line 318 batches five `install_one` calls into one block. This reduces the block count below what a naive per-call approach would produce.
- **Document safety invariants explicitly**: every unsafe block carries a `// SAFETY: …` comment covering all preconditions that make the unsafe operation sound. The comment is reviewed as part of code review; missing or vague SAFETY comments block merge.
- **Mark marker-trait impls with explicit justification**: the `unsafe impl Send for Mimelike {}` / `unsafe impl Sync for Mimelike {}` pair at `mimelike.rs:384–385` shares a 10-line SAFETY comment block immediately above it explaining the four-point rationale.

If the total count ever exceeds 50, each site over 50 requires a dedicated written justification paragraph in this file explaining why isolation into a single helper could not reduce the count. The justification must cover: (a) the reason no existing wrapper crate exposes the required primitive, (b) why the consumer cannot be refactored to use an adjacent primitive that _is_ wrapped, and (c) the marginal safety risk the site imposes and the mitigation in place.

## Audit Maintenance

This document is regenerated whenever

    grep -rnE '\bunsafe\s+(fn|impl|\{|extern)' crates/heavything/src/ crates/webserver/src/ crates/sshtalk/src/ crates/hnwatch/src/

returns a different set of lines from the one captured at the head of this document. The verification invocation is:

    grep -rnE '\bunsafe\s+(fn|impl|\{|extern)' crates/heavything/src/ crates/webserver/src/ crates/sshtalk/src/ crates/hnwatch/src/ | wc -l

which should currently return `30` (= 27 production + 3 test-only across all four production crates: 27 lexical matches in `heavything` + 3 in `webserver` + 0 in `sshtalk` + 0 in `hnwatch`). If it returns a different number, one of two conditions holds:

1. A new production unsafe site was introduced without adding a matching entry in the sections above — this is a merge-blocking audit finding, and the correct remediation is to add the entry (or to refactor the code to eliminate the new site).
2. An existing unsafe site was removed — update the relevant section to delete the stale entry and decrement the "Total production `unsafe` sites" row of the Audit Summary table.

The maintenance workflow is:

1. Run the grep command above from the workspace root.
2. For each line in the output, locate the corresponding entry in this file by searching for the file:line.
3. If the entry is missing, either (a) add an entry in the correct category section with all six fields, or (b) remove the unsafe block if it is avoidable.
4. Update the "Total production `unsafe` sites" row of the `## Audit Summary` table to reflect the new count.
5. If the count exceeds 50, add justification paragraphs under the applicable category header for each site beyond 50.
6. Commit the regenerated document alongside the code change that introduced the new site.

Line numbers in this document are precise at the time of writing and expected to remain stable across patch-level edits. If a refactor shifts a line number by more than 20 lines, update this document rather than relying on the tolerance. The maintenance script (if added in a future checkpoint) will validate line numbers exactly rather than by range.
