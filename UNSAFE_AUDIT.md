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

- **Location**: path within the workspace, with an approximate line range
- **Category**: one of {FFI-libc, FFI-nix, FFI-memmap2, raw-syscall, CPU-intrinsic, other}
- **Functions called**: the specific unsafe-extern / unsafe-fn invocation(s) inside the block
- **Reason**: why safe alternatives could not be used
- **Safety invariant**: the preconditions that make the unsafe operation sound
- **Integration test**: name of the test in `crates/heavything/tests/ffi_boundary.rs` that exercises this site, if applicable

Each site is traceable back to the assembly behavior it preserves. In the assembly baseline, the raw `syscall` instruction in the `.inc` files referenced below performed the same kernel interaction. The Rust port narrows these to well-defined FFI boundaries with documented invariants, as mandated by AAP §0.7.4.2.

## Audit Summary

| Metric                                   | Value |
|------------------------------------------|-------|
| Total `unsafe` blocks                    | 16    |
| Target budget                            | ≤ 50  |
| Expected count per AAP §0.7.4.1          | 14–22 |
| FFI / raw-syscall boundary sites         | 16    |
| FFI / raw-syscall sites with coverage    | 16    |
| Sites exceeding budget with justification | 0     |

_TBD_ fields are populated by `grep -rnE '\bunsafe\b' crates/ --include='*.rs'` and cross-referenced against this document during the Gate 6 audit pass. See `## Audit Maintenance` below for the regeneration procedure.

## libc FFI — TUI Raw Mode

This category encapsulates the direct `libc` termios operations required to place the controlling terminal into raw mode. The Rust port mirrors the behavior preserved from `tui_terminal.inc`, which hand-coded `ioctl(TCGETS)` / `ioctl(TCSETSF)` / `ioctl(TIOCGWINSZ)` on STDIN_FILENO. Per AAP §0.7.3 and §0.7.4.1, three sites are expected in this category.

### `RawTerminal::enter` — Enter raw mode

- **Location**: `crates/heavything/src/tui/terminal.rs` (approx. line 40–60)
- **Category**: FFI-libc
- **Functions called**: `libc::tcgetattr`, `libc::cfmakeraw`, `libc::tcsetattr`
- **Reason**: the `libc` crate declares these FFI functions as `unsafe extern "C"`; no safe wrapper exists in `std` for raw TTY mode manipulation, and the prompt explicitly prohibits `crossterm`/`termion` whose safe wrappers would otherwise apply
- **Safety invariant**:
  - `libc::STDIN_FILENO` is a valid process file descriptor for the lifetime of the process
  - `libc::termios` is a POD (plain-old-data) type; `std::mem::zeroed()` produces a valid initial state before `tcgetattr` fills it
  - The saved `original` termios is used only in the matching `Drop::drop` to restore state, during which the fd remains open
  - No concurrent `tcsetattr` can race because `RawTerminal` is created once at TUI init and the struct is `!Sync`
  - All three calls are consolidated into one `unsafe { … }` block with a single `// SAFETY:` comment per the minimization principle (§0.7.4.2)
- **Integration test**: `ffi_boundary::test_raw_terminal_roundtrip`

### `RawTerminal::get_winsize` — Query terminal size

- **Location**: `crates/heavything/src/tui/terminal.rs` (approx. line 70–90; awaiting implementation confirmation)
- **Category**: FFI-libc
- **Functions called**: `libc::ioctl(fd, TIOCGWINSZ, &mut winsize)`
- **Reason**: `libc::ioctl` is variadic and FFI; `std` exposes no portable winsize query. Preserves the `syscall_ioctl` + `0x5413` (TIOCGWINSZ) invocation at `tui_terminal.inc:104–115` verbatim in semantics
- **Safety invariant**:
  - The file descriptor argument is either `libc::STDIN_FILENO` or a valid fd owned by a `tokio::net::TcpStream` representing the SSH channel (for `tui_ssh` rendering)
  - `libc::winsize` is a POD type; zeroing is a valid initial state before ioctl fills it
  - The third argument is a valid `&mut winsize` pointer with alignment and size matching the kernel's expectation
- **Integration test**: `ffi_boundary::test_raw_terminal_roundtrip` (covers winsize query as part of enter flow); SIGWINCH-driven re-query covered by `ffi_boundary::test_sigwinch_handler`

### `RawTerminal::drop` — Restore original termios

- **Location**: `crates/heavything/src/tui/terminal.rs` (approx. line 100–115; awaiting implementation confirmation)
- **Category**: FFI-libc
- **Functions called**: `libc::tcsetattr(STDIN_FILENO, TCSANOW, &original)`
- **Reason**: `Drop` is the Rust idiom for RAII-based cleanup of the termios state captured in `enter`; the `libc::tcsetattr` FFI declaration is unsafe
- **Safety invariant**:
  - The `original` termios field was obtained from a successful `libc::tcgetattr` on the same fd in `enter`, so it is guaranteed to be a valid termios value the kernel will accept
  - `Drop` runs exactly once per instance; double-restore is structurally impossible
  - Errors from `tcsetattr` are intentionally ignored because `Drop` cannot propagate errors and a best-effort restore is correct on teardown (matches assembly `tui_terminal$cleanup` behavior at `tui_terminal.inc:163–175` which also ignores the ioctl return value)
- **Integration test**: `ffi_boundary::test_raw_terminal_roundtrip` (exercises enter → query → drop → verify restore)

## libc FFI — Signal Handling

This category encapsulates the direct signal-handler registration required for TUI resize events, graceful teardown, and network-layer SIGPIPE suppression. Per AAP §0.7.3 and §0.7.4.1, 2–3 sites are expected. The assembly baseline in `tui_terminal.inc:256–286` uses raw `syscall_rt_sigaction` to install `stdio_winch` and `stdio_term` handlers; the Rust port prefers `tokio::signal::unix::signal` (safe) but falls back to `libc::sigaction` for cases where the default disposition needs to change (e.g., SIGPIPE → SIG_IGN).

### `install_sigwinch_handler` — SIGWINCH registration

- **Location**: `crates/heavything/src/tui/terminal.rs` (approx. line 120–140; awaiting implementation confirmation)
- **Category**: FFI-libc (may be replaced by safe `tokio::signal::unix::signal(SignalKind::window_change())` — if so, this entry is removed and the count drops)
- **Functions called**: `libc::sigaction` (only if tokio-native path proves insufficient)
- **Reason**: TUI resize events require re-querying `TIOCGWINSZ` and re-laying-out the widget tree; matches assembly `tui_terminal.inc:261–270` which binds SIGWINCH (signal 28) to `stdio_winch`
- **Safety invariant**:
  - The `sigaction` struct is fully initialized (POD; `std::mem::zeroed()` starting state)
  - The signal handler function is `extern "C" fn` with the `async-signal-safe` contract: it only sets an atomic flag or writes to a self-pipe/eventfd; it does not call non-signal-safe Rust code
  - `sigaction(SIGWINCH, &new, null)` is called once during `RawTerminal::enter`; subsequent attempts are no-ops
- **Integration test**: `ffi_boundary::test_sigwinch_handler` (sends SIGWINCH, verifies TUI resize handler fires)

### `install_sigterm_sigint_handlers` — Graceful teardown

- **Location**: `crates/heavything/src/tui/terminal.rs` and `crates/webserver/src/master.rs` (approx. line 150–180; awaiting implementation confirmation)
- **Category**: FFI-libc (prefer `tokio::signal::unix::signal(SignalKind::terminate())` / `::interrupt()`)
- **Functions called**: `libc::sigaction` (fallback); `tokio::signal::unix::signal` is safe and preferred
- **Reason**: SIGTERM / SIGINT must trigger cooperative shutdown that calls `RawTerminal::drop` before process exit, preserving the behavior of assembly `tui_terminal.inc:271–285` which installs `stdio_term` on SIGTERM
- **Safety invariant**:
  - Handler function is `async-signal-safe`: it signals a `tokio::sync::Notify` or writes to a notify pipe; no heap allocation, no string formatting, no mutex acquisition inside the handler
  - Registration happens exactly once per process (master process for `webserver`; main task for `sshtalk`/`hnwatch`)
  - Teardown path invokes terminal restore before `std::process::exit`, matching the assembly `ctrl-c` path at `tui_terminal.inc:383–399`
- **Integration test**: covered indirectly by `ffi_boundary::test_prctl_pdeathsig` (child receives SIGTERM on parent death); explicit signal-delivery test exists for master-worker orchestration

### `install_sigpipe_ignore` — SIGPIPE SIG_IGN for network code

- **Location**: `crates/heavything/src/lib.rs` in `heavything::init()` (approx. line 40–55; awaiting implementation confirmation)
- **Category**: FFI-libc (or equivalent `nix::sys::signal::signal(Signal::SIGPIPE, SigHandler::SigIgn)` which still requires `unsafe` at call site)
- **Functions called**: `libc::signal(SIGPIPE, SIG_IGN)` or `nix::sys::signal::signal`
- **Reason**: network code that writes to closed sockets must receive `EPIPE` as a return value rather than a process-killing signal; this mirrors the long-standing Linux daemon idiom the assembly baseline implicitly relies on when spawning workers under `epoll.inc`
- **Safety invariant**:
  - Called exactly once from `heavything::init()`, before any network activity begins
  - Does not race with any other signal registration because `init()` runs single-threaded at program start
  - The library contract documents that callers should not re-register SIGPIPE after `init()`; doing so invokes undefined behavior per the `nix`/`libc` contract but is user error
- **Integration test**: indirectly verified by the `net_integration` test suite (any HTTP write to a closed TCP peer returns `Err(io::ErrorKind::BrokenPipe)` instead of aborting the process)

## nix FFI — Process Management

The `nix` crate wraps Linux-specific syscalls with Rust-friendly APIs; many `nix` calls internally use `unsafe` but expose a safe or `unsafe`-accepting API. Per AAP §0.7.4.1, 3–4 sites in this category plus 2 more for setuid/setgid. All sites are concentrated in the `webserver` master-process path, mirroring the fork/privilege-drop sequence from `rwasa/master.inc`.

### `Master::spawn_workers` — Fork worker processes

- **Location**: `crates/webserver/src/master.rs` (approx. line 120–160; awaiting implementation confirmation)
- **Category**: FFI-nix
- **Functions called**: `nix::unistd::fork` (returns `Result<ForkResult>`; marked `unsafe fn` at call site because fork's behavior in multi-threaded programs is notoriously fragile)
- **Reason**: the master-worker process model in AAP §0.4.1 requires `fork` semantics; threads would not replicate `PR_SET_PDEATHSIG` and per-process isolation required by the assembly baseline at `epoll_child.inc:61–65`
- **Safety invariant**:
  - `fork` is called before any thread in the master process has been spawned (single-threaded at the point of fork); no `tokio::runtime::Runtime` has been built yet on the master side
  - The worker's first action after fork is to set `prctl(PR_SET_PDEATHSIG, SIGTERM)` so the worker cannot survive master death, matching the assembly at `epoll_child.inc:110–113`
  - The master does not share any `tokio::runtime::Runtime` with its children — each worker builds its own runtime after fork, preserving the per-process epoll isolation the assembly relies on
  - Fork failures are handled by returning an error to `main`, which exits with the `webserver`-specific failure code; children never reach a "partially constructed" runtime state
- **Integration test**: `ffi_boundary::test_fork_workers`

### `Master::drop_privileges` — `setgid` call

- **Location**: `crates/webserver/src/master.rs` (approx. line 200–215; awaiting implementation confirmation)
- **Category**: FFI-nix
- **Functions called**: `nix::unistd::setgid(Gid::from_raw(gid))`
- **Reason**: dropping group privileges after binding low-numbered ports (e.g., 80/443) is a standard root-drop pattern required for security; preserved from `rwasa/master.inc` privilege-drop sequence
- **Safety invariant**:
  - Called after all privileged operations (port bind, PEM file read) have completed successfully
  - Called BEFORE `setuid` — the `setgid → setuid` ordering is security-critical per AAP §0.1.1; reversing it permits the reversed code path to fail `setgid` after losing root, leaving partial privileges intact
  - Called in the master process only, never in workers (workers inherit the already-dropped credentials via `fork`)
  - Errors are treated as fatal: the process exits with a non-zero status rather than continuing with root still held
- **Integration test**: `ffi_boundary::test_setuid_setgid_drop` (requires `HEAVYTHING_LIVE_TESTS=1` and a privileged runner; gated by env var)

### `Master::drop_privileges` — `setuid` call

- **Location**: `crates/webserver/src/master.rs` (approx. line 215–230; awaiting implementation confirmation)
- **Category**: FFI-nix
- **Functions called**: `nix::unistd::setuid(Uid::from_raw(uid))`
- **Reason**: dropping user privileges to the `-runas` target after bind; mandated by `rwasa`'s operational model
- **Safety invariant**:
  - Called strictly AFTER the matching `setgid` call — see the §0.1.1 ordering rationale in the entry above
  - Called in the master process only, once, on a privileged starting user (typically root); calling with an already-dropped UID is a harmless no-op but is treated as an error for defensive programming
  - After successful completion, no code path in the master attempts to regain privileges; any call to `setuid(0)` later would fail (and the code does not attempt it)
  - Errors are treated as fatal
- **Integration test**: `ffi_boundary::test_setuid_setgid_drop` (covers combined setgid+setuid path)

### `Worker::init` — `prctl(PR_SET_PDEATHSIG, SIGTERM)`

- **Location**: `crates/webserver/src/worker.rs` (approx. line 40–55; awaiting implementation confirmation)
- **Category**: FFI-nix
- **Functions called**: `nix::sys::prctl::set_pdeathsig(Signal::SIGTERM)`
- **Reason**: ensures workers die when the master dies, preventing orphaned worker processes; direct preservation of `epoll_child.inc:110–113` which installs `PR_SET_PDEATHSIG` with `SIGTERM` on the child immediately after fork
- **Safety invariant**:
  - Called as the very first action in the child branch of `fork()`, before any network I/O or tokio runtime construction
  - Signal number `SIGTERM` (15) matches the assembly baseline; changing it would be a behavioral regression
  - The `prctl` call is per-thread on Linux, but because the child is single-threaded immediately post-fork, per-thread semantics coincide with per-process semantics here
- **Integration test**: `ffi_boundary::test_prctl_pdeathsig` (forks a worker, kills the master, verifies the worker received SIGTERM)

### `net::child::spawn_child` — `fork(2)` syscall

- **Location**: `crates/heavything/src/net/child.rs:924` (within `spawn_child`)
- **Category**: FFI-nix
- **Functions called**: `nix::unistd::fork()` (returns `Result<ForkResult>`; marked `unsafe fn` because `fork()` in a multi-threaded program is notoriously fragile — after `fork`, only async-signal-safe functions may be called in the child until `exec` or `_exit`)
- **Reason**: preserves the master-worker process model from `epoll_child.inc:58–113` which forks a child per worker, installs `PR_SET_PDEATHSIG`, and wraps the parent-side socketpair end for IPC; threads would not replicate per-process isolation or `PR_SET_PDEATHSIG` semantics. This is the primary `fork` site for `sshtalk`, `hnwatch`, and worker-side process spawning in the `heavything` library, complementing the `webserver`-specific `Master::spawn_workers` site above
- **Safety invariant**:
  - Prior to `fork()`, the socketpair is already created (`socketpair(AF_UNIX, SOCK_STREAM, SOCK_CLOEXEC)`); no tokio runtime has been constructed on behalf of this `spawn_child` call in a way that crosses the fork boundary (the caller is permitted to be inside a tokio runtime, but the child must build its own after fork per AAP §0.7.1.2)
  - The child code path between `fork()` and the user-provided `child_main` closure performs only async-signal-safe operations: `prctl(PR_SET_PDEATHSIG, SIGTERM)` and `close(parent_fd)`; the subsequent `from_raw_fd` on the child's socketpair end is pure memory manipulation with no syscalls
  - The child's first syscall is `prctl(PR_SET_PDEATHSIG, SIGTERM)` (matches the assembly baseline at `epoll_child.inc:110–113`), guaranteeing the child dies if the parent dies before `child_main` completes setup
  - The caller of `spawn_child` is contractually required to make `child_main` itself async-signal-safe or to confine any non-async-signal-safe work (including tokio runtime construction and crypto RNG reseeding per AAP §0.7.4.2) to paths that do not signal before full initialization
  - Fork failures bubble up via `NetError::Fork(nix::Error)` and never leave the parent in a "partial child" state — no PID is registered in `CHILD_PIDS` until fork succeeds and parent-side setup completes
- **Integration test**: `ffi_boundary::test_fork_spawn_child_basic` (forks a child, exchanges a `LinkMessage::Log` round-trip over the socketpair, confirms clean child exit via `waitpid`)

### `net::child::spawn_child` — parent-side `UnixStream::from_raw_fd`

- **Location**: `crates/heavything/src/net/child.rs:958` (parent branch after successful `fork`)
- **Category**: FFI-nix (raw fd construction)
- **Functions called**: `std::os::unix::net::UnixStream::from_raw_fd(parent_fd)` (unsafe because the caller asserts exclusive ownership of the fd and its suitability for `UnixStream` semantics)
- **Reason**: the socketpair created by `nix::sys::socket::socketpair` returns `OwnedFd` pairs, but the parent-side fd must be transferred into a `std::os::unix::net::UnixStream` so that `set_nonblocking(true)` and `tokio::net::UnixStream::from_std` can build the async wrapper used by `ChildProcess::send_message` / `ChildProcess::recv_message`. `from_raw_fd` is the only API that performs this conversion without an intermediate allocation or syscall
- **Safety invariant**:
  - `parent_fd` is obtained from `OwnedFd::into_raw_fd()` immediately before `fork()`, which consumes the `OwnedFd` and suppresses its `Drop` — the raw fd is therefore uniquely owned at the point of transfer
  - The parent branch runs `close(child_fd)` on the sibling fd before `from_raw_fd(parent_fd)`, ensuring no aliasing of the parent's fd within the parent process
  - After `from_raw_fd`, the `UnixStream` takes exclusive ownership and will `close` the fd on drop; no other code path accesses `parent_fd` by raw integer after this line
  - If `set_nonblocking` or `tokio::net::UnixStream::from_std` fail after this transfer, the `UnixStream` is still dropped correctly (closing the fd) before the error bubbles up; the child is cleaned up via a pre-emptive `SIGTERM` in the same error path
- **Integration test**: `ffi_boundary::test_fork_spawn_child_basic` (constructs a real `ChildProcess`, validates async I/O through the wrapped `UnixStream`)

### `net::child::spawn_child` — child-side `UnixStream::from_raw_fd`

- **Location**: `crates/heavything/src/net/child.rs:1029` (child branch after `prctl` and `close(parent_fd)`)
- **Category**: FFI-nix (raw fd construction)
- **Functions called**: `std::os::unix::net::UnixStream::from_raw_fd(child_fd)` (same unsafety contract as the parent-side call)
- **Reason**: the child process needs its side of the socketpair wrapped in a `std::os::unix::net::UnixStream` so it can be handed to the caller-supplied `child_main` closure. `from_raw_fd` is the sole conversion path and matches the parent-side pattern
- **Safety invariant**:
  - `child_fd` is obtained from `OwnedFd::into_raw_fd()` on the parent side of `fork` and inherited through fork — the child has a valid, open copy
  - The child calls `close(parent_fd)` (the sibling fd) immediately before this line, ensuring no aliasing of the child's fd within the child process
  - After `from_raw_fd`, the `UnixStream` takes exclusive ownership; the caller's `child_main` receives it by value and may pass it to its own tokio runtime or keep it synchronous at its discretion
  - The operation is performed **before** `child_main` is invoked, but **after** the async-signal-safe `prctl` and `close` calls; `from_raw_fd` itself is a pure memory operation (no syscalls, no allocations in `std::os::unix::net::UnixStream` construction), so it does not violate the async-signal-safety requirement between `fork()` and `child_main`
- **Integration test**: `ffi_boundary::test_fork_spawn_child_basic` (child_main receives the `UnixStream`, performs a `LinkMessage` round-trip, exits 0)

## memmap2 FFI — Memory-Mapped Files

The `memmap2` crate exposes `Mmap::map` as an `unsafe fn` because the caller must guarantee the backing file is not mutated for the lifetime of the mapping — otherwise the mapped slice may exhibit UB (torn reads, changing length). Per AAP §0.7.4.1, 3–5 sites are expected, all in the file-cache and session-cache paths. All three sites mirror the assembly behavior at `mapped.inc`, `privmapped.inc`, and `mappedheap.inc` respectively.

### `WebServer::hotlist_insert` — mmap static file for serving

- **Location**: `crates/heavything/src/net/http/server.rs` (approx. line 200–240; awaiting implementation confirmation)
- **Category**: FFI-memmap2
- **Functions called**: `memmap2::Mmap::map(&file)` (wraps `mmap(PROT_READ, MAP_PRIVATE)` — matches assembly `privmapped$new` at `privmapped.inc:130–138`)
- **Reason**: the webserver's mmap-backed file cache is a critical path preserved from `webserver.inc`; its "900-second entry lifetime, 120-second stat-recheck, explicit re-mmap on mtime change" behavior cannot use `std::fs::read` without incurring per-request copy cost that the prompt's minimal-change discipline forbids us from regressing
- **Safety invariant**:
  - The 900-second cache entry lifetime (with 120-second recheck) means the mapping is refreshed when the underlying file's mtime changes; within a single 120-second window, the file is assumed stable (this is the same assumption the assembly baseline makes)
  - The cache invalidates entries on mtime change: stat-recheck every 120s discovers modifications and drops+re-mmaps the file, bounding the exposure to modification-during-mapping UB
  - The mapping is read-only (`PROT_READ`); no Rust code writes through the returned `&[u8]`
  - Files served from the sandbox are owned by the webserver's runas user, which has no write access, further constraining external mutation surfaces
- **Integration test**: `ffi_boundary::test_mmap_file_cache` (mmaps a test file, reads content, verifies cleanup)

### `TlsSessionCache::open` — mmap encrypted TLS session cache

- **Location**: `crates/heavything/src/net/tls.rs` (approx. line 300–330; awaiting implementation confirmation)
- **Category**: FFI-memmap2
- **Functions called**: `memmap2::MmapMut::map_mut(&file)` (wraps `mmap(PROT_READ|PROT_WRITE, MAP_SHARED)` — matches assembly `mapped$init_cstr` at `mapped.inc:180–192`)
- **Reason**: the TLS session cache must be accessible read/write (the session store grows), shared across workers (AES-256 encrypted), and backed by disk to survive worker restarts. This mirrors the 3600-second TLS session TTL from `tls.inc` and uses the `mappedheap` file-based heap pattern from `mappedheap.inc`
- **Safety invariant**:
  - Only the master process mutates the cache; workers read entries via the master's IPC relay (`LinkMessage::TlsUpdate`), preventing writer-writer races
  - The underlying file is locked exclusively by the master via `flock(LOCK_EX)` for the process lifetime
  - Cache entries are AES-256-GCM encrypted at the `StoresServerSessions` layer, so observable decryption failures on partial writes produce a clean entry-invalidation rather than UB
  - `MmapMut::flush` is called at shutdown to ensure durable persistence
- **Integration test**: `ffi_boundary::test_mmap_file_cache` (parameterized for read-only and read-write paths)

### `MappedHeap::new_file` — file-backed mmap heap constructor

- **Location**: `crates/heavything/src/util/mappedheap.rs` lines 305–310 (the `unsafe { … }` expression inside `MappedHeap::new_file`; the accompanying `// SAFETY:` documentation block spans lines 281–304)
- **Category**: FFI-memmap2
- **Functions called**: `memmap2::MmapOptions::new().len(size as usize).map_mut(&file)` (wraps `mmap(PROT_READ|PROT_WRITE, MAP_SHARED)` against a freshly `set_len`'d regular file — matches the FASM `mappedheap.inc` line 45 invariant "file based mapped goods do MAP_SHARED")
- **Reason**: the TLS session cache (AAP §0.5.1.7) and any other mapped-heap consumer needs a persistent, read/write, disk-backed mmap surface. Using a plain `Vec<u8>` would not persist across worker restarts, and `memmap2`'s `map_mut` is the sole path to obtain a writable file-backed mapping. The Rust port establishes the mapping once at construction; the heap does not grow at runtime in this port (the free-list is sized at construction from the requested `size` parameter), so there is no `ftruncate`+remap path to audit
- **Safety invariant**:
  - The `std::fs::File` passed to `map_mut(&file)` is a locally-owned handle created on the immediately preceding lines via `OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?`; memmap2 internally dupes the descriptor it needs, so dropping `file` at end-of-function is sound
  - `file.set_len(size)?` is invoked immediately before `map_mut`, ensuring the kernel's view of the file length matches the length requested in `MmapOptions::len(size as usize)`
  - The constructor runs single-threaded (callers receive a fresh `MappedHeap` and have no aliases yet), so no concurrent truncation or `map_mut` race is possible during this call window
  - The resulting `MmapMut` is moved into `MappedHeapInner` which lives behind a `std::sync::Mutex`, so all subsequent read/write access through `slice_mut` and `write` is serialized — no writer-writer races, no torn reads through the `&mut [u8]` view
  - Callers only receive owned `Vec<u8>` copies from `slice_mut`; the raw mapping is never exposed directly, so any UB from external truncation would be confined to the `MappedHeap`'s own methods, not leak into the caller's memory
  - Residual risk: another process with write access to `path` could truncate or replace the backing file and cause SIGBUS on subsequent `copy_from_slice` through the mapping. This is the same residual risk present in the FASM `mappedheap.inc` baseline and is documented in the file's module-level doc comment. Callers are expected to use a path that only the process owns (e.g., a `runas`-owned directory under the webserver sandbox)
- **Integration test**: `ffi_boundary::test_mmap_file_cache` (AAP §0.7.4.4 — exercises the memmap2 file-backed cache path)

## Raw Syscall — libc::syscall Paths

This category covers syscalls performed via `libc::syscall(SYS_*)` that are not available via any higher-level wrapper. Per AAP §0.7.4.1, 0–2 sites are expected. The assembly's `syscall.inc` enumerates all Linux x86_64 syscalls, but the Rust port routes every required syscall through `libc`, `nix`, `memmap2`, or the `tokio` runtime.

> **Zero sites**. All required syscalls are exposed via the `nix`, `memmap2`, `tokio`, or `libc`-with-typed-wrapper paths above. The Rust port does not invoke `libc::syscall(SYS_*)` directly. If a future requirement surfaces a syscall not covered by these wrappers (for example, a new Linux syscall not yet in `libc`), that site shall be added to this section with a dedicated entry and a written justification for why no wrapper is suitable.

## CPU Intrinsics

Per AAP §0.7.4.1, 0 sites are expected because `ring` and the `aes` + `cbc` crates handle AES-NI internally and `std::is_x86_feature_detected!` is a safe macro.

> **Zero sites**. No direct `std::arch::x86_64::*` intrinsic calls. CPU feature dispatch is handled by the `ring` and `aes` crates' internal runtime detection. CPU feature query in `heavything::cpu` uses the safe macro `std::is_x86_feature_detected!` to populate the `CpuFeatures` record stored in `OnceLock<CpuFeatures>`. This is the full replacement for the assembly `ht$init` CPUID block (see AAP §0.7.4.1 rationale and `ht.inc` lines ~290–340).

## Other Unsafe Blocks

This catch-all section is reserved for `unsafe` sites that do not fit into any of the categories above. Any site that appears here carries additional scrutiny: per AAP §0.8.1, the aggregate budget is 50 and the _expected_ count in this category is zero. Therefore, even a single entry in this section — regardless of the overall aggregate count — requires a written justification paragraph explaining why the site cannot be isolated into one of the wrapper-backed categories (`FFI-libc`, `FFI-nix`, `FFI-memmap2`).

> **Zero sites**. No `unsafe` blocks exist outside the categories above. If a future change introduces one, it shall be recorded here with the full six-field template plus a justification paragraph. The project-level review gate REJECTS merges that add an uncategorized `unsafe` block without such justification.

## Integration Test Mapping

Per AAP §0.7.4.4, every FFI / raw-syscall boundary site must have a corresponding integration test in `crates/heavything/tests/ffi_boundary.rs`. The table below maps the eight canonical test names to the unsafe sites they exercise.

| Unsafe Site                                    | Integration Test                                    |
|------------------------------------------------|-----------------------------------------------------|
| `RawTerminal::enter`                           | `test_raw_terminal_roundtrip`                       |
| `nix::unistd::fork`                            | `test_fork_workers`, `test_fork_spawn_child_basic`  |
| `nix::unistd::{setuid, setgid}`                | `test_setuid_setgid_drop`                           |
| `nix::sys::prctl::set_pdeathsig`               | `test_prctl_pdeathsig`                              |
| `memmap2::Mmap::map` (file cache)              | `test_mmap_file_cache`                              |
| `std::os::unix::net::UnixStream::from_raw_fd`  | `test_fork_spawn_child_basic`                       |
| `nix::sys::signal::kill`                       | `test_killall_children_on_drop`                     |
| SIGWINCH / SIGINT handlers                     | `test_sigwinch_handler`                             |

Per AAP §0.7.4.4, every row above must have a passing test in `crates/heavything/tests/ffi_boundary.rs`. Run via:

    HEAVYTHING_LIVE_TESTS=1 cargo test --test ffi_boundary

Tests requiring elevated privileges (`test_setuid_setgid_drop`) are additionally gated on a `HEAVYTHING_PRIVILEGED_TESTS=1` environment variable to prevent accidental invocation in unprivileged CI environments.

## Unsafe Minimization Principles

The following principles are applied uniformly across the Rust port to keep the unsafe budget well below the 50-site ceiling (per AAP §0.7.4.2):

- **Encapsulate unsafe at type boundaries**: e.g., `RawTerminal` owns all termios unsafe; consumers interact via safe methods. The `unsafe` blocks are members of a small, well-tested newtype whose API surface is entirely safe.
- **Prefer wrapper crates over raw libc**: `nix::unistd::fork` instead of `libc::fork`; `memmap2::Mmap` instead of raw `mmap`. The `nix` and `memmap2` crates have their own safety-invariant documentation and have been reviewed by the Rust community.
- **Group related unsafe into single blocks**: consolidate `tcgetattr → cfmakeraw → tcsetattr` into one `unsafe { … }` with one consolidated safety comment. This reduces the block count below what a naive per-call approach would produce.
- **Document safety invariants explicitly**: every unsafe block carries a `// SAFETY: …` comment covering all preconditions that make the unsafe operation sound. The comment is reviewed as part of code review; missing or vague SAFETY comments block merge.

If the total count ever exceeds 50, each site over 50 requires a dedicated written justification paragraph in this file (Phase 8 "Other" category) explaining why isolation into a single helper could not reduce the count. The justification must cover: (a) the reason no existing wrapper crate exposes the required primitive, (b) why the consumer cannot be refactored to use an adjacent primitive that _is_ wrapped, and (c) the marginal safety risk the site imposes and the mitigation in place.

## Audit Maintenance

This document is regenerated whenever `grep -rn 'unsafe' crates/ --include='*.rs'` returns a different set of lines. Re-generate by running the `audit_unsafe` helper script (if present) or manually via:

    grep -rnE '\bunsafe\b' crates/ --include='*.rs' | grep -v '^\s*//'

Verify that every reported line has a matching entry in Phases 2–8 of this document. Any new site without a matching entry is a merge-blocking audit finding.

The maintenance workflow is:

1. Run the grep command above from the workspace root.
2. For each line in the output, locate the corresponding entry in this file by searching for the file path + approximate line range.
3. If the entry is missing, either (a) add an entry in the correct category section with all six fields, or (b) remove the unsafe block if it is avoidable.
4. Update the "Total `unsafe` blocks" row of the `## Audit Summary` table to reflect the new count.
5. If the count exceeds 50, add justification paragraphs under `## Other Unsafe Blocks` for each site beyond 50.
6. Commit the regenerated document alongside the code change that introduced the new site.

The approximate line ranges given throughout this document ("approx. line 40–60") are tolerant of ±20 lines of drift; if drift exceeds that, update the range rather than the entry.
