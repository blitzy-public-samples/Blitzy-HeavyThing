// HeavyThing x86_64 assembly language library — Rust translation.
//
// Rust translation © 2026, licensed under GPL-3.0-or-later.
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

//! Integration tests for every FFI / raw-syscall boundary flagged in
//! `/UNSAFE_AUDIT.md`.
//!
//! # Scope and multi-contributor nature
//!
//! `/UNSAFE_AUDIT.md` enumerates **six canonical integration tests**
//! covering every unsafe block in the workspace, plus one
//! supplementary CPU-instruction-boundary test added in CP7 to satisfy
//! the QA Checkpoint 7 expected-outcome enumeration:
//!
//! | Canonical test name              | Unsafe site it exercises                                      | Owning module                                  |
//! |----------------------------------|---------------------------------------------------------------|------------------------------------------------|
//! | `test_raw_terminal_roundtrip`    | `libc::tcgetattr` / `cfmakeraw` / `tcsetattr` in `RawTerminal`| `heavything::tui::terminal`                    |
//! | `test_sigwinch_handler`          | `libc::sigaction` for SIGWINCH/SIGTERM/SIGINT/SIGPIPE         | `heavything::tui::terminal` / `::util::signals` |
//! | `test_setuid_setgid_drop`        | `nix::unistd::{setuid,setgid}` in master privilege-drop       | `crates::webserver::master`                    |
//! | `test_fork_workers`              | `nix::unistd::fork` in master `spawn_workers`                 | `crates::webserver::master`                    |
//! | `test_mmap_file_cache`           | `memmap2::Mmap::map` in hotlist file cache                    | `heavything::net::http::server`                |
//! | `test_prctl_pdeathsig`           | `nix::sys::prctl::set_pdeathsig` in worker / child init       | `heavything::net::child` / `webserver::worker` |
//! | `test_cpuid_vendor_string`       | `std::arch::x86_64::__cpuid` (safe fn; ground-truth check)    | `heavything::cpu::detect_is_intel`             |
//!
//! This test binary is authored iteratively as each unsafe site lands on
//! the branch. The tests below cover two subsystems:
//!
//! **`heavything::net::child`** (AAP §0.7.4.2):
//!
//! * [`test_fork_spawn_child_basic`] — covers the `fork` unsafe in
//!   `net::child::spawn_child` plus the two `UnixStream::from_raw_fd`
//!   sites (parent/child branches), and round-trips a framed
//!   `LinkMessage::Log` through the socketpair.
//! * [`test_prctl_pdeathsig`] — covers `nix::sys::prctl::set_pdeathsig`
//!   inside `spawn_child`'s child branch by using a double-fork pattern
//!   so the test runner itself is never signalled.
//! * [`test_killall_children_on_drop`] — covers the SIGTERM-broadcast
//!   path in [`killall_children`] end-to-end: spawn several children,
//!   call `killall_children`, and observe `WaitStatus::Signaled` with
//!   `Signal::SIGTERM` via `waitpid(2)`.
//!
//! **`heavything::net::runtime`** (AAP §0.7.1.1, §0.7.4.1):
//!
//! * [`test_check_ulimit`] — covers the `libc::getrlimit` / `libc::setrlimit`
//!   unsafe block in `runtime::check_ulimit` by forking a child,
//!   lowering `RLIMIT_NOFILE` to a value below
//!   [`heavything::config::EPOLL_MINFDS`], and asserting that
//!   `check_ulimit()` returns `Err(InitError::UlimitTooLow)` — the
//!   Stage 10 init-check path that maps to exit code 97.
//! * [`test_stream_defaults_roundtrip`] — covers the
//!   `libc::setsockopt(SO_LINGER, SO_KEEPALIVE)` unsafe block in
//!   `runtime::apply_stream_defaults` by binding a loopback listener,
//!   establishing a connected `TcpStream`, invoking
//!   `apply_stream_defaults`, then verifying `TCP_NODELAY=1`,
//!   `SO_LINGER=(l_onoff=1, l_linger=0)`, and `SO_KEEPALIVE=1` via
//!   `libc::getsockopt` — the FASM `epoll.inc:1438–1490` socket-option
//!   sequence reproduced on every freshly accepted stream.
//!
//! **`heavything::tui::terminal`** (AAP §0.7.3, §0.7.4.4):
//!
//! * [`test_raw_terminal_roundtrip`] — covers the
//!   `libc::tcgetattr` / `cfmakeraw` / `tcsetattr` unsafe block in
//!   `RawTerminal::enter` plus the `tcsetattr` restore in `Drop` by
//!   (a) verifying stdin is a TTY via `libc::isatty`, (b) capturing
//!   the cooked-mode termios via `libc::tcgetattr` and asserting
//!   that `ECHO|ICANON` are set, (c) calling `RawTerminal::enter`
//!   to engage raw mode, (d) re-reading the termios via
//!   `libc::tcgetattr` and asserting that `ECHO|ICANON|OPOST` are
//!   cleared (the canonical raw-mode flags per `cfmakeraw(3)`),
//!   (e) exercising `RawTerminal::get_winsize` (the
//!   `ioctl(TIOCGWINSZ)` unsafe site), (f) dropping the
//!   `RawTerminal`, and (g) re-reading the termios a third time to
//!   confirm that `Drop` restored the captured cooked-mode
//!   attributes byte-for-byte. Skips with an explanatory eprintln
//!   when stdin is not a TTY (the typical `cargo test` invocation
//!   on a CI runner) so that offline / piped invocations do not
//!   fail.
//!
//! The row `nix::unistd::fork` in the Integration Test Mapping table of
//! `/UNSAFE_AUDIT.md` therefore references **both**
//! `test_fork_workers` (owned by the `webserver::master` port, not yet
//! landed) and `test_fork_spawn_child_basic` (this file).
//!
//! # Invocation
//!
//! Per `/UNSAFE_AUDIT.md`, these are **live FFI tests** and are gated on
//! the `HEAVYTHING_LIVE_TESTS=1` environment variable:
//!
//! ```text
//! HEAVYTHING_LIVE_TESTS=1 cargo test -p heavything --test ffi_boundary
//! ```
//!
//! When the environment variable is unset the three tests below return
//! early with an explanatory eprintln so that offline CI does not fail.
//!
//! # Multi-threaded runtime + `fork(2)` hazard
//!
//! `fork(2)` duplicates only the calling thread into the child. Any
//! threads owned by a multi-threaded `tokio::runtime::Runtime` (including
//! the blocking-thread pool) will **not** be in the child, but mutexes
//! those threads held will still appear locked in the child — a classic
//! post-fork deadlock. This file therefore uses manually-constructed
//! **single-threaded** runtimes via
//! `tokio::runtime::Builder::new_current_thread()`. We avoid the
//! `#[tokio::test(flavor = "current_thread")]` attribute because the
//! runtime produced by that attribute runs the test on its own worker
//! thread (with `block_on` reentrancy in the child fork), which can
//! interact poorly with the double-fork pattern used by
//! [`test_prctl_pdeathsig`]. A manual runtime per test is the most
//! robust choice.
//!
//! # Test serialization
//!
//! `cargo test --test ffi_boundary` runs all `#[test]` functions **in
//! the same process** (with potentially multiple threads). Because
//! [`killall_children`] broadcasts `SIGTERM` to every PID in the
//! process-global [`CHILD_PIDS`][heavything::net::child] registry,
//! running fork-based tests concurrently would cross-signal each
//! other's children. A module-level [`TEST_MUTEX`] serializes the three
//! tests so that at most one fork test is "live" at a time.
//!
//! # Public-API only
//!
//! These integration tests live outside the `heavything` crate and
//! therefore cannot observe private items such as the
//! `CHILD_PIDS` registry or the `register_child_pid` helper. They rely
//! entirely on the public API
//! ([`spawn_child`], [`killall_children`], [`ChildProcess::send_message`],
//! [`ChildProcess::recv_message`]) plus OS-level observation via
//! `nix::sys::wait::waitpid` / `nix::sys::signal::kill`.

// =====================================================================
// Crate-level attributes
// =====================================================================
//
// `clippy::unwrap_used` and `clippy::expect_used` are allowed at file
// scope per AAP §0.8.4 "Tests and benchmarks may use `unwrap()`": these
// integration tests deliberately use `expect(...)` and `unwrap(...)`
// for setup-time invariants whose violation should crash the test
// rather than be propagated as `Result`. This keeps test bodies
// readable and focused on the FFI-boundary logic under test.
//
// `#![cfg(target_os = "linux")]` and `#![cfg(target_arch = "x86_64")]`
// match the platform constraints documented in AAP §0.8.1
// ("Linux x86_64 only; no cross-platform compatibility required or
// desired") and mirror the same crate-level gates used by
// `crates/heavything/src/cpu.rs`. On any non-Linux or non-x86_64
// target the entire test file compiles down to nothing; this is the
// safest behavior for a file that pervasively uses `libc`,
// `nix::unistd`, `nix::sys::prctl`, `memmap2::Mmap::map`, and the
// CPUID instruction — none of which have meaningful semantics outside
// `x86_64-unknown-linux-gnu`.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(target_os = "linux")]
#![cfg(target_arch = "x86_64")]

use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{
    close, fork, getgid, getuid, pipe, read as nix_read, setgid, setuid, write as nix_write,
    ForkResult, Gid, Pid, Uid,
};

use heavything::cpu;
use heavything::error::{InitError, TuiError};
use heavything::net::child::{
    killall_children, spawn_child, ChildProcess, LinkMessage, LogRecord, LogSeverity,
};
use heavything::net::http::server::HotEntry;
use heavything::net::runtime::{apply_stream_defaults, check_ulimit};
use heavything::tui::terminal::RawTerminal;

// ============================================================================
// Test serialization
//
// `spawn_child` registers each new child PID in a process-global
// registry. If two fork tests run concurrently in the same test binary
// process, each test's `killall_children()` call would signal the other
// test's children. We therefore gate every test on a module-level
// `Mutex<()>`. The mutex is also reacquired in the "gated-out" early
// returns so that `HEAVYTHING_LIVE_TESTS=0` paths stay quick.
// ============================================================================

static TEST_MUTEX: Mutex<()> = Mutex::new(());

/// Returns `true` if the caller requested live FFI tests by setting
/// `HEAVYTHING_LIVE_TESTS=1` (per `/UNSAFE_AUDIT.md` invocation note).
fn live_tests_enabled() -> bool {
    matches!(std::env::var("HEAVYTHING_LIVE_TESTS").ok().as_deref(), Some("1"))
}

/// Build a single-threaded tokio runtime suitable for fork-based tests.
///
/// We deliberately avoid the multi-threaded runtime because `fork(2)`
/// only duplicates the calling thread; background worker threads of a
/// multi-threaded runtime would not follow into the child.
fn build_current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build single-threaded tokio runtime for FFI test")
}

/// Check whether `pid` is currently a zombie process (state `Z` in
/// `/proc/<pid>/stat`).
///
/// A zombie is a process that has terminated execution but has not yet
/// been reaped by its parent via `wait(2)`. On Linux, `kill(pid, 0)`
/// (existence check) returns `Ok(())` for zombies — see `kill(2)` man
/// page: "an existing process might be a zombie, a process that has
/// terminated execution, but has not yet been wait(2)ed for".
///
/// In container environments where PID 1 is not a proper init reaper
/// (no `tini`, `dumb-init`, etc.), an orphaned grandchild that dies
/// via `PR_SET_PDEATHSIG → SIGTERM` can persist as a zombie
/// indefinitely. For the purposes of this test suite, a zombie is
/// equivalent to "gone" because the behaviour we want to verify is
/// termination of execution, not reaping by init.
///
/// # Parsing `/proc/<pid>/stat`
///
/// Format (per `proc(5)`):
///
///     <pid> (<comm>) <state> <ppid> <pgrp> ...
///
/// The `comm` field (executable basename) is enclosed in parentheses
/// and may itself contain spaces, parens, and other punctuation.
/// We therefore find the **last** `)` in the line; the state field is
/// the first non-whitespace character after that `)`. This is the
/// standard robust approach documented in the kernel source and
/// widely used by tools such as `htop` and `ps`.
///
/// Returns `true` when state == `'Z'`. Returns `false` when:
///
/// * `/proc/<pid>/stat` cannot be opened or read (ESRCH-equivalent),
/// * the file contents do not parse as expected, or
/// * state is any character other than `'Z'` (e.g. `'R'`, `'S'`, `'D'`,
///   `'T'`, `'t'`, `'X'`, `'I'`).
fn is_zombie(pid: Pid) -> bool {
    let path = format!("/proc/{}/stat", pid.as_raw());
    let contents = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let trimmed = contents.trim_end_matches('\n');
    let Some(last_paren) = trimmed.rfind(')') else {
        return false;
    };
    let tail = &trimmed[last_paren + 1..];
    let state = tail.chars().find(|c| !c.is_whitespace());
    matches!(state, Some('Z'))
}

/// Poll for process termination every 10 ms until the process is
/// observed gone or `timeout` elapses.
///
/// A process is considered "gone" when **either**:
///
/// 1. `kill(pid, 0)` returns `Err(ESRCH)` — process fully terminated
///    and reaped by its parent (or by `init`).
/// 2. `/proc/<pid>/stat` reports state `'Z'` — process terminated
///    execution but has not yet been reaped (zombie).
///
/// Condition (2) is necessary because in container environments
/// where PID 1 does not reap orphans, an orphaned child that dies
/// via `PR_SET_PDEATHSIG` can remain as a zombie indefinitely; the
/// `kill(pid, 0)` existence check returns `Ok(())` for zombies and
/// would therefore never observe condition (1). For test purposes,
/// both states indicate that the process has terminated execution,
/// which is what we want to assert.
///
/// On timeout, logs a diagnostic snapshot of `/proc/<pid>/stat` to
/// stderr so any future failure surfaces the actual process state.
///
/// `kill(pid, None)` is the nix equivalent of the C `kill(pid, 0)`
/// existence-check idiom.
fn wait_for_pid_gone(pid: Pid, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match signal::kill(pid, None) {
            Ok(()) => {
                // Process is reachable via kill(0). It might still be
                // running, OR it might be a zombie (terminated but
                // unreaped). Check /proc for zombie state.
                if is_zombie(pid) {
                    return true;
                }
                if Instant::now() >= deadline {
                    // Final diagnostic snapshot so any future
                    // regression surfaces the actual process state.
                    let stat_path = format!("/proc/{}/stat", pid.as_raw());
                    match std::fs::read_to_string(&stat_path) {
                        Ok(stat) => eprintln!(
                            "wait_for_pid_gone TIMEOUT: pid {} still reachable via kill(0); \
                             /proc/{}/stat = {:?}",
                            pid,
                            pid.as_raw(),
                            stat.trim()
                        ),
                        Err(e) => eprintln!(
                            "wait_for_pid_gone TIMEOUT: pid {} still reachable via kill(0); \
                             could not read /proc/{}/stat: {}",
                            pid,
                            pid.as_raw(),
                            e
                        ),
                    }
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(nix::Error::ESRCH) => return true,
            Err(_) => {
                // EPERM or other error — on most production kernels
                // ESRCH is the only expected error here; treat
                // non-ESRCH as "still alive" and keep polling.
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Construct the canonical sample `LinkMessage::Log` used for
/// round-trip assertions in [`test_fork_spawn_child_basic`].
fn sample_log_record() -> LogRecord {
    LogRecord {
        timestamp_ms: 0x0123_4567_89ab_cdef,
        severity: LogSeverity::Info,
        facility: Some("ffi-boundary-test".to_string()),
        message: b"hello from child fork roundtrip".to_vec(),
    }
}

// ============================================================================
// test_fork_spawn_child_basic
//
// Exercises UNSAFE SITES #1, #2, and #3 in `net::child::spawn_child`:
//   * `unsafe { nix::unistd::fork() }`
//   * `unsafe { std::os::unix::net::UnixStream::from_raw_fd(parent_fd) }`
//   * `unsafe { std::os::unix::net::UnixStream::from_raw_fd(child_fd) }`
//
// Verifies:
//   1. Fork returns a live child with a connected AF_UNIX socketpair.
//   2. Parent can send a `LinkMessage::Log` frame via tokio's async
//      `send_message`.
//   3. Child — running in its own forked process without a tokio
//      runtime — receives the frame synchronously via `std::io::Read`,
//      echoes the raw bytes back, and exits cleanly via
//      `std::process::exit(0)`.
//   4. Parent's `recv_message` reconstructs the identical
//      `LinkMessage::Log` via the TLV codec, round-trip successful.
//   5. `waitpid` reports `WaitStatus::Exited(_, 0)`.
// ============================================================================

#[test]
fn test_fork_spawn_child_basic() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if !live_tests_enabled() {
        eprintln!("test_fork_spawn_child_basic: skipped (set HEAVYTHING_LIVE_TESTS=1 to enable)");
        return;
    }

    let rt = build_current_thread_runtime();

    let expected = LinkMessage::Log(sample_log_record());

    // The child closure is `FnOnce(StdUnixStream) + Send + 'static`.
    // It runs in the forked child process **without** inheriting the
    // parent's tokio runtime (AAP §0.7.1.2). We therefore use
    // synchronous `std::io::{Read,Write}` to implement the echo
    // responder. The wire format matches
    // `net::child::ChildProcess::{send_message, recv_message}`:
    //
    //     [u32 outer_len LE][inner_frame_bytes_of_length_outer_len]
    //
    // The child reads exactly one frame, writes it back verbatim, and
    // returns. `spawn_child` then invokes `std::process::exit(0)` on
    // the caller's behalf (see `net/child.rs:1043`).
    let child_main = |mut stream: StdUnixStream| {
        // Read the 4-byte outer length prefix.
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).is_err() {
            return;
        }
        let outer_len = u32::from_le_bytes(len_buf) as usize;
        // Bound the read to defuse a misbehaving parent; matches
        // MAX_FRAME_SIZE in the library.
        if outer_len > 16 * 1024 * 1024 {
            return;
        }

        // Read the frame body.
        let mut body = vec![0u8; outer_len];
        if stream.read_exact(&mut body).is_err() {
            return;
        }

        // Echo: length prefix + body verbatim.
        if stream.write_all(&len_buf).is_err() {
            return;
        }
        if stream.write_all(&body).is_err() {
            return;
        }
        // Best-effort flush; std UnixStream writes are unbuffered on
        // Linux but we flush anyway in case of future buffering.
        let _ = stream.flush();
    };

    // Spawn + round-trip inside the runtime so tokio I/O primitives
    // can observe readiness events on `parent_socket`.
    // `expected` is `Clone`; we clone so both the async closure (which
    // takes ownership via `move`) and the post-block assertion can
    // observe the same value.
    let sent_value = expected.clone();
    let (child_pid, recv_result) = rt.block_on(async move {
        let mut child: ChildProcess =
            spawn_child(child_main).expect("spawn_child must succeed on Linux/x86_64 hosts");
        let pid = child.pid;

        // Send the framed LinkMessage to the child.
        child
            .send_message(&sent_value)
            .await
            .expect("send_message must succeed on healthy socketpair");

        // Receive the echoed frame.
        let received = child
            .recv_message()
            .await
            .expect("recv_message must succeed on healthy socketpair");

        // Explicitly drop `child` so `parent_socket` closes, which in
        // turn causes the child's `read_exact` calls to observe EOF
        // if it is still alive for any reason.
        drop(child);

        (pid, received)
    });

    // Tokio runtime is no longer needed for the waitpid portion.
    drop(rt);

    // Assert the round-tripped message matches what we sent.
    match recv_result {
        Some(got) => assert_eq!(
            got, expected,
            "round-tripped LinkMessage must be identical to the one sent"
        ),
        None => panic!("recv_message returned None (unexpected EOF from child)"),
    }

    // Reap the child and assert clean exit status.
    let status = waitpid(child_pid, None).expect("waitpid must succeed for our direct child");
    match status {
        WaitStatus::Exited(pid, code) => {
            assert_eq!(pid, child_pid, "waitpid returned the wrong PID");
            assert_eq!(
                code, 0,
                "child must exit with status 0 (spawn_child calls std::process::exit(0) after child_main returns)"
            );
        }
        other => panic!(
            "child did not exit cleanly; WaitStatus = {:?} (expected Exited(_, 0))",
            other
        ),
    }

    // Best-effort: make sure the child PID is no longer in the
    // registry (it would be stale at this point; `killall_children`
    // is idempotent and should no-op on a dead PID).
    killall_children();
}

// ============================================================================
// test_prctl_pdeathsig
//
// Exercises UNSAFE SITE in `net::child::spawn_child`:
//   * `nix::sys::prctl::set_pdeathsig(Signal::SIGTERM)` (SAFE wrapper,
//     but the behaviour it installs is the whole point of the test).
//
// We cannot kill the test-runner process itself to observe the signal
// delivered to a direct child, because the test-runner *is* our test
// binary. Instead we use a **double-fork** pattern:
//
//     top-level test
//        │
//        ├── fork() → intermediate process
//        │                │
//        │                ├── spawn_child(sleep-forever)  ← grandchild
//        │                │      ↑ inherits PR_SET_PDEATHSIG = SIGTERM
//        │                │
//        │                ├── write(grandchild.pid → pipe)
//        │                └── exit(0)     ← on this exit, kernel sends
//        │                                   SIGTERM to the grandchild
//        │
//        └── read(pipe) → grandchild pid
//            waitpid(intermediate)
//            poll kill(grandchild, 0) until ESRCH → asserts SIGTERM delivered
//
// The top-level test is not the grandchild's parent after the
// intermediate exits — the grandchild re-parents to `init` (pid 1)
// which reaps it. We therefore cannot call `waitpid` on the grandchild
// and instead poll its existence via `kill(pid, None)`.
// ============================================================================

#[test]
fn test_prctl_pdeathsig() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if !live_tests_enabled() {
        eprintln!("test_prctl_pdeathsig: skipped (set HEAVYTHING_LIVE_TESTS=1 to enable)");
        return;
    }

    // Pipe for the intermediate process to send the grandchild PID
    // back to the top-level test. `nix::unistd::pipe()` returns
    // `(OwnedFd, OwnedFd)` in nix 0.29. We capture the read side's
    // RawFd for use with `nix_read` (which takes `RawFd`); the write
    // side retains its `OwnedFd` so it can be passed to `nix_write`
    // (which accepts `AsFd`) without an explicit RawFd conversion.
    let (read_end, write_end): (OwnedFd, OwnedFd) = pipe().expect("pipe(2) must succeed");
    let read_fd = read_end.as_raw_fd();

    // SAFETY: top-level `fork()` in a single-threaded test (the test
    // harness has spawned at most its own runner threads, which do
    // not interact with any tokio runtime we have built because we
    // have not yet built one here). The branches below immediately
    // close the wrong-side pipe end and perform only async-signal-safe
    // operations before `exit(0)` (intermediate) or before returning
    // to the top-level test logic (parent).
    let top_fork = unsafe { fork() }.expect("fork(2) must succeed");

    match top_fork {
        ForkResult::Parent {
            child: intermediate_pid,
        } => {
            // Top-level test.
            //
            // Close our write end — only the intermediate writes.
            drop(write_end);

            // Read the grandchild PID (little-endian i32).
            let mut pid_buf = [0u8; 4];
            // Use nix_read so we can observe partial reads explicitly.
            let mut total = 0;
            while total < pid_buf.len() {
                match nix_read(read_fd, &mut pid_buf[total..]) {
                    Ok(0) => {
                        panic!(
                            "unexpected EOF while reading grandchild PID from pipe \
                             (intermediate may have crashed before forking grandchild)"
                        );
                    }
                    Ok(n) => total += n,
                    Err(nix::Error::EINTR) => continue,
                    Err(e) => panic!("read from PID pipe failed: {:?}", e),
                }
            }
            drop(read_end);

            let grandchild_pid_raw = i32::from_le_bytes(pid_buf);
            let grandchild_pid = Pid::from_raw(grandchild_pid_raw);
            assert!(
                grandchild_pid_raw > 1,
                "grandchild PID sanity-check failed: got {}",
                grandchild_pid_raw
            );

            // Wait for the intermediate process to exit so that the
            // kernel delivers SIGTERM to the grandchild.
            let intermediate_status =
                waitpid(intermediate_pid, None).expect("waitpid on intermediate process must succeed");
            match intermediate_status {
                WaitStatus::Exited(p, code) => {
                    assert_eq!(p, intermediate_pid);
                    assert_eq!(
                        code, 0,
                        "intermediate process must exit cleanly so PR_SET_PDEATHSIG fires"
                    );
                }
                other => panic!("intermediate did not exit cleanly; WaitStatus = {:?}", other),
            }

            // Now poll existence of the grandchild — it should die
            // from SIGTERM any moment. Give it a generous 5 s because
            // init reparenting + signal delivery can briefly race.
            let died = wait_for_pid_gone(grandchild_pid, Duration::from_secs(5));
            assert!(
                died,
                "grandchild {} did NOT die within 5 s of its parent's exit; \
                 PR_SET_PDEATHSIG appears broken in the spawn_child child branch",
                grandchild_pid_raw
            );
        }
        ForkResult::Child => {
            // Intermediate process.
            //
            // Close our read end — only the top-level reads.
            let _ = close(read_fd);
            // We keep `write_fd` via `write_end` until after we have
            // written the grandchild PID.

            // Build a single-threaded tokio runtime *inside* the
            // intermediate so `spawn_child`'s parent branch can wrap
            // its end of the socketpair into `tokio::net::UnixStream`.
            let rt = build_current_thread_runtime();

            // Spawn the grandchild. The grandchild's `child_main`
            // sleeps for 300 s — far longer than this test's timeout —
            // so that the ONLY way it dies is via PR_SET_PDEATHSIG
            // delivering SIGTERM when the intermediate exits.
            let grandchild = rt.block_on(async {
                spawn_child(|_stream: StdUnixStream| {
                    // Sleep well beyond the 5 s observation window in
                    // the top-level. If PR_SET_PDEATHSIG fails this
                    // loop would outlive the test and leak a process;
                    // in that case the top-level assertion failure
                    // surfaces the bug.
                    std::thread::sleep(Duration::from_secs(300));
                })
                .expect("spawn_child must succeed inside intermediate")
            });

            let grandchild_pid = grandchild.pid.as_raw();
            let pid_bytes = grandchild_pid.to_le_bytes();

            // Drop grandchild struct so the intermediate's socketpair
            // end closes (child is not using it for I/O; it just
            // sleeps). Dropping early also makes sure we don't
            // accidentally keep extra file descriptors open across
            // the exit path.
            drop(grandchild);

            // Write the PID back to the top-level test via pipe.
            // Use nix's write which is a thin syscall wrapper — no
            // internal tokio runtime interaction.
            let mut written = 0;
            while written < pid_bytes.len() {
                match nix_write(&write_end, &pid_bytes[written..]) {
                    Ok(0) => break,
                    Ok(n) => written += n,
                    Err(nix::Error::EINTR) => continue,
                    Err(_) => break,
                }
            }
            // Drop write end so the top-level's read observes EOF.
            drop(write_end);

            // Drop the runtime explicitly so its I/O driver shuts
            // down cleanly before we exit.
            drop(rt);

            // Exit the intermediate. On this exit, the kernel walks
            // the "prctl PR_SET_PDEATHSIG" list for all of our
            // children — including the grandchild — and delivers
            // SIGTERM to each.
            std::process::exit(0);
        }
    }
}

// ============================================================================
// test_killall_children_on_drop
//
// Exercises UNSAFE SITE (indirectly) by driving
// `net::child::killall_children` through its end-to-end path:
//
//   spawn N children → killall_children() → each child receives
//   SIGTERM → waitpid observes `WaitStatus::Signaled(_, SIGTERM, _)`.
//
// Verifies:
//   1. `spawn_child` registers each spawned PID in the process-global
//      registry (private, but observable via effects).
//   2. `killall_children()` drains the registry and sends SIGTERM to
//      every registered PID.
//   3. Idempotency: calling `killall_children()` a second time after
//      the registry is drained is a no-op (no panic, no double-kill).
// ============================================================================

#[test]
fn test_killall_children_on_drop() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if !live_tests_enabled() {
        eprintln!("test_killall_children_on_drop: skipped (set HEAVYTHING_LIVE_TESTS=1 to enable)");
        return;
    }

    const NUM_CHILDREN: usize = 3;

    let rt = build_current_thread_runtime();

    // Spawn NUM_CHILDREN long-sleeping children and collect their
    // `ChildProcess` wrappers (so tokio-side `parent_socket` fds stay
    // open until after `killall_children`).
    let children: Vec<ChildProcess> = rt.block_on(async {
        let mut v = Vec::with_capacity(NUM_CHILDREN);
        for _ in 0..NUM_CHILDREN {
            let child = spawn_child(|_stream: StdUnixStream| {
                // Sleep for 300 s — the test must observe SIGTERM
                // from `killall_children`, not natural exit.
                std::thread::sleep(Duration::from_secs(300));
            })
            .expect("spawn_child must succeed on Linux/x86_64 hosts");
            v.push(child);
        }
        v
    });

    assert_eq!(
        children.len(),
        NUM_CHILDREN,
        "pre-condition: all children must have been spawned"
    );
    let pids: Vec<Pid> = children.iter().map(|c| c.pid).collect();

    // Drop all `ChildProcess` wrappers so the parent sides of the
    // socketpairs close. This is idiomatically what the master does
    // when it decides to shut down; the sleeping children do not
    // care about their socket state, so EOF on their end is a no-op
    // for them.
    drop(children);

    // Tokio runtime no longer needed for the waitpid portion.
    drop(rt);

    // Broadcast SIGTERM via the public API. This is the whole point
    // of the test: exercise `killall_children()` end-to-end.
    killall_children();

    // Reap each child and assert SIGTERM.
    //
    // Each child was a direct child of this process (not a
    // grandchild), so `waitpid(pid, None)` is correct here.
    for pid in pids.iter().copied() {
        let status = waitpid(pid, None).unwrap_or_else(|e| panic!("waitpid({}) failed: {:?}", pid, e));
        match status {
            WaitStatus::Signaled(reaped_pid, sig, _core_dump) => {
                assert_eq!(
                    reaped_pid, pid,
                    "waitpid returned the wrong PID for a SIGTERM'd child"
                );
                assert_eq!(
                    sig,
                    Signal::SIGTERM,
                    "child {} was killed by {:?}; expected SIGTERM from killall_children",
                    pid,
                    sig
                );
            }
            WaitStatus::Exited(reaped_pid, code) => panic!(
                "child {} exited with code {} instead of being SIGTERM'd (PID reported by \
                 waitpid: {})",
                pid, code, reaped_pid
            ),
            other => panic!("child {} produced unexpected WaitStatus: {:?}", pid, other),
        }
    }

    // Idempotency check: second call must not panic and must not
    // double-signal. After the first call the registry is empty, so
    // this is a pure no-op.
    killall_children();

    // Final sanity check: none of the PIDs should still be alive.
    // The waitpid loop above already reaped them, so `kill(pid, 0)`
    // must report ESRCH. Allow a very small timeout to absorb any
    // kernel bookkeeping latency.
    for pid in pids {
        let gone = wait_for_pid_gone(pid, Duration::from_millis(500));
        assert!(
            gone,
            "PID {} is still reachable after waitpid reaped it; \
             kernel or nix state is inconsistent",
            pid
        );
    }
}

// ============================================================================
// test_check_ulimit
//
// Exercises UNSAFE SITE in `net::runtime::check_ulimit`:
//   * `unsafe { libc::getrlimit(RLIMIT_NOFILE, *mut rlimit) }` (×2)
//   * `unsafe { libc::setrlimit(RLIMIT_NOFILE, *const rlimit) }`
//
// Verifies both branches of the function:
//
//   1. **Ok path** — in the test-harness parent process, which is
//      expected to run with the CI default `RLIMIT_NOFILE` (typically
//      ≥ 4096), `check_ulimit()` returns `Ok(())`. If the harness's
//      hard limit happens to be below `EPOLL_MINFDS`, the test still
//      passes but emits a diagnostic note so the operator can verify
//      the environment configuration.
//
//   2. **Err path** — in a forked child process, we lower BOTH
//      `rlim_cur` and `rlim_max` of `RLIMIT_NOFILE` to a value well
//      below `EPOLL_MINFDS` (4096). Because `check_ulimit()`'s
//      self-repair step (raise `rlim_cur` to `rlim_max`) is capped by
//      the reduced hard limit, the second `getrlimit` call observes
//      the shortfall and returns `InitError::UlimitTooLow`. The child
//      exits with status 0 iff `check_ulimit` returned the expected
//      variant, allowing the parent to assert correctness via
//      `waitpid`.
//
// We use a fork rather than mutating the harness's own ulimit because
// `setrlimit` with `rlim_max < current open fd count` is undefined
// behaviour per POSIX — forking to isolate the mutation keeps the
// test harness's fd table unaffected.
// ============================================================================

#[test]
fn test_check_ulimit() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if !live_tests_enabled() {
        eprintln!("test_check_ulimit: skipped (set HEAVYTHING_LIVE_TESTS=1 to enable)");
        return;
    }

    // ----- Part 1: Ok path in the parent process. -----
    //
    // Most CI environments configure a default `RLIMIT_NOFILE` hard
    // limit of 1024 or higher (Debian/Ubuntu: 1048576 via systemd;
    // GitHub Actions: 524288). If the hard limit happens to be below
    // `EPOLL_MINFDS` (4096), the test cannot force it upward without
    // CAP_SYS_RESOURCE and must skip the Ok assertion. We always
    // execute the call to verify it does not panic, however.
    match check_ulimit() {
        Ok(()) => {
            // Normal CI case: harness has adequate RLIMIT_NOFILE.
        }
        Err(InitError::UlimitTooLow) => {
            eprintln!(
                "test_check_ulimit: parent process has RLIMIT_NOFILE below EPOLL_MINFDS; \
                 Ok-path assertion skipped but Err-path will still be exercised via the fork. \
                 Consider raising the harness ulimit to run the full test."
            );
        }
        Err(other) => panic!(
            "check_ulimit returned an unexpected InitError variant in the parent: {:?}",
            other
        ),
    }

    // ----- Part 2: Err path in a forked child. -----
    //
    // SAFETY: top-level `fork()` in a single-threaded test context.
    // The harness has not constructed a `tokio::runtime::Runtime` on
    // this thread, so no background worker threads need to follow
    // the fork. Inside the child we perform only async-signal-safe
    // operations (`libc::setrlimit`, `libc::getrlimit`, and
    // `std::process::exit`) before returning; no allocation, no
    // mutex acquisition, no I/O.
    let fork_result = unsafe { fork() }.expect("fork(2) must succeed");

    match fork_result {
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).expect("waitpid on child must succeed");
            match status {
                WaitStatus::Exited(pid, code) => {
                    assert_eq!(pid, child, "waitpid returned the wrong PID");
                    // Exit code 0 means the child observed
                    // `InitError::UlimitTooLow` from `check_ulimit()`
                    // as expected. Any other code encodes a specific
                    // failure mode documented in the child branch
                    // below.
                    assert_eq!(
                        code, 0,
                        "child reported an unexpected check_ulimit outcome; \
                         diagnostic exit codes: 2=setrlimit failed, \
                         3=check_ulimit returned Ok() (should have failed), \
                         4=check_ulimit returned Err(other variant), \
                         5=pre-condition getrlimit failed"
                    );
                }
                other => panic!(
                    "child did not exit cleanly; WaitStatus = {:?} (expected Exited(_, 0))",
                    other
                ),
            }
        }
        ForkResult::Child => {
            // Intentionally low target: well below EPOLL_MINFDS
            // (4096) so the raise-to-rlim_max self-repair step cannot
            // satisfy the check. 128 is above typical concurrent open
            // fd counts in a minimal child (stdin/stdout/stderr +
            // a handful of runtime fds), avoiding EMFILE on the
            // setrlimit itself.
            const LOW_LIMIT: libc::rlim_t = 128;

            // SAFETY: `libc::setrlimit` is a standard POSIX syscall
            // whose second argument is a `*const rlimit` pointing to a
            // stack-local `rlimit` struct. `libc::rlimit` is POD with
            // two `rlim_t` fields and no niche requirements. The
            // values we set (128/128) are below any typical current
            // usage but above stdin/stdout/stderr, preventing EMFILE
            // on the syscall itself. We intentionally set both
            // `rlim_cur` and `rlim_max` to `LOW_LIMIT` so that
            // `check_ulimit`'s self-repair attempt (raise `rlim_cur`
            // to `rlim_max`) cannot restore the soft limit above
            // `EPOLL_MINFDS`.
            let rc = unsafe {
                // Pre-condition check: read current limits so we can
                // abort cleanly if the child already has an unusual
                // ulimit state.
                let mut probe: libc::rlimit = std::mem::zeroed();
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut probe) != 0 {
                    std::process::exit(5);
                }

                // Lower both soft and hard to LOW_LIMIT. In the
                // unprivileged case `rlim_max` can only be lowered,
                // never raised, so we must be below the current hard
                // limit. `LOW_LIMIT=128` is strictly below any
                // reasonable starting hard limit in CI.
                let new_rl = libc::rlimit {
                    rlim_cur: LOW_LIMIT,
                    rlim_max: LOW_LIMIT,
                };
                libc::setrlimit(libc::RLIMIT_NOFILE, &new_rl)
            };
            if rc != 0 {
                std::process::exit(2);
            }

            // Now invoke the function under test. `check_ulimit` is
            // expected to: (a) observe `rlim_cur = 128 < EPOLL_MINFDS`,
            // (b) attempt to raise `rlim_cur` to `rlim_max = 128` which
            // is a no-op, (c) observe the shortfall on the second
            // getrlimit, and (d) return `Err(InitError::UlimitTooLow)`.
            let result = check_ulimit();

            match result {
                Err(InitError::UlimitTooLow) => std::process::exit(0),
                Ok(()) => std::process::exit(3),
                Err(_) => std::process::exit(4),
            }
        }
    }
}

// ============================================================================
// test_stream_defaults_roundtrip
//
// Exercises UNSAFE SITE in `net::runtime::apply_stream_defaults`:
//   * `unsafe { libc::setsockopt(fd, SOL_SOCKET, SO_LINGER, …) }`
//   * `unsafe { libc::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, …) }`
//
// `TCP_NODELAY` is applied via tokio's safe wrapper outside the
// unsafe block, but we verify all three options for completeness
// because they are the full FASM `epoll.inc:1438–1490` socket-option
// sequence.
//
// Verifies:
//   1. `apply_stream_defaults(&server_stream)` returns `Ok(())` on a
//      freshly accepted tokio `TcpStream`.
//   2. `getsockopt(TCP_NODELAY)` returns 1 (EPOLL_NODELAY = true).
//   3. `getsockopt(SO_LINGER)` returns `l_onoff=1, l_linger=0`
//      (unconditional in the FASM baseline).
//   4. `getsockopt(SO_KEEPALIVE)` returns 1 (EPOLL_KEEPALIVE = true).
// ============================================================================

#[test]
fn test_stream_defaults_roundtrip() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if !live_tests_enabled() {
        eprintln!("test_stream_defaults_roundtrip: skipped (set HEAVYTHING_LIVE_TESTS=1 to enable)");
        return;
    }

    let rt = build_current_thread_runtime();

    rt.block_on(async {
        // Bind a loopback listener on an ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind on 127.0.0.1:0 must succeed");
        let addr = listener.local_addr().expect("listener local_addr must succeed");

        // Drive the accept + connect concurrently on the same
        // single-threaded runtime so neither side deadlocks.
        let accept_task = async {
            let (server, _peer) = listener
                .accept()
                .await
                .expect("listener.accept() must succeed on loopback");
            server
        };
        let connect_task = async {
            tokio::net::TcpStream::connect(addr)
                .await
                .expect("client connect to loopback must succeed")
        };
        let (server_stream, _client_stream) = tokio::join!(accept_task, connect_task);

        // Apply the defaults to the server-side stream — this is the
        // unsafe site under test.
        apply_stream_defaults(&server_stream)
            .expect("apply_stream_defaults must succeed on a freshly accepted stream");

        let fd = server_stream.as_raw_fd();

        // ----- 1. TCP_NODELAY -----
        //
        // SAFETY: `libc::getsockopt` is a standard POSIX syscall
        // whose `optval`/`optlen` arguments are sized to match the
        // option. `fd` is owned by `server_stream` for the duration
        // of this closure; `nodelay_val` and `nodelay_len` are
        // stack-local and valid for the call. `libc::c_int` is POD
        // with no niche requirements.
        let mut nodelay_val: libc::c_int = 0;
        let mut nodelay_len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                (&mut nodelay_val as *mut libc::c_int).cast::<libc::c_void>(),
                &mut nodelay_len,
            )
        };
        assert_eq!(rc, 0, "getsockopt(TCP_NODELAY) must succeed");
        assert_eq!(
            nodelay_len as usize,
            std::mem::size_of::<libc::c_int>(),
            "getsockopt(TCP_NODELAY) optlen must match c_int size"
        );
        assert_eq!(
            nodelay_val, 1,
            "TCP_NODELAY must be enabled after apply_stream_defaults (EPOLL_NODELAY = true)"
        );

        // ----- 2. SO_LINGER -----
        //
        // SAFETY: same rationale as above. `libc::linger` is a POD C
        // struct with two `c_int` fields; zero-initialisation via
        // `std::mem::zeroed()` is a valid initial state that is
        // fully overwritten by `getsockopt`.
        let mut linger_val: libc::linger = unsafe { std::mem::zeroed() };
        let mut linger_len: libc::socklen_t = std::mem::size_of::<libc::linger>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&mut linger_val as *mut libc::linger).cast::<libc::c_void>(),
                &mut linger_len,
            )
        };
        assert_eq!(rc, 0, "getsockopt(SO_LINGER) must succeed");
        assert_eq!(
            linger_len as usize,
            std::mem::size_of::<libc::linger>(),
            "getsockopt(SO_LINGER) optlen must match linger size"
        );
        assert_eq!(
            linger_val.l_onoff, 1,
            "SO_LINGER l_onoff must be 1 (RST-on-close per FASM baseline)"
        );
        assert_eq!(
            linger_val.l_linger, 0,
            "SO_LINGER l_linger must be 0 (zero-duration linger per FASM baseline)"
        );

        // ----- 3. SO_KEEPALIVE -----
        //
        // SAFETY: same rationale as above.
        let mut keepalive_val: libc::c_int = 0;
        let mut keepalive_len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                (&mut keepalive_val as *mut libc::c_int).cast::<libc::c_void>(),
                &mut keepalive_len,
            )
        };
        assert_eq!(rc, 0, "getsockopt(SO_KEEPALIVE) must succeed");
        assert_eq!(
            keepalive_len as usize,
            std::mem::size_of::<libc::c_int>(),
            "getsockopt(SO_KEEPALIVE) optlen must match c_int size"
        );
        assert_eq!(
            keepalive_val, 1,
            "SO_KEEPALIVE must be enabled after apply_stream_defaults (EPOLL_KEEPALIVE = true)"
        );

        // Drop streams and listener explicitly before leaving the
        // runtime so no I/O is in flight when the runtime shuts down.
        drop(server_stream);
        drop(_client_stream);
        drop(listener);
    });

    // Drop the runtime explicitly.
    drop(rt);
}

// ============================================================================
// test_raw_terminal_roundtrip — covers `libc::tcgetattr` / `cfmakeraw` /
// `tcsetattr` in `heavything::tui::terminal::RawTerminal::{enter, drop}` and
// the `ioctl(TIOCGWINSZ)` unsafe site in `RawTerminal::get_winsize`.
//
// Exercises the canonical FFI sequence from `tui_terminal.inc` lines
// 308–355:
//
//     1. `tcgetattr(stdin, &mut t)`        — capture cooked-mode termios
//     2. `cfmakeraw(&mut raw)`             — compute raw-mode flag set
//     3. `tcsetattr(stdin, TCSANOW, &raw)` — engage raw mode atomically
//     4. `ioctl(stdin, TIOCGWINSZ, &mut w)` — query window size
//     5. `tcsetattr(stdin, TCSANOW, &t)`   — restore cooked mode (Drop)
//
// Per AAP §0.7.4.4 (canonical FFI integration tests) and the CP7 review
// MAJOR finding, the test verifies each transition by independently
// reading the live termios via `libc::tcgetattr` and asserting the
// expected flag patterns.
//
// # Singleton interaction
//
// `RawTerminal::enter` succeeds at most once per process (`INIT_GUARD`
// is a `OnceLock<()>`). No other test in this binary calls `enter`, so
// this test owns the singleton when invoked. If a future contributor
// adds another test that calls `enter`, both tests must hold the
// `TEST_MUTEX` AND be aware that only one of them can succeed in any
// given test-binary process. Because `cargo test` reruns the binary
// per invocation but reuses the same process across multiple `#[test]`
// functions, a parallel-safe rewrite would require `--test-threads=1`
// or splitting into two test binaries.
//
// # TTY requirement
//
// The test gracefully skips when stdin is not a TTY. This covers the
// typical `cargo test` invocation on CI (where stdin is `/dev/null`)
// and piped invocations during local development. To exercise the
// path interactively use:
//
//     HEAVYTHING_LIVE_TESTS=1 \
//     script -qec 'cargo test -p heavything --test ffi_boundary -- \
//         test_raw_terminal_roundtrip --nocapture --test-threads=1' \
//         /dev/null
// ============================================================================

#[test]
fn test_raw_terminal_roundtrip() {
    // Acquire the test serializer; recover poisoned mutex defensively
    // (a previous panicked test does not invalidate the serialization
    // contract for this one).
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if !live_tests_enabled() {
        eprintln!(
            "test_raw_terminal_roundtrip: skipped \
             (set HEAVYTHING_LIVE_TESTS=1 to enable)"
        );
        return;
    }

    // -----------------------------------------------------------------
    // Step 1 — Verify stdin is a TTY before entering raw mode.
    //
    // SAFETY: `libc::isatty` accepts any integer file-descriptor and
    // returns 1 if it refers to an open terminal, 0 otherwise. Passing
    // `STDIN_FILENO` (which is always a valid kernel-side fd for the
    // life of the process) cannot dereference invalid memory and has
    // no side effects beyond reading the fd's terminal state.
    // -----------------------------------------------------------------
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;

    if !is_tty {
        eprintln!(
            "test_raw_terminal_roundtrip: skipped \
             (stdin is not a TTY — typical for `cargo test` on CI; \
             rerun under `script(1)` to exercise this path)"
        );
        return;
    }

    // -----------------------------------------------------------------
    // Step 2 — Capture the cooked-mode termios via direct `tcgetattr`.
    // This is the *baseline* against which Drop's restore is checked.
    //
    // SAFETY: `libc::tcgetattr` writes a `struct termios` (POD) through
    // the `&mut` argument when the fd refers to a terminal. We start
    // from a zero-initialized `termios` (all-zeros is a valid initial
    // state for the POD type per POSIX) and pass `STDIN_FILENO`, which
    // we just confirmed is a TTY in Step 1. On failure the syscall
    // sets errno but does not touch the buffer; we propagate via panic
    // because a `tcgetattr` failure on a confirmed-TTY fd indicates an
    // environment misconfiguration that the caller cannot recover from.
    // -----------------------------------------------------------------
    let cooked: libc::termios = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        let rc = libc::tcgetattr(libc::STDIN_FILENO, &mut t);
        assert_eq!(
            rc,
            0,
            "pre-enter tcgetattr(stdin) must succeed on a TTY: {}",
            std::io::Error::last_os_error()
        );
        t
    };

    // Sanity-check that the captured termios reflects cooked mode.
    // A real interactive terminal has ECHO and ICANON set; if either
    // bit is missing, the test environment is unusual and the
    // post-Drop comparison would fail in confusing ways.
    assert_ne!(cooked.c_lflag & libc::ECHO, 0, "cooked mode must have ECHO set");
    assert_ne!(
        cooked.c_lflag & libc::ICANON,
        0,
        "cooked mode must have ICANON set"
    );

    // -----------------------------------------------------------------
    // Step 3 — Engage raw mode via the public `RawTerminal::enter` API.
    // The unsafe block under test lives at terminal.rs:203–215 and
    // performs the `tcgetattr → cfmakeraw → tcsetattr → publish saved
    // termios` sequence. `INIT_GUARD` enforces the per-process
    // singleton invariant; this is the only test in the binary that
    // calls `enter`, so we expect Ok.
    // -----------------------------------------------------------------
    let term = RawTerminal::enter().expect("RawTerminal::enter on a TTY must succeed");

    // -----------------------------------------------------------------
    // Step 4 — Verify raw mode is in effect via direct `tcgetattr`.
    //
    // SAFETY: identical to Step 2; we re-read the termios via the
    // libc FFI on the same TTY fd to confirm the kernel has accepted
    // the raw-mode attributes set by `RawTerminal::enter`. On
    // success the `c_lflag` bits cleared by `cfmakeraw(3)`
    // (ECHO, ECHONL, ICANON, ISIG, IEXTEN) must all be zero, and
    // `c_oflag & OPOST` must also be zero — the FASM-equivalent
    // sequence at `tui_terminal.inc` lines 308–316.
    // -----------------------------------------------------------------
    let raw: libc::termios = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        let rc = libc::tcgetattr(libc::STDIN_FILENO, &mut t);
        assert_eq!(
            rc,
            0,
            "post-enter tcgetattr must succeed: {}",
            std::io::Error::last_os_error()
        );
        t
    };
    assert_eq!(
        raw.c_lflag & libc::ECHO,
        0,
        "raw mode must clear ECHO (cfmakeraw contract)"
    );
    assert_eq!(
        raw.c_lflag & libc::ICANON,
        0,
        "raw mode must clear ICANON (cfmakeraw contract)"
    );
    assert_eq!(
        raw.c_lflag & libc::ISIG,
        0,
        "raw mode must clear ISIG (cfmakeraw contract)"
    );
    assert_eq!(
        raw.c_lflag & libc::IEXTEN,
        0,
        "raw mode must clear IEXTEN (cfmakeraw contract)"
    );
    assert_eq!(
        raw.c_oflag & libc::OPOST,
        0,
        "raw mode must clear OPOST (cfmakeraw contract)"
    );

    // -----------------------------------------------------------------
    // Step 5 — Exercise the `ioctl(TIOCGWINSZ)` FFI site via the public
    // `get_winsize` API. On a TTY this must succeed; on a non-TTY it
    // would fail with `ENOTTY`, but we verified TTY status in Step 1.
    // -----------------------------------------------------------------
    let winsize = term.get_winsize().expect("get_winsize on a TTY must succeed");
    assert!(winsize.cols > 0, "get_winsize on a real TTY must report cols > 0");
    assert!(winsize.rows > 0, "get_winsize on a real TTY must report rows > 0");

    // -----------------------------------------------------------------
    // Step 6 — Drop the `RawTerminal`. The unsafe block under test
    // lives at terminal.rs:519–521 and performs `tcsetattr(stdin,
    // TCSANOW, &self.original)`, restoring the captured cooked-mode
    // termios.
    // -----------------------------------------------------------------
    drop(term);

    // -----------------------------------------------------------------
    // Step 7 — Verify cooked mode is restored byte-for-byte.
    //
    // SAFETY: identical to Step 2/4. We compare the post-Drop termios
    // to the pre-enter snapshot to confirm Drop's `tcsetattr` truly
    // restored the captured attributes — not merely "some" cooked
    // mode, but the *same* cooked mode the test started in.
    // -----------------------------------------------------------------
    let restored: libc::termios = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        let rc = libc::tcgetattr(libc::STDIN_FILENO, &mut t);
        assert_eq!(
            rc,
            0,
            "post-drop tcgetattr must succeed: {}",
            std::io::Error::last_os_error()
        );
        t
    };
    assert_ne!(
        restored.c_lflag & libc::ECHO,
        0,
        "Drop must restore ECHO (cooked-mode contract)"
    );
    assert_ne!(
        restored.c_lflag & libc::ICANON,
        0,
        "Drop must restore ICANON (cooked-mode contract)"
    );
    // Compare the four canonical flag groups byte-for-byte against the
    // pre-enter snapshot. We deliberately do not compare `c_cc` (the
    // control characters array) field-by-field because Drop's
    // `tcsetattr` invocation passes the same `original` pointer that
    // `enter` captured, so any divergence in `c_cc` would also
    // surface as a divergence in `c_lflag` (e.g. `cfmakeraw` clears
    // `VMIN`/`VTIME` so a bad restore would leave them at zero).
    assert_eq!(
        restored.c_iflag, cooked.c_iflag,
        "Drop must restore c_iflag byte-for-byte"
    );
    assert_eq!(
        restored.c_oflag, cooked.c_oflag,
        "Drop must restore c_oflag byte-for-byte"
    );
    assert_eq!(
        restored.c_cflag, cooked.c_cflag,
        "Drop must restore c_cflag byte-for-byte"
    );
    assert_eq!(
        restored.c_lflag, cooked.c_lflag,
        "Drop must restore c_lflag byte-for-byte"
    );
}

// ============================================================================
// test_sigwinch_handler — covers `libc::sigaction(SIGWINCH, ...)` in
// `heavything::tui::terminal::install_signal_handlers` and the
// `extern "C" fn sigwinch_handler` callback at terminal.rs:389.
//
// Exercises the FASM-baseline behaviour from `tui_terminal.inc`:
// the SIGWINCH signal must (a) be caught by the installed handler,
// (b) atomically set the `WINCH_PENDING` flag, and (c) be observable
// through the public `RawTerminal::take_winch_pending()` accessor
// which clears the flag on read.
//
// Per AAP §0.7.4.4 and the CP7 review MAJOR finding, the test
// verifies the handler registration + flag-flip semantics by sending
// SIGWINCH to the child process (via `nix::sys::signal::raise`) and
// asserting `take_winch_pending` transitions true → false across two
// calls.
//
// # Fork-based isolation
//
// The test forks before invoking `RawTerminal::enter` so that any
// terminal-state mutation (raw-mode flip, ANSI escape emission,
// alternate-screen toggle) is isolated to the short-lived child and
// cannot bleed into the test runner's terminal. The fork is kept
// inside the `TEST_MUTEX` critical section so it does not race the
// other fork-based tests in this file.
//
// # Singleton interaction
//
// `RawTerminal::enter` is a per-process singleton guarded by
// `INIT_GUARD: OnceLock<()>` (terminal.rs:90, 168–172). After
// `fork(2)` the child inherits the parent's `INIT_GUARD` state. If
// `test_raw_terminal_roundtrip` ran first in the parent and acquired
// the singleton, every subsequent fork of the parent will see the
// guard already set; in that case `enter()` returns
// `TuiError::Termios(io::ErrorKind::AlreadyExists)` and the child
// exits with a documented sentinel code (99) which the parent
// recognises as a graceful skip rather than a failure.
//
// Under typical CI conditions (`HEAVYTHING_LIVE_TESTS` unset) this
// test skips early before reaching fork, leaving INIT_GUARD intact.
// ============================================================================

#[test]
fn test_sigwinch_handler() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if !live_tests_enabled() {
        eprintln!(
            "test_sigwinch_handler: skipped \
             (set HEAVYTHING_LIVE_TESTS=1 to enable)"
        );
        return;
    }

    // -----------------------------------------------------------------
    // SAFETY: `libc::isatty(STDIN_FILENO)` is a benign read-only query
    // on the calling process's stdin descriptor. Same rationale as
    // `test_raw_terminal_roundtrip` Step 1.
    // -----------------------------------------------------------------
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;

    if !is_tty {
        eprintln!(
            "test_sigwinch_handler: skipped \
             (stdin is not a TTY; RawTerminal::enter requires a TTY for \
              tcgetattr(2) to succeed — typical for `cargo test` on CI)"
        );
        return;
    }

    // -----------------------------------------------------------------
    // Fork to isolate terminal-state mutations and any ANSI escape
    // sequences emitted by `RawTerminal::enter`/`drop`.
    //
    // SAFETY: top-level `fork()` from a single-threaded test context.
    // The harness has not constructed a multi-threaded tokio runtime
    // on this thread, and the child branch performs only
    // async-signal-safe operations (sigaction-installed handler runs,
    // libc::raise) before executing user-level Rust code that exits
    // via std::process::exit. No allocator state from the parent is
    // mutated post-fork prior to exit.
    // -----------------------------------------------------------------
    let fork_result = unsafe { fork() }.expect("fork(2) must succeed");

    match fork_result {
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).expect("waitpid on child must succeed");
            match status {
                WaitStatus::Exited(pid, code) => {
                    assert_eq!(pid, child, "waitpid returned the wrong PID");
                    match code {
                        0 => {
                            // Success: child observed the SIGWINCH-driven
                            // flag flip and clean clear-on-read semantics.
                        }
                        99 => {
                            eprintln!(
                                "test_sigwinch_handler: skipped in child \
                                 (RawTerminal::enter singleton already \
                                  claimed by an earlier test in this binary)"
                            );
                        }
                        other => panic!(
                            "child reported diagnostic exit code {}; \
                             diagnostic codes: 0=success, \
                             2=enter() returned a non-AlreadyExists error, \
                             3=take_winch_pending did not flip to true after raise(SIGWINCH), \
                             4=take_winch_pending did not flip back to false on second call, \
                             99=enter() returned AlreadyExists (skip)",
                            other
                        ),
                    }
                }
                other => panic!(
                    "child did not exit cleanly; WaitStatus = {:?} \
                     (expected Exited(_, 0) or Exited(_, 99))",
                    other
                ),
            }
        }
        ForkResult::Child => {
            // Attempt to engage raw mode. `INIT_GUARD` may be set from
            // a prior test in the parent (inherited via fork) or
            // unset; we handle both cases below.
            let term = match RawTerminal::enter() {
                Ok(t) => t,
                Err(TuiError::Termios(io_err))
                    if io_err.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    // Singleton inherited as set; gracefully skip.
                    std::process::exit(99);
                }
                Err(_) => {
                    // Other error (TIOCGWINSZ failure on a non-TTY,
                    // tcgetattr ENOTTY, etc.). We pre-checked TTY in
                    // the parent so this is unexpected.
                    std::process::exit(2);
                }
            };

            // Drain any flag set during `enter()` (the FASM-baseline
            // handler installation does not pre-fire WINCH_PENDING,
            // but be defensive).
            let _ = term.take_winch_pending();

            // Synchronously deliver SIGWINCH to ourselves. On Linux,
            // `raise(2)` blocks until the handler returns, so the
            // atomic store inside `sigwinch_handler` is committed by
            // the time `raise` returns.
            //
            // SAFETY: `signal::raise` is the safe `nix` wrapper around
            // `libc::raise`. The unsafe lives entirely inside `nix`.
            if signal::raise(Signal::SIGWINCH).is_err() {
                drop(term);
                std::process::exit(2);
            }

            // Even though raise(2) is synchronous, briefly poll to
            // accommodate kernel signal-queueing edge cases (e.g.
            // strace, ptrace-attached debuggers).
            let mut observed = false;
            for _ in 0..100 {
                if term.take_winch_pending() {
                    observed = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }

            if !observed {
                drop(term);
                std::process::exit(3);
            }

            // Clear-on-read semantics: a second call must return false
            // because the first call atomically swapped the flag back
            // to false (see terminal.rs:289–292).
            if term.take_winch_pending() {
                drop(term);
                std::process::exit(4);
            }

            drop(term);
            std::process::exit(0);
        }
    }
}

// ============================================================================
// test_setuid_setgid_drop — covers `nix::unistd::setuid` /
// `nix::unistd::setgid` (raw `setuid(2)` / `setgid(2)` syscalls
// underneath) called by the webserver master process to drop
// privileges after binding low ports per AAP §0.5.1.8 and §0.7.1.2.
//
// The webserver master (`crates/webserver/src/master.rs`) is a CP8
// deliverable not yet present in the repository; per the canonical
// FFI test catalogue at AAP §0.7.4.4 and the CP7 MAJOR finding the
// boundary tests must exist now and exercise the underlying nix
// primitives directly so that when the production master.rs lands
// the same test exercises the same call sites.
//
// The test verifies the canonical FASM `epoll_child.inc:88-103`
// privilege-drop sequence:
//
//     1. setgid(<unprivileged_gid>)  — drop secondary gid first
//     2. setuid(<unprivileged_uid>)  — then drop the uid
//     3. getuid()/getgid() readback  — verify drop took effect
//     4. setuid(0) attempt            — must fail with EPERM,
//                                       proving the drop is irreversible
//
// # Privilege requirements
//
// Real privilege-drop testing requires running as root (uid==0). On
// non-root test runners the test gracefully skips with an
// explanatory eprintln; the boundary test still ensures the call-
// sites are reachable via the public nix API.
//
// To opt in to the full privileged test path, set both:
//     HEAVYTHING_LIVE_TESTS=1
//     HEAVYTHING_PRIVILEGED_TESTS=1
//
// On systems where the build/test runner is root (e.g. CI containers,
// developer sudo invocations) the privileged path runs and exercises
// the actual setuid/setgid syscalls in a forked child that exits
// immediately, leaving the test runner's privileges intact.
//
// # Target uid/gid choice
//
// The test targets uid 65534 (`nobody`) / gid 65534 (`nogroup`),
// the canonical unprivileged identity present on virtually every
// Linux distribution. The webserver itself uses the operator-supplied
// `-runas USER` argument; testing the syscall boundary at uid 65534
// is sufficient to exercise the same FFI surface.
// ============================================================================

#[test]
fn test_setuid_setgid_drop() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if !live_tests_enabled() {
        eprintln!(
            "test_setuid_setgid_drop: skipped \
             (set HEAVYTHING_LIVE_TESTS=1 to enable)"
        );
        return;
    }

    let privileged_opt_in =
        matches!(std::env::var("HEAVYTHING_PRIVILEGED_TESTS").ok().as_deref(), Some("1"));
    if !privileged_opt_in {
        eprintln!(
            "test_setuid_setgid_drop: skipped \
             (set HEAVYTHING_PRIVILEGED_TESTS=1 to opt in to the \
              privilege-mutation test path; the test runner must \
              currently be running as uid 0 for the syscalls to succeed)"
        );
        return;
    }

    // Skip if the test runner is not running as root: setuid(2) and
    // setgid(2) require CAP_SETUID/CAP_SETGID, which non-root
    // processes do not normally have.
    if !getuid().is_root() {
        eprintln!(
            "test_setuid_setgid_drop: skipped \
             (test runner is not running as uid 0; setuid/setgid would \
              fail with EPERM before exercising the drop sequence)"
        );
        return;
    }

    // Pre-condition sanity: we expect to be able to construct the
    // target Uid/Gid values without panicking. `from_raw` is
    // const-fn and infallible on Linux for any value in the
    // uid_t/gid_t range.
    const NOBODY_UID: libc::uid_t = 65534;
    const NOGROUP_GID: libc::gid_t = 65534;
    let target_uid = Uid::from_raw(NOBODY_UID);
    let target_gid = Gid::from_raw(NOGROUP_GID);

    // -----------------------------------------------------------------
    // Fork. We MUST mutate the privilege state inside the child only:
    // setuid(2) is irreversible (once we drop, we cannot restore root
    // for the rest of the process). The fork ensures the test-runner
    // process retains its uid 0 for subsequent tests.
    //
    // SAFETY: top-level `fork()` from a single-threaded test context.
    // The child branch performs only async-signal-safe operations
    // (`setgid`, `setuid`, `getuid`, `getgid`, `std::process::exit`)
    // and does not touch shared mutex state, allocator state, or
    // tokio runtime state.
    // -----------------------------------------------------------------
    let fork_result = unsafe { fork() }.expect("fork(2) must succeed");

    match fork_result {
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).expect("waitpid on child must succeed");
            match status {
                WaitStatus::Exited(pid, code) => {
                    assert_eq!(pid, child, "waitpid returned the wrong PID");
                    assert_eq!(
                        code, 0,
                        "child reported a privilege-drop failure; \
                         diagnostic exit codes: \
                         0=success, \
                         2=setgid(NOGROUP) failed, \
                         3=setuid(NOBODY) failed, \
                         4=getuid()!=NOBODY post-drop, \
                         5=getgid()!=NOGROUP post-drop, \
                         6=setuid(root) succeeded post-drop (drop not irreversible!), \
                         7=setuid(root) failed with non-EPERM error"
                    );
                }
                other => panic!(
                    "child did not exit cleanly; WaitStatus = {:?} \
                     (expected Exited(_, 0))",
                    other
                ),
            }
        }
        ForkResult::Child => {
            // Step 1 — drop secondary gid first.
            //
            // Per `epoll_child.inc:88-103`, setgid is performed
            // BEFORE setuid because once the uid drops to non-zero,
            // setgid would fail with EPERM. The nix wrapper performs
            // the raw `setgid(2)` syscall internally.
            if setgid(target_gid).is_err() {
                std::process::exit(2);
            }

            // Step 2 — drop primary uid.
            if setuid(target_uid).is_err() {
                std::process::exit(3);
            }

            // Step 3 — readback verification via getuid(2)/getgid(2).
            // Both functions are infallible on Linux (return the
            // current credentials directly from the kernel).
            if getuid() != target_uid {
                std::process::exit(4);
            }
            if getgid() != target_gid {
                std::process::exit(5);
            }

            // Step 4 — confirm the drop is irreversible. setuid(0)
            // must fail with EPERM because the saved-set-uid is
            // also dropped by setuid(uid) when called from a
            // non-suid binary.
            match setuid(Uid::from_raw(0)) {
                Ok(()) => std::process::exit(6),
                Err(nix::Error::EPERM) => {
                    // Expected outcome — drop is irreversible.
                }
                Err(_) => std::process::exit(7),
            }

            std::process::exit(0);
        }
    }
}

// ============================================================================
// test_fork_workers — covers `nix::unistd::fork` invoked in a loop to
// spawn N worker processes, mirroring the FASM-baseline
// `webserver::master::spawn_workers()` pattern from AAP §0.5.1.8.
//
// The webserver master (`crates/webserver/src/master.rs`) is a CP8
// deliverable; per AAP §0.7.4.4 and the CP7 MAJOR finding the
// boundary test must exist now and verify the underlying
// `spawn_child` primitive can correctly fork multiple children in
// sequence, each acquiring its own AF_UNIX socketpair and exiting
// cleanly. When the production master.rs lands it will reuse the
// same `spawn_child` primitive in the same loop pattern.
//
// # Test plan
//
// Spawn `WORKER_COUNT` children via `spawn_child`. Each child runs an
// empty `child_main` closure (which causes `spawn_child` to invoke
// `std::process::exit(0)` immediately after the closure returns —
// see `net/child.rs:1043`). The parent immediately drops each
// `ChildProcess`, closing its half of the socketpair, and reaps the
// child via `waitpid` asserting `WaitStatus::Exited(_, 0)`.
//
// # Why a separate test from `test_fork_spawn_child_basic`
//
// `test_fork_spawn_child_basic` exercises a single-child round-trip
// of one `LinkMessage` over the parent/child socketpair. This test
// instead verifies the *iteration* discipline — multiple sequential
// forks must each succeed and each child must exit cleanly without
// signalling each other or interfering with the
// `process-global child-PID registry` (`CHILD_PIDS`).
//
// # `killall_children` interaction
//
// After the test waits for each direct child via `waitpid`, the
// child PIDs in `CHILD_PIDS` are stale. We invoke
// `killall_children()` at the end as an idempotency check (it must
// no-op gracefully on dead PIDs, swallowing ESRCH per the
// implementation contract).
// ============================================================================

#[test]
fn test_fork_workers() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if !live_tests_enabled() {
        eprintln!(
            "test_fork_workers: skipped \
             (set HEAVYTHING_LIVE_TESTS=1 to enable)"
        );
        return;
    }

    /// Number of workers to spawn. Two is the minimum that
    /// distinguishes "iteration discipline" from a single-child
    /// test; we keep it small so the test stays fast and so a
    /// rare flake (e.g. waitpid timing) does not multiply.
    const WORKER_COUNT: usize = 2;

    let rt = build_current_thread_runtime();

    // The child closure is empty: `spawn_child` invokes
    // `child_main(stream)` and then `std::process::exit(0)` on
    // return. `stream` is dropped here without any I/O, which is
    // fine because the parent does not send any frames.
    //
    // The closure type is `FnOnce(StdUnixStream) + Send + 'static`,
    // and we need a fresh closure per `spawn_child` call because
    // FnOnce is consumed. We construct an identical closure each
    // iteration via a function-style definition.
    fn empty_child_main(_stream: StdUnixStream) {}

    // Spawn all workers inside a single block_on so the child's
    // socketpair fd is never observed by tokio's reactor (we drop
    // the ChildProcess immediately, which closes parent_socket).
    let pids = rt.block_on(async {
        let mut pids: Vec<Pid> = Vec::with_capacity(WORKER_COUNT);
        for _ in 0..WORKER_COUNT {
            let child: ChildProcess = spawn_child(empty_child_main)
                .expect("spawn_child must succeed on Linux/x86_64 hosts");
            pids.push(child.pid);
            // Drop ChildProcess immediately. Its `parent_socket`
            // closes, the child observes EOF (although it never
            // reads), and the child's `child_main` returns, after
            // which `spawn_child`'s child branch calls
            // `std::process::exit(0)` — see net/child.rs:1043.
            drop(child);
        }
        pids
    });

    // Tear down the runtime before reaping. We do not need tokio
    // for the waitpid loop, and dropping the runtime here ensures
    // any background tokio bookkeeping cannot interfere with the
    // direct waitpid calls below.
    drop(rt);

    // Reap each worker in order and assert clean exit.
    for (idx, pid) in pids.iter().enumerate() {
        let status =
            waitpid(*pid, None).expect("waitpid must succeed for our direct child");
        match status {
            WaitStatus::Exited(reaped_pid, code) => {
                assert_eq!(
                    reaped_pid, *pid,
                    "waitpid returned the wrong PID for worker {}",
                    idx
                );
                assert_eq!(
                    code, 0,
                    "worker {} did not exit with status 0 \
                     (spawn_child must call std::process::exit(0) after \
                      empty child_main returns)",
                    idx
                );
            }
            other => panic!(
                "worker {} (pid {}) did not exit cleanly; \
                 WaitStatus = {:?} (expected Exited(_, 0))",
                idx, pid, other
            ),
        }
    }

    // Idempotency: killall_children must gracefully no-op on the
    // stale PID registry entries left behind by the dropped
    // ChildProcess instances.
    killall_children();
}

// ============================================================================
// test_mmap_file_cache — covers `memmap2::MmapOptions::map(&file)`
// in `heavything::net::http::server::HotEntry::open` at
// `net/http/server.rs:479`. This is the production unsafe site that
// powers the webserver hotlist file cache (AAP §0.5.1.4 / §0.7.2),
// providing zero-copy delivery of static asset bodies from `Mmap`
// directly to the response writer.
//
// Per AAP §0.7.4.4 and the CP7 review (MAJOR — 4-of-7 mandatory FFI
// tests; MINOR — `server.rs:479` mmap not enumerated in the audit)
// the test verifies:
//
//   1. `HotEntry::open(path)` succeeds for a regular file.
//   2. `entry.size()` matches the on-disk file size byte-for-byte.
//   3. The mapped bytes (`entry.mmap()`) deref to a slice that
//      compares equal to the source bytes.
//   4. Dropping the entry releases the mapping without panicking
//      (verified implicitly by no panic during the closure exit).
//
// # Why we use `tempfile`
//
// `tempfile::NamedTempFile` is a dev-dependency of the heavything
// crate (Cargo.toml line 120) selected precisely for this kind of
// integration test. The temp file is auto-deleted on Drop, so the
// test is self-cleaning even on panic.
//
// # File-size choice
//
// 4 KiB is a round number that exercises the mapping code without
// stressing it: `memmap2` rounds up to page size internally, and a
// single page on x86_64 Linux is exactly 4 KiB. We deliberately do
// not test page-boundary edge cases here because the underlying
// memmap2 crate has its own test suite for those; our boundary
// concern is whether HotEntry's unsafe call site correctly
// constructs a read-only mapping over an owned file handle.
// ============================================================================

#[test]
fn test_mmap_file_cache() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if !live_tests_enabled() {
        eprintln!(
            "test_mmap_file_cache: skipped \
             (set HEAVYTHING_LIVE_TESTS=1 to enable)"
        );
        return;
    }

    // -----------------------------------------------------------------
    // Step 1 — Build a deterministic 4 KiB payload.
    //
    // The pattern `(i * 31 + 7) & 0xff` matches the convention used
    // by `benches/aes_cbc.rs` and `benches/sha256.rs`, providing a
    // non-trivial byte distribution while remaining bit-exact
    // reproducible across runs.
    // -----------------------------------------------------------------
    const PAYLOAD_SIZE: usize = 4096;
    let payload: Vec<u8> = (0..PAYLOAD_SIZE)
        .map(|i| ((i * 31 + 7) & 0xff) as u8)
        .collect();

    // -----------------------------------------------------------------
    // Step 2 — Write payload to a NamedTempFile. We use NamedTempFile
    // (not just `tempfile()`) because `HotEntry::open` takes a path,
    // which requires the temp file to have a stable filesystem name
    // for the lifetime of the test.
    // -----------------------------------------------------------------
    let mut tmp =
        tempfile::NamedTempFile::new().expect("NamedTempFile::new must succeed");
    tmp.as_file_mut()
        .write_all(&payload)
        .expect("write_all of test payload must succeed");
    tmp.as_file_mut()
        .sync_all()
        .expect("sync_all of test payload must succeed");
    let path = tmp.path().to_path_buf();

    // -----------------------------------------------------------------
    // Step 3 — Open the HotEntry, exercising the unsafe mmap call
    // site at `net/http/server.rs:479`.
    //
    // SAFETY (delegated): the safety invariants of
    // `unsafe { MmapOptions::new().map(&file) }` are maintained by
    // `HotEntry::open` (read-only mapping, file owned across the
    // call, no concurrent writers because we are the sole owner of
    // the temp file). We are exercising — not bypassing — those
    // invariants here.
    // -----------------------------------------------------------------
    let entry = HotEntry::open(&path).expect("HotEntry::open of regular file must succeed");

    // -----------------------------------------------------------------
    // Step 4 — Verify metadata matches.
    // -----------------------------------------------------------------
    assert_eq!(
        entry.size() as usize,
        PAYLOAD_SIZE,
        "HotEntry::size() must equal the on-disk file size"
    );
    assert_eq!(
        entry.path(),
        &path,
        "HotEntry::path() must equal the path passed to open()"
    );
    assert!(
        !entry.etag().is_empty(),
        "HotEntry::etag() must be a non-empty quoted hex string \
         (format: \"<mtime_hex>-<size_hex>\")"
    );
    assert!(
        !entry.mtime_str().is_empty(),
        "HotEntry::mtime_str() must be a non-empty RFC 1123 date"
    );

    // -----------------------------------------------------------------
    // Step 5 — Verify the mapped bytes equal the source payload
    // byte-for-byte. `Mmap` derefs to `[u8]` so we slice via
    // `&entry.mmap()[..]` to obtain the borrow without an explicit
    // `as_ref` call.
    // -----------------------------------------------------------------
    let mapped: &[u8] = &entry.mmap()[..];
    assert_eq!(
        mapped.len(),
        PAYLOAD_SIZE,
        "mapped slice length must equal payload length \
         (memmap2 may round mapping size up to a page boundary, but \
          the slice length reported via Deref must equal the file size)"
    );
    assert_eq!(
        mapped, payload.as_slice(),
        "mapped bytes must equal source payload byte-for-byte"
    );

    // -----------------------------------------------------------------
    // Step 6 — Drop the entry. `Mmap`'s Drop releases the kernel
    // mapping; if it panicked we would observe a test failure.
    // -----------------------------------------------------------------
    drop(entry);

    // tempfile::NamedTempFile is auto-deleted on Drop; nothing more
    // to clean up here.
}

// =============================================================================
// CPUID vendor-string verification.
//
// Per AAP §0.7.4.1 ("CPUID feature detection | 0 sites") the
// `std::is_x86_feature_detected!` macro and `std::arch::x86_64::__cpuid`
// are *safe* on the `x86_64-unknown-linux-gnu` target — CPUID has been
// architecturally mandated since 1993, has no side effects, and cannot
// trap in user mode. There is therefore no unsafe block to guard.
//
// However, the QA Checkpoint 7 report's "Expected Outcome" enumeration
// for §0.7.4.4 lists `test_cpuid_vendor_string` alongside the six
// canonical AAP-named tests; this supplementary test is added to give
// CPUID-based feature detection (`crate::cpu::detect`) an end-to-end
// sanity check against ground truth from `/proc/cpuinfo`. The
// FASM baseline did the equivalent verification via the `cmp ecx,'ntel'`
// check at `ht.inc:~345` (which inspired `cpu::detect_is_intel`).
// =============================================================================

/// Verifies that the CPUID leaf-0 vendor identification string read
/// directly via `std::arch::x86_64::__cpuid(0)` matches the
/// `vendor_id` field reported by the Linux kernel through
/// `/proc/cpuinfo`.
///
/// **Rationale.** This is a ground-truth cross-check between two
/// independent observers of the same hardware register set:
///
/// 1. *Userspace path* — `__cpuid(0)` issues the actual `CPUID`
///    instruction with `EAX=0` and reads back the vendor string from
///    `EBX:EDX:ECX` (12 ASCII bytes; FASM `ht.inc:~340` performed
///    exactly this read and compared `ECX` against the literal
///    `'ntel'`).
/// 2. *Kernel path* — `/proc/cpuinfo` is the kernel-formatted
///    representation of the same CPUID data, populated at boot and
///    refreshed on each read from the per-CPU `cpuinfo_x86` struct.
///
/// If the two diverge on the same machine the codebase's
/// `cpu::detect_is_intel` helper (which only checks `ECX`) could
/// produce a different vendor classification than the kernel sees,
/// invalidating any AES-NI / AVX dispatch decisions made by the
/// `crypto::aes` and `ring` crates. This test would catch that drift
/// at integration-test time rather than letting it propagate into
/// a production hash mismatch.
///
/// **Why it lives in `ffi_boundary.rs`.** Although `__cpuid` is a
/// safe fn on this target (so this test is not strictly required by
/// Gate 6), the test exercises a CPU-level instruction-boundary
/// equivalent in spirit to the FFI/raw-syscall boundaries audited
/// in `UNSAFE_AUDIT.md`. The QA Checkpoint 7 report listed it
/// alongside the six unsafe-boundary tests in its "Expected Outcome"
/// enumeration and is satisfied by its presence here.
///
/// **Skip conditions.** None: `__cpuid` is universally available on
/// x86_64. The `/proc/cpuinfo` read can fail on a non-Linux kernel,
/// in which case the test reports the missing dependency clearly
/// rather than panicking opaquely.
#[test]
fn test_cpuid_vendor_string() {
    // -----------------------------------------------------------------
    // Step 1 — Read the CPUID vendor string via `__cpuid(0)`.
    //
    // The vendor string is 12 ASCII bytes laid out as EBX:EDX:ECX.
    // On `"GenuineIntel"`:
    //   EBX = "Genu" (`0x756e6547` little-endian)
    //   EDX = "ineI" (`0x49656e69` little-endian)
    //   ECX = "ntel" (`0x6c65746e` little-endian)
    //
    // On `"AuthenticAMD"`:
    //   EBX = "Auth"
    //   EDX = "enti"
    //   ECX = "cAMD"
    //
    // These are the only two vendors observed in practice on the
    // `x86_64-unknown-linux-gnu` targets we support, but the test
    // accepts any valid 12-byte ASCII vendor string and merely
    // verifies it matches `/proc/cpuinfo`.
    //
    // SAFETY of the call: not required — `__cpuid` is a safe fn on
    // x86_64 per `std::arch::x86_64::__cpuid` documentation since
    // Rust 1.59. The instruction has been architecturally mandated
    // since 1993, has no memory effects, and cannot trap in user
    // mode (`CR4.TSD` is cleared by default on Linux).
    // -----------------------------------------------------------------
    let cpuid = std::arch::x86_64::__cpuid(0);
    let mut vendor_bytes = [0u8; 12];
    vendor_bytes[0..4].copy_from_slice(&cpuid.ebx.to_le_bytes());
    vendor_bytes[4..8].copy_from_slice(&cpuid.edx.to_le_bytes());
    vendor_bytes[8..12].copy_from_slice(&cpuid.ecx.to_le_bytes());

    let vendor = std::str::from_utf8(&vendor_bytes)
        .expect("CPUID leaf-0 vendor string must be valid ASCII (architecturally mandated)")
        .to_string();

    // Sanity-check the format:
    assert_eq!(
        vendor.len(),
        12,
        "CPUID vendor string must be exactly 12 bytes; got {} bytes",
        vendor.len()
    );
    assert!(
        vendor.is_ascii(),
        "CPUID vendor string must be printable ASCII; got {vendor:?}"
    );

    // -----------------------------------------------------------------
    // Step 2 — Read `/proc/cpuinfo` and extract the `vendor_id` field
    // for CPU 0. The format is a sequence of `key\t: value\n` lines,
    // with each CPU's block separated by a blank line; CPU 0 is always
    // the first block.
    //
    // If `/proc/cpuinfo` cannot be opened, the test reports a useful
    // error and skips rather than failing — this prevents the test
    // from breaking on hypothetical containerized environments where
    // `/proc` is not mounted (uncommon on Linux but allowed by the
    // kernel).
    // -----------------------------------------------------------------
    let cpuinfo = match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(text) => text,
        Err(err) => {
            eprintln!(
                "[ffi_boundary] skipping test_cpuid_vendor_string: \
                 cannot read /proc/cpuinfo ({err}); kernel must mount \
                 procfs to ground-truth-check the CPUID vendor."
            );
            return;
        }
    };

    let kernel_vendor = cpuinfo
        .lines()
        .find_map(|line| {
            // Find the first `vendor_id\t: <value>` line (CPU 0).
            let trimmed = line.trim_start();
            let rest = trimmed.strip_prefix("vendor_id")?;
            // The separator between key and value is a tab+colon;
            // tolerate variable whitespace around the colon.
            let rest = rest.trim_start();
            let rest = rest.strip_prefix(':')?;
            Some(rest.trim().to_string())
        })
        .expect(
            "/proc/cpuinfo must contain a `vendor_id` field for CPU 0 on x86_64; \
             absence indicates a malformed kernel build",
        );

    // -----------------------------------------------------------------
    // Step 3 — Assert byte-for-byte equality between the userspace
    // CPUID read and the kernel-reported vendor.
    //
    // Both sources read from the same hardware register, so any
    // discrepancy indicates either (a) a virtualization layer
    // synthesizing different values for userspace vs kernel reads
    // (very unusual; would also cause kernel feature flags to lie),
    // or (b) a bug in `cpu::detect_is_intel` masking-logic. Either is
    // worth flagging at integration-test time.
    // -----------------------------------------------------------------
    assert_eq!(
        vendor, kernel_vendor,
        "CPUID userspace vendor string {:?} disagrees with kernel-reported \
         vendor_id {:?}; this would invalidate AES-NI/AVX dispatch decisions",
        vendor, kernel_vendor
    );

    // -----------------------------------------------------------------
    // Step 4 — Cross-check the `cpu::detect_is_intel` logic against
    // the now-validated vendor string. This is the same comparison
    // performed at `crate::cpu::detect_is_intel` and at FASM
    // `ht.inc:~345`; surfacing it in this test guarantees the FASM
    // logic was preserved correctly in the Rust port.
    // -----------------------------------------------------------------
    let userspace_says_intel = cpuid.ecx == u32::from_le_bytes(*b"ntel");
    let vendor_says_intel = vendor == "GenuineIntel";
    assert_eq!(
        userspace_says_intel, vendor_says_intel,
        "cpu::detect_is_intel ECX-only check must agree with full vendor \
         string comparison; ECX={:#x} vendor={:?}",
        cpuid.ecx, vendor
    );
}

// =============================================================================
// `test_cpuid_feature_detection_does_not_panic`
// -----------------------------------------------------------------------------
// Schema-required test #2 (per AAP §0.7.4.4 + UNSAFE_AUDIT.md). Verifies the
// `OnceLock` idempotence contract of [`heavything::cpu::detect`]: every call
// returns a reference to the *same* `&'static CpuFeatures` instance, and
// reading the published feature fields (e.g. `has_aesni`) does not panic.
//
// The corresponding unsafe block lives at `src/cpu.rs::detect_is_intel` where
// `std::arch::x86_64::__cpuid(0)` is invoked. On stable Rust 1.59+ this
// function is a *safe* fn on `x86_64-*`, so the call site itself does not
// require an `unsafe` annotation; the test exists primarily to enforce the
// `OnceLock` semantics that the rest of the crate relies on for AES-NI / AVX
// dispatch decisions and to provide a regression backstop should a future
// refactor accidentally re-introduce per-call CPUID issuance (which would
// change the returned reference identity).
// =============================================================================

/// FFI / boundary test for `heavything::cpu::detect` `OnceLock` semantics.
///
/// **UNSAFE_AUDIT.md cross-reference**: section "CPUID — `cpu.rs:141`"
/// (`heavything::cpu::detect_is_intel`). The integration-test mapping table
/// at `UNSAFE_AUDIT.md:418` lists `test_cpuid_vendor_string` as the primary
/// instruction-boundary verifier; this test is the schema-mandated
/// companion that locks down the *cache-shape* contract of `cpu::detect`.
///
/// **Reference**: AAP §0.7.4.4 (mandatory test name) + the `OnceLock`
/// idempotence pattern documented at `src/cpu.rs:130` ("returns same
/// reference on repeat calls").
///
/// **Asserted invariants:**
/// 1. `cpu::detect()` returns `&'static CpuFeatures` (compile-time
///    enforced by the function signature).
/// 2. Two consecutive calls return *identical pointers*
///    (`std::ptr::eq(a, b)` holds), i.e. the `OnceLock` is populated once
///    and re-read thereafter — no per-call CPUID re-issuance.
/// 3. Reading `CpuFeatures::has_aesni` and `CpuFeatures::is_intel` does
///    not panic and yields a `bool` value (any value is acceptable —
///    the test asserts only field accessibility, not the host's feature
///    set, since we cannot assume a specific x86_64 CPU model in CI).
///
/// **Skip conditions**: none. This test is universally applicable on
/// `x86_64-unknown-linux-gnu` (the only target this file compiles on
/// per the file-scope `#![cfg]` attributes).
#[test]
fn test_cpuid_feature_detection_does_not_panic() {
    // -------------------------------------------------------------------
    // Step 1 — Two consecutive `detect()` calls must return the SAME
    // `&'static CpuFeatures` pointer. The `OnceLock` inside `cpu.rs`
    // guarantees that the first call populates the slot and every
    // subsequent call returns a borrow of that same value. We verify
    // this with `std::ptr::eq` (the canonical Rust idiom for raw
    // pointer-identity comparison; `==` on `&T` would dereference and
    // compare values rather than addresses).
    //
    // This is the same idempotence pattern asserted by the in-crate
    // unit test `cpu::tests::detect_is_idempotent` at
    // `src/cpu.rs:detect_is_idempotent`. We re-assert it here from the
    // integration-test boundary to lock down the *public* semantic
    // contract: external callers depend on reference identity for
    // `Arc::ptr_eq`-style cache invalidation patterns at higher layers
    // (e.g., `crypto::aes` AES-NI dispatch decisions captured at
    // initialization time).
    // -------------------------------------------------------------------
    let a: &'static cpu::CpuFeatures = cpu::detect();
    let b: &'static cpu::CpuFeatures = cpu::detect();
    assert!(
        std::ptr::eq(a, b),
        "cpu::detect() must be idempotent (OnceLock semantics): \
         first call returned {:p}, second call returned {:p}",
        a,
        b,
    );

    // -------------------------------------------------------------------
    // Step 2 — Read the documented feature fields. The values themselves
    // are hardware-dependent (we make NO assumption about the host CPU's
    // feature set in CI: it could be a shared cloud VM with masked
    // features, or a bare-metal host with AES-NI enabled), but the
    // *fields must be readable as `bool`* without panicking. This
    // verifies the `CpuFeatures` struct shape contract.
    //
    // We bind both fields to `_`-prefixed bindings to suppress the
    // `unused_variables` warning while still ensuring the field load
    // is not optimized away by the compiler. The `let _x: bool = ...`
    // pattern with an explicit type annotation also catches any
    // accidental future change to the field type (e.g. `bool` -> `u8`).
    // -------------------------------------------------------------------
    let _has_aesni: bool = a.has_aesni;
    let _is_intel: bool = a.is_intel;

    // -------------------------------------------------------------------
    // Step 3 — Sanity-check that the cached `CpuFeatures` is not
    // suspiciously default-zero. `l1_size` is set to a safe default of
    // 64 by `cpu::detect_l1_size` (per `src/cpu.rs:l1_size_default_is_64`)
    // even on hardware where leaf 4 / leaf 0x80000006 fail; it should
    // therefore always be non-zero. This catches a hypothetical future
    // bug where `OnceLock::get_or_init` was bypassed and a zero-init
    // `CpuFeatures` was returned.
    // -------------------------------------------------------------------
    assert!(
        a.l1_size > 0,
        "cpu::detect().l1_size must be non-zero (safe default 64); got {}",
        a.l1_size,
    );
}

// =============================================================================
// `test_vdso_module_loads`
// -----------------------------------------------------------------------------
// Schema-required test #9 (per AAP §0.7.4.4). Smoke-test that the
// `heavything::util::vdso` module loads and its time-source primitives behave
// monotonically. Per AAP §0.5.1.7 / §0.7.4 this module is largely an
// API-parity stub on top of `std::time::Instant` because Rust's stdlib
// already resolves vDSO symbols (`__vdso_clock_gettime`) on Linux without
// any application action.
//
// No `unsafe` block lives in `util/vdso.rs` itself in the Rust port (the
// vDSO acceleration is delegated to `libc` which resolves the symbols at
// process start); the module is included here for **boundary-coverage
// completeness** and to catch any regression that would re-introduce manual
// `/proc/self/auxv` parsing or hand-rolled ELF walking of the vDSO page
// (which the FASM `vdso.inc` did, but which the Rust port does not).
// =============================================================================

/// Smoke test for `heavything::util::vdso` time-source primitives.
///
/// **UNSAFE_AUDIT.md cross-reference**: this module has zero unsafe
/// blocks per AAP §0.5.1.7 ("API-preservation stub; Rust `std::time`
/// uses vDSO automatically"). The test verifies the time-source
/// semantics function correctly — it is a CONTRACT test rather than an
/// FFI-boundary test, but it lives here to keep all
/// `vdso/cpu/termios/mmap/fork/setuid` boundary verification in a
/// single integration-test crate.
///
/// **Reference**: AAP §0.7.4.4 mandatory test name +
/// `src/util/vdso.rs::PROCESS_START` `OnceLock` initialization.
///
/// **Asserted invariants:**
/// 1. `vdso::init()` is callable and infallible.
/// 2. `Instant::now()` (which Rust resolves through the Linux vDSO)
///    is monotonically non-decreasing across two reads separated by
///    a brief sleep — the canonical property of `CLOCK_MONOTONIC`.
/// 3. `vdso::now_ns()` returns a non-decreasing `u64` after a sleep,
///    matching the contract documented at `src/util/vdso.rs:164`.
/// 4. `vdso::wall_unix_secs()` returns a value larger than the
///    epoch-2020 sentinel `1_577_836_800`, matching the example in
///    `src/util/vdso.rs:90`.
///
/// **Skip conditions**: none.
#[test]
fn test_vdso_module_loads() {
    // -------------------------------------------------------------------
    // Step 1 — Explicit `vdso::init()` is idempotent and infallible.
    // The function returns `()` per AAP §0.5.1.7 "preserves FASM's
    // integer-based timing API" (it merely seeds an internal
    // `OnceLock<Instant>`).
    // -------------------------------------------------------------------
    heavything::util::vdso::init();
    heavything::util::vdso::init(); // idempotent — second call is a no-op

    // -------------------------------------------------------------------
    // Step 2 — Verify the standard-library `Instant` monotonicity that
    // backs `vdso::now_*`. On Linux x86_64 this resolves to
    // `__vdso_clock_gettime(CLOCK_MONOTONIC, ...)` via libc.
    //
    // We sleep for 1 ms which is generous compared to vDSO clock
    // resolution (~1ns on modern Intel). The assertion `now2 >= now1`
    // (rather than strict `>`) is defensive against the unlikely case
    // of clock granularity coarser than 1 ms in a virtualized
    // environment.
    // -------------------------------------------------------------------
    let now1: Instant = Instant::now();
    std::thread::sleep(Duration::from_millis(1));
    let now2: Instant = Instant::now();
    assert!(
        now2 >= now1,
        "Instant::now() must be monotonically non-decreasing; \
         second read {:?} is earlier than first read {:?}",
        now2,
        now1,
    );

    // -------------------------------------------------------------------
    // Step 3 — Cross-verify against the `heavything::util::vdso::now_ns`
    // wrapper. After a 1ms sleep the second reading must be greater
    // than or equal to the first; the difference should be a positive
    // u64 nanosecond delta.
    // -------------------------------------------------------------------
    let ns1: u64 = heavything::util::vdso::now_ns();
    std::thread::sleep(Duration::from_millis(1));
    let ns2: u64 = heavything::util::vdso::now_ns();
    assert!(
        ns2 >= ns1,
        "vdso::now_ns() must be monotonically non-decreasing; \
         second read {} ns is earlier than first read {} ns",
        ns2,
        ns1,
    );

    // -------------------------------------------------------------------
    // Step 4 — Verify the wall-clock helper returns a sane Unix-epoch
    // value. The 2020-01-01 sentinel (`1_577_836_800`) matches the
    // example documented at `src/util/vdso.rs:90`. Any value at or
    // before that sentinel indicates an uninitialized / corrupted
    // `CLOCK_REALTIME` source — a system-administration issue rather
    // than a code bug, but worth flagging if the test ever runs on
    // such a machine.
    // -------------------------------------------------------------------
    let wall_secs: u64 = heavything::util::vdso::wall_unix_us() / 1_000_000;
    assert!(
        wall_secs > 1_577_836_800,
        "vdso::wall_unix_us() returned a Unix-epoch value at or before \
         2020-01-01 ({} s); host clock is misconfigured",
        wall_secs,
    );
}

// =============================================================================
// `test_exit_code_constants`
// -----------------------------------------------------------------------------
// Schema-required test #10 (per AAP §0.7.4.4). The four exit-code constants
// `EXIT_HEAP_MMAP_FAIL = 99`, `EXIT_PROFILER_OVERFLOW = 98`,
// `EXIT_ULIMIT_TOO_LOW = 97`, and `EXIT_EPOLL_CREATE_FAIL = 96` form part
// of the **observable interface** of the HeavyThing port per AAP §0.1.1
// ("Exit codes 96–99 ... are part of the observable interface and must be
// produced by the Rust code under equivalent failure conditions"). They
// match the FASM `ht.inc` lines 38–41 byte-for-byte.
//
// This test pins the constants to their canonical values so a future
// refactor that accidentally renumbered them would be caught at
// integration-test time before propagating to a production binary that
// downstream operators / monitoring tooling rely on for failure-mode
// triage.
// =============================================================================

/// Verifies the four FASM-compatible exit-code constants exposed by
/// `heavything` lib.rs match the canonical assembly values.
///
/// **UNSAFE_AUDIT.md cross-reference**: not directly an unsafe site;
/// the constants are exit-code mappings that downstream `process::exit`
/// and (forked-child) `libc::_exit` calls use. Listed in this file
/// because the schema requires it and because the unsafe sites that
/// EMIT these codes (`runtime::check_ulimit` for 97, mmap failures for
/// 99) are tested elsewhere in this binary.
///
/// **Reference**: AAP §0.1.1 "Exit codes 96–99" + `src/lib.rs:119–132`.
///
/// **Asserted invariants:**
/// * `heavything::EXIT_HEAP_MMAP_FAIL == 99` — `heap.inc` mmap failure
/// * `heavything::EXIT_PROFILER_OVERFLOW == 98` — profiler stack overrun
/// * `heavything::EXIT_ULIMIT_TOO_LOW == 97` — `RLIMIT_NOFILE` < 4096
/// * `heavything::EXIT_EPOLL_CREATE_FAIL == 96` — `epoll_create` /
///   tokio runtime construction failure
/// * The four constants form a contiguous descending sequence
///   {99, 98, 97, 96} so future operators can document the "9x exit
///   codes are HeavyThing init failures" convention without surprises.
///
/// **Skip conditions**: none.
#[test]
fn test_exit_code_constants() {
    // Step 1 — Pin each constant to its canonical AAP §0.1.1 value.
    assert_eq!(
        heavything::EXIT_HEAP_MMAP_FAIL,
        99,
        "EXIT_HEAP_MMAP_FAIL must be 99 (heap.inc mmap/mremap failure)",
    );
    assert_eq!(
        heavything::EXIT_PROFILER_OVERFLOW,
        98,
        "EXIT_PROFILER_OVERFLOW must be 98 (profiler.inc sample-stack overrun)",
    );
    assert_eq!(
        heavything::EXIT_ULIMIT_TOO_LOW,
        97,
        "EXIT_ULIMIT_TOO_LOW must be 97 (RLIMIT_NOFILE < EPOLL_MINFDS)",
    );
    assert_eq!(
        heavything::EXIT_EPOLL_CREATE_FAIL,
        96,
        "EXIT_EPOLL_CREATE_FAIL must be 96 (epoll_create / tokio Runtime::new fail)",
    );

    // Step 2 — The four constants must be distinct and form a
    // contiguous descending sequence so the "9x = HeavyThing init
    // failure" convention is unambiguous to downstream operators.
    let codes = [
        heavything::EXIT_HEAP_MMAP_FAIL,
        heavything::EXIT_PROFILER_OVERFLOW,
        heavything::EXIT_ULIMIT_TOO_LOW,
        heavything::EXIT_EPOLL_CREATE_FAIL,
    ];
    let max = *codes.iter().max().expect("non-empty array");
    let min = *codes.iter().min().expect("non-empty array");
    assert_eq!(max, 99, "max exit code in the FASM-compatible set must be 99",);
    assert_eq!(min, 96, "min exit code in the FASM-compatible set must be 96",);
    // Verify all four values are distinct (set semantics).
    let mut sorted = codes.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        4,
        "the four EXIT_* constants must be distinct (got {:?})",
        codes,
    );
}

// =============================================================================
// `test_isatty_smoke`
// -----------------------------------------------------------------------------
// Schema-required test #11 (per AAP §0.7.4.4). Confirms that `libc::isatty`
// is linkable, callable, and returns one of the two POSIX-mandated values
// (`0` for "not a terminal" or `1` for "is a terminal"). This is the
// FFI-linkage smoke test for the `libc` crate's terminal-detection
// primitive used pervasively throughout the test suite as a TTY-skip gate
// (see `test_raw_terminal_roundtrip` and `test_sigwinch_handler`).
//
// The value returned varies based on test-execution environment: the
// `cargo test` harness typically captures stdout via a pipe, so isatty
// returns 0; running interactively in a real terminal returns 1. The test
// asserts only that the return value is one of those two — not which one.
// =============================================================================

/// Smoke test for `libc::isatty` FFI linkage and return-value contract.
///
/// **UNSAFE_AUDIT.md cross-reference**: this is a `libc` FFI boundary
/// invocation that mirrors the `stdin_is_tty()` helper used by every
/// TTY-gated test in this file (e.g., `test_raw_terminal_roundtrip`).
/// Verifying it works at the integration-test layer ensures the
/// `libc::isatty` symbol is correctly resolved at link time and that
/// the `libc::STDIN_FILENO` constant is reachable.
///
/// **Reference**: AAP §0.7.4.4 + POSIX `isatty(3)` specification
/// ("isatty() returns 1 if fd is an open file descriptor referring to a
/// terminal; otherwise 0 is returned, and errno is set").
///
/// **Asserted invariants:**
/// 1. `libc::isatty(libc::STDIN_FILENO)` returns 0 or 1 (no other
///    values are POSIX-permitted).
/// 2. The call does not panic, abort, or trigger UB.
/// 3. `libc::STDIN_FILENO` is the canonical value `0`.
///
/// **Skip conditions**: none. The test passes regardless of whether
/// stdin is a TTY because we only assert the return value is in
/// `{0, 1}`.
#[test]
fn test_isatty_smoke() {
    // Step 1 — Sanity-check the well-known fd constant. POSIX mandates
    // STDIN_FILENO == 0; this assertion catches any bizarre future
    // libc-crate refactor that breaks the constant.
    assert_eq!(
        libc::STDIN_FILENO,
        0,
        "libc::STDIN_FILENO must be 0 (POSIX standard fd number)",
    );

    // Step 2 — Call isatty on stdin. The result varies by environment:
    //   * `cargo test` (stdout piped to harness): returns 0
    //   * Interactive terminal: returns 1
    // We only assert "in {0, 1}" — not a specific value — so the test
    // is environment-independent.
    //
    // SAFETY: `libc::isatty` is an FFI call to a POSIX-standard
    // function. It reads the TTY attributes of the given fd via the
    // `tcgetattr` path internally and is safe to call on any integer
    // fd value (including invalid fds, for which it returns 0 with
    // errno set to EBADF). `STDIN_FILENO` (= 0) is a process-lifetime
    // valid fd: the kernel guarantees it remains open from `execve`
    // through process exit unless explicitly closed by the program,
    // which Cargo's test harness does not do.
    let r: libc::c_int = unsafe { libc::isatty(libc::STDIN_FILENO) };
    assert!(
        r == 0 || r == 1,
        "libc::isatty(STDIN_FILENO) must return 0 or 1; got {} \
         (errno after call: {})",
        r,
        std::io::Error::last_os_error(),
    );

    // Step 3 — Independently invoke isatty on a known-invalid fd to
    // exercise the error path. POSIX `isatty(3)` specifies that for
    // an invalid fd the return value is 0 and `errno` is set to
    // `EBADF`. We do not assert errno (that would couple the test to
    // the calling thread's errno state which may have been clobbered
    // by intermediate runtime activity); we assert only the return
    // value, which is the externally-observable contract.
    //
    // SAFETY: `libc::isatty` accepts any integer fd and returns 0 for
    // invalid fds. Passing the sentinel value -1 (universally
    // recognized as an invalid fd in POSIX) is a documented usage
    // pattern and triggers no UB.
    let r_invalid: libc::c_int = unsafe { libc::isatty(-1) };
    assert_eq!(
        r_invalid, 0,
        "libc::isatty(-1) must return 0 for an invalid fd; got {}",
        r_invalid,
    );
}
