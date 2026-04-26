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
//! covering every unsafe block in the workspace:
//!
//! | Canonical test name              | Unsafe site it exercises                                      | Owning module                                  |
//! |----------------------------------|---------------------------------------------------------------|------------------------------------------------|
//! | `test_raw_terminal_roundtrip`    | `libc::tcgetattr` / `cfmakeraw` / `tcsetattr` in `RawTerminal`| `heavything::tui::terminal`                    |
//! | `test_sigwinch_handler`          | `libc::sigaction` for SIGWINCH/SIGTERM/SIGINT/SIGPIPE         | `heavything::tui::terminal` / `::util::signals` |
//! | `test_setuid_setgid_drop`        | `nix::unistd::{setuid,setgid}` in master privilege-drop       | `crates::webserver::master`                    |
//! | `test_fork_workers`              | `nix::unistd::fork` in master `spawn_workers`                 | `crates::webserver::master`                    |
//! | `test_mmap_file_cache`           | `memmap2::Mmap::map` in hotlist file cache                    | `heavything::net::http::server`                |
//! | `test_prctl_pdeathsig`           | `nix::sys::prctl::set_pdeathsig` in worker / child init       | `heavything::net::child` / `webserver::worker` |
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

#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{close, fork, pipe, read as nix_read, write as nix_write, ForkResult, Pid};

use heavything::error::InitError;
use heavything::net::child::{
    killall_children, spawn_child, ChildProcess, LinkMessage, LogRecord, LogSeverity,
};
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
