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
//! the branch. The three tests below cover the **`heavything::net::child`
//! subsystem specifically** (AAP §0.7.4.2):
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

use heavything::net::child::{
    killall_children, spawn_child, ChildProcess, LinkMessage, LogRecord, LogSeverity,
};

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
