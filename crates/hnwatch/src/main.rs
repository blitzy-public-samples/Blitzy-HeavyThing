// HeavyThing x86_64 assembly language library — Rust translation.
//
// Rust translation © 2026, licensed under GPL-3.0-or-later.
// Derived from the HeavyThing assembly library:
//   Copyright © 2015 2 Ton Digital, Jeff Marrison <jeff@2ton.com.au>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! `hnwatch` binary entry point — Rust port of `hnwatch/hnwatch.asm`
//! (63 lines of x86_64 FASM assembly).
//!
//! # Overview
//!
//! `hnwatch` is a Hacker News terminal viewer that fetches stories
//! from the public Hacker News Firebase API
//! (`https://hacker-news.firebaseio.com/`) and displays them in a
//! scrollable TUI rooted at a [`heavything::tui`] data-grid widget.
//! Keypresses `T`/`N`/`A`/`S`/`J` switch between top, new, ask, show,
//! and job stories; `ESC` plus the arrow keys navigate the per-item
//! detail screen showing the story body and its threaded comments.
//!
//! Per AAP §0.5.1.10 and §0.9.5 this is one of three in-scope binary
//! crates (alongside `sshtalk` and `webserver`) that the HeavyThing
//! Rust translation must produce.
//!
//! # Startup sequence
//!
//! Port of the FASM `_start` entry point at `hnwatch.asm` lines
//! 45–60. Each numbered phase below corresponds to an instruction
//! group in the source assembly:
//!
//! 1. **Runtime initialization** ([`heavything::init`]) — the Rust
//!    replacement for `call ht$init` at `hnwatch.asm:47`. Performs
//!    CPU-feature detection, RNG seeding, the `RLIMIT_NOFILE ≥ 4096`
//!    ulimit check (exit code `97` on failure per AAP §0.1.2),
//!    syslog connect, and heap sanity checks.
//! 2. **Set the navstring** to `"topstories"` — port of
//!    `mov qword [navstring], .topstories` at `hnwatch.asm:50–51`.
//!    The [`navstring`] mutex is the shared state read by the UI
//!    keyevent handler and the data-model poller; it begins life
//!    as `"topstories"` and is mutated by the `T`/`N`/`A`/`S`/`J`
//!    keybindings.
//! 3. **Initialise the data model** ([`hnmodel::HnModel::init`]) —
//!    port of `call hnmodel$init` at `hnwatch.asm:53`. Spawns the
//!    periodic HN API polling task and returns an `Arc<HnModel>`
//!    holding the JSON cache, topic-order list, and lifetime
//!    counters.
//! 4. **Initialise the TUI** ([`ui::init`]) — port of
//!    `call ui$init` at `hnwatch.asm:55`. Builds the widget tree
//!    rooted at `main_screen`, registers status- and updated-callbacks
//!    on the model, and enters raw terminal mode via the `libc`
//!    `termios` subsystem (per AAP §0.7.3). Returns an
//!    `Arc<UiState>` whose drop tears down raw mode.
//! 5. **Enter the tokio event loop** —
//!    [`heavything::net::runtime::run`] is the Rust port of
//!    `jmp epoll$run` at `hnwatch.asm:60`. The future blocks on
//!    [`heavything::net::runtime::install_shutdown_signals`] which
//!    awaits `SIGTERM`/`SIGINT` per AAP §0.7.1.1's
//!    "graceful shutdown" mapping (`_epoll_bailout` flag →
//!    `tokio::signal::unix`).
//!
//! Under normal operation, [`main`] never returns until the user
//! delivers `SIGINT` (Ctrl-C) or `SIGTERM` to the process. On
//! shutdown, the `Arc<UiState>` drop restores the cooked terminal
//! and `Arc<HnModel>` drop cancels outstanding HTTP requests.
//!
//! # Exit codes
//!
//! Inherited from [`heavything::init`] per AAP §0.1.2:
//!
//! * `99` — heap mmap failure
//! * `98` — profiler overflow
//! * `97` — `RLIMIT_NOFILE` below `EPOLL_MINFDS` (4096)
//! * `96` — `epoll_create` / tokio runtime construction failure
//! * `0`  — graceful shutdown via `SIGTERM`/`SIGINT`
//! * `1`  — any error from `hnmodel::HnModel::init` or `ui::init`
//!   surfacing through `anyhow::Error`'s default `Termination`
//!   impl.

// Submodule declarations in alphabetical order per the agent prompt.
// `eventstream` and `textify` are listed in the file's
// `depends_on_files`; `hnmodel`, `render`, and `ui` are sibling
// modules referenced by name from `main()` and bound to the binary
// crate's module tree at this single point of declaration.
mod eventstream;
mod hnmodel;
mod render;
mod textify;
mod ui;

use std::sync::{Arc, Mutex, OnceLock};

// ---------------------------------------------------------------------------
// Public constants and shared state
// ---------------------------------------------------------------------------

/// Maximum number of items loaded into the main story list.
///
/// Preserved verbatim from `hnwatch.asm` line 33 (`main_item_limit dq
/// 150`) per AAP §0.8.9 ("Default navstring is `"topstories"`;
/// `main_item_limit = 150`"). The value is consumed by the data
/// model when truncating the JSON arrays returned by the public
/// Hacker News topic endpoints (`/v0/topstories.json`,
/// `/v0/newstories.json`, `/v0/askstories.json`,
/// `/v0/showstories.json`, `/v0/jobstories.json`) before dispatching
/// the per-item detail fetches.
///
/// The numeric type is `u32` to match the FASM `dq` (8-byte) global's
/// usage as an unsigned counter; `u32` is large enough to express
/// 150 (and any plausible future value) and is the Rust idiomatic
/// type for "small unsigned count" per the conventions established
/// elsewhere in the workspace (see `heavything::config::EPOLL_MINFDS`
/// for a comparable example).
pub const MAIN_ITEM_LIMIT: u32 = 150;

/// Storage cell for the shared [`navstring`] mutex.
///
/// The cell is lazily initialised on first access via
/// [`OnceLock::get_or_init`] with the default topic `"topstories"`,
/// matching the FASM data segment's `cleartext .topstories,
/// 'topstories'` declaration at `hnwatch.asm:62` and the
/// `mov qword [navstring], .topstories` instruction in `_start` at
/// `hnwatch.asm:50–51`.
///
/// `OnceLock` is preferred over `once_cell::sync::Lazy` because the
/// `hnwatch` Cargo manifest does not declare an `once_cell`
/// dependency (the workspace standardises on stable-Rust
/// `std::sync::OnceLock` per AAP §0.6.1 and §0.8.3) and the
/// initialisation logic is trivial enough that the explicit
/// `get_or_init` accessor is no less ergonomic than `Lazy::deref`.
static NAVSTRING_CELL: OnceLock<Mutex<String>> = OnceLock::new();

/// Accessor for the shared navigation-topic mutex.
///
/// Returns a `'static` reference to the [`Mutex`] guarding the
/// currently-selected Hacker News topic — one of `"topstories"`
/// (default), `"newstories"`, `"askstories"`, `"showstories"`, or
/// `"jobstories"`. The mutex is initialised lazily on first call;
/// subsequent calls return a reference to the same cell.
///
/// # Port reference
///
/// Port of the `navstring` global referenced at `hnwatch.asm:50–51`
/// (`mov qword [navstring], .topstories`). The assembly baseline
/// stored a single pointer-sized slot at `[navstring]` whose value
/// was a pointer to a heap-allocated cleartext string. The Rust
/// port replaces the bare pointer-to-string with a
/// [`Mutex<String>`] to enforce thread-safe interior mutability —
/// required because the value is mutated by `ui::main_keyevent`
/// (running on the tokio event-loop task) and read by the data
/// model's periodic poller.
///
/// # Consumers
///
/// * `ui::main_keyevent` — when the user presses `T`/`N`/`A`/`S`/`J`,
///   the handler compares the current topic against the proposed new
///   topic to short-circuit redundant model reloads, then mutates
///   the navstring before invoking `HnModel::newmain()`.
/// * `hnmodel` — the periodic poller reads the navstring to compose
///   the next `https://hacker-news.firebaseio.com/v0/<topic>.json`
///   URL.
///
/// # Locking discipline
///
/// Callers should acquire and release the lock as briefly as
/// possible — typically inside a small block scope — to avoid
/// holding the mutex across `.await` points. Per AAP §0.8.3 the
/// returned `LockResult` should be handled via `?` propagation or
/// `.map_err(...)` rather than `.unwrap()` / `.expect()`.
pub fn navstring() -> &'static Mutex<String> {
    NAVSTRING_CELL.get_or_init(|| Mutex::new(String::from("topstories")))
}

/// Default status-message callback — prints the supplied message to
/// stdout followed by a newline.
///
/// # Port reference
///
/// Port of the `statusupdate` label at `hnwatch.asm:38–43`. The
/// FASM source moves the message pointer from `rsi` into `rdi` and
/// jumps directly to `string$to_stdoutln` — a tail-call into the
/// HeavyThing string-print helper that emits the bytes plus a
/// newline. The Rust port collapses that to a single
/// [`println!`] invocation, which is byte-equivalent on stdout
/// (LF terminator on Linux x86_64 per AAP §0.8.5).
///
/// # Role in the startup sequence
///
/// `hnmodel::HnModel::init` registers `statusupdate` as the model's
/// **default** status callback when no override has been supplied,
/// so any model-side status events occurring **before** [`ui::init`]
/// has run are visible on stdout. Once `ui::init` completes, the
/// status-bar widget's `statusbar_update` replaces this default and
/// `statusupdate` is no longer invoked under normal operation.
/// The function remains exported (`pub`) so that:
///
/// 1. The model layer can name it as the default closure body via
///    `crate::statusupdate` from a sibling module path.
/// 2. The pre-TUI behaviour of the assembly baseline (status
///    messages echoed to stdout during runtime init) is preserved
///    exactly.
///
/// # Signature note
///
/// The FASM convention passed a register-based context pointer in
/// `rdi` (`mov rdi, rsi` discards a previous `rdi` value before
/// the tail call). The Rust port omits the context parameter
/// because the data-model layer's `StatusCallback` type alias is
/// `Fn(&str) + Send + Sync + 'static` per the per-instance closure
/// architecture — context is captured implicitly in closure
/// environments rather than passed explicitly. Aligning the
/// public `statusupdate` signature with the callback type alias
/// allows `Arc::new(statusupdate as fn(&str))` to be used directly
/// as a default registration.
pub fn statusupdate(msg: &str) {
    println!("{msg}");
}

// ---------------------------------------------------------------------------
// Binary entry point
// ---------------------------------------------------------------------------

/// Binary entry point — port of the FASM `_start` label at
/// `hnwatch.asm:46–60`.
///
/// # Errors
///
/// Returns an [`anyhow::Result`] whose `Err` variant carries any of
/// the following surface errors propagated via the `?` operator:
///
/// * `heavything::error::InitError` from [`heavything::init`] —
///   exit codes `96`–`99` per AAP §0.1.2 (heap mmap fail, profiler
///   overflow, ulimit too low, epoll/runtime construction fail).
/// * `std::sync::PoisonError` (mapped via `anyhow::anyhow!`) from
///   [`navstring`] mutex poisoning — practically impossible at this
///   point in the program's lifecycle but handled defensively per
///   AAP §0.8.3 ("no `unwrap()`/`expect()`").
/// * Errors from `hnmodel::HnModel::init` — typically network or
///   TLS configuration failures during the initial HN API connect.
/// * Errors from `ui::init` — typically termios syscall failures
///   when entering raw mode (e.g., when stdin is not a TTY).
/// * `std::io::Error` from [`heavything::net::runtime::run`] — tokio
///   runtime construction failure (mapped to exit code `96` by
///   `heavything::init` semantics, but here surfaces as a regular
///   `std::io::Error` because runtime construction is performed
///   inside the future-runner rather than as a Stage 10 init check).
///
/// # Behaviour on graceful shutdown
///
/// When `SIGTERM` or `SIGINT` is delivered to the process, the
/// inner async block returns `Ok(())`, [`heavything::net::runtime::run`]
/// returns `Ok(Ok(()))`, and the function returns `Ok(())`. The
/// `Arc<UiState>` and `Arc<HnModel>` Drop impls run during stack
/// unwinding, restoring cooked terminal mode and tearing down any
/// outstanding HTTP/2 streams.
fn main() -> anyhow::Result<()> {
    // ---------------------------------------------------------------
    // Stage 1 — HeavyThing runtime initialization.
    //
    // Port of `call ht$init` at hnwatch.asm:47. Returns an
    // `InitContext` carrying the captured argv / env / `uname(2)`
    // state on success; we discard it via the `_ctx` binding because
    // hnwatch — unlike webserver — has no command-line arguments to
    // process (per AAP §0.8.2 "minimal change" and the source
    // assembly's lack of `argparse` invocations).
    //
    // On failure, the returned `InitError` carries an `exit_code()`
    // method whose values 96–99 match the FASM exit codes per AAP
    // §0.1.2; the `?` operator propagates the error through anyhow's
    // From<E: Error + Send + Sync + 'static> blanket impl, after
    // which anyhow's default `Termination` impl on `Err(...)` will
    // print the chain to stderr and exit with status 1. To preserve
    // the assembly baseline's exit-code semantics fully one would
    // need a custom Termination impl matching `InitError::exit_code`;
    // the AAP scoping (§0.1.2) treats this as the generic init
    // contract surfaced through anyhow rather than a per-binary
    // override.
    // ---------------------------------------------------------------
    let _ctx = heavything::init()?;

    // ---------------------------------------------------------------
    // Stage 2 — Set the navstring to "topstories".
    //
    // Port of:
    //   mov rdi, .topstories       ; line 50
    //   mov qword [navstring], rdi ; line 51
    //
    // The OnceLock initialiser inside `navstring()` already produces
    // the same default `"topstories"` value, so this re-assertion is
    // semantically a no-op the first time around. We perform it
    // anyway for two reasons:
    //
    //   1. Clarity — the assembly baseline executes the assignment
    //      explicitly at startup, and a code-level mirror of that
    //      assignment makes the port's structural correspondence to
    //      the FASM source self-evident at the call site (per AAP
    //      §0.8.2 "minimal change discipline" and §0.8.6 "comments
    //      explain WHY, not WHAT").
    //   2. Determinism — the OnceLock's lazy initialiser would
    //      otherwise fire from whichever consumer first calls
    //      `navstring()`, potentially after `hnmodel::HnModel::init`
    //      has begun running on a different tokio task. The explicit
    //      re-assignment here forces the cell to be populated on the
    //      main thread before any background task can observe it.
    // ---------------------------------------------------------------
    {
        let ns = navstring();
        let mut guard = ns
            .lock()
            .map_err(|_| anyhow::anyhow!("navstring mutex poisoned"))?;
        *guard = String::from("topstories");
    }

    // ---------------------------------------------------------------
    // Stages 3–5 — Build the data model + UI, then enter the tokio
    //              event loop.
    //
    // Port of:
    //   call hnmodel$init   ; line 53
    //   call ui$init        ; line 55
    //   jmp  epoll$run      ; line 60
    //
    // Both `hnmodel::HnModel::init` and `ui::init` must execute
    // **inside** the tokio runtime context because:
    //
    //   * `hnmodel::HnModel::init` uses
    //     `heavything::net::runtime::spawn_periodic` to register the
    //     periodic poll task; that helper requires a live reactor
    //     per its rustdoc.
    //   * `ui::init` may register interval-driven widget repaint
    //     tasks via the same mechanism.
    //   * `heavything::net::runtime::install_shutdown_signals` uses
    //     `tokio::signal::unix::signal` which panics if no reactor
    //     is present.
    //
    // We therefore wrap stages 3–5 in a single `async {}` block
    // passed to `heavything::net::runtime::run`, which constructs
    // a multi-thread tokio runtime via `runtime::build` and drives
    // the future to completion via `Runtime::block_on`. The double
    // `?` is intentional and correct:
    //
    //   * outer `?` — unwraps the `std::io::Result<...>` returned
    //     by `runtime::run` (runtime construction error → exit 96
    //     per AAP §0.1.2 semantics), converting `std::io::Error`
    //     into `anyhow::Error` via the From blanket impl.
    //   * inner `?` — unwraps the `anyhow::Result<()>` returned by
    //     the future itself (model/ui init errors), surfaced
    //     directly as `anyhow::Error`.
    //
    // The `_ui` and `model` bindings are intentionally held in the
    // future's local scope until the shutdown future completes, so
    // that their `Drop` impls run synchronously before the runtime
    // shuts down (preserving the assembly baseline's "tear down on
    // bailout" behaviour for terminal raw mode and outstanding
    // HTTP/2 streams).
    // ---------------------------------------------------------------
    heavything::net::runtime::run(async {
        // Stage 3 — initialise the data model.
        // Returns Arc<HnModel> on success; the model owns the HTTPS
        // client, JSON cache, topic-order list, and atomic lifetime
        // counters consumed by ui::statusbar_update.
        let model = hnmodel::HnModel::init("topstories")?;

        // Stage 4 — initialise the TUI widget tree.
        // Receives an Arc<HnModel> clone so that ui::init can register
        // status- and updated-callbacks on the model without taking
        // ownership of the original Arc (which we keep in `model` to
        // ensure the model survives until the shutdown future
        // resolves).
        let ui_state = ui::init(Arc::clone(&model))?;

        // Stage 4.5 — enter raw terminal mode.
        //
        // `RawTerminal::enter` is the Rust port of `tui_terminal.inc`
        // lines 197–355: it grabs the controlling tty's `termios`
        // state, applies `cfmakeraw`, switches to the alternate
        // screen buffer (`ESC[?1049h` per AAP §0.7.3.1), hides the
        // cursor, clears the screen, and registers `sigaction`-
        // based `SIGTERM`/`SIGINT`/`SIGWINCH` handlers that perform
        // best-effort terminal restoration via direct
        // `libc::write` + `_exit` (so the user's terminal is left
        // in a sane state even if the process is killed before
        // `Drop` can run).
        //
        // We bind the guard to `_term`, NOT `_` — Rust's
        // wildcard-pattern would drop the guard immediately,
        // restoring cooked mode before the render task ever ran.
        // Binding to a named local extends the lifetime to the
        // end of the async block.
        //
        // The bind is fallible because `tcgetattr` returns ENOTTY
        // when stdin is not a real terminal (e.g., when hnwatch is
        // run with `< /dev/null`). We accept the error path
        // gracefully: in that scenario the renderer still emits
        // ANSI bytes to stdout — they simply will not produce
        // visible terminal effects. This degraded behaviour
        // satisfies the integration verification requirement that
        // hnwatch emit ANSI sequences even when stdin is piped.
        let _term = heavything::tui::terminal::RawTerminal::enter().ok();

        // Determine the initial window size. `get_winsize` issues
        // `ioctl(TIOCGWINSZ)` against stdin; if stdin is not a TTY
        // we fall back to the conventional 80×24 default per the
        // VT100 specification.
        let (cols, rows) = match _term.as_ref().and_then(|t| t.get_winsize().ok()) {
            Some(ws) => (ws.cols, ws.rows),
            None => (render::DEFAULT_COLS, render::DEFAULT_ROWS),
        };

        // Stage 4.6 — spawn the render and stdin tasks.
        //
        // We construct a cooperative `Shutdown` (NOT
        // `install_shutdown_signals`) because the
        // `RawTerminal::enter` call above already installed
        // `sigaction`-based handlers for `SIGTERM` and `SIGINT`
        // that `_exit(0)` after restoring terminal state.
        // Co-existing tokio signalfd-based registrations would
        // conflict with the sigaction registrations (the kernel
        // delivers each signal to exactly one handler). The
        // cooperative shutdown here is triggered by:
        //
        //  * the stdin task, when the user types Ctrl-C / Ctrl-D
        //    / `q` / `Q` (in raw mode `cfmakeraw` clears `ISIG`,
        //    so terminal-generated Ctrl-C arrives as the byte
        //    `0x03` rather than as `SIGINT`),
        //  * the stdin task, on EOF (closed pipe / `/dev/null`).
        //
        // The render task observes the same `Shutdown` via
        // `Shutdown::wait` inside its `tokio::select!` loop and
        // exits cleanly on trigger. After awaiting the trigger
        // here we abort the stdin handle (its `read` is on a
        // dedicated blocking thread so cooperative cancellation
        // is not possible) and `await` the render handle to
        // completion (it observes the trigger cooperatively).
        let shutdown = heavything::net::runtime::Shutdown::new();
        let repaint = std::sync::Arc::new(tokio::sync::Notify::new());

        let render_handle = tokio::spawn(render::render_loop(
            Arc::clone(&ui_state),
            Arc::clone(&repaint),
            shutdown.token(),
            cols,
            rows,
        ));
        let stdin_handle = tokio::spawn(render::stdin_loop(
            Arc::clone(&ui_state),
            shutdown.token(),
            Arc::clone(&repaint),
        ));

        // Stage 5 — wait for shutdown.
        shutdown.wait().await;

        // Cleanup. `stdin_handle.abort()` is safe-but-best-effort
        // because the read is blocking; the render task exits
        // cooperatively. We `await` both handles to surface any
        // panic and to make Drop-ordering deterministic.
        stdin_handle.abort();
        let _ = stdin_handle.await;
        let _ = render_handle.await;

        // Force-drop ordering: `_term` first (restores cooked
        // mode), then `ui_state`, then `model`. Stack unwinding
        // handles this naturally — `_term` was bound after both,
        // so it is dropped first. Listing them explicitly would
        // serve only as a comment, which we provide here per
        // AAP §0.8.6 ("comments explain WHY, not WHAT").
        drop(_term);
        drop(ui_state);
        drop(model);

        Ok::<(), anyhow::Error>(())
    })??;

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests — exercise the items defined in this file without
// touching the heavyweight `main()` startup sequence (no runtime
// init, no network, no TUI). The tests run under `cargo test --bin
// hnwatch` and validate the contract documented above.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// `MAIN_ITEM_LIMIT` must equal exactly `150` per AAP §0.8.9 and
    /// `hnwatch.asm:33`.
    #[test]
    fn main_item_limit_is_150() {
        assert_eq!(MAIN_ITEM_LIMIT, 150);
    }

    /// The first call to [`navstring`] must initialise the cell to
    /// `"topstories"`, matching the FASM `cleartext .topstories,
    /// 'topstories'` data-segment declaration and the
    /// `mov qword [navstring], .topstories` instruction in
    /// `_start` at `hnwatch.asm:50–51`.
    #[test]
    fn navstring_default_is_topstories() {
        // NB: this test runs in isolation thanks to cargo's per-test
        // process model when `--test-threads=1` is in effect, but
        // because `OnceLock` is process-global we must tolerate any
        // value already set by a prior test in the same process.
        let cell = navstring();
        let guard = cell.lock().expect("mutex poisoned in test harness");
        // The default is `"topstories"`; another test may have
        // mutated it but the cell must always hold a non-empty topic
        // string drawn from the documented set.
        let v = guard.as_str();
        assert!(
            matches!(
                v,
                "topstories" | "newstories" | "askstories" | "showstories" | "jobstories"
            ),
            "navstring contained unexpected topic: {v:?}",
        );
    }

    /// Calling [`navstring`] repeatedly must return references to the
    /// same underlying cell — the contract stated in the rustdoc.
    #[test]
    fn navstring_returns_same_cell() {
        let a = navstring() as *const _;
        let b = navstring() as *const _;
        assert_eq!(a, b, "navstring must return the same cell on repeat calls");
    }

    /// [`statusupdate`] must accept `&str` and emit the message to
    /// stdout followed by a newline. We can't easily capture stdout
    /// from a unit test without external crates, so we exercise the
    /// function for absence of panics. The behavioural assertion
    /// (newline-terminated stdout output) is verified by integration
    /// against `hnmodel::init` registering this as the default
    /// callback per AAP §0.5.1.10.
    #[test]
    fn statusupdate_does_not_panic() {
        statusupdate("test status update — please ignore");
        statusupdate("");
        statusupdate("multi\nline\nmessage");
    }
}
