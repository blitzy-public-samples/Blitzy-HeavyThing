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

//! Entry point for the `webserver` binary crate (translation of
//! `rwasa/rwasa.asm` per AAP §0.5.1.8).
//!
//! Responsibilities:
//!
//! 1. Parse CLI arguments via [`arguments::parse`]. On failure, print
//!    the error message followed by the usage banner to stdout and
//!    exit with status `1` (byte-identical to the assembly `rwasa`'s
//!    output path: errors go through `string$to_stdoutln` which ends
//!    with `mov edi, 1; syscall_write` (`string32.inc` lines
//!    2229–2260) and the banner is emitted via a direct
//!    `syscall_write` with `edi = 1` at `arguments.inc` line 763).
//!    This preserves the AAP §0.8.1 "preserve all observable
//!    behavior" contract for argument-parse failures.
//!
//! 2. On successful parse, hand control to [`master::run`], which
//!    binds all TCP listeners, drops privileges (`bind → setgid →
//!    setuid → fork` ordering per AAP §0.1.1), forks `cpucount`
//!    workers, daemonizes if `-background` is set, builds a tokio
//!    multi-thread runtime, and runs the master-side event loop until
//!    SIGTERM/SIGINT.
//!
//! 3. Translate the master's `Result<()>` into an [`ExitCode`].
//!    Note that most fatal error paths inside [`master::run`] call
//!    [`std::process::exit`] directly with byte-identical error
//!    messages (`"setgid() failed."`, `"setuid() failed."`,
//!    `"Fatal: fork and/or socketpair failed."`, etc.) and never
//!    return; only structural errors (bind failures, daemonize
//!    failures, runtime-context errors) bubble back here as `Err`.
//!    For those, we print the full error chain to stderr and return
//!    [`ExitCode::FAILURE`] (status `1`).

mod arguments;
mod master;

use std::process::ExitCode;

fn main() -> ExitCode {
    // Collect argv as the OS-native `OsString` sequence, matching the
    // signature expected by `arguments::parse` (AAP §0.8.3: no
    // `unwrap`/`expect` on untrusted input).
    let args = std::env::args_os();

    // Parse arguments. On failure: print the error followed by the
    // usage banner (both to stdout, byte-identical to the assembly
    // `rwasa`'s output path) and exit with status 1.
    let cfg = match arguments::parse(args) {
        Ok(c) => c,
        Err(e) => {
            println!("{e}");
            arguments::print_usage();
            return ExitCode::from(1);
        }
    };

    // Hand control to the master-process lifecycle. Most fatal paths
    // inside `master::run` call `std::process::exit` directly with
    // byte-identical FASM error messages; those never return. The
    // residual `Err` cases are structural failures (bind, daemonize,
    // tokio UnixStream wrap) that haven't already printed.
    match master::run(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `{:#}` prints the full anyhow error chain (top-level
            // message + every `.context(...)` layer + the root cause)
            // on a single line, which is the behavior closest to the
            // FASM `string$to_stdoutln` single-line error reports.
            eprintln!("master: {e:#}");
            ExitCode::from(1)
        }
    }
}
