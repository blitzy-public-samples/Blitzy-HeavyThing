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

//! **TEMPORARY PLACEHOLDER** for `crates/webserver/src/main.rs`.
//!
//! Per AAP §0.5.1.8, the final `main.rs` is authored by a downstream
//! agent and is responsible for the full master-worker lifecycle:
//! calling `heavything::init_args`, building the master process,
//! forking `-cpu N` workers, dropping privileges, and running the
//! `tokio::runtime::Runtime`.
//!
//! This placeholder exists solely to satisfy `[[bin]] path = "src/main.rs"`
//! in `crates/webserver/Cargo.toml` so that the sibling module
//! [`arguments`] (the file actually owned by this task) can be
//! compiled, type-checked, linted, and unit-tested by `cargo`.
//!
//! It performs the bare minimum main-process work required to exercise
//! [`arguments::parse`] end-to-end:
//!
//! 1. Parse CLI args via [`arguments::parse`].
//! 2. On failure, print the error message + usage banner to stderr and
//!    exit with status `1` (matching the assembly `rwasa`'s failure
//!    behavior verbatim per `arguments.inc` lines 731–767).
//! 3. On success, print a one-line-per-field dry-run summary to stderr
//!    and exit with status `0`. The summary legitimately reads every
//!    field of every exported struct so that the strict `-D warnings`
//!    `dead_code` lint is satisfied without any `#[allow(...)]`
//!    suppressions (AAP §0.8.3).
//!
//! It does **not** bind sockets, fork workers, drop privileges, or
//! start any runtime. The downstream agent implementing the real
//! master/worker is expected to replace this file wholesale.

mod arguments;

use std::process::ExitCode;

use arguments::Config;

fn main() -> ExitCode {
    // Collect argv as the OS-native `OsString` sequence, matching the
    // signature expected by `arguments::parse` (AAP §0.8.3: no
    // `unwrap`/`expect` on untrusted input).
    let args = std::env::args_os();

    // Parse arguments. On failure: print the error followed by the
    // usage banner (both to stderr, byte-identical to the assembly
    // `rwasa`'s output path per `arguments.inc` lines 731–767) and
    // exit with status 1.
    let cfg = match arguments::parse(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            arguments::print_usage();
            return ExitCode::from(1);
        }
    };

    // Dry-run summary: print one line per config field. This serves two
    // purposes: (1) confirms to the user that the parse succeeded and
    // shows what the final main.rs would act on, and (2) performs a
    // legitimate read of every field of every exported struct, which
    // keeps the strict dead-code lint satisfied for this placeholder
    // without any `#[allow(dead_code)]` annotation.
    eprintln!("{}", summarize(&cfg));

    // The real main.rs (downstream) would now build the master from
    // `cfg` and enter the runtime. This stub stops here and exits 0.
    ExitCode::SUCCESS
}

/// Produce a multi-line summary of `cfg` that reads every publicly
/// exposed field of every struct defined in [`arguments`]. This is the
/// one behavior unique to this placeholder main; the real main.rs will
/// not need it.
fn summarize(cfg: &Config) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("cpucount={}", cfg.cpucount));
    lines.push(format!("runas={:?}", cfg.runas));
    lines.push(format!("runas_uid={:?}", cfg.runas_uid));
    lines.push(format!("runas_gid={:?}", cfg.runas_gid));
    lines.push(format!("funcmatch={}", cfg.funcmatch));
    lines.push(format!("background={}", cfg.background));
    for (idx, c) in cfg.configs.iter().enumerate() {
        lines.push(format!(
            "config[{}]: bind_addr={} is_tls={} pem_path={:?} logs_path={:?} \
             errorlog_path={:?} errorlog_syslog={} backpath={:?} vhost={:?} \
             global_sandbox={:?} cache_control={:?} file_stat_time={:?} \
             index_files={} redirects={} fastcgi_map={} host_sandbox={}",
            idx,
            c.bind_addr,
            c.is_tls,
            c.pem_path,
            c.logs_path,
            c.errorlog_path,
            c.errorlog_syslog,
            c.backpath,
            c.vhost,
            c.global_sandbox,
            c.cache_control,
            c.file_stat_time,
            c.index_files.len(),
            c.redirects.len(),
            c.fastcgi_map.len(),
            c.host_sandbox.len(),
        ));
        for m in &c.fastcgi_map {
            lines.push(format!(
                "  fastcgi: endswith={} address={}",
                m.endswith, m.address
            ));
        }
        for h in &c.host_sandbox {
            lines.push(format!("  hostsandbox: host={} dir={}", h.host, h.dir.display()));
        }
        for r in &c.redirects {
            lines.push(format!("  redirect: from={} to={}", r.from, r.to));
        }
        for s in &c.index_files {
            lines.push(format!("  indexfile: {s}"));
        }
    }
    lines.join("\n")
}
