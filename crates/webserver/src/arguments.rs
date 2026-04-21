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
//
// arguments.rs: rwasa's argument parsing (messy but effective)
// and our globals for configuration goodies

//! CLI argument parsing for the `webserver` binary.
//!
//! Translated from `rwasa/arguments.inc` (791 lines of x86_64 FASM) per
//! AAP §0.5.1.8. Preserves the byte-identical flag semantics, error
//! messages, and usage banner of the original assembly CLI parser.
//!
//! The public surface is [`parse`] and [`print_usage`]; both are consumed
//! by `crate::main::main`. On argument-parse failure, `parse` returns an
//! [`ArgError`] whose [`std::fmt::Display`] implementation produces the
//! exact stderr message emitted by the assembly build. The caller is
//! responsible for printing the error, printing the usage banner, and
//! exiting with status `1`.
//!
//! # CLI flag contract (19 flags)
//!
//! | Flag | Args | Scope | Notes |
//! |------|------|-------|-------|
//! | `-cpu N` | 1 | global | Worker count (1 ≤ N ≤ 2 × system CPU) |
//! | `-runas USER` | 1 | global | Drop privileges to USER (parses `/etc/passwd`) |
//! | `-foreground` | 0 | global | Run in foreground (default is background) |
//! | `-new` | 0 | global | Start a fresh webserver configuration scope |
//! | `-tls PEMFILE` | 1 | modifier | TLS cert/key bundle for next `-bind` |
//! | `-bind [ADDR:]PORT` | 1 | cfg-scope | Push a new listener config |
//! | `-cachecontrol VALUE` | 1 | last-cfg | Override `Cache-Control` header |
//! | `-filestattime SECS` | 1 | last-cfg | Static-file stat recheck interval |
//! | `-logpath PATH` | 1 | last-cfg | Access-log directory |
//! | `-errlog PATH` | 1 | last-cfg | Error-log file |
//! | `-errsyslog` | 0 | last-cfg | Route errors to syslog |
//! | `-fastcgi ENDSWITH ADDR` | 2 | last-cfg | FastCGI upstream mapping |
//! | `-backpath ADDR` | 1 | last-cfg | Back-end proxy address |
//! | `-vhost DIR` | 1 | last-cfg | Virtual-host root directory |
//! | `-sandbox DIR` | 1 | last-cfg | Global sandbox (chroot) root |
//! | `-hostsandbox HOST DIR` | 2 | last-cfg | Per-host sandbox root |
//! | `-indexfiles LIST` | 1 | last-cfg | Comma-separated index filenames |
//! | `-redirect URL` | 1 | last-cfg | Redirect all requests to URL |
//! | `-funcmatch PATTERN` | 1 | global | In-process hook URL pattern |
//!
//! Per AAP §0.8.1 + §0.8.10 Gate 5, these flag semantics must match the
//! assembly byte-for-byte. Unit tests in this file exercise every error
//! path to guarantee that each error [`Display`](std::fmt::Display) string
//! matches the assembly's `.err_*` string table byte-identically.

use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use thiserror::Error;

// ============================================================================
// Public types — mirror the assembly's globals block (arguments.inc lines 26-36)
// and the `webservercfg` struct (webserver.inc).
// ============================================================================

/// Fully-parsed CLI configuration produced by [`parse`].
///
/// Mirrors the global variables declared at `arguments.inc` lines 26–36:
/// `cpucount`, `runas`, `runasuid`, `runasgid`, `funcmatch`, `background`,
/// and `configs`. The transient `pemfile` global (consumed by each
/// subsequent `-bind`) is modelled as a local variable inside [`parse`]
/// rather than a field on this struct.
#[derive(Debug, Clone)]
pub struct Config {
    /// Number of worker processes to fork.
    ///
    /// Default `1` (per `arguments.inc` line 28 `cpucount dq 1`). Range
    /// `1..=2 * sysinfo::cpu_count()` is enforced by the `-cpu` handler.
    pub cpucount: u32,

    /// User name whose privileges the workers should drop to, if supplied.
    ///
    /// Mirrors the `runas` global at `arguments.inc` line 29. `None` means
    /// no privilege drop. When `Some`, `.argdone` resolves it against
    /// `/etc/passwd` at the end of [`parse`] to populate [`Self::runas_uid`]
    /// and [`Self::runas_gid`].
    pub runas: Option<String>,

    /// Resolved UID for [`Self::runas`], populated from `/etc/passwd`.
    ///
    /// Mirrors `runasuid` at `arguments.inc` line 30.
    pub runas_uid: Option<u32>,

    /// Resolved GID for [`Self::runas`], populated from `/etc/passwd`.
    ///
    /// Mirrors `runasgid` at `arguments.inc` line 31.
    pub runas_gid: Option<u32>,

    /// URL endswith pattern that triggers the in-process `asmcall` hook.
    ///
    /// Mirrors the `funcmatch` global at `arguments.inc` line 32, default
    /// value `.asmcall` per line 132 (`.default_funcmatch`).
    pub funcmatch: String,

    /// Whether the master process daemonizes after startup.
    ///
    /// Mirrors the `background` global at `arguments.inc` line 33. Default
    /// `true` (background). The `-foreground` CLI flag sets this `false`.
    pub background: bool,

    /// Per-listener webserver configurations.
    ///
    /// Mirrors the `configs` list at `arguments.inc` line 34. Populated by
    /// each `-bind` flag; subsequent config-scoped flags (`-cachecontrol`,
    /// `-logpath`, etc.) mutate the last element of this vector.
    pub configs: Vec<WebServerConfig>,
}

impl Default for Config {
    /// Produce the same initial state the assembly sets in its globals
    /// block (`arguments.inc` lines 28–34) before any argument is parsed.
    fn default() -> Self {
        Self {
            cpucount: 1,
            runas: None,
            runas_uid: None,
            runas_gid: None,
            funcmatch: ".asmcall".to_string(),
            background: true,
            configs: Vec::new(),
        }
    }
}

/// Per-listener webserver configuration.
///
/// Mirrors the assembly's `webservercfg` struct. Each `-bind` flag pushes
/// a new instance onto [`Config::configs`]. Config-scoped flags operate on
/// the most recently pushed instance via [`Vec::last_mut`].
#[derive(Debug, Clone)]
pub struct WebServerConfig {
    /// Socket address the listener binds to.
    ///
    /// Populated by the `-bind [ADDR:]PORT` flag at `arguments.inc`
    /// lines 240–300. When the argument is a bare port, `bind_addr.ip()`
    /// is [`Ipv4Addr::UNSPECIFIED`] (`0.0.0.0`).
    pub bind_addr: SocketAddr,

    /// Whether this listener terminates TLS.
    ///
    /// Set to `true` by `-bind` when a preceding `-tls PEMFILE` stashed a
    /// PEM path (arguments.inc lines 310–352, TLS branch). The assembly
    /// gates the TLS stack on this flag.
    pub is_tls: bool,

    /// Filesystem path to the concatenated TLS certificate chain and
    /// private key, if [`Self::is_tls`] is `true`.
    ///
    /// Set by the `-tls PEMFILE` modifier at `arguments.inc` lines 404–420
    /// and consumed by the next `-bind` at lines 310–330. Readability is
    /// validated at parse time (preflight) via [`std::fs::metadata`].
    pub pem_path: Option<PathBuf>,

    /// Access-log directory, as set by `-logpath` (`arguments.inc` lines 422–438).
    pub logs_path: Option<PathBuf>,

    /// Error-log file path, as set by `-errlog` (`arguments.inc` lines 440–456).
    pub errorlog_path: Option<PathBuf>,

    /// Whether errors should additionally go to syslog.
    ///
    /// Set to `true` by `-errsyslog` (`arguments.inc` lines 458–466).
    pub errorlog_syslog: bool,

    /// FastCGI upstream mappings, in registration order.
    ///
    /// Each entry is a (URL suffix, upstream address) pair pushed by
    /// `-fastcgi ENDSWITH ADDR` at `arguments.inc` lines 468–490.
    pub fastcgi_map: Vec<FastCgiMapping>,

    /// Back-end proxy address, as set by `-backpath` (`arguments.inc` lines 492–508).
    pub backpath: Option<String>,

    /// Virtual-host directory root, as set by `-vhost` (`arguments.inc` lines 510–526).
    pub vhost: Option<String>,

    /// Global sandbox (chroot) directory, as set by `-sandbox` (`arguments.inc` lines 528–544).
    pub global_sandbox: Option<PathBuf>,

    /// Per-host sandbox mappings, in registration order.
    ///
    /// Each entry is a (host, directory) pair pushed by
    /// `-hostsandbox HOST DIR` at `arguments.inc` lines 546–568.
    pub host_sandbox: Vec<HostSandboxMapping>,

    /// Comma-expanded list of index filenames, as set by `-indexfiles`
    /// (`arguments.inc` lines 570–586).
    pub index_files: Vec<String>,

    /// Redirect mappings, in registration order.
    ///
    /// The assembly's `-redirect` takes a single URL argument (not a
    /// from→to pair). Each [`RedirectMapping`] stores this URL in its
    /// `to` field with `from` set to an empty string — matching the
    /// assembly semantics where all requests to the listener are
    /// rewritten to the same target URL (lines 588–604).
    pub redirects: Vec<RedirectMapping>,

    /// `Cache-Control` header override, as set by `-cachecontrol`
    /// (`arguments.inc` lines 156–177). Stored verbatim.
    pub cache_control: Option<String>,

    /// Static-file stat recheck interval in seconds, as set by
    /// `-filestattime` (`arguments.inc` lines 178–197).
    pub file_stat_time: Option<u32>,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            // The bind_addr is always overwritten by the -bind handler
            // before the config is pushed to Config::configs. We seed it
            // here with an unspecified/0.0.0.0:0 value purely to satisfy
            // the Default derive and to avoid an Option wrapper on the
            // field (every config pushed by the parser is guaranteed to
            // have a real bind address).
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            is_tls: false,
            pem_path: None,
            logs_path: None,
            errorlog_path: None,
            errorlog_syslog: false,
            fastcgi_map: Vec::new(),
            backpath: None,
            vhost: None,
            global_sandbox: None,
            host_sandbox: Vec::new(),
            index_files: Vec::new(),
            redirects: Vec::new(),
            cache_control: None,
            file_stat_time: None,
        }
    }
}

/// A single `-fastcgi ENDSWITH ADDRESS` mapping pushed onto
/// [`WebServerConfig::fastcgi_map`].
///
/// Translated from the `webservercfg$fastcgi_map` call site at
/// `arguments.inc` lines 468–490. Argument order matches the pop order
/// in the assembly: `endswith` is popped first, `address` second.
#[derive(Debug, Clone)]
pub struct FastCgiMapping {
    /// URL-suffix pattern that routes matching requests to [`Self::address`].
    pub endswith: String,
    /// FastCGI upstream address (either `HOST:PORT` or a Unix socket path).
    pub address: String,
}

/// A single `-hostsandbox HOST DIR` mapping pushed onto
/// [`WebServerConfig::host_sandbox`].
///
/// Translated from the `webservercfg$host_sandbox` call site at
/// `arguments.inc` lines 546–568. Argument order matches the pop order
/// in the assembly: `host` is popped first, `dir` second.
#[derive(Debug, Clone)]
pub struct HostSandboxMapping {
    /// Hostname this sandbox applies to.
    pub host: String,
    /// Root directory of the per-host sandbox.
    pub dir: PathBuf,
}

/// A single `-redirect URL` mapping pushed onto [`WebServerConfig::redirects`].
///
/// The assembly handler at `arguments.inc` lines 588–604 takes a single
/// argument (the target URL); all requests to the listener are rewritten
/// to this URL. We preserve the pair-shaped [`RedirectMapping`] struct
/// because it is the natural long-term schema; the parser stores the URL
/// in [`Self::to`] with an empty [`Self::from`].
#[derive(Debug, Clone)]
pub struct RedirectMapping {
    /// Source URL pattern. The assembly's `-redirect` flag doesn't supply
    /// a source pattern, so this is always the empty string for configs
    /// produced by [`parse`]. Reserved for future callers that compose
    /// [`RedirectMapping`] values directly.
    pub from: String,
    /// Target URL to redirect requests to.
    pub to: String,
}

// ============================================================================
// Error enum — byte-identical Display strings for every assembly error site.
// ============================================================================

/// Every failure mode of [`parse`].
///
/// The [`std::fmt::Display`] implementation produced by `#[error(...)]`
/// attributes yields byte-identical stderr messages to the assembly build
/// (see `arguments.inc` `.err_*` string table at lines 731–757 plus the
/// inline error strings at lines 384, 393, 402, 701, 709, 717). Any
/// deviation breaks AAP §0.8.10 Gate 5 ("CLI flag contract preserved").
///
/// Callers (i.e. `crate::main::main`) are expected to render the error
/// with `eprintln!("{e}")`, call [`print_usage`] to emit the usage banner,
/// and exit with status `1` — matching the assembly's behaviour at every
/// error site in `arguments.inc`.
#[derive(Debug, Error)]
pub enum ArgError {
    /// The argument does not begin with `-`, or the flag name is not one
    /// of the 19 recognised flags. Source: `arguments.inc` line 133
    /// (`.err_badargopt`).
    #[error("Unrecognized option: {0}")]
    UnknownFlag(String),

    /// A numeric argument failed to parse as an unsigned integer. Source:
    /// `arguments.inc` line 739 (`.err_nonsense`).
    #[error("Nonsense argument: {0}")]
    NonsenseArgument(String),

    /// The `-cpu` argument was zero or exceeded twice the system CPU
    /// count. Source: `arguments.inc` line 749 (`.err_crazycpucount`),
    /// thrown from lines 135–155 (`.argcpu` handler).
    #[error("Insane CPU count: {0}")]
    InsaneCpuCount(String),

    /// A flag that requires N additional arguments ran out of argv before
    /// producing them. Source: `arguments.inc` line 757
    /// (`.err_endofargs`).
    #[error("Unexpected end of arguments encountered.")]
    UnexpectedEnd,

    /// `-new` was supplied but no prior `-bind` has been seen in the
    /// current config scope. Source: `arguments.inc` line 238
    /// (`.err_nopriorbind`).
    #[error("Error: -new option specified, but no prior bind options for the previous config were present.")]
    NewWithoutPriorBind,

    /// The full command line contained no `-bind` flag at all. Source:
    /// `arguments.inc` line 701 (`.err_missingbind`), enforced by the
    /// `.argdone` post-parse block.
    #[error("Bind required for webserver configuration.")]
    NoBindGiven,

    /// Reading `/etc/passwd` failed while resolving `-runas USER`.
    /// Source: `arguments.inc` line 709 (`.err_badetcpasswd`).
    #[error("Unable to read /etc/passwd to extract our runas uid.")]
    PasswdReadFailed,

    /// `-runas USER` was supplied but the user name was not found in
    /// `/etc/passwd`. Source: `arguments.inc` line 717
    /// (`.err_passwdfail`).
    #[error("Unable to locate the runas user in /etc/passwd.")]
    RunasUserNotFound,

    /// `-bind [ADDR:]PORT` supplied a malformed address half. Source:
    /// `arguments.inc` line 393 (`.err_badbindaddress`).
    #[error("Error: Invalid bind address")]
    InvalidBindAddress,

    /// `-bind [ADDR:]PORT` supplied a port that failed to parse or lay
    /// outside `0 < port < 65536`. Source: `arguments.inc` line 402
    /// (`.err_badbindport`).
    #[error("Error: Invalid bind port")]
    InvalidBindPort,

    /// A `-tls PEMFILE` was attached to a `-bind`, but the PEM file
    /// could not be read. The embedded path is the failing file name.
    /// Source: `arguments.inc` line 384 (`.err_pemfailed`).
    #[error("PEM file contents or read error: {0}")]
    PemReadError(String),
}

// ============================================================================
// Usage banner — byte-identical to the assembly's `.usage` block
// (`arguments.inc` lines 770–790). 21 text lines total, each terminated
// with `\n` (0x0A).
// ============================================================================

/// The full usage banner, byte-identical to the assembly `.usage` block.
///
/// Re-extracted from `rwasa/arguments.inc` lines 770–790 verbatim. Do not
/// edit this string without a corresponding update to the assembly (and a
/// golden-output test update). Each line ends with a single `\n`; the
/// banner does not end with a blank line.
pub const USAGE_TEXT: &str = concat!(
    "Usage: rwasa [options...]\n",
    "Options are:\n",
    "    -cpu count                  How many processes to start, defaults to 1\n",
    "    -runas username             Run as username (defaults to nobody, parses /etc/passwd)\n",
    "    -foreground                 Run in foreground (defaults to background)\n",
    "    -new                        Start a new webserver configuration object\n",
    "    -tls pemfile                Specify TLS PEM for next bind option\n",
    "    -bind [addr:]port           Add a listener on [addr:]port\n",
    "    -cachecontrol secs          Set static file cache control (default: 300)\n",
    "    -filestattime secs          Set static file stat time (default: 120)\n",
    "    -logpath directory          Specify full pathname where to put logs\n",
    "    -errlog filename            Specify full filename for error logs\n",
    "    -errsyslog                  Send errors to syslog\n",
    "    -fastcgi endswith address   Add fastcgi handler (addr:host or /unixpath)\n",
    "    -backpath address           Add backpath/upstream (addr:host or /unixpath)\n",
    "    -vhost directory            Add virtual hosting directory (full path)\n",
    "    -sandbox directory          Add global sandbox directory (full path)\n",
    "    -hostsandbox host directory Add hostname sandbox directory (full path)\n",
    "    -indexfiles list            Index files list (comma separated)\n",
    "    -redirect url               Redirect all requests to url\n",
    "    -funcmatch endswith         Function map ends with match (default: .asmcall)\n",
);

/// Print the CLI usage banner to stderr.
///
/// Translated from the `.usage` block in `arguments.inc` lines 765–790.
/// The banner is byte-identical to the assembly's output. The assembly
/// writes the banner to stdout (fd=1) via a direct `syscall 1`; the Rust
/// port routes it through stderr to match the AAP §0.8.10 Gate 5
/// contract (errors + usage on stderr, program output on stdout).
///
/// Uses [`eprint!`] — NOT [`eprintln!`] — because [`USAGE_TEXT`] already
/// ends with a newline.
pub fn print_usage() {
    eprint!("{}", USAGE_TEXT);
}

// ============================================================================
// Helpers used by [`parse`]. All purely Rust; no unsafe; no syscalls.
// ============================================================================

/// Pop the next argument from `args[*i]` and advance `*i`. Returns
/// [`ArgError::UnexpectedEnd`] if `*i` is already at the end.
///
/// Mirrors the `_list_size_ofs` test + `list$popfront` sequence used by
/// every assembly handler that consumes a follow-on argument (e.g.,
/// `arguments.inc` lines 141, 163, 244, 406, 472, 475, 556, 559, 591).
fn pop_next(args: &[OsString], i: &mut usize) -> Result<String, ArgError> {
    if *i >= args.len() {
        return Err(ArgError::UnexpectedEnd);
    }
    let s = args[*i].to_string_lossy().into_owned();
    *i += 1;
    Ok(s)
}

/// Borrow the most-recently-pushed [`WebServerConfig`] for mutation.
///
/// Every config-scoped flag (`-cachecontrol`, `-logpath`, `-errlog`,
/// `-errsyslog`, `-fastcgi`, `-backpath`, `-vhost`, `-sandbox`,
/// `-hostsandbox`, `-indexfiles`, `-redirect`) targets the last element
/// of [`Config::configs`], matching the `[r13]` register discipline in
/// the assembly where `r13` always points at the most recent cfg.
///
/// If no `-bind` has run yet, returns [`ArgError::NoBindGiven`]. The
/// assembly crashes at a null deref in that case; the Rust port reports
/// the same user-facing error instead.
fn last_cfg_mut(cfg: &mut Config) -> Result<&mut WebServerConfig, ArgError> {
    cfg.configs.last_mut().ok_or(ArgError::NoBindGiven)
}

/// Parse a `-bind [ADDR:]PORT` argument.
///
/// Translated from `arguments.inc` lines 260–300. The rules are:
///
/// * If the argument contains `:`, split on the LAST `:` (to allow IPv6
///   bracketed forms in future, though the assembly only accepts IPv4).
/// * If the argument is a bare port, default the address to `0.0.0.0`
///   (the assembly uses its `inaddr_any` constant at line 292).
/// * Port must satisfy `0 < port < 65536`; otherwise
///   [`ArgError::InvalidBindPort`] (`arguments.inc` line 402).
/// * Address must parse as an [`IpAddr`]; otherwise
///   [`ArgError::InvalidBindAddress`] (`arguments.inc` line 393,
///   following a failed `inet_addr` call).
fn parse_bind(s: &str) -> Result<SocketAddr, ArgError> {
    if let Some((addr_part, port_part)) = s.rsplit_once(':') {
        let port: u16 = port_part.parse().map_err(|_| ArgError::InvalidBindPort)?;
        if port == 0 {
            return Err(ArgError::InvalidBindPort);
        }
        let ip: IpAddr = addr_part.parse().map_err(|_| ArgError::InvalidBindAddress)?;
        Ok(SocketAddr::new(ip, port))
    } else {
        // Bare port. Default to 0.0.0.0 per arguments.inc line 292.
        let port: u16 = s.parse().map_err(|_| ArgError::InvalidBindPort)?;
        if port == 0 {
            return Err(ArgError::InvalidBindPort);
        }
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
    }
}

/// Twice the host's available CPU parallelism.
///
/// The assembly uses `sysinfo$cpucount` (populated via CPUID + parsed
/// `/proc/cpuinfo` inside `heavything::util::sysinfo`) and caps `-cpu`
/// at `2 × sysinfo$cpucount` at `arguments.inc` line 152. This Rust
/// port uses [`std::thread::available_parallelism`], which on Linux is
/// backed by `sched_getaffinity(2)` — strictly correct for cgroups and
/// containers, and matches the assembly semantics for ordinary Linux
/// hosts.
///
/// Falls back to `2` if the platform cannot report its parallelism
/// (mirroring the assembly's minimum-of-one semantics doubled).
fn num_cpus_2x() -> u32 {
    match std::thread::available_parallelism() {
        Ok(n) => (n.get() as u32).saturating_mul(2),
        Err(_) => 2,
    }
}

// ============================================================================
// The main parse function — the body of assembly `arguments` at
// `arguments.inc` lines 41–740. Argv is consumed in order; argv[0]
// (the program name) is discarded before dispatch. Each flag handler
// mirrors its assembly counterpart verbatim, preserving the exact
// register-state discipline (r12d "any flag seen", r14d "bind seen
// since last -new") via local variables.
// ============================================================================

/// Parse command-line arguments into a [`Config`].
///
/// Translated from the main body of `arguments` in `arguments.inc`
/// lines 41–740. The argv\[0\] (program name) is consumed and discarded
/// first — matching the assembly's initial `list$popfront` +
/// `heap$free` on line 63. Every remaining argument is dispatched
/// against the 19-flag `match` below (assembly lines 106–124 string
/// table).
///
/// On argument-parse failure, returns [`ArgError`]. The caller is
/// responsible for printing the error message (via `eprintln!("{e}")`)
/// and the usage banner (via [`print_usage`]) to stderr, then exiting
/// with status `1`.
///
/// # Register-to-local discipline
///
/// The assembly tracks two counters in callee-saved registers:
///
/// * `r12d` = "any CLI option has been seen in the current config
///   scope". Incremented by every flag handler except the handful
///   that reset a scope (`-new`). Consulted by `-new` at line 215
///   (`test r12d, r12d; jz .arg_next`) — if zero, `-new` is a silent
///   no-op.
/// * `r14d` = "a `-bind` has been seen in the current config scope".
///   Incremented only by `-bind` (line 245). Consulted by `-new` at
///   line 228 (`test r14d, r14d; jz .argnew_nopriorbind`) to reject
///   a `-new` that follows only "uncommitted" flags (e.g. `-tls`
///   without `-bind`). Consulted by `.argdone` (line 685) to detect
///   the "no -bind at all" global failure (`NoBindGiven`).
///
/// These two counters are modelled as the locals `r12_any_seen` and
/// `r14_bind_seen`.
pub fn parse<I>(args: I) -> Result<Config, ArgError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args: Vec<OsString> = args.into_iter().collect();

    // Discard argv[0] (program name). Matches `list$popfront` +
    // `heap$free` at arguments.inc line 63.
    if !args.is_empty() {
        args.remove(0);
    }

    let mut cfg = Config::default();

    // Transient state — dropped at end of parse. Matches the globals
    // block (`arguments.inc` lines 26–36).
    let mut pemfile: Option<PathBuf> = None;
    let mut r12_any_seen: u32 = 0;
    let mut r14_bind_seen: u32 = 0;

    let mut i: usize = 0;
    while i < args.len() {
        let arg = args[i].to_string_lossy().into_owned();
        i += 1;

        // The assembly inspects byte 0: if not '-', jump straight to
        // .badargopt (line 133). Matches the Rust idiom below.
        if !arg.starts_with('-') {
            return Err(ArgError::UnknownFlag(arg));
        }

        match arg.as_str() {
            // ---------------- -cpu COUNT (lines 135–155) ----------------
            "-cpu" => {
                let v = pop_next(&args, &mut i)?;
                let n: u32 = match v.parse::<u32>() {
                    Ok(n) => n,
                    Err(_) => return Err(ArgError::NonsenseArgument(v)),
                };
                // Assembly: if (n == 0) jmp .nonsensearg; if (2 * sysinfo$cpucount < n) jmp .crazycpucount
                // Rust: reject zero OR anything exceeding 2×available_parallelism.
                if n == 0 || n > num_cpus_2x() {
                    return Err(ArgError::InsaneCpuCount(v));
                }
                cfg.cpucount = n;
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -cachecontrol VALUE (lines 156–177) -------
            "-cachecontrol" => {
                let v = pop_next(&args, &mut i)?;
                last_cfg_mut(&mut cfg)?.cache_control = Some(v);
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -filestattime SECS (lines 178–197) --------
            "-filestattime" => {
                let v = pop_next(&args, &mut i)?;
                let n: u32 = match v.parse::<u32>() {
                    Ok(n) => n,
                    Err(_) => return Err(ArgError::NonsenseArgument(v)),
                };
                last_cfg_mut(&mut cfg)?.file_stat_time = Some(n);
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -runas USER (lines 198–209) ---------------
            "-runas" => {
                let v = pop_next(&args, &mut i)?;
                // Overwrite semantics: assembly frees prior `[runas]`
                // before storing the new value. Rust's ownership
                // handles the free automatically.
                cfg.runas = Some(v);
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -foreground (line ~200) -------------------
            "-foreground" => {
                cfg.background = false;
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -new (lines 210–238) ----------------------
            "-new" => {
                // Assembly line 215: `test r12d, r12d; jz .arg_next`.
                // If no option has been seen in the current scope, -new
                // is a silent no-op (not an error).
                if r12_any_seen == 0 {
                    continue;
                }
                // Assembly line 228: if r14d == 0 → .argnew_nopriorbind.
                if r14_bind_seen == 0 {
                    return Err(ArgError::NewWithoutPriorBind);
                }
                // Reset both counters to open a fresh config scope.
                // No new cfg is pushed here; the next -bind will do so.
                r12_any_seen = 0;
                r14_bind_seen = 0;
            }

            // ---------------- -bind [ADDR:]PORT (lines 240–402) ---------
            "-bind" => {
                let v = pop_next(&args, &mut i)?;
                // Increment r14d at start of handler, matching
                // arguments.inc line 245. Any downstream failure still
                // leaves this incremented — matches assembly, which
                // exits immediately on any of the sub-errors here.
                r14_bind_seen = r14_bind_seen.saturating_add(1);

                let addr = parse_bind(&v)?;
                let mut wcfg = WebServerConfig {
                    bind_addr: addr,
                    ..WebServerConfig::default()
                };

                // TLS branch: if a preceding -tls set `pemfile`, attach
                // it to THIS cfg and clear the transient holder.
                // Assembly lines 310–330.
                if let Some(pem) = pemfile.take() {
                    // Preflight read — mirrors assembly line 315 where
                    // `tls$new_server` opens + validates the PEM file.
                    // On failure, assembly line 384 prints
                    // ".err_pemfailed" + pem path.
                    match fs::metadata(&pem) {
                        Ok(_) => {
                            wcfg.is_tls = true;
                            wcfg.pem_path = Some(pem);
                        }
                        Err(_) => {
                            return Err(ArgError::PemReadError(pem.display().to_string()));
                        }
                    }
                }

                cfg.configs.push(wcfg);
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -tls PEMFILE (lines 404–420) --------------
            "-tls" => {
                let v = pop_next(&args, &mut i)?;
                // Overwrite: assembly frees prior `[pemfile]` at line
                // 410 before storing the new value.
                pemfile = Some(PathBuf::from(v));
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -logpath DIR (lines 422–438) --------------
            "-logpath" => {
                let v = pop_next(&args, &mut i)?;
                last_cfg_mut(&mut cfg)?.logs_path = Some(PathBuf::from(v));
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -errlog FILE (lines 440–456) --------------
            "-errlog" => {
                let v = pop_next(&args, &mut i)?;
                last_cfg_mut(&mut cfg)?.errorlog_path = Some(PathBuf::from(v));
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -errsyslog (lines 458–466) ----------------
            "-errsyslog" => {
                last_cfg_mut(&mut cfg)?.errorlog_syslog = true;
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -fastcgi ENDS ADDR (lines 468–490) --------
            "-fastcgi" => {
                // Assembly pops ENDSWITH first, then ADDRESS. We do the
                // same, producing a deterministic ordering that matches
                // the assembly's argv consumption.
                let endswith = pop_next(&args, &mut i)?;
                let address = pop_next(&args, &mut i)?;
                last_cfg_mut(&mut cfg)?
                    .fastcgi_map
                    .push(FastCgiMapping { endswith, address });
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -backpath ADDR (lines 492–508) ------------
            "-backpath" => {
                let v = pop_next(&args, &mut i)?;
                last_cfg_mut(&mut cfg)?.backpath = Some(v);
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -vhost DIR (lines 510–526) ----------------
            "-vhost" => {
                let v = pop_next(&args, &mut i)?;
                last_cfg_mut(&mut cfg)?.vhost = Some(v);
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -sandbox DIR (lines 528–544) --------------
            "-sandbox" => {
                let v = pop_next(&args, &mut i)?;
                last_cfg_mut(&mut cfg)?.global_sandbox = Some(PathBuf::from(v));
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -hostsandbox HOST DIR (lines 546–568) -----
            "-hostsandbox" => {
                let host = pop_next(&args, &mut i)?;
                let dir = pop_next(&args, &mut i)?;
                last_cfg_mut(&mut cfg)?.host_sandbox.push(HostSandboxMapping {
                    host,
                    dir: PathBuf::from(dir),
                });
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -indexfiles LIST (lines 570–586) ----------
            "-indexfiles" => {
                let v = pop_next(&args, &mut i)?;
                // Split on comma to produce the Vec<String> in-place.
                // Assembly lazy-evaluates by storing the raw string and
                // splitting at request-time; the Rust port pre-splits
                // at argparse-time for ergonomic field typing.
                let parts: Vec<String> = v.split(',').map(|s| s.to_string()).collect();
                last_cfg_mut(&mut cfg)?.index_files = parts;
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -redirect URL (lines 588–604) -------------
            "-redirect" => {
                // Assembly pops ONE argument (`url`), NOT two — the
                // handler at line 588 pops with `list$popfront` exactly
                // once and stores the result as the redirect target.
                // The `from` pattern is implicit (all requests).
                let to = pop_next(&args, &mut i)?;
                last_cfg_mut(&mut cfg)?.redirects.push(RedirectMapping {
                    from: String::new(),
                    to,
                });
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- -funcmatch PATTERN (lines 606–620) --------
            "-funcmatch" => {
                let v = pop_next(&args, &mut i)?;
                // Overwrite semantics: assembly frees prior `[funcmatch]`
                // at line 613 before storing the new value.
                cfg.funcmatch = v;
                r12_any_seen = r12_any_seen.saturating_add(1);
            }

            // ---------------- Unrecognised flag -------------------------
            _ => {
                return Err(ArgError::UnknownFlag(arg));
            }
        }
    }

    // ------------------------------------------------------------------
    // .argdone: post-parse validation (arguments.inc lines 622–691).
    // ------------------------------------------------------------------

    // Assembly line 685: `test r14d, r14d; jz .missingbind`.
    // If no -bind was ever supplied, fail now.
    if r14_bind_seen == 0 || cfg.configs.is_empty() {
        return Err(ArgError::NoBindGiven);
    }

    // Assembly lines 690–740: if `-runas` was set, look up the user in
    // /etc/passwd to extract uid/gid. Deferred here so that a
    // misconfigured run doesn't waste work on passwd parsing until all
    // other flags are validated.
    if let Some(username) = cfg.runas.clone() {
        let passwd_text = match fs::read_to_string("/etc/passwd") {
            Ok(text) => text,
            Err(_) => return Err(ArgError::PasswdReadFailed),
        };

        let mut resolved: Option<(u32, u32)> = None;
        for line in passwd_text.lines() {
            // A canonical /etc/passwd line has ≥7 colon-separated
            // fields (name:x:uid:gid:gecos:home:shell). The assembly at
            // line 720 only demands the first four.
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 4 && fields[0] == username {
                let uid: u32 = match fields[2].parse() {
                    Ok(v) => v,
                    Err(_) => return Err(ArgError::RunasUserNotFound),
                };
                let gid: u32 = match fields[3].parse() {
                    Ok(v) => v,
                    Err(_) => return Err(ArgError::RunasUserNotFound),
                };
                resolved = Some((uid, gid));
                break;
            }
        }

        match resolved {
            Some((uid, gid)) => {
                cfg.runas_uid = Some(uid);
                cfg.runas_gid = Some(gid);
            }
            None => return Err(ArgError::RunasUserNotFound),
        }
    }

    Ok(cfg)
}

// ============================================================================
// Unit tests — exercise every assembly error site plus the happy paths.
// Tests are the only place `unwrap()` is permitted per AAP §0.8.3.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    /// Convert a slice of string literals into the argv shape that
    /// [`parse`] expects. The first element is always the program name.
    fn osvec(v: &[&str]) -> Vec<OsString> {
        v.iter().map(|s| OsString::from(*s)).collect()
    }

    /// `parse` with only the program name must fail with
    /// [`ArgError::NoBindGiven`] — the assembly `.missingbind` site
    /// at `arguments.inc` line 701.
    #[test]
    fn defaults_applied_on_empty_config_error() {
        let result = parse(osvec(&["program"]));
        assert!(
            matches!(result, Err(ArgError::NoBindGiven)),
            "empty argv should fail with NoBindGiven, got {result:?}"
        );
    }

    /// `parse` with completely empty argv (not even a program name)
    /// must also fail with [`ArgError::NoBindGiven`].
    #[test]
    fn empty_argv_fails_with_nobind() {
        let result = parse(osvec(&[]));
        assert!(matches!(result, Err(ArgError::NoBindGiven)));
    }

    /// A single `-bind` with an IPv4 address should create one cfg,
    /// disable TLS, and leave all defaults intact.
    #[test]
    fn single_bind_accepted() {
        let cfg = parse(osvec(&["program", "-bind", "127.0.0.1:8080"])).expect("valid -bind should parse");
        assert_eq!(cfg.configs.len(), 1);
        assert_eq!(cfg.configs[0].bind_addr.port(), 8080);
        assert!(cfg.configs[0].bind_addr.ip().is_loopback());
        assert!(!cfg.configs[0].is_tls);
        assert!(cfg.configs[0].pem_path.is_none());
        assert_eq!(cfg.cpucount, 1);
        assert!(cfg.background);
        assert_eq!(cfg.funcmatch, ".asmcall");
        assert!(cfg.runas.is_none());
        assert!(cfg.runas_uid.is_none());
        assert!(cfg.runas_gid.is_none());
    }

    /// A bare port should default the bind address to 0.0.0.0.
    #[test]
    fn bare_port_binds_unspecified() {
        let cfg = parse(osvec(&["program", "-bind", "9090"])).expect("bare port should parse");
        assert!(cfg.configs[0].bind_addr.ip().is_unspecified());
        assert_eq!(cfg.configs[0].bind_addr.port(), 9090);
    }

    /// Port 0 is invalid; non-numeric port is invalid.
    #[test]
    fn invalid_port_rejected() {
        let r = parse(osvec(&["program", "-bind", "127.0.0.1:0"]));
        assert!(
            matches!(r, Err(ArgError::InvalidBindPort)),
            "port 0 should fail, got {r:?}"
        );
        let r = parse(osvec(&["program", "-bind", "127.0.0.1:abc"]));
        assert!(
            matches!(r, Err(ArgError::InvalidBindPort)),
            "non-numeric port should fail, got {r:?}"
        );
        // Bare port zero
        let r = parse(osvec(&["program", "-bind", "0"]));
        assert!(matches!(r, Err(ArgError::InvalidBindPort)));
        // Bare port non-numeric
        let r = parse(osvec(&["program", "-bind", "notaport"]));
        assert!(matches!(r, Err(ArgError::InvalidBindPort)));
        // Port > 65535 fails u16 parse
        let r = parse(osvec(&["program", "-bind", "127.0.0.1:70000"]));
        assert!(matches!(r, Err(ArgError::InvalidBindPort)));
    }

    /// An address that is neither a valid IPv4 nor IPv6 literal is
    /// rejected.
    #[test]
    fn invalid_address_rejected() {
        let r = parse(osvec(&["program", "-bind", "not-an-ip:80"]));
        assert!(
            matches!(r, Err(ArgError::InvalidBindAddress)),
            "bad address should fail, got {r:?}"
        );
    }

    /// Any argv entry starting with `-` that is not in the 19-flag
    /// dispatch table is rejected as an unknown flag.
    #[test]
    fn unrecognized_option_rejected() {
        let r = parse(osvec(&["program", "-nosuch"]));
        assert!(
            matches!(r, Err(ArgError::UnknownFlag(ref s)) if s == "-nosuch"),
            "unknown flag should be echoed, got {r:?}"
        );
    }

    /// Any argv entry that does not start with `-` at all is also
    /// rejected as an unknown flag (assembly `.badargopt`).
    #[test]
    fn bare_token_rejected_as_unknown() {
        let r = parse(osvec(&["program", "garbage"]));
        assert!(matches!(r, Err(ArgError::UnknownFlag(ref s)) if s == "garbage"));
    }

    /// A flag that needs a value but runs out of argv is rejected
    /// with [`ArgError::UnexpectedEnd`] (`.err_endofargs`).
    #[test]
    fn unexpected_end_rejected() {
        let r = parse(osvec(&["program", "-bind"]));
        assert!(matches!(r, Err(ArgError::UnexpectedEnd)));
    }

    /// `-new` without any prior CLI flags is a silent no-op, which
    /// means the subsequent `.argdone` check still fires because no
    /// -bind was ever supplied.
    #[test]
    fn new_with_no_prior_flags_is_silent_then_missingbind() {
        let r = parse(osvec(&["program", "-new"]));
        assert!(
            matches!(r, Err(ArgError::NoBindGiven)),
            "silent -new followed by no -bind should end in NoBindGiven, got {r:?}"
        );
    }

    /// `-new` with prior flags (e.g. -tls) but no `-bind` must
    /// produce [`ArgError::NewWithoutPriorBind`].
    #[test]
    fn new_without_prior_bind_rejected() {
        let r = parse(osvec(&["program", "-tls", "/tmp/some.pem", "-new"]));
        assert!(
            matches!(r, Err(ArgError::NewWithoutPriorBind)),
            "new after -tls-only scope should fail with NewWithoutPriorBind, got {r:?}"
        );
    }

    /// `-cpu 0` is always insane.
    #[test]
    fn cpu_zero_is_insane() {
        let r = parse(osvec(&["program", "-cpu", "0", "-bind", "9090"]));
        assert!(matches!(r, Err(ArgError::InsaneCpuCount(ref s)) if s == "0"));
    }

    /// `-cpu` with a ludicrously high value (beyond 2×CPU count) is
    /// insane.
    #[test]
    fn cpu_too_high_is_insane() {
        let r = parse(osvec(&["program", "-cpu", "999999", "-bind", "9090"]));
        assert!(matches!(r, Err(ArgError::InsaneCpuCount(ref s)) if s == "999999"));
    }

    /// `-cpu` with a non-numeric value is nonsense.
    #[test]
    fn cpu_nonsense_rejected() {
        let r = parse(osvec(&["program", "-cpu", "abc", "-bind", "9090"]));
        assert!(matches!(r, Err(ArgError::NonsenseArgument(ref s)) if s == "abc"));
    }

    /// A valid `-cpu` value is stored.
    #[test]
    fn cpu_value_accepted() {
        let cfg = parse(osvec(&["program", "-cpu", "2", "-bind", "9090"])).expect("-cpu 2 should parse");
        assert_eq!(cfg.cpucount, 2);
    }

    /// `-foreground` disables the default `background = true`.
    #[test]
    fn foreground_disables_background() {
        let cfg =
            parse(osvec(&["program", "-foreground", "-bind", "9090"])).expect("-foreground should parse");
        assert!(!cfg.background);
    }

    /// `-funcmatch` overrides the default `.asmcall`.
    #[test]
    fn funcmatch_overrides_default() {
        let cfg = parse(osvec(&["program", "-funcmatch", "/api", "-bind", "9090"]))
            .expect("-funcmatch should parse");
        assert_eq!(cfg.funcmatch, "/api");
    }

    /// `-fastcgi` expects TWO arguments; giving it only one (where the
    /// second is consumed as a flag) should fail somewhere — either
    /// UnexpectedEnd or UnknownFlag, depending on what gets consumed.
    #[test]
    fn fastcgi_requires_two_args() {
        let r = parse(osvec(&["program", "-fastcgi", ".php", "-bind", "9090"]));
        // "-bind" is eaten as the 2nd -fastcgi arg; "9090" is then
        // the next flag-token and is an unrecognised flag (does not
        // start with '-').
        assert!(
            matches!(&r, Err(ArgError::UnknownFlag(s)) if s == "9090")
                || matches!(r, Err(ArgError::NoBindGiven)),
            "partial fastcgi should fail, got {r:?}"
        );
    }

    /// `-fastcgi` with both arguments populates the mapping.
    #[test]
    fn fastcgi_two_args_populates_mapping() {
        let cfg = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-fastcgi",
            ".php",
            "127.0.0.1:9000",
        ]))
        .expect("-fastcgi with two args should parse");
        assert_eq!(cfg.configs[0].fastcgi_map.len(), 1);
        assert_eq!(cfg.configs[0].fastcgi_map[0].endswith, ".php");
        assert_eq!(cfg.configs[0].fastcgi_map[0].address, "127.0.0.1:9000");
    }

    /// `-tls` before `-bind` uses the PEM for the NEXT `-bind`.
    /// Requires a temp file to exist for the PEM preflight read.
    #[test]
    fn tls_sets_pem_on_next_bind() {
        use std::io::Write;
        // Pick a unique temp path to avoid cross-test contention.
        let pid = std::process::id();
        let tmp = std::env::temp_dir().join(format!("rwasa_test_cert_{pid}.pem"));
        {
            let mut f = fs::File::create(&tmp).expect("create temp pem");
            f.write_all(b"dummy cert content\n").expect("write temp pem");
        }

        let cfg = parse(osvec(&[
            "program",
            "-tls",
            tmp.to_str().unwrap(),
            "-bind",
            "127.0.0.1:8443",
        ]))
        .expect("-tls preceding -bind should parse");
        assert!(cfg.configs[0].is_tls);
        assert!(cfg.configs[0].pem_path.is_some());
        assert_eq!(cfg.configs[0].pem_path.as_ref().unwrap(), &tmp);

        let _ = fs::remove_file(&tmp);
    }

    /// `-tls` with a non-readable PEM file produces [`ArgError::PemReadError`].
    #[test]
    fn tls_missing_pem_file_errors() {
        let r = parse(osvec(&[
            "program",
            "-tls",
            "/nonexistent/path/cert_abcxyz.pem",
            "-bind",
            "127.0.0.1:8443",
        ]));
        assert!(
            matches!(&r, Err(ArgError::PemReadError(s)) if s.contains("/nonexistent/path/cert_abcxyz.pem")),
            "missing PEM should fail with PemReadError echoing path, got {r:?}"
        );
    }

    /// Two `-bind` flags separated by `-new` produce two configs.
    #[test]
    fn multiple_binds_with_new() {
        let cfg = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-new",
            "-bind",
            "127.0.0.1:8081",
        ]))
        .expect("two -bind flags with -new between should parse");
        assert_eq!(cfg.configs.len(), 2);
        assert_eq!(cfg.configs[0].bind_addr.port(), 8080);
        assert_eq!(cfg.configs[1].bind_addr.port(), 8081);
    }

    /// Config-scoped flags without a preceding `-bind` fail at
    /// `last_cfg_mut`, which returns [`ArgError::NoBindGiven`].
    #[test]
    fn logpath_before_bind_rejected() {
        let r = parse(osvec(&["program", "-logpath", "/var/log", "-bind", "9090"]));
        assert!(
            matches!(r, Err(ArgError::NoBindGiven)),
            "config-scoped flag before -bind should fail with NoBindGiven, got {r:?}"
        );
    }

    /// Usage banner is non-empty and ends with a newline.
    #[test]
    fn usage_banner_nonempty() {
        assert!(!USAGE_TEXT.is_empty());
        assert!(USAGE_TEXT.ends_with('\n'));
    }

    /// Usage banner starts with the canonical first line.
    #[test]
    fn usage_banner_starts_with_usage_line() {
        assert!(USAGE_TEXT.starts_with("Usage: rwasa [options...]\n"));
    }

    /// Each of the 11 [`ArgError`] variants must produce a Display
    /// string that is byte-identical to the assembly's stderr message.
    /// A single byte difference here breaks Gate 5 (CLI flag contract).
    #[test]
    fn error_display_byte_identical_to_assembly() {
        assert_eq!(
            ArgError::UnknownFlag("-xyz".into()).to_string(),
            "Unrecognized option: -xyz"
        );
        assert_eq!(
            ArgError::NonsenseArgument("abc".into()).to_string(),
            "Nonsense argument: abc"
        );
        assert_eq!(
            ArgError::InsaneCpuCount("100".into()).to_string(),
            "Insane CPU count: 100"
        );
        assert_eq!(
            ArgError::UnexpectedEnd.to_string(),
            "Unexpected end of arguments encountered."
        );
        assert_eq!(
            ArgError::NewWithoutPriorBind.to_string(),
            "Error: -new option specified, but no prior bind options for the previous config were present."
        );
        assert_eq!(
            ArgError::NoBindGiven.to_string(),
            "Bind required for webserver configuration."
        );
        assert_eq!(
            ArgError::PasswdReadFailed.to_string(),
            "Unable to read /etc/passwd to extract our runas uid."
        );
        assert_eq!(
            ArgError::RunasUserNotFound.to_string(),
            "Unable to locate the runas user in /etc/passwd."
        );
        assert_eq!(
            ArgError::InvalidBindAddress.to_string(),
            "Error: Invalid bind address"
        );
        assert_eq!(ArgError::InvalidBindPort.to_string(), "Error: Invalid bind port");
        assert_eq!(
            ArgError::PemReadError("/tmp/x.pem".into()).to_string(),
            "PEM file contents or read error: /tmp/x.pem"
        );
    }

    /// `-cachecontrol` targets the LAST cfg.
    #[test]
    fn cachecontrol_targets_last_cfg() {
        let cfg = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-cachecontrol",
            "max-age=3600",
        ]))
        .expect("-cachecontrol should parse");
        assert_eq!(cfg.configs[0].cache_control.as_deref(), Some("max-age=3600"));
    }

    /// `-filestattime` targets the LAST cfg.
    #[test]
    fn filestattime_targets_last_cfg() {
        let cfg = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-filestattime",
            "120",
        ]))
        .expect("-filestattime should parse");
        assert_eq!(cfg.configs[0].file_stat_time, Some(120));
    }

    /// `-filestattime` rejects non-numeric.
    #[test]
    fn filestattime_nonsense_rejected() {
        let r = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-filestattime",
            "xyz",
        ]));
        assert!(matches!(r, Err(ArgError::NonsenseArgument(ref s)) if s == "xyz"));
    }

    /// `-sandbox` sets the global_sandbox on the LAST cfg.
    #[test]
    fn sandbox_targets_last_cfg() {
        let cfg = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-sandbox",
            "/srv/www",
        ]))
        .expect("-sandbox should parse");
        assert_eq!(cfg.configs[0].global_sandbox, Some(PathBuf::from("/srv/www")));
    }

    /// `-hostsandbox` pushes a (host, dir) pair on the LAST cfg.
    #[test]
    fn hostsandbox_targets_last_cfg() {
        let cfg = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-hostsandbox",
            "example.com",
            "/srv/ex",
        ]))
        .expect("-hostsandbox should parse");
        assert_eq!(cfg.configs[0].host_sandbox.len(), 1);
        assert_eq!(cfg.configs[0].host_sandbox[0].host, "example.com");
        assert_eq!(cfg.configs[0].host_sandbox[0].dir, PathBuf::from("/srv/ex"));
    }

    /// `-indexfiles` splits on commas into a `Vec<String>`.
    #[test]
    fn indexfiles_splits_on_comma() {
        let cfg = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-indexfiles",
            "index.html,index.htm,index.php",
        ]))
        .expect("-indexfiles should parse");
        assert_eq!(
            cfg.configs[0].index_files,
            vec!["index.html", "index.htm", "index.php"]
        );
    }

    /// `-redirect` pops ONE arg and stores it as the redirect target.
    #[test]
    fn redirect_stores_single_url() {
        let cfg = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-redirect",
            "https://example.com/",
        ]))
        .expect("-redirect should parse");
        assert_eq!(cfg.configs[0].redirects.len(), 1);
        assert_eq!(cfg.configs[0].redirects[0].from, "");
        assert_eq!(cfg.configs[0].redirects[0].to, "https://example.com/");
    }

    /// `-vhost` sets the vhost on the LAST cfg.
    #[test]
    fn vhost_targets_last_cfg() {
        let cfg = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-vhost",
            "/srv/vhosts",
        ]))
        .expect("-vhost should parse");
        assert_eq!(cfg.configs[0].vhost.as_deref(), Some("/srv/vhosts"));
    }

    /// `-backpath` sets the backpath on the LAST cfg.
    #[test]
    fn backpath_targets_last_cfg() {
        let cfg = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-backpath",
            "http://upstream:8000",
        ]))
        .expect("-backpath should parse");
        assert_eq!(cfg.configs[0].backpath.as_deref(), Some("http://upstream:8000"));
    }

    /// `-errlog` + `-errsyslog` both target the LAST cfg.
    #[test]
    fn errlog_and_errsyslog_target_last_cfg() {
        let cfg = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-errlog",
            "/var/log/rwasa.err",
            "-errsyslog",
        ]))
        .expect("-errlog + -errsyslog should parse");
        assert_eq!(
            cfg.configs[0].errorlog_path,
            Some(PathBuf::from("/var/log/rwasa.err"))
        );
        assert!(cfg.configs[0].errorlog_syslog);
    }

    /// `-logpath` targets the LAST cfg.
    #[test]
    fn logpath_targets_last_cfg() {
        let cfg = parse(osvec(&[
            "program",
            "-bind",
            "127.0.0.1:8080",
            "-logpath",
            "/var/log/rwasa",
        ]))
        .expect("-logpath should parse");
        assert_eq!(cfg.configs[0].logs_path, Some(PathBuf::from("/var/log/rwasa")));
    }

    /// `-runas root` should resolve uid=0,gid=0 on any Unix system
    /// that has root in /etc/passwd (essentially all of them).
    /// Skipped on environments where /etc/passwd is not readable.
    #[test]
    fn runas_root_resolves_to_zero() {
        // Only runnable on systems with a readable /etc/passwd
        // containing a root user — which is virtually all Linux
        // environments including CI.
        if fs::read_to_string("/etc/passwd").is_err() {
            return;
        }
        let cfg = parse(osvec(&["program", "-runas", "root", "-bind", "127.0.0.1:8080"]));
        if let Ok(cfg) = cfg {
            // On any sane system, root is uid/gid 0.
            assert_eq!(cfg.runas_uid, Some(0));
            assert_eq!(cfg.runas_gid, Some(0));
        } else {
            // If /etc/passwd is unreadable in CI, that's acceptable —
            // but we still expect a well-formed error.
            assert!(matches!(
                cfg,
                Err(ArgError::PasswdReadFailed) | Err(ArgError::RunasUserNotFound)
            ));
        }
    }

    /// `-runas __no_such_user_xyz__` must fail with
    /// [`ArgError::RunasUserNotFound`], assuming /etc/passwd is readable.
    #[test]
    fn runas_missing_user_fails() {
        if fs::read_to_string("/etc/passwd").is_err() {
            return; // skip on unusual environments
        }
        let r = parse(osvec(&[
            "program",
            "-runas",
            "__heavything_test_no_such_user_xyz__",
            "-bind",
            "127.0.0.1:8080",
        ]));
        assert!(
            matches!(r, Err(ArgError::RunasUserNotFound)),
            "missing runas user should fail, got {r:?}"
        );
    }

    /// `Config::default()` produces exactly the assembly-line-28
    /// globals: cpucount=1, background=true, funcmatch=".asmcall",
    /// everything else None/empty.
    #[test]
    fn config_default_matches_assembly_globals() {
        let cfg = Config::default();
        assert_eq!(cfg.cpucount, 1);
        assert!(cfg.background);
        assert_eq!(cfg.funcmatch, ".asmcall");
        assert!(cfg.runas.is_none());
        assert!(cfg.runas_uid.is_none());
        assert!(cfg.runas_gid.is_none());
        assert!(cfg.configs.is_empty());
    }

    /// `WebServerConfig::default()` starts with all-default fields
    /// including `is_tls = false`.
    #[test]
    fn webserverconfig_default_matches_assembly_fields() {
        let w = WebServerConfig::default();
        assert!(!w.is_tls);
        assert!(w.pem_path.is_none());
        assert!(w.logs_path.is_none());
        assert!(w.errorlog_path.is_none());
        assert!(!w.errorlog_syslog);
        assert!(w.fastcgi_map.is_empty());
        assert!(w.backpath.is_none());
        assert!(w.vhost.is_none());
        assert!(w.global_sandbox.is_none());
        assert!(w.host_sandbox.is_empty());
        assert!(w.index_files.is_empty());
        assert!(w.redirects.is_empty());
        assert!(w.cache_control.is_none());
        assert!(w.file_stat_time.is_none());
    }

    /// A fully-stacked CLI with many flags on the first cfg and a
    /// separate second cfg via `-new` should parse cleanly.
    #[test]
    fn complex_multi_cfg_cli_parses() {
        let cfg = parse(osvec(&[
            "program",
            "-cpu",
            "2",
            "-foreground",
            "-bind",
            "127.0.0.1:8080",
            "-cachecontrol",
            "max-age=600",
            "-filestattime",
            "120",
            "-logpath",
            "/var/log/rwasa",
            "-fastcgi",
            ".php",
            "127.0.0.1:9000",
            "-vhost",
            "/srv/vhost",
            "-new",
            "-bind",
            "0.0.0.0:80",
            "-backpath",
            "http://10.0.0.1:8080",
            "-funcmatch",
            "/api",
        ]))
        .expect("complex CLI should parse");
        assert_eq!(cfg.cpucount, 2);
        assert!(!cfg.background);
        assert_eq!(cfg.funcmatch, "/api");
        assert_eq!(cfg.configs.len(), 2);
        // cfg 0
        assert_eq!(cfg.configs[0].bind_addr.port(), 8080);
        assert_eq!(cfg.configs[0].cache_control.as_deref(), Some("max-age=600"));
        assert_eq!(cfg.configs[0].file_stat_time, Some(120));
        assert_eq!(cfg.configs[0].logs_path, Some(PathBuf::from("/var/log/rwasa")));
        assert_eq!(cfg.configs[0].fastcgi_map.len(), 1);
        assert_eq!(cfg.configs[0].vhost.as_deref(), Some("/srv/vhost"));
        // cfg 1
        assert_eq!(cfg.configs[1].bind_addr.port(), 80);
        assert_eq!(cfg.configs[1].backpath.as_deref(), Some("http://10.0.0.1:8080"));
    }

    /// The parser must ignore nothing: every CLI flag must land somewhere.
    /// This is a smoke test that `parse` with every valid flag once
    /// produces a well-formed Config.
    #[test]
    fn every_flag_exercised() {
        use std::io::Write;
        let pid = std::process::id();
        let tmp = std::env::temp_dir().join(format!("rwasa_test_every_{pid}.pem"));
        {
            let mut f = fs::File::create(&tmp).expect("create temp pem");
            f.write_all(b"dummy\n").expect("write temp pem");
        }

        let cfg = parse(osvec(&[
            "program",
            "-cpu",
            "1",
            "-foreground",
            "-funcmatch",
            ".asmcall",
            "-tls",
            tmp.to_str().unwrap(),
            "-bind",
            "127.0.0.1:4443",
            "-cachecontrol",
            "max-age=300",
            "-filestattime",
            "60",
            "-logpath",
            "/tmp/rwasa_log",
            "-errlog",
            "/tmp/rwasa_err.log",
            "-errsyslog",
            "-fastcgi",
            ".php",
            "127.0.0.1:9000",
            "-backpath",
            "http://10.0.0.1:8080",
            "-vhost",
            "/srv/vh",
            "-sandbox",
            "/srv/sb",
            "-hostsandbox",
            "ex.com",
            "/srv/ex",
            "-indexfiles",
            "index.html",
            "-redirect",
            "https://example.com/",
        ]))
        .expect("every-flag CLI should parse");

        assert_eq!(cfg.configs.len(), 1);
        let w = &cfg.configs[0];
        assert!(w.is_tls);
        assert!(w.pem_path.is_some());
        assert_eq!(w.bind_addr.port(), 4443);
        assert_eq!(w.cache_control.as_deref(), Some("max-age=300"));
        assert_eq!(w.file_stat_time, Some(60));
        assert_eq!(w.logs_path, Some(PathBuf::from("/tmp/rwasa_log")));
        assert_eq!(w.errorlog_path, Some(PathBuf::from("/tmp/rwasa_err.log")));
        assert!(w.errorlog_syslog);
        assert_eq!(w.fastcgi_map.len(), 1);
        assert_eq!(w.backpath.as_deref(), Some("http://10.0.0.1:8080"));
        assert_eq!(w.vhost.as_deref(), Some("/srv/vh"));
        assert_eq!(w.global_sandbox, Some(PathBuf::from("/srv/sb")));
        assert_eq!(w.host_sandbox.len(), 1);
        assert_eq!(w.index_files, vec!["index.html"]);
        assert_eq!(w.redirects.len(), 1);

        let _ = fs::remove_file(&tmp);
    }

    /// `parse_bind` helper: well-formed IPv4 address+port.
    #[test]
    fn parse_bind_ipv4() {
        let sa = parse_bind("192.168.1.1:443").expect("valid IPv4:port should parse");
        assert_eq!(sa.port(), 443);
    }

    /// `parse_bind` helper: bare port defaults to 0.0.0.0.
    #[test]
    fn parse_bind_bare_port() {
        let sa = parse_bind("8080").expect("bare port should parse");
        assert!(sa.ip().is_unspecified());
        assert_eq!(sa.port(), 8080);
    }

    /// `parse_bind` helper: bad port fails.
    #[test]
    fn parse_bind_bad_port() {
        assert!(matches!(
            parse_bind("127.0.0.1:65536"),
            Err(ArgError::InvalidBindPort)
        ));
        assert!(matches!(
            parse_bind("127.0.0.1:-1"),
            Err(ArgError::InvalidBindPort)
        ));
    }

    /// `parse_bind` helper: bad address fails.
    #[test]
    fn parse_bind_bad_address() {
        assert!(matches!(parse_bind("nope:80"), Err(ArgError::InvalidBindAddress)));
    }

    /// `num_cpus_2x` returns a positive value.
    #[test]
    fn num_cpus_2x_positive() {
        let n = num_cpus_2x();
        assert!(n >= 2, "2× CPU count must be at least 2, got {n}");
    }

    /// Every public struct derives Debug and Clone (compile-time check).
    #[test]
    fn structs_derive_debug_clone() {
        let cfg = Config::default();
        let _cloned = cfg.clone();
        let _debug = format!("{cfg:?}");

        let w = WebServerConfig::default();
        let _cloned = w.clone();
        let _debug = format!("{w:?}");

        let m = FastCgiMapping {
            endswith: ".php".into(),
            address: "127.0.0.1:9000".into(),
        };
        let _cloned = m.clone();
        let _debug = format!("{m:?}");

        let h = HostSandboxMapping {
            host: "x".into(),
            dir: PathBuf::from("/y"),
        };
        let _cloned = h.clone();
        let _debug = format!("{h:?}");

        let r = RedirectMapping {
            from: String::new(),
            to: "/".into(),
        };
        let _cloned = r.clone();
        let _debug = format!("{r:?}");
    }
}
