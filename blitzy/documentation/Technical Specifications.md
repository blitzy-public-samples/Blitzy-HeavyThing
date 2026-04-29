# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Refactoring Objective

Based on the prompt, the Blitzy platform understands that the refactoring objective is to **translate the HeavyThing x86_64 Linux assembly language library and three of its showcase applications into an idiomatic, warning-clean Rust codebase** that preserves every externally observable behavior while replacing the hand-written FASM sources with a Cargo workspace built on `tokio`, `ring`, `rustls`, and supporting `crates.io` dependencies.

- **Refactoring type**: **Tech stack migration** (x86_64 FASM assembly → Rust 2021) combined with code-structure modernization (60+ single-file `.inc` modules → idiomatic Rust module tree)
- **Target repository**: **Same repository** at `/tmp/blitzy/Blitzy-HeavyThing/master_fc613b`; the Cargo workspace is added in-place alongside the existing assembly sources
- **Primary goals (restated with technical precision)**:
  - Produce a single Cargo workspace that builds warning-clean under `RUSTFLAGS="-D warnings"` on stable Rust (2021 edition) targeting `x86_64-unknown-linux-gnu`
  - Deliver a library crate named `heavything` exposing five top-level modules (`crypto`, `net`, `tui`, `ds`, `util`) that functionally replace the 106 `.inc` files comprising the assembly library
  - Deliver three binary crates — `sshtalk`, `hnwatch`, and `webserver` — that compile, start, and service live traffic without any logic modification to the showcase-application behavior observed in `sshtalk/sshtalk.asm`, `hnwatch/hnwatch.asm`, and `rwasa/rwasa.asm`
  - Replace the hand-rolled epoll loop in `epoll.inc` with the `tokio` runtime (epoll backend) while preserving the three-message IPC relay (`linkmessage_log`, `linkmessage_tlsupdate`, `linkmessage_ocsp`) and all eight timer-driven integration points (HTTP idle 30s, log flush 1.5s, PEM reload 3600s, TLS session cache 3600s, OCSP refresh 7200s, OCSP retry 300s, file cache recheck 120s, IP blacklist 86400s)
  - Replace the hand-rolled TLS 1.2 state machine in `tls.inc` with `rustls` + `webpki` while preserving the externally observable handshake outcomes (session resumption, OCSP stapling, HSTS/BREACH header emission) for both TLS 1.2 and TLS 1.3
  - Replace the hand-written cryptographic primitives in `aes.inc`, `sha1.inc`, `sha2.inc`, `md5.inc`, `hmac.inc`, `hmac_drbg.inc`, `pbkdf2.inc`, and `scrypt.inc` with `ring` + `scrypt` crate wrappers that return byte-for-byte identical outputs for identical inputs
  - Translate the TUI framework (32 `tui_*.inc` files) to a direct Rust implementation using `struct` + `trait` polymorphism — **third-party TUI crates (`ratatui`, `crossterm`, etc.) are prohibited**; existing TUI semantics must be preserved exactly, with terminal raw-mode management performed through direct `libc` `termios` syscalls
  - Translate the data structures (`heap.inc`, `maps.inc`, `list.inc`, `buffer.inc`) to use `std::collections` where semantically equivalent; custom implementations are permitted **only where assembly semantics differ materially** from standard library types
  - Replace the utility primitives (`zlib_deflate.inc`/`zlib_inflate.inc`, `base64_latin1.inc`, `json.inc`, `url.inc`, `crc.inc`) with `flate2`, `base64`, `serde_json`, `url`, and direct Rust implementations
  - Deliver measured performance comparisons via `criterion` benchmarks for AES-128-CBC throughput, SHA-256 throughput, and epoll-driven HTTP round-trip latency, captured in `BENCHMARK_REPORT.md`
  - Deliver a complete audit of every `unsafe` block in `UNSAFE_AUDIT.md` with site, reason, and safety invariant; any count exceeding 50 requires per-site written justification; all FFI and raw-syscall boundary sites must have a corresponding integration test
- **Implicit requirements surfaced from the prompt**:
  - **Cargo workspace layout is mandatory**: separate library crate + three binary crates implies a workspace `Cargo.toml` at the repository root with a `members` array; this is required even though it is not stated explicitly
  - **CPU feature detection must be runtime**, not compile-time: the assembly library uses `CPUID` at `ht$init` to set `has_AESNI`, `has_AVX`, etc.; the Rust port must use `std::is_x86_feature_detected!` or `ring`'s internal detection to retain graceful degradation
  - **Master-worker process model must be preserved** for `webserver`: the `rwasa` architecture forks workers with inherited listening sockets and drops privileges post-bind; the Rust port must replicate this using `nix::unistd::fork` + `nix::unistd::{setuid, setgid}` rather than substituting threads, because the assembly baseline relies on per-process isolation and `PR_SET_PDEATHSIG` for worker cleanup
  - **Privilege-drop sequence ordering is security-critical**: `bind → setgid → setuid → fork` must be preserved exactly; reordering (e.g., dropping privileges before binding low ports) would break the existing behavior
  - **Timer semantics**: return value of `0` means "reset timer"; non-zero means "fire fatality/teardown" — this assembly convention is load-bearing and must map to a Rust `TimerAction` enum or `Result`-equivalent
  - **Exit codes 96–99** (heap mmap fail = 99, profiler overflow = 98, ulimit < 4096 = 97, epoll_create fail = 96) are part of the observable interface and must be produced by the Rust code under equivalent failure conditions
  - **`Strict-Transport-Security: max-age=31536000; includeSubDomains`** header emission must be preserved byte-identically when `webserver_hsts = 1`
  - **`X-NB` BREACH mitigation header** (1–48 random bytes) must continue to be emitted on TLS+gzip responses
  - **Feature-gated build configurations** equivalent to the 60+ compile-time constants in `ht_defaults.inc` should be expressed via Cargo features plus `const` declarations
  - **GPLv3 license header** from each source `.inc` file must be preserved in the ported Rust sources to honor the existing copyright (source headers uniformly carry © 2015 2 Ton Digital, Jeff Marrison)

### 0.1.2 Technical Interpretation

This refactoring translates to the following technical transformation strategy: **every `.inc` file in the assembly library maps to a Rust module inside the `heavything` crate**, organized into five top-level subsystems that mirror the existing architectural boundaries described in `ht.inc`. Protocol stacking is re-expressed through `tokio`'s `AsyncRead` / `AsyncWrite` traits and a custom `IoChain` trait that preserves the directional-dispatch semantics of the existing 7-method virtual method table in `io.inc`.

**Current architecture → target architecture**:

| Current (Assembly)                                                                 | Target (Rust)                                                                                       |
|-----------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| 106 `.inc` files + `ht.inc` master include + `ht_defaults.inc` constants           | `heavything` library crate with `crypto/`, `net/`, `tui/`, `ds/`, `util/` modules                    |
| Hand-rolled epoll loop in `epoll.inc` (3,512 lines)                                | `tokio::runtime::Runtime` + async tasks; `tokio::net` for sockets                                    |
| 7-method IO virtual table in `io.inc` (forward: destroy/clone/send; back: connected/receive/error/timeout) | `trait IoChain` with async methods; `Arc<dyn IoChain>` parent/child pointers; directional semantics preserved |
| TLS 1.2 hand-rolled state machine in `tls.inc` (6,866 lines)                       | `rustls` server & client configs with `DangerousClientConfig` for rustls and `webpki` for X.509     |
| SSH2 hand-rolled in `ssh.inc` (6,011 lines) — dh-group-exchange-sha256, aes256-cbc, hmac-sha2-256 | Direct Rust re-implementation under `net::ssh` using `ring` for SHA-2/HMAC + `aes` crate for CBC    |
| HTTP/1.1 server in `webserver.inc` (5,670 lines) — 8-stage dispatch pipeline       | `net::http::server` module reproducing identical 8-stage pipeline using `tokio::io` + `mimelike`-equivalent parser |
| Custom bin allocator `heap.inc` (never-return policy, 2 GB attempt)                 | Rust global allocator (`std` default) — allocator is behaviorally equivalent; `heap.inc` semantics do not map to user code |
| Hand-rolled AES-NI + Wei Dai fallback in `aes.inc` (1,423 lines)                    | `ring::aead` where AEAD-equivalent suffices; `aes` + `cbc` crates for raw AES-CBC (SSH + htcrypt)   |
| UTF-32 string engine `string32.inc` / `string16.inc` (~4,500 lines each)            | Rust `String` / `&str` (UTF-8) — identical Unicode case tables via `unicode-case-mapping` derivation |
| 32 `tui_*.inc` widget files                                                        | `tui/widgets/` submodule tree with `trait Widget` + concrete structs; raw terminal I/O via `libc` `termios` + async stdin stream |
| FASM `if used` conditional compilation                                              | Cargo features + `cfg`-gated modules + link-time dead-code elimination                               |
| `format ELF64`, static binaries via `ld`                                            | `cargo build --release`; static-linking decisions delegated to `cargo` defaults (dynamic libc acceptable per project prompt) |
| Master-worker via `fork()` + Unix socketpair in `epoll_child.inc`                   | `nix::unistd::fork` + `tokio::net::UnixStream` pair; workers enter their own `tokio` runtimes       |
| `ht$init` twelve-stage initialization                                               | `heavything::init()` equivalent function invoked by each binary crate's `main`                       |

**Transformation rules and patterns** (applied uniformly across all source files):

- Each `.inc` file → one Rust module file (`.rs`) under the appropriate subsystem directory
- Assembly `falign` + named function → public `pub fn` or `pub(crate) fn` in Rust
- FASM `object$method` naming (with `$` as separator) → snake_case methods on Rust structs (e.g., `webserver$connected` → `WebServer::on_connected`)
- FASM `globals { }` blocks → module-level `static` / `LazyLock` / per-instance struct fields
- Register-based argument passing (rdi, rsi, rdx) → Rust function parameters with ownership / borrowing discipline
- Virtual method tables (7 IO vmethods, 35 TUI vmethods) → Rust `trait` objects with `async fn` where appropriate
- `rdtsc` cycle counters in `profiler.inc` → `std::time::Instant` with per-call accumulators; CPC computation preserved
- Compile-time constants in `ht_defaults.inc` → `pub const` declarations in `heavything::config` + Cargo features
- Direct syscalls via `syscall.inc` → `libc` crate raw syscalls at exactly the same sites where assembly makes them (no substitution)
- `vdso.inc` fast `gettimeofday` → unchanged: standard library `SystemTime::now()` uses vDSO on Linux automatically
- Error handling: `io_verror` backward propagation → Rust `Result` types flowing up the async call stack plus explicit teardown in the `Drop` path

The refactoring is executed in **a single phase**: all 106 `.inc` files and all three in-scope showcase applications are translated together in one delivery. No partial or staged rollout is permitted.


## 0.2 Source Analysis

### 0.2.1 Comprehensive Source File Discovery

The HeavyThing library occupies `/tmp/blitzy/Blitzy-HeavyThing/master_fc613b/` and contains **106 top-level `.inc` files** (131,445 lines of FASM assembly in aggregate), seven showcase-application directories (`rwasa/`, `sshtalk/`, `hnwatch/`, `toplip/`, `webslap/`, `dhtool/`, `util/`), and one `examples/` directory. Every `.inc` file requires translation because `ht.inc` transitively includes all 106 of them via its master include chain (confirmed in `ht.inc` lines 56–250).

#### 0.2.1.1 Current Structure Mapping

```
Current:
/tmp/blitzy/Blitzy-HeavyThing/master_fc613b/
├── ht.inc                  (master include; 653 lines)
├── ht_defaults.inc         (compile-time config; 523 lines)
├── ht_data.inc             (shared data segment; 36 lines)
│
├── [Core Runtime / F-001 — 13 files, ~20k lines]
│   ├── heap.inc, memfuncs.inc, rng.inc, hmac_drbg.inc
│   ├── profiler.inc, vdso.inc, rdtsc.inc, crc.inc
│   ├── syscall.inc, syslog.inc, breakpoint.inc, sleeps.inc
│   └── sysinfo.inc
│
├── [Data Structures / part of F-001 / F-009 — 11 files]
│   ├── list.inc, maps.inc, buffer.inc
│   ├── string32.inc, string16.inc, unicodecase.inc, string_math.inc
│   ├── dir.inc, file.inc, formatter.inc, date.inc
│   ├── math.inc, blacklist.inc
│   └── cookiejar.inc
│
├── [Crypto / F-007 — 15 files, ~22k lines]
│   ├── aes.inc (1,423 lines; AES-NI + Wei Dai fallback)
│   ├── sha1.inc, sha2.inc (2,146 lines), md5.inc, hmac.inc
│   ├── pbkdf2.inc, scrypt.inc, htcrypt.inc, htxts.inc
│   ├── bigint.inc (10,923 lines — largest file)
│   ├── dh_pool.inc + dh_pool_{2k,3k,4k,6k,8k,16k}.inc
│   ├── dh_groups.inc
│   └── X509.inc (4,133 lines)
│
├── [Networking / F-002 through F-006 — 12 files, ~24k lines]
│   ├── io.inc (IO chaining; virtual method tables)
│   ├── epoll.inc (3,512 lines), epoll_child.inc, epoll_dns.inc
│   ├── tls.inc (6,866 lines), ssh.inc (6,011 lines)
│   ├── http1.inc, httpheaders.inc, mimelike.inc (3,814 lines)
│   ├── webserver.inc (5,670 lines), webclient.inc (2,042 lines)
│   ├── fcgiclient.inc, url.inc
│
├── [Data / Utility — 7 files]
│   ├── json.inc (1,639 lines), png.inc
│   ├── zlib_inflate.inc (2,656), zlib_deflate.inc (4,805)
│   ├── base64_latin1.inc
│   ├── mapped.inc, privmapped.inc, mappedheap.inc
│
├── [TUI Framework / F-008 — 32 files]
│   ├── tui_object.inc, tui_render.inc, tui_lock.inc
│   ├── tui_terminal.inc, tui_ansi.inc, tui_geometry.inc, tui_gridguts.inc
│   ├── tui_panel.inc, tui_background.inc, tui_lines.inc, tui_spacers.inc
│   ├── tui_label.inc, tui_text.inc, tui_textbox.inc, tui_button.inc
│   ├── tui_form.inc, tui_simpleauth.inc, tui_alert.inc, tui_bell.inc
│   ├── tui_progressbar.inc, tui_progressbox.inc, tui_spinner.inc
│   ├── tui_datagrid.inc, tui_statusbar.inc, tui_newsticker.inc
│   ├── tui_matrix.inc, tui_typist.inc, tui_splash.inc, tui_effect.inc
│   ├── tui_effects.inc, tui_png.inc, tui_ssh.inc
│
├── [Macros / Build Helpers — 4 files]
│   ├── align_macros.inc, call.inc, cleartext.inc, dataseg_macros.inc
│
├── [Showcase Applications — 7 directories]
│   ├── rwasa/           (flagship web server — IN SCOPE as 'webserver' binary)
│   │   ├── rwasa.asm (152 lines), arguments.inc (791), master.inc (337), worker.inc (361)
│   │   └── rwasa_tlsmin.asm + tlsmin_defaults.inc (TLS-minimalist variant)
│   ├── sshtalk/         (SSH chat — IN SCOPE)
│   │   ├── sshtalk.asm (326), chatpanel.inc (1030), chatroom.inc (423)
│   │   ├── screen.inc (1973), statusbar.inc (197), userdb.inc (732)
│   ├── hnwatch/         (HN viewer — IN SCOPE)
│   │   ├── hnwatch.asm (63), hnmodel.inc (703), ui.inc (1715)
│   │   ├── textify.inc (221), eventstream.inc (458)
│   ├── toplip/          (file encryption — OUT OF SCOPE)
│   ├── webslap/         (load tester — OUT OF SCOPE)
│   ├── dhtool/          (DH param generator — OUT OF SCOPE)
│   ├── util/            (bigint_tune, make_dh_static, mersenneprimetest — OUT OF SCOPE)
│   └── examples/        (hello_world variants, tuieffects, etc. — OUT OF SCOPE)
│
├── LICENSE, README, README.md, ChangeLog, 2ton.png
```

#### 0.2.1.2 Complete File Inventory — All 106 `.inc` Files

The following inventory enumerates every `.inc` file in the repository root. **No file is listed as "pending" or "to be discovered"**; every file has been identified and assigned a subsystem classification.

| # | File | Lines | Classification |
|---|------|-------|----------------|
| 1 | `align_macros.inc` | — | Macro (build helper) |
| 2 | `base64_latin1.inc` | — | util subsystem |
| 3 | `bigint.inc` | 10923 | crypto subsystem |
| 4 | `blacklist.inc` | — | ds subsystem |
| 5 | `breakpoint.inc` | — | util subsystem (debug) |
| 6 | `buffer.inc` | 1247 | ds subsystem |
| 7 | `call.inc` | — | Macro (build helper) |
| 8 | `cleartext.inc` | — | Macro (build helper) |
| 9 | `cookiejar.inc` | — | net subsystem |
| 10 | `crc.inc` | — | util subsystem |
| 11 | `dataseg_macros.inc` | — | Macro (build helper) |
| 12 | `date.inc` | 1336 | util subsystem |
| 13 | `dh_groups.inc` | — | crypto subsystem |
| 14 | `dh_pool.inc` | — | crypto subsystem |
| 15–20 | `dh_pool_{2k,3k,4k,6k,8k,16k}.inc` | — | crypto subsystem (data only) |
| 21 | `dir.inc` | — | util subsystem |
| 22 | `epoll.inc` | 3512 | net subsystem |
| 23 | `epoll_child.inc` | — | net subsystem |
| 24 | `epoll_dns.inc` | 1264 | net subsystem |
| 25 | `fcgiclient.inc` | — | net subsystem |
| 26 | `file.inc` | — | util subsystem |
| 27 | `formatter.inc` | 2157 | util subsystem |
| 28 | `heap.inc` | — | ds subsystem (replaced by std allocator) |
| 29 | `hmac.inc` | — | crypto subsystem |
| 30 | `hmac_drbg.inc` | — | crypto subsystem |
| 31 | `ht.inc` | 653 | Master — replaced by `heavything::lib.rs` |
| 32 | `ht_data.inc` | 36 | Data-seg — absorbed into Rust statics |
| 33 | `ht_defaults.inc` | 523 | Config — replaced by `heavything::config` + Cargo features |
| 34 | `htcrypt.inc` | — | crypto subsystem (OUT OF SCOPE: toplip-only) |
| 35 | `htxts.inc` | — | crypto subsystem (OUT OF SCOPE: toplip-only) |
| 36 | `http1.inc` | — | net subsystem |
| 37 | `httpheaders.inc` | 3750 | net subsystem |
| 38 | `io.inc` | — | net subsystem (IO chain trait) |
| 39 | `json.inc` | 1639 | util subsystem (→ `serde_json`) |
| 40 | `list.inc` | — | ds subsystem |
| 41 | `mapped.inc` | — | util subsystem |
| 42 | `mappedheap.inc` | — | ds subsystem |
| 43 | `maps.inc` | 4507 | ds subsystem |
| 44 | `math.inc` | — | util subsystem |
| 45 | `md5.inc` | — | crypto subsystem |
| 46 | `memfuncs.inc` | 1822 | ds subsystem (→ Rust slice ops) |
| 47 | `mimelike.inc` | 3814 | net subsystem |
| 48 | `pbkdf2.inc` | — | crypto subsystem |
| 49 | `png.inc` | — | util subsystem (used by `tui_png`) |
| 50 | `privmapped.inc` | — | util subsystem |
| 51 | `profiler.inc` | 1315 | util subsystem (→ `criterion` for benches; CPC profiler omitted) |
| 52 | `rdtsc.inc` | — | Macro (time source) |
| 53 | `rng.inc` | — | crypto subsystem |
| 54 | `scrypt.inc` | — | crypto subsystem |
| 55 | `sha1.inc` | — | crypto subsystem |
| 56 | `sha2.inc` | 2146 | crypto subsystem |
| 57 | `sleeps.inc` | — | util subsystem |
| 58 | `ssh.inc` | 6011 | net subsystem |
| 59 | `string16.inc` | 4513 | util subsystem (UTF-16 variant; see note) |
| 60 | `string32.inc` | 4550 | util subsystem (UTF-32 default) |
| 61 | `string_math.inc` | 2158 | util subsystem |
| 62 | `syscall.inc` | — | Macro (syscall numbers; → `libc::syscall`) |
| 63 | `sysinfo.inc` | — | util subsystem |
| 64 | `syslog.inc` | — | util subsystem |
| 65 | `tls.inc` | 6866 | net subsystem (→ `rustls` wrapper) |
| 66–97 | `tui_*.inc` (32 files) | — | tui subsystem |
| 98 | `unicodecase.inc` | — | util subsystem |
| 99 | `url.inc` | 1670 | util subsystem (→ `url` crate) |
| 100 | `vdso.inc` | — | util subsystem (→ `std::time` which uses vDSO automatically) |
| 101 | `webclient.inc` | 2042 | net subsystem |
| 102 | `webserver.inc` | 5670 | net subsystem |
| 103 | `zlib_deflate.inc` | 4805 | util subsystem (→ `flate2`) |
| 104 | `zlib_inflate.inc` | 2656 | util subsystem (→ `flate2`) |
| 105 | `X509.inc` | 4133 | crypto subsystem (→ `webpki` / `x509-parser`) |
| 106 | `unicodecase.inc` | — | util subsystem |

### 0.2.2 Showcase Application Source Inventory

#### 0.2.2.1 In-Scope Applications

| Application | Entry File | Lines | Supporting Files | Total Lines |
|-------------|-----------|-------|------------------|-------------|
| **webserver** (ex-rwasa) | `rwasa/rwasa.asm` | 152 | `arguments.inc`, `master.inc`, `worker.inc` | ~1,641 |
| **sshtalk** | `sshtalk/sshtalk.asm` | 326 | `userdb.inc`, `chatroom.inc`, `chatpanel.inc`, `screen.inc`, `statusbar.inc` | ~4,681 |
| **hnwatch** | `hnwatch/hnwatch.asm` | 63 | `hnmodel.inc`, `ui.inc`, `textify.inc`, `eventstream.inc` | ~3,160 |

#### 0.2.2.2 Out-of-Scope Applications (Not Translated)

Per the prompt's explicit statement that "one binary crate per example application (sshtalk, hnwatch, webserver)" defines the complete set of in-scope binaries, the following applications and their supporting `.inc` files are **not translated** in this refactor:

| Application | Directory | Rationale |
|-------------|-----------|-----------|
| toplip | `toplip/` | Not listed in prompt's three example apps; relies on htcrypt/htxts which are toplip-specific |
| webslap | `webslap/` | Not listed in prompt's three example apps; relies on `rwasa_tlsmin` variant |
| dhtool | `dhtool/` | Not listed in prompt's three example apps; relies on BigInt safe-prime generation |
| util/bigint_tune | `util/` | Utility benchmark for BigInt unroll size — not listed |
| util/make_dh_static | `util/` | DH parameter file generator — not listed |
| util/mersenneprimetest | `util/` | Mersenne primality test utility — not listed |
| examples/* | `examples/` | All 14 examples (hello_world variants, tuieffects, sshecho, tlsecho, multicore_echo, simplechat C/C++, echo, minigzip, sha256, tuimatrix) — not listed |

Library `.inc` files used exclusively by out-of-scope applications (`htcrypt.inc`, `htxts.inc`) are **implemented as stubs or omitted** from the `heavything` crate; see Section 0.3 for precise scope boundaries.

### 0.2.3 Build Artifact Discovery

The repository contains pre-compiled artifacts that do **not** require modification:

- `rwasa/rwasa.o`, `sshtalk/sshtalk.o`, `hnwatch/hnwatch.o`, `toplip/toplip.o`, `webslap/webslap.o`, `dhtool/dhtool.o`, `util/*.o` — FASM output object files (ignored)
- `rwasa/rwasa`, `sshtalk/sshtalk`, `hnwatch/hnwatch`, `toplip/toplip`, `webslap/webslap`, `dhtool/dhtool`, `util/bigint_tune`, `util/make_dh_static`, `util/mersenneprimetest` — pre-built static ELF64 binaries (reference artifacts)
- `2ton.png` — library logo (ignored)
- `.git/` — version control metadata (ignored)

These artifacts are **kept in place** and serve as behavioral oracles during Gate 1 (live smoke test) and Gate 4 (named real-world validation artifacts).


## 0.3 Scope Boundaries

### 0.3.1 Exhaustively In Scope

The following files, directories, and deliverables are **in scope** for this refactor. All paths are relative to the repository root `/tmp/blitzy/Blitzy-HeavyThing/master_fc613b/`.

#### 0.3.1.1 New Files to Create — Cargo Workspace Root

- `Cargo.toml` — workspace manifest declaring members `heavything`, `sshtalk`, `hnwatch`, `webserver`
- `Cargo.lock` — generated lockfile
- `.cargo/config.toml` — sets `RUSTFLAGS = ["-D", "warnings"]` for warning-clean enforcement
- `rust-toolchain.toml` — pins stable toolchain, 2021 edition, `x86_64-unknown-linux-gnu` target
- `rustfmt.toml` — style configuration
- `clippy.toml` — lint configuration

#### 0.3.1.2 New Files to Create — `heavything` Library Crate

- `crates/heavything/Cargo.toml`
- `crates/heavything/src/lib.rs` — crate root; public module declarations; `init()` and `init_args()` public functions; exit-code constants; CPU feature detection
- `crates/heavything/src/config.rs` — all 60+ compile-time constants from `ht_defaults.inc` expressed as `pub const`
- `crates/heavything/src/crypto/**/*.rs` — `mod.rs`, `aes.rs`, `sha1.rs`, `sha2.rs`, `md5.rs`, `hmac.rs`, `hmac_drbg.rs`, `pbkdf2.rs`, `scrypt.rs`, `bigint.rs`, `dh.rs`, `rng.rs`, `x509.rs`
- `crates/heavything/src/net/**/*.rs` — `mod.rs`, `io.rs`, `epoll.rs` (thin shim over `tokio`), `dns.rs`, `child.rs`, `http/mod.rs`, `http/server.rs`, `http/client.rs`, `http/headers.rs`, `http/mimelike.rs`, `http/cookiejar.rs`, `fcgi.rs`, `tls.rs`, `ssh/mod.rs`, `ssh/kex.rs`, `ssh/cipher.rs`, `ssh/auth.rs`, `blacklist.rs`, `url.rs`
- `crates/heavything/src/tui/**/*.rs` — `mod.rs`, `object.rs`, `render.rs`, `terminal.rs`, `ansi.rs`, `geometry.rs`, `gridguts.rs`, `lock.rs`, `widgets/mod.rs`, `widgets/panel.rs`, `widgets/background.rs`, `widgets/lines.rs`, `widgets/spacers.rs`, `widgets/label.rs`, `widgets/text.rs`, `widgets/textbox.rs`, `widgets/button.rs`, `widgets/form.rs`, `widgets/simpleauth.rs`, `widgets/alert.rs`, `widgets/bell.rs`, `widgets/progressbar.rs`, `widgets/progressbox.rs`, `widgets/spinner.rs`, `widgets/datagrid.rs`, `widgets/statusbar.rs`, `widgets/newsticker.rs`, `widgets/matrix.rs`, `widgets/typist.rs`, `widgets/splash.rs`, `widgets/effect.rs`, `widgets/effects.rs`, `widgets/png.rs`, `widgets/ssh.rs`
- `crates/heavything/src/ds/**/*.rs` — `mod.rs`, `list.rs`, `maps.rs`, `buffer.rs`, `blacklist.rs` (moved here), `cookiejar.rs` (moved here if net doesn't own it), `memfuncs.rs`
- `crates/heavything/src/util/**/*.rs` — `mod.rs`, `string.rs`, `unicodecase.rs`, `string_math.rs`, `crc.rs`, `base64_encode.rs` (wrapper over `base64` crate), `json.rs` (wrapper over `serde_json`), `zlib.rs` (wrapper over `flate2`), `png.rs`, `formatter.rs`, `math.rs`, `date.rs`, `file.rs`, `dir.rs`, `sysinfo.rs`, `syslog.rs`, `sleeps.rs`, `mapped.rs`, `privmapped.rs`, `mappedheap.rs`, `profiler.rs`, `vdso.rs`
- `crates/heavything/benches/aes_cbc.rs` — AES-128-CBC throughput benchmark
- `crates/heavything/benches/sha256.rs` — SHA-256 throughput benchmark
- `crates/heavything/benches/http_roundtrip.rs` — HTTP round-trip latency benchmark
- `crates/heavything/tests/crypto_integration.rs` — integration test for crypto subsystem (known-answer tests against assembly outputs)
- `crates/heavything/tests/net_integration.rs` — integration test for net subsystem (live TCP + DNS + HTTP)
- `crates/heavything/tests/tui_integration.rs` — integration test for tui subsystem (rendered-frame byte comparison against expected ANSI)
- `crates/heavything/tests/ds_integration.rs` — integration test for ds subsystem (map/list/buffer semantics)
- `crates/heavything/tests/util_integration.rs` — integration test for util subsystem (zlib round-trip, base64 round-trip, JSON round-trip)
- `crates/heavything/tests/ffi_boundary.rs` — integration tests for every FFI / raw-syscall boundary site flagged in `UNSAFE_AUDIT.md`

#### 0.3.1.3 New Files to Create — Binary Crates

- `crates/sshtalk/Cargo.toml`
- `crates/sshtalk/src/main.rs` — entry point equivalent to `sshtalk/sshtalk.asm` (`call ht$init` → userdb init → TUI init → `epoll$run`)
- `crates/sshtalk/src/userdb.rs` — pipe-delimited flat-file user database with `authenticate` and `newuser` hooks
- `crates/sshtalk/src/chatroom.rs` — chat broadcast state
- `crates/sshtalk/src/chatpanel.rs`, `crates/sshtalk/src/screen.rs`, `crates/sshtalk/src/statusbar.rs` — TUI composition
- `crates/hnwatch/Cargo.toml`
- `crates/hnwatch/src/main.rs` — entry point equivalent to `hnwatch/hnwatch.asm`
- `crates/hnwatch/src/hnmodel.rs`, `crates/hnwatch/src/ui.rs`, `crates/hnwatch/src/textify.rs`, `crates/hnwatch/src/eventstream.rs`
- `crates/webserver/Cargo.toml`
- `crates/webserver/src/main.rs` — entry point equivalent to `rwasa/rwasa.asm`
- `crates/webserver/src/arguments.rs` — CLI parsing (`-cpu`, `-runas`, `-tls`, `-bind`, `-fastcgi`, `-vhost`, `-sandbox`, `-funcmatch`, `-background`, `-new`)
- `crates/webserver/src/master.rs` — master-process lifecycle (bind → drop privileges → fork workers → IPC relay)
- `crates/webserver/src/worker.rs` — worker-process lifecycle (re-seed RNG → new epoll → install hooks → `tokio::Runtime::block_on`)

#### 0.3.1.4 New Deliverable Documents

- `UNSAFE_AUDIT.md` — inventory of every `unsafe` block with location (file:line), reason, and safety invariant; any count > 50 requires per-site written justification
- `BENCHMARK_REPORT.md` — `criterion` output for AES-128-CBC, SHA-256, and HTTP round-trip latency comparing assembly baselines (measured by invoking the pre-built FASM binaries in `rwasa/rwasa`, plus example binaries where available for AES/SHA primitives) to Rust measurements
- `INTEGRATION_SIGNOFF.md` — completed Gate 8 checklist evidencing live smoke tests, API contract verification, and audit deliverables

#### 0.3.1.5 Files to Update

- `README.md` — add Rust build instructions section (`cargo build --release`, `cargo bench`, `cargo test`); preserve existing assembly build documentation
- `.gitignore` — add `/target/`, `/Cargo.lock` if it already exists it is preserved; the binary crates' `Cargo.lock` rules apply

#### 0.3.1.6 Wildcard Patterns Considered In Scope

- `crates/heavything/src/**/*.rs` — all newly created Rust source files
- `crates/{sshtalk,hnwatch,webserver}/src/**/*.rs` — all newly created binary crate sources
- `crates/heavything/benches/*.rs` — all criterion benchmark files
- `crates/heavything/tests/*.rs` — all integration test files

### 0.3.2 Explicitly Out of Scope

The following files, directories, and activities are **explicitly out of scope** and must not be modified, translated, or touched beyond observational access where strictly necessary.

#### 0.3.2.1 Out-of-Scope Showcase Applications

| Directory | Contents | Reason Out of Scope |
|-----------|----------|---------------------|
| `toplip/` | `toplip.asm`, `toplip.o`, `toplip` binary | Not listed as in-scope example app |
| `webslap/` | `webslap.asm`, `worker.inc`, `master.inc`, `master_ui.inc`, `globals.inc`, `tlsmin_defaults.inc`, plus `webslap_tlsmin` variant | Not listed as in-scope example app |
| `dhtool/` | `dhtool.asm`, `dhtool_settings.inc` | Not listed as in-scope example app |
| `util/` | `bigint_tune.asm`, `make_dh_static.asm`, `mersenneprimetest.asm`, `bigger_int_settings.inc` | Not listed as in-scope example app |
| `examples/` | 14 subdirectories containing `echo`, `hello_world*`, `minigzip`, `multicore_echo`, `sha256`, `simplechat_c++`, `simplechat_ssh_auth_c++`, `simplechat_ssh_c++`, `sshecho`, `tlsecho`, `tuieffects`, `tuimatrix` | Not listed as in-scope example app |

#### 0.3.2.2 Library `.inc` Files Used Only by Out-of-Scope Applications

| File | Used By | Disposition |
|------|---------|-------------|
| `htcrypt.inc` | toplip (cascaded AES-256 pipeline) | Not ported; stub placeholder only if required by compilation graph |
| `htxts.inc` | toplip (XTS-AES for file encryption) | Not ported |
| `dh_pool.inc` + `dh_pool_{2k,3k,4k,6k,8k,16k}.inc` | dhtool (static DH safe-prime pools) | Data files — kept as reference; loaded by `heavything::crypto::dh` if needed for TLS DHE suites, otherwise not ported |

Note on DH pools: the TLS subsystem relies on pre-computed safe primes for DHE key exchange. The current assembly code embeds these pools at compile time via `dh_pool.inc`. The Rust port uses `rustls` which manages DH parameters internally for TLS 1.2, so the pools are **not required** by the in-scope binaries. They remain in the repository but are not ported.

#### 0.3.2.3 Preserved Assembly Sources

All 106 `.inc` files and all seven showcase application directories **remain in place** in the repository. The Rust Cargo workspace is added alongside them, not in place of them. This preserves the assembly baseline for:
- Gate 3 benchmark comparison (assembly baseline measurement)
- Historical reference and behavioral verification
- Respect for the GPLv3 copyright of the original authors

#### 0.3.2.4 Out-of-Scope Build Infrastructure

- **FASM toolchain**: `fasm` and `ld` invocations are not altered; the Rust build is additive
- **Shell scripts**: no shell scripts exist in the repository; none are added (cargo handles the build)
- **CI/CD configuration**: no CI configuration exists in the repository; none is added beyond the `.cargo/config.toml` flag enforcement
- **Cross-platform compatibility**: Windows and macOS targets are explicitly out of scope per the prompt ("Linux-only")
- **Cross-architecture compatibility**: ARM, i686, and other architectures are out of scope (`x86_64-unknown-linux-gnu` only)

#### 0.3.2.5 Out-of-Scope Features and Optimizations

- **No new features**: no new protocols, new cipher suites, new TUI widgets, new HTTP methods, new SSH algorithms
- **No architectural expansion**: no microservices, no containerization, no distributed deployment, no service mesh
- **No performance optimizations beyond translation**: SIMD intrinsics via `std::arch` are permitted only where they preserve exact assembly behavior; speculative enhancements (e.g., TLS 1.3 0-RTT if not already present in rustls default) are not added
- **No API surface expansion**: public functions mirror what the assembly exported; no additional public helpers
- **No behavior modifications**: exit codes, HTTP response headers, TLS wire format, SSH wire format, TUI rendering output are all preserved byte-identically where applicable
- **No logging format changes**: syslog output format (RFC 3164 via `AF_UNIX`/`SOCK_DGRAM` to `/dev/log`) is preserved
- **No configuration format changes**: CLI argument parsing for `webserver` preserves the exact `-key value` format used by `rwasa`


## 0.4 Target Design

### 0.4.1 Refactored Structure Planning

The target Rust codebase is a **single Cargo workspace** rooted at `/tmp/blitzy/Blitzy-HeavyThing/master_fc613b/`, containing one library crate (`heavything`) and three binary crates (`sshtalk`, `hnwatch`, `webserver`). The workspace coexists with the preserved assembly sources without modifying them.

#### 0.4.1.1 Target Directory Layout

```
Target:
/tmp/blitzy/Blitzy-HeavyThing/master_fc613b/
│
├── Cargo.toml                          (workspace root manifest)
├── Cargo.lock                          (generated)
├── rust-toolchain.toml                 (stable, 2021 edition)
├── rustfmt.toml
├── clippy.toml
├── .cargo/
│   └── config.toml                     (RUSTFLAGS="-D warnings")
│
├── UNSAFE_AUDIT.md                     (deliverable)
├── BENCHMARK_REPORT.md                 (deliverable)
├── INTEGRATION_SIGNOFF.md              (deliverable)
│
├── crates/
│   ├── heavything/                     (library crate)
│   │   ├── Cargo.toml
│   │   ├── benches/
│   │   │   ├── aes_cbc.rs              (criterion: AES-128-CBC throughput)
│   │   │   ├── sha256.rs               (criterion: SHA-256 throughput)
│   │   │   └── http_roundtrip.rs       (criterion: HTTP round-trip latency)
│   │   ├── tests/
│   │   │   ├── crypto_integration.rs   (KAT vectors vs. assembly outputs)
│   │   │   ├── net_integration.rs      (live TCP/DNS/HTTP)
│   │   │   ├── tui_integration.rs      (rendered-frame comparison)
│   │   │   ├── ds_integration.rs
│   │   │   ├── util_integration.rs
│   │   │   └── ffi_boundary.rs         (per-site tests for every unsafe/FFI boundary)
│   │   └── src/
│   │       ├── lib.rs                  (crate root; pub uses; init(); init_args())
│   │       ├── config.rs               (all compile-time constants from ht_defaults.inc)
│   │       ├── cpu.rs                  (runtime CPUID → has_aesni, has_avx, has_sse*)
│   │       ├── error.rs                (crate-wide error types)
│   │       │
│   │       ├── crypto/
│   │       │   ├── mod.rs
│   │       │   ├── aes.rs              (AES-128/256; ring AEAD + aes crate CBC where needed)
│   │       │   ├── sha1.rs             (ring::digest SHA-1)
│   │       │   ├── sha2.rs             (ring::digest SHA-256, SHA-512)
│   │       │   ├── md5.rs              (md-5 crate from RustCrypto)
│   │       │   ├── hmac.rs             (ring::hmac)
│   │       │   ├── hmac_drbg.rs        (manual DRBG over ring::hmac)
│   │       │   ├── pbkdf2.rs           (ring::pbkdf2)
│   │       │   ├── scrypt.rs           (scrypt crate)
│   │       │   ├── bigint.rs           (num-bigint + num-traits; Miller-Rabin 64 rounds)
│   │       │   ├── dh.rs               (DHE parameters; integrates with rustls)
│   │       │   ├── x509.rs             (webpki / x509-parser wrapper)
│   │       │   └── rng.rs              (HMAC-DRBG seeded from /dev/urandom + rdtsc + gettimeofday; 64-bit discard per 3072 bits)
│   │       │
│   │       ├── net/
│   │       │   ├── mod.rs
│   │       │   ├── io.rs               (IoChain trait; 7 vmethods preserved semantically)
│   │       │   ├── runtime.rs          (tokio runtime builder; replaces epoll$run)
│   │       │   ├── dns.rs              (tokio DNS; 10s timeout)
│   │       │   ├── child.rs            (nix::fork + socketpair; 3 IPC message types)
│   │       │   ├── blacklist.rs        (IP blacklist; 86400s default ban)
│   │       │   ├── url.rs              (url crate wrapper)
│   │       │   ├── http/
│   │       │   │   ├── mod.rs
│   │       │   │   ├── server.rs       (8-stage dispatch pipeline)
│   │       │   │   ├── client.rs       (connection pool; 4 max per host; cookie jar; redirect)
│   │       │   │   ├── headers.rs      (HTTP header constants)
│   │       │   │   ├── mimelike.rs     (mimelike$new_parse equivalent)
│   │       │   │   └── cookiejar.rs
│   │       │   ├── fcgi.rs             (FastCGI client over Unix socket)
│   │       │   ├── tls.rs              (rustls Server/Client config; OCSP stapling hook; PEM reload)
│   │       │   └── ssh/
│   │       │       ├── mod.rs
│   │       │       ├── kex.rs          (diffie-hellman-group-exchange-sha256 ONLY)
│   │       │       ├── cipher.rs       (aes256-cbc via aes + cbc crates; hmac-sha2-256 via ring)
│   │       │       ├── auth.rs         (callback registration; userdb$authenticate equivalent)
│   │       │       ├── compression.rs  (zlib via flate2)
│   │       │       └── server.rs       (server state machine; CBC oracle mitigation; SSH_MSG_IGNORE injection)
│   │       │
│   │       ├── tui/
│   │       │   ├── mod.rs
│   │       │   ├── object.rs           (Widget trait with 35 virtual methods preserved)
│   │       │   ├── render.rs
│   │       │   ├── terminal.rs         (termios raw mode via libc; alternate screen; VT100 ACS)
│   │       │   ├── ansi.rs             (ANSI escape codes)
│   │       │   ├── geometry.rs
│   │       │   ├── gridguts.rs
│   │       │   ├── lock.rs
│   │       │   └── widgets/
│   │       │       ├── mod.rs
│   │       │       ├── panel.rs, background.rs, lines.rs, spacers.rs
│   │       │       ├── label.rs, text.rs, textbox.rs, button.rs, form.rs
│   │       │       ├── simpleauth.rs, alert.rs, bell.rs
│   │       │       ├── progressbar.rs, progressbox.rs, spinner.rs
│   │       │       ├── datagrid.rs, statusbar.rs, newsticker.rs
│   │       │       ├── matrix.rs, typist.rs, splash.rs
│   │       │       ├── effect.rs, effects.rs, png.rs
│   │       │       └── ssh.rs          (tui_ssh.inc equivalent)
│   │       │
│   │       ├── ds/
│   │       │   ├── mod.rs
│   │       │   ├── list.rs             (wraps std::collections::VecDeque where semantically equivalent)
│   │       │   ├── maps.rs             (wraps std::collections::HashMap; stringmap variant; AVL-ordered variant for timers)
│   │       │   ├── buffer.rs           (byte buffer with exact capacity/alignment preservation)
│   │       │   └── memfuncs.rs         (slice copy/fill wrappers; largely omitted in favor of std)
│   │       │
│   │       └── util/
│   │           ├── mod.rs
│   │           ├── string.rs           (Rust String/&str wrappers; UTF-8 native)
│   │           ├── unicodecase.rs      (case mapping tables from unicodecase.inc)
│   │           ├── string_math.rs
│   │           ├── crc.rs              (CRC-32)
│   │           ├── base64.rs           (wrapper over base64 crate; preserves line-break behavior)
│   │           ├── json.rs             (wrapper over serde_json; preserves json.inc API shape)
│   │           ├── zlib.rs             (wrapper over flate2; level 6 default; deflate + inflate)
│   │           ├── png.rs              (wrapper over png crate; used by tui_png)
│   │           ├── formatter.rs        (number formatting)
│   │           ├── math.rs
│   │           ├── date.rs
│   │           ├── file.rs             (direct syscall-backed file ops; mmap via memmap2)
│   │           ├── dir.rs
│   │           ├── sysinfo.rs
│   │           ├── syslog.rs           (RFC 3164 over /dev/log; AF_UNIX SOCK_DGRAM)
│   │           ├── sleeps.rs
│   │           ├── mapped.rs           (mmap helpers; uses memmap2 crate)
│   │           ├── privmapped.rs
│   │           ├── mappedheap.rs
│   │           ├── profiler.rs         (thin wrapper; real profiling via cargo bench)
│   │           └── vdso.rs             (vDSO gettimeofday — Rust std uses vDSO automatically; module kept for API parity)
│   │
│   ├── sshtalk/                        (binary crate — port of sshtalk/sshtalk.asm)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs                 (entry; invokes heavything::init; starts SSH server port 4001)
│   │       ├── userdb.rs               (pipe-delimited flat-file; override userdb$authenticate + userdb$newuser)
│   │       ├── chatroom.rs             (broadcast state; shared via tokio::sync::RwLock)
│   │       ├── chatpanel.rs            (TUI composition; tui_text + tui_textbox widgets)
│   │       ├── screen.rs               (tui_ssh layout)
│   │       └── statusbar.rs
│   │
│   ├── hnwatch/                        (binary crate — port of hnwatch/hnwatch.asm)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs                 (default "Top Stories"; invokes heavything::init; ui::init; epoll run)
│   │       ├── hnmodel.rs              (HTTP client; JSON; periodic polling)
│   │       ├── ui.rs                   (TUI data grid; main_item_limit = 150)
│   │       ├── textify.rs              (HTML → text conversion)
│   │       └── eventstream.rs
│   │
│   └── webserver/                      (binary crate — port of rwasa/rwasa.asm)
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs                 (entry; invokes heavything::init_args)
│           ├── arguments.rs            (CLI parse: -cpu, -runas, -tls, -bind, -fastcgi, -vhost, -sandbox, -funcmatch, -background, -new)
│           ├── master.rs               (bind → drop privs → fork N workers → IPC relay loop)
│           └── worker.rs               (re-seed RNG → new tokio runtime → install hooks → per-worker event loop)
│
└── [PRESERVED: all 106 existing .inc files, 7 showcase directories, LICENSE, README, etc.]
```

#### 0.4.1.2 Cargo Workspace Manifest Strategy

The workspace `Cargo.toml` uses a `[workspace]` declaration with a `members` array listing all four crates. The workspace root also declares shared `[workspace.dependencies]` so every crate pulls identical pinned versions of third-party dependencies.

```toml
[workspace]
members = ["crates/heavything", "crates/sshtalk", "crates/hnwatch", "crates/webserver"]
resolver = "2"
```

A `.cargo/config.toml` at the workspace root enforces the warning-as-error policy globally:

```toml
[build]
rustflags = ["-D", "warnings"]
```

#### 0.4.1.3 Feature Flag Strategy (Replacing `if used` Dead-Code Elimination)

The assembly library's `if used` conditional compilation is replaced by:
- **Cargo features** for coarse-grained inclusion (e.g., `feature = "ssh"`, `feature = "tls"`, `feature = "tui"`)
- **Rust's own link-time dead-code elimination** under `cargo build --release` handles fine-grained function-level elimination automatically
- **`cfg`-gated modules** via `#[cfg(feature = "…")]` for build-time exclusion of entire submodules

Default features enable all five subsystems so the three binary crates compile out of the box.

### 0.4.2 Web Search Research Conducted

The following topics were researched during target-design planning to validate crate selection and translation strategies against current best practices (stable Rust ecosystem as of April 2026):

- **Assembly-to-Rust translation patterns** — best practices for preserving low-level semantics while moving to a memory-safe language; common approaches: extern "C" FFI preservation, `libc` for syscalls, `unsafe` isolation with audit manifests
- **tokio epoll backend architecture** — tokio uses `mio` internally which wraps `epoll` on Linux; this matches the existing hand-rolled `epoll.inc` infrastructure closely, minimizing behavioral divergence
- **rustls TLS 1.2 support** — rustls fully supports TLS 1.2 via default `DEFAULT_CIPHER_SUITES`; DHE key exchange is **not** supported in current rustls (ECDHE only); this is flagged as an architectural divergence requiring special analysis (see Section 0.7)
- **ring AES-CBC exposure** — ring's public API does **not** expose AES-CBC; AES-CBC for SSH transport layer requires the `aes` + `cbc` crates from the RustCrypto project (FIPS 197 compliant, constant-time)
- **SSH2 direct Rust implementation** — implementing SSH2 directly in Rust is uncommon in the ecosystem; `russh`/`thrussh` are canonical, but the prompt's minimal-change clause favors a direct re-implementation to preserve existing ssh.inc wire format behavior exactly
- **Terminal raw mode via libc termios** — the `libc` crate on Linux exposes `tcsetattr`, `tcgetattr`, `cfmakeraw` allowing termios-based raw-mode management without pulling in `crossterm` or `termion`
- **criterion benchmarking with baseline comparison** — `criterion` supports saving baselines (`--save-baseline <name>`) and comparing (`--baseline <name>`), ideal for Gate 3's assembly-vs-Rust comparison
- **Privilege dropping with nix** — `nix::unistd::{setuid, setgid}` and `nix::unistd::fork` provide the Linux-specific syscall wrappers needed to reproduce rwasa's privilege-drop sequence
- **memmap2 crate for mmap** — replaces raw `mmap`/`mremap` syscalls while preserving the mmap-based file-serving path in `webserver.inc`

### 0.4.3 Design Pattern Applications

The following design patterns are applied systematically during translation:

- **Trait-based polymorphism replaces virtual method tables**: the IO chain's 7 vmethods (`io_vdestroy`, `io_vclone`, `io_vconnected`, `io_vsend`, `io_vreceive`, `io_verror`, `io_vtimeout`) become methods on a `trait IoChain: Send + Sync`; TUI's 35 widget vmethods become a `trait Widget`
- **Arc<dyn Trait> replaces pointer-based parent/child chaining**: the 24-byte IO object (vtable + parent + child pointers) becomes a Rust struct with `Arc<dyn IoChain>` parent and child fields, preserving the double-linked chain topology
- **async/await replaces manual event-loop state machines**: the epoll event loop becomes the `tokio` runtime; protocol state machines become `async fn` coroutines where appropriate, falling back to explicit state enums where the assembly logic demands it
- **Typed enum messages replace raw union structs for IPC**: the three `linkmessage_*` types (`linkmessage_log`, `linkmessage_tlsupdate`, `linkmessage_ocsp`) become an `enum LinkMessage` with explicit variants, serialized over `tokio::net::UnixStream` socketpairs
- **Newtype wrapper pattern for FFI primitives**: `c_int`, `size_t`, file descriptors are wrapped in Rust newtypes (`Fd(c_int)`, `SocketPair(Fd, Fd)`) to prevent accidental misuse while preserving exact underlying layout
- **Builder pattern for configuration**: `WebServerConfig::builder()` replaces the hand-built `webservercfg` struct in `webserver.inc`, exposing the same knobs with compile-time checked defaults
- **Drop-based resource cleanup replaces explicit `io_vdestroy` chains**: where assembly walked the chain calling destroy on each layer, Rust's `Drop` implementation on each IO chain struct handles per-layer cleanup; explicit `shutdown` futures handle graceful close
- **`thiserror` + `anyhow` layered error handling**: `thiserror` for library-level typed errors (e.g., `TlsError`, `SshError`, `HttpError`); `anyhow` for binary-level end-user error reporting
- **Feature detection at init, not per-call**: CPU feature flags (`has_aesni`, `has_avx`, `has_sse41`) detected once in `heavything::init()` and stored in `OnceLock<CpuFeatures>`, mirroring `ht$init`'s approach

### 0.4.4 User Interface Design

The TUI framework is translated as a direct Rust implementation per the prompt's explicit directive. Key insights that drive the UI design:

- **No third-party TUI crate**: `ratatui`, `crossterm`, `termion`, `tui` are all prohibited. This rules out any dependency on their widget abstractions
- **Widget hierarchy preservation**: the 32 `tui_*.inc` files map 1:1 to Rust modules under `heavything::tui::widgets`; every widget exposed in the assembly library has a Rust equivalent
- **Rendering engine**: `tui_render.inc` becomes `heavything::tui::render`, handling ANSI escape-code generation, VT100 ACS line-character translation (when `acs_linechars = 1`), and alternate-screen mode (when `terminal_alternatescreen = 1`)
- **Terminal raw mode**: `tui_terminal.inc`'s direct `termios` manipulation becomes direct `libc::tcgetattr` / `libc::tcsetattr` calls in `heavything::tui::terminal`; see Section 0.7 for the site-by-site unsafe rationale
- **SSH TUI rendering**: `tui_ssh.inc`'s SSH-aware renderer (sends ANSI codes over the SSH channel instead of stdout) becomes `heavything::tui::widgets::ssh::SshRenderer`, integrating with `heavything::net::ssh`
- **Input event handling**: keypresses flow in through either stdin (local terminal) or the SSH channel (remote); the Rust design uses a `mpsc::channel<TuiEvent>` that feeds the widget tree, replacing the assembly's direct dispatch from the `io_vreceive` callback
- **Alternate-screen modes preserved**: both `tui_ssh_alternatescreen = 1` and `terminal_alternatescreen = 1` defaults are preserved; the Rust `Terminal` and `SshRenderer` types expose builder methods to change them
- **Widget-level animation timers**: `tui_spinner`, `tui_matrix`, `tui_typist`, `tui_newsticker` and other animated widgets integrate with the epoll timer registration; in Rust this becomes `tokio::time::interval` streams driving per-widget `render()` calls
- **`tui_simpleauth` authentication flow**: the 3 virtual hooks (`tui_simpleauth_vuserpass`, `tui_simpleauth_vtoken`, `tui_simpleauth_vnewuser`) become methods on a `trait SimpleAuthHandler` that `sshtalk`'s `userdb` implements
- **Unicode case tables**: `unicodecase.inc`'s case-mapping tables are preserved verbatim in `heavything::util::unicodecase` to ensure identical case-folding behavior across UTF-8 inputs


## 0.5 Transformation Mapping

### 0.5.1 File-by-File Transformation Plan

The tables below provide a comprehensive mapping from every in-scope assembly source file to its Rust target. Transformation modes are:
- **CREATE** — new Rust file created; the listed assembly file is its behavioral source
- **REFERENCE** — the listed assembly file provides structural patterns only (e.g., using an adjacent file as a stylistic template); no behavior is copied
- **UPDATE** — modify an existing file in the repository

Note: since this is a full library translation with no existing Rust code in the repository, **UPDATE** applies only to `README.md` and (optionally) `.gitignore`; every other Rust file is **CREATE**.

#### 0.5.1.1 Workspace and Configuration Files

| Target File | Transformation | Source File | Key Changes |
|-------------|---------------|-------------|-------------|
| `Cargo.toml` (workspace root) | CREATE | (new) | Declare workspace members, shared dependency versions, resolver="2" |
| `Cargo.lock` | CREATE | (generated) | Auto-generated by `cargo build` |
| `.cargo/config.toml` | CREATE | (new) | Set `rustflags = ["-D", "warnings"]` |
| `rust-toolchain.toml` | CREATE | (new) | Pin stable toolchain, 2021 edition, x86_64-unknown-linux-gnu |
| `rustfmt.toml` | CREATE | (new) | Style configuration |
| `clippy.toml` | CREATE | (new) | Lint configuration |
| `README.md` | UPDATE | `README.md` | Add "Building with Cargo" section; preserve assembly build docs |
| `UNSAFE_AUDIT.md` | CREATE | (deliverable) | Per-site unsafe inventory |
| `BENCHMARK_REPORT.md` | CREATE | (deliverable) | criterion output with assembly baselines |
| `INTEGRATION_SIGNOFF.md` | CREATE | (deliverable) | Gate 8 checklist |

#### 0.5.1.2 Library Crate Root and Configuration

| Target File | Transformation | Source File | Key Changes |
|-------------|---------------|-------------|-------------|
| `crates/heavything/Cargo.toml` | CREATE | (new) | Crate manifest; declare dependencies + features |
| `crates/heavything/src/lib.rs` | CREATE | `ht.inc` | Expose modules; define `pub fn init()` / `pub fn init_args(argc, argv)`; exit-code constants 96–99 |
| `crates/heavything/src/config.rs` | CREATE | `ht_defaults.inc` | All 60+ `pub const` constants (page_size, alignment, epoll_minfds, tls_* knobs, ssh_* knobs, webserver_* knobs, etc.) |
| `crates/heavything/src/cpu.rs` | CREATE | `ht.inc` (CPUID block lines ~290–340) | Runtime CPU feature detection via `std::is_x86_feature_detected!`; `CpuFeatures` struct in `OnceLock` |
| `crates/heavything/src/error.rs` | CREATE | (new) | Crate-wide error types via `thiserror` |

#### 0.5.1.3 Crypto Subsystem — `crates/heavything/src/crypto/`

| Target File | Transformation | Source File | Key Changes |
|-------------|---------------|-------------|-------------|
| `mod.rs` | CREATE | (new) | Module declarations; pub re-exports |
| `aes.rs` | CREATE | `aes.inc` | AES-128/256 wrapper: `ring::aead` for AEAD suites; `aes` + `cbc` crates for raw CBC; runtime AES-NI detection preserved |
| `sha1.rs` | CREATE | `sha1.inc` | SHA-1 via `ring::digest::SHA1_FOR_LEGACY_USE_ONLY` |
| `sha2.rs` | CREATE | `sha2.inc` | SHA-256 and SHA-512 via `ring::digest::{SHA256, SHA512}` |
| `md5.rs` | CREATE | `md5.inc` | MD5 via `md-5` crate (RustCrypto); legacy protocol support only |
| `hmac.rs` | CREATE | `hmac.inc` | HMAC via `ring::hmac`; signing + verification |
| `hmac_drbg.rs` | CREATE | `hmac_drbg.inc` | HMAC-DRBG per NIST SP 800-90A over `ring::hmac`; 64-bit discard per 3072 bits preserved |
| `pbkdf2.rs` | CREATE | `pbkdf2.inc` | PBKDF2 via `ring::pbkdf2` |
| `scrypt.rs` | CREATE | `scrypt.inc` | scrypt via `scrypt` crate; defaults N=1024, r=1, p=1; optional scrypt-SHA512 variant |
| `bigint.rs` | CREATE | `bigint.inc` | BigInt via `num-bigint` + `num-traits`; Miller-Rabin 64 rounds; DSA 3072-bit with 256-bit subgroup |
| `dh.rs` | CREATE | `dh_pool.inc` + `dh_groups.inc` | DH parameter management; integrates with rustls where possible |
| `x509.rs` | CREATE | `X509.inc` | X.509 parsing via `webpki` + `x509-parser`; preserve "garbage-in/garbage-out" no-chain-validation default behavior for server certs |
| `rng.rs` | CREATE | `rng.inc` | HMAC-DRBG seeded from /dev/urandom (or /dev/random when `rng_paranoid = 1`) + rdtsc + gettimeofday; 1408-byte state; 64-bit discard per 3072 bits |

Note on `htcrypt.rs` and `htxts.rs`: these files exist in `ht.inc`'s include chain but service only the out-of-scope `toplip` application. They are **not ported**.

#### 0.5.1.4 Networking Subsystem — `crates/heavything/src/net/`

| Target File | Transformation | Source File | Key Changes |
|-------------|---------------|-------------|-------------|
| `mod.rs` | CREATE | (new) | Module declarations |
| `io.rs` | CREATE | `io.inc` | `trait IoChain: Send + Sync` with 7 async methods preserving directional dispatch: `destroy`, `clone_io`, `connected`, `send`, `receive`, `error`, `timeout`; `Arc<dyn IoChain>` parent/child |
| `runtime.rs` | CREATE | `epoll.inc` | tokio runtime builder; replaces `epoll$run`; preserves event priority ordering (EPOLLHUP/ERR > EPOLLOUT > EPOLLIN) via tokio task polling semantics |
| `dns.rs` | CREATE | `epoll_dns.inc` | Async DNS via `tokio::net::lookup_host`; 10-second timeout; global cache when `webclient_global_dnscache = 1` |
| `child.rs` | CREATE | `epoll_child.inc` | `nix::unistd::fork` + `UnixStream::pair`; 3-message IPC enum (`LinkMessage::Log`, `LinkMessage::TlsUpdate`, `LinkMessage::Ocsp`); `PR_SET_PDEATHSIG SIGTERM` via `prctl` |
| `blacklist.rs` | CREATE | `blacklist.inc` | IP blacklist with 86400s default TTL; used by tls and ssh |
| `url.rs` | CREATE | `url.inc` | URL parsing via `url` crate wrapper |
| `http/mod.rs` | CREATE | (new) | HTTP module aggregator |
| `http/server.rs` | CREATE | `webserver.inc` | HTTP/1.1 server; 8-stage dispatch pipeline preserved (Method → MIME parse → Size → Host → FuncMap → FastCGI → Redirect → File serve); mmap hotlist file cache (900s lifetime, 120s recheck); HSTS + BREACH on TLS |
| `http/client.rs` | CREATE | `webclient.inc` | HTTP/1.1 client; 4 max connections per host; 120s read timeout; redirect following; DNS caching; cookie jar integration |
| `http/headers.rs` | CREATE | `httpheaders.inc` | Static HTTP header name/value constants |
| `http/mimelike.rs` | CREATE | `mimelike.inc` | MIME-like parser for HTTP messages; 1024-byte gzip threshold; 65535-byte chunk size |
| `http/cookiejar.rs` | CREATE | `cookiejar.inc` | Session cookie storage |
| `fcgi.rs` | CREATE | `fcgiclient.inc` | FastCGI client over Unix domain socket; dual IO chain architecture |
| `tls.rs` | CREATE | `tls.inc` | rustls Server/Client configs; cipher suite selection; session cache (3600s TTL, AES-256 encrypted); PEM hot-reload (3600s); OCSP stapling (7200s refresh, 300s retry); IP blacklist on crypto errors (86400s) — see Section 0.7 for state machine mapping |
| `ssh/mod.rs` | CREATE | `ssh.inc` (part) | SSH2 module aggregator |
| `ssh/kex.rs` | CREATE | `ssh.inc` (KEX section) | `diffie-hellman-group-exchange-sha256` exclusively |
| `ssh/cipher.rs` | CREATE | `ssh.inc` (cipher section) | `aes256-cbc` via `aes` + `cbc` crates; `hmac-sha2-256` via `ring::hmac` |
| `ssh/auth.rs` | CREATE | `ssh.inc` (auth section) | Callback registration (`ssh$set_authcb` equivalent); 3-argument callback: connection, username, password |
| `ssh/compression.rs` | CREATE | `ssh.inc` (zlib section) | zlib compression via `flate2`; forced when `ssh_force_compression = 1` |
| `ssh/server.rs` | CREATE | `ssh.inc` (state machine) | Full server state machine; CBC oracle mitigation (randomized packet length on bad HMAC); SSH_MSG_IGNORE injection before password auth; OpenSSH 8.x+ interop preserved |

#### 0.5.1.5 TUI Subsystem — `crates/heavything/src/tui/`

| Target File | Transformation | Source File | Key Changes |
|-------------|---------------|-------------|-------------|
| `mod.rs` | CREATE | (new) | Module declarations |
| `object.rs` | CREATE | `tui_object.inc` | `trait Widget` with all 35 virtual methods from the assembly base class preserved |
| `render.rs` | CREATE | `tui_render.inc` | ANSI escape generation; VT100 ACS line-char translation |
| `terminal.rs` | CREATE | `tui_terminal.inc` | termios raw-mode via `libc::tcsetattr` / `libc::tcgetattr` / `libc::cfmakeraw`; alternate-screen mode |
| `ansi.rs` | CREATE | `tui_ansi.inc` | ANSI color/cursor escape constants |
| `geometry.rs` | CREATE | `tui_geometry.inc` | Layout math |
| `gridguts.rs` | CREATE | `tui_gridguts.inc` | Grid sub-layout primitives |
| `lock.rs` | CREATE | `tui_lock.inc` | TUI rendering mutex (tokio::sync::Mutex equivalent) |
| `widgets/mod.rs` | CREATE | (new) | Widget module aggregator |
| `widgets/panel.rs` | CREATE | `tui_panel.inc` | Container widget |
| `widgets/background.rs` | CREATE | `tui_background.inc` | Background fill widget |
| `widgets/lines.rs` | CREATE | `tui_lines.inc` | Line-drawing widget |
| `widgets/spacers.rs` | CREATE | `tui_spacers.inc` | Layout spacers |
| `widgets/label.rs` | CREATE | `tui_label.inc` | Static text label |
| `widgets/text.rs` | CREATE | `tui_text.inc` | Multi-line text display |
| `widgets/textbox.rs` | CREATE | `tui_textbox.inc` | Editable text input |
| `widgets/button.rs` | CREATE | `tui_button.inc` | Clickable button |
| `widgets/form.rs` | CREATE | `tui_form.inc` | Form container; field collection |
| `widgets/simpleauth.rs` | CREATE | `tui_simpleauth.inc` | Pre-built authentication screen; 3 virtual hooks (`vuserpass`, `vtoken`, `vnewuser`) |
| `widgets/alert.rs` | CREATE | `tui_alert.inc` | Modal alert dialog |
| `widgets/bell.rs` | CREATE | `tui_bell.inc` | Terminal bell emission |
| `widgets/progressbar.rs` | CREATE | `tui_progressbar.inc` | Horizontal progress indicator |
| `widgets/progressbox.rs` | CREATE | `tui_progressbox.inc` | Boxed progress with label |
| `widgets/spinner.rs` | CREATE | `tui_spinner.inc` | Animated spinner |
| `widgets/datagrid.rs` | CREATE | `tui_datagrid.inc` | Scrollable data grid (used by hnwatch) |
| `widgets/statusbar.rs` | CREATE | `tui_statusbar.inc` | Bottom-row status bar |
| `widgets/newsticker.rs` | CREATE | `tui_newsticker.inc` | Horizontal scrolling text |
| `widgets/matrix.rs` | CREATE | `tui_matrix.inc` | Matrix-rain effect |
| `widgets/typist.rs` | CREATE | `tui_typist.inc` | Typewriter animation |
| `widgets/splash.rs` | CREATE | `tui_splash.inc` | Splash-screen composition |
| `widgets/effect.rs` | CREATE | `tui_effect.inc` | Generic effect base |
| `widgets/effects.rs` | CREATE | `tui_effects.inc` | Effect catalog |
| `widgets/png.rs` | CREATE | `tui_png.inc` | PNG image rendering to terminal |
| `widgets/ssh.rs` | CREATE | `tui_ssh.inc` | SSH-aware renderer; integrates with `heavything::net::ssh` |

#### 0.5.1.6 Data Structures Subsystem — `crates/heavything/src/ds/`

| Target File | Transformation | Source File | Key Changes |
|-------------|---------------|-------------|-------------|
| `mod.rs` | CREATE | (new) | Module declarations |
| `list.rs` | CREATE | `list.inc` | Doubly-linked-list semantics preserved where needed; `std::collections::VecDeque` for sequential access; custom linked list only where `list$foreach` callback-based iteration demands it |
| `maps.rs` | CREATE | `maps.inc` | `std::collections::HashMap` for stringmap; custom AVL-tree map for ordered iteration (needed by epoll timer AVL walk) |
| `buffer.rs` | CREATE | `buffer.inc` | Byte buffer with exact capacity semantics (`heap$alloc`-aligned to 64-byte bins); wraps `Vec<u8>` with capacity-preserving API |
| `memfuncs.rs` | CREATE | `memfuncs.inc` | Slice copy / fill / compare wrappers; largely thin re-exports of `slice::copy_from_slice`, `slice::fill`, `slice::eq` |

Note on `heap.inc`: the custom bin allocator with never-return-to-kernel policy is **not ported**. The Rust port uses the standard `std` allocator (typically jemalloc or the system allocator). This is intentional: (a) the assembly allocator is an optimization for servers that out-lives the life of a Rust process, (b) the `std` allocator is well-tested and idiomatic, (c) the external behavior (fast allocation, bounded RSS growth) is preserved by the OS-level allocator. Per the prompt: "Data structures (heap, maps, lists, buffers) MUST use std collections where semantically equivalent" — this applies directly.

Note on `mappedheap.inc`: this heap-over-mmap implementation (used for TLS session cache) is ported to `heavything::util::mappedheap` and uses the `memmap2` crate.

#### 0.5.1.7 Utility Subsystem — `crates/heavything/src/util/`

| Target File | Transformation | Source File | Key Changes |
|-------------|---------------|-------------|-------------|
| `mod.rs` | CREATE | (new) | Module declarations |
| `string.rs` | CREATE | `string32.inc` (primary) + `string16.inc` (alternative) | Rust `String`/`&str`; UTF-8 native (transparently supports UTF-32 semantics for case mapping since every codepoint representable); the `string_bits` compile-time toggle is simplified to always use Rust native strings |
| `unicodecase.rs` | CREATE | `unicodecase.inc` | Case mapping tables ported verbatim from assembly; used for locale-independent Unicode case folding |
| `string_math.rs` | CREATE | `string_math.inc` | Arbitrary-precision decimal string math (used by formatter) |
| `crc.rs` | CREATE | `crc.inc` | CRC-32 (IEEE 802.3 polynomial) — may use `crc32fast` crate or direct implementation |
| `base64.rs` | CREATE | `base64_latin1.inc` | Base64 encode/decode; wraps `base64` crate; preserves `base64_linebreaks = 1` and `base64_maxline = 76` defaults |
| `json.rs` | CREATE | `json.inc` | Wraps `serde_json`; preserves `json.inc` API shape for callers in hnwatch |
| `zlib.rs` | CREATE | `zlib_deflate.inc` + `zlib_inflate.inc` | Wraps `flate2`; default deflate level 6 preserved (`zlib_deflate_level`) |
| `png.rs` | CREATE | `png.inc` | PNG image parsing via `png` crate; used by `tui_png` widget |
| `formatter.rs` | CREATE | `formatter.inc` | Numeric formatting (thousands separator, scientific, etc.) |
| `math.rs` | CREATE | `math.inc` | Math helpers (GCD, LCM, basic FP ops — actual heavy math via `num-traits`) |
| `date.rs` | CREATE | `date.inc` | Date/time handling; HTTP Date header formatting; preserves RFC 1123 output format |
| `file.rs` | CREATE | `file.inc` | File I/O helpers via `std::fs` + direct syscalls where assembly does |
| `dir.rs` | CREATE | `dir.inc` | Directory enumeration via `std::fs::read_dir` |
| `sysinfo.rs` | CREATE | `sysinfo.inc` | `uname` syscall results; exposes `sysname`, `nodename`, `release`, `version`, `machine` |
| `syslog.rs` | CREATE | `syslog.inc` | RFC 3164 syslog messages over `AF_UNIX` `SOCK_DGRAM` to `/dev/log`; OCSP activity when `X509_ocsp_syslog = 1` |
| `sleeps.rs` | CREATE | `sleeps.inc` | `nanosleep` wrappers via `std::thread::sleep` and `tokio::time::sleep` |
| `mapped.rs` | CREATE | `mapped.inc` | mmap-backed file access via `memmap2::Mmap` |
| `privmapped.rs` | CREATE | `privmapped.inc` | Private mmap (MAP_PRIVATE) variant |
| `mappedheap.rs` | CREATE | `mappedheap.inc` | Heap-over-mmap allocator used by TLS session cache |
| `profiler.rs` | CREATE | `profiler.inc` | Thin API-preservation wrapper; actual profiling delegated to `cargo bench` + `criterion`; CPC records omitted |
| `vdso.rs` | CREATE | `vdso.inc` | API-preservation stub; Rust `std::time::SystemTime::now()` uses vDSO automatically on Linux |

Note on macros (`align_macros.inc`, `call.inc`, `cleartext.inc`, `dataseg_macros.inc`, `breakpoint.inc`, `rdtsc.inc`, `syscall.inc`): these are FASM macros with no runtime behavior. They do not port to Rust files; their semantics are absorbed into the Rust compiler's code generation, macro system, or direct `libc` calls.

#### 0.5.1.8 Binary Crate: `webserver` — port of `rwasa/`

| Target File | Transformation | Source File | Key Changes |
|-------------|---------------|-------------|-------------|
| `crates/webserver/Cargo.toml` | CREATE | (new) | Binary crate manifest; dependencies on `heavything`, `tokio`, `nix`, `clap` (or manual parse) |
| `crates/webserver/src/main.rs` | CREATE | `rwasa/rwasa.asm` | Entry point: `heavything::init_args` → parse args → build master → enter tokio runtime |
| `crates/webserver/src/arguments.rs` | CREATE | `rwasa/arguments.inc` | CLI parser preserving exact flags: `-cpu N`, `-runas USER`, `-tls PEM`, `-bind ADDR:PORT`, `-fastcgi PATTERN ADDR`, `-vhost HOST`, `-sandbox PATH`, `-funcmatch PATTERN`, `-background`, `-new` |
| `crates/webserver/src/master.rs` | CREATE | `rwasa/master.inc` | Master lifecycle: bind → setgid → setuid → fork workers → destroy delayed listeners → 1.5s log flush timer → IPC relay loop |
| `crates/webserver/src/worker.rs` | CREATE | `rwasa/worker.inc` | Worker lifecycle: `PR_SET_PDEATHSIG SIGTERM` → `rng` re-seed → new tokio runtime → install log/tls hooks → event loop |

Note: the `rwasa_tlsmin.asm` + `tlsmin_defaults.inc` TLS-minimalist variant is **out of scope** (a secondary variant not requested in the three in-scope example apps). If a minimalist variant is desired later, it is a feature flag on the `webserver` crate, not a separate binary.

#### 0.5.1.9 Binary Crate: `sshtalk` — port of `sshtalk/`

| Target File | Transformation | Source File | Key Changes |
|-------------|---------------|-------------|-------------|
| `crates/sshtalk/Cargo.toml` | CREATE | (new) | Binary crate manifest |
| `crates/sshtalk/src/main.rs` | CREATE | `sshtalk/sshtalk.asm` | Entry: `heavything::init` → userdb init → SSH server on port 4001 → epoll run |
| `crates/sshtalk/src/userdb.rs` | CREATE | `sshtalk/userdb.inc` | Pipe-delimited flat-file user database (`username\|password\|buddy1\|…`); override `userdb$authenticate` + `userdb$newuser`; load/persist at startup/shutdown |
| `crates/sshtalk/src/chatroom.rs` | CREATE | `sshtalk/chatroom.inc` | Shared chat state; broadcast to all connected TUI clients; `tokio::sync::RwLock<Vec<ChatEntry>>` |
| `crates/sshtalk/src/chatpanel.rs` | CREATE | `sshtalk/chatpanel.inc` | TUI composition of chat history + input field |
| `crates/sshtalk/src/screen.rs` | CREATE | `sshtalk/screen.inc` | TUI layout inside SSH session (`tui_ssh` → SSH → epoll chain) |
| `crates/sshtalk/src/statusbar.rs` | CREATE | `sshtalk/statusbar.inc` | Bottom status bar (connected users, current room) |

Missing SSH host keys in `/etc/ssh` → stderr error + exit 1 (preserves existing behavior).

#### 0.5.1.10 Binary Crate: `hnwatch` — port of `hnwatch/`

| Target File | Transformation | Source File | Key Changes |
|-------------|---------------|-------------|-------------|
| `crates/hnwatch/Cargo.toml` | CREATE | (new) | Binary crate manifest |
| `crates/hnwatch/src/main.rs` | CREATE | `hnwatch/hnwatch.asm` | Entry: `heavything::init` → default navstring "topstories" → `hnmodel::init` → `ui::init` → `epoll::run`; `main_item_limit = 150` global |
| `crates/hnwatch/src/hnmodel.rs` | CREATE | `hnwatch/hnmodel.inc` | HTTP client (HTTPS) to Hacker News API; JSON parsing via `heavything::util::json`; periodic polling |
| `crates/hnwatch/src/ui.rs` | CREATE | `hnwatch/ui.inc` | TUI data grid + panels; keybindings; reactive update on model change |
| `crates/hnwatch/src/textify.rs` | CREATE | `hnwatch/textify.inc` | HTML → plain-text conversion for story bodies |
| `crates/hnwatch/src/eventstream.rs` | CREATE | `hnwatch/eventstream.inc` | HN events / firebase streaming adaptation; async tokio stream |

### 0.5.2 Cross-File Dependencies

#### 0.5.2.1 Import Statement Transformation Rules

Existing assembly includes via `include 'X.inc'` become Rust module references. The most common transformations:

| FASM Include Pattern | Rust Equivalent |
|---------------------|-----------------|
| `include 'ht.inc'` in any file | `use heavything;` at crate root; specific items via `use heavything::{crypto, net, tui, ds, util};` |
| `include 'epoll.inc'` | `use heavything::net::runtime;` (tokio Runtime) |
| `include 'io.inc'` | `use heavything::net::io::IoChain;` |
| `include 'aes.inc'` | `use heavything::crypto::aes;` |
| `include 'tls.inc'` | `use heavything::net::tls;` |
| `include 'ssh.inc'` | `use heavything::net::ssh;` |
| `include 'webserver.inc'` | `use heavything::net::http::server;` |
| `include 'tui_*.inc'` | `use heavything::tui::widgets::*;` |
| `include 'json.inc'` | `use heavything::util::json;` |
| Cross-app includes (e.g., `sshtalk/screen.inc` includes `tui_ssh.inc`) | `use heavything::tui::widgets::ssh::SshRenderer;` within `sshtalk` crate |

#### 0.5.2.2 Symbol-Level Transformation Examples

- **Old**: `call webserver$new_listener`, `call webserver$connected`, `call tls$new_server`
- **New**: `http::server::WebServer::new_listener(...)`, `http::server::WebServer::on_connected(...)`, `tls::ServerConfig::new(...)`

- **Old**: `mov qword [ssh_authcb_ofs + rax], rdi` (register-based callback installation)
- **New**: `ssh_server.set_auth_callback(Box::new(|conn, user, pass| { ... }))`

- **Old**: `call heap$alloc`, `call heap$free`
- **New**: Direct Rust owned types (`Box<T>`, `Vec<T>`); `Drop` handles deallocation automatically

- **Old**: Global via `globals { ... }` block
- **New**: Module-level `static` (for compile-time constants) or `OnceLock<T>` (for lazily-initialized singletons)

#### 0.5.2.3 Configuration File Transformation

The 60+ compile-time constants in `ht_defaults.inc` are translated to a single `heavything::config` module with public constants:

```rust
pub const PAGE_SIZE: usize = 4096;
pub const EPOLL_MINFDS: u32 = 4096;
pub const EPOLL_READSIZE: usize = 32_768;
pub const WEBSERVER_MAXHEADER: usize = 32_768;
pub const WEBSERVER_MAXREQUEST: usize = 64 * 1024 * 1024;
pub const TLS_SERVER_SESSIONCACHE: u64 = 3600;
pub const TLS_PEM_REFRESH_INTERVAL: u64 = 3600;
pub const SSH_BLACKLIST: u64 = 86_400;
pub const DH_BITS: u32 = 2048;
pub const SCRYPT_N: u32 = 1024;
pub const MILLERRABIN_ERROR_RATE: u32 = 64;
// ...and so on for all ~60 constants
```

Behavioral knobs with multiple valid values (e.g., `string_bits = 32|16`) are collapsed to the default (UTF-8 Rust strings). Debug knobs (`heap_bincheck`, `heap_barriers`, `profiling`, `calltracing`) are covered by Cargo features rather than const flags.

### 0.5.3 Wildcard Patterns

Wildcards are used sparingly and **only trailing patterns**. The following blanket patterns apply:

- `crates/heavything/src/**/*.rs` | CREATE — all library crate source files
- `crates/heavything/benches/*.rs` | CREATE — all criterion benchmarks
- `crates/heavything/tests/*.rs` | CREATE — all integration tests
- `crates/{sshtalk,hnwatch,webserver}/src/**/*.rs` | CREATE — all binary crate sources
- Preserved existing `.inc` / `.asm` files: no wildcard applies; every existing file stays unmodified

### 0.5.4 One-Phase Execution

The entire refactor is executed by the Blitzy platform **in a single phase**. The deliverable comprises:
- Complete `heavything` library crate with all five subsystems
- All three binary crates (`sshtalk`, `hnwatch`, `webserver`) functional
- All `criterion` benchmarks written and measured against assembly baselines
- All integration tests passing
- `UNSAFE_AUDIT.md`, `BENCHMARK_REPORT.md`, and `INTEGRATION_SIGNOFF.md` deliverables complete

No partial delivery is acceptable per Gate 7. All 106 in-scope `.inc` file translations, all three binary crates, all five integration tests, all three benchmarks, and all three deliverable documents ship together.


## 0.6 Dependency Inventory

### 0.6.1 Key Public Packages

The following public `crates.io` dependencies form the backbone of the Rust translation. The prompt explicitly names several of these crates; others are supporting packages whose inclusion is mandated by the named crates' APIs (e.g., `aes` + `cbc` are required because `ring` does not expose raw AES-CBC). Version pins target stable releases known to compile on stable Rust 2021 edition for `x86_64-unknown-linux-gnu`.

| Registry | Package | Version | Purpose |
|----------|---------|---------|---------|
| crates.io | `tokio` | `1` | Async runtime with epoll backend; replaces hand-rolled `epoll.inc` loop; provides `net::TcpListener`, `net::TcpStream`, `net::UnixStream`, `time::interval`, `sync::Mutex`, `sync::RwLock`, `sync::mpsc` |
| crates.io | `tokio-util` | `0.7` | Codec helpers (LengthDelimited, LinesCodec) used by HTTP/1.1 parser and SSH packet framing |
| crates.io | `ring` | `0.17` | Cryptographic primitives: SHA-1 (legacy), SHA-256, SHA-512, HMAC, HMAC-DRBG (manual via `ring::hmac`), PBKDF2, AES-AEAD; replaces `sha1.inc`, `sha2.inc`, `hmac.inc`, `hmac_drbg.inc`, `pbkdf2.inc`, and AES-AEAD paths of `aes.inc` |
| crates.io | `rustls` | `0.23` | TLS 1.2 and TLS 1.3 implementation; replaces `tls.inc` handshake state machine; integrates with webpki for X.509 |
| crates.io | `rustls-pemfile` | `2` | PEM certificate + private key parsing for rustls configuration |
| crates.io | `rustls-webpki` | `0.102` | X.509 certificate-chain validation for rustls (note: current rustls bundles webpki; exact package name tracked in Cargo.lock) |
| crates.io | `webpki-roots` | `0.26` | Mozilla root CA bundle for TLS client certificate validation (used by `webclient` in hnwatch's HTTPS calls to `news.ycombinator.com` API) |
| crates.io | `aes` | `0.8` | Raw AES block cipher (128/256-bit) from RustCrypto; required by SSH `aes256-cbc` transport because `ring` does not expose raw AES-CBC |
| crates.io | `cbc` | `0.1` | CBC mode of operation from RustCrypto; combined with `aes` for SSH transport encryption |
| crates.io | `md-5` | `0.10` | MD5 hash from RustCrypto; replaces `md5.inc` (legacy protocol support only — not used for security) |
| crates.io | `scrypt` | `0.11` | scrypt KDF per RFC 7914; defaults N=1024, r=1, p=1; replaces `scrypt.inc` |
| crates.io | `num-bigint` | `0.4` | Arbitrary-precision integer arithmetic; replaces `bigint.inc` |
| crates.io | `num-traits` | `0.2` | Numeric traits (Zero, One, Pow) used by `num-bigint` |
| crates.io | `num-integer` | `0.1` | GCD, LCM helpers |
| crates.io | `flate2` | `1` | zlib deflate/inflate; replaces `zlib_deflate.inc` + `zlib_inflate.inc` |
| crates.io | `serde_json` | `1` | JSON parsing and serialization; replaces `json.inc` |
| crates.io | `serde` | `1` | Serialization framework required by `serde_json` |
| crates.io | `base64` | `0.22` | Base64 encode/decode; replaces `base64_latin1.inc`; preserves 76-char line-break default |
| crates.io | `url` | `2` | URL parsing; replaces `url.inc` |
| crates.io | `png` | `0.17` | PNG image decoding; used by `tui_png` widget; replaces `png.inc` |
| crates.io | `libc` | `0.2` | Raw syscall and `termios` / `setuid` / `setgid` / `fork` / `prctl` bindings at exactly the sites where assembly makes direct syscalls |
| crates.io | `nix` | `0.29` | Higher-level Linux syscall wrappers (`nix::unistd::{fork, setuid, setgid}`, `nix::sys::socket::{socketpair}`, `nix::sys::prctl`); used in master-worker process management |
| crates.io | `memmap2` | `0.9` | mmap-backed file access; replaces `mmap`/`mremap` syscalls in `mapped.inc`, `privmapped.inc`, `mappedheap.inc`, and the `webserver.inc` file hotlist cache |
| crates.io | `bytes` | `1` | Zero-copy byte-buffer utilities; complements `tokio-util` codecs |
| crates.io | `thiserror` | `1` | Derive-macro-based error types for library-level errors |
| crates.io | `anyhow` | `1` | Application-level error handling in the three binary crates |
| crates.io | `crc32fast` | `1` | CRC-32 IEEE 802.3 implementation; replaces `crc.inc` |
| crates.io | `once_cell` | `1` | `Lazy`/`OnceCell` for lazy static initialization (e.g., CPU feature flags); note stable Rust now provides `OnceLock` in `std` so `once_cell` usage may be minimized |
| crates.io | `criterion` | `0.5` | Benchmarking harness with baseline save/compare support; required for `BENCHMARK_REPORT.md` delivery |
| crates.io | `atty` or `is-terminal` | `0.2` / `0.4` | Terminal detection for TUI raw-mode activation (optional; can be done via `libc::isatty` directly) |

**Dev-dependency-only crates** (used in tests and benchmarks, not shipped in release binaries):

| Registry | Package | Version | Purpose |
|----------|---------|---------|---------|
| crates.io | `criterion` | `0.5` | Benchmarking (dev-dependency of `heavything`) |
| crates.io | `hex` | `0.4` | Hex encoding for known-answer test vectors in `crypto_integration.rs` |
| crates.io | `tempfile` | `3` | Temporary file handling in integration tests |
| crates.io | `tokio-test` | `0.4` | Async test harness helpers |

### 0.6.2 Key Private Packages

**None**. Per the prompt: "Internal dependencies: None; all dependencies sourced from crates.io". No private registry authentication is required for build, test, or bench.

### 0.6.3 Dependency Updates

#### 0.6.3.1 Import Refactoring

Since this is a greenfield Rust codebase with no pre-existing Rust imports, there are no import-statement updates in existing Rust files. However, the FASM `include` directives in the assembly sources are **not modified**; the existing assembly files continue to use their original includes since the assembly tree is preserved as-is.

The only "imports" created by this refactor are Rust `use` statements in the new Rust files, which are authored in their final form. No transformation of existing Rust imports occurs.

Files requiring import declarations (newly created):
- `crates/heavything/src/**/*.rs` — all new sources use `use` statements declaring dependencies on `tokio`, `ring`, `rustls`, etc.
- `crates/{sshtalk,hnwatch,webserver}/src/**/*.rs` — each binary crate declares `use heavything::{…}` plus app-level dependencies

Import transformation rules applied uniformly:
- Old (FASM): `include 'aes.inc'` produces no Rust import — inclusion is via Cargo manifest plus `use heavything::crypto::aes;` in consuming files
- Old (FASM): `call webserver$new_listener` → `http::server::WebServer::new_listener(…)` at the Rust call site, with `use heavything::net::http::server::WebServer;` at file top
- Apply to: every newly created Rust source file

#### 0.6.3.2 External Reference Updates

The following external references require updating to reflect the new Rust build chain:

- `README.md` — add a new section titled "Building with Cargo" documenting `cargo build --release`, `cargo run --bin {sshtalk|hnwatch|webserver}`, `cargo bench`, `cargo test`; preserve existing "Building with FASM" section
- **No configuration files** (`.json`, `.yaml`, `.toml` outside of Cargo.toml / rustfmt.toml) require updating because the repository has no such files pre-existing
- **No build files** (no `setup.py`, no `package.json`, no `Makefile`) pre-exist; only the new `Cargo.toml` files are added
- **No CI/CD files** (no `.github/workflows/*.yml`, no `.gitlab-ci.yml`) pre-exist; none are added beyond the `.cargo/config.toml` flag enforcement
- **No documentation files** (no `docs/**/*.md`) pre-exist beyond `README.md` and `ChangeLog`; `ChangeLog` is not modified (it tracks historical FASM releases)

#### 0.6.3.3 Version Pinning Strategy

All dependencies are pinned via major/minor version constraints in workspace `Cargo.toml`:
- Named crates from the prompt (`tokio`, `ring`, `rustls`, `scrypt`, `flate2`, `serde_json`, `criterion`) use their current stable major version
- Supplementary crates use the most recent stable release compatible with the named-crate versions
- The generated `Cargo.lock` is committed (standard for workspaces with binary crates) to ensure reproducible builds across Gate 2 environments

```toml
[workspace.dependencies]
tokio        = { version = "1", features = ["full"] }
tokio-util   = { version = "0.7", features = ["codec"] }
ring         = "0.17"
rustls       = "0.23"
rustls-pemfile = "2"
webpki-roots = "0.26"
aes          = "0.8"
cbc          = "0.1"
md-5         = "0.10"
scrypt       = "0.11"
num-bigint   = "0.4"
num-traits   = "0.2"
flate2       = "1"
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"
base64       = "0.22"
url          = "2"
png          = "0.17"
libc         = "0.2"
nix          = { version = "0.29", features = ["user", "process", "fs", "socket", "signal"] }
memmap2      = "0.9"
bytes        = "1"
thiserror    = "1"
anyhow       = "1"
crc32fast    = "1"
once_cell    = "1"

[workspace.dev-dependencies]
criterion    = "0.5"
hex          = "0.4"
tempfile     = "3"
tokio-test   = "0.4"
```

#### 0.6.3.4 Toolchain Pinning

`rust-toolchain.toml` at the workspace root pins the exact toolchain to ensure reproducible Gate 2 builds:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
targets = ["x86_64-unknown-linux-gnu"]
profile = "minimal"
```

The project is tested against the current stable channel; MSRV (minimum supported Rust version) is not formally declared but aligns with the stable channel at the time of Gate 2 verification.


## 0.7 Special Analysis

The prompt explicitly requires increased visibility in the Agent Action Plan for four specific refactoring concerns: (a) the epoll-to-tokio translation approach, (b) the TLS/X.509 state-machine mapping to rustls, (c) TUI raw-mode syscall handling, and (d) unsafe block site-by-site rationale. This section provides in-depth analyses for each, with concrete behavioral, architectural, and validation details that downstream code-generation agents must preserve.

### 0.7.1 epoll-to-tokio Translation Approach

The `epoll.inc` file (3,512 lines) implements a hand-rolled event-loop that is the beating heart of every HeavyThing network application. Translating it to `tokio` is the single highest-risk element of the refactor because subtle behavioral regressions can cause connection-handling, timer-firing, or back-pressure anomalies that pass unit tests but fail Gate 1 live smoke tests.

#### 0.7.1.1 Baseline Behavior That Must Be Preserved

| Behavior | Source | Target in Rust |
|----------|--------|----------------|
| Event priority: EPOLLHUP/EPOLLERR (0x18) > EPOLLOUT (0x4) > EPOLLIN on listener > EPOLLIN on data | `epoll.inc` dispatch ordering | `tokio` processes ready events in FD registration order; errors bubble via `Poll::Ready(Err)`; forced `on_error` callback pre-empts `on_receive` in IO chain `poll` implementation |
| AVL-tree-ordered timers with 1.5s log flush, 30s HTTP idle, 7200s OCSP, etc. | `epoll.inc` timer walk at top of each iteration | `tokio::time::interval` per timer + per-connection `tokio::time::timeout`; AVL ordering is implicit in tokio's delay queue |
| Multiple accepts per iteration when `epoll_multiple_accepts = 1` | `epoll.inc` accept4 loop | `tokio::net::TcpListener::accept` in a loop until `WouldBlock`; spawned as background accept task |
| Socket defaults: keepalive=1, linger=0, nodelay=1, non-blocking | `epoll.inc` socket init path | Applied via `tokio::net::TcpSocket` configuration methods; `set_nodelay(true)`, `set_keepalive(true)`, `set_linger(None)` |
| `epoll_readsize` = 32,768 bytes per read | `epoll.inc` read buffer sizing | Per-connection `BytesMut::with_capacity(32_768)` |
| `epoll_minfds` = 4096 ulimit requirement | `epoll.inc` `setrlimit` call | Check `getrlimit(RLIMIT_NOFILE)` at `heavything::init`; exit 97 if cur < 4096; attempt `setrlimit` to raise |
| `epoll_create` failure → exit 96 | `epoll.inc` error path | `tokio::runtime::Builder::new_multi_thread().enable_all().build()` failure → exit 96 |
| IO chain 7-method virtual dispatch (destroy/clone/send/connected/receive/error/timeout) | `io.inc` vtable | `trait IoChain: Send + Sync + 'static` with 7 `async fn` methods; default impls forward to `parent` or `child` based on directional semantics |
| Forward dispatch (destroy/clone/send) walks toward kernel/epoll | `io.inc` walk-down logic | `trait IoChain::forward()` helper walks `child` pointer chain until `None`; last layer is the tokio-managed socket |
| Backward dispatch (connected/receive/error/timeout) walks toward application | `io.inc` walk-up logic | `trait IoChain::backward()` helper walks `parent` pointer chain; application layer is the outermost |
| `epoll$inbound` / `epoll$outbound` utility functions to locate the FD | `epoll.inc` | `IoChain::find_fd()` helper method returns the underlying `tokio::net::TcpStream` FD |
| Timer return value convention (`0` = reset, non-zero = fatality/teardown) | `epoll.inc` timer dispatch | `enum TimerAction { Reset, Teardown(TeardownReason) }` returned from timer closure |
| `EPOLLHUP/EPOLLERR` → `io_verror` backward → `epoll$fatality` → `io_vdestroy` per layer | `epoll.inc` error handling | `IoChain::on_error()` propagates backward, then tokio's `Drop` semantics invoke per-layer teardown |

#### 0.7.1.2 Translation Strategy

The high-level strategy is: **the tokio runtime replaces `epoll$run`; the IO chain trait replaces the vtable; per-connection state is owned by a `tokio::task::JoinHandle` spawned from the accept loop**.

```rust
// Pseudocode illustrating the translation
pub async fn run() -> Result<(), RuntimeError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RuntimeError::EpollCreateFailed)?; // -> exit 96

    rt.block_on(async {
        // Setup listeners (replaces epoll$add for listener sockets)
        let listener = TcpListener::bind(addr).await?;
        
        // Accept loop with multiple-accepts-per-iteration semantics
        loop {
            let (stream, peer) = listener.accept().await?;
            let chain = build_io_chain(stream);  // wraps stream in IoChain layers
            tokio::spawn(connection_handler(chain, peer));
        }
    })
}
```

Worker-process architecture (for `webserver`):
- Master process calls `nix::unistd::fork()` N times to create workers (equivalent to `epoll_child.inc` `epoll_child$spawn`)
- Each worker inherits the bound TCP listener file descriptor via `fork`
- Each worker builds its own `tokio::runtime::Runtime` and runs its own accept loop
- Master process relays three IPC message types over `tokio::net::UnixStream` socketpairs: `LinkMessage::Log`, `LinkMessage::TlsUpdate`, `LinkMessage::Ocsp`
- Master uses `prctl(PR_SET_PDEATHSIG, SIGTERM)` so workers die if master dies — preserved via `nix::sys::prctl::set_pdeathsig(Signal::SIGTERM)`

#### 0.7.1.3 Behavioral Risk Areas

The following risks demand targeted integration tests:

- **Back-pressure behavior**: the assembly loop uses synchronous buffer-fill-and-flush; tokio's async model introduces task-switching that can reorder writes; mitigation is to keep per-connection state serialized within a single task
- **Connection-limit edge cases**: tokio's default task scheduler is multi-threaded; the assembly is single-threaded per worker. The Rust port must preserve per-connection state locality (no lock-free sharding) to match existing behavior
- **Timer drift under load**: tokio's timer wheel resolution is 1ms; this matches or exceeds the assembly's resolution
- **Graceful shutdown**: the assembly's `_epoll_bailout` flag → Rust's `tokio::signal::unix` for SIGTERM + cooperative task cancellation
- **EPOLLET vs EPOLLLT mode**: confirm whether the assembly uses edge-triggered or level-triggered epoll; tokio uses edge-triggered via mio; if the assembly uses level-triggered the read-ready semantics differ
- **`accept4` vs `accept`**: the assembly uses `accept4` with `SOCK_NONBLOCK | SOCK_CLOEXEC`; tokio's `TcpListener::accept` uses `accept4` internally on Linux, preserving this behavior

### 0.7.2 TLS / X.509 State Machine Mapping to rustls

The assembly TLS implementation in `tls.inc` (6,866 lines) is a full TLS 1.2 engine with cipher-suite negotiation, session caching (AES-256 encrypted), PEM hot-reload, OCSP stapling, IP blacklisting on crypto errors, and a "garbage-in/garbage-out" certificate-chain validation policy (intentionally no chain validation for server certs). Mapping to `rustls` requires careful handling of behavioral differences.

#### 0.7.2.1 Baseline TLS 1.2 Behavior Catalog

| Behavior | Source in `tls.inc` | Target in rustls |
|----------|---------------------|------------------|
| Cipher suite preference order (12 suites when `tls_server_cipher_order = 1`): DHE_DSS/DHE_RSA AES_256/128_CBC_SHA256/SHA then RSA variants | `tls.inc` cipher tables (lines ~1000–1300) | rustls does **not** support DHE or CBC in its default supported cipher suites (TLS 1.2 supports ECDHE + AES-GCM/CHACHA20-Poly1305 only); see 0.7.2.3 |
| No ECDHE — only classical DHE and RSA key exchange | Commented out in `tls.inc` lines 22–77 | **Architectural divergence**: rustls only offers ECDHE for TLS 1.2 key exchange |
| AES-only cipher suites; CBC modes only (GCM commented out lines 138–143) | Explicit in `tls.inc` comments | **Architectural divergence**: rustls TLS 1.2 offers ECDHE + AES-GCM (inverse of assembly) |
| Session cache (3600s TTL, AES-256 encrypted) | `tls.inc` session cache subsystem | `rustls::server::ServerSessionMemoryCache` (in-memory, not encrypted by default); wrap with custom `StoresServerSessions` implementation that AES-256-encrypts entries |
| PEM certificate hot-reload every 3600s (`tls_pem_refresh_interval`) with intentional memory leak | `tls.inc` reload timer + X.509 ref | Custom `tokio::time::interval(3600s)` that rebuilds a `Arc<ServerConfig>` and atomically swaps via `ArcSwap`; no memory leak required (Rc counting handles it) |
| OCSP stapling (`tls_server_ocsp_stapling = 1`, refresh 7200s, retry 300s) | `tls.inc` + `X509.inc` OCSP paths | rustls supports OCSP stapling via `CertifiedKey::new_with_ocsp`; custom refresh loop fetches OCSP response, updates CertifiedKey; 300s retry on fetch failure |
| RSA blinding (`tls_server_rsa_blinding = 0` by default, performance cost) | `tls.inc` RSA math | Not user-configurable in rustls; rustls's RSA implementation handles side-channel concerns internally |
| IP blacklist on crypto errors (86400s default) | `tls.inc` → `blacklist.inc` | Wrap rustls `Accepted`/`Connection` future with error handler that invokes `heavything::net::blacklist::Blacklist::add(ip, 86_400)` on cryptographic failures |
| Server cipher-order preference | `tls_server_cipher_order = 1` | `rustls::ServerConfig::cipher_suites` order is the server preference |
| PFS-only mode (`tls_perfect_forward_secrecy_only`) | `tls.inc` cipher filter | rustls's default cipher suites are PFS-only (ECDHE), so this is implicit |

#### 0.7.2.2 Cipher-Suite Divergence Resolution

The assembly library uses **DHE + AES-CBC-SHA256/SHA**, and rustls offers **ECDHE + AES-GCM/CHACHA20-Poly1305** for TLS 1.2. This is a fundamental divergence with the following mitigations:

- **For HTTPS server compatibility**: rustls with its default suites is compatible with the same client browsers and servers that already interoperate with the assembly library's narrower suite set — real-world clients negotiate the best mutually supported suite and will select ECDHE-GCM (with rustls) just as they previously selected DHE-CBC (with HeavyThing). External observable behavior from the perspective of "does HTTPS work" is preserved
- **For the `webclient` client-mode**: rustls-as-client likewise negotiates best mutual suite
- **For TLS 1.3 additions**: rustls supports TLS 1.3 by default; this is a **widening** of supported protocols (the assembly has no TLS 1.3). The prompt explicitly lists "TLS 1.2/1.3" for rustls scope, so TLS 1.3 support is in scope
- **Documentation requirement**: the divergence is documented in `BENCHMARK_REPORT.md` and `README.md` under "Behavioral Differences from Assembly Baseline"

#### 0.7.2.3 X.509 / Certificate Validation Behavior

The assembly's `X509.inc` uses explicit "garbage-in/garbage-out" — no certificate-chain validation on server-presented certs. For the `webserver` binary acting as a TLS **server**, this is natural because the server presents its own cert and does not validate client certs. For the `webclient`-style HTTPS client used by `hnwatch`:

- `hnwatch` connects to `news.ycombinator.com` HTTPS API → requires client-side cert validation
- rustls with `webpki` + `webpki-roots` provides proper chain validation by default — this is a **behavioral improvement** (not a regression) that the prompt tacitly endorses by listing rustls + webpki
- For the `webserver` binary, no client-cert-validation is performed by default (matching assembly)

#### 0.7.2.4 Session Cache Implementation

| Concern | Approach |
|---------|---------|
| TTL preservation (3600s) | `tokio::time::interval` sweeps expired entries |
| AES-256 encryption of cache entries (`tls_server_encryptcache = 1`) | Wrap `rustls::server::StoresServerSessions` with a custom impl that AES-256-encrypts the session blob before returning from `get()` and decrypts on `put()`; cache key derived from session ID |
| Per-worker cache vs. shared master cache | Master aggregates via `LinkMessage::TlsUpdate` IPC; workers broadcast updates to master, master broadcasts back to all workers — preserves the existing assembly relay pattern |

#### 0.7.2.5 PEM Hot-Reload Mechanism

The existing 3600s PEM refresh interval is preserved via `tokio::time::interval`:

```text
master process spawns `tokio::task::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    loop {
        interval.tick().await;
        if let Ok(new_config) = reload_pem_from_disk(&cert_path, &key_path) {
            config_swap.store(Arc::new(new_config));  // ArcSwap
        }
    }
});
```

No memory leak is required (Rust's Arc refcounting handles the old config's cleanup automatically once no active connection holds a reference).

### 0.7.3 TUI Raw-Mode Syscall Handling

Terminal raw-mode management is tightly coupled to Linux terminal syscalls and must not regress per the prompt's explicit directive ("TUI MUST be managed via libc termios syscalls matching existing behavior exactly"). This section specifies the exact syscall sequences.

#### 0.7.3.1 Baseline termios Operations

`tui_terminal.inc` performs the following termios-related syscalls in sequence on startup:

1. `tcgetattr(STDIN_FILENO, &original)` — save original terminal settings for restoration
2. `cfmakeraw(&new)` or manual equivalent — set raw mode flags
3. `tcsetattr(STDIN_FILENO, TCSANOW, &new)` — apply raw mode
4. `ioctl(STDIN_FILENO, TIOCGWINSZ, &winsize)` — get terminal dimensions
5. Output `ESC[?1049h` (alternate screen buffer enable) when `terminal_alternatescreen = 1`
6. Output `ESC[?25l` (hide cursor) typically
7. Output `ESC[2J` + `ESC[H` (clear screen + home cursor)

On shutdown (both graceful and signal-driven):

1. Output `ESC[?25h` (show cursor)
2. Output `ESC[?1049l` (alternate screen disable)
3. `tcsetattr(STDIN_FILENO, TCSANOW, &original)` — restore original settings

Signal handling must cover SIGINT, SIGTERM, SIGWINCH (resize), and SIGSEGV/SIGABRT (for best-effort cleanup).

#### 0.7.3.2 Rust Implementation Plan

```text
// In crates/heavything/src/tui/terminal.rs
pub struct RawTerminal {
    original: libc::termios,
    stdin_fd: RawFd,
}

impl RawTerminal {
    pub fn enter() -> Result<Self, io::Error> {
        // unsafe: calling libc tcgetattr/tcsetattr with valid fd
        // safety invariant: stdin_fd is valid for the process lifetime;
        //                   libc::termios is POD and safe to zero-initialize
        unsafe {
            let stdin_fd = libc::STDIN_FILENO;
            let mut original: libc::termios = mem::zeroed();
            if libc::tcgetattr(stdin_fd, &mut original) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut new = original;
            libc::cfmakeraw(&mut new);
            if libc::tcsetattr(stdin_fd, libc::TCSANOW, &new) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { original, stdin_fd })
        }
    }

    pub fn get_winsize(&self) -> Result<(u16, u16), io::Error> { /* ... */ }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        // unsafe: calling libc tcsetattr with saved original termios
        // safety invariant: saved termios was obtained from tcgetattr on this same fd
        unsafe { libc::tcsetattr(self.stdin_fd, libc::TCSANOW, &self.original); }
    }
}
```

Signal-handler cleanup: register `SIGINT`/`SIGTERM` handlers via `tokio::signal::unix::signal(SignalKind::interrupt())` that invoke an explicit `restore()` method plus `std::process::exit(130)` (standard 128+SIGINT convention).

#### 0.7.3.3 Remote SSH Rendering Path

`tui_ssh.inc` routes ANSI output through the SSH channel instead of stdout. In Rust:

- `SshRenderer` struct holds a `tokio::sync::mpsc::Sender<Bytes>` that pipes into the SSH session's `channel data` handler
- No termios manipulation is required on the local side (the local terminal is managed by the SSH client)
- Alternate-screen enable/disable escape codes are still emitted (controlled by `tui_ssh_alternatescreen = 1`)
- Input events arrive via the `channel data` receive handler and are forwarded to the widget tree through a `mpsc::Sender<TuiEvent>`

### 0.7.4 Unsafe Block Site-by-Site Rationale

Per Gate 6, every `unsafe` block must be inventoried in `UNSAFE_AUDIT.md` with location, reason, and safety invariant. Any count exceeding 50 requires per-site written justification; all FFI and raw-syscall boundary sites must have a corresponding integration test in `crates/heavything/tests/ffi_boundary.rs`.

#### 0.7.4.1 Expected Unsafe Block Categories

Based on the refactor's needs, unsafe blocks are expected only in the following categories. The target count is **under 50** through aggressive isolation of unsafe into small, well-tested helper functions.

| Category | Approximate Site Count | Rationale Summary |
|----------|------------------------|-------------------|
| `libc` termios calls (`tcgetattr`, `tcsetattr`, `cfmakeraw`) | 3–4 sites | Required because `libc` exposes these as `unsafe extern "C"` |
| `libc` signal handling (`sigaction`, `signal`) | 2–3 sites | Required for raw signal registration in TUI apps |
| `libc` winsize ioctl (`ioctl` with `TIOCGWINSZ`) | 1–2 sites | Required for terminal-size query |
| `nix::unistd::fork` (wraps `unsafe`) | 2–3 sites | Required by Linux process semantics; all calls in `webserver::master` |
| `nix::sys::prctl::set_pdeathsig` | 1 site | Required for worker cleanup on master death |
| `libc::setuid` / `libc::setgid` (via `nix`) | 2 sites | Required for privilege drop in `webserver::master` |
| `memmap2::Mmap::map` | 3–5 sites | Safe API wraps unsafe mmap; used for file cache and TLS session cache |
| AES-NI intrinsics (`std::arch::x86_64::*_aesni`) | 0 sites expected | `ring` and `aes` crates handle AES-NI internally; no direct intrinsic calls needed |
| CPUID feature detection | 0 sites | `std::is_x86_feature_detected!` is a safe macro |
| Raw syscall for syscalls not exposed by `libc` (`syscall.inc` equivalents) | 0–2 sites | Rare; most required syscalls have libc wrappers |

**Expected total: 14–22 sites, well under the 50-site threshold.**

#### 0.7.4.2 Unsafe Site Isolation Principles

The following principles are applied to minimize unsafe usage:

- **Encapsulate unsafe at type boundaries**: e.g., `RawTerminal` owns all termios unsafe; consumers interact via safe methods
- **Prefer wrapper crates over direct libc**: `nix::unistd::fork` instead of raw `libc::fork`; `memmap2::Mmap` instead of raw `mmap`; reduces site count and improves review-ability
- **Group related unsafe into single blocks**: in `RawTerminal::enter`, all three syscalls (`tcgetattr`, `cfmakeraw`, `tcsetattr`) live in a single `unsafe` block with one consolidated safety comment
- **Document safety invariants explicitly**: every unsafe block carries a `// SAFETY: …` comment specifying the preconditions that make the unsafe operation sound

#### 0.7.4.3 Example `UNSAFE_AUDIT.md` Entry

```
### heavything::tui::terminal::RawTerminal::enter

- Location: `crates/heavything/src/tui/terminal.rs:42`
- Category: libc termios FFI
- Functions called: `libc::tcgetattr`, `libc::cfmakeraw`, `libc::tcsetattr`
- Reason for unsafe: `libc` FFI functions are unsafe-by-declaration; no safe wrapper in std
- Safety invariant:
  * STDIN_FILENO is a valid process file descriptor
  * The `termios` struct is a POD type; zeroing is a valid initial state before tcgetattr fills it
  * The saved `original` termios is used only in Drop to restore, before which the fd remains open
- Integration test: `ffi_boundary::test_raw_terminal_roundtrip` (exercises enter → query → drop → verify restore)
```

#### 0.7.4.4 Integration Test Coverage

`crates/heavything/tests/ffi_boundary.rs` contains one test per unsafe site:
- `test_raw_terminal_roundtrip` — enters/exits raw mode, verifies restoration
- `test_fork_workers` — forks a worker, signals parent, verifies IPC
- `test_setuid_setgid_drop` — validates privilege drop (requires root; gated by env var)
- `test_prctl_pdeathsig` — kills parent, verifies child death
- `test_mmap_file_cache` — mmaps a test file, reads content, verifies cleanup
- `test_sigwinch_handler` — sends SIGWINCH, verifies TUI resize handler fires

These tests satisfy Gate 6's requirement that all FFI and raw-syscall boundary sites have a corresponding integration test.


## 0.8 Refactoring Rules

The following rules, derived directly from the user's prompt and from the Validation Framework's eight translation quality gates, govern the conduct of the refactor. All downstream code-generation agents must treat these rules as non-negotiable constraints.

### 0.8.1 Refactoring-Specific Rules

The user's prompt explicitly establishes the following primary directives:

- **Preserve all observable behavior** of `sshtalk`, `hnwatch`, `webserver`, and every TUI demo application. Behavioral preservation is verified via Gate 1 (live smoke tests), Gate 4 (real-world artifacts), and Gate 5 (API contract verification). Behavior includes: SSH wire-protocol output, HTTP/1.x parsing behavior, TLS handshake correctness, and byte-for-byte crypto primitive output
- **Maintain SSH wire-protocol interoperability with OpenSSH 8.x+**. The `SSH-2.0-HeavyThing` identification string is preserved. `dh-group-exchange-sha256`, `ssh-rsa`/`ssh-dss`, `aes256-cbc`, `hmac-sha2-256`, and forced zlib compression are all preserved
- **Crypto primitive outputs must be byte-for-byte identical to assembly outputs** for identical inputs. This includes AES-CBC/ECB encryption, SHA-1/SHA-256/SHA-512/MD5 digests, HMAC outputs, PBKDF2 derivations, and scrypt outputs. Test vectors are extracted from the assembly build and used as golden values in `crates/heavything/tests/crypto_vectors.rs`
- **All three example applications (`sshtalk`, `hnwatch`, `webserver`) must compile, start, and handle live requests without modification to their logic**. Command-line argument parsing, default values, config flags, and runtime semantics are all preserved exactly
- **Linux x86_64 only; no cross-platform compatibility required or desired**. `#[cfg(target_os = "linux")]` and `#[cfg(target_arch = "x86_64")]` gates are acceptable at module boundaries; Windows and macOS compatibility stubs are explicitly forbidden
- **No feature additions, no architectural expansion, no platform generalization**. The scope is exclusively translation of existing functionality. New flags, new endpoints, new config knobs, and new APIs are prohibited
- **No performance optimizations beyond what translation naturally yields**. The benchmark comparison is informational (documenting deltas), not an optimization target
- **Acceptable performance threshold: within 3× of assembly baseline** for AES-128-CBC throughput, SHA-256 throughput, and HTTP round-trip latency. Any regression beyond 3× must be documented in `BENCHMARK_REPORT.md` with root-cause analysis

### 0.8.2 Minimal-Change Discipline

The user's Minimal Change Clause requires these disciplines:

- Make only the minimal necessary changes to implement the refactor
- Do not modify code that is not directly impacted by the technology transition
- Do not enhance or optimize code beyond the requirements of the translation
- Isolate each subsystem translation in its dedicated module (`crypto/`, `net/`, `tui/`, `ds/`, `util/`)
- Document translation-specific decisions with inline comments explaining **why** a particular Rust pattern was chosen to match assembly behavior — comments explain WHY, not WHAT; no narration of self-evident code

### 0.8.3 Code Quality Rules

- **RUSTFLAGS="-D warnings"** must be set in CI and enforced on every build. No `#[allow(warnings)]` or `#[allow(unused)]` suppressions are permitted under any circumstances (per Gate 2)
- **2021 edition** exclusively; no nightly features; no unstable Cargo features
- **Stable Rust toolchain** pinned via `rust-toolchain.toml` to a specific version (e.g., `stable-1.75.0` or later)
- **Naming conventions**: Rust idiomatic `snake_case` for functions and variables, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants. Assembly symbols (e.g., `ht$init`, `webserver$new_listener`) are translated to their Rust idiomatic equivalents (`heavything::init`, `WebServer::new_listener`)
- **Module organization** mirrors the subsystem taxonomy: `crypto/`, `net/`, `tui/`, `ds/`, `util/` directories each contain a `mod.rs` and subordinate modules. Cross-module types go in `heavything::error` (errors), `heavything::config` (compile-time constants), and `heavything::cpu` (CPU feature detection)
- **Error handling**: `thiserror`-derived error enums at module boundaries (e.g., `crypto::CryptoError`, `net::NetError`, `tui::TuiError`); the binary crates use `anyhow::Result<T>` for top-level error propagation in `main`
- **Async vs blocking**: all I/O-bound code is `async`; CPU-bound crypto code is synchronous (offloaded via `tokio::task::spawn_blocking` when invoked from async context)
- **No `unwrap()` or `expect()` in library code paths** that can be reached at runtime; use `?` propagation and typed error conversion. Tests and benchmarks may use `unwrap()`
- **Doc comments (`///`)** on every public item in the `heavything` library; doc comments reference the original assembly source file when the implementation directly corresponds to an assembly function

### 0.8.4 Testing Rules

- **Integration test per major subsystem** (crypto, net, tui, ds, util) verifying at least one real-world operation end-to-end. Unit tests that mock I/O do not satisfy Gate 1
- **Unit test coverage ≥70%** on crypto and ds modules, measured via `cargo-tarpaulin` or `cargo-llvm-cov`
- **Test files live in**:
  * `crates/heavything/tests/` — integration tests per subsystem
  * `crates/heavything/src/**/mod.rs` `#[cfg(test)] mod tests` blocks — unit tests
  * `crates/{app}/tests/` — per-binary integration tests
- **FFI and raw-syscall boundary tests**: `crates/heavything/tests/ffi_boundary.rs` contains one test per `unsafe` site (per Gate 6)
- **Crypto golden-vector tests**: `crates/heavything/tests/crypto_vectors.rs` verifies byte-for-byte output match with assembly baseline for all crypto primitives
- **Live network tests are gated by environment variables** (e.g., `HEAVYTHING_LIVE_TESTS=1`) so they do not run in offline CI but are runnable for Gate 1 verification

### 0.8.5 Benchmark Rules

- **`criterion` version** pinned in `workspace.dependencies` (0.5)
- **Benchmark files live in `crates/heavything/benches/`**:
  * `aes_cbc.rs` — AES-128-CBC throughput measurement
  * `sha256.rs` — SHA-256 throughput measurement
  * `http_roundtrip.rs` — epoll-driven HTTP round-trip latency
- **Baseline save/compare**: criterion's `--save-baseline` and `--baseline` modes are used to persist assembly measurements, then compare Rust measurements against them. Assembly measurements are produced by running the original FASM-built binaries and recorded separately
- **`BENCHMARK_REPORT.md`** is delivered containing all criterion outputs and the assembly-vs-Rust comparison table (per Gate 3)

### 0.8.6 Documentation Rules

- **`README.md`** at the repository root is updated to reflect the new build steps (`cargo build --release`, `cargo run --bin sshtalk`, `cargo bench`, `cargo test`) while preserving the original HeavyThing project attribution
- **`UNSAFE_AUDIT.md`** is delivered at the repository root (per Gate 6) listing every `unsafe` block with location, reason, and safety invariant. Count >50 triggers per-site written justification
- **`BENCHMARK_REPORT.md`** is delivered at the repository root (per Gate 3) containing criterion output and assembly-vs-Rust comparisons
- **`INTEGRATION_SIGNOFF.md`** is delivered at the repository root (per Gate 8) containing the completed integration sign-off checklist
- **Doc comments** on public items; internal modules use `//` comments explaining *why* a Rust pattern was chosen to match assembly behavior (per the Minimal Change Clause)
- **GPLv3 license headers** preserved or ported into each translated Rust source file consistent with the original 2 Ton Digital copyright notices (2015–2018, Jeff Marrison)

### 0.8.7 Dependency Governance Rules

- **All dependencies sourced from crates.io**; no private registries, no git URLs, no path dependencies outside the workspace
- **Exact versions pinned** in `workspace.dependencies` section of the root `Cargo.toml`; dependencies use the `{ workspace = true }` pattern in per-crate `Cargo.toml` files
- **`Cargo.lock`** is committed to the repository to ensure reproducible builds
- **No dependency churn**: adding new dependencies beyond the inventory in §0.6 requires justification in the PR description

### 0.8.8 Scope Matching (Gate 7)

All five subsystems (crypto, net, tui, ds, util) must be fully translated — partial delivery is not acceptable. Gate 7 scopes this as Extended Specification Tier given the combined presence of networking, cryptography, async I/O, and TUI.

### 0.8.9 Constraint Captures from User's Prompt

The following user-emphasized constraints are captured verbatim or near-verbatim:

- **User Example (SSH ident)**: `SSH-2.0-HeavyThing` — preserved as-is in `heavything::net::ssh` identification string
- **User Example (cipher suites disabled in assembly)**: "no ECDHE, AES-only, CBC only (GCM commented 138-143)" — noted in the TLS module; rustls divergence documented per §0.7.2.2
- **User Example (build commands)**:
  - `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
  - `source $HOME/.cargo/env`
  - `cd /Users/ripplingadmin/Blitzy-HeavyThing`
  - `cargo build --release`
  - `cargo run --bin sshtalk -- [args]`
  - `cargo bench`
  - `cargo test`
- **User Example (binary crate names)**: `sshtalk`, `hnwatch`, `webserver` (the user explicitly says "binary crate per example application (sshtalk, hnwatch, webserver)", so the binary built from `rwasa/` sources is named `webserver`)
- **User Constraint (performance threshold)**: "acceptable threshold is within 3x of assembly baseline; any regression beyond 3x MUST be documented with root cause"
- **User Constraint (unsafe block threshold)**: "any count >50 requires per-site written justification"
- **User Constraint (coverage threshold)**: "unit test coverage ≥70% on crypto and ds modules measured via cargo-tarpaulin or cargo-llvm-cov"
- **User Constraint (external integrations)**: "hnwatch connects to the public Hacker News API (no auth); no other external service integrations required"
- **User Constraint (TUI crate prohibition)**: "no third-party TUI crate (ratatui, crossterm, etc.) is permitted — existing TUI semantics must be preserved exactly"
- **User Constraint (std collections preference)**: "MUST use std collections where semantically equivalent; custom implementations required only where assembly semantics differ materially"

### 0.8.10 Gate Compliance Summary

| Gate | Requirement | Compliance Mechanism |
|------|-------------|----------------------|
| Gate 1 | End-to-end boundary verification: live sshtalk session, live HN page, live HTTP request | `INTEGRATION_SIGNOFF.md` checklist with signed-off rows; `HEAVYTHING_LIVE_TESTS=1` environment |
| Gate 2 | Zero-warning build with `-D warnings` | CI workflow sets `RUSTFLAGS="-D warnings"`; no `#[allow(...)]` suppressions |
| Gate 3 | Performance baseline comparison | `BENCHMARK_REPORT.md` with criterion output for AES-128-CBC, SHA-256, HTTP roundtrip |
| Gate 4 | Named real-world artifacts: TLS cert chain validation, OpenSSH 8.x+ handshake | `hnwatch` connects to HN (TLS); `sshtalk` interoperates with OpenSSH client |
| Gate 5 | API/interface contract verification | `curl` HTTP test, real OpenSSH client against sshtalk, real HTTPS host for TLS |
| Gate 6 | `UNSAFE_AUDIT.md` with per-site detail; count >50 justified; FFI tests | `UNSAFE_AUDIT.md` + `crates/heavything/tests/ffi_boundary.rs` |
| Gate 7 | All five subsystems fully translated | Single-phase delivery per §0.5; no partial subsystem delivery |
| Gate 8 | Integration sign-off checklist submitted | `INTEGRATION_SIGNOFF.md` deliverable |


## 0.9 References

This section enumerates every artifact consulted during the preparation of this Agent Action Plan: Technical Specification sections retrieved, source files and folders inspected in the HeavyThing repository, user-provided attachments and metadata, and external research performed.

### 0.9.1 Technical Specification Sections Retrieved

The following sections of the accompanying Technical Specification document were retrieved (via `get_tech_spec_section`) to establish authoritative context for the Agent Action Plan:

| Section | Purpose in this Plan |
|---------|----------------------|
| 1.2 System Overview | Established HeavyThing as a pure x86_64 assembly library with five subsystems and the four showcase-plus-tools deliverables |
| 1.3 Scope | Confirmed in-scope (five subsystems + three binaries) and out-of-scope boundaries (toplip, webslap, dhtool, util programs, examples) |
| 2.1 FEATURE CATALOG | Established the 19 features F-001 through F-019 driving scope decomposition |
| 2.2 FUNCTIONAL REQUIREMENTS | Extracted per-feature acceptance criteria (heap, epoll, HTTP/TLS/SSH protocol conformance, TUI widget behavior, crypto outputs) |
| 2.3 FEATURE RELATIONSHIPS | Captured feature dependency graph (F-001 underpins all; F-002 underpins F-003/F-004/F-005/F-006; F-007 underpins F-005/F-006/F-012/F-014) and shared-component set |
| 2.4 IMPLEMENTATION CONSIDERATIONS | Captured technical constraints, performance knobs, scalability parameters, security posture, known limitations, and maintenance realities |
| 3.1 TECHNOLOGY STACK OVERVIEW | Confirmed current stack (FASM + Linux x86_64 + raw ELF64) and target-stack selection space |
| 3.2 PROGRAMMING LANGUAGES | Confirmed assembly-only source with GPLv3 license and FASM dependency |
| 3.3 FRAMEWORKS AND LIBRARIES | Documented the current library taxonomy used to guide the crypto/net/tui/ds/util module split |
| 3.4 OPEN SOURCE DEPENDENCIES | Established that the current stack has zero third-party dependencies (monolithic self-contained assembly) |
| 3.7 PLATFORM AND SYSTEM REQUIREMENTS | Confirmed Linux x86_64 kernel ≥2.6.28, ELF64 static binaries, and ulimit requirements |
| 3.10 LICENSING | Captured GPLv3 license (© 2015–2018 2 Ton Digital, Jeff Marrison) and AES fallback attribution (Wei Dai public domain) requiring preservation in ported sources |
| 4.2 CORE APPLICATION PROCESS FLOWS | Captured 12-stage `ht$init` sequence, master→worker fork flow, privilege-drop ordering, and IPC relay patterns |
| 5.1 HIGH-LEVEL ARCHITECTURE | Captured the overall subsystem layering (Core Runtime at base; Net/Crypto/TUI/DS/Util above; showcase apps on top) |
| 5.2 COMPONENT DETAILS | Captured heap allocator tiers, IO chain 7-method vtable, 12-stage init, HTTP pipeline, TLS suite restrictions, SSH identity, crypto primitive details |
| 5.3 TECHNICAL DECISIONS | Captured design rationales (mmap caching, never-free heap, runtime CPU dispatch) preserved in Rust target design |
| 5.4 CROSS-CUTTING CONCERNS | Captured logging (syslog + stderr), signal handling (SIGWINCH, SIGTERM, SIGPIPE), exit-code convention (96/97/98/99), profiling-flag behavior |
| 6.1 Core Services Architecture | Captured master-worker architecture details used in worker-process planning |
| 6.3 Integration Architecture | Captured external integration surface (public Hacker News API, OpenSSH wire compat, curl HTTP compat, live TLS host) |
| 6.4 Security Architecture | Captured TLS "Garbage-in/Garbage-out" posture, IP blacklist timings, HSTS + BREACH mitigation, PEM hot-reload |
| 6.6 Testing Strategy | Captured coverage expectations, integration-test boundaries, and the real-world artifact requirements aligned with Gate 1/4/5 |
| 7.2 TUI FRAMEWORK ARCHITECTURE | Captured widget hierarchy (30+ widgets under `tui_object` base), SSH-rendering path via `tui_ssh`, ANSI-output path via `tui_ansi`, and simpleauth gate |
| 8.2 Build Infrastructure | Captured current FASM-only build reality and informed the Cargo workspace target design |

### 0.9.2 Source Files and Folders Inspected

The HeavyThing repository at `/tmp/blitzy/Blitzy-HeavyThing/master_fc613b` was inspected via the `bash` tool. The following paths and artifacts were consulted:

#### 0.9.2.1 Repository Root and Top-Level Inventory

- Repository root listing — established the set of 106 `.inc` files (of which 32 are `tui_*` files), the seven showcase-app directories (`dhtool/`, `examples/`, `hnwatch/`, `rwasa/`, `sshtalk/`, `toplip/`, `webslap/`), the `util/` utility-programs directory, and pre-built `.o` / ELF artifacts
- `wc -l` on all top-level `.inc` files — produced the size inventory driving module-split decisions (bigint.inc=10,923, tls.inc=6,866, ssh.inc=6,011, webserver.inc=5,670, zlib_deflate.inc=4,805, string32.inc=4,550, string16.inc=4,513, maps.inc=4,507, X509.inc=4,133, tui_text.inc=3,901, mimelike.inc=3,814, httpheaders.inc=3,750, epoll.inc=3,512, tui_object.inc=3,095, zlib_inflate.inc=2,656, string_math.inc=2,158, formatter.inc=2,157, sha2.inc=2,146, webclient.inc=2,042, tui_simpleauth.inc=1,960, memfuncs.inc=1,822, tui_render.inc=1,782, url.inc=1,670, json.inc=1,639, aes.inc=1,423, date.inc=1,336, profiler.inc=1,315, epoll_dns.inc=1,264, buffer.inc=1,247, and the remaining ~77 files). **Total: 131,445 assembly lines**

#### 0.9.2.2 Master Include Files

- `ht.inc` (653 lines) — inspected lines 1–350 to extract the exact include order and the 12-stage `ht$init_args` function prologue. This established the module layering contract that the `heavything` crate's `lib.rs` must preserve
- `ht_defaults.inc` (523 lines) — inspected lines 1–120 to extract the full set of `if ~ definite` compile-time defaults (page_size=4096, function_alignment=16, framepointers=1, public_funcs=1, code_preload=1, heap_bincheck=0, rng_heavy_init=1, string_bits=32, base64_linebreaks=1, base64_maxline=76, etc.) driving the `heavything::config` constants table
- `ht_data.inc` (36 lines) — confirms the data-segment declarations

#### 0.9.2.3 Showcase Application Sources (In-Scope Binaries)

- `rwasa/rwasa.asm` (152 lines) — inspected entry-point showing the include chain (`../ht_defaults.inc`, `../ht.inc`, `arguments`, `worker`, `master`) and the `_start.hookthemall` function-call hook contract with `rdi=webserver, rsi=url, rdx=mimelike` semantics
- `rwasa/arguments.inc` (791 lines) — argument parser for `-cpu`, `-tls`, `-fastcgi`, `-runas`, `-funcmatch`, `-new` flags
- `rwasa/master.inc` (337 lines) — master-process IPC relay loop (OCSP, TLS session updates, log)
- `rwasa/worker.inc` (361 lines) — worker-process epoll loop and request-handler registration
- `rwasa/tlsmin_defaults.inc` (523 lines) — minimal-TLS build variant (not in scope for translation as the default build includes full TLS)
- `sshtalk/sshtalk.asm` (326 lines) — inspected entry-point; confirmed the sequence `_start → ht$init → load userdb → userdb$init → chatroom$init → chatpanel$init → screen$init → statusbar$init → epoll$run`
- `sshtalk/userdb.inc` (732 lines) — user-database with `userdb$vtable` auth callback
- `sshtalk/chatroom.inc` (423 lines) — multi-user chat state machine
- `sshtalk/chatpanel.inc` (1,030 lines) — TUI panel rendering per chat session
- `sshtalk/screen.inc` (1,973 lines) — top-level TUI screen composition
- `sshtalk/statusbar.inc` (197 lines) — status bar widget
- `hnwatch/hnwatch.asm` (63 lines) — inspected entry-point; confirmed default `main_item_limit dq 150`; sequence `_start → ht$init → set navstring to topstories → hnmodel$init → ui$init → epoll$run`
- `hnwatch/hnmodel.inc` (703 lines) — HN API model fetcher
- `hnwatch/eventstream.inc` (458 lines) — event-stream reader
- `hnwatch/textify.inc` (221 lines) — text rendering helper
- `hnwatch/ui.inc` (1,715 lines) — datagrid-based TUI

#### 0.9.2.4 Showcase Application Sources (Out-of-Scope, Examined Only to Confirm Exclusion)

- `toplip/` — 3 artifacts listed (`toplip.asm`, `toplip.o`, `toplip` binary); excluded from translation per scope
- `webslap/` — 5 variants listed (`globals.inc`, `master.inc`, `master_ui.inc`, `tlsmin_defaults.inc`, `webslap.asm`); excluded
- `dhtool/` — 2 artifacts listed (`dhtool.asm`, `dhtool_settings.inc`); excluded
- `util/` — 4 utility programs listed (`bigint_tune.asm`, `make_dh_static.asm`, `mersenneprimetest.asm`, `bigger_int_settings.inc`); excluded
- `examples/` — 14 subdirectories listed (`echo`, `hello_world`, `hello_world_c1`, `hello_world_c2`, `minigzip`, `multicore_echo`, `sha256`, `simplechat_c++`, `simplechat_ssh_auth_c++`, `simplechat_ssh_c++`, `sshecho`, `tlsecho`, `tuieffects`, `tuimatrix`); excluded
- `rwasa_tlsmin.asm` (154 lines) — reduced-TLS variant of the `rwasa` webserver; excluded in favor of the full-TLS build

### 0.9.3 User-Provided Attachments and Metadata

- **Uploaded files**: The user attached **zero files** to this project (`/tmp/environments_files` contained no attachments)
- **Figma URLs**: None provided. The refactor does not involve UI design work; the TUI layout is driven by the existing assembly widget hierarchy
- **External service URLs**: Only the public Hacker News API (https://hacker-news.firebaseio.com/, no authentication) is referenced — exclusively consumed by `hnwatch` for live data fetches
- **Installation URL (referenced in the prompt)**: https://sh.rustup.rs — the official Rust toolchain installer used in build-step (a) of the user's build instructions
- **Environment variables / secrets**: None provided or required, per the user's own declaration: "Secrets/environment variables: None required to build or run"
- **Private dependencies**: None; all dependencies sourced from crates.io per the user's declaration
- **Submodules**: None; the user explicitly stated "No submodules"

### 0.9.4 External References Informing the Target Design

The Rust target design draws on well-established crate and tool conventions:

- **crates.io** — the sole package registry for all Rust dependencies listed in §0.6
- **Tokio documentation** — confirming that `tokio` uses `mio` (which uses `epoll` on Linux) as its I/O backend, satisfying the prompt's "tokio (epoll backend)" requirement
- **ring crate documentation** — confirming `ring` provides SHA-1, SHA-256, SHA-512, HMAC, and PBKDF2 primitives, but notably does **not** expose raw AES-CBC (only AES-GCM for AEAD); hence the separate `aes` + `cbc` crate selection for SSH AES256-CBC needs
- **rustls + webpki documentation** — confirming rustls supports TLS 1.2 and TLS 1.3 with ECDHE key exchange only (not classical DHE); this drives the architectural divergence noted in §0.7.2.2
- **RustCrypto organization crates** — `aes` (0.8), `cbc` (0.1), `md-5` (0.10), `scrypt` (0.11); selected for algorithms not exposed by `ring`
- **num-bigint crate documentation** — selected to replace `bigint.inc`'s 10,923-line BigInt implementation (512-word capacity, 64-round Miller-Rabin); `num-bigint` supports arbitrary-precision integers with Miller-Rabin primality testing via `num-integer`
- **nix crate documentation** — selected for `fork`, `setuid`, `setgid`, `prctl(PR_SET_PDEATHSIG)`, `socketpair` wrappers; chosen over raw `libc` calls to reduce `unsafe` block count per §0.7.4
- **libc crate documentation** — selected for direct `termios` operations (`tcgetattr`, `tcsetattr`, `cfmakeraw`) since `nix` does not fully abstract TTY raw-mode in a way that preserves exact assembly behavior; chosen with explicit `unsafe` blocks documented in `UNSAFE_AUDIT.md`
- **criterion crate documentation** — selected for baseline save/compare mechanics required by Gate 3's assembly-vs-Rust comparison
- **RFC 4253 (The Secure Shell Transport Layer Protocol)** — informing the SSH module's wire-protocol preservation; called out in the prompt as "SSH wire protocol (RFC 4253) compatibility with OpenSSH 8.x+"

### 0.9.5 Scope Decisions Summary

The following scope decisions were established during context gathering and are reaffirmed here for traceability:

- **In-scope deliverables**: a single Cargo workspace with one library crate (`heavything`) and three binary crates (`sshtalk`, `hnwatch`, `webserver`); plus three required deliverable documents (`UNSAFE_AUDIT.md`, `BENCHMARK_REPORT.md`, `INTEGRATION_SIGNOFF.md`)
- **In-scope source files**: all 106 top-level `.inc` files (subject to narrow exceptions noted below), plus the six in-scope showcase-app source-file subsets (rwasa → webserver: 6 files, sshtalk: 6 files, hnwatch: 5 files)
- **Narrow exceptions within the 106**: `htcrypt.inc` and `htxts.inc` are toplip-only and not ported; `dh_pool_*.inc` static DH tables are preserved as embedded byte arrays but their consumer logic is simplified via `num-bigint`
- **Out-of-scope**: all contents of `toplip/`, `webslap/`, `dhtool/`, `util/`, `examples/`; the `rwasa_tlsmin.asm` minimal-TLS variant; every existing `.o` and ELF64 binary
- **Preserved in place**: every `.asm` and `.inc` source file remains untouched in its original location; the Rust workspace lives alongside, not atop, the assembly sources


