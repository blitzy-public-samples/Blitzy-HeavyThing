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

# HeavyThing Rust Port — Integration Sign-off

**Project**: HeavyThing assembly → Rust translation  
**Target**: Linux x86_64 (`x86_64-unknown-linux-gnu`), stable Rust 2021 edition  
**Scope**: `heavything` library crate + three binary crates (`sshtalk`, `hnwatch`, `webserver`)  
**License**: GPLv3 (© 2015–2018 2 Ton Digital, Jeff Marrison)

This document records the completion evidence for each of the eight quality gates (Gate 1 through Gate 8) of the HeavyThing translation validation framework defined in AAP §0.8.10. It is the capstone deliverable required by AAP §0.3.1.4 and Gate 8 itself: a single, reviewable artifact that cross-references every other deliverable (`UNSAFE_AUDIT.md`, `BENCHMARK_REPORT.md`, the Cargo workspace, and the three binary crates) and confirms that the assembly-to-Rust migration is functionally complete, warning-clean, and behaviorally equivalent to the x86_64 FASM baseline preserved alongside this file.

All checklist items below begin **unchecked**. A gate is considered satisfied only when the engineer performing the verification ticks the corresponding box and the accompanying artifact (log output, screenshot, wireshark capture, or benchmark table) is committed or referenced. Unit tests with mocked I/O do **not** satisfy gates that require live, end-to-end evidence (per AAP §0.8.4).

## Gate 1 — Live Smoke Tests

Gate 1 verifies end-to-end boundary behavior on the three in-scope binary crates using **real network and terminal traffic**, not mocked harnesses. Each bullet below must be exercised in a live process against a real peer before being ticked.

- [ ] `sshtalk` binary: live SSH session from an OpenSSH 8.x+ client connects, authenticates, and exchanges chat messages
  - Command: `cargo run --release --bin sshtalk &` then `ssh -p 4001 localhost`
  - Expected: `SSH-2.0-HeavyThing` identification line, successful `dh-group-exchange-sha256` key exchange, `aes256-cbc` + `hmac-sha2-256` transport
  - Artifact: Capture wireshark / tcpdump of handshake; paste identification banner into the sign-off evidence bundle
- [ ] `hnwatch` binary: live fetch from https://hacker-news.firebaseio.com/v0/topstories.json succeeds
  - Command: `cargo run --release --bin hnwatch`
  - Expected: TUI renders at least one story from HN top stories within the 150-item cap (`main_item_limit = 150`)
  - Artifact: Screenshot or stdin/stdout capture
- [ ] `webserver` binary: live HTTP request serviced end-to-end
  - Command: `cargo run --release --bin webserver -- -bind 127.0.0.1:8080 -sandbox /tmp/wwwroot &` then `curl -v http://127.0.0.1:8080/`
  - Expected: HTTP/1.1 response with `Server: HeavyThing`-style identification and static file content
  - Artifact: Full `curl -v` output captured

> Unit tests with mocked I/O do **not** satisfy Gate 1. Only live, end-to-end runs against the real kernel network stack, a real OpenSSH client, and the real public HN API count as Gate 1 evidence. See AAP §0.8.4 for the governing rule.

## Gate 2 — Zero-Warning Build

Gate 2 confirms that the entire Cargo workspace compiles clean under the `-D warnings` flag required by AAP §0.8.3 and that no `#[allow(...)]` suppressions were used to silence warnings in any source file.

- [ ] Workspace builds clean under `RUSTFLAGS="-D warnings"`
  - Command: `cargo build --release`
  - Expected: Exit code 0, no warnings on any crate
- [ ] `.cargo/config.toml` contains `rustflags = ["-D", "warnings"]` under `[build]`
- [ ] No `#[allow(warnings)]`, `#[allow(unused)]`, `#[allow(dead_code)]` suppressions present in any `crates/**/*.rs` file
  - Verification command: `grep -rn "#\[allow" crates/ | grep -v "#\[cfg_attr" | wc -l` should return 0
- [ ] Clippy runs clean with default lints
  - Command: `cargo clippy --workspace --all-targets --release -- -D warnings`
  - Expected: Exit code 0
- [ ] Formatting is normalized with `rustfmt`
  - Command: `cargo fmt --all -- --check`
  - Expected: Exit code 0

## Gate 3 — Performance Baseline

Gate 3 asserts that the Rust port is within 3× of the assembly baseline for the three workloads mandated by AAP §0.8.5. Raw `criterion` output, hardware provenance, and any root-cause analysis live in `BENCHMARK_REPORT.md`; this sign-off records only whether the gate passed.

- [ ] `BENCHMARK_REPORT.md` exists at the repository root
- [ ] All three benchmarks run and produce output
  - [ ] AES-128-CBC throughput (`crates/heavything/benches/aes_cbc.rs`)
  - [ ] SHA-256 throughput (`crates/heavything/benches/sha256.rs`)
  - [ ] HTTP round-trip latency (`crates/heavything/benches/http_roundtrip.rs`)
- [ ] Assembly baseline measurements captured by running pre-built binaries (`rwasa/rwasa`, plus any example binaries for primitive throughput)
- [ ] Rust measurements stay within 3× of assembly baseline OR written root-cause analysis is present for any regression exceeding 3×
- [ ] `criterion --save-baseline assembly` / `--baseline assembly` workflow was used so the Rust-vs-assembly delta is reproducible

> **Note**: The actual benchmark numbers — criterion output tables, iteration counts, CPU model, and delta-versus-baseline figures — live in `BENCHMARK_REPORT.md`. This checklist records only the pass/fail state of the Gate 3 criteria.

## Gate 4 — Named Real-World Artifacts

Gate 4 verifies that each binary inter-operates with a named real-world peer: a real OpenSSH client for `sshtalk`, the real HN Firebase API for `hnwatch`, and `curl` for `webserver`. These artifacts are the concrete external integrations called out by the user's prompt and AAP §0.8.10.

- [ ] `sshtalk` interoperates with a real OpenSSH 8.x+ client (verified via `ssh -V && ssh -p 4001 localhost`)
- [ ] `hnwatch` retrieves live data from https://hacker-news.firebaseio.com/ — TLS 1.2/1.3 certificate chain validates against Mozilla root CAs (`webpki-roots`)
- [ ] `webserver` serves static files correctly when addressed via `curl -v http://localhost:...` and `curl -kv https://localhost:...` (with `-tls` configured)
- [ ] `webserver` emits the exact `Strict-Transport-Security: max-age=31536000; includeSubDomains` header when `webserver_hsts = 1`
- [ ] `webserver` emits an `X-NB` BREACH-mitigation header (1–48 random bytes) on TLS+gzip responses
- [ ] OCSP stapling refresh and retry timers (`7200s` refresh, `300s` retry) fire at their assembly-baseline intervals when `-tls` is used with a cert carrying OCSP URLs

## Gate 5 — API Contract Verification

Gate 5 confirms that the observable interface surface — CLI flags, exit codes, identification strings, and file formats — is preserved byte-identically with the assembly baseline, so downstream consumers (shell scripts, init-system unit files, OpenSSH, curl, syslogd) cannot tell the difference.

- [ ] CLI argument format for `webserver` matches the assembly baseline exactly: `-cpu N`, `-runas USER`, `-tls PEM`, `-bind ADDR:PORT`, `-fastcgi PATTERN ADDR`, `-vhost HOST`, `-sandbox PATH`, `-funcmatch PATTERN`, `-background`, `-new`
- [ ] Exit codes match assembly baseline exactly:
  - [ ] 99 = heap mmap/mremap failure (preserved for API parity even though Rust uses std allocator)
  - [ ] 98 = profiler stack overrun (preserved for API parity)
  - [ ] 97 = epoll minfds not met (ulimit < 4096)
  - [ ] 96 = epoll_create failure (tokio runtime init failure)
- [ ] SSH identification string is `SSH-2.0-HeavyThing` byte-for-byte
- [ ] HTTP response `Server:` header reflects the HeavyThing identity (exact string per assembly `webserver.inc`)
- [ ] `sshtalk` missing SSH host keys in `/etc/ssh` → stderr error + exit 1 (preserved)
- [ ] `hnwatch` default navstring = `"topstories"`; `main_item_limit` = 150
- [ ] `syslog` output format: RFC 3164 over `AF_UNIX` / `SOCK_DGRAM` to `/dev/log`
- [ ] `webserver` privilege-drop ordering preserved: `bind → setgid → setuid → fork` (per AAP §0.1.1)
- [ ] Timer semantics preserved: return value `0` means reset; non-zero means fire fatality/teardown (AAP §0.1.1)

## Gate 6 — Unsafe Audit

Gate 6 confirms that every `unsafe` block introduced by the Rust port is accounted for in `UNSAFE_AUDIT.md` with location, reason, and safety invariant; that the total site count stays within the 50-site budget (or is accompanied by per-site written justification); and that every FFI / raw-syscall boundary has a corresponding integration test.

- [ ] `UNSAFE_AUDIT.md` exists at the repository root
- [ ] Every `unsafe` block in `crates/` is listed with file:line, reason, and safety invariant
- [ ] Total unsafe site count is ≤ 50 OR per-site written justification is present for any count exceeding 50
- [ ] Every FFI / raw-syscall boundary site has a corresponding integration test in `crates/heavything/tests/ffi_boundary.rs`:
  - [ ] `test_raw_terminal_roundtrip` — `libc::tcgetattr` / `libc::tcsetattr` / `libc::cfmakeraw`
  - [ ] `test_fork_workers` — `nix::unistd::fork`
  - [ ] `test_setuid_setgid_drop` — `nix::unistd::{setuid, setgid}`
  - [ ] `test_prctl_pdeathsig` — `nix::sys::prctl::set_pdeathsig`
  - [ ] `test_mmap_file_cache` — `memmap2::Mmap`
  - [ ] `test_sigwinch_handler` — `tokio::signal::unix::signal`
- [ ] Audit inventory matches actual `unsafe` blocks: cross-check via `grep -rn 'unsafe' crates/ --include='*.rs'`
- [ ] Every audit entry includes a `// SAFETY:` comment at the `unsafe` block itself, as required by AAP §0.7.4.2

## Gate 7 — All Five Subsystems Translated

Gate 7 verifies that the translation is complete and balanced — all five subsystems defined in AAP §0.4.1.1 are present with the exact file inventory specified in AAP §0.5.1, and that every integration test surface called for by AAP §0.3.1.2 is delivered.

- [ ] `heavything::crypto` module complete with all listed files: `aes.rs`, `sha1.rs`, `sha2.rs`, `md5.rs`, `hmac.rs`, `hmac_drbg.rs`, `pbkdf2.rs`, `scrypt.rs`, `bigint.rs`, `dh.rs`, `x509.rs`, `rng.rs`
- [ ] `heavything::net` module complete with: `io.rs`, `runtime.rs`, `dns.rs`, `child.rs`, `blacklist.rs`, `url.rs`, `http/**`, `fcgi.rs`, `tls.rs`, `ssh/**`
- [ ] `heavything::tui` module complete with: `object.rs`, `render.rs`, `terminal.rs`, `ansi.rs`, `geometry.rs`, `gridguts.rs`, `lock.rs`, and all 27 widgets under `widgets/`
- [ ] `heavything::ds` module complete with: `list.rs`, `maps.rs`, `buffer.rs`, `memfuncs.rs`
- [ ] `heavything::util` module complete with: `string.rs`, `unicodecase.rs`, `string_math.rs`, `crc.rs`, `base64.rs`, `json.rs`, `zlib.rs`, `png.rs`, `formatter.rs`, `math.rs`, `date.rs`, `file.rs`, `dir.rs`, `sysinfo.rs`, `syslog.rs`, `sleeps.rs`, `mapped.rs`, `privmapped.rs`, `mappedheap.rs`, `profiler.rs`, `vdso.rs`
- [ ] All three binary crates (`sshtalk`, `hnwatch`, `webserver`) build and run
- [ ] Integration tests per subsystem exist under `crates/heavything/tests/`:
  - [ ] `crypto_integration.rs`
  - [ ] `net_integration.rs`
  - [ ] `tui_integration.rs`
  - [ ] `ds_integration.rs`
  - [ ] `util_integration.rs`
  - [ ] `ffi_boundary.rs`
- [ ] All six integration test files compile and pass under `cargo test --workspace`
- [ ] No subsystem is stubbed or marked `todo!()` / `unimplemented!()` — complete implementations per AAP §0.5.4 (single-phase delivery)

## Gate 8 — Integration Sign-off

Gate 8 is this document itself. The checklist below is the terminal acceptance criterion for the project: every preceding gate is ticked, every deliverable document is present, and the workspace is reproducible from a clean machine using the recipe in the appendix.

- [ ] All preceding gates (1–7) passed
- [ ] `UNSAFE_AUDIT.md`, `BENCHMARK_REPORT.md`, and this file committed to the repository
- [ ] `README.md` updated with Rust build instructions
- [ ] `Cargo.lock` committed for reproducibility
- [ ] `rust-toolchain.toml` pins stable channel
- [ ] `cargo build --release` completes in clean state with no warnings
- [ ] `cargo test` passes on the default offline suite
- [ ] `HEAVYTHING_LIVE_TESTS=1 cargo test` passes when network is available
- [ ] The preserved assembly sources (106 `.inc` files plus the three in-scope `.asm` entry points) remain untouched in the repository, honoring the Minimal Change Clause (AAP §0.8.2)
- [ ] The GPLv3 copyright headers (© 2015–2018 2 Ton Digital, Jeff Marrison) are preserved in the ported Rust sources (AAP §0.8.6)

### Sign-off

| Role        | Name      | Date      | Signature |
|-------------|-----------|-----------|-----------|
| Engineering | _________ | _________ | _________ |
| QA          | _________ | _________ | _________ |
| Release     | _________ | _________ | _________ |

## Appendix — Build Reproduction

The following recipe reproduces the full Gate 2, Gate 3, and Gate 7 build artifacts from a clean Linux x86_64 machine. It is the canonical set of commands a reviewer should run when validating the sign-off claims above.

```bash
# 1. Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# 2. Clone the repository (repository URL is project-specific; placeholder shown)
git clone <repo-url> && cd <repo-dir>

# 3. Build the workspace
cargo build --release

# 4. Run the test suite
cargo test --workspace

# 5. Run benchmarks (takes several minutes)
cargo bench --workspace

# 6. (Optional) Run live tests with network access
HEAVYTHING_LIVE_TESTS=1 cargo test --workspace -- --include-ignored
```

### Running the three binary crates

```bash
# sshtalk — SSH chat on port 4001 (requires /etc/ssh host keys)
cargo run --release --bin sshtalk

# hnwatch — Hacker News terminal watcher
cargo run --release --bin hnwatch

# webserver — rwasa equivalent; bind, sandbox, optional TLS
cargo run --release --bin webserver -- \
  -cpu 4 \
  -bind 0.0.0.0:8080 \
  -sandbox /var/www \
  -runas nobody
```

### Verifying zero-warning build

```bash
# Enforces the AAP §0.8.3 zero-warning policy
RUSTFLAGS="-D warnings" cargo build --release
cargo clippy --workspace --all-targets --release -- -D warnings
cargo fmt --all -- --check
```

### Regenerating the Unsafe Audit cross-reference

```bash
# Count unsafe blocks and cross-check against UNSAFE_AUDIT.md
grep -rnE '\bunsafe\b' crates/ --include='*.rs' | wc -l
grep -rn 'unsafe' crates/ --include='*.rs' > /tmp/unsafe_sites.txt
diff <(sort /tmp/unsafe_sites.txt) <(grep -oE 'crates/[^ ]+\.rs' UNSAFE_AUDIT.md | sort -u)
```

### Reproducing the benchmark baseline comparison

```bash
# Save assembly baseline (requires pre-built rwasa, example AES/SHA binaries)
cargo bench --bench aes_cbc -- --save-baseline assembly
cargo bench --bench sha256  -- --save-baseline assembly
cargo bench --bench http_roundtrip -- --save-baseline assembly

# Compare Rust against saved baseline — delta tables land in target/criterion/
cargo bench --bench aes_cbc -- --baseline assembly
cargo bench --bench sha256  -- --baseline assembly
cargo bench --bench http_roundtrip -- --baseline assembly
```

## Appendix — Related Deliverables

| Artifact                  | Purpose                                                                 | Gate covered  |
|---------------------------|-------------------------------------------------------------------------|---------------|
| `UNSAFE_AUDIT.md`         | Inventory of every `unsafe` block with invariants and test references   | Gate 6        |
| `BENCHMARK_REPORT.md`     | Raw criterion output + assembly-vs-Rust deltas + hardware provenance    | Gate 3        |
| `INTEGRATION_SIGNOFF.md`  | This document — the Gate 8 acceptance checklist                         | Gate 8        |
| `README.md`               | Rust build instructions plus preserved FASM instructions                | Gate 8        |
| `Cargo.lock`              | Pinned transitive dependency graph for reproducible builds              | Gate 2, 8     |
| `rust-toolchain.toml`     | Stable channel pin for reproducible builds                              | Gate 2, 8     |
| `.cargo/config.toml`      | `RUSTFLAGS="-D warnings"` enforcement                                   | Gate 2        |
| `crates/heavything/`      | Library crate covering crypto, net, tui, ds, util subsystems            | Gate 7        |
| `crates/sshtalk/`         | Binary crate equivalent to `sshtalk/sshtalk.asm`                        | Gate 1, 4, 5  |
| `crates/hnwatch/`         | Binary crate equivalent to `hnwatch/hnwatch.asm`                        | Gate 1, 4, 5  |
| `crates/webserver/`       | Binary crate equivalent to `rwasa/rwasa.asm`                            | Gate 1, 4, 5  |

Every row in the table above must exist in the repository at the moment the Release-role signature is applied below Gate 8. Missing artifacts invalidate the sign-off and the release must be held.
