# HeavyThing

HeavyThing is a dual-codebase project. The **legacy assembly library** — 106
`.inc` files plus the showcase applications in `dhtool/`, `examples/`,
`hnwatch/`, `rwasa/`, `sshtalk/`, `toplip/`, `util/`, and `webslap/` — remains
in place and continues to build with FASM as described at
<https://2ton.com.au/HeavyThing/>. A **Rust port** lives alongside in the
`crates/` subtree as a Cargo workspace with one library crate (`heavything`)
and three binary crates (`sshtalk`, `hnwatch`, `webserver`).

Licensed under the GNU General Public License v3.0 — © 2015–2018 2 Ton
Digital, Jeff Marrison. See `LICENSE` for the full text.

## Building with FASM (original assembly library)

The original HeavyThing library is written in pure x86_64 Linux assembly and
assembled with [FASM](https://flatassembler.net/). Pre-built static ELF64
binaries for the showcase applications are already present in the repository
for reference:

- `rwasa/rwasa`
- `sshtalk/sshtalk`
- `hnwatch/hnwatch`
- `toplip/toplip`
- `webslap/webslap`
- `dhtool/dhtool`
- `util/bigint_tune`, `util/make_dh_static`, `util/mersenneprimetest`

Full FASM build instructions and documentation are available at
<https://2ton.com.au/HeavyThing/>. The assembly build process is unchanged
by the Rust port and the assembly sources are preserved verbatim.

## Building with Cargo (Rust port)

### Prerequisites

Install the stable Rust toolchain using `rustup`:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

- Linux x86_64 only — the workspace targets `x86_64-unknown-linux-gnu`;
  Windows and macOS are not supported.
- Requires Linux kernel ≥ 2.6.28 for `epoll_create1`, `accept4`,
  `SOCK_CLOEXEC`, and `SOCK_NONBLOCK`.
- Requires `ulimit -n` ≥ 4096; the `webserver` binary exits with code 97
  if the per-process file-descriptor limit is lower.

### Workspace Build

From the repository root:

```bash
cargo build --release
```

This builds the `heavything` library crate and all three binary crates
(`sshtalk`, `hnwatch`, `webserver`) with warnings-as-errors enforced via
`.cargo/config.toml` (`RUSTFLAGS="-D warnings"`). Because the same
`.cargo/config.toml` pins `target = "x86_64-unknown-linux-gnu"` per
AAP §0.3.2.4 (Linux x86_64 only), release artifacts land in
`target/x86_64-unknown-linux-gnu/release/` rather than the default
`target/release/`.

### Running the Binaries

```bash
cargo run --release --bin sshtalk   -- [args]
cargo run --release --bin hnwatch   -- [args]
cargo run --release --bin webserver -- [args]
```

- `sshtalk` — starts the SSH-accessible multi-user chat server on port
  4001. Requires readable SSH host keys in `/etc/ssh`.
- `hnwatch` — starts the terminal Hacker News viewer. Requires network
  access to <https://hacker-news.firebaseio.com/>.
- `webserver` — starts the HTTP/HTTPS server (port of the `rwasa`
  assembly showcase). Requires bind permissions on the configured address.

Commonly used `webserver` flags:

- `-cpu N` — number of worker processes to fork.
- `-runas USER` — drop privileges to `USER` after binding.
- `-tls PEM` — enable TLS using the certificate and key in `PEM`.
- `-bind ADDR:PORT` — listen address and port (may be repeated).
- `-fastcgi PATTERN ADDR` — forward matching paths to a FastCGI backend.
- `-vhost HOST` — restrict this `-bind` to a virtual host.
- `-sandbox PATH` — chroot into `PATH` after binding.
- `-funcmatch PATTERN` — enable request-function matching.
- `-foreground` — keep the master process attached to the controlling
  terminal (the default behaviour is to fork into the background as a
  daemon, mirroring `rwasa.asm` and `master.inc`).
- `-new` — ignore pre-existing state and start fresh.

### Testing

```bash
cargo test
cargo test --workspace
```

Live network tests are gated behind the `HEAVYTHING_LIVE_TESTS` environment
variable:

```bash
HEAVYTHING_LIVE_TESTS=1 cargo test
```

Integration tests live in `crates/heavything/tests/` and cover crypto
known-answer vectors, live network I/O, TUI rendering, data-structure
semantics, utility round-trips, and FFI boundary safety.

### Benchmarking

```bash
cargo bench
```

Three benchmarks are provided in `crates/heavything/benches/`:

- `aes_cbc.rs` — AES-128-CBC throughput.
- `sha256.rs` — SHA-256 throughput.
- `http_roundtrip.rs` — epoll-driven HTTP round-trip latency.

Save a baseline and compare later runs against it:

```bash
cargo bench -- --save-baseline assembly
cargo bench -- --baseline   assembly
```

See `BENCHMARK_REPORT.md` at the repository root for the complete benchmark
report with Rust-vs-assembly comparisons.

## Project Layout

```
/
├── Cargo.toml              (Rust workspace manifest)
├── rust-toolchain.toml     (pins stable Rust, 2021 edition, x86_64-unknown-linux-gnu)
├── rustfmt.toml, clippy.toml
├── .cargo/config.toml      (RUSTFLAGS="-D warnings")
├── crates/
│   ├── heavything/         (library crate: crypto, net, tui, ds, util)
│   ├── sshtalk/            (binary crate: SSH chat server)
│   ├── hnwatch/            (binary crate: Hacker News terminal viewer)
│   └── webserver/          (binary crate: port of rwasa)
│
├── UNSAFE_AUDIT.md         (inventory of every `unsafe` block)
├── BENCHMARK_REPORT.md     (criterion benchmark results)
├── INTEGRATION_SIGNOFF.md  (integration sign-off checklist)
│
├── LICENSE, README, ChangeLog, 2ton.png
├── ht.inc, ht_defaults.inc, ht_data.inc
├── *.inc                   (the 106 assembly library modules)
├── rwasa/                  (original assembly web server)
├── sshtalk/                (original assembly SSH chat)
├── hnwatch/                (original assembly HN viewer)
├── toplip/                 (original assembly encryption tool — not ported)
├── webslap/                (original assembly load tester — not ported)
├── dhtool/                 (original assembly DH tool — not ported)
├── util/                   (original assembly utilities — not ported)
└── examples/               (assembly example programs — not ported)
```

## Behavioral Differences from Assembly Baseline

TLS cipher-suite support is the single architectural divergence introduced
by the Rust port:

- The original HeavyThing library negotiates classical DHE + AES-CBC-SHA256
  suites for TLS 1.2.
- The Rust port uses `rustls`, which negotiates ECDHE + AES-GCM /
  CHACHA20-Poly1305 for TLS 1.2 and adds TLS 1.3 support.
- Real-world HTTPS clients select the best mutually supported suite, so the
  observable "does HTTPS work" behavior is preserved.

For a complete list of behavioral preservations, see the module-level doc
comments in `crates/heavything/src/net/tls.rs`.

## Deliverable Documents

- `UNSAFE_AUDIT.md` — per-site inventory of every `unsafe` block in the
  Rust code, with location, reason, and safety invariant.
- `BENCHMARK_REPORT.md` — `criterion` benchmark output with assembly-vs-
  Rust comparisons.
- `INTEGRATION_SIGNOFF.md` — completed integration sign-off checklist.
