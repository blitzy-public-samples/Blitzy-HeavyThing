# webslap

HTTP/HTTPS load-testing utility with a multi-process worker pool, preemptive DNS resolution, and an optional live terminal status display.

## Overview

webslap is an ApacheBench-style load generator (Source: /webslap/webslap.asm:22–23) that drives sustained HTTP/1.x or HTTPS traffic against one or more URLs with configurable concurrency, total request count, and multi-process fan-out. Two build targets are produced from this folder: the standard `webslap`, and the TLS-minimalist `webslap_tlsmin` variant — the latter differs structurally from the standard build only in that it substitutes `tlsmin_defaults.inc` for `../ht_defaults.inc` so that `tls_minimalist = 1` and `webclient_maxconns = 6` are in effect at compile time (Source: /webslap/webslap_tlsmin.asm:50, /webslap/tlsmin_defaults.inc:319, /webslap/tlsmin_defaults.inc:509). Internally, the tool exercises the HeavyThing library's `webclient`, `tls`, `epoll`, `epoll_dns`, and `epoll_child` subsystems (Source: /webslap/webslap.asm:46–51), and identifies itself as `WebSlap v1.12` in its startup greeting (Source: /webslap/webslap.asm:161).

## Architecture Fit

webslap is a terminal-node tool: no module in the HeavyThing library imports it, and it links statically against the library's `.inc` files as a standalone ELF64 executable.

### Dependencies In

| HeavyThing module | Role within webslap |
|---|---|
| `../webclient.inc` | HTTP/1.x client issued by each worker per channel |
| `../tls.inc` | TLS 1.2 client side, used for `https://` URLs |
| `../epoll.inc` | Event loop driving every socket, timer, and IPC channel |
| `../epoll_dns.inc` | Asynchronous DNS resolver used by the preflight step (Source: /webslap/webslap.asm:200–205) |
| `../epoll_child.inc` | Master/worker fork and socketpair IPC (Source: /webslap/master.inc:244–266) |
| `../url.inc` | URL parsing of argv operands (Source: /webslap/webslap.asm:99–102) |
| `../mimelike.inc` | HTTP request and response header handling |
| `../list.inc`, `../maps.inc`, `../buffer.inc` | Per-URL result aggregation and counters |
| `../tui_label.inc`, `../tui_statusbar.inc`, `../tui_terminal.inc`, `../tui_object.inc` | Optional live TUI status panel (Source: /webslap/master_ui.inc:38–104) |
| `../formatter.inc`, `../date.inc` | TSV and JSON formatting, timestamp rendering |

### Dependencies Out

None. No library module consumes webslap.

### Process Model

A single master process performs argument parsing and a one-shot preemptive DNS lookup for every distinct URL host, then forks `[cpucount]` worker processes via `epoll_child` and sends a `'DOIT'` command message to each worker to start the benchmark (Source: /webslap/webslap.asm:135–158, /webslap/master.inc:244–266, /webslap/master.inc:296–304). Each worker maintains up to `[concurrency]` in-flight channels using 88-byte per-channel records (Source: /webslap/worker.inc:42–54). Workers stream per-request result records back to the master over the parent socketpair; the master aggregates totals, per-URL statistics, response-code histograms, and latency breakdowns (Source: /webslap/master.inc:500–600). Each worker-to-master message carries ten fields: URL, response code, header size, body size, bytes received, keepalive flag, `ctime`, `dtime`, `ttime`, and `wait` (Source: /webslap/worker.inc:215–216).

## Key Components

| File | Purpose |
|---|---|
| `./webslap.asm` | Standard-variant entrypoint: `_start`, argument parsing, preemptive DNS, transfer to `master` (Source: /webslap/webslap.asm:58–159) |
| `./webslap_tlsmin.asm` | TLS-minimalist entrypoint; structurally identical to `webslap.asm` except it substitutes `include 'tlsmin_defaults.inc'` for `include '../ht_defaults.inc'` (Source: /webslap/webslap_tlsmin.asm:50) |
| `./globals.inc` | Per-tool global state: request count, concurrency, cpucount, URL list, output file handles, and feature-toggle flags (Source: /webslap/globals.inc:24–42) |
| `./master.inc` | Master process: worker spawn via `epoll_child`, benchmark orchestration, `childcomms` result aggregation, and TSV/JSON output (Source: /webslap/master.inc:22, /webslap/master.inc:244–302) |
| `./master_ui.inc` | Optional TUI status panel built from `tui_label`, `tui_statusbar`, and `tui_terminal`; 100ms timer-driven repaints (Source: /webslap/master_ui.inc:22, /webslap/master_ui.inc:94) |
| `./worker.inc` | Per-worker request loop, `channel_fire` launch, and `channel_response` callback that assembles the parent-bound result record (Source: /webslap/worker.inc:22, /webslap/worker.inc:210–216) |
| `./tlsmin_defaults.inc` | Local copy of `../ht_defaults.inc` with two deltas — `tls_minimalist = 1` and `webclient_maxconns = 6`; consumed only by `webslap_tlsmin.asm` (Source: /webslap/tlsmin_defaults.inc:319, /webslap/tlsmin_defaults.inc:509) |

Compiled outputs — `webslap`, `webslap.o`, `webslap_tlsmin`, and `webslap_tlsmin.o` — are build artifacts and are not documented as source units.

## CLI Reference

webslap accepts one or more URL operands of the form `[POST:filename:contenttype:]http[s]://hostname[:port]/path[?query][#ref]` and processes options in any order (Source: /webslap/webslap.asm:525).

### Options with arguments

| Flag | Argument | Default | Purpose | Parse site |
|---|---|---|---|---|
| `-n` | `requests` | `1` | Total number of HTTP requests to issue across all workers (Source: /webslap/globals.inc:27) | /webslap/webslap.asm:342, /webslap/webslap.asm:365–380 |
| `-c` | `concurrency` | `1` | Number of simultaneous in-flight request channels per worker (Source: /webslap/globals.inc:28) | /webslap/webslap.asm:343, /webslap/webslap.asm:382–397 |
| `-cpu` | `count` | `2` | Number of worker processes to fork; capped at `2 × sysinfo$cpucount` (Source: /webslap/globals.inc:29, /webslap/webslap.asm:412–415) | /webslap/webslap.asm:344, /webslap/webslap.asm:399–418 |
| `-first` | `URL` | none | Visit this URL once before starting the benchmark, suitable for warm-up or session setup (Source: /webslap/globals.inc:30) | /webslap/webslap.asm:345, /webslap/webslap.asm:420–445 |
| `-g` | `filename` | none | Write per-request TSV output to this file; columns are `URL`, `time`, `rcode`, `ctime`, `dtime`, `ttime`, `wait` (Source: /webslap/master.inc:282) | /webslap/webslap.asm:346, /webslap/webslap.asm:447–458 |
| `-json` | `filename` | none | Write the final aggregated results to this JSON file (Source: /webslap/globals.inc:32) | /webslap/webslap.asm:347, /webslap/webslap.asm:465–477 |

### Toggle options

All toggle flags default to **enabled** in `globals.inc`; passing the flag flips the corresponding global to `0` via the `argbool` macro, which uses a conditional move from a zero register when the flag is present (Source: /webslap/webslap.asm:327–341, /webslap/globals.inc:34–41).

| Flag | Disables | Default state | Parse site |
|---|---|---|---|
| `-nokeepalive` | HTTP keep-alive on every channel | enabled | /webslap/webslap.asm:348 |
| `-nogz` | `Accept-Encoding: gzip` and response gunzip | enabled | /webslap/webslap.asm:349 |
| `-nocookies` | Per-channel session cookie jar | enabled | /webslap/webslap.asm:350 |
| `-notlsresume` | TLS session resumption across requests | enabled | /webslap/webslap.asm:351 |
| `-noetag` | `ETag` / `If-None-Match` handling | enabled | /webslap/webslap.asm:352 |
| `-nolastmodified` | `Last-Modified` / `If-Modified-Since` handling | enabled | /webslap/webslap.asm:353 |
| `-ordered` | Randomized URL arglist visitation; URLs are then visited in argv order | randomized | /webslap/webslap.asm:354 |
| `-noui` | Live TUI status display; plain-text status is printed instead | TUI on | /webslap/webslap.asm:355, /webslap/master.inc:275–290 |

### Argument sanitization

After parsing, the master clamps the effective run parameters: concurrency is reduced to the request count when it exceeds it, and worker count is reduced to the effective concurrency when it exceeds it (Source: /webslap/webslap.asm:117–130). Non-numeric input to `-n`, `-c`, or `-cpu` exits with status `1` and prints `Nonsense argument:` (Source: /webslap/webslap.asm:485–493); `-cpu` values larger than `2 × sysinfo$cpucount` exit with status `1` and print `Insane CPU count:` (Source: /webslap/webslap.asm:495–504); an unrecognized flag exits with status `1` and prints `Unrecognized option:` (Source: /webslap/webslap.asm:362); a DNS lookup failure during preflight exits with status `1` and prints `DNS lookup failed for host:` (Source: /webslap/webslap.asm:208–224).

## Usage

### Include structure

The entrypoint follows the three-file include contract used by every HeavyThing application (see `../docs/architecture.md`). Abridged from `/webslap/webslap.asm:46–61` and `/webslap/webslap.asm:543`:

```nasm
include '../ht_defaults.inc'
include '../ht.inc'

include 'globals.inc'
include 'worker.inc'
include 'master.inc'

public _start
falign
_start:
    call    ht$init
    ; argument parsing and preemptive DNS omitted;
    ; control transfers to `master` on success

include '../ht_data.inc'            ; required last
```

The `webslap_tlsmin.asm` variant is identical in structure; it only replaces the first include with `include 'tlsmin_defaults.inc'` (Source: /webslap/webslap_tlsmin.asm:50).

### Build

```bash
# Standard build (uses ../ht_defaults.inc, tls_minimalist = 0):
fasm -m 524288 webslap.asm
ld -o webslap webslap.o

# TLS-minimalist build (uses local tlsmin_defaults.inc, tls_minimalist = 1):
fasm -m 524288 webslap_tlsmin.asm
ld -o webslap_tlsmin webslap_tlsmin.o
```

The `-m 524288` flag raises FASM's symbol-pool allocation so the assembler can complete the build without running out of memory. See `../docs/building.md` for the general build flow and prerequisites.

### Typical invocations

```bash
# Minimum: a single request against one URL
./webslap https://example.com/

# 10000 requests, 32 concurrent channels per worker, 4 workers
./webslap -n 10000 -c 32 -cpu 4 https://example.com/

# Multiple URLs, randomized visitation, TSV per-request log
./webslap -n 50000 -c 64 -cpu 8 -g run.tsv \
    https://example.com/ https://example.com/health

# Headless (no TUI), ordered URL walk, JSON result dump
./webslap -noui -ordered -n 5000 -c 16 -json results.json \
    https://example.com/ https://example.com/api/ping

# POST a file, taking the request body and content-type from disk
./webslap -n 1000 -c 8 \
    POST:body.json:application/json:https://example.com/api/ingest
```

The `POST:filename:contenttype:` prefix on a URL operand is recognized by the argument parser (Source: /webslap/webslap.asm:281) and loads `filename` as the request body with the supplied MIME type.

## Configuration

### Compile-time knobs

webslap reads compile-time constants from `../ht_defaults.inc` (standard build) or `./tlsmin_defaults.inc` (minimalist build). The knobs below materially affect the tool's behavior.

| Knob | Relevance to webslap |
|---|---|
| `webclient_global_dnscache` | Hard prerequisite. The preflight calls `wcdns$lookup_ipv4` only when this is `1`; otherwise the build aborts with the FASM diagnostic `HeavyThing library setting webclient_global_dnscache is required for webslap` (Source: /webslap/webslap.asm:200–205, /webslap/webslap_tlsmin.asm:204–209) |
| `tls_minimalist` | `0` in the standard build (from `../ht_defaults.inc`); forced to `1` in `webslap_tlsmin` via `./tlsmin_defaults.inc:319`. When `1`, the TLS client advertises only RSA/AES-128/CBC ciphersuites and excludes DHE-based suites (Source: /webslap/tlsmin_defaults.inc:319). The full support matrix is documented in `../docs/security.md` |
| `webclient_maxconns` | `4` in the standard build (from `../ht_defaults.inc`); raised to `6` in `webslap_tlsmin` via `./tlsmin_defaults.inc:509`. Defines the upper limit on simultaneous connections per hostname in the webclient — raised in the minimalist build to permit higher per-host concurrency when cipher negotiation is cheaper (Source: /webslap/tlsmin_defaults.inc:509) |
| `epoll_minfds` | Must accommodate every per-channel socket plus listener and parent-socketpair descriptors; insufficient descriptors trigger exit code `97` during `ht$init` (Source: /ht.inc:38–42) |
| `epoll_stacksize` | Size of the per-coroutine stack backing every in-flight channel |
| `epoll_readsize` | Per-`recv` buffer size; affects the cost of each TCP read |

Server-side TLS knobs (`tls_server_sessioncache`, `tls_server_ocsp_stapling`) are defined for web-server code and are not exercised by webslap.

### Runtime configuration

All runtime tuning is performed through CLI flags; webslap has no configuration file. Worker count, concurrency, request count, feature toggles, and output file paths are all set on the command line — see the [CLI Reference](#cli-reference) section above.

## Limitations

- HTTP/1.x only. `../webclient.inc` does not implement HTTP/2 or HTTP/3.
- TLS 1.2 only. `../tls.inc` does not implement TLS 1.3; the `webslap_tlsmin` build further narrows the cipher set — see `../docs/security.md`.
- Linux x86_64 only. The tool uses Linux `epoll` and direct `syscall` against the x86_64 System V ABI.
- DNS resolution runs once at startup for every distinct URL host (preemptive DNS, Source: /webslap/webslap.asm:135–158). DNS changes made after launch are not observed until the tool is restarted.
- Cookie state, when enabled, is per-channel inside a single worker; it is neither shared across channels nor across workers (Source: /webslap/globals.inc:36).
- Per-request data is emitted only by `-g` (TSV) and `-json`; there is no long-running persistent log beyond these outputs.
- Running out of local ephemeral ports yields undefined behavior. The author states: "If you use this thing in a 'maniac' sorta way, whereby we actually run out of local available ports, the results are undefined" (Source: /webslap/webslap.asm:38–41). Tune the kernel's `ip_local_port_range` and keep-alive settings accordingly.
- Startup failures in the HeavyThing core inherit exit codes `96`–`99` from `ht$init` (Source: /ht.inc:38–42); see `../docs/architecture.md` for the full table.
- webslap is a showcase for the HeavyThing networking stack; it is not positioned as a replacement for full-featured load-testing frameworks.

## See Also

- [`../net/README.md`](../net/README.md) — HeavyThing networking subsystem (`webclient`, TLS, SSH, `epoll`, DNS)
- [`../rwasa/README.md`](../rwasa/README.md) — rwasa web server, the matched server-side tool for end-to-end tests
- [`../docs/architecture.md`](../docs/architecture.md) — master/worker IPC via `epoll_child`, event-loop lifecycle, exit-code table
- [`../docs/security.md`](../docs/security.md) — TLS version, cipher support, and `tls_minimalist` differences
- [`../docs/building.md`](../docs/building.md) — prerequisites, FASM and `ld` build flow, three-file include contract
- [`../README.md`](../README.md) — project-level overview
- [`../LICENSE`](../LICENSE) — GPLv3 license text

## License

webslap, like the rest of the HeavyThing repository, is distributed under the GNU General Public License v3. See [`../LICENSE`](../LICENSE) for the full text (Source: /webslap/webslap.asm:9–19).
