# rwasa — Rapid Web Application Server in Assembler

An HTTP/HTTPS server written entirely in x86_64 assembly, serving as both a standalone showcase of the HeavyThing library and a template for embedding native-assembler request handlers.

## Overview

`rwasa` is the flagship showcase application of the HeavyThing library. It is a full HTTP/1.x server — static files, FastCGI gateway, reverse-proxy (`-backpath`), virtual hosting, per-host sandboxing, TLS 1.2 termination, and a native-assembler request hook that illustrates how to embed custom request handling into the event loop (Source: /rwasa/rwasa.asm:22–37). The startup banner identifies the build as `rwasa v1.12` authored by Jeff Marrison, copyright © 2015 2 Ton Digital (Source: /rwasa/master.inc:146).

Two build variants ship in this directory. The standard variant, `rwasa`, is assembled against the repository-wide `../ht_defaults.inc` and exposes the library's full TLS cipher suite including DHE. The minimalist variant, `rwasa_tlsmin`, is identical in logic but substitutes a local `tlsmin_defaults.inc` so that two compile-time knobs differ: `tls_minimalist = 1` (disables everything but RSA/AES-128/CBC) and `webclient_maxconns = 6` (raises per-host concurrency). Rationale for the minimalist variant is preserved verbatim in [`./README.rwasa_tlsmin`](./README.rwasa_tlsmin) (Source: /rwasa/rwasa_tlsmin.asm:22–26, /rwasa/README.rwasa_tlsmin).

The binary is a statically-linked Linux x86_64 ELF executable with no libc dependency. All syscalls are issued directly; the process forks a master that drops privileges and then spawns worker subprocesses that handle the actual request traffic.

## Architecture Fit

### Dependencies In

| Dependency | Role |
|---|---|
| `../ht_defaults.inc` (or `./tlsmin_defaults.inc` for the tlsmin variant) | Compile-time configuration: TLS profile, webserver limits, webclient concurrency, logging toggles |
| `../ht.inc` | Library-wide includes: webserver engine, TLS stack, epoll loop, HTTP parser, mimelike request/response, URL parser, X.509 handling, buffer/list/string primitives |
| `../ht_data.inc` | Data-segment finale included at `/rwasa/rwasa.asm:152` and `/rwasa/rwasa_tlsmin.asm:154` — this is the three-file include contract enforced across the repository |

### Dependencies Out

None within the repository. `rwasa` is an application, not a library — no other subsystem or tool includes it.

### Process Model

`rwasa` uses a master-then-workers fork model implemented on top of `epoll_child`. The master process:

1. Initialises `ht$init`, parses CLI arguments, and builds one or more `webservercfg` objects in the global `[configs]` list (Source: /rwasa/rwasa.asm:119–141).
2. Installs the `asmcall` hook on every configuration via `webservercfg$function_map` so that requests ending in `.asmcall` (or the `-funcmatch` override) are dispatched to the native-assembly handler at `/rwasa/rwasa.asm:66`.
3. Enters `masterthread`, where it drops privileges via `setgid([runasgid])` followed by `setuid([runasuid])`; nonzero return branches to `.setgidfail` / `.setuidfail` and aborts startup (Source: /rwasa/master.inc:37–46).
4. Daemonises if `-foreground` was not set (Source: /rwasa/master.inc:49–73).
5. Forks `cpucount` workers, each spawned through `epoll_child(master$vtable, workerthread)`. Results are collected into the `[workers]` list (Source: /rwasa/master.inc:82–98).
6. Installs `master_ocsp_hook` so that OCSP-stapling updates observed in the master are broadcast to every worker (Source: /rwasa/master.inc:137, /rwasa/master.inc:271).
7. Enters `epoll$run` (Source: /rwasa/master.inc:140).

Each worker, on entry to `workerthread`, reinitialises the epoll loop and RNG, resets its syslog pid, attaches a `masterlink` pipe to the parent, and — when running with more than one CPU — installs the `worker_loghook` into `webservercfg$log_hook` and the `worker_tlscache` into `tls$sessioncache_hook`. Workers also receive a 1500ms timer to recreate per-configuration timers through `.newconfigtimer` (Source: /rwasa/worker.inc:42–105).

### Master/Worker IPC — Link-Message Protocol

All inter-process messages share an 8-byte header (`[+0]=type`, `[+4]=total_len`) followed by a message-type-specific payload. Three types are defined at `/rwasa/worker.inc:36–38`:

| Constant | Value | Direction | Purpose | Composer | Handler |
|---|---|---|---|---|---|
| `linkmessage_ocsp` | `0` | master -> all workers | Propagate an updated OCSP-stapling response for a given subject CN; oneshot broadcast capped at 4096 bytes per message | `master_ocsp_hook` (/rwasa/master.inc:271) | `masterlink$receive` `.ocsp` branch (/rwasa/worker.inc:277) |
| `linkmessage_log` | `1` | worker -> master | Forward access-log or error-log records from worker to master, which writes to `webservercfg$log` or `webservercfg$logerror` | `worker_loghook` (/rwasa/worker.inc:156) | `master$receive` `.logmessage` branch (/rwasa/master.inc:229) |
| `linkmessage_tlsupdate` | `2` | worker -> master -> other workers | Broadcast a new TLS session-cache entry (32-byte session id + 64-byte state, fixed 104-byte message) so that resumption works across workers | `worker_tlscache` (/rwasa/worker.inc:208) | master `.tlsbroadcast` (/rwasa/master.inc:210); worker `masterlink$receive` tlsupdate fallthrough (/rwasa/worker.inc:259–275) |

The worker `masterlink$receive` handler temporarily clears `tls$sessioncache_hook` when applying an inbound `linkmessage_tlsupdate` to avoid echoing the update back to the master (Source: /rwasa/worker.inc:265–269).

## Key Components

| File | Purpose |
|---|---|
| `./rwasa.asm` | Standard-build entry point. Contains `_start`, the `asmcall` demonstration hook, and the `.hookthemall` iterator that binds `asmcall` to every loaded `webservercfg`. Pulls `../ht_defaults.inc` for the full TLS profile (Source: /rwasa/rwasa.asm:47–52). |
| `./rwasa_tlsmin.asm` | Minimalist-build entry point. Byte-for-byte identical to `rwasa.asm` except the first include — line 49 pulls `./tlsmin_defaults.inc` instead of `../ht_defaults.inc`, producing a binary with reduced TLS cipher surface and higher webclient concurrency (Source: /rwasa/rwasa_tlsmin.asm:49). |
| `./arguments.inc` | CLI parser. Declares the 19 supported flags via `argcheck`/`argbool` macros at lines 106–124, provides the printed usage message at `.msg_usage` (lines 769–790), builds `webservercfg` objects, attaches TLS listeners, validates `/etc/passwd` for `-runas`, and emits errors for malformed arguments (Source: /rwasa/arguments.inc:106–124, /rwasa/arguments.inc:769–790). |
| `./master.inc` | Master process: privilege drop, daemonisation, worker fork, OCSP-stapling broadcast hook, master-side link-message receive dispatch, logwriter timer (1500ms) that iterates `[configs]` calling `webservercfg$timer` (Source: /rwasa/master.inc:37–46, /rwasa/master.inc:173–183, /rwasa/master.inc:271). |
| `./worker.inc` | Worker process: per-worker log/session hooks, master-link composer and receiver, OCSP-response application into each TLS PEM's X509 cert cache via `tls$pem_byptr` AVL walk (Source: /rwasa/worker.inc:36–38, /rwasa/worker.inc:156, /rwasa/worker.inc:208, /rwasa/worker.inc:239). |
| `./tlsmin_defaults.inc` | Local copy of `../ht_defaults.inc` with exactly two deltas relative to the repository-wide defaults — `tls_minimalist = 1` and `webclient_maxconns = 6`; consumed only by `rwasa_tlsmin.asm` (Source: /rwasa/tlsmin_defaults.inc:319, /rwasa/tlsmin_defaults.inc:509). |
| `./README.rwasa_tlsmin` | Preserved 6-line operator note explaining the motivation for the `rwasa_tlsmin` variant (Source: /rwasa/README.rwasa_tlsmin). |

## CLI Reference

All 19 flags are registered in the dispatch table at `/rwasa/arguments.inc:106–124`. The built-in usage text (visible on any parse error or missing `-bind`) lives at `/rwasa/arguments.inc:769–790`.

### No-argument flags

| Flag | Handler | Line | Behaviour |
|---|---|---|---|
| `-foreground` | `argbool` on `background` | 108 | Disable daemonisation; the master stays attached to the controlling terminal instead of forking to the background (default: background) |
| `-new` | `.argnew` | 211 | Start a new `webservercfg` object so that subsequent `-bind` / `-tls` / `-vhost` / `-sandbox` / `-fastcgi` / `-backpath` / `-indexfiles` / `-redirect` flags apply to it; requires at least one prior `-bind` (Source: /rwasa/arguments.inc:211, /rwasa/arguments.inc:232) |
| `-errsyslog` | `.argerrsyslog` | 458 | Route error-log output through syslog instead of (or in addition to) `-errlog` |

### Single-argument flags

| Flag | Handler | Line | Argument | Purpose |
|---|---|---|---|---|
| `-cpu` count | `.argcpu` | 136 | decimal | Number of worker processes to fork; capped at 2× detected CPU count via `sysinfo$cpucount` (default: 1) |
| `-runas` username | `.argrunas` | 199 | string | Drop privileges to this user after binding listeners; resolved against `/etc/passwd` (default: `nobody`) |
| `-bind` [addr:]port | `.argbind` | 240 | `addr:port` or `port` | Add an HTTP (or HTTPS if prefixed by a `-tls` flag) listener. Sub-handlers at `.argbind_portonly:295`, `.argbind_doit:310`, `.argbind_doit_notls:354`, `.argbind_pemerror:375`, `.argbind_badaddress:386`, `.argbind_badport:395` |
| `-tls` pemfile | `.argtls` | 404 | path | Attach the PEM cert/key to the **next** `-bind` so that listener becomes TLS-wrapped via `tls$new_server`; errors with `.argtls_noprior:416` if no pending bind |
| `-cachecontrol` secs | `.argcachecontrol` | 157 | decimal | `Cache-Control: max-age=…` value for static-file responses (default: 300) |
| `-filestattime` secs | `.argfilestattime` | 179 | decimal | File-stat cache lifetime — how long the server trusts a cached inode result before re-stating (default: 120) |
| `-logpath` directory | `.arglogpath` | 422 | path | Full directory path where access logs are written |
| `-errlog` filename | `.argerrlog` | 440 | path | Full filename for error-log output |
| `-backpath` address | `.argbackpath` | 492 | `host:port` or `/unix/path` | Reverse-proxy / upstream backend; used to forward requests to another HTTP origin |
| `-vhost` directory | `.argvhost` | 510 | path | Virtual-hosting root — requests for a host get served from `directory/<host>/…` |
| `-sandbox` directory | `.argsandbox` | 528 | path | Global chroot-style sandbox directory (full path) |
| `-indexfiles` list | `.argindexfiles` | 570 | comma-separated | Ordered list of index files to probe when a request resolves to a directory |
| `-redirect` url | `.argredirect` | 588 | URL | Send a redirect response to the supplied URL for every request matching the configuration |
| `-funcmatch` endswith | `.argfuncmatch` | 606 | string | Override the default `.asmcall` suffix that triggers the native-assembler hook |

### Two-argument flags

| Flag | Handler | Line | Arguments | Purpose |
|---|---|---|---|---|
| `-fastcgi` endswith address | `.argfastcgi` | 468 | suffix + `host:port` or `/unix/path` | Register a FastCGI mapping: URLs ending in `endswith` are forwarded to the supplied FastCGI endpoint |
| `-hostsandbox` host dir | `.arghostsandbox` | 546 | hostname + path | Per-host sandbox directory — overrides `-sandbox` for a specific `Host:` header value |

### Validation and exit paths

Argument parsing terminates in one of several labelled paths at `/rwasa/arguments.inc:622–767`: `.argdone:622`, `.passwdloop:633`, `.passwdfound:651`, `.missingbind:695` (no `-bind` ever seen), `.badetcpasswd:703`, `.passwdfail:711`, `.arg_next_free:719`, `.arg_next:726`, `.nonsensearg:731`, `.crazycpucount:741`, `.endofargs:751`, `.usage:759`.

## Usage

### Three-file include structure (both variants)

```nasm
; rwasa.asm — standard build
include '../ht_defaults.inc'          ; line 47 — full TLS profile
include '../ht.inc'                   ; line 48

include 'arguments.inc'               ; line 50
include 'worker.inc'                  ; line 51
include 'master.inc'                  ; line 52

; ... entry points and the asmcall hook ...

include '../ht_data.inc'              ; line 152 — finale
```

```nasm
; rwasa_tlsmin.asm — minimalist TLS build
include 'tlsmin_defaults.inc'         ; line 49 — local overrides
include '../ht.inc'                   ; line 50

include 'arguments.inc'               ; line 52
include 'worker.inc'                  ; line 53
include 'master.inc'                  ; line 54

; ... same logic as rwasa.asm ...

include '../ht_data.inc'              ; line 154 — finale
```

### Build

Build either variant with FASM plus GNU `ld`:

```bash
# Standard build
fasm -m 524288 rwasa.asm
ld -o rwasa rwasa.o

# Minimalist-TLS build
fasm -m 524288 rwasa_tlsmin.asm
ld -o rwasa_tlsmin rwasa_tlsmin.o
```

### Typical invocations

```bash
# Plain HTTP on port 8080, foreground, running as the invoking user
./rwasa -foreground -runas nobody -bind 8080

# HTTPS: PEM must contain cert + key; note -tls precedes its -bind
./rwasa -tls /etc/ssl/site.pem -bind 0.0.0.0:443 -bind 80

# Multi-process (4 workers) with access log and syslog errors
./rwasa -cpu 4 -logpath /var/log/rwasa -errsyslog -bind 80

# FastCGI for PHP
./rwasa -bind 80 -fastcgi .php /run/php/php-fpm.sock

# Reverse proxy: forward .api requests to an upstream
./rwasa -bind 80 -backpath api.internal:9000

# Per-host sandbox (multiple configurations via -new)
./rwasa -bind 80 -hostsandbox example.com /srv/example \
        -new -bind 8080 -sandbox /srv/default
```

The built-in `asmcall` demonstration handler at `/rwasa/rwasa.asm:66` responds to every URL ending in `.asmcall` (or the `-funcmatch` override) with a plain-text body synthesised from the parsed URL; copying `rwasa.asm`, editing the handler body, and reassembling is the canonical path for deploying custom native-assembler request processing (Source: /rwasa/rwasa.asm:24–34).

## Configuration

### Compile-time knobs (from `../ht_defaults.inc` unless noted)

Knobs are listed by subsystem. Citations point at `../ht_defaults.inc` because `/rwasa/tlsmin_defaults.inc` shares every line number with it except the two-line delta called out below.

**epoll**

| Knob | Default | Relevance to rwasa |
|---|---|---|
| `epoll_minfds` | `4096` | Minimum file-descriptor slot count reserved at startup; if the soft `RLIMIT_NOFILE` is below this the binary exits with code 97 (Source: /ht_defaults.inc:130) |
| `epoll_multiple_accepts` | `1` | Drain `accept()` in a loop per wake-up so a single epoll event can admit many pending connections (Source: /ht_defaults.inc:133) |
| `epoll_stacksize` | `4096` | Per-connection stack budget inside the epoll handler dispatcher, in bytes (Source: /ht_defaults.inc:148) |

**TLS**

| Knob | Default | Relevance to rwasa |
|---|---|---|
| `tls_server_cipher_order` | `1` | Server-preferred cipher ordering; when enabled the server's list wins the negotiation (Source: /ht_defaults.inc:300) |
| `tls_pem_refresh_interval` | `3600` | Seconds between PEM-file re-reads; enables cert hot-reload without restart (Source: /ht_defaults.inc:304) |
| `tls_minimalist` | `0` (standard) / `1` (tlsmin) | In the minimalist variant, restricts the TLS cipher list to RSA key-exchange with AES-128/CBC only — no DHE, no AES-256 (Source: /ht_defaults.inc:319, /rwasa/tlsmin_defaults.inc:319) |
| `tls_blacklist` | `86400` | Seconds an offending client IP stays on the TLS blacklist after repeated handshake failures (Source: /ht_defaults.inc:327) |
| `tls_server_sessioncache` | `3600` | TLS session-cache entry lifetime in seconds; longer values increase resumption hit rate at memory cost (Source: /ht_defaults.inc:334) |
| `tls_server_ocsp_stapling` | `1` | Enables OCSP-stapling refresh in the master, propagated to workers via `linkmessage_ocsp` (Source: /ht_defaults.inc:343) |

**webserver**

| Knob | Default | Relevance to rwasa |
|---|---|---|
| `webserver_maxheader` | `32768` | Maximum bytes allowed in an incoming HTTP request header block (Source: /ht_defaults.inc:443) |
| `webserver_maxrequest` | `64 * 1048576` | Maximum request body size, 64 MiB default (Source: /ht_defaults.inc:448) |
| `webserver_bigfile` | `32 * 1048576` | Threshold at which static-file responses switch to `mmap`-backed serving, 32 MiB default (Source: /ht_defaults.inc:455) |
| `webserver_autogzip` | `1` | Transparently gzip responses whose `Content-Type` is on the compressible list (Source: /ht_defaults.inc:458) |
| `webserver_initialsend` | `262144` | Bytes sent in the first write after a response header is emitted (Source: /ht_defaults.inc:467) |
| `webserver_subsequentsend` | `262144` | Bytes sent per subsequent write-completion callback (Source: /ht_defaults.inc:468) |
| `webserver_hotlist_statfreq` | `120` | Seconds between `stat()` refreshes for files in the hot-list cache (Source: /ht_defaults.inc:474) |
| `webserver_hotlist_time` | `900` | Seconds an unreferenced file is retained in the hot-list cache before eviction (Source: /ht_defaults.inc:479) |
| `webserver_hsts` | `1` | When a TLS listener is active, emit `Strict-Transport-Security` headers on responses (Source: /ht_defaults.inc:485) |
| `webserver_breach_mitigation` | `48` | Bytes of random padding inserted into compressible responses to frustrate BREACH-style attacks (Source: /ht_defaults.inc:499) |
| `webserver_fastcgi_postprocess` | `0` | When non-zero, post-process FastCGI responses (for example to inject additional headers) before forwarding to the client (Source: /ht_defaults.inc:503) |

**webclient (used for `-backpath` upstreams)**

| Knob | Default | Relevance to rwasa |
|---|---|---|
| `webclient_maxconns` | `4` (standard) / `6` (tlsmin) | Maximum simultaneous outbound webclient connections per hostname; raised in the minimalist build because cipher negotiation is cheaper (Source: /ht_defaults.inc:509, /rwasa/tlsmin_defaults.inc:509) |

### The `tlsmin_defaults.inc` two-line delta

`/rwasa/tlsmin_defaults.inc` is an otherwise byte-identical copy of `../ht_defaults.inc` with exactly two assignments changed:

```diff
319c319
< 	tls_minimalist = 0
---
> 	tls_minimalist = 1
509c509
< 	webclient_maxconns = 4
---
> 	webclient_maxconns = 6
```

Both lines are material to runtime behaviour: the first reshapes the advertised TLS cipher suite, the second raises per-hostname concurrency. An operator building `rwasa_tlsmin` is opting into both changes together.

### Runtime configuration

All runtime configuration is expressed through the CLI flags documented in the [CLI Reference](#cli-reference). There is no configuration file and no dynamic reconfiguration path — a privileges-changed or cert-changed operator re-executes `rwasa` with new arguments.

## Limitations

- **HTTP/1.x only.** No HTTP/2, no HTTP/3. The request parser is single-version and lives in `../http1.inc`.
- **TLS 1.2 only.** TLS 1.3, Curve25519/Ed25519, ChaCha20-Poly1305 are not implemented. See [`../docs/security.md`](../docs/security.md) for the full cipher-suite matrix.
- **Linux x86_64 only.** Syscalls are issued directly; the binary will not run on other kernels or ISAs.
- **No dynamic reconfiguration.** CLI arguments are parsed once at startup; PEM hot-reload is performed by the library's file-stat poll (driven by `tls_server_sessioncache` and the `filestattime` cache) but the listener set, worker count, FastCGI map, virtual-host layout and sandbox roots are fixed for the life of the master process.
- **Argument parsing is intolerant by design.** Per the author's note at `/rwasa/rwasa.asm:39–42`, "garbage in or nonsensible order" produces "undefined results" — flag ordering (especially `-tls` before `-bind`, and `-new` between configurations) matters.
- **Single address-family per bind syntax.** `-bind` accepts only `port` or `ipv4:port`; IPv6 listener syntax is not exposed at the CLI (Source: /rwasa/arguments.inc:240–395).
- **OCSP broadcast is capped at 4096 bytes per message.** Larger stapled responses are silently skipped in propagation from master to workers (Source: /rwasa/master.inc:271).

## See Also

- [`./README.rwasa_tlsmin`](./README.rwasa_tlsmin) — preserved operator note on the minimalist-TLS variant's rationale
- [`../net/README.md`](../net/README.md) — the epoll / TLS / HTTP / webserver stack that rwasa sits on top of
- [`../docs/architecture.md`](../docs/architecture.md) — three-file include contract, `ht$init` lifecycle, IO chaining model
- [`../docs/security.md`](../docs/security.md) — cipher-suite matrix, OCSP stapling, HSTS, BREACH mitigation
- [`../docs/building.md`](../docs/building.md) — canonical FASM + `ld` invocation, `ht_defaults.inc` knob catalogue, adding a new tool
- [`../webslap/README.md`](../webslap/README.md) — companion load-tester that exercises `rwasa` end-to-end
- [`../README.md`](../README.md) — repository root overview

## License

rwasa and the HeavyThing library it depends on are released under the GNU General Public License version 3 (Source: /rwasa/rwasa.asm:9–19). See [`../LICENSE`](../LICENSE) for the full licence text.
