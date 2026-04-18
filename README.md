# HeavyThing

x86_64 Linux assembly language library and showcase programs.

## Overview

HeavyThing is a self-contained x86_64 assembly language library for Linux
that depends on nothing beyond the kernel system-call ABI. The repository
ships the library as a collection of `.inc` include files, a handful of
showcase applications (`rwasa`, `webslap`, `toplip`, `sshtalk`, `dhtool`),
and fourteen worked example programs under `examples/`. Every binary is
produced as a statically linked ELF64 executable with no libc, no glibc,
and no dynamic linker. The project is distributed under the GNU General
Public License, version 3 (Source: `/ht.inc:1-20`, `/LICENSE:1-2`). The
original upstream project page, preserved here only as a historical
pointer, is `https://2ton.com.au/HeavyThing/` (Source: `/README:1-3`).

## Prerequisites

| Requirement | Notes |
|---|---|
| FASM (Flat Assembler) by Tomasz Grysztar | The actual assembler used to build HeavyThing. Evidence: `ht_defaults.inc:24` ("we are the first include, set our fasm format") and `ht_defaults.inc:26` (`format ELF64`, which is FASM syntax). See `http://flatassembler.net` for the assembler itself. |
| Linux x86_64 | The library calls the Linux kernel directly via the `syscall` instruction; see `/syscall.inc` for the wrapper surface and `/vdso.inc` for the vDSO-based fast paths. |
| GNU `ld` (binutils) | Used to link the FASM-produced ELF64 object into the final static binary. |
| GCC / G++ (optional) | Required only for the mixed-language examples such as `examples/hello_world_c1/`, `examples/hello_world_c2/`, and `examples/simplechat_c++/`. |
| No libc, no glibc | HeavyThing does not link against the C library. Static ELF64 binaries invoke Linux system calls directly. |

Note on the code-fence tag used throughout this documentation: GitHub has
no `fasm` syntax highlighter, so assembly blocks are fenced with ```nasm```
purely for Intel-syntax rendering. The underlying assembler for every
snippet is FASM.

## Architecture Fit

HeavyThing sits directly on top of the Linux system-call ABI. `syscall.inc`
and `vdso.inc` provide the only interface between the library and the
kernel; no user-space runtime is interposed. Every tool and example in
this repository is built on top of the library through the same three-file
include contract: `ht_defaults.inc` establishes compile-time configuration
and the `format ELF64` directive, `ht.inc` pulls in the roughly 100
subsystem `.inc` files transitively, and `ht_data.inc` terminates the
code segment and opens the writable data segment. The include fan-out is
controlled by FASM's `if used` conditional-assembly pattern so that only
the library pieces actually referenced by the entry point end up in the
final binary (Source: `/ht.inc:22-36`).

For the full transitive include graph as a Mermaid diagram, see
[`docs/architecture.md`](docs/architecture.md).

## Three-File Include Contract

Every `.asm` entry point in HeavyThing must include exactly three files
in exactly this order:

1. `ht_defaults.inc` first — it declares `format ELF64` and every compile-time
   constant that the rest of the library reads during assembly.
2. `ht.inc` second — it opens `section '.text'` (Source: `/ht.inc:57`),
   defines `ht$init`, and transitively includes every subsystem `.inc` file.
3. `ht_data.inc` last — it closes the code section and opens
   `section '.data'` for globals declared anywhere in the program via the
   `globals { }` macro (Source: `/ht_data.inc:29-34`).

The order is enforced by FASM's single-pass section model: reversing it
produces unresolved symbols at link time or an invalid ELF64 layout.

```nasm
; hello_world.asm - canonical three-file include contract
include '../../ht_defaults.inc'   ; FIRST: configuration constants + format ELF64
include '../../ht.inc'            ; SECOND: library + fans out to 100+ submodules

public _start
_start:
    call    ht$init               ; initialise the library
    mov     rdi, .helloworld
    call    string$to_stdoutln    ; print "Hello World\n"
    mov     eax, syscall_exit
    xor     edi, edi
    syscall

cleartext .helloworld, 'Hello World'

include '../../ht_data.inc'       ; LAST: seals the .data section
```

(Source: `/examples/hello_world/hello_world.asm:24-41`; mandatory ordering
explained in `/ht.inc:22-36` and `/ht_data.inc:22-30`.)

Cross-ref: see [`docs/calling-convention.md`](docs/calling-convention.md)
for the library-wide register contract, the `subsystem$function` label
naming convention, and the `prolog` / `epilog` macro details. See
[`docs/architecture.md`](docs/architecture.md) for the full include graph.

## Build a Minimal Example

The `examples/hello_world` program is the shortest end-to-end demonstration
of the three-file contract. Build and run it as follows:

```bash
cd examples/hello_world
fasm -m 524288 hello_world.asm    # produces hello_world.o
ld -o hello_world hello_world.o   # produces the static ELF64 binary
./hello_world                     # prints: Hello World
```

The `-m 524288` flag raises FASM's internal symbol memory pool, which is
required because HeavyThing's transitive include chain defines many more
symbols than FASM allocates by default. For the full build reference,
including the `include_everything` flag used when mixing assembly with
C or C++, see [`docs/building.md`](docs/building.md).

## Subsystem Map

The four logical subsystems below each have their own README that covers
the nine-section module template (overview, architecture fit, key
components, calling convention, usage, configuration, limitations, and
cross-references). The `.inc` files themselves remain at the repository
root; each subsystem README refers to them via `../<filename>.inc` paths.

| Subsystem | README | Scope |
|---|---|---|
| Cryptography | [`crypto/README.md`](crypto/README.md) | AES, SHA-1, SHA-2, MD5, HMAC, PBKDF2, scrypt, RNG, X.509 |
| Networking | [`net/README.md`](net/README.md) | epoll, HTTP/1.x, TLS 1.2, SSH2, `webclient`, `webserver` |
| Terminal UI | [`tui/README.md`](tui/README.md) | 32 `tui_*.inc` widgets (alert, button, datagrid, form, matrix, etc.) |
| Data Structures | [`ds/README.md`](ds/README.md) | `list`, `maps`, `heap`, `buffer`, `json` |

The following core and infrastructure `.inc` files are not grouped into
any of the four subsystems above; they are referenced directly from
[`docs/architecture.md`](docs/architecture.md) and
[`docs/calling-convention.md`](docs/calling-convention.md), and each file
opens with a purpose comment in its header block that a reader can inspect
directly: `ht.inc`, `ht_defaults.inc`, `ht_data.inc`, `syscall.inc`,
`call.inc`, `cleartext.inc`, `profiler.inc`, `math.inc`, `memfuncs.inc`,
`date.inc`, `formatter.inc`, `file.inc`, `dir.inc`, `io.inc`, `mapped.inc`,
`privmapped.inc`, `mappedheap.inc`, `sleeps.inc`, `syslog.inc`,
`sysinfo.inc`, `unicodecase.inc`, `string16.inc`, `string32.inc`,
`string_math.inc`, `base64_latin1.inc`, `mimelike.inc`, `png.inc`,
`zlib_inflate.inc`, `zlib_deflate.inc`, `bigint.inc`, the `dh_pool*.inc`
family, `breakpoint.inc`, `crc.inc`, `rdtsc.inc`, `vdso.inc`,
`align_macros.inc`, and `dataseg_macros.inc`.

## Tools

Each showcase application lives in its own top-level directory with its
own README. Build invocations, command-line flags, deployment notes, and
the library features each tool exercises are documented per-tool.

| Tool | README | Purpose |
|---|---|---|
| `rwasa` | [`rwasa/README.md`](rwasa/README.md) | Rapid Web Application Server in Assembler (HTTP, HTTPS, FastCGI) |
| `webslap` | [`webslap/README.md`](webslap/README.md) | HTTP and HTTPS load-testing utility with TLS-minimalist variant |
| `toplip` | [`toplip/README.md`](toplip/README.md) | Encrypted-file utility with optional PNG media-carrier output |
| `sshtalk` | [`sshtalk/README.md`](sshtalk/README.md) | SSH-enabled terminal chat server |
| `dhtool` | [`dhtool/README.md`](dhtool/README.md) | Diffie-Hellman parameter generation, verification, and PEM conversion |

## Examples

The `examples/` directory contains fourteen worked programs that
demonstrate individual subsystems in isolation:
`echo`, `hello_world`, `hello_world_c1`, `hello_world_c2`, `minigzip`,
`multicore_echo`, `sha256`, `simplechat_c++`, `simplechat_ssh_auth_c++`,
`simplechat_ssh_c++`, `sshecho`, `tlsecho`, `tuieffects`, and `tuimatrix`.
The consolidated index, per-example build invocation, and the library
features each example exercises are documented in
[`examples/README.md`](examples/README.md).

## Configuration

All compile-time configuration lives in a single file, `ht_defaults.inc`.
A project that customises the library should copy `ht_defaults.inc` into
its own source tree and adjust the constants before the first include.
The table below groups the knobs by functional area and points to the
document where each group is described in detail.

| Category | Example knobs | Documented in |
|---|---|---|
| Alignment | `function_alignment`, `align_functions`, `align_returns`, `align_callreturns` | [`docs/building.md`](docs/building.md), [`docs/calling-convention.md`](docs/calling-convention.md) |
| Debug / Profile | `framepointers`, `profiling`, `calltracing` | [`docs/building.md`](docs/building.md) |
| Strings | `string_bits` (16 or 32) | [`ds/README.md`](ds/README.md) |
| Heap | `heap_bincheck`, `heap_barriers` | [`ds/README.md`](ds/README.md) |
| Epoll | `epoll_minfds`, `epoll_readsize`, `epoll_stacksize` | [`net/README.md`](net/README.md) |
| TLS | `tls_server_sessioncache`, `tls_minimalist`, `tls_blacklist` | [`net/README.md`](net/README.md), [`docs/security.md`](docs/security.md) |
| SSH | `ssh_do_compression`, `ssh_blacklist` | [`net/README.md`](net/README.md), [`docs/security.md`](docs/security.md) |
| Web | `webserver_maxheader`, `webserver_hsts`, `webserver_breach_mitigation` | [`net/README.md`](net/README.md), [`rwasa/README.md`](rwasa/README.md) |
| Crypto | `dh_bits`, `scrypt_N`, `rng_heavy_init` | [`crypto/README.md`](crypto/README.md), [`docs/security.md`](docs/security.md) |
| Code-gen | `code_preload`, `use_movbe`, `include_everything` | [`docs/building.md`](docs/building.md), [`docs/contributing.md`](docs/contributing.md) |
| Page / Platform | `page_size` | [`docs/building.md`](docs/building.md) |

## Limitations

- Linux x86_64 only. The library does not target Windows, macOS, BSD, or
  any non-x86_64 architecture.
- No TLS 1.3. No Ed25519 or Curve25519. No ChaCha20-Poly1305. No Argon2.
  The supported TLS and cryptographic-primitive matrix is enumerated in
  [`docs/security.md`](docs/security.md).
- SSH protocol version 2 only. SSH-1 is not implemented.
- HTTP/1.x only. Neither HTTP/2 nor HTTP/3 is implemented.
- The runtime signals four distinct premature-exit conditions through
  process exit codes 96, 97, 98, and 99 (Source: `/ht.inc:38-42`). The
  authoritative table mapping each code to its trigger is in
  [`docs/architecture.md`](docs/architecture.md).
- No automated test suite. Validation of the library is performed by
  manually building and running the programs under `examples/` and the
  showcase tools.
- Single-process by default. Multi-process behaviour (fork plus parent
  / worker IPC) is opt-in through `epoll_child.inc` and is exercised by
  `rwasa`, `webslap`, and `dhtool`.
- The `ChangeLog` in this repository snapshot terminates at v1.13
  (released 2015-07-16) (Source: `/ChangeLog:1-3`).

## Further Reading

| Document | Topic |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Include-dependency graph, subsystem boundary map, `ht$init` and event-loop lifecycle, IO chaining model, the exit-code table |
| [`docs/building.md`](docs/building.md) | FASM invocation, `ld` link flow, build-flow diagram, the `include_everything` flag, troubleshooting the exit codes |
| [`docs/calling-convention.md`](docs/calling-convention.md) | Register contract, stack alignment, `subsystem$function` label naming, the `prolog` / `epilog` macros, data-segment macros |
| [`docs/security.md`](docs/security.md) | Cryptographic primitive scope, TLS and SSH support matrix, operational guidance |
| [`docs/contributing.md`](docs/contributing.md) | How to add a new `.inc` module and wire it into `ht.inc` |

## See Also

- [`README`](README) — the three-line legacy plain-text file, preserved
  byte-for-byte, pointing at the original upstream project home.
- [`ChangeLog`](ChangeLog) — version-by-version history of the library;
  the newest entry in this repository snapshot is v1.13 dated 2015-07-16
  (Source: `/ChangeLog:1-3`).
- [`LICENSE`](LICENSE) — the full text of the GNU General Public License,
  version 3.

## License

HeavyThing is distributed under the GNU General Public License, version 3.
See [`LICENSE`](LICENSE) for the full text. Every source file in the
repository begins with a standard GPLv3 preamble in its header comment
block; `/ht.inc:1-20` is a representative example.

