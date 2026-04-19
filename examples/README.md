# HeavyThing Examples

Runnable showcase programs demonstrating HeavyThing library capabilities.

## Overview

The `examples/` directory is a showcase, not a test suite. Each subdirectory contains a self-contained runnable program that exercises a specific slice of the HeavyThing library surface. Every example begins by including `ht_defaults.inc` and `ht.inc`, and ends by including `ht_data.inc` — the three-file include contract documented in `../docs/architecture.md`. All examples assemble with FASM (Flat Assembler) via `fasm -m 524288 ...` and link statically with GNU `ld`, producing zero-libc ELF64 binaries (Source: `../ht_defaults.inc:22-26`).

Nine of the 14 examples are pure x86_64 assembly; the remaining five demonstrate C or C++ integration through a small assembly shim. Collectively the set exercises console I/O, file-backed memory mapping, gzip compression and decompression, TCP accept/send, TLS 1.2 and SSH2 transports, SHA-256 hashing, and terminal UI animation.

## Index

| Example | Entry Point | Features Demonstrated | Notes |
|---|---|---|---|
| `echo` | `echo.asm` | `epoll.inc`, TCP accept/send, vtable composition | Minimal TCP echo server; binds `INADDR_ANY:8001` (Source: `./echo/echo.asm:21,90,117`) |
| `hello_world` | `hello_world.asm` | `ht$init`, `string$to_stdoutln`, `cleartext` macro, `syscall_exit` | **Canonical starter** — 42 lines including GPLv3 preamble, simplest possible HeavyThing program (Source: `./hello_world/hello_world.asm`) |
| `hello_world_c1` | `hello.c` + `ht.asm` + `settings.inc` | C integration via `extern` declarations; uses `include_everything = 1` | Mixed-language; full-library inclusion because `if used` cannot see C-side calls (Source: `./hello_world_c1/settings.inc:91`) |
| `hello_world_c2` | `hello.c` + `ht.asm` + `settings.inc` | C integration with explicit `_include:` anchor (manual symbol retention) | Mixed-language; smaller binary than `_c1` because only listed symbols are retained (Source: `./hello_world_c2/ht.asm:8-13`) |
| `minigzip` | `minigzip.asm` | `privmapped.inc`, `zlib_deflate.inc`, `zlib_inflate.inc`, arg parsing | CLI compressor/decompressor; output goes to stdout; compression level is a compile-time constant defaulting to 6 (Source: `./minigzip/minigzip.asm:22-32`) |
| `multicore_echo` | `multicore_echo.asm` + `custom_settings.inc` | `epoll_child.inc` fork/IPC, multi-process TCP echo | Usage: `./multicore_echo [-XX] PORT` where optional `XX` is process count, `PORT` is the TCP port (Source: `./multicore_echo/multicore_echo.asm:236`) |
| `sha256` | `sha256.asm` | `sha2.inc`, `privmapped.inc`, hex formatting | CLI SHA-256 utility; memory-maps input file, prints hex digest (Source: `./sha256/sha256.asm:34-90`) |
| `simplechat_c++` | `simplechat.cpp` + `ht.asm` | C++ integration via `extern "C"`, `epoll.inc` TCP chat room | Chat server on `INADDR_ANY:8001`; uses `std::unordered_map` for client registry (Source: `./simplechat_c++/simplechat.cpp:141,355,367`) |
| `simplechat_ssh_auth_c++` | `simplechat_ssh.cpp` + `ht.asm` | SSH2 transport plus permissive authentication callback | Chat over SSH with an `ssh$set_authcb` hook; `INADDR_ANY:8001` (Source: `./simplechat_ssh_auth_c++/simplechat_ssh.cpp:430,449`) |
| `simplechat_ssh_c++` | `simplechat_ssh.cpp` + `ht.asm` | SSH2 transport without an authentication hook | Chat over SSH; `INADDR_ANY:8001` (Source: `./simplechat_ssh_c++/simplechat_ssh.cpp:430,442`) |
| `sshecho` | `sshecho.asm` | `ssh.inc`, IO chaining (app layer, SSH2 layer, epoll layer) | SSH2 echo server; reads host keys from `/etc/ssh` by default; `INADDR_ANY:8001` (Source: `./sshecho/sshecho.asm:21,122,180`) |
| `tlsecho` | `tlsecho.asm` + `rsa_selfsigned.pem` + `dsa_selfsigned.pem` | `tls.inc`, IO chaining (app layer, TLS layer, epoll layer) | TLS 1.2 echo server; PEM files must be present in the working directory; `INADDR_ANY:8001` (Source: `./tlsecho/tlsecho.asm:21,101-107,162-164`) |
| `tuieffects` | `tuieffects.asm` | `tui_background.inc`, `tui_effect.inc`, custom vtable descendant | 10-iteration terminal-animation demo with slide, sprinkle, materialize, and fountain effects (Source: `./tuieffects/tuieffects.asm:21,29,103,111`) |
| `tuimatrix` | `tuimatrix.asm` | `tui_matrix.inc` 100-percent-wide-and-tall object | Matrix-style raining half-width kana (`0xff61+`); may overwhelm some terminal emulators, use caution (Source: `./tuimatrix/tuimatrix.asm:22-36,50`) |

The `hello_world_c1` versus `hello_world_c2` pair is deliberate: `_c1` sets `include_everything = 1` in its `settings.inc` to pull the entire library into the object file, while `_c2` leaves that flag commented out and instead provides a `_include:` label whose explicit `call` sequence steers FASM's `if used` elimination to retain only the five functions the C side actually references (`ht$init_args`, `string$from_cstr`, `string$to_stdoutln`, `heap$free`, `ht$syscall`). The two variants teach the two supported C/C++ integration patterns.

## Build

Every example follows the same two-step flow: assemble the `.asm` entry point with FASM, then link the resulting object with GNU `ld`. The canonical `hello_world` build illustrates the pattern:

```bash
cd examples/hello_world
fasm -m 524288 hello_world.asm      # produces hello_world.o
ld -o hello_world hello_world.o     # produces the static ELF64 binary
./hello_world                       # prints: Hello World
```

For any other pure-assembly example, substitute the filename: `fasm -m 524288 <example>.asm && ld -o <binary> <example>.o`. Readers should consult `../docs/building.md` for the authoritative reference on FASM prerequisites, conditional compilation, the `include_everything` flag, troubleshooting, and exit codes 96 through 99.

The `-m 524288` argument raises FASM's internal symbol pool to accommodate HeavyThing's transitive includes, which together define many thousands of symbols (Source: `../docs/building.md`).

## Mixed-Language Builds (C/C++ Integration)

The five mixed-language examples (`hello_world_c1`, `hello_world_c2`, `simplechat_c++`, `simplechat_ssh_c++`, `simplechat_ssh_auth_c++`) each compile a small assembly shim (`ht.asm`) independently from the C or C++ source, then link both object files together using `gcc -nostdlib` or `g++ -nostdlib`. The shim is responsible for making every HeavyThing symbol the C-side or C++-side calls visible to the linker — FASM's default `if used` elimination cannot see cross-language references and would otherwise strip needed functions.

Two patterns are available and are illustrated by the `hello_world_c1` and `hello_world_c2` pair. In the `_c1` pattern, `settings.inc` sets `include_everything = 1` and FASM assembles every library function; this is the simpler approach but produces a larger binary. In the `_c2` pattern, `include_everything` stays commented out and the shim declares a `_include:` label containing explicit `call` instructions for each required function; FASM sees those calls and retains the corresponding symbols while still eliding the rest. The second pattern yields a smaller binary at the cost of maintaining the `_include:` list as the C or C++ surface evolves.

Authoritative build commands — including the exact `gcc`/`g++` invocations and linker flags — live in the Conditional Compilation section of `../docs/building.md`. This README does not duplicate them.

## Limitations

- No automated test harness exists; every example is a manual build-and-run demonstration. Readers verify behavior by inspection and by running each binary.
- Linux x86_64 only. The library uses raw Linux `syscall` directly and has no cross-platform support.
- Network examples (`echo`, `tlsecho`, `sshecho`, `multicore_echo`, `simplechat_c++`, `simplechat_ssh_c++`, `simplechat_ssh_auth_c++`) assume port `8001` is free (or that the user supplies a free port, in the case of `multicore_echo`). Binding below port 1024 requires elevated privileges; binding port 8001 normally does not.
- `sshecho` expects SSH host keys under `/etc/ssh/` by default and reports `'/etc/ssh host keys and/or contents error.'` if they are missing (Source: `./sshecho/sshecho.asm:122,180`). `tlsecho` expects `rsa_selfsigned.pem` and `dsa_selfsigned.pem` in the current working directory (Source: `./tlsecho/tlsecho.asm:163-164`); both PEM files ship alongside the example. Both requirements must be satisfied before launch.
- No Makefile ties the examples together. Each example is built individually from its own subdirectory.
- `tuimatrix` uses half-width kana (`0xff61+`) and can overwhelm or corrupt the display on some terminal emulators (Source: `./tuimatrix/tuimatrix.asm:22-36`). It is safe to kill the process from another terminal if the host terminal becomes unresponsive.

## See Also

- `../README.md` — HeavyThing project overview and the three-file include contract
- `../docs/building.md` — Full build guide, FASM prerequisites, `include_everything` semantics, exit codes 96 through 99
- `../docs/architecture.md` — Include-dependency graph, `ht$init` and event-loop lifecycle, IO chaining model
- `../docs/calling-convention.md` — `subsystem$function` label naming convention and register contract used throughout every example
- `../tui/README.md` — TUI subsystem overview for readers interested in the widget framework demonstrated by `tuimatrix` and `tuieffects`
- `../rwasa/README.md` — Web server built on the same library primitives
- `../webslap/README.md` — HTTP load tester built on the same library primitives
- `../sshtalk/README.md` — SSH-enabled terminal chat server
- `../toplip/README.md` — Encrypted-file utility
- `../dhtool/README.md` — Diffie-Hellman parameter generation utility

Licensed under GPLv3. See ../LICENSE.
