# HeavyThing Calling Convention Reference

## Overview

HeavyThing uses a lightly customised variant of the Linux System V AMD64
calling convention. Integer-register argument passing, integer return values,
and caller-saved register identity all follow the System V contract. The
library additionally specifies a `subsystem$function` label-naming pattern, a
mandatory `prolog`/`epilog` macro pair on every public label, and hooks that
accommodate the profiler and calltrace instrumentation. The convention is
FASM-native: every entry point is called from what the master include file
describes as "a pure fasm enviro" (Source: /ht.inc:613), and the library does
not participate in libc startup.

## Register Model

HeavyThing is assembled and linked exclusively for Linux x86_64. Integer
register usage matches System V AMD64:

- Integer argument registers, in order: `rdi`, `rsi`, `rdx`, `rcx`, `r8`,
  `r9`.
- Integer return value: `rax`. For 128-bit results (for example the output
  of the `mul` and `div` instructions), `rdx` holds the high half.
- Floating-point arguments and returns use `xmm0` through `xmm7` when they
  appear, which is rare; HeavyThing hot paths deal in integers and SIMD
  block ciphers rather than scalar floats.
- The profiler, when enabled, additionally preserves a fixed set of
  caller-saved registers across its own instrumentation code (see the
  following section).

## Preserved vs. Clobbered Registers

The table below lists every general-purpose 64-bit integer register and its
role from the caller perspective. Preservation responsibilities match System
V AMD64 unmodified.

| Register | Role | Notes |
|---|---|---|
| `rax` | Caller-saved | Return value; also scratch |
| `rbx` | Callee-saved | Must be restored if modified |
| `rcx` | Caller-saved | 4th argument in userland; replaced by `r10` for syscalls |
| `rdx` | Caller-saved | 3rd argument; upper half of 128-bit return |
| `rsi` | Caller-saved | 2nd argument |
| `rdi` | Caller-saved | 1st argument |
| `rbp` | Callee-saved | Frame pointer when `framepointers = 1` |
| `rsp` | Callee-saved | Stack pointer |
| `r8` | Caller-saved | 5th argument |
| `r9` | Caller-saved | 6th argument |
| `r10` | Caller-saved | Replaces `rcx` as syscall 4th argument |
| `r11` | Caller-saved | Clobbered by the `syscall` instruction itself |
| `r12` | Callee-saved | |
| `r13` | Callee-saved | |
| `r14` | Callee-saved | |
| `r15` | Callee-saved | |

When `profiling = 1` in `ht_defaults.inc` (Source: /ht_defaults.inc:62), the
`prolog` and `epilog` macros preserve exactly `rax`, `rcx`, `rdx`, `rdi`,
`rsi`, `r8`, `r9`, `r10`, and `r11` across their internal
`call profiler$enter` and `call profiler$leave` sequences (Source:
/profiler.inc:70, /profiler.inc:73, /profiler.inc:133, /profiler.inc:135).
This means that even though the profiler is itself a function call embedded
into every prolog and epilog, callers never need to save the caller-saved
integer registers around that instrumentation. The same preservation set
applies when `calltracing = 1` (Source: /profiler.inc:84,
/profiler.inc:90).

## Stack Alignment

The System V AMD64 ABI requires that at the moment control reaches a
callee first instruction, `rsp` is 16-byte aligned minus 8: once the
`call` instruction has pushed the return address onto the stack, the
callee sees `rsp mod 16 == 8`; after the callee has optionally pushed a
saved frame pointer via `push rbp`, `rsp mod 16 == 0` and the stack is
16-byte aligned. HeavyThing honours this convention and relies on it for
SSE and SIMD code that uses `movapd`, `movdqa`, and similar
alignment-sensitive instructions.

Three alignment helpers sit behind the scenes to pad code and data with
multi-byte NOP sequences until the following byte reaches the required
boundary:

- `falign` pads the code stream to `function_alignment` before a public
  function label (Source: /align_macros.inc:25-70).
- `calign` pads the code stream to `inner_alignment` before an inner jump
  target such as a loop head (Source: /align_macros.inc:71-116).
- `dalign` pads the data stream to `data_alignment` before a data
  declaration (Source: /align_macros.inc:117-162).

The table below lists the knobs in `ht_defaults.inc` that control
alignment. All defaults reflect the repository as shipped.

| Knob | Default | Effect |
|---|---|---|
| `function_alignment` | `16` | Target boundary for every public function entry (Source: /ht_defaults.inc:51) |
| `inner_alignment` | `16` | Target boundary for inner jump targets (Source: /ht_defaults.inc:52) |
| `data_alignment` | `16` | Target boundary for entries in the data segment (Source: /ht_defaults.inc:53) |
| `align_functions` | `1` | When `1`, `falign` emits padding before public functions (Source: /ht_defaults.inc:36) |
| `align_inner` | `1` | When `1`, `calign` emits padding before inner labels (Source: /ht_defaults.inc:45) |
| `align_data` | `1` | When `1`, `dalign` emits padding before data entries (Source: /ht_defaults.inc:48) |
| `align_returns` | `0` | When `1`, rewrites `call target` as `push label; jmp target; calign; label:`, causing the return label to land on `inner_alignment` (Source: /ht_defaults.inc:39, /call.inc:73-78) |
| `align_callreturns` | `0` | When `1`, pads multi-byte NOPs before `call target` so the byte immediately following the call opcode lands on a 16-byte boundary (Source: /ht_defaults.inc:42, /call.inc:25-72) |

Only one of `align_returns` and `align_callreturns` is intended to be
active at a time. Both are off in the default configuration; enabling
either biases instruction-fetch behaviour on certain microarchitectures.

## Label Naming Convention

Every public label in HeavyThing uses the form `subsystem$function`. The
dollar sign is a legal identifier character in FASM and serves as the
namespace separator. This is one of the reasons the library is authored
in FASM rather than NASM: NASM treats `$` as the current-address
expression operator and would not accept it as part of an identifier.

Representative examples taken directly from the library:

- `ht$init` (Source: /ht.inc:609) is the master initialiser.
- `ht$init_args` (Source: /ht.inc:316) is the argument-aware variant that
  `ht$init` tail-calls.
- `ht$syscall` (Source: /ht.inc:640) is the HLL-to-syscall shuffle
  wrapper.
- `_start` calls into `ht$init` as its very first instruction (Source:
  /examples/hello_world/hello_world.asm:30).

The table below catalogues representative public labels by subsystem. The
list is not exhaustive but illustrates the pattern.

| Subsystem | Representative Labels |
|---|---|
| `ht` | `ht$init`, `ht$init_args`, `ht$syscall`, `ht$codeseg`, `ht$dataseg` |
| `heap` | `heap$init`, `heap$alloc`, `heap$free`, `heap$realloc` |
| `string` | `string$to_stdoutln`, `string$from_utf8`, `string$indexof_charcode`, `string$substr` |
| `list` | `list$new`, `list$push_back`, `list$foreach` |
| `stringmap` | `stringmap$new`, `stringmap$insert`, `stringmap$find`, `stringmap$findvalue` |
| `unsignedmap` | `unsignedmap$new`, `unsignedmap$insert` |
| `buffer` | `buffer$new`, `buffer$append`, `buffer$destroy` |
| `json` | `json$parse`, `json$stringify` |
| `epoll` | `epoll$init`, `epoll$iteration`, `epoll$run`, `epoll$send`, `epoll$outbound`, `epoll$established` |
| `rng` | `rng$init`, `rng$int`, `rng$block`, `rng$block_nzb` |
| `aes` | `aes$init_encrypt`, `aes$encrypt`, `aes$init_decrypt`, `aes$decrypt` |
| `sha160` | `sha160$new`, `sha160$init`, `sha160$write`, `sha160$read` |
| `sha224` / `sha256` / `sha384` / `sha512` | `sha224$new`, `sha256$new`, `sha384$new`, `sha512$new` |
| `hmac` | `hmac$new_md5`, `hmac$new_sha256`, `hmac$key` |
| `pbkdf2` | `pbkdf2$new_md5`, `pbkdf2$init_md5`, `pbkdf2$new_sha256` |
| `tls` | `tls$peminit`, `tls$pemlookup`, `tls$sessioncacheinit`, `tls$new_server`, `tls$new_client` |
| `ssh` | `ssh$new_server`, `ssh$blacklist` |
| `X509` | `X509$new`, `X509$new_pem`, `X509$new_ssh`, `X509$destroy` |
| `blacklist` | `blacklist$new` |
| `url` | `url$init`, `url$new` |
| `webserver` | `webserver$init`, `webservercfg$init`, `webservercfg$function_map`, `webservercfg$hotlist`, `webservercfg$direxists`, `webservercfg$fastcgi_map` |
| `fcgiclient` | `fcgiclient$init` |
| `wcdns` | `wcdns$init` |
| `tui_*` | `tui_splash$initlogo`, `tui_statusbar$globalinit`, `tui_button$new`, `tui_form$new` |
| `profiler` | `profiler$init`, `profiler$leave`, `profiler$enter`, `profiler$reset` |
| `vdso` | `vdso$init` |
| `syslog` | `syslog$init` |

Local (function-scoped) labels use a leading dot. FASM scopes such
labels to the enclosing non-dotted label, so the same local name can
appear in many different public functions without collision.
Representative local labels inside `ht$init_args` (Source:
/ht.inc:316-604) include `.preloadloop`, `.cachesize`,
`.cachesize_intel`, `.cachesize_done`, `.argloop`, and `.envloop`.

## Prolog / Epilog Macro Contract

Every public label in the library is wrapped in a matching
`prolog`/`epilog` pair. The canonical template:

```nasm
falign
mymod$myfunc:
        prolog  mymod$myfunc
        ; ... body ...
        epilog
```

The macros sit in `profiler.inc` and expand differently depending on
which configuration knobs are set in `ht_defaults.inc`. The master
include file states the mandate plainly: "all of our functions still
use the prolog/epilog macros, so whether profiling is actually turned
ON or not, the macros still need to be here" (Source: /ht.inc:85-86).

Four variants of the pair are defined. The table below enumerates them.

| Macro Pair | Behaviour | When to Use |
|---|---|---|
| `prolog` / `epilog` | Emits `public name` when `public_funcs = 1`; sets up a frame pointer when `framepointers = 1`; emits profiler entry and exit calls when `profiling = 1`; emits a calltrace `write(1, "calltrace: name\n", ...)` when `calltracing = 1` (Source: /profiler.inc:55-92, /profiler.inc:130-141) | Default for every public library label |
| `prolog_noprofile` / `epilog_noprofile` | Emits `public name` and the frame pointer, but skips all profiler and calltrace instrumentation (Source: /profiler.inc:94-102, /profiler.inc:171-176) | Labels called from inside the profiler itself, to avoid infinite instrumentation recursion |
| `prolog_silent` / `epilog_silent` | Skips the `public name` declaration; otherwise behaves like the default pair (Source: /profiler.inc:111-128) | File-private helper labels that should not appear in the symbol table |
| `prolog_inner` / `epilog_inner` | Profiler instrumentation only; no frame-pointer setup, no public declaration (Source: /profiler.inc:147-160, /profiler.inc:162-169) | Instrumented sub-scopes inside a larger function; each `prolog_inner` must be paired 1:1 with an `epilog_inner` |

When any of the `prolog` variants that includes profiler instrumentation
is active, the register set `rax`, `rcx`, `rdx`, `rdi`, `rsi`, `r8`,
`r9`, `r10`, `r11` is pushed before `call profiler$enter` and popped
afterwards (Source: /profiler.inc:70, /profiler.inc:73). The matching
`epilog` performs the same save/restore around `call profiler$leave`
(Source: /profiler.inc:133, /profiler.inc:135). Callers therefore do not
need to save any additional registers around the prolog entry beyond
what the target function documented contract requires.

Omitting `prolog`/`epilog` from a public label assembles cleanly, but
the resulting function will not be emitted into the symbol table
(because no `public name` is issued), will not participate in the
profiler or calltrace, and will not establish a frame pointer for
`gdb`. New modules are expected to use the macros uniformly.

## The `call` Macro

The library overrides the FASM built-in `call` directive with a macro
that operates in one of three modes depending on the `align_returns`
and `align_callreturns` knobs. The macro lives in `call.inc` (Source:
/call.inc:25-81).

- **Default mode** (`align_returns = 0`, `align_callreturns = 0`): emits
  a plain `call target` instruction (Source: /call.inc:79-81).
- **`align_returns = 1` mode**: expands `call target` into
  `push label; jmp target; calign; label:` (Source: /call.inc:73-78).
  This transforms the CPU-level calling convention from `call`-based to
  `jmp`-based with an explicit push of the return address, and
  guarantees that the return label (the instruction after the logical
  `call`) is `inner_alignment`-aligned.
- **`align_callreturns = 1` mode**: emits up to fifteen bytes of
  multi-byte NOP padding immediately before the `call target` so that
  the byte immediately following the `call` opcode lands on a 16-byte
  boundary (Source: /call.inc:25-72). The machine-level convention
  remains `call`-based, but the return address is now aligned, which
  helps certain instruction-fetch front ends.

Only one of the two knobs should be active; both are `0` in the default
configuration (Source: /ht_defaults.inc:39, /ht_defaults.inc:42).

## Cleartext Macro (Static Strings)

Static string literals are declared with the `cleartext` macro:

```nasm
cleartext .helloworld, 'Hello World'
```

The macro emits a HeavyThing-native string in the encoding selected by
the `string_bits` knob in `ht_defaults.inc` (Source:
/cleartext.inc:31-61).

- When `string_bits = 32` (the default, Source: /ht_defaults.inc:103),
  the macro emits a `dq CC` length header followed by a
  backward-promoted byte stream that results in a UTF-32 string
  consumable by `string32.inc` labels (Source: /cleartext.inc:33-51).
- When `string_bits = 16`, the macro emits a `dq AA` length header
  followed by a `du val` sequence that yields a UTF-16 string
  consumable by `string16.inc` labels (Source:
  /cleartext.inc:52-60).

The label produced by the macro (here `.helloworld`) points at the
length header, not at the first character; HeavyThing string routines
expect this layout and read the header before walking the character
data.

The macro is credited in its source file to `revolution` and `l_inc`
from `board.flatassembler.net` (Source: /cleartext.inc:27-28).

## Globals Macro (Data Segment)

Any module that needs a writeable global variable declares it inside a
`globals { ... }` block. Declarations emitted outside of a `globals`
block would land in `.text` (which is read-only) and fail at link time.

```nasm
if used argc | defined include_everything
globals
{
argc    dq      0
}
end if
```

(Source: /ht.inc:210-217.) The `if used argc` guard ensures that the
global appears in the binary only when some other module actually
references `argc`; otherwise FASM conditional-compilation mechanism
omits it entirely. The `| defined include_everything` clause forces the
global into the binary unconditionally when the `include_everything`
flag is set (the flag is useful for C and C++ integration, where FASM
cannot see what the externally compiled object files will reference).

The macro itself is defined in `dataseg_macros.inc` (Source:
/dataseg_macros.inc:30-36) and works by accumulating every
`globals { ... }` block into a single deferred list that is expanded en
bloc into the `.data` section opened by `ht_data.inc`. This is the
reason `ht_data.inc` must be the last include in every application
`.asm` file: by the time it runs, every `globals` declaration from
every transitive include has already been queued.

## Linux Syscall ABI

The Linux x86_64 syscall ABI differs from the userland System V calling
convention in two places: the 4th argument is passed in `r10` instead
of `rcx`, and the `syscall` instruction itself clobbers `rcx` and `r11`
at the architectural level. The library source states this verbatim:
"syscall # into rax, args: rdi, rsi, rdx, r10, r8, r9" and "return
always in rax" (Source: /syscall.inc:26-27).

| Item | Register |
|---|---|
| Syscall number | `rax` |
| 1st argument | `rdi` |
| 2nd argument | `rsi` |
| 3rd argument | `rdx` |
| 4th argument | `r10` (not `rcx`) |
| 5th argument | `r8` |
| 6th argument | `r9` |
| Return value | `rax` |

`rcx` and `r11` are always clobbered by the `syscall` instruction at
the architectural level: the CPU stashes `rip` into `rcx` and `rflags`
into `r11`.

The file `syscall.inc` provides a symbolic name for every Linux x86_64
syscall. A representative sample of the most frequently used constants
in HeavyThing code:

| Constant | Value | Purpose |
|---|---|---|
| `syscall_read` | `0` | `read(fd, buf, count)` |
| `syscall_write` | `1` | `write(fd, buf, count)` |
| `syscall_open` | `2` | `open(path, flags, mode)` |
| `syscall_close` | `3` | `close(fd)` |
| `syscall_mmap` | `9` | `mmap(addr, len, prot, flags, fd, off)` |
| `syscall_munmap` | `11` | `munmap(addr, len)` |
| `syscall_exit` | `60` | `exit(status)` (Source: /syscall.inc:89) |
| `syscall_epoll_create` | `213` | `epoll_create(size)` (Source: /syscall.inc:242) |
| `syscall_epoll_wait` | `232` | `epoll_wait(epfd, events, maxevents, timeout)` (Source: /syscall.inc:261) |
| `syscall_epoll_ctl` | `233` | `epoll_ctl(epfd, op, fd, event)` (Source: /syscall.inc:262) |
| `syscall_accept4` | `288` | `accept4(sockfd, addr, addrlen, flags)` (Source: /syscall.inc:317) |

The exit sequence at the tail of every minimal HeavyThing program
follows the ABI directly (Source:
/examples/hello_world/hello_world.asm:34-36):

```nasm
mov     eax, syscall_exit
xor     edi, edi
syscall
```

`eax` holds the syscall number, `edi` holds the first (and only)
argument (the exit status), and the `syscall` instruction transfers
control to the kernel.

A higher-level convenience wrapper, `ht$syscall` (Source:
/ht.inc:640-651), accepts the syscall number in `edi` with arguments in
`rsi`, `rdx`, `rcx`, `r8`, `r9`, `r10` and shuffles them into the
kernel ABI before issuing `syscall`. The wrapper is included only when
`ht$syscall` is actually referenced (Source: /ht.inc:632) and is
intended for mixed-language builds that need syscall access from C or
C++ without linking libc.

## Exit Codes

The library reserves four process exit codes for internal failure
signals. User code should therefore avoid returning these from
`_start`. The table below is reproduced here for locality; the same
table appears in `./architecture.md`, which is the authoritative
cross-reference.

| Exit Code | Meaning |
|---|---|
| `96` | `epoll_create` syscall failed during `epoll$init` (Source: /ht.inc:41) |
| `97` | Epoll minimum file-descriptor count (`epoll_minfds`) could not be met via `setrlimit` (Source: /ht.inc:40) |
| `98` | Profiler record stack overrun (`profiler_recordcount` exceeded) (Source: /ht.inc:39) |
| `99` | Heap `mmap` or `mremap` failed during `heap$init` (Source: /ht.inc:38) |

User code should return `0` for success and a distinct non-zero value
(conventionally `1` or `2`) for failure, so as not to shadow the
library-reserved signals.

## See Also

- `./architecture.md` — include chain, three-file contract, `ht$init`
  lifecycle, IO chaining, and authoritative exit-code cross-reference
- `./building.md` — FASM invocation, `fasm -m 524288` memory-pool
  rationale, linker invocation, `include_everything` for C and C++
  integration
- `./contributing.md` — how to add a new `.inc` module with proper
  `prolog`/`epilog` and `globals { ... }` discipline
- `./security.md` — cryptographic primitive scope, TLS and SSH support
  matrices
- `../ht.inc` — master include; defines `ht$init`, `ht$init_args`,
  `ht$syscall`, `ht$codeseg`, `ht$dataseg`
- `../ht_defaults.inc` — compile-time knobs referenced throughout this
  document
- `../profiler.inc` — `prolog`, `epilog`, `prolog_noprofile`,
  `prolog_silent`, `prolog_inner`, and matching `epilog_*` variants
- `../call.inc` — the three-mode `call` macro
- `../align_macros.inc` — `falign`, `calign`, `dalign`
- `../dataseg_macros.inc` — `globals { ... }` macro
- `../cleartext.inc` — `cleartext` static-string macro
- `../syscall.inc` — symbolic Linux x86_64 syscall constants
- `../LICENSE` — GPLv3 license text
