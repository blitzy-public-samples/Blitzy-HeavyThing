# Contributing to HeavyThing

## Overview

HeavyThing is an x86_64 FASM assembly library whose contributions take one
of two forms: a new `.inc` module that extends a library subsystem, or a
new `.asm` entry point that provides a tool or example program. Every
library `.inc` file lives at the repository root and is reached from
application sources through the mandatory three-file include contract
documented in `./architecture.md` (Source: /ht.inc:22-42).

The repository ships no automated test harness. Historically each release
recorded in `/ChangeLog` was validated by running hand-crafted binary
demos under `/examples/` and the showcase tools (`rwasa`, `webslap`,
`sshtalk`, `toplip`, `dhtool`), and new contributions are expected to
follow the same pattern. Conventions in this document describe patterns
already present in the codebase; contributors should document existing
code as-is and must not refactor, optimise, or change existing interfaces
as part of a documentation or module-addition pass.

## Module File Layout

Every `.inc` and `.asm` file in the repository follows a consistent
layout. New modules must preserve this layout so that the transitive
`include 'ht.inc'` mechanism and the `if used` elision model continue to
behave correctly.

1. **GPLv3 preamble (lines 1 through 20)** — a 20-line banner comment
   beginning with `; HeavyThing x86_64 assembly language library and
   showcase programs` and terminated by a line of dashes. The preamble
   carries the copyright notice and the GPLv3 disclaimer (Source:
   /ht.inc:1-20). The preamble is byte-for-byte identical across every
   existing `.inc` and `.asm` file.

2. **Purpose comment (line 22)** — a single-line description in the
   form `; <filename>: <one-line summary>`. Representative lines:
   `; ht.inc: main include file that includes everything else` (Source:
   /ht.inc:22), `; epoll.inc: epoll/socket/fd layer` (Source:
   /epoll.inc:22), `; heap.inc: memory management goodies` (Source:
   /heap.inc:22), `; aes.inc: aes128/aes192/aes256 goodies...` (Source:
   /aes.inc:22), and `; tls.inc: TLS 1.2 minimalist implementation`
   (Source: /tls.inc:22).

3. **Extended design notes (optional)** — larger modules carry a block
   of author commentary immediately below the purpose line. The pattern
   is exemplified by `/epoll.inc:22-80` (the IO chaining model),
   `/tls.inc:24-105` (certificate policy, blinding countermeasures,
   cipher-suite rationale, and PEM pathname handling), `/aes.inc:24-34`
   (AESNI versus software choice), and `/heap.inc:25-67` (bin-allocator
   philosophy). Contributors are encouraged to document non-obvious
   invariants inline with the subsystem they govern.

4. **Struct offset and constant block (object-like modules)** — a run
   of `<subsystem>_<field>_ofs = <offset>` lines terminated by a
   `<subsystem>_size = <total>` line. For example, `aes_rounds_ofs = 0`,
   `aes_loopidx_ofs = 8`, `aes_roundkeys_ofs = 16`, and `aes_size = 264`
   (Source: /aes.inc:39-42). The offsets must be consistent with any
   `globals { ... }` declaration emitted elsewhere in the module.

5. **Conditional-compilation-guarded bodies** — every public label and
   every global variable must be wrapped in an
   `if used <symbol> | defined include_everything` ... `end if` block.
   This is the mechanism by which `include 'ht.inc'` pulls in the entire
   library declaration surface without bloating the final binary. The
   pattern is detailed in the dedicated section below.

## Naming Conventions

Every identifier observed in the repository follows one of the patterns
below. New contributions are expected to match the established form.

| Element | Convention | Representative Example |
|---|---|---|
| File name | lowercase, underscores, `.inc` or `.asm` extension | `ht.inc`, `hmac_drbg.inc`, `tui_button.inc`, `hello_world.asm` |
| Public label | `subsystem$function` | `ht$init` (Source: /ht.inc:609), `ht$syscall` (Source: /ht.inc:640), `ht$init_args` (Source: /ht.inc:316) |
| Struct field offset constant | `<subsystem>_<field>_ofs` | `aes_rounds_ofs`, `aes_loopidx_ofs`, `aes_roundkeys_ofs` (Source: /aes.inc:39-41) |
| Struct total size constant | `<subsystem>_size` | `aes_size = 264` (Source: /aes.inc:42) |
| Configuration knob | lowercase snake, declared in `/ht_defaults.inc` | `page_size`, `framepointers`, `align_functions`, `heap_bincheck`, `epoll_minfds`, `tls_minimalist` |
| Local label (function-private) | leading dot, scoped to enclosing public label | `.preloadloop`, `.cachesize`, `.argloop` (Source: /ht.inc:316-604 inside `ht$init_args`) |
| Global data variable | plain identifier, declared inside `globals { ... }` | `argc`, `argv`, `env` (Source: /ht.inc:210-302) |

The dollar sign (`$`) in the `subsystem$function` pattern is a valid
FASM label character. NASM treats `$` as the current-address operator,
which is one of the reasons HeavyThing is written for FASM rather than
NASM. Full coverage of the label-naming convention and the complete
catalogue of subsystem prefixes appears in `./calling-convention.md`
under the Label Naming Convention heading.

Local labels scoped under a public label use FASM local-label semantics:
a leading dot binds the name to the nearest preceding non-dotted label.
For example, `.preloadloop` inside `ht$init_args` is distinct from
`.preloadloop` inside any other public label (Source: /ht.inc:316-604).

## Adding a New Module

The procedure below covers the addition of a new library subsystem
exposed through a new `.inc` file at the repository root. For adding a
new showcase tool (a new `.asm` entry point), see the Adding a New Tool
section of `./building.md`.

1. **Create the new `.inc` file at the repository root.** All library
   `.inc` files live at the repository root; `/ht.inc:54-208` includes
   each one by bare filename. A module placed in a subdirectory would
   not be reachable through the standard include chain without editing
   multiple files.

2. **Copy the 20-line GPLv3 preamble** verbatim from an existing module
   (Source: /ht.inc:1-20 serves as the canonical source). Adjust the
   copyright line to reflect the contributing party if the contribution
   is not being routed through the original project maintainers. The
   license itself must remain GPLv3 or a GPLv3-compatible license; the
   full license text is at `../LICENSE`.

3. **Add the line-22 purpose comment** in the form
   `; <filename>: <one-line summary>`. Keep the summary under roughly
   eighty characters so that the pattern remains greppable alongside the
   existing modules.

4. **Implement each public label behind an `if used` guard.** The
   guard uses the canonical two-clause form
   `if used <label> | defined include_everything`. A worked example of
   a single public label follows; it uses the `prolog`/`epilog` macros
   (see `./calling-convention.md`), the `cleartext` macro (Source:
   /cleartext.inc:31-61), and the `string$to_stdoutln` helper exposed
   by the string subsystem:

```nasm
if used mymod$hello | defined include_everything

falign
mymod$hello:
    prolog  mymod$hello
    mov     rdi, .greeting
    call    string$to_stdoutln
    epilog

cleartext .greeting, 'hello from mymod'

end if
```

The `prolog <name>` macro emits the public label, inserts the
framepointer prologue controlled by `framepointers` (Source:
/ht_defaults.inc, `framepointers = 1`), and chains into the profiler
instrumentation when profiling is compiled in. The matching `epilog`
macro emits the return sequence. Both macros are defined in
`/profiler.inc` and are documented exhaustively under the Prolog /
Epilog Macro Contract heading of `./calling-convention.md`.

5. **Declare persistent storage inside `globals { ... }`.** The
   `globals` macro accumulates declarations that are replayed into the
   `.data` section when `/ht_data.inc` is included at the end of the
   compilation unit (Source: /ht.inc:44-50 for the rationale; Source:
   /ht_data.inc:29-34 for the replay site). Declarations placed outside
   `globals { ... }` will break the three-file include contract.

6. **Wire the new module into `/ht.inc`** by adding an `include
   '<newmod>.inc'` line at the appropriate position in the transitive
   include chain (Source: /ht.inc:54-208). The chain is grouped by
   functional area: macros first, then core runtime, then strings and
   data structures, then cryptography (around /ht.inc:141-151), then
   file and network layers (around /ht.inc:153-167), then memory-mapped
   helpers, then the TUI widget set (around /ht.inc:173-201), and
   finally the web layer (around /ht.inc:203-208). The placement
   matters: any module the new file depends on must be included before
   it.

7. **Add any compile-time knobs to `/ht_defaults.inc`.** Knobs use the
   `identifier = value` form and are consumed through `if <knob>` or
   `if <knob> = <value>` tests inside the module body. Existing modules
   that consult knobs include `/tls.inc` (tests `tls_minimalist` and
   `tls_blacklist`) and `/heap.inc` (tests `heap_bincheck` and
   `heap_barriers`).

8. **Write a minimal demo under `/examples/<name>/`** that exercises
   the new module. Use `/examples/hello_world/hello_world.asm:24-41` as
   the template. The relative include paths below use `../../` because
   every example lives two directory levels below the repository root;
   a tool directly at `/mytool/` would use `../` instead (Source:
   /examples/hello_world/hello_world.asm:24-25).

```nasm
include '../../ht_defaults.inc'
include '../../ht.inc'

public _start
_start:
    call    ht$init
    ; ... exercise the new module here ...
    mov     eax, syscall_exit
    xor     edi, edi
    syscall

include '../../ht_data.inc'
```

Build with `fasm -m 524288 mymod_demo.asm && ld -o mymod_demo
mymod_demo.o`. The complete build flow, including the `-m 524288`
memory-pool rationale and the linker invocation, is documented in
`./building.md`.

## The `if used` / `include_everything` Pattern

Every public label and every global variable in the library is wrapped
in a two-clause guard of the form
`if used <symbol> | defined include_everything`. The canonical worked
example is the `argc` declaration inside `/ht.inc`:

```nasm
if used argc | defined include_everything

    ; this is an ordinary integer
    globals
    {
        argc    dq  0
    }

end if
```

(Source: /ht.inc:210-217.) The pattern repeats across `/ht.inc` at
lines 210, 221, 233, 248, 269, 278, 287, 296, 305, 612, and 632, among
others.

The two clauses have distinct purposes:

- **`if used <symbol>`** instructs FASM to evaluate at assembly time
  whether `<symbol>` has been referenced anywhere in the compilation
  unit. When the symbol is unreferenced, the entire block is elided and
  no bytes are emitted for it. This is the mechanism by which
  `include 'ht.inc'` drags in the full library declaration surface
  without inflating the resulting binary: pure FASM callers only pay
  for the labels they actually invoke.

- **`| defined include_everything`** is an escape hatch that forces the
  block to be emitted regardless of the `used` predicate. Setting
  `include_everything = 1` in the consuming `.asm` file before
  `include 'ht.inc'` switches the library into export-everything mode.
  This form is required for mixed-language builds, because FASM cannot
  see which library labels will be referenced by the separately
  compiled C or C++ object file. The mixed-language examples
  `/examples/hello_world_c1/`, `/examples/hello_world_c2/`, and
  `/examples/simplechat_c++/` enable this flag; pure-assembly examples
  do not.

Rule for contributors: every new public label and every new global
variable in a new module must be wrapped in this guard. Omitting the
guard causes the symbol to be emitted into every binary that includes
the library, defeating the minimalism the pattern preserves.

## Code Style

Existing code conforms to the conventions below. New contributions
should match so that alignment, profiling, and global-data semantics
remain consistent across the library.

| Guideline | Source of Truth |
|---|---|
| Wrap every public label with matching `prolog <name>` and `epilog` macros | /profiler.inc:55-141 (macro definitions); /ht.inc:85-86 ("all of our functions still use the prolog/epilog macros") |
| Emit `falign` immediately before every public label | /align_macros.inc (`falign` inserts NOPs to the next `function_alignment` boundary, default 16 bytes) |
| Emit `calign` before loop heads and branch targets inside a function | /align_macros.inc (`calign` uses `inner_alignment`, default 16 bytes, gated by `align_inner`) |
| Use the `cleartext <name>, '<literal>'` macro for static strings | /cleartext.inc:31-61 (emits length-prefixed UTF-16 or UTF-32 payload depending on the `string_bits` knob) |
| Use the `call` macro semantics supplied by `/call.inc` | /call.inc:25-81 (supports plain, `align_returns`, and `align_callreturns` modes) |
| Declare persistent state inside `globals { ... }` blocks | /dataseg_macros.inc:30-44; replay site at /ht_data.inc:34 |
| Preserve the register-clobber set documented for each subsystem | Subsystem-specific; see the Calling Convention section of each subsystem README and the full treatment in `./calling-convention.md` |
| Match the tab-indentation of surrounding code | Observable across all existing `.inc` and `.asm` files |

The register preservation contract around `prolog`/`epilog` is
summarised by the push/pop sequence at /profiler.inc:70, /profiler.inc:73,
/profiler.inc:133, and /profiler.inc:135: `rax`, `rcx`, `rdx`, `rdi`,
`rsi`, `r8`, `r9`, `r10`, and `r11` are preserved across the entry and
exit profiler hooks. Contributors should consult
`./calling-convention.md` before introducing a subsystem that deviates
from these expectations.

## Testing Approach

HeavyThing has no automated unit-test harness, no continuous-integration
pipeline, and no in-repository test runner. Validation is performed
manually, by running a binary demo that exercises the new code path and
observing its output or its externally visible behaviour (process exit
code, network traffic, rendered terminal output, produced file content).

The recommended procedure for a new module is:

1. Build and run the new module's own `/examples/<name>/` demo. Verify
   that the demo terminates with exit code 0 and produces the expected
   output.
2. Rebuild at least one of the major showcase tools that transitively
   pulls the new module in through `/ht.inc`. Appropriate choices are
   `rwasa` (for networking and TLS changes), `webslap` (for HTTP client
   and DNS changes), `sshtalk` (for SSH and TUI changes), `toplip` (for
   cryptographic changes), and `dhtool` (for bigint and DH changes).
   The rebuild confirms that the new `include` line in `/ht.inc` does
   not break the transitive include chain and that `/ht_data.inc` still
   replays every accumulated `globals { ... }` block correctly.
3. Observe the exit code. A value of 99 indicates heap mmap or mremap
   failure; 98 indicates profiler stack overrun; 97 indicates
   `epoll_minfds` was not met by `setrlimit`; 96 indicates
   `epoll_create` failure (Source: /ht.inc:38-42). The authoritative
   exit-code table is maintained in `./architecture.md`.

The historical record of what each release actually changed is preserved
in `/ChangeLog`; every entry describes observable behavioural changes
rather than test-suite metrics, which reflects the demo-driven
validation model that remains in effect today.

## See Also

- `./architecture.md` — the authoritative treatment of the three-file
  include contract, the full include-dependency graph, subsystem
  boundaries, the `ht$init` lifecycle, and the authoritative exit-code
  table
- `./building.md` — FASM invocation, the `fasm -m 524288` rationale,
  the linker invocation, the `include_everything` flag for C and C++
  integration, and the Adding a New Tool procedure that complements
  the Adding a New Module procedure above
- `./calling-convention.md` — register contract, stack alignment, the
  `subsystem$function` label-naming convention, and the `prolog` and
  `epilog` macro contract
- `./security.md` — cryptographic primitive scope and the TLS and SSH
  support matrices, relevant when contributing to the crypto or
  networking subsystems
- `../ht.inc` — master include file; see lines 1-20 for the GPLv3
  preamble, line 22 for the purpose-comment convention, lines 38-42
  for exit codes, lines 54-208 for the include chain, and lines
  210-219 for the canonical `if used` guard
- `../ht_defaults.inc` — the single source of compile-time configuration
  knobs consulted throughout the library
- `../ht_data.inc` — the mandatory finale include that replays every
  `globals { ... }` block into the `.data` section
- `../profiler.inc` — the `prolog` and `epilog` macro family and the
  register-preservation contract
- `../align_macros.inc` — the `falign`, `calign`, and `dalign` macros
- `../dataseg_macros.inc` — the `globals { ... }` accumulator macro
- `../cleartext.inc` — the `cleartext` static-string macro
- `../examples/hello_world/hello_world.asm` — the canonical 41-line
  minimal entry-point template referenced in step 8 above
- `../ChangeLog` — historical record of released versions, terminating
  at v1.13 (16 July 2015)
- `../README.md` — the project landing page

---

Licensed under GPLv3. See [`../LICENSE`](../LICENSE).

